"""A tagged item is stored by handle, so the bulk "export tagged items"
action reconstructs an entry on the server from what the tag row kept.
Issue #85 fixed the deleted/modified/... fields; exFAT has one more that
must survive the round trip: a NoFatChain (contiguous) stream has no FAT
chain at all, so a deleted contiguous file whose clusters have since been
reallocated is read correctly only if `contiguous` reaches
engine.fs.exfat.ExfatFS.runs(). Dropping it makes the read walk the FAT --
which after deletion describes entirely different clusters -- and the
export silently contains the wrong bytes.

Also covers the storage side: engine.casedb.tagged_items must keep the
flag so the client can send it back.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import imagebuild_fat as build                                    # noqa: E402
from test_fs_fat import ImageFiles, by_name, open_first_volume    # noqa: E402
from engine import casedb                                         # noqa: E402
from engine import server                                         # noqa: E402
from engine.casedb import Case                                    # noqa: E402


class FakeCase:
    """The two Case members _export_one touches, without a real case db."""
    examiner = "tester"

    def __init__(self):
        self.logged = []

    def log(self, action, detail=None):
        self.logged.append((action, detail))


class FakeSession:
    def __init__(self):
        self.case = FakeCase()


class ExportTaggedExfat(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()
        cls.image = cls.files.open(build.build_exfat())
        cls.layout, cls.part, cls.fs = open_first_volume(cls.image)
        cls.root = by_name(cls.fs.listdir(0))

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    def setUp(self):
        self.out_dir = tempfile.mkdtemp(prefix="strata-export-test-")
        self.addCleanup(shutil.rmtree, self.out_dir, ignore_errors=True)
        self.session = FakeSession()

    def body(self, **extra):
        e = self.root["Deleted file.txt"]
        body = {"node": e["start_cluster"], "name": e["name"],
                "path": e["path"], "size": e["size"], "deleted": True,
                "modified": e["modified"]}
        body.update(extra)
        return e, body

    def test_entry_from_body_carries_contiguous(self):
        e, body = self.body(contiguous=True)
        got = server._entry_from_body(self.fs, body)
        self.assertEqual(got["start_cluster"], e["start_cluster"])
        self.assertTrue(got["contiguous"])
        self.assertTrue(got["deleted"])

    def test_contiguous_missing_walks_chain_exports_wrong(self):
        # What the bulk export sent before the fix: deleted survives but
        # contiguous does not, so the read walks the FAT. A real driver
        # zeroes the FAT entries of a NoFatChain stream when it writes them
        # (the fixture's Contiguous.dat has FAT entries 10-12 zero, exactly
        # as a live driver leaves them), and a deleted file's clusters may
        # since have been reallocated and their FAT rewritten. Either way
        # the walk follows whatever the FAT now says instead of the one
        # extent the directory entry described. In this fixture the walk
        # stops after the first cluster: 1024 bytes instead of 3000.
        e = self.root["Contiguous.dat"]
        body = {"node": e["start_cluster"], "name": e["name"],
                "path": e["path"], "size": e["size"]}
        entry = server._entry_from_body(self.fs, body)
        self.assertFalse(entry["contiguous"])
        rec, path, written = server._export_one(
            self.fs, entry, self.out_dir, self.session, manifest=False)
        self.assertLess(written, e["size"])
        with open(path, "rb") as fh:
            self.assertNotEqual(fh.read(), build.pattern(3000, 12))

    def test_contiguous_forwarded_deleted_exports_exact_extent(self):
        # The issue #94 shape: a deleted contiguous file. The chain walk
        # and the contiguous read happen to agree on this 100-byte fixture
        # file (one cluster, FAT[13] left zero), so the wrongness above is
        # exercised on Contiguous.dat; this asserts the exported bytes for
        # the deleted entry are the exact pattern the entry described.
        e, body = self.body(contiguous=True)
        entry = server._entry_from_body(self.fs, body)
        rec, path, written = server._export_one(
            self.fs, entry, self.out_dir, self.session, manifest=False)
        self.assertEqual(written, 100)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), build.pattern(100, 13))
        self.assertTrue(rec["deleted"])

    def test_tag_item_stores_contiguous(self):
        d = tempfile.mkdtemp(prefix="strata-case-tag-")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        case = Case(d, name="New", examiner="tester")
        self.addCleanup(case.close)
        ev_id = case.add_evidence("/images/exfat.raw",
                                  {"kind": "image", "format": "raw",
                                   "size": len(build.build_exfat())})
        e = self.root["Deleted file.txt"]
        case.tag_item(ev_id, {"path": e["path"], "name": e["name"],
                              "size": e["size"], "deleted": True,
                              "contiguous": True,
                              "start_cluster": e["start_cluster"]},
                      "evidence")
        rows = case.tagged(ev_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["contiguous"], 1)
        self.assertEqual(rows[0]["deleted"], 1)
        cols = {r[1] for r in case.db.execute(
            "PRAGMA table_info(tagged_items)")}
        self.assertIn("contiguous", cols)

    def test_migration_re_adds_contiguous_to_old_db(self):
        # Simulate a case db from before the column: create the table with
        # the old 15-column shape, reopen, and the migration must add the
        # column back without disturbing the row.
        d = tempfile.mkdtemp(prefix="strata-case-old-")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        case = Case(d, name="Old", examiner="tester")
        ev_id = case.add_evidence("/images/exfat.raw",
                                  {"kind": "image", "format": "raw",
                                   "size": 1})
        case.tag_item(ev_id, {"path": "/x", "name": "old.txt",
                              "size": 5, "deleted": True,
                              "start_cluster": 13}, "evidence")
        case.close()
        db_path = os.path.join(d, casedb.DB_NAME)
        import sqlite3
        con = sqlite3.connect(db_path)
        # Old schema: rebuild the table without contiguous and without the
        # UNIQUE index it backs.
        con.execute("PRAGMA foreign_keys=OFF")
        con.execute("ALTER TABLE tagged_items RENAME TO tagged_items_old")
        con.execute(
            "CREATE TABLE tagged_items ("
            "id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL,"
            "part INTEGER NOT NULL DEFAULT 0, node TEXT, path TEXT,"
            "name TEXT, size INTEGER, is_dir INTEGER DEFAULT 0,"
            "deleted INTEGER DEFAULT 0, tag TEXT NOT NULL, note TEXT,"
            "created_at TEXT NOT NULL, examiner TEXT, modified TEXT,"
            "accessed TEXT, file_created TEXT,"
            "UNIQUE (evidence_id, part, node, tag))")
        con.execute(
            "INSERT INTO tagged_items (evidence_id,part,node,path,name,size,"
            "is_dir,deleted,tag,note,created_at,examiner,modified,accessed,"
            "file_created) SELECT evidence_id,part,node,path,name,size,"
            "is_dir,deleted,tag,note,created_at,examiner,modified,accessed,"
            "file_created FROM tagged_items_old")
        con.execute("DROP TABLE tagged_items_old")
        con.commit()
        con.close()

        again = Case(d, examiner="tester")
        self.addCleanup(again.close)
        cols = {r[1] for r in again.db.execute(
            "PRAGMA table_info(tagged_items)")}
        self.assertIn("contiguous", cols)
        rows = again.tagged(ev_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "old.txt")
        self.assertEqual(rows[0]["deleted"], 1)
        self.assertIsNone(rows[0]["contiguous"])


if __name__ == "__main__":
    unittest.main()