"""What a case costs on disk, and what gives the space back (engine.casedb,
engine.server.Session.sweep_cache).
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import casedb                                         # noqa: E402
from engine import server                                         # noqa: E402
from engine import treecache                                      # noqa: E402
from engine.casedb import Case                                    # noqa: E402


def legacy_case(folder, docs=20):
    # A case from before the index moved to cache/: content_index lives in
    # case.sqlite itself.
    Case(folder, name="legacy").close()
    db = sqlite3.connect(os.path.join(folder, casedb.DB_NAME))
    db.executescript(casedb.FTS_SCHEMA)
    db.executemany(
        "INSERT INTO content_index (name,path,body,node,part,size,deleted,"
        "modified,abs_offset,kind,evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [("f%d.txt" % i, "/f%d.txt" % i, "word%d " % i * 200, str(i), 0, 10,
          0, "", "", "file", "1") for i in range(docs)])
    db.execute("INSERT INTO meta VALUES ('index_part_0', ?)", (str(docs),))
    db.commit()
    db.close()


def actions(case):
    return [r["action"] for r in case.db.execute(
        "SELECT action FROM audit ORDER BY seq")]


def audit_detail(case, action):
    row = case.db.execute(
        "SELECT detail FROM audit WHERE action=? ORDER BY seq DESC LIMIT 1",
        (action,)).fetchone()
    return json.loads(row["detail"]) if row else None


class Relocate(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.folder = os.path.join(self.tmp, "c.strata")
        legacy_case(self.folder)
        self.case = Case(self.folder)

    def tearDown(self):
        self.case.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_moves_the_index_out_of_the_record(self):
        self.assertEqual(self.case.index_pending, 20)
        r = self.case.relocate_index()
        self.assertEqual(r["moved"], 20)
        self.assertEqual(self.case.index_pending, 0)
        self.assertIsNot(self.case.index, self.case.db)
        self.assertIn("index.relocated", actions(self.case))

    def test_without_room_it_defers_and_says_so(self):
        with mock.patch.object(casedb, "_free_space", return_value=1024):
            r = self.case.relocate_index()
        self.assertTrue(r["deferred"])
        self.assertEqual(r["moved"], 0)
        self.assertEqual(self.case.index_pending, 20)
        detail = audit_detail(self.case, "index.relocate.deferred")
        self.assertEqual(detail["free_bytes"], 1024)
        self.assertGreater(detail["need_bytes"], 1024)
        n = self.case.db.execute(
            "SELECT COUNT(*) c FROM content_index").fetchone()["c"]
        self.assertEqual(n, 20)

    def test_a_failure_part_way_is_recorded_and_rolled_back(self):
        with mock.patch.object(Case, "_build_index_file",
                               side_effect=sqlite3.OperationalError(
                                   "database or disk is full")):
            r = self.case.relocate_index()
        self.assertEqual(r["moved"], 0)
        self.assertIn("disk is full", r["error"])
        detail = audit_detail(self.case, "index.relocate.failed")
        self.assertIn("disk is full", detail["error"])
        self.assertEqual(self.case.index_pending, 20)
        # The record is still usable, and the move still works afterwards.
        self.assertEqual(self.case.relocate_index()["moved"], 20)

    def test_the_audit_chain_survives_a_failed_move(self):
        with mock.patch.object(Case, "_build_index_file",
                               side_effect=sqlite3.OperationalError("full")):
            self.case.relocate_index()
        prev = None
        for row in self.case.db.execute(
                "SELECT prev_hash, hash FROM audit ORDER BY seq"):
            if prev is not None:
                self.assertEqual(row["prev_hash"], prev)
            prev = row["hash"]


class Compact(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.folder = os.path.join(self.tmp, "c.strata")
        self.case = Case(self.folder, name="c")

    def tearDown(self):
        self.case.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fill_and_empty(self):
        blob = "x" * 4096
        for k in range(200):
            self.case.save_artefact(1, k, "browser", {"k": k, "b": blob * 20})
        self.case.db.execute("DELETE FROM artefacts")
        self.case.db.commit()

    def test_gives_back_space_left_by_deleted_rows(self):
        self.fill_and_empty()
        r = self.case.compact()
        self.assertTrue(r["compacted"])
        self.assertLess(r["after"], r["before"])
        detail = audit_detail(self.case, "case.compact")
        self.assertEqual(detail["before_bytes"], r["before"])
        self.assertLess(detail["record_after"], detail["record_before"])

    def test_leaves_every_recorded_row_in_place(self):
        self.case.index_add([("a", "/a", "needle haystack", "1", 0, 1, 0, "",
                              "", "file", "1")])
        audit_before = self.case.db.execute(
            "SELECT COUNT(*) c FROM audit").fetchone()["c"]
        self.case.compact()
        hits = self.case.index.execute(
            "SELECT path FROM content_index WHERE content_index MATCH 'needle'"
        ).fetchall()
        self.assertEqual([h[0] for h in hits], ["/a"])
        audit_after = self.case.db.execute(
            "SELECT COUNT(*) c FROM audit").fetchone()["c"]
        self.assertEqual(audit_after, audit_before + 1)

    def test_refuses_without_room_and_changes_nothing(self):
        self.fill_and_empty()
        size = os.path.getsize(self.case.db_path)
        with mock.patch.object(casedb, "_free_space", return_value=0):
            r = self.case.compact()
        self.assertFalse(r["compacted"])
        self.assertEqual(os.path.getsize(self.case.db_path), size)
        self.assertNotIn("case.compact", actions(self.case))

    def test_refuses_while_the_index_is_still_in_the_record(self):
        self.case.close()
        shutil.rmtree(self.folder)
        legacy_case(self.folder)
        self.case = Case(self.folder)
        r = self.case.compact()
        self.assertFalse(r["compacted"])
        self.assertEqual(self.case.index_pending, 20)


class Sweep(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.folder = os.path.join(self.tmp, "c.strata")
        self.case = Case(self.folder, name="c")
        self.case.db.execute(
            "INSERT INTO evidence (id, path, added_at) VALUES "
            "(1, ?, 'now')", (os.path.join(self.tmp, "Disk One.E01"),))
        self.case.db.commit()
        self.cache = self.case.cache_dir(create=True)
        self.session = server.Session()
        self.session.case = self.case

    def tearDown(self):
        self.case.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def touch(self, name, size=10):
        with open(os.path.join(self.cache, name), "wb") as fh:
            fh.write(b"\0" * size)

    def test_removes_what_belongs_to_exhibits_no_longer_in_the_case(self):
        mine = treecache.path_for(self.cache,
                                  os.path.join(self.tmp, "Disk One.E01"), 0)
        self.touch(os.path.basename(mine))
        self.touch("timeline-ev1-p0.sqlite")
        self.touch("timeline-ev2-p1048576.sqlite", 100)
        self.touch("timeline-ev2-p1048576.sqlite-journal", 5)
        self.touch("mft-Other.E01-1048576.sqlite", 50)
        self.touch("timeline-tagged.sqlite")
        self.touch(casedb.INDEX_NAME)
        gone = self.session.sweep_cache()
        self.assertEqual(sorted(gone), [
            "mft-Other.E01-1048576.sqlite",
            "timeline-ev2-p1048576.sqlite",
            "timeline-ev2-p1048576.sqlite-journal"])
        left = sorted(os.listdir(self.cache))
        self.assertEqual(left, sorted([
            os.path.basename(mine), "timeline-ev1-p0.sqlite",
            "timeline-tagged.sqlite", casedb.INDEX_NAME]))
        detail = audit_detail(self.case, "cache.swept")
        self.assertEqual(detail["freed_bytes"], 155)

    def test_nothing_to_sweep_writes_nothing(self):
        self.touch("timeline-ev1-p0.sqlite")
        before = actions(self.case)
        self.assertEqual(self.session.sweep_cache(), [])
        self.assertEqual(actions(self.case), before)

    def test_read_only_mode_sweeps_nothing(self):
        self.touch("timeline-ev9-p0.sqlite")
        with mock.patch.object(server, "READ_ONLY", True):
            self.assertEqual(self.session.sweep_cache(), [])
        self.assertIn("timeline-ev9-p0.sqlite", os.listdir(self.cache))

    def test_drop_timelines_retries_a_file_that_is_briefly_held(self):
        self.touch("timeline-ev1-p0.sqlite")
        real = os.remove
        calls = {"n": 0}

        def flaky(path):
            calls["n"] += 1
            if calls["n"] < 3:
                raise PermissionError("in use")
            real(path)

        with mock.patch.object(server.os, "remove", side_effect=flaky), \
                mock.patch.object(server.time, "sleep"):
            gone = self.session.drop_timelines(1)
        self.assertEqual(gone, ["timeline-ev1-p0.sqlite"])


if __name__ == "__main__":
    unittest.main()
