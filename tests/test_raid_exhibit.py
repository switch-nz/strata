"""A RAID set as an exhibit, through the real server: it can be checked
without a case, opened into one, browsed like any disk, stored as its
definition and assembled again when the case is reopened, and it is a
different exhibit when its definition is different."""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import casedb, raid, treecache                        # noqa: E402
import imagebuild_fat                                             # noqa: E402
import imagebuild_raid as build                                   # noqa: E402
import test_notes_api                                             # noqa: E402
from test_notes_api import Client                                 # noqa: E402

CHUNK = 65536


def setUpModule():
    test_notes_api._PORT.clear()


class Base(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-raid-ex-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.fat = imagebuild_fat.build_fat(16)
        self.c = Client()
        self.c.call("GET", "/")

    def members(self, level=5, n=4, layout="left-symmetric", missing=(),
                tag="m"):
        chunk = CHUNK if level != 1 else None
        blobs = build.split(self.fat, level, n, chunk, layout)
        paths = []
        for i, b in enumerate(blobs):
            p = os.path.join(self.dir, "%s%d.img" % (tag, i))
            with open(p, "wb") as fh:
                fh.write(b)
            paths.append(None if i in missing else p)
        return chunk, paths

    def definition(self, level=5, n=4, layout="left-symmetric", missing=(),
                   name="Server data", tag="m"):
        chunk, paths = self.members(level, n, layout, missing, tag)
        d = {"name": name, "level": level,
             "members": [{"path": p, "offset": 0} for p in paths]}
        if chunk:
            d["chunk"] = chunk
        if level == 5:
            d["layout"] = layout
        return d

    def case_path(self, name="c.strata"):
        return os.path.join(self.dir, name)

    def task(self, t):
        for _ in range(300):
            _, r = self.c.call("GET", "/api/task?id=" + t["id"])
            if r.get("state") in ("done", "error"):
                return r
            time.sleep(0.05)
        self.fail("task did not finish")

    def names(self, r):
        return sorted(e["name"] for e in r["entries"])


class Check(Base):

    def test_a_set_is_checked_without_a_case_and_nothing_is_added(self):
        status, r = self.c.call("POST", "/api/raid/check",
                                {"definition": self.definition()})
        self.assertEqual(status, 200, r)
        self.assertIn("RAID 5 (4 members", r["info"]["format"])
        self.assertTrue(r["recognised"])
        self.assertEqual(r["volumes"][0]["fs"][:3], "FAT")
        self.assertEqual(r["info"]["size"], r["info"]["size"])
        self.assertTrue(raid.is_set_id(r["id"]))
        status, state = self.c.call("GET", "/api/evidence")
        self.assertNotEqual(status, 500)

    def test_a_wrong_layout_is_shown_as_not_recognised(self):
        d = self.definition()
        d["layout"] = "right-asymmetric"
        status, r = self.c.call("POST", "/api/raid/check", {"definition": d})
        self.assertEqual(status, 200, r)
        self.assertFalse(r["recognised"])

    def test_bad_definitions_are_a_400_with_the_reason(self):
        good = self.definition()
        cases = [
            (dict(good, level=6), "level"),
            (dict(good, chunk=100), "chunk"),
            (dict(good, name=""), "name"),
            (dict(good, members=good["members"][:2]), "at least 3"),
            (None, "object"),
        ]
        for d, text in cases:
            status, r = self.c.call("POST", "/api/raid/check",
                                    {"definition": d})
            self.assertEqual(status, 400, d)
            self.assertIn(text, r["error"])

    def test_a_member_that_is_not_there_is_named(self):
        d = self.definition()
        d["members"][2]["path"] = os.path.join(self.dir, "nope.img")
        status, r = self.c.call("POST", "/api/raid/check", {"definition": d})
        self.assertEqual(status, 400)
        self.assertIn("nope.img", r["error"])
        self.assertIn("Member 3", r["error"])
        self.assertTrue(r["advice"])


class Open(Base):

    def open(self, d, case=None, add=False):
        return self.c.call("POST", "/api/raid/open", {
            "definition": d, "case": case or self.case_path(),
            "examiner": "Alice", "add": add})

    def test_a_set_opens_as_one_exhibit_and_its_filesystem_is_browsable(self):
        status, r = self.open(self.definition())
        self.assertEqual(status, 200, r)
        self.assertTrue(r["open"])
        self.assertIn("RAID 5", r["image"]["format"])
        ev = r["evidence"][0]
        self.assertEqual(ev["label"], "Server data")
        self.assertTrue(raid.is_set_id(ev["path"]))
        status, listing = self.c.call("GET", "/api/dir?part=0")
        self.assertEqual(status, 200, listing)
        self.assertIn("HELLO.TXT", self.names(listing))

    def test_the_case_stores_the_definition_and_the_members(self):
        d = self.definition()
        _, r = self.open(d)
        case = casedb.Case(self.case_path())
        self.addCleanup(case.close)
        row = [e for e in case.summary()["evidence"]][0]
        self.assertEqual(row["kind"], "raid")
        self.assertEqual(json.loads(row["parents"]),
                         [m["path"] for m in d["members"]])
        stored = case.evidence_definition(row["path"])
        self.assertEqual(stored["level"], 5)
        self.assertEqual(stored["members"][1]["path"], d["members"][1]["path"])
        self.assertEqual(row["path"], raid.set_id(stored))
        added = [e for e in case.audit() if e["action"] == "evidence.add"][0]
        self.assertIn("raid", json.loads(added["detail"]))

    def test_the_same_definition_is_the_same_exhibit_a_different_one_is_not(self):
        d = self.definition()
        self.open(d)
        self.open(d, add=True)
        case = casedb.Case(self.case_path())
        self.addCleanup(case.close)
        self.assertEqual(len(case.summary()["evidence"]), 1)
        # The same members put together another way are another exhibit.
        other = dict(d, name="Server data", layout="left-asymmetric")
        self.open(other, add=True)
        self.assertEqual(len(case.summary()["evidence"]), 2)
        renamed = dict(d, name="Another name")
        self.open(renamed, add=True)
        self.assertEqual(len(case.summary()["evidence"]), 3)

    def test_a_case_opens_the_set_again_from_its_definition(self):
        self.open(self.definition())
        self.c.call("POST", "/api/case/close", {})
        status, r = self.c.call("POST", "/api/case/open",
                                {"path": self.case_path(), "examiner": "Alice"})
        self.assertEqual(status, 200, r)
        self.assertTrue(r["open"])
        self.assertIn("RAID 5", r["image"]["format"])
        _, listing = self.c.call("GET", "/api/dir?part=0")
        self.assertIn("HELLO.TXT", self.names(listing))

    def test_reopening_names_a_member_that_has_gone(self):
        d = self.definition()
        self.open(d)
        self.c.call("POST", "/api/case/close", {})
        os.remove(d["members"][1]["path"])
        status, r = self.c.call("POST", "/api/case/open",
                                {"path": self.case_path(), "examiner": "Alice"})
        self.assertEqual(status, 400)
        self.assertEqual(r["missing"], [d["members"][1]["path"]])

    def test_an_exhibit_can_be_opened_again_by_its_identifier(self):
        _, r = self.open(self.definition())
        ident = r["evidence"][0]["path"]
        status, r2 = self.c.call("POST", "/api/open", {
            "path": ident, "add": True, "case": self.case_path()})
        self.assertEqual(status, 200, r2)
        status, r3 = self.c.call("POST", "/api/open", {
            "path": "strata-raid-unknown-x", "add": True})
        self.assertEqual(status, 400)
        self.assertIn("no definition", r3["error"])

    def test_a_new_case_must_be_named_and_an_open_one_need_not_be(self):
        d = self.definition()
        status, r = self.c.call("POST", "/api/raid/open", {"definition": d})
        self.assertEqual(status, 400)
        self.assertIn("case file", r["error"])
        status, _ = self.c.call("POST", "/api/raid/open", {
            "definition": d, "add": True})
        self.assertEqual(status, 400)          # no case is open to add to
        self.open(d)
        d2 = self.definition(name="Second", tag="n")
        status, r = self.c.call("POST", "/api/raid/open", {
            "definition": d2, "add": True})
        self.assertEqual(status, 200, r)
        self.assertEqual(len(r["evidence"]), 2)

    def test_a_set_missing_a_member_opens_and_reads(self):
        _, r = self.open(self.definition(missing=(2,)))
        self.assertIn("Member 3 is missing", " ".join(r["image"]["findings"]))
        _, listing = self.c.call("GET", "/api/dir?part=0")
        self.assertIn("HELLO.TXT", self.names(listing))

    def test_two_missing_members_is_refused(self):
        status, r = self.open(self.definition(missing=(1, 2)))
        self.assertEqual(status, 400)
        self.assertIn("not two", r["error"])

    def test_mirror_and_stripe_sets_open_too(self):
        for level, n in ((0, 2), (1, 2)):
            status, r = self.open(self.definition(level, n, name="S%d" % level,
                                                  tag="l%d" % level),
                                  add=level != 0)
            self.assertEqual(status, 200, (level, r))
        _, r = self.c.call("GET", "/api/evidence")
        self.assertEqual(len(r["items"]), 2)

    def test_verify_reports_what_the_members_hold(self):
        d = self.definition()
        self.open(d)
        chunk = d["chunk"]
        # Damage one parity chunk on a member, then verify.
        with open(d["members"][0]["path"], "r+b") as fh:
            fh.seek(chunk + 10)
            b = fh.read(1)
            fh.seek(chunk + 10)
            fh.write(bytes([b[0] ^ 0x55]))
        self.c.call("POST", "/api/case/close", {})
        self.c.call("POST", "/api/case/open",
                    {"path": self.case_path(), "examiner": "Alice"})
        status, t = self.c.call("POST", "/api/verify", {})
        self.assertEqual(status, 200, t)
        r = self.task(t)
        self.assertEqual(r["state"], "done", r)
        res = r["result"]
        self.assertEqual(res["raid"]["kind"], "parity")
        self.assertEqual(res["raid"]["rows_inconsistent"], 1)
        self.assertIn("does not match", res["note"])
        self.assertEqual(len(res["computed_sha1"]), 40)


class Stamp(unittest.TestCase):

    def test_the_tree_cache_stamp_follows_how_the_set_was_put_together(self):
        d = tempfile.mkdtemp(prefix="strata-stamp-")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        p = os.path.join(d, "a.img")
        with open(p, "wb") as fh:
            fh.write(b"x" * 10)
        plain = treecache.stamp(p, 0)
        self.assertEqual(treecache.stamp(p, 0, extra=""), plain)
        a = treecache.stamp(p, 0, extra="one")
        self.assertNotEqual(a, plain)
        self.assertNotEqual(a, treecache.stamp(p, 0, extra="two"))
        self.assertIsNone(treecache.stamp(os.path.join(d, "gone"), 0,
                                          extra="one"))


if __name__ == "__main__":
    unittest.main()
