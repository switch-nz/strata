"""Unit tests for volume tag reassociation (engine.casedb #82).

When the same volume is re-acquired into another image (new acquisition,
GPT re-wrap, different offsets) the exhibit gets a new evidence_id and its
tags used to stay behind on the old row.  These tests drive the pass the
server runs at acquire time -- volume.identities -> register_volumes ->
reassociate_tags -- directly against a Case.
"""

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import imagebuild_fat as build_fat_mod                            # noqa: E402
import imagebuild_ntfs as build_ntfs_mod                          # noqa: E402
from engine import volume                                         # noqa: E402
from engine.casedb import Case                                    # noqa: E402
from engine.ewf import RawImage                                   # noqa: E402
from test_fs_fat import BytesImage                                # noqa: E402


def acquire(case, img_path):
    """The part of Session._open this feature adds, driven directly."""
    img = RawImage(img_path)
    found = volume.identities(img, volume.scan(img))
    ev_id = case.add_evidence(img_path, {"kind": "image", "size": img.size})
    case.register_volumes(ev_id, found)
    counts = case.reassociate_tags(ev_id, found)
    return ev_id, counts


class Reassociation(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="strata-retag-test-")
        self.addCleanup(lambda: shutil.rmtree(self._dir, ignore_errors=True))
        self.ntfs = build_ntfs_mod.build_ntfs()
        self.a = self._write("a.img", self.ntfs)
        self.b = self._write("b.img", self.ntfs)
        self.case = Case(os.path.join(self._dir, "case"), name="t",
                         examiner="tester")
        self.addCleanup(self.case.close)

    def _write(self, name, data):
        path = os.path.join(self._dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def _tag_hello(self, ev_id, part=None):
        item = {"mft": 16, "path": "/hello.txt", "name": "hello.txt",
                "size": 13}
        if part is None:
            return self.case.tag_item(ev_id, item, "Evidence")
        return self.case.tag_item(ev_id, item, "Evidence", part=part)

    def _reassociated_rows(self):
        return list(reversed(list(self.case.audit(limit=1000))))

    def test_tags_follow_reacquired_volume(self):
        ev1, _ = acquire(self.case, self.a)
        self._tag_hello(ev1)
        ev2, counts = acquire(self.case, self.b)
        rows = self.case.tagged(ev2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["node"], "16")
        self.assertEqual(rows[0]["tag"], "Evidence")
        self.assertEqual(rows[0]["name"], "hello.txt")
        self.assertEqual(self.case.tagged(ev1), [])
        self.assertEqual(counts, {"remapped": 1, "duplicates_dropped": 0,
                                  "ambiguous": 0, "unchanged": 0,
                                  "ambiguous_details": []})
        # audit() is newest-first; the last entry is this acquire's.
        entry = [r for r in self._reassociated_rows()
                 if r["action"] == "tags.reassociated"][-1]
        detail = entry["detail"] if isinstance(entry["detail"], dict) \
            else __import__("json").loads(entry["detail"])
        self.assertEqual(detail["remapped"], 1)
        self.assertEqual(detail["evidence_id"], ev2)

    def test_part_offset_moves_with_volume(self):
        g = self._write("g.img", build_ntfs_mod.wrap_gpt(self.ntfs))
        ev1, _ = acquire(self.case, self.a)
        self._tag_hello(ev1)
        ev2, counts = acquire(self.case, g)
        rows = self.case.tagged(ev2)
        self.assertEqual(counts["remapped"], 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["part"], 1048576)
        self.assertEqual(rows[0]["node"], "16")
        self.assertEqual(rows[0]["tag"], "Evidence")

    def test_ambiguous_volume_leaves_tags_and_reports(self):
        # Two prior evidences, each holding the same volume key.  They must
        # be real evidence rows: the incoming acquisition dedupes by path
        # and would otherwise reuse id 1 and re-register over its candidate.
        self.case.add_evidence(self.a, {"kind": "image",
                                        "size": len(self.ntfs)})
        self.case.add_evidence(self.b, {"kind": "image",
                                        "size": len(self.ntfs)})
        self.case.register_volumes(1, [{"part": 0,
                                        "key": "ntfs:0123456789ABCDEF"}])
        self.case.register_volumes(2, [{"part": 0,
                                        "key": "ntfs:0123456789ABCDEF"}])
        self._tag_hello(1)
        third = self._write("c.img", self.ntfs)
        ev3, counts = acquire(self.case, third)
        self.assertEqual(len(self.case.tagged(1)), 1)
        self.assertEqual(counts["ambiguous"], 1)
        self.assertEqual(counts["remapped"], 0)
        detail = [r for r in self._reassociated_rows()
                  if r["action"] == "tags.reassociated"][-1]
        parsed = detail["detail"] if isinstance(detail["detail"], dict) \
            else __import__("json").loads(detail["detail"])
        candidates = parsed["ambiguous_details"][0]["candidates"]
        self.assertEqual(sorted(tuple(c) for c in candidates), [(1, 0), (2, 0)])

    def test_duplicate_tag_on_target_is_dropped_from_source(self):
        self.case.add_evidence(self.a, {"kind": "image",
                                        "size": len(self.ntfs)})
        self.case.register_volumes(1, [{"part": 0,
                                        "key": "ntfs:0123456789ABCDEF"}])
        self._tag_hello(1)
        ev3 = self.case.add_evidence(self.b, {"kind": "image",
                                              "size": len(self.ntfs)})
        self._tag_hello(ev3)
        self.case.register_volumes(
            ev3, [{"part": 0, "key": "ntfs:0123456789ABCDEF"}])
        counts = self.case.reassociate_tags(
            ev3, [{"part": 0, "key": "ntfs:0123456789ABCDEF"}])
        self.assertEqual(counts["duplicates_dropped"], 1)
        self.assertEqual(counts["remapped"], 0)
        self.assertEqual(self.case.tagged(1), [])
        self.assertEqual(len(self.case.tagged(ev3)), 1)

    def test_volume_without_identity_keeps_its_tags(self):
        fat1 = self._write("f1.img", build_fat_mod.build_fat())
        fat2 = self._write("f2.img", build_fat_mod.build_fat())
        img = RawImage(fat1)
        self.assertEqual(volume.identities(img, volume.scan(img)), [])
        ev1, _ = acquire(self.case, fat1)
        self._tag_hello(ev1)
        ev2, counts = acquire(self.case, fat2)
        self.assertEqual(len(self.case.tagged(ev1)), 1)
        self.assertEqual(len(self.case.tagged(ev2)), 0)
        for key in ("remapped", "duplicates_dropped", "ambiguous",
                    "unchanged"):
            self.assertEqual(counts[key], 0)

    def test_identities_shapes(self):
        img = RawImage(self.a)
        self.assertEqual(volume.identities(img),
                         [{"part": 0, "key": "ntfs:0123456789ABCDEF"}])
        ex = BytesImage(build_fat_mod.build_exfat())
        self.assertEqual(volume.identities(ex),
                         [{"part": 0, "key": "exfat:1234ABCD"}])
        fat = BytesImage(build_fat_mod.build_fat())
        self.assertEqual(volume.identities(fat), [])
        g = RawImage(self._write("g.img", build_ntfs_mod.wrap_gpt(self.ntfs)))
        self.assertEqual(volume.identities(g),
                         [{"part": 1048576, "key": "ntfs:0123456789ABCDEF"}])

    def test_audit_chain_intact(self):
        ev1, _ = acquire(self.case, self.a)
        self._tag_hello(ev1)
        acquire(self.case, self.b)
        self.assertEqual(self.case.verify_audit(),
                         {"intact": True, "broken_at": None})


if __name__ == "__main__":
    unittest.main()