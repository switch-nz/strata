import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from engine import filesearch
from engine import listingdiff


def entry(path, size=1, modified=None, created=None, accessed=None,
          deleted=False, mft=None, is_dir=False):
    return {"path": path, "name": path.rsplit("/", 1)[-1], "is_dir": is_dir,
            "size": size, "deleted": deleted, "created": created,
            "modified": modified, "accessed": accessed, "mft": mft}


class Compare(unittest.TestCase):

    def test_added_removed_changed_and_unchanged_are_sorted_by_path(self):
        a = [entry("/b.txt", size=3), entry("/a.txt", size=1),
             entry("/gone.txt", size=9)]
        b = [entry("/b.txt", size=4), entry("/a.txt", size=1),
             entry("/new.txt", size=2)]
        d = listingdiff.compare(a, b)
        self.assertEqual([r["path"] for r in d["added"]], ["/new.txt"])
        self.assertEqual([r["path"] for r in d["removed"]], ["/gone.txt"])
        self.assertEqual([r["path"] for r in d["changed"]], ["/b.txt"])
        self.assertEqual(d["unchanged_count"], 1)
        self.assertEqual(d["compared"], 4)
        self.assertEqual(d["changed"][0]["a"]["size"], 3)
        self.assertEqual(d["changed"][0]["b"]["size"], 4)

    def test_changed_covers_each_timestamp_and_deleted_flag(self):
        base = dict(size=5, modified="2024-01-01T00:00:00Z")
        cases = [
            (entry("/x", modified="2024-02-01T00:00:00Z"), "modified"),
            (entry("/x", created="2020-01-01T00:00:00Z"), "created"),
            (entry("/x", accessed="2020-01-01T00:00:00Z"), "accessed"),
            (entry("/x", deleted=True), "deleted"),
        ]
        for other, field in cases:
            d = listingdiff.compare([entry("/x", **base)], [other])
            self.assertEqual(len(d["changed"]), 1, field)
            self.assertEqual(d["changed"][0]["path"], "/x")

    def test_node_number_only_difference_is_not_a_change(self):
        # ROADMAP debt note: node identity is unstable across acquisitions;
        # two entries that differ only in mft must compare unchanged.
        a = [entry("/same.txt", size=1, mft=100)]
        b = [entry("/same.txt", size=1, mft=999)]
        d = listingdiff.compare(a, b)
        self.assertEqual(d["changed"], [])
        self.assertEqual(d["unchanged_count"], 1)

    def test_none_timestamp_equals_none_but_not_a_value(self):
        d = listingdiff.compare([entry("/x")], [entry("/x")])
        self.assertEqual(d["changed"], [])
        d = listingdiff.compare([entry("/x")],
                                [entry("/x", modified="2024-01-01")])
        self.assertEqual(len(d["changed"]), 1)

    def test_case_folding_merges_same_names_differing_in_case(self):
        a = [entry("/Sub/X.txt", size=1)]
        b = [entry("/sub/x.txt", size=1)]
        d = listingdiff.compare(a, b, ignore_case=True)
        self.assertEqual(d["added"] + d["removed"] + d["changed"], [])
        self.assertEqual(d["unchanged_count"], 1)
        # Row paths stay in their original case (side a wins).
        self.assertEqual(d["compared"], 1)

    def test_without_folding_case_difference_is_added_plus_removed(self):
        a = [entry("/Sub/X.txt", size=1)]
        b = [entry("/sub/x.txt", size=1)]
        d = listingdiff.compare(a, b)
        self.assertEqual(len(d["added"]), 1)
        self.assertEqual(len(d["removed"]), 1)

    def test_empty_sides(self):
        self.assertEqual(listingdiff.compare([], [])["compared"], 0)
        d = listingdiff.compare([entry("/x")], [])
        self.assertEqual([r["path"] for r in d["removed"]], ["/x"])
        d = listingdiff.compare([], [entry("/x")])
        self.assertEqual([r["path"] for r in d["added"]], ["/x"])

    def test_added_row_carries_b_fields_only(self):
        d = listingdiff.compare([], [entry("/x", size=7)])
        self.assertEqual(d["added"][0]["b"]["size"], 7)
        self.assertNotIn("a", d["added"][0])



class ImageLevelDiff(unittest.TestCase):
    """Issue #74 image-level check: two independent walks over freshly
    built, identical NTFS images diff to zero changes, and every entry
    collected from one image is accounted for as unchanged."""

    def test_two_walks_of_identical_images_diff_clean(self):
        import imagebuild_ntfs
        from test_fs_fat import ImageFiles, open_first_volume

        img = imagebuild_ntfs.build_ntfs()
        files = ImageFiles()
        try:
            a = files.open(img)
            b = files.open(img)
            ea = filesearch.collect(open_first_volume(a)[2], 5)
            eb = filesearch.collect(open_first_volume(b)[2], 5)
        finally:
            files.close()
        self.assertTrue(ea)
        d = listingdiff.compare(ea, eb)
        self.assertEqual(d["added"], [])
        self.assertEqual(d["removed"], [])
        self.assertEqual(d["changed"], [])
        self.assertEqual(d["unchanged_count"], len(ea))
        self.assertEqual(d["compared"], len(ea))
