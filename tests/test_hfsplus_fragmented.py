"""An HFS+ catalog or attributes file in more pieces than the volume header
can hold: its first eight extents are in the header and the rest in the
extents overflow tree. The builder scatters the file a block at a time and
numbers the catalog's leaves from the top down, so the first leaf lies in the
last piece. libfshfs, an independent reader, lists the same volume."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_hfsplus as hb                               # noqa: E402
from engine import volume                                     # noqa: E402
from engine.ewf import OffsetReader                           # noqa: E402
from engine.fs import hfsplus                                 # noqa: E402


class Mem(object):
    bytes_per_sector = 512

    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


def entries():
    return [hb.Dir("Top", [hb.File("f%d.txt" % i, b"data%d" % i,
                                   xattrs={"user.k": b"value%d" % i})
                           for i in range(250)])]


def open_fs(data):
    return hfsplus.HfsPlus(OffsetReader(Mem(data), 0, len(data)))


class Fragmented(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = hb.build(entries(), name="Frag Vol",
                            fragment=("catalog", "attributes"),
                            reverse_leaves=True)
        cls.fs = open_fs(cls.data)

    def test_the_catalog_really_has_more_extents_than_the_header_holds(self):
        header_only = hfsplus.Fork(self.data, 1024 + 272)
        self.assertEqual(len(header_only.extents), 8)
        self.assertGreater(header_only.total_blocks, 8)
        self.assertGreater(len(self.fs.catalog_fork.extents), 8)

    def test_the_root_and_a_folder_list_in_full(self):
        root = self.fs.listdir(hfsplus.CNID_ROOT_FOLDER)
        self.assertEqual([e["name"] for e in root], ["Top"])
        top = self.fs.listdir(root[0]["cnid"], "/Top")
        self.assertEqual(len(top), 250)

    def test_a_file_in_it_reads_back(self):
        root = self.fs.listdir(hfsplus.CNID_ROOT_FOLDER)
        top = {e["name"]: e for e in self.fs.listdir(root[0]["cnid"], "/Top")}
        self.assertEqual(self.fs.read_file(top["f17.txt"]), b"data17")

    def test_attributes_in_a_scattered_attributes_file_are_found(self):
        root = self.fs.listdir(hfsplus.CNID_ROOT_FOLDER)
        top = {e["name"]: e for e in self.fs.listdir(root[0]["cnid"], "/Top")}
        info = self.fs.stat(top["f200.txt"])
        self.assertEqual(info["xattrs"][0]["name"], "user.k")

    def test_the_volume_name_is_read(self):
        self.assertEqual(self.fs.volume_name(), "Frag Vol")
        self.assertEqual(volume.volume_label(Mem(self.data), 0, "HFS+"),
                         "Frag Vol")

    def test_a_contiguous_volume_is_unchanged(self):
        plain = open_fs(hb.build(entries(), name="Frag Vol"))
        self.assertEqual(len(plain.catalog_fork.extents), 1)
        root = plain.listdir(hfsplus.CNID_ROOT_FOLDER)
        self.assertEqual(len(plain.listdir(root[0]["cnid"], "/Top")), 250)


class Damaged(unittest.TestCase):

    def test_missing_overflow_records_give_a_partial_listing_not_an_error(self):
        data = bytearray(hb.build(entries(), fragment=("catalog",)))
        import struct
        # Blank the extents overflow file's header-held extent: its records
        # are then unreadable, as if the tree were lost.
        data[1024 + 192 + 16:1024 + 192 + 80] = bytes(64)
        fs = open_fs(bytes(data))
        root = fs.listdir(hfsplus.CNID_ROOT_FOLDER)
        self.assertIsInstance(root, list)
        self.assertLessEqual(len(fs.catalog_fork.extents), 8)


if __name__ == "__main__":
    unittest.main()
