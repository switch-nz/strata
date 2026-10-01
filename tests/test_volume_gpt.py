"""Volume layout on a GPT disk: partition names, the filesystem label of an
HFS+ volume, and what counts as unpartitioned space (the GPT's own tables at
the front and back do not)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_gpt as g                                    # noqa: E402
import imagebuild_hfsplus as hb                               # noqa: E402
from engine import volume                                     # noqa: E402


class Mem(object):
    bytes_per_sector = 512

    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


def layout():
    hfs = hb.build([hb.File("a.txt", b"x")], name="Data Vol")
    sectors = -(-len(hfs) // 512)
    first = 40
    second = first + sectors + 100            # a 100-sector gap before it
    total = second + 64 + 200 + 33 + 1        # a 200-sector gap, then GPT
    data, last_usable = g.build([
        (first, sectors, g.HFS, "first slot", hfs),
        (second, 64, g.LINUX, "second slot", None),
    ], total)
    return data, first, sectors, second, total, last_usable


class Layout(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        (cls.data, cls.first, cls.sectors, cls.second, cls.total,
         cls.last_usable) = layout()
        cls.scan = volume.scan(Mem(cls.data))
        cls.parts = cls.scan["partitions"]

    def real(self):
        return [p for p in self.parts if p.get("allocated") is not False]

    def gaps(self):
        return [(p["start_sector"], p["start_sector"] + p["sector_count"])
                for p in self.parts if p.get("allocated") is False]

    def test_gpt_names_are_kept(self):
        self.assertEqual([p["name"] for p in self.real()],
                         ["first slot", "second slot"])

    def test_an_hfsplus_volume_has_its_label(self):
        first = self.real()[0]
        self.assertEqual(first["detected"], "HFS+")
        self.assertEqual(first["label"], "Data Vol")
        self.assertIsNone(self.real()[1]["label"])

    def test_the_gpt_tables_are_not_unpartitioned_space(self):
        gaps = self.gaps()
        for start, end in gaps:
            self.assertGreaterEqual(start, g.FIRST_USABLE)
            self.assertLessEqual(end, self.last_usable + 1)

    def test_real_gaps_are_still_reported(self):
        end_first = self.first + self.sectors
        self.assertEqual(self.gaps(), [
            (g.FIRST_USABLE, self.first),
            (end_first, self.second),
            (self.second + 64, self.last_usable + 1)])

    def test_the_trailing_gap_is_marked_trailing(self):
        last = [p for p in self.parts if p.get("allocated") is False][-1]
        self.assertEqual(last["type"], "Unpartitioned (trailing)")

    def test_a_disk_with_no_spare_room_reports_no_gaps_beyond_the_tables(self):
        hfs = hb.build([hb.File("a.txt", b"x")], name="V")
        sectors = -(-len(hfs) // 512)
        total = g.FIRST_USABLE + sectors + 33 + 1
        data, _ = g.build([(g.FIRST_USABLE, sectors, g.HFS, "only", hfs)],
                          total)
        parts = volume.scan(Mem(data))["partitions"]
        self.assertEqual([p for p in parts if p.get("allocated") is False],
                         [])


class HfsLabel(unittest.TestCase):

    def test_the_label_comes_from_the_catalog_without_walking_it(self):
        from engine.ewf import OffsetReader
        from engine.fs import hfsplus
        entries = [hb.File("f%d.txt" % i, b"x") for i in range(300)]
        data = hb.build(entries, name="Many Files")
        fs = hfsplus.HfsPlus(OffsetReader(Mem(data), 0, len(data)))
        self.assertEqual(fs.volume_name(), "Many Files")
        self.assertIsNone(fs._by_parent)          # nothing was indexed

    def test_a_damaged_catalog_gives_no_label_instead_of_an_error(self):
        data = bytearray(hb.build([hb.File("a", b"x")], name="Vol"))
        self.assertEqual(volume.volume_label(Mem(bytes(data)), 0, "HFS+"),
                         "Vol")
        # blank the volume header's catalog fork
        data[1024 + 272:1024 + 352] = bytes(80)
        self.assertIsNone(volume.volume_label(Mem(bytes(data)), 0, "HFS+"))


if __name__ == "__main__":
    unittest.main()
