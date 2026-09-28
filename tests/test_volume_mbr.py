"""MBR extended partitions: the chain of extended boot records and the
logical partitions it describes."""

import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import imagebuild_fat as build                                   # noqa: E402
from engine import volume                                        # noqa: E402
from engine.ewf import OffsetReader                              # noqa: E402
from engine.fs import ntfs                                       # noqa: E402

SS = 512


class Disk:
    def __init__(self, sectors):
        self.data = bytearray(sectors * SS)
        self.size = len(self.data)
        self.bytes_per_sector = SS

    def read_at(self, off, n):
        return bytes(self.data[off:off + n])

    def entry(self, sector, slot, ptype, start, count):
        at = sector * SS + 446 + slot * 16
        self.data[at:at + 16] = struct.pack("<B3sB3sII", 0, b"\xFE\xFF\xFF",
                                            ptype, b"\xFE\xFF\xFF", start,
                                            count)
        self.data[sector * SS + 510:sector * SS + 512] = b"\x55\xAA"

    def put(self, sector, blob):
        self.data[sector * SS:sector * SS + len(blob)] = blob


def slots(layout):
    return [(p["slot"], p["type"], p["start_sector"], p["sector_count"])
            for p in layout["partitions"]]


class LogicalPartitions(unittest.TestCase):

    def disk_with_chain(self):
        # MBR: FAT32 at 63; extended 0x0F over 1000-3999.
        # EBR 1000 -> logical at 1063 (FAT16, a real volume), next EBR 2100.
        # EBR 2100 -> logical at 2163 (Linux, 1000 sectors), end of chain.
        fat = build.build_fat(16)
        d = Disk(4096 + len(fat) // SS)
        fat_sectors = len(fat) // SS
        d.entry(0, 0, 0x0C, 63, 500)
        d.entry(0, 1, 0x0F, 1000, 1100 + fat_sectors + 2000)
        d.entry(1000, 0, 0x06, 63, fat_sectors)
        d.entry(1000, 1, 0x05, 1100 + fat_sectors, 1063)
        d.put(1063, fat)
        second = 1000 + 1100 + fat_sectors
        d.entry(second, 0, 0x83, 63, 1000)
        return d, fat_sectors, second

    def test_logical_partitions_are_listed_after_their_container(self):
        d, fat_sectors, second = self.disk_with_chain()
        layout = volume.scan(d)
        listed = [s for s in slots(layout) if s[0] != "Gap"]
        self.assertEqual(listed, [
            ("MBR 1", "FAT32 LBA", 63, 500),
            ("MBR 2", "Extended LBA", 1000, 1100 + fat_sectors + 2000),
            ("MBR 5", "FAT16", 1063, fat_sectors),
            ("MBR 6", "Linux", second + 63, 1000),
        ])
        self.assertEqual(layout["findings"], [])
        container = layout["partitions"][3]
        self.assertTrue(container["container"])
        self.assertIsNone(container["detected"])

    def test_filesystem_in_a_logical_partition_opens(self):
        d, _, _ = self.disk_with_chain()
        part = next(p for p in volume.scan(d)["partitions"]
                    if p["slot"] == "MBR 5")
        self.assertEqual(part["detected"], "FAT16")
        fs = ntfs.open_fs(OffsetReader(d, part["offset"], part["size"]))
        names = {e["name"] for e in fs.listdir(0)}
        self.assertIn("HELLO.TXT", names)

    def test_space_inside_the_container_is_not_called_unpartitioned(self):
        d, fat_sectors, second = self.disk_with_chain()
        gaps = [(p["type"], p["start_sector"],
                 p["start_sector"] + p["sector_count"])
                for p in volume.scan(d)["partitions"] if p["slot"] == "Gap"]
        inside = "Unused (inside extended partition)"
        self.assertIn((inside, 1000, 1063), gaps)
        # From the end of the first logical partition, over the second EBR.
        self.assertIn((inside, 1063 + fat_sectors, second + 63), gaps)
        self.assertIn(("Unpartitioned", 563, 1000), gaps)

    def test_a_looping_chain_stops_and_says_so(self):
        d = Disk(4096)
        d.entry(0, 0, 0x05, 1000, 3000)
        d.entry(1000, 0, 0x83, 63, 100)
        d.entry(1000, 1, 0x05, 0, 3000)          # links back to itself
        layout = volume.scan(d)
        self.assertEqual([s[0] for s in slots(layout) if s[0] != "Gap"],
                         ["MBR 1", "MBR 5"])
        self.assertTrue(any("loops back" in f for f in layout["findings"]))

    def test_missing_ebr_signature_is_a_finding(self):
        d = Disk(4096)
        d.entry(0, 0, 0x05, 1000, 3000)
        layout = volume.scan(d)
        self.assertEqual([s[0] for s in slots(layout) if s[0] != "Gap"],
                         ["MBR 1"])
        self.assertTrue(any("no boot signature" in f
                            for f in layout["findings"]))

    def test_link_outside_the_container_stops_the_chain(self):
        d = Disk(8192)
        d.entry(0, 0, 0x05, 1000, 2000)
        d.entry(1000, 0, 0x83, 63, 100)
        d.entry(1000, 1, 0x05, 5000, 100)        # past the container's end
        layout = volume.scan(d)
        self.assertEqual([s[0] for s in slots(layout) if s[0] != "Gap"],
                         ["MBR 1", "MBR 5"])
        self.assertTrue(any("outside its extended partition" in f
                            for f in layout["findings"]))

    def test_logical_partition_outside_the_container_is_flagged(self):
        d = Disk(8192)
        d.entry(0, 0, 0x05, 1000, 2000)
        d.entry(1000, 0, 0x83, 4000, 100)        # starts at LBA 5000
        layout = volume.scan(d)
        self.assertIn(("MBR 5", "Linux", 5000, 100), slots(layout))
        self.assertTrue(any("lies outside the extended partition" in f
                            for f in layout["findings"]))


if __name__ == "__main__":
    unittest.main()
