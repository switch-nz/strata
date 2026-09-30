"""Unit tests for VirtualBox VDI disks (engine.vdi): blocks are found
through the block map, blocks never written or discarded read as zeros, a
fixed disk reads straight through, and disks that hold only a difference,
or whose headers do not add up, are refused or reported rather than
misread."""

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_vdi as build                                   # noqa: E402
from engine import ewf, vdi                                       # noqa: E402

BS = 4096


def pattern(n, seed):
    return bytes((seed + i * 7) & 0xFF for i in range(n))


class VdiCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def open(self, data, name="disk.vdi"):
        path = os.path.join(self.dir.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        img = ewf.open_image(path)
        self.addCleanup(img.close)
        return img


class Dynamic(VdiCase):
    def setUp(self):
        VdiCase.setUp(self)
        self.b0, self.b2 = pattern(BS, 1), pattern(BS, 9)
        # Block 1 was never written; block 3 was written and discarded.
        self.data, self.uid = build.build(
            5 * BS, {0: self.b0, 2: self.b2}, zero=(3,))
        self.img = self.open(self.data)

    def test_is_opened_as_a_vdi(self):
        self.assertIsInstance(self.img, vdi.VdiImage)
        self.assertEqual(self.img.size, 5 * BS)

    def test_reads_allocated_blocks_and_zeros_elsewhere(self):
        self.assertEqual(self.img.read_at(0, BS), self.b0)
        self.assertEqual(self.img.read_at(BS, BS), bytes(BS))
        self.assertEqual(self.img.read_at(2 * BS, BS), self.b2)
        self.assertEqual(self.img.read_at(3 * BS, BS), bytes(BS))
        self.assertEqual(self.img.read_at(4 * BS, BS), bytes(BS))

    def test_blocks_are_placed_by_the_map_not_by_file_order(self):
        # Block 2 is the second block stored, so it is at slot 1.
        self.assertEqual(self.img.read_at(2 * BS + 5, 10), self.b2[5:15])

    def test_reads_across_block_boundaries(self):
        want = self.b0[-8:] + bytes(BS) + self.b2[:8]
        self.assertEqual(self.img.read_at(BS - 8, BS + 16), want)

    def test_read_past_end_is_empty_and_short_at_end(self):
        self.assertEqual(self.img.read_at(5 * BS, 10), b"")
        self.assertEqual(len(self.img.read_at(5 * BS - 4, 100)), 4)
        self.assertEqual(self.img.read_at(-1, 10), b"")

    def test_banner_and_header_are_not_disk_data(self):
        self.assertFalse(b"VirtualBox" in self.img.read_at(0, 5 * BS))

    def test_info_names_the_type_and_counts_blocks(self):
        info = self.img.info()
        self.assertIn("VDI, dynamic", info["format"])
        acq = info["acquisition"]
        self.assertEqual(acq["blocks allocated"], 2)
        self.assertEqual(acq["blocks discarded as zero"], 1)
        self.assertEqual(acq["blocks in map"], 5)
        self.assertEqual(info["findings"], [])

    def test_verify_hashes_the_disk(self):
        import hashlib
        whole = self.img.read_at(0, 5 * BS)
        got = self.img.verify()
        self.assertEqual(got["computed_sha1"], hashlib.sha1(whole).hexdigest())
        self.assertIsNone(got["stored_sha1"])


class Fixed(VdiCase):
    def test_a_fixed_disk_reads_straight_through(self):
        b1 = pattern(BS, 3)
        data, _ = build.build(3 * BS, {1: b1}, kind=build.FIXED)
        img = self.open(data)
        self.assertIn("VDI, fixed", img.info()["format"])
        self.assertEqual(img.read_at(BS, BS), b1)
        self.assertEqual(img.read_at(0, BS), bytes(BS))


class Refused(VdiCase):
    def refused(self, data, text):
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            self.open(data)
        self.assertIn(text, str(cm.exception))
        return cm.exception

    def test_a_differencing_disk_is_refused_not_shown_alone(self):
        for kind in (build.DIFF, build.UNDO):
            data, _ = build.build(2 * BS, {0: pattern(BS, 1)}, kind=kind)
            exc = self.refused(data, "only what changed")
            self.assertIn("VBoxManage", exc.advice)

    def test_an_unknown_type_is_refused(self):
        data, _ = build.build(BS, {}, kind=9)
        self.refused(data, "image type")

    def test_an_old_version_is_refused(self):
        data, _ = build.build(BS, {}, version=0x00010000)
        self.refused(data, "version 1.0")

    def test_bad_block_sizes_are_refused(self):
        for bs in (0, 100, 3 * 512, 1 << 30):
            data, _ = build.build(4096, {}, block_size=bs or 4096)
            data = bytearray(data)
            struct.pack_into("<I", data, 0x178, bs)
            self.refused(bytes(data), "block size")

    def test_extra_data_before_each_block_is_refused(self):
        data, _ = build.build(2 * BS, {0: pattern(BS, 1)}, extra=16)
        self.refused(data, "extra data")

    def test_a_map_past_the_end_of_the_file_is_refused(self):
        data, _ = build.build(2 * BS, {})
        data = bytearray(data)
        struct.pack_into("<I", data, 0x154, 1 << 30)
        self.refused(bytes(data), "block map")

    def test_a_short_file_is_not_mistaken_for_a_vdi(self):
        self.assertFalse(vdi.looks_like_vdi(build.BANNER))
        img = self.open(b"<<< not a vdi >>>" + bytes(600))
        self.assertNotIsInstance(img, vdi.VdiImage)


class Damaged(VdiCase):
    def test_a_map_covering_less_than_the_disk_says_so(self):
        data, _ = build.build(4 * BS, {0: pattern(BS, 1)}, map_entries=2)
        img = self.open(data)
        self.assertEqual(img.size, 4 * BS)
        self.assertEqual(img.read_at(3 * BS, BS), bytes(BS))
        self.assertTrue(any("block map holds 2 blocks" in f
                            for f in img.info()["findings"]))

    def test_a_map_longer_than_the_disk_needs_is_not_read_past(self):
        data, _ = build.build(2 * BS, {0: pattern(BS, 1)}, map_entries=50000)
        img = self.open(data)
        self.assertEqual(len(img._map), 2)

    def test_a_block_past_the_end_of_the_file_reads_as_zeros_and_says_so(self):
        data, _ = build.build(2 * BS, {0: pattern(BS, 1), 1: pattern(BS, 2)})
        img = self.open(data[:-BS // 2])
        got = img.read_at(BS, BS)
        self.assertEqual(got[:BS // 2], pattern(BS, 2)[:BS // 2])
        self.assertEqual(got[BS // 2:], bytes(BS // 2))
        self.assertTrue(any("runs past the end" in f
                            for f in img.info()["findings"]))

    def test_an_allocated_count_that_disagrees_is_reported(self):
        data, _ = build.build(2 * BS, {0: pattern(BS, 1)}, allocated=7)
        img = self.open(data)
        self.assertTrue(any("7 blocks are allocated" in f
                            for f in img.info()["findings"]))

    def test_two_entries_sharing_a_block_are_reported(self):
        data, _ = build.build(2 * BS, {0: pattern(BS, 1), 1: pattern(BS, 2)})
        data = bytearray(data)
        struct.pack_into("<I", data, 512 + 4, 0)     # block 1 -> slot 0
        img = self.open(bytes(data))
        self.assertEqual(img.read_at(BS, BS), pattern(BS, 1))
        self.assertTrue(any("already uses" in f for f in img.info()["findings"]))

    def test_truncation_at_every_boundary_never_raises_from_reads(self):
        data, _ = build.build(3 * BS, {0: pattern(BS, 1), 2: pattern(BS, 2)})
        for cut in (100, 511, 512, 520, 1024, 1024 + BS // 2, len(data) - 1):
            path = os.path.join(self.dir.name, "cut%d.vdi" % cut)
            with open(path, "wb") as fh:
                fh.write(data[:cut])
            try:
                img = ewf.open_image(path)
            except ewf.UnsupportedContainer:
                continue
            try:
                img.read_at(0, img.size) if hasattr(img, "_map") else None
            finally:
                img.close()


class WholeDisk(VdiCase):
    def test_a_real_filesystem_round_trips_byte_for_byte(self):
        import imagebuild_ntfs
        raw = imagebuild_ntfs.build_ntfs()
        cs = 4096
        cl = {i // cs: raw[i:i + cs].ljust(cs, b"\x00")
              for i in range(0, len(raw), cs) if any(raw[i:i + cs])}
        img = self.open(build.build(len(raw), cl)[0])
        self.assertEqual(img.size, len(raw))
        self.assertEqual(img.read_at(0, len(raw)), raw)


if __name__ == "__main__":
    unittest.main()
