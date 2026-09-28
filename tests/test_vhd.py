"""Unit tests for Conectix VHD disks (engine.vhd): a fixed VHD opens
directly with the footer excluded from the exposed disk; dynamic disks read
through their block allocation table; differencing disks read through their
parent, which must be the exact disk they were made from; and footers or
headers that fail to validate are refused explicitly rather than misread."""

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_vhd as build                                   # noqa: E402
from engine import ewf, vhd                                       # noqa: E402

DISK_TYPE_FIXED = 2
DISK_TYPE_DYNAMIC = 3
DISK_TYPE_DIFFERENCING = 4


def build_footer(disk_type=DISK_TYPE_FIXED, current_size=0, original_size=None,
                  cookie=b"conectix", bad_checksum=False):
    footer = bytearray(512)
    struct.pack_into(">8s", footer, 0, cookie)
    struct.pack_into(">I", footer, 8, 2)                  # features
    struct.pack_into(">I", footer, 12, 0x00010000)        # file format version
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)  # data offset
    struct.pack_into(">I", footer, 24, 0)                 # timestamp
    struct.pack_into(">4s", footer, 28, b"stra")           # creator app
    struct.pack_into(">I", footer, 32, 0x00010000)        # creator version
    struct.pack_into(">4s", footer, 36, b"Wi2k")           # creator host OS
    struct.pack_into(">Q", footer, 40,
                     current_size if original_size is None else original_size)
    struct.pack_into(">Q", footer, 48, current_size)
    struct.pack_into(">I", footer, 56, 0)                 # disk geometry
    struct.pack_into(">I", footer, 60, disk_type)
    total = sum(footer[:64]) + sum(footer[68:512])
    checksum = (~total) & 0xFFFFFFFF
    if bad_checksum:
        checksum ^= 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)
    return bytes(footer)


MEDIA = bytes((i * 37 + 11) % 256 for i in range(4096))


def fixed_vhd_bytes(data=MEDIA):
    return data + build_footer(DISK_TYPE_FIXED, current_size=len(data))


class VhdCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="strata-vhd-test-")
        self.addCleanup(self._tmp.cleanup)

    def write(self, data, name="disk.vhd"):
        path = os.path.join(self._tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def open(self, data, name="disk.vhd"):
        img = ewf.open_image(self.write(data, name))
        self.addCleanup(img.close)
        return img


class FixedVhd(VhdCase):
    def setUp(self):
        super(FixedVhd, self).setUp()
        self.img = self.open(fixed_vhd_bytes())

    def test_opens_as_fixed_vhd(self):
        self.assertIsInstance(self.img, vhd.VhdImage)
        self.assertEqual(self.img.findings, [])

    def test_exposes_only_the_virtual_disk_bytes(self):
        self.assertEqual(self.img.size, len(MEDIA))
        self.assertEqual(self.img.read_at(0, len(MEDIA)), MEDIA)

    def test_footer_is_not_readable_as_disk_data(self):
        # Asking for more than the disk holds must not spill into the
        # footer that follows it in the file.
        got = self.img.read_at(0, len(MEDIA) + 512)
        self.assertEqual(len(got), len(MEDIA))
        self.assertEqual(got, MEDIA)

    def test_read_past_end_is_empty(self):
        self.assertEqual(self.img.read_at(len(MEDIA), 100), b"")

    def test_info_reports_fixed_vhd(self):
        info = self.img.info()
        self.assertIn("VHD", info["format"])
        self.assertIn("fixed", info["format"])
        self.assertEqual(info["size"], len(MEDIA))
        self.assertEqual(info["findings"], [])

    def test_verify_hashes_only_the_disk_bytes(self):
        import hashlib
        result = self.img.verify()
        self.assertEqual(result["computed_md5"], hashlib.md5(MEDIA).hexdigest())


class UnsupportedTypes(VhdCase):
    def test_unrecognised_disk_type_is_refused(self):
        data = MEDIA + build_footer(5, current_size=len(MEDIA))
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(self.write(data))

    def test_dynamic_footer_without_a_dynamic_header_is_refused(self):
        # The footer says dynamic but points nowhere valid (its data offset
        # is the all-ones "none" value a fixed disk carries).
        data = MEDIA + build_footer(DISK_TYPE_DYNAMIC, current_size=len(MEDIA))
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            ewf.open_image(self.write(data))
        self.assertIn("dynamic header", str(cm.exception))


BS = 4096                                 # 8 sectors per block
DISK = 5 * BS                             # blocks 0-4


def pattern(n, seed):
    return bytes((i * 31 + seed * 7 + (i >> 9)) & 0xFF for i in range(n))


class DynamicVhd(VhdCase):
    """Blocks 0 and 3 written; 1, 2 and 4 never allocated."""

    def setUp(self):
        super(DynamicVhd, self).setUp()
        self.b0, self.b3 = pattern(BS, 1), pattern(BS, 3)
        data, self.uid = build.sparse(DISK, {0: (self.b0, None),
                                             3: (self.b3, None)},
                                      block_size=BS)
        self.img = self.open(data)
        self.want = self.b0 + bytes(2 * BS) + self.b3 + bytes(BS)

    def test_reads_allocated_blocks_and_zeros_elsewhere(self):
        self.assertIsInstance(self.img, vhd.VhdImage)
        self.assertEqual(self.img.size, DISK)
        self.assertEqual(self.img.read_at(0, DISK), self.want)
        self.assertEqual(self.img.findings, [])

    def test_reads_across_block_boundaries(self):
        for off, n in ((BS - 10, 20), (3 * BS - 1, BS + 2), (123, 3 * BS)):
            with self.subTest(off=off, n=n):
                self.assertEqual(self.img.read_at(off, n),
                                 self.want[off:off + n])

    def test_info_names_the_type_and_counts_blocks(self):
        info = self.img.info()
        self.assertEqual(info["format"],
                         "Virtual PC / Hyper-V disk (VHD, dynamic)")
        self.assertEqual(info["acquisition"]["blocks allocated"], 2)
        self.assertEqual(info["acquisition"]["block size"], BS)

    def test_verify_hashes_the_disk(self):
        import hashlib
        self.assertEqual(self.img.verify()["computed_md5"],
                         hashlib.md5(self.want).hexdigest())


class DifferencingVhd(VhdCase):
    """A dynamic parent with blocks 0-2 written; a child that rewrote
    sectors 2-3 of block 0, all of block 4, and nothing else."""

    def setUp(self):
        super(DifferencingVhd, self).setUp()
        self.p = {i: pattern(BS, 10 + i) for i in range(3)}
        parent, self.parent_uid = build.sparse(
            DISK, {i: (d, None) for i, d in self.p.items()}, block_size=BS)
        self.parent_path = self.write(parent, "base.vhd")
        self.c0 = pattern(BS, 50)
        self.c4 = pattern(BS, 54)
        self.child_blocks = {0: (self.c0, {2, 3}), 4: (self.c4, None)}
        want = bytearray(self.p[0] + self.p[1] + self.p[2] + bytes(BS)
                         + self.c4)
        want[2 * 512:4 * 512] = self.c0[2 * 512:4 * 512]
        self.want = bytes(want)

    def child(self, **kw):
        kw.setdefault("parent_name", "base.vhd")
        data, _ = build.sparse(DISK, self.child_blocks, block_size=BS,
                               parent=self.parent_uid, **kw)
        return self.open(data, "child.vhd")

    def test_sectors_come_from_child_or_parent_by_bitmap(self):
        img = self.child()
        self.assertEqual(img.read_at(0, DISK), self.want)
        for off, n in ((1000, 100), (2 * 512 - 3, 6), (4 * 512 - 1, 2),
                       (BS - 1, BS + 2)):
            with self.subTest(off=off, n=n):
                self.assertEqual(img.read_at(off, n), self.want[off:off + n])

    def test_info_names_the_parent_and_how_it_was_found(self):
        info = self.child().info()
        self.assertEqual(info["segments"], ["child.vhd", "base.vhd"])
        self.assertEqual(info["acquisition"]["parent"], self.parent_path)
        self.assertEqual(info["acquisition"]["parent found by"],
                         "parent name in the header, beside this file")

    def test_parent_found_through_a_relative_locator(self):
        img = self.child(parent_name="",
                         locators=[(b"W2ru", ".\\base.vhd".encode(
                             "utf-16-le"))])
        self.assertEqual(img.read_at(0, DISK), self.want)
        self.assertEqual(img.info()["acquisition"]["parent found by"],
                         "relative locator")

    def test_absolute_locator_from_another_machine_falls_back_to_the_name(self):
        img = self.child(parent_name="", locators=[
            (b"W2ku", "D:\\VMs\\base.vhd".encode("utf-16-le"))])
        self.assertEqual(img.read_at(0, DISK), self.want)

    def test_missing_parent_is_refused_by_name(self):
        os.remove(self.parent_path)
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            self.child()
        self.assertIn("base.vhd", str(cm.exception))

    def test_wrong_parent_is_refused(self):
        other, _ = build.sparse(DISK, {0: (pattern(BS, 99), None)},
                                block_size=BS)
        with open(self.parent_path, "wb") as fh:
            fh.write(other)
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            self.child()
        self.assertIn("not this differencing VHD's parent",
                      str(cm.exception))

    def test_a_locator_naming_a_directory_is_not_opened(self):
        os.remove(self.parent_path)
        os.mkdir(os.path.join(self._tmp.name, "base.vhd"))
        with self.assertRaises(ewf.UnsupportedContainer):
            self.child()

    def test_a_child_naming_itself_as_parent_is_refused(self):
        data, uid = build.sparse(DISK, self.child_blocks, block_size=BS,
                                 parent=b"\x00" * 16, parent_name="self.vhd")
        # Rebuild with its own id as the parent id so only the loop guard
        # can stop it.
        data, _ = build.sparse(DISK, self.child_blocks, block_size=BS,
                               parent=uid, parent_name="self.vhd",
                               unique_id=uid)
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            self.open(data, "self.vhd")
        self.assertIn("already in the chain", str(cm.exception))


class DamagedSparse(VhdCase):
    def test_corrupt_dynamic_header_is_refused(self):
        data, _ = build.sparse(DISK, {0: (pattern(BS, 1), None)},
                               block_size=BS, corrupt_header=True)
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            self.open(data)
        self.assertIn("checksum", str(cm.exception))

    def test_block_past_end_of_file_reads_zeros_with_a_finding(self):
        data, _ = build.sparse(DISK, {0: (pattern(BS, 1), None)},
                               block_size=BS)
        # Cut the block's data (keeping the trailing footer).
        cut = data[:-512 - BS // 2] + data[-512:]
        img = self.open(cut)
        got = img.read_at(0, BS)
        self.assertEqual(len(got), BS)
        self.assertTrue(any("past the end of the file" in f
                            for f in img.findings))

    def test_random_damage_never_crashes(self):
        import random
        good, _ = build.sparse(DISK, {0: (pattern(BS, 1), None),
                                      2: (pattern(BS, 2), None)},
                               block_size=BS)
        rng = random.Random(46)
        for trial in range(200):
            data = bytearray(good)
            for _ in range(6):
                data[rng.randrange(len(data))] = rng.getrandbits(8)
            with self.subTest(trial=trial):
                try:
                    img = self.open(bytes(data), "d%d.vhd" % trial)
                except ewf.UnsupportedContainer:
                    continue
                self.assertEqual(len(img.read_at(0, img.size)), img.size)


class Malformed(VhdCase):
    def test_bad_checksum_fails_safely(self):
        data = MEDIA + build_footer(DISK_TYPE_FIXED, current_size=len(MEDIA),
                                    bad_checksum=True)
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(self.write(data))

    def test_size_mismatch_is_reported_and_clamped(self):
        # The footer claims a virtual disk 100 bytes smaller than the data
        # actually in front of it.
        data = MEDIA + build_footer(DISK_TYPE_FIXED, current_size=len(MEDIA) - 100)
        img = ewf.open_image(self.write(data))
        self.addCleanup(img.close)
        self.assertEqual(img.size, len(MEDIA) - 100)
        self.assertTrue(img.findings)

    def test_truncated_footer_falls_back_to_raw_without_crashing(self):
        # Cut into the footer itself: the tail no longer carries a whole,
        # valid footer, so this cannot be confirmed as a VHD at all and is
        # read as a raw file instead of raising or hanging.
        data = fixed_vhd_bytes()[:-100]
        img = ewf.open_image(self.write(data))
        self.addCleanup(img.close)
        self.assertIsInstance(img, ewf.RawImage)
        self.assertEqual(img.size, len(data))

    def test_file_too_small_for_a_footer_is_refused_not_crashed(self):
        # Too short for a full 512-byte footer to be confirmed at the tail,
        # but it still starts with the cookie, so the coarse head-based
        # check still recognises and refuses it explicitly.
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(self.write(b"conectix" + bytes(50)))

    def test_empty_file_does_not_crash(self):
        img = ewf.open_image(self.write(b""))
        self.addCleanup(img.close)
        self.assertIsInstance(img, ewf.RawImage)
        self.assertEqual(img.size, 0)


if __name__ == "__main__":
    unittest.main()
