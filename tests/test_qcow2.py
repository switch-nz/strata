"""Unit tests for QEMU QCOW2 disks (engine.qcow2): clusters are found
through the two-level table, unallocated and zero-flagged clusters read as
zeros, compressed clusters are inflated, and disks that hold only a
difference, are encrypted or use features Strata cannot read are refused
rather than misread."""

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_qcow2 as build                                 # noqa: E402
from engine import ewf, qcow2                                     # noqa: E402

CS = 4096


def pattern(n, seed):
    return bytes((seed + i * 7) & 0xFF for i in range(n))


class QcowCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def open(self, data, name="disk.qcow2"):
        path = os.path.join(self.dir.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        img = ewf.open_image(path)
        self.addCleanup(img.close)
        return img

    def refused(self, data, text):
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            self.open(data)
        self.assertIn(text, str(cm.exception))
        return cm.exception


class Reading(QcowCase):
    def setUp(self):
        QcowCase.setUp(self)
        self.c0, self.c2 = pattern(CS, 1), pattern(CS, 9)
        self.data = build.build(6 * CS, {0: self.c0, 2: self.c2, 4: "zero"},
                                version=3)
        self.img = self.open(self.data)

    def test_is_opened_as_a_qcow2(self):
        self.assertIsInstance(self.img, qcow2.Qcow2Image)
        self.assertEqual(self.img.size, 6 * CS)

    def test_reads_clusters_and_zeros_elsewhere(self):
        self.assertEqual(self.img.read_at(0, CS), self.c0)
        self.assertEqual(self.img.read_at(CS, CS), bytes(CS))
        self.assertEqual(self.img.read_at(2 * CS, CS), self.c2)
        self.assertEqual(self.img.read_at(4 * CS, CS), bytes(CS))   # zero flag
        self.assertEqual(self.img.read_at(5 * CS, CS), bytes(CS))

    def test_the_zero_flag_wins_over_data_still_behind_the_cluster(self):
        img = self.open(build.build(2 * CS, {0: ("zero+", pattern(CS, 4)),
                                             1: pattern(CS, 5)}, version=3))
        self.assertEqual(img.read_at(0, CS), bytes(CS))
        self.assertEqual(img.read_at(CS, CS), pattern(CS, 5))

    def test_reads_across_cluster_boundaries(self):
        want = self.c0[-8:] + bytes(CS) + self.c2[:8]
        self.assertEqual(self.img.read_at(CS - 8, CS + 16), want)

    def test_read_past_end_is_empty_and_short_at_end(self):
        self.assertEqual(self.img.read_at(6 * CS, 10), b"")
        self.assertEqual(len(self.img.read_at(6 * CS - 4, 100)), 4)
        self.assertEqual(self.img.read_at(-1, 10), b"")

    def test_version_2_reads_the_same(self):
        img = self.open(build.build(6 * CS, {0: self.c0, 2: self.c2}))
        self.assertEqual(img.read_at(0, 3 * CS), self.c0 + bytes(CS) + self.c2)
        self.assertIn("version 2", img.info()["format"])

    def test_info_and_verify(self):
        import hashlib
        info = self.img.info()
        self.assertIn("QCOW2, version 3", info["format"])
        self.assertEqual(info["acquisition"]["cluster size"], CS)
        self.assertEqual(info["findings"], [])
        whole = self.img.read_at(0, 6 * CS)
        self.assertEqual(self.img.verify()["computed_sha1"],
                         hashlib.sha1(whole).hexdigest())

    def test_other_cluster_sizes(self):
        for bits in (9, 16):
            cs = 1 << bits
            img = self.open(build.build(3 * cs, {1: pattern(cs, 5)},
                                        cluster_bits=bits), "c%d.qcow2" % bits)
            self.assertEqual(img.read_at(cs, cs), pattern(cs, 5))
            self.assertEqual(img.read_at(0, cs), bytes(cs))

    def test_a_disk_needing_several_l2_tables(self):
        # 512-byte clusters hold 64 entries per L2 table.
        cs = 512
        img = self.open(build.build(200 * cs, {3: pattern(cs, 1),
                                               130: pattern(cs, 2)},
                                    cluster_bits=9))
        self.assertEqual(img.read_at(3 * cs, cs), pattern(cs, 1))
        self.assertEqual(img.read_at(130 * cs, cs), pattern(cs, 2))
        self.assertEqual(img.read_at(70 * cs, cs), bytes(cs))


class Compressed(QcowCase):
    def test_compressed_clusters_are_inflated(self):
        text = (b"strata compressed cluster " * 200)[:CS]
        img = self.open(build.build(
            4 * CS, {0: pattern(CS, 1), 1: ("z", text),
                     3: ("z", bytes(CS))}))
        self.assertEqual(img.read_at(CS, CS), text)
        self.assertEqual(img.read_at(3 * CS, CS), bytes(CS))
        self.assertEqual(img.read_at(0, CS), pattern(CS, 1))
        self.assertEqual(img.info()["findings"], [])

    def test_packed_streams_at_unaligned_offsets(self):
        # QEMU writes each stream right after the last, at a byte offset:
        # the entry's sector count is measured from the sector it starts in.
        parts = {i: ("z", pattern(CS, i * 3)) for i in range(6)}
        img = self.open(build.build(6 * CS, parts, pack=True))
        for i in range(6):
            self.assertEqual(img.read_at(i * CS, CS), pattern(CS, i * 3))
        self.assertEqual(img.info()["findings"], [])

    def test_several_compressed_clusters_in_a_row(self):
        parts = {i: ("z", pattern(CS, i)) for i in range(6)}
        img = self.open(build.build(6 * CS, parts))
        for i in range(6):
            self.assertEqual(img.read_at(i * CS, CS), pattern(CS, i))

    def test_a_damaged_compressed_cluster_is_reported_not_raised(self):
        data = bytearray(build.build(2 * CS, {0: ("z", pattern(CS, 3))}))
        # Find the compressed entry in the L2 table and damage the start of
        # its deflate stream.
        entry_at = None
        for at in range(0, len(data) - 8, 8):
            if struct.unpack_from(">Q", data, at)[0] >> 62 & 1 \
                    and at > CS:
                entry_at = at
        self.assertIsNotNone(entry_at)
        host = struct.unpack_from(">Q", data, entry_at)[0] & 0xFFFFFFFF
        for i in range(host, host + 8):
            data[i] ^= 0xFF
        img = self.open(bytes(data), "bad.qcow2")
        got = img.read_at(0, CS)
        self.assertEqual(len(got), CS)
        self.assertTrue(any("would not inflate" in f
                            for f in img.info()["findings"]))


class Refusals(QcowCase):
    def test_a_backing_file_is_refused_by_name(self):
        exc = self.refused(build.build(2 * CS, {0: pattern(CS, 1)},
                                       backing=b"/somewhere/base.qcow2"),
                           "base.qcow2")
        self.assertIn("qemu-img", exc.advice)

    def test_an_encrypted_disk_is_refused(self):
        self.refused(build.build(2 * CS, {}, crypt=1), "encrypted")

    def test_external_data_and_extended_l2_are_refused(self):
        self.refused(build.build(2 * CS, {}, version=3, incompatible=1 << 2),
                     "external file")
        self.refused(build.build(2 * CS, {}, version=3, incompatible=1 << 4),
                     "extended L2")

    def test_other_compression_types_are_refused(self):
        self.refused(build.build(2 * CS, {}, version=3, incompatible=1 << 3,
                                 compression=1), "method 1")

    def test_unknown_incompatible_features_are_refused(self):
        self.refused(build.build(2 * CS, {}, version=3, incompatible=1 << 9),
                     "0x200")

    def test_version_1_and_unknown_versions_are_refused(self):
        for v in (0, 1, 4):
            data = bytearray(build.build(2 * CS, {}))
            struct.pack_into(">I", data, 4, v)
            self.refused(bytes(data), "version %d" % v)

    def test_bad_cluster_sizes_are_refused(self):
        for bits in (0, 8, 22, 63):
            data = bytearray(build.build(2 * CS, {}))
            struct.pack_into(">I", data, 20, bits)
            self.refused(bytes(data), "cluster size")

    def test_a_misplaced_or_oversized_l1_table_is_refused(self):
        self.refused(build.build(2 * CS, {}, l1_offset=1 << 30),
                     "L1 table")
        data = bytearray(build.build(2 * CS, {}))
        struct.pack_into(">Q", data, 40, 100)          # not cluster aligned
        self.refused(bytes(data), "L1 table")

    def test_a_short_header_is_not_a_qcow2(self):
        self.refused(b"QFI\xfb" + bytes(20), "QCOW")


class Damaged(QcowCase):
    def test_an_l1_shorter_than_the_disk_needs_says_so(self):
        cs = 512
        data = build.build(200 * cs, {3: pattern(cs, 1)}, cluster_bits=9,
                           l1_entries=1)
        img = self.open(data)
        self.assertEqual(img.read_at(3 * cs, cs), pattern(cs, 1))
        self.assertEqual(img.read_at(150 * cs, cs), bytes(cs))
        self.assertTrue(any("L1 table holds 1 entries" in f
                            for f in img.info()["findings"]))

    def test_an_oversized_l1_is_not_read_past_the_disk(self):
        data = bytearray(build.build(2 * CS, {0: pattern(CS, 1)}))
        struct.pack_into(">I", data, 36, 1 << 28)      # claimed L1 size
        img = self.open(bytes(data))
        self.assertEqual(len(img._l1), 1)
        self.assertEqual(img.read_at(0, CS), pattern(CS, 1))

    def test_a_cluster_past_the_end_of_the_file_reads_as_zeros_and_says_so(self):
        data = build.build(2 * CS, {0: pattern(CS, 1)})
        # The data cluster is the last thing written before the L2 table.
        img = self.open(data[:-CS - CS // 2])
        got = img.read_at(0, CS)
        self.assertEqual(len(got), CS)
        self.assertTrue(any("runs past the end" in f or
                            "not a whole cluster" in f
                            for f in img.info()["findings"]))

    def test_an_l2_pointer_outside_the_file_is_reported(self):
        data = bytearray(build.build(2 * CS, {0: pattern(CS, 1)}))
        struct.pack_into(">Q", data, CS, (1 << 63) | (1 << 40))
        img = self.open(bytes(data))
        self.assertEqual(img.read_at(0, CS), bytes(CS))
        self.assertTrue(any("L2 table" in f for f in img.info()["findings"]))

    def test_snapshots_and_dirty_flag_are_reported(self):
        img = self.open(build.build(2 * CS, {0: pattern(CS, 1)}, version=3,
                                    incompatible=1, snapshots=2))
        findings = " ".join(img.info()["findings"])
        self.assertIn("2 internal snapshot", findings)
        self.assertIn("not closed cleanly", findings)
        self.assertEqual(img.read_at(0, CS), pattern(CS, 1))

    def test_truncation_at_every_boundary_never_raises_from_reads(self):
        data = build.build(3 * CS, {0: pattern(CS, 1),
                                    2: ("z", pattern(CS, 2))})
        for cut in (10, 72, 111, 112, CS, CS + 4, 2 * CS, 3 * CS,
                    len(data) - 1):
            path = os.path.join(self.dir.name, "cut%d.qcow2" % cut)
            with open(path, "wb") as fh:
                fh.write(data[:cut])
            try:
                img = ewf.open_image(path)
            except ewf.UnsupportedContainer:
                continue
            try:
                if isinstance(img, qcow2.Qcow2Image):
                    img.read_at(0, img.size)
            finally:
                img.close()


class WholeDisk(QcowCase):
    def test_a_real_filesystem_round_trips_byte_for_byte(self):
        import imagebuild_ntfs
        raw = imagebuild_ntfs.build_ntfs()
        cs = 4096
        cl = {i // cs: raw[i:i + cs].ljust(cs, b"\x00")
              for i in range(0, len(raw), cs) if any(raw[i:i + cs])}
        comp = {k: ("z", c) if k % 2 else c for k, c in cl.items()}
        img = self.open(build.build(len(raw), comp, pack=True, version=3))
        self.assertEqual(img.size, len(raw))
        self.assertEqual(img.read_at(0, len(raw)), raw)


if __name__ == "__main__":
    unittest.main()
