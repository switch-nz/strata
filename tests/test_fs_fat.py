"""Unit tests for the FAT12/16/32 parser (engine.fs.fat) and the MBR probe.

Images come from tests/imagebuild_fat.py. They are written to a temporary
file and opened the way the server opens evidence: ewf.open_image ->
volume.scan -> OffsetReader over the partition -> ntfs.open_fs (the
filesystem dispatcher).
"""

import os
import random
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import imagebuild_fat as build                                   # noqa: E402
from engine import volume                                        # noqa: E402
from engine.ewf import OffsetReader, open_image                  # noqa: E402
from engine.fs import fat, ntfs                                  # noqa: E402

C = build.FAT_CLUSTER
L = build.FAT_LAYOUT


class BytesImage:
    """In-memory stand-in for ewf.RawImage (read_at + size), used only where
    a test mutates an image many times and a file per mutation is wasteful."""

    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)
        self.bytes_per_sector = 512

    def read_at(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


class ImageFiles:
    """Write built images to a temp dir and open them with ewf.open_image."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="strata-fs-test-")
        self.images = []

    def open(self, data, name="image.raw"):
        path = os.path.join(self.dir, "%d-%s" % (len(self.images), name))
        with open(path, "wb") as fh:
            fh.write(data)
        img = open_image(path)
        self.images.append(img)
        return img

    def open_extents(self, size, extents, name="image.raw"):
        """Like ``open`` for a SparseImage's extents, never holding the
        whole image in memory."""
        path = os.path.join(self.dir, "%d-%s" % (len(self.images), name))
        build.write_sparse(path, size, extents)
        img = open_image(path)
        self.images.append(img)
        return img

    def close(self):
        for img in self.images:
            img.close()
        shutil.rmtree(self.dir, ignore_errors=True)


def open_first_volume(image):
    """What the server does for /api/dir: scan, pick the partition, wrap it
    in an OffsetReader and hand that to the dispatcher."""
    layout = volume.scan(image)
    part = next(p for p in layout["partitions"] if p.get("detected"))
    src = OffsetReader(image, part["offset"], part["size"], part["slot"])
    return layout, part, ntfs.open_fs(src)


def by_name(entries):
    return {e["name"]: e for e in entries}


class _FatWidth:
    """Width-sensitive checks, run once per FAT width by the subclasses."""

    bits = None

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()
        cls.image = cls.files.open_extents(*build.build_fat_extents(cls.bits))
        cls.layout, cls.part, cls.fs = open_first_volume(cls.image)
        cls.root = by_name(cls.fs.listdir(0))

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    def test_dispatcher_returns_fat_with_detected_width(self):
        self.assertIsInstance(self.fs, fat.FatFS)
        self.assertEqual(self.fs.bits, self.bits)
        self.assertEqual(self.fs.name, "FAT%d" % self.bits)
        self.assertEqual(self.fs.info()["type"], "FAT%d" % self.bits)

    def test_volume_probe_names_the_width(self):
        self.assertEqual(volume.identify_fs(self.image, 0), "FAT%d" % self.bits)
        self.assertEqual(self.layout["scheme"], "None (unpartitioned)")
        self.assertEqual(self.part["detected"], "FAT%d" % self.bits)
        self.assertEqual(self.part["label"], "STRATATEST")

    def test_bpb_fields(self):
        total, reserved, nfats, fat_size, root_entries = \
            build.FAT_GEOMETRY[self.bits]
        root_sectors = (root_entries * 32 + 511) // 512
        first_data = reserved + nfats * fat_size + root_sectors
        info = self.fs.info()
        self.assertEqual(info["bytes_per_sector"], 512)
        self.assertEqual(info["sectors_per_cluster"], 1)
        self.assertEqual(info["cluster_size"], C)
        self.assertEqual(info["fat_count"], nfats)
        self.assertEqual(info["fat_size_sectors"], fat_size)
        self.assertEqual(info["first_data_offset"], first_data * 512)
        self.assertEqual(info["cluster_count"], total - first_data)
        self.assertEqual(info["root_cluster"],
                         L["root_cluster_fat32"] if self.bits == 32 else 0)
        self.assertEqual(info["label"], "STRATATEST")
        self.assertEqual(self.fs.total_sectors, total)
        self.assertEqual(self.fs.reserved_sectors, reserved)
        self.assertEqual(self.fs.root_entries, root_entries)

    def test_root_listing(self):
        self.assertEqual(set(self.root), {
            "HELLO.TXT", "Long file name.txt", "SUBDIR", "_ELETED.TXT",
            self.root_deleted_lfn_name(), "CYCLE.BIN", build.GONE_NAME})
        # The volume label entry is metadata, not a file.
        self.assertNotIn("STRATATEST", self.root)
        self.assertTrue(self.root["SUBDIR"]["is_dir"])
        self.assertEqual(self.root["HELLO.TXT"]["path"], "/HELLO.TXT")

    def root_deleted_lfn_name(self):
        # Deliberately taken from the listing: its exact spelling is covered
        # (as a known bug) in FatDirectoryEntries.
        return next(e["name"] for e in self.root.values()
                    if e["short_name"] == "_EMOVE~1.TXT")

    def test_single_cluster_file_content(self):
        e = self.root["HELLO.TXT"]
        self.assertEqual(e["start_cluster"], L["hello"]["cluster"])
        self.assertEqual(self.fs.read_file(e), build.HELLO_TEXT)
        self.assertEqual(self.fs.read_file(e, max_bytes=5), b"Hello")

    def test_fragmented_chain_content_and_runs(self):
        e = self.root["Long file name.txt"]
        self.assertEqual(self.fs.chain(e["start_cluster"]),
                         list(build.LONG_CLUSTERS))
        self.assertEqual(self.fs.read_file(e), build.long_content())
        runs = self.fs.runs(e["start_cluster"], e["size"])
        self.assertEqual(
            [(r["offset"], r["length"], r["used"], r["clusters"])
             for r in runs],
            [(self.fs.cluster_offset(4), 2 * C, 2 * C, 2),
             (self.fs.cluster_offset(9), C, 100, 1)])

    def test_read_range_across_fragment_boundary(self):
        e = self.root["Long file name.txt"]
        want = build.long_content()
        self.assertEqual(self.fs.read_range(e, 1000, 100), want[1000:1100])
        # Reads are clamped to the file size.
        self.assertEqual(self.fs.read_range(e, 1100, 500), want[1100:])
        self.assertEqual(self.fs.read_range(e, 5000, 10), b"")

    def test_subdirectory_spanning_two_clusters(self):
        sub = self.root["SUBDIR"]
        self.assertEqual(self.fs.chain(sub["start_cluster"]),
                         list(L["subdir"]["clusters"]))
        entries = by_name(self.fs.listdir(sub["start_cluster"], "/SUBDIR"))
        self.assertNotIn(".", entries)
        self.assertNotIn("..", entries)
        self.assertEqual(len(entries), L["subdir_fillers"] + 1)
        nested = entries["NESTED.BIN"]
        self.assertEqual(nested["path"], "/SUBDIR/NESTED.BIN")
        self.assertEqual(self.fs.read_file(nested), build.nested_content())

    def test_cyclic_chain_is_cut_not_followed_forever(self):
        e = self.root["CYCLE.BIN"]
        self.assertEqual(self.fs.chain(e["start_cluster"]),
                         list(L["cycle"]["clusters"]))
        self.assertEqual(self.fs.read_file(e), b"A" * C + b"B" * C)

    def test_allocated_extents_cover_live_files_only(self):
        extents = self.fs.allocated_extents()
        starts = {s for s, _ in extents}
        self.assertIn(self.fs.cluster_offset(L["hello"]["cluster"]), starts)
        self.assertIn(self.fs.cluster_offset(L["nested"]["clusters"][0]),
                      starts)
        self.assertNotIn(self.fs.cluster_offset(L["deleted"]["cluster"]),
                         starts)


class Fat12(_FatWidth, unittest.TestCase):
    bits = 12


class Fat16(_FatWidth, unittest.TestCase):
    bits = 16


class Fat32(_FatWidth, unittest.TestCase):
    bits = 32


class FatDirectoryEntries(unittest.TestCase):
    """Entry-level behaviour that does not depend on the FAT width (FAT16)."""

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()
        cls.image = cls.files.open(build.build_fat(16))
        _layout, _part, cls.fs = open_first_volume(cls.image)
        cls.entries = cls.fs.listdir(0)
        cls.root = by_name(cls.entries)

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    def test_timestamps(self):
        e = self.root["HELLO.TXT"]
        # 10:20:30 plus a 10 ms-resolution byte of 150 -> 31 s.
        self.assertEqual(e["created"], "2024-03-15T10:20:31")
        self.assertEqual(e["modified"], "2024-03-15T13:45:30")
        self.assertEqual(e["accessed"], "2024-03-16T00:00:00")
        self.assertIsNone(self.root["CYCLE.BIN"]["modified"])

    def test_attributes(self):
        self.assertEqual(self.root["HELLO.TXT"]["attributes"], ["archive"])
        self.assertEqual(self.root["SUBDIR"]["attributes"], ["directory"])

    def test_long_filename_and_short_alias(self):
        e = self.root["Long file name.txt"]
        self.assertEqual(e["short_name"], "LONGFI~1.TXT")
        self.assertFalse(e["deleted"])

    def test_deleted_entry_without_lfn(self):
        e = self.root["_ELETED.TXT"]
        self.assertTrue(e["deleted"])
        self.assertEqual(e["size"], build.DELETED_SIZE)
        # The FAT chain is gone; content is read contiguously from the start.
        self.assertEqual(self.fs.read_file(e), build.deleted_content())
        self.assertEqual(self.fs.read_range(e, 500, 50),
                         build.deleted_content()[500:550])
        self.assertIn("recovery", self.fs.stat(e))

    def test_deleted_entry_first_character_recovered_from_lfn(self):
        # Deletion overwrites only the first byte of each entry; the long
        # name keeps the character the short name lost.
        e = self.root[build.GONE_NAME]
        self.assertTrue(e["deleted"])
        self.assertEqual(e["short_name"], "_ONEFI~1.TXT")
        self.assertEqual(self.fs.read_file(e), build.GONE_TEXT)
        by_short = {x["short_name"]: x for x in self.entries if x["deleted"]}
        self.assertEqual(self.fs.read_file(by_short["_EMOVE~1.TXT"]),
                         build.deleted_lfn_content())

    # Deletion overwrites every LFN sequence byte with 0xE5, so a multi-part
    # deleted name has to be assembled from on-disk order, not sequence.
    def test_deleted_multi_part_lfn_is_in_order(self):
        names = {e["name"] for e in self.entries if e["deleted"]}
        self.assertIn(build.DELETED_LFN_NAME, names)

    def test_file_slack(self):
        e = self.root["HELLO.TXT"]
        slack = self.fs.slack(e)
        off = self.fs.cluster_offset(L["hello"]["cluster"])
        self.assertEqual(slack, {"offset": off + len(build.HELLO_TEXT),
                                 "length": C - len(build.HELLO_TEXT)})
        got = self.fs.source.read_at(slack["offset"], slack["length"])
        self.assertEqual(got, build.fill(slack["length"], build.SLACK_MARK))
        self.assertEqual(self.fs.stat(e)["slack"], slack)

    def test_no_slack_for_directories_or_exact_fit(self):
        self.assertIsNone(self.fs.slack(self.root["SUBDIR"]))
        exact = dict(self.root["HELLO.TXT"], size=C)
        self.assertIsNone(self.fs.slack(exact))

    # A deleted file's FAT chain is freed, so slack and runs follow the
    # contiguous clusters read_file() reads, not the one-cluster chain.
    def test_deleted_multi_cluster_file_slack_follows_its_content(self):
        e = self.root["_ELETED.TXT"]
        tail = build.DELETED_SIZE - C
        self.assertEqual(self.fs.slack(e), {
            "offset": self.fs.cluster_offset(L["deleted"]["cluster"] + 1)
            + tail,
            "length": C - tail})
        got = self.fs.source.read_at(self.fs.slack(e)["offset"], C - tail)
        self.assertEqual(got, build.fill(C - tail, build.SLACK_MARK))

    def test_no_slack_when_clusters_cannot_hold_the_file(self):
        last = self.fs.cluster_count + 1
        cut = dict(self.root["_ELETED.TXT"], start_cluster=last)
        self.assertIsNone(self.fs.slack(cut))
        self.assertIsNone(self.fs.slack(dict(cut, start_cluster=last + 5)))

    def test_deleted_multi_cluster_file_runs_cover_its_content(self):
        e = self.root["_ELETED.TXT"]
        start = L["deleted"]["cluster"]
        self.assertEqual(self.fs.stat(e)["runs"], [{
            "offset": self.fs.cluster_offset(start), "length": 2 * C,
            "used": build.DELETED_SIZE, "cluster": start, "clusters": 2}])


class FatInMbrPartition(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    def test_partition_found_and_opened(self):
        image = self.files.open(build.wrap_mbr(build.build_fat(16), 63, 0x06))
        scheme, parts = volume.parse_mbr(image)
        self.assertEqual(scheme, "MBR")
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["offset"], 63 * 512)
        self.assertEqual(parts[0]["type"], "FAT16")
        layout, part, fs = open_first_volume(image)
        self.assertEqual(layout["scheme"], "MBR")
        self.assertEqual(part["detected"], "FAT16")
        self.assertEqual(part["label"], "STRATATEST")
        self.assertIn("HELLO.TXT", by_name(fs.listdir(0)))
        self.assertEqual(fs.read_file(by_name(fs.listdir(0))["HELLO.TXT"]),
                         build.HELLO_TEXT)

    def test_table_type_disagreeing_with_boot_record_is_noted(self):
        image = self.files.open(build.wrap_mbr(build.build_fat(12), 63, 0x83))
        part = next(p for p in volume.scan(image)["partitions"]
                    if p.get("slot") == "MBR 1")
        self.assertEqual(part["detected"], "FAT12")
        self.assertIn("FAT12", part.get("note", ""))


class FatRobustness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.good = build.build_fat(12)

    def open_bytes(self, data):
        return ntfs.open_fs(OffsetReader(BytesImage(data), 0, len(data)))

    def test_random_garbage_is_not_a_filesystem(self):
        rng = random.Random(1234)
        junk = bytes(rng.getrandbits(8) for _ in range(64 * 1024))
        with self.assertRaises(ValueError):
            self.open_bytes(junk)
        with self.assertRaises(ValueError):
            fat.FatFS(BytesImage(junk))

    def test_garbage_bpb_with_boot_signature_is_rejected(self):
        rng = random.Random(99)
        junk = bytearray(rng.getrandbits(8) for _ in range(8192))
        junk[11:13] = b"\x00\x03"         # 768 bytes per sector: implausible
        junk[510:512] = b"\x55\xAA"
        with self.assertRaises(ValueError):
            fat.FatFS(BytesImage(junk))

    def test_empty_and_tiny_images(self):
        for data in (b"", b"\x00" * 100, self.good[:511]):
            with self.assertRaises(ValueError):
                self.open_bytes(data)

    def test_truncated_volume_is_refused(self):
        files = ImageFiles()
        self.addCleanup(files.close)
        image = files.open(self.good[:4096])
        with self.assertRaises(ValueError):
            ntfs.open_fs(OffsetReader(image, 0, image.size))

    def test_listing_a_nonsense_cluster_is_empty(self):
        fs = fat.FatFS(BytesImage(self.good))
        self.assertEqual(fs.listdir(0x0FFFFFF0), [])
        self.assertEqual(fs.chain(1), [])

    def test_mutated_boot_sector_fails_cleanly(self):
        # Every BPB byte set to 0x00 and 0xFF in turn: the parser either
        # refuses the volume with ValueError or lists it without crashing.
        for at in range(11, 62):
            for value in (0x00, 0xFF):
                data = bytearray(self.good)
                data[at] = value
                try:
                    fs = fat.FatFS(BytesImage(data))
                except ValueError:
                    continue
                with self.subTest(offset=at, value=value):
                    self.assertIsInstance(fs.listdir(0), list)

    def test_mutated_root_directory_does_not_crash(self):
        fs = fat.FatFS(BytesImage(self.good))
        root = (fs.reserved_sectors + fs.num_fats * fs.fat_size) * 512
        rng = random.Random(7)
        for trial in range(40):
            data = bytearray(self.good)
            for _ in range(16):
                data[root + rng.randrange(0, 12 * 32)] = rng.getrandbits(8)
            fs = fat.FatFS(BytesImage(data))
            with self.subTest(trial=trial):
                for e in fs.listdir(0):
                    if not e["is_dir"]:
                        fs.read_file(e, max_bytes=1 << 16)
                        fs.stat(e)


class LongNameChecksum(unittest.TestCase):
    """Long-name entries carry the checksum of the short name they were
    written for; entries left over from another file are not attached."""

    def volume_with(self, *entries):
        data = bytearray(build.build_fat(16))
        fs = fat.FatFS(BytesImage(data))
        raw, base = fs._read_dir_bytes(0)
        free = next(i for i in range(0, len(raw), 32) if raw[i] == 0)
        blob = b"".join(entries)
        data[base + free:base + free + len(blob)] = blob
        fs = fat.FatFS(BytesImage(data))
        return {e["short_name"]: e for e in fs.listdir(0)}

    def test_orphaned_deleted_long_name_is_not_given_to_a_live_file(self):
        got = self.volume_with(
            *build.lfn_entries("Old secret plan.txt", b"OLDSEC~1TXT",
                               deleted=True),
            build.short_entry(b"B       TXT", 0x20, 0, 0))
        self.assertEqual(got["B.TXT"]["name"], "B.TXT")

    def test_live_long_name_after_orphaned_entries_is_kept(self):
        got = self.volume_with(
            *build.lfn_entries("Old secret plan.txt", b"OLDSEC~1TXT",
                               deleted=True),
            *build.lfn_entries("New notes.txt", b"NEWNOT~1TXT"),
            build.short_entry(b"NEWNOT~1TXT", 0x20, 0, 0))
        self.assertEqual(got["NEWNOT~1.TXT"]["name"], "New notes.txt")

    def test_long_name_with_the_wrong_checksum_is_not_attached(self):
        got = self.volume_with(
            *build.lfn_entries("Someone else.txt", b"SOMEON~1TXT"),
            build.short_entry(b"MINE    TXT", 0x20, 0, 0))
        self.assertEqual(got["MINE.TXT"]["name"], "MINE.TXT")

    def test_deleted_file_keeps_its_own_deleted_long_name(self):
        short = bytearray(build.short_entry(b"REPORT~1TXT", 0x20, 0, 0))
        short[0] = 0xE5
        got = self.volume_with(
            *build.lfn_entries("Quarterly report.txt", b"REPORT~1TXT",
                               deleted=True),
            bytes(short))
        self.assertEqual(got["_EPORT~1.TXT"]["name"], "Quarterly report.txt")


if __name__ == "__main__":
    unittest.main()
