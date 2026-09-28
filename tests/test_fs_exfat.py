"""Unit tests for the exFAT parser (engine.fs.exfat).

The image comes from tests/imagebuild_fat.build_exfat() and is opened the
way the server opens evidence: ewf.open_image -> volume.scan -> OffsetReader
-> ntfs.open_fs (the filesystem dispatcher).
"""

import os
import random
import struct
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import imagebuild_fat as build                                   # noqa: E402
from test_fs_fat import BytesImage, ImageFiles, by_name, \
    open_first_volume                                            # noqa: E402
from engine import volume                                        # noqa: E402
from engine.ewf import OffsetReader                              # noqa: E402
from engine.fs import exfat, ntfs                                # noqa: E402
from engine.fs.streams import UnsupportedStream                  # noqa: E402

C = build.EXFAT_CLUSTER
L = build.EXFAT_LAYOUT


class Exfat(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()
        cls.data = build.build_exfat()
        cls.image = cls.files.open(cls.data)
        cls.layout, cls.part, cls.fs = open_first_volume(cls.image)
        cls.root = by_name(cls.fs.listdir(0))

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    # -- boot record and volume metadata ---------------------------------

    def test_dispatcher_and_probe(self):
        self.assertIsInstance(self.fs, exfat.ExfatFS)
        self.assertEqual(volume.identify_fs(self.image, 0), "exFAT")
        self.assertEqual(self.part["detected"], "exFAT")
        self.assertEqual(self.part["label"], build.EXFAT_LABEL)

    def test_boot_record_fields(self):
        info = self.fs.info()
        self.assertEqual(info["bytes_per_sector"], 512)
        self.assertEqual(info["sectors_per_cluster"], 2)
        self.assertEqual(info["cluster_size"], C)
        self.assertEqual(info["cluster_count"], build.EXFAT_CLUSTERS)
        self.assertEqual(info["fat_count"], 1)
        self.assertEqual(info["first_data_offset"],
                         build.EXFAT_HEAP_OFFSET * 512)
        self.assertEqual(info["root_cluster"], L["root"][0])
        self.assertEqual(info["serial"], "%08X" % build.EXFAT_SERIAL)
        self.assertEqual(info["revision"], "1.0")
        self.assertEqual(info["percent_in_use"], 30)
        self.assertFalse(info["volume_dirty"])
        self.assertEqual(info["label"], build.EXFAT_LABEL)

    def test_allocation_bitmap(self):
        self.assertEqual(self.fs._bitmap_start, L["bitmap"])
        bitmap = self.fs._load_bitmap()
        self.assertEqual(len(bitmap), (build.EXFAT_CLUSTERS + 7) // 8)

        def allocated(c):
            return bool(bitmap[(c - 2) // 8] >> ((c - 2) % 8) & 1)

        for c in (L["bitmap"], L["upcase"], L["hello"]["cluster"],
                  L["contiguous"]["cluster"] + 2, L["subdir"]["cluster"] + 1):
            self.assertTrue(allocated(c), c)
        self.assertFalse(allocated(L["deleted"]["cluster"]))
        self.assertFalse(allocated(40))
        # The bitmap's own cluster is reported as allocated space.
        off = self.fs.cluster_offset(L["bitmap"])
        self.assertIn((off, off + C), self.fs.allocated_extents())

    def test_up_case_table_is_metadata_not_a_file(self):
        # The up-case entry sits between the bitmap entry and the files;
        # it must neither appear as a file nor stop the root scan.
        names = set(self.root)
        self.assertFalse(any("upcase" in n.lower() for n in names))
        self.assertIn("Hello.txt", names)
        table = self.fs.source.read_at(self.fs.cluster_offset(L["upcase"]),
                                       256)
        self.assertEqual(table, build.upcase_table())

    # -- directory listing ------------------------------------------------

    def test_root_listing(self):
        self.assertEqual(set(self.root), {
            "Hello.txt", "Fragmented file.bin", "Contiguous.dat",
            "Deleted file.txt", "Timezone.txt", "Empty.txt",
            build.EXFAT_LONG_NAME, "Subdir", "Tail.txt"})
        # Directories sort first.
        self.assertEqual(self.fs.listdir(0)[0]["name"], "Subdir")
        self.assertTrue(self.root["Subdir"]["is_dir"])
        self.assertTrue(self.root["Subdir"]["contiguous"])

    def test_root_directory_follows_its_fat_chain(self):
        self.assertEqual(self.fs.chain(L["root"][0]), list(L["root"]))
        tail = self.root["Tail.txt"]           # entry set straddles clusters
        self.assertEqual(self.fs.read_file(tail), b"tail")

    def test_three_part_file_name(self):
        e = self.root[build.EXFAT_LONG_NAME]
        self.assertEqual(e["path"], "/" + build.EXFAT_LONG_NAME)
        self.assertEqual(self.fs.read_file(e), b"long name\n")

    def test_timestamps_and_attributes(self):
        e = self.root["Hello.txt"]
        # Hello.txt records no valid UTC offset, so no zone is claimed.
        self.assertEqual(e["modified"], "2023-11-05T08:30:44")
        self.assertEqual(e["accessed"], "2023-11-05T08:30:44")
        self.assertEqual(e["attributes"], ["archive"])

    # The offset bytes (spec 7.4.10) now shift the local timestamp into UTC:
    # 10:00 at +12:00 is 22:00 UTC the previous day.
    def test_timestamp_honours_utc_offset(self):
        self.assertEqual(self.root["Timezone.txt"]["created"],
                         "2024-05-31T22:00:00Z")

    def test_subdirectory_first_cluster(self):
        sub = self.root["Subdir"]
        inner = by_name(self.fs.listdir(sub["start_cluster"], "/Subdir"))
        self.assertIn("Inner.txt", inner)
        self.assertEqual(inner["Inner.txt"]["path"], "/Subdir/Inner.txt")
        self.assertEqual(self.fs.read_file(inner["Inner.txt"]), b"inner\n")

    # A NoFatChain directory's FAT entries are zero, so its clusters come
    # from the stream extension in its parent, not from the FAT.
    def test_bytes_past_valid_data_length_read_as_zeros(self):
        e = dict(self.root["Contiguous.dat"], valid_size=1000)
        full = build.exfat_contiguous_content()
        want = full[:1000] + bytes(3000 - 1000)
        self.assertEqual(self.fs.read_file(e), want)
        self.assertEqual(self.fs.read_range(e, 990, 20), want[990:1010])
        self.assertEqual(self.fs.read_range(e, 2000, 10), bytes(10))
        self.assertIn("read as zeros", self.fs.stat(e)["note"])
        # Fully valid, the file reads as it always did.
        self.assertEqual(self.fs.read_file(self.root["Contiguous.dat"]), full)

    def test_contiguous_subdirectory_second_cluster_listed(self):
        sub = self.root["Subdir"]
        inner = by_name(self.fs.listdir(sub["start_cluster"], "/Subdir"))
        self.assertIn("Second.txt", inner)
        self.assertEqual(inner["Second.txt"]["path"], "/Subdir/Second.txt")
        self.assertEqual(self.fs.read_file(inner["Second.txt"]), b"second\n")

    def test_contiguous_subdirectory_listed_before_its_parent(self):
        # A node can arrive without its parent listed first (a saved case,
        # a bookmark), so the stream is found from the root down.
        fs = ntfs.open_fs(OffsetReader(self.image, self.part["offset"],
                                       self.part["size"], self.part["slot"]))
        inner = by_name(fs.listdir(self.root["Subdir"]["start_cluster"],
                                   "/Subdir"))
        self.assertEqual(set(inner), {"Inner.txt", "Second.txt"})

    # -- file content ------------------------------------------------------

    def test_fat_chain_stream(self):
        e = self.root["Fragmented file.bin"]
        self.assertFalse(e["contiguous"])
        want = build.exfat_fragmented_content()
        self.assertEqual(self.fs.read_file(e), want)
        self.assertEqual(self.fs.read_file(e, max_bytes=1500), want[:1500])
        self.assertEqual(self.fs.read_range(e, 1000, 1100), want[1000:2100])
        runs = self.fs.runs(e)
        self.assertEqual([(r["cluster"], r["clusters"], r["used"])
                          for r in runs], [(7, 1, C), (9, 1, C), (8, 1, 452)])

    def test_no_fat_chain_contiguous_stream(self):
        e = self.root["Contiguous.dat"]
        self.assertTrue(e["contiguous"])
        # Nothing in the FAT describes this file; the extent comes from the
        # stream extension alone.
        c0 = L["contiguous"]["cluster"]
        for c in range(c0, c0 + L["contiguous"]["count"]):
            self.assertEqual(self.fs._fat_entry(c), 0)
        want = build.exfat_contiguous_content()
        self.assertEqual(self.fs.read_file(e), want)
        self.assertEqual(self.fs.read_range(e, 2000, 2000), want[2000:])
        runs = self.fs.runs(e)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["offset"], self.fs.cluster_offset(c0))
        self.assertEqual(runs[0]["length"], 3 * C)
        self.assertEqual(runs[0]["used"], 3000)
        self.assertTrue(self.fs.stat(e)["contiguous"])

    def test_empty_file(self):
        e = self.root["Empty.txt"]
        self.assertEqual(self.fs.read_file(e), b"")
        self.assertEqual(self.fs.read_range(e, 0, 10), b"")
        self.assertIsNone(self.fs.slack(e))
        self.assertEqual(self.fs.runs(e), [])

    def test_named_streams_are_refused(self):
        with self.assertRaises(UnsupportedStream):
            self.fs.read_file(self.root["Hello.txt"], stream="ads")

    def test_deleted_entry(self):
        e = self.root["Deleted file.txt"]
        self.assertTrue(e["deleted"])
        self.assertTrue(e["contiguous"])
        self.assertEqual(e["size"], 100)
        self.assertEqual(self.fs.read_file(e), build.pattern(100, 13))
        self.assertIn("contiguous", self.fs.stat(e)["recovery"])
        # Deleted files are not allocated space.
        off = self.fs.cluster_offset(L["deleted"]["cluster"])
        self.assertNotIn(off, {s for s, _ in self.fs.allocated_extents()})

    def test_slack(self):
        e = self.root["Hello.txt"]
        n = len(build.EXFAT_HELLO)
        slack = self.fs.slack(e)
        self.assertEqual(slack, {
            "offset": self.fs.cluster_offset(L["hello"]["cluster"]) + n,
            "length": C - n})
        self.assertEqual(self.fs.source.read_at(slack["offset"],
                                                slack["length"]),
                         build.fill(C - n, build.SLACK_MARK))
        self.assertEqual(self.fs.stat(e)["slack"], slack)

        cont = self.fs.slack(self.root["Contiguous.dat"])
        self.assertEqual(cont, {
            "offset": self.fs.cluster_offset(L["contiguous"]["cluster"] + 2)
            + (3000 - 2 * C),
            "length": 3 * C - 3000})
        self.assertIsNone(self.fs.slack(self.root["Subdir"]))


class ExfatRobustness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.good = build.build_exfat()

    def open_bytes(self, data):
        return ntfs.open_fs(OffsetReader(BytesImage(data), 0, len(data)))

    def test_truncated_to_boot_sector(self):
        files = ImageFiles()
        self.addCleanup(files.close)
        image = files.open(self.good[:512])
        try:
            fs = ntfs.open_fs(OffsetReader(image, 0, image.size))
        except ValueError:
            return
        self.assertEqual(fs.listdir(0), [])

    def test_contiguous_directory_claiming_huge_length_reads_to_its_end(self):
        fs = self.open_bytes(self.good)
        sub = by_name(fs.listdir(0))["Subdir"]
        data = bytearray(self.good)
        streams = [k for k in range(0, len(data) - 31, 32)
                   if data[k] == 0xC0 and struct.unpack(
                       "<I", data[k + 20:k + 24])[0] == sub["start_cluster"]]
        self.assertEqual(len(streams), 1)
        at = streams[0] + 24                       # stream extension length
        data[at:at + 8] = struct.pack("<Q", 1 << 40)

        reads = []

        class Counting(BytesImage):
            def read_at(self, offset, length):
                reads.append(length)
                return BytesImage.read_at(self, offset, length)

        fs = ntfs.open_fs(OffsetReader(Counting(data), 0, len(data)))
        fs.listdir(0)
        del reads[:]
        inner = by_name(fs.listdir(sub["start_cluster"], "/Subdir"))
        self.assertEqual(set(inner), {"Inner.txt", "Second.txt"})
        self.assertLessEqual(sum(reads), 2 * C)

    def test_truncated_mid_heap(self):
        fs = self.open_bytes(self.good[:self.good.index(b"Hello, exFAT")])
        for e in fs.listdir(0):
            self.assertIsInstance(fs.read_file(e), bytes)

    def test_implausible_shifts_rejected(self):
        for at, value in ((108, 0), (108, 20), (109, 40)):
            data = bytearray(self.good)
            data[at] = value
            with self.subTest(offset=at, value=value):
                with self.assertRaises(ValueError):
                    exfat.ExfatFS(BytesImage(data))

    def test_signature_only_is_not_exfat(self):
        data = bytearray(self.good)
        data[3:11] = b"EXFAX   "
        with self.assertRaises(ValueError):
            exfat.ExfatFS(BytesImage(data))

    def fat_offset(self, cluster):
        return build.EXFAT_FAT_OFFSET * 512 + cluster * 4

    def test_root_chain_loop_terminates(self):
        data = bytearray(self.good)
        struct.pack_into("<I", data, self.fat_offset(L["root"][1]),
                         L["root"][0])
        fs = exfat.ExfatFS(BytesImage(data))
        self.assertEqual(fs.chain(L["root"][0]), list(L["root"]))
        self.assertEqual(len(fs.listdir(0)), 9)

    def test_absurd_secondary_count(self):
        data = bytearray(self.good)
        # Tail.txt's set straddles root clusters 4 and 15; its File entry is
        # the last entry of cluster 4.
        file_entry = (build.EXFAT_HEAP_OFFSET * 512
                      + (L["root"][0] - 2) * C + C - 32)
        self.assertEqual(data[file_entry], 0x85)
        data[file_entry + 1] = 0xFF
        fs = exfat.ExfatFS(BytesImage(data))
        self.assertIsInstance(fs.listdir(0), list)

    def test_random_entry_header_damage_does_not_crash(self):
        # Damage confined to each entry's type, secondary-count, flag and
        # name-length bytes. Length fields are left alone: a huge
        # NoFatChain length is the unbounded case tested separately below.
        root = build.EXFAT_HEAP_OFFSET * 512 + (L["root"][0] - 2) * C
        rng = random.Random(4321)
        for trial in range(40):
            data = bytearray(self.good)
            for _ in range(12):
                data[root + rng.randrange(0, C // 32) * 32
                     + rng.randrange(0, 4)] = rng.getrandbits(8)
            with self.subTest(trial=trial):
                fs = exfat.ExfatFS(BytesImage(data))
                for e in fs.listdir(0):
                    if not e["is_dir"] and e["size"] <= 1 << 20:
                        fs.read_file(e, max_bytes=1 << 16)
                        fs.stat(e)

    # Bug: exfat.py chain() (line 86) expands a NoFatChain stream into one
    # list element per cluster from the untrusted length, unbounded by the
    # cluster count, so a corrupt length of 2^50 means a 2^40-element list
    # (hang / MemoryError) on any read. Kept small here: 64 MiB, 65536 items.
    def test_contiguous_run_bounded_by_cluster_heap(self):
        data = bytearray(self.good)
        stream = self.good.index("Contiguous.dat".encode("utf-16-le")) - 34
        self.assertEqual(data[stream], 0xC0)
        struct.pack_into("<Q", data, stream + 24, 64 << 20)
        fs = exfat.ExfatFS(BytesImage(data))
        e = by_name(fs.listdir(0))["Contiguous.dat"]
        heap_end = fs.cluster_offset(fs.cluster_count + 2)
        for r in fs.runs(e):
            self.assertLessEqual(r["offset"] + r["length"], heap_end)

    # Bug: exfat.py trusts the boot sector's cluster_count (offset 92), so a
    # 0xFFFFFFFF value defeats the heap-end clamp in chain() (the #17 fix)
    # and a NoFatChain stream still expands by the billions.
    def test_cluster_count_bounded_by_image(self):
        data = bytearray(self.good)
        struct.pack_into("<I", data, 92, 0xFFFFFFFF)
        fs = exfat.ExfatFS(BytesImage(data))
        held = max(0, (len(data) - fs.data_offset) // fs.cluster_size)
        self.assertEqual(fs.cluster_count, held)
        self.assertIn("trusting the image", " ".join(fs.findings))
        e = by_name(fs.listdir(0))["Contiguous.dat"]
        heap_end = fs.cluster_offset(fs.cluster_count + 2)
        for r in fs.runs(e):
            self.assertLessEqual(r["offset"] + r["length"], heap_end)

    # A contiguous (NoFatChain) stream is one run end to end; chain() must
    # not build a list of every cluster in it to discover that, or a large
    # genuine volume with a huge claimed run costs memory proportional to
    # its cluster count (residual of #15/#19, issue #43).
    def test_huge_contiguous_run_stays_flat(self):
        data = bytearray(self.good)
        fs = exfat.ExfatFS(BytesImage(data))
        e = dict(by_name(fs.listdir(0))["Contiguous.dat"])
        # A large genuine volume: billions of clusters, all real (no
        # boot-sector lie for the heap-end clamp to catch), and a file
        # claiming to span most of it.
        fs.cluster_count = 2_000_000_000
        e["size"] = 1_000_000_000 * fs.cluster_size

        chain = fs.chain(e["start_cluster"], True, e["size"])
        self.assertIsInstance(chain, range)
        self.assertEqual(len(chain), 1_000_000_000)

        t0 = time.time()
        runs = fs.runs(e)
        self.assertLess(time.time() - t0, 1.0)
        self.assertEqual(runs, [{
            "offset": fs.cluster_offset(e["start_cluster"]),
            "length": e["size"], "used": e["size"],
            "cluster": e["start_cluster"], "clusters": 1_000_000_000,
            "sparse": False}])

    def test_random_garbage_is_not_exfat(self):
        rng = random.Random(5)
        junk = bytes(rng.getrandbits(8) for _ in range(16384))
        with self.assertRaises(ValueError):
            exfat.ExfatFS(BytesImage(junk))


if __name__ == "__main__":
    unittest.main()
