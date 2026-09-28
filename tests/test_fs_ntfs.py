"""Unit tests for the NTFS parser (engine.fs.ntfs), LZNT1 (engine.fs.lznt1)
and the GPT reader (engine.volume.parse_gpt).

Images come from tests/imagebuild_ntfs.py and are opened the way the server
opens evidence: ewf.open_image -> volume.scan -> OffsetReader -> ntfs.open_fs.
"""

import os
import random
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import imagebuild_ntfs as build                                  # noqa: E402
from test_fs_fat import BytesImage, ImageFiles, by_name, \
    open_first_volume                                            # noqa: E402
from engine import volume                                        # noqa: E402
from engine.ewf import OffsetReader                              # noqa: E402
from engine.fs import lznt1, ntfs                                # noqa: E402
from engine.fs.streams import NoSuchStream                       # noqa: E402

C = build.CLUSTER
REC = build.REC


class NtfsOnGpt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.files = ImageFiles()
        cls.volume = build.build_ntfs()
        cls.image = cls.files.open(build.wrap_gpt(cls.volume))
        cls.layout, cls.part, cls.fs = open_first_volume(cls.image)
        cls.root = by_name(cls.fs.listdir(5))

    @classmethod
    def tearDownClass(cls):
        cls.files.close()

    # -- partition table and boot sector ------------------------------------

    def test_gpt_partition_detected(self):
        scheme, parts, findings = volume.parse_gpt(self.image)
        self.assertEqual(scheme, "GPT")
        self.assertEqual(findings, [])
        self.assertEqual(len(parts), 1)
        p = parts[0]
        self.assertEqual(p["type"], "Microsoft Basic Data")
        self.assertEqual(p["name"], "Strata data")
        self.assertEqual(p["offset"], 2048 * 512)
        self.assertEqual(p["size"], len(self.volume))
        self.assertEqual(self.layout["scheme"], "GPT")
        self.assertEqual(self.part["detected"], "NTFS")
        self.assertEqual(self.part["label"], build.VOLUME_LABEL)

    def test_damaged_primary_gpt_falls_back_to_backup(self):
        disk = bytearray(build.wrap_gpt(self.volume))
        disk[2 * 512 + 60] ^= 0xFF                 # inside the entry name
        scheme, parts, findings = volume.parse_gpt(BytesImage(disk))
        self.assertEqual(scheme, "GPT")
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["name"], "Strata data")
        text = " ".join(findings)
        self.assertIn("checksum", text)
        self.assertIn("backup", text)

    def test_mbr_view_is_protective(self):
        scheme, parts = volume.parse_mbr(self.image)
        self.assertEqual(scheme, "GPT protective")

    def test_boot_sector_fields(self):
        self.assertIsInstance(self.fs, ntfs.NtfsFS)
        info = self.fs.info()
        self.assertEqual(info["label"], build.VOLUME_LABEL)
        self.assertEqual(info["bytes_per_sector"], 512)
        self.assertEqual(info["sectors_per_cluster"], 2)
        self.assertEqual(info["cluster_size"], C)
        self.assertEqual(info["mft_offset"], build.MFT_LCN * C)
        self.assertEqual(info["mft_record_size"], build.RECORD)
        self.assertEqual(info["mft_records"], build.MFT_RECORDS)
        self.assertEqual(info["serial"], "%016X" % build.SERIAL)
        self.assertEqual(self.fs.mftmirr_cluster, build.MFTMIRR_LCN)

    # -- records, fixups, names, timestamps ---------------------------------

    def test_root_listing(self):
        for name in ("hello.txt", "big.bin", "ads.txt", "deleted.txt", "Docs",
                     "sparse.bin", "compressed.txt",
                     "Long filename document.txt", "fixup.txt", "torn.txt",
                     "$MFT", "$Volume"):
            self.assertIn(name, self.root)
        self.assertNotIn("note.txt", self.root)
        self.assertEqual(self.root["hello.txt"]["path"], "/hello.txt")
        self.assertTrue(self.root["Docs"]["is_dir"])
        self.assertTrue(self.root["$MFT"]["system"])

    def test_directory_listing(self):
        docs = self.root["Docs"]
        inside = self.fs.listdir(docs["mft"], "/Docs")
        self.assertEqual([e["name"] for e in inside], ["note.txt"])
        self.assertEqual(inside[0]["path"], "/Docs/note.txt")
        self.assertEqual(self.fs.read_file(inside[0]), build.NOTE_TEXT)

    def test_fixups_restore_bytes_at_stride_end(self):
        e = self.root["fixup.txt"]
        self.assertTrue(e["fixup_ok"])
        self.assertEqual(self.fs.read_file(e), build.fixup_content())

    def test_torn_record_flagged(self):
        e = self.root["torn.txt"]
        self.assertFalse(e["fixup_ok"])
        self.assertTrue(self.root["hello.txt"]["fixup_ok"])

    def test_apply_fixups_directly(self):
        raw = build.mft_record(40, [build.resident_attr(
            0x80, bytes(range(256)) * 3)])
        self.assertEqual(raw[510:512], build.USN)
        fixed, ok = ntfs.apply_fixups(raw, 512)
        self.assertTrue(ok)
        self.assertNotEqual(fixed[510:512], build.USN)
        torn = build.mft_record(40, [], tear=True)
        self.assertFalse(ntfs.apply_fixups(torn, 512)[1])
        self.assertEqual(ntfs.apply_fixups(b"FILE", 512), (b"FILE", False))

    def test_si_and_fn_timestamps_are_kept_apart(self):
        rec = self.fs.record(REC["hello"])
        si, fn = build.SI_TIMES, build.FN_TIMES
        self.assertEqual(rec.si["created"], build.iso(si["created"]))
        self.assertEqual(rec.si["modified"], build.iso(si["modified"]))
        self.assertEqual(rec.si["mft_modified"], build.iso(si["mft_modified"]))
        self.assertEqual(rec.si["accessed"], build.iso(si["accessed"]))
        name = rec.names[0]
        self.assertEqual(name["fn_created"], build.iso(fn["created"]))
        self.assertEqual(name["fn_modified"], build.iso(fn["modified"]))
        self.assertEqual(name["fn_mft_modified"],
                         build.iso(fn["mft_modified"]))
        self.assertEqual(name["fn_accessed"], build.iso(fn["accessed"]))
        node = self.root["hello.txt"]
        self.assertEqual(node["created"], build.iso(si["created"]))
        self.assertEqual(node["fn_created"], build.iso(fn["created"]))
        self.assertEqual(node["fn_modified"], build.iso(fn["modified"]))

    def test_win32_name_preferred_over_dos_name(self):
        e = self.root["Long filename document.txt"]
        names = self.fs.stat(e)["names"]
        self.assertEqual({n["name"]: n["namespace"] for n in names},
                         {"Long filename document.txt": 1, "LONGFI~1.TXT": 2})
        self.assertNotIn("LONGFI~1.TXT", self.root)

    def test_deleted_record(self):
        e = self.root["deleted.txt"]
        self.assertTrue(e["deleted"])
        self.assertFalse(self.fs.record(REC["deleted"]).in_use)
        self.assertEqual(self.fs.read_file(e), build.DELETED_TEXT)
        self.assertIn("recovery", self.fs.stat(e))
        live = {s for s, _ in self.fs.allocated_extents()}
        self.assertIn(40 * C, live)

    # -- $DATA --------------------------------------------------------------

    def test_resident_data(self):
        e = self.root["hello.txt"]
        self.assertTrue(e["resident"])
        self.assertEqual(e["size"], len(build.HELLO_TEXT))
        self.assertEqual(self.fs.read_file(e), build.HELLO_TEXT)
        self.assertEqual(self.fs.read_range(e, 7, 4), b"NTFS")
        data = [a for a in self.fs.stat(e)["attributes"]
                if a["type"] == "$DATA"]
        self.assertTrue(data[0]["resident"])
        self.assertNotIn("slack", self.fs.stat(e))

    def test_non_resident_data_runs_and_slack(self):
        e = self.root["big.bin"]
        self.assertIsNone(e["resident"])
        want = build.big_content()
        self.assertEqual(self.fs.read_file(e), want)
        self.assertEqual(self.fs.read_range(e, 2000, 100), want[2000:2100])
        self.assertEqual(self.fs.read_file(e, max_bytes=10), want[:10])
        info = self.fs.stat(e)
        self.assertEqual(
            [(r["offset"], r["length"], r["used"]) for r in info["runs"]],
            [(40 * C, 2 * C, 2 * C), (60 * C, C, build.BIG_SIZE - 2 * C)])
        self.assertEqual(info["slack"], {"offset": 60 * C + C - 300,
                                         "length": 300})
        self.assertEqual(self.fs.source.read_at(60 * C + C - 300, 300),
                         build.fill(300, build.SLACK_MARK))

    def test_sparse_runs_read_as_zeros(self):
        e = self.root["sparse.bin"]
        want = build.sparse_content()
        self.assertEqual(self.fs.read_file(e), want)
        self.assertEqual(self.fs.read_range(e, 1000, 2200),
                         want[1000:3200])
        runs = self.fs.stat(e)["runs"]
        self.assertEqual([r["sparse"] for r in runs], [False, True, False])

    def test_decode_runlist_vector(self):
        # (40 x2) (+20 -> 60 x1) (sparse x3) (-50 -> 10 x1)
        raw = b"\x11\x02\x28\x11\x01\x14\x01\x03\x11\x01\xCE\x00"
        self.assertEqual(ntfs.decode_runlist(raw),
                         [(40, 2), (60, 1), (None, 3), (10, 1)])
        # The builder encodes the same list to the same bytes.
        self.assertEqual(build.encode_runs(
            [(40, 2), (60, 1), (None, 3), (10, 1)]), raw)

    def test_decode_runlist_stops_at_impossible_runs(self):
        findings = []
        runs = ntfs.decode_runlist(b"\x11\x02\x05\x11\x40\x01\x00", 20,
                                   findings)
        self.assertEqual(runs, [(5, 2)])
        self.assertEqual(findings, [ntfs.RUN_TOO_LONG])
        findings = []
        self.assertEqual(ntfs.decode_runlist(b"\x11\x01\xF0\x00", 20,
                                             findings), [])
        self.assertEqual(findings, [ntfs.RUN_OUT_OF_VOLUME])
        self.assertEqual(ntfs.decode_runlist(b"\x44\x01"), [])

    def test_decode_runlist_sparse_run_longer_than_volume(self):
        # A sparse file's hole can span more clusters than the volume holds;
        # only runs that occupy clusters are bounded by it.
        # (5 x2) (sparse x300) (+10 -> 15 x1), on a 20-cluster volume
        findings = []
        raw = b"\x11\x02\x05\x02\x2C\x01\x11\x01\x0A\x00"
        self.assertEqual(ntfs.decode_runlist(raw, 20, findings),
                         [(5, 2), (None, 300), (15, 1)])
        self.assertEqual(findings, [])

    # -- alternate data streams ---------------------------------------------

    def test_alternate_data_streams(self):
        e = self.root["ads.txt"]
        self.assertEqual(e["size"], len(build.ADS_MAIN))
        self.assertEqual(e["streams"], [
            {"name": "Zone.Identifier", "size": len(build.ZONE_ID)},
            {"name": "secret", "size": build.SECRET_SIZE}])
        self.assertEqual(self.fs.read_file(e), build.ADS_MAIN)
        self.assertEqual(self.fs.read_file(e, stream="Zone.Identifier"),
                         build.ZONE_ID)
        self.assertEqual(self.fs.read_file(e, stream="secret"),
                         build.secret_content())
        self.assertEqual(self.fs.read_range(e, 10, 5, stream="secret"),
                         build.secret_content()[10:15])
        streams = {s["name"]: s for s in self.fs.streams(e)}
        self.assertTrue(streams[""]["default"])
        self.assertTrue(streams["Zone.Identifier"]["resident"])
        self.assertFalse(streams["secret"]["resident"])
        info = self.fs.stat(e, "secret")
        self.assertEqual(info["runs"][0]["offset"], build.SECRET_LCN * C)
        self.assertEqual(info["slack"]["length"], C - build.SECRET_SIZE)

    def test_missing_stream(self):
        e = self.root["ads.txt"]
        with self.assertRaises(NoSuchStream) as ctx:
            self.fs.read_file(e, stream="nope")
        self.assertEqual(ctx.exception.available,
                         ["Zone.Identifier", "secret"])
        self.assertTrue(self.fs.stat(e, "nope")["stream_missing"])

    # -- compression --------------------------------------------------------

    def test_lznt1_compressed_attribute(self):
        e = self.root["compressed.txt"]
        self.assertEqual(self.fs.read_file(e), build.COMPRESSED_TEXT)
        self.assertEqual(self.fs.read_range(e, 600, 30),
                         build.COMPRESSED_TEXT[600:630])
        info = self.fs.stat(e)
        self.assertTrue(info["runs_compressed"])
        self.assertEqual(self.fs.findings, [])

    # -- known engine bugs --------------------------------------------------

    def test_invalid_record_stays_invalid_on_second_lookup(self):
        fs = ntfs.NtfsFS(BytesImage(self.volume))
        self.assertIsNone(fs.record(30))
        self.assertIsNone(fs.record(30))


class Lznt1(unittest.TestCase):

    def test_back_reference(self):
        self.assertEqual(lznt1.decompress(b"\x05\xb0\x08abc\x06\x20"),
                         b"abcabcabcabc")

    def test_displacement_width_grows_with_position(self):
        # 17 literals, then token 0x8007 at position 17: 5 displacement bits
        # and 11 length bits -> offset 17, length 10. A decoder still on the
        # 4/12 split would read offset 9 instead.
        body = (b"\x00ABCDEFGH" + b"\x00IJKLMNOP" + b"\x02Q"
                + struct.pack("<H", 0x8007))
        chunk = struct.pack("<H", 0xB000 | (len(body) - 1)) + body
        self.assertEqual(lznt1.decompress(chunk),
                         b"ABCDEFGHIJKLMNOPQ" + b"ABCDEFGHIJ")

    def test_uncompressed_chunk_and_padding(self):
        self.assertEqual(lznt1.decompress(b"\x04\x30hello"), b"hello")
        self.assertEqual(lznt1.decompress(b"\x04\x30hello", 8),
                         b"hello\x00\x00\x00")
        self.assertEqual(lznt1.decompress(b"\x00\x00trailing"), b"")

    def test_malformed_input_does_not_raise(self):
        good = b"\x05\xb0\x08abc\x06\x20"
        for cut in range(len(good)):
            self.assertIsInstance(lznt1.decompress(good[:cut]), bytes)
        # Back-reference before the start of output.
        self.assertEqual(lznt1.decompress(b"\x02\xb0\x01\x05\x00"), b"")
        rng = random.Random(3)
        for _ in range(200):
            junk = bytes(rng.getrandbits(8) for _ in range(64))
            self.assertIsInstance(lznt1.decompress(junk, 4096), bytes)


class NtfsRobustness(unittest.TestCase):
    """Nothing here lists a damaged volume: listdir walks every record the
    MFT claims."""

    @classmethod
    def setUpClass(cls):
        cls.good = build.build_ntfs()

    def open_bytes(self, data):
        return ntfs.open_fs(OffsetReader(BytesImage(data), 0, len(data)))

    def test_unpartitioned_probe(self):
        img = BytesImage(self.good)
        self.assertEqual(volume.identify_fs(img, 0), "NTFS")
        part = volume.scan(img)["partitions"][0]
        self.assertEqual(part["detected"], "NTFS")
        self.assertEqual(part["label"], build.VOLUME_LABEL)

    def test_random_garbage_is_not_a_filesystem(self):
        rng = random.Random(11)
        junk = bytes(rng.getrandbits(8) for _ in range(16384))
        with self.assertRaises(ValueError):
            self.open_bytes(junk)
        with self.assertRaises(ValueError):
            ntfs.NtfsFS(BytesImage(junk))

    def test_truncated_volume(self):
        files = ImageFiles()
        self.addCleanup(files.close)
        image = files.open(self.good[:8192])
        fs = ntfs.open_fs(OffsetReader(image, 0, image.size))
        self.assertIsNone(fs.record(REC["hello"]))
        self.assertIsInstance(fs.info(), dict)

    def test_mutated_boot_sector(self):
        for at in range(11, 80):
            for value in (0x00, 0x80, 0xFF):
                data = bytearray(self.good)
                data[at] = value
                with self.subTest(offset=at, value=value):
                    try:
                        fs = self.open_bytes(data)
                    except ValueError:
                        continue
                    rec = fs.record(REC["hello"])
                    if rec is not None:
                        self.assertIsInstance(rec.names, list)

    def record_offset(self, n):
        return build.MFT_LCN * C + n * build.RECORD

    def test_zero_attribute_length(self):
        data = bytearray(self.good)
        at = self.record_offset(REC["hello"]) + 56 + 4       # first attr
        struct.pack_into("<I", data, at, 0)
        fs = ntfs.NtfsFS(BytesImage(data))
        rec = fs.record(REC["hello"])
        self.assertTrue(rec.valid)
        self.assertEqual(rec.attrs, [])
        self.assertEqual(fs.read_file({"mft": REC["hello"]}), b"")

    def with_valid_data_length(self, vdl):
        data = bytearray(self.good)
        base = self.record_offset(REC["big"])
        runs = self.good.index(b"\x11\x02\x28", base, base + build.RECORD)
        attr = runs - 64                     # unnamed, uncompressed header
        self.assertEqual(struct.unpack_from("<Q", data, attr + 48)[0],
                         build.BIG_SIZE)     # real size, so attr is right
        struct.pack_into("<Q", data, attr + 56, vdl)
        return ntfs.NtfsFS(BytesImage(data))

    def test_bytes_past_valid_data_length_read_as_zeros(self):
        fs = self.with_valid_data_length(1000)
        want = build.big_content()[:1000] + bytes(build.BIG_SIZE - 1000)
        entry = {"mft": REC["big"]}
        self.assertEqual(fs.read_file(entry), want)
        self.assertEqual(fs.read_range(entry, 900, 3000), want[900:3900])
        self.assertEqual(fs.read_range(entry, 2000, 50), bytes(50))
        info = fs.stat(entry)
        self.assertEqual(info["valid_data_length"], 1000)
        self.assertIn("read as zeros", info["note"])
        # The stale bytes themselves are still where the runs say.
        first = info["runs"][0]
        self.assertEqual(fs.source.read_at(first["offset"] + 1000, 16),
                         build.big_content()[1000:1016])

    def test_zero_valid_data_length_reads_all_zeros(self):
        fs = self.with_valid_data_length(0)
        self.assertEqual(fs.read_file({"mft": REC["big"]}),
                         bytes(build.BIG_SIZE))

    def test_valid_data_length_past_the_file_size_changes_nothing(self):
        fs = self.with_valid_data_length(build.BIG_SIZE * 4)
        self.assertEqual(fs.read_file({"mft": REC["big"]}),
                         build.big_content())
        self.assertNotIn("valid_data_length", fs.stat({"mft": REC["big"]}))

    def test_run_longer_than_volume(self):
        data = bytearray(self.good)
        base = self.record_offset(REC["big"])
        at = self.good.index(b"\x11\x02\x28", base, base + build.RECORD)
        data[at + 1] = 0xF0                           # 240 clusters > 127
        fs = ntfs.NtfsFS(BytesImage(data))
        self.assertEqual(fs.read_file({"mft": REC["big"]}), b"")
        self.assertIn(ntfs.RUN_TOO_LONG, fs.findings)

    def test_random_record_damage(self):
        base = self.record_offset(REC["big"])
        rng = random.Random(8)
        for trial in range(60):
            data = bytearray(self.good)
            for _ in range(8):
                data[base + rng.randrange(0, 510)] = rng.getrandbits(8)
            with self.subTest(trial=trial):
                fs = ntfs.NtfsFS(BytesImage(data))
                rec = fs.record(REC["big"])
                if rec is None:
                    continue
                for a in rec.data_attrs():
                    fs.read_attr(a, max_bytes=1 << 16)
                fs.stat({"mft": REC["big"]})

    def test_record_count_bounded_by_volume(self):
        data = bytearray(self.good[:4096])
        data[13] = 8                                  # 4096-byte clusters
        fs = ntfs.NtfsFS(BytesImage(data))
        most = fs.cluster_count * fs.cluster_size // fs.record_size
        self.assertLessEqual(fs.record_count, most)


if __name__ == "__main__":
    unittest.main()
