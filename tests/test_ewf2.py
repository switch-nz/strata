"""Unit tests for engine.ewf2 (EWF2 / Ex01), fed synthetic images from
imagebuild_ewf2 -- built independently from libyal's EWF2 specification,
not from engine.ewf2 itself. Cross-validated during development against
pyewf (libewf's own Python bindings, the real reference implementation):
it reads these same synthetic fixtures identically to engine.ewf2. No
real-world Ex01 image is used or available; corroborate with another tool
before relying on this reader for a real exhibit.
"""

import hashlib
import os
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_ewf2 as build                                   # noqa: E402
from engine import ewf, ewf2                                      # noqa: E402


class TempDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="strata-ewf2-test-")
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path


class Basics(TempDir):

    def test_looks_like_ewf2(self):
        self.assertTrue(ewf2.looks_like_ewf2(build.EVF2_SIG + bytes(100)))
        self.assertFalse(ewf2.looks_like_ewf2(b"EVF\x09\x0d\x0a\xff\x00"))

    def test_small_uncompressed_round_trips(self):
        data = bytes(range(256)) * 16            # 4096 bytes, 2 chunks
        path = self.write("a.Ex01", build.build_ex01(data, compress=False))
        img = ewf2.Ewf2Image(path)
        self.assertEqual(img.size, len(data))
        self.assertEqual(img.read_at(0, img.size), data)
        img.close()

    def test_compressed_round_trips(self):
        data = (bytes(range(256)) * 16) + (b"A" * 2048)   # compressible
        path = self.write("a.Ex01", build.build_ex01(data, compress=True))
        img = ewf2.Ewf2Image(path)
        self.assertEqual(img.read_at(0, img.size), data)
        img.close()

    def test_mixed_compressed_and_stored_chunks(self):
        compressible = bytes(range(256)) * 8      # 2048 bytes, compresses well
        incompressible = os.urandom(2048)
        data = compressible + incompressible
        path = self.write("a.Ex01", build.build_ex01(data, chunk_size=2048))
        img = ewf2.Ewf2Image(path)
        self.assertEqual(img.read_at(0, img.size), data)
        img.close()

    def test_partial_and_overlapping_reads(self):
        data = bytes((i * 7) & 0xFF for i in range(4096))
        path = self.write("a.Ex01", build.build_ex01(data, chunk_size=1024))
        img = ewf2.Ewf2Image(path)
        self.assertEqual(img.read_at(10, 100), data[10:110])
        self.assertEqual(img.read_at(1020, 20), data[1020:1040])  # crosses a chunk
        self.assertEqual(img.read_at(img.size - 5, 100), data[-5:])
        self.assertEqual(img.read_at(img.size, 10), b"")
        img.close()

    def test_read_seek_interface(self):
        data = bytes(range(256)) * 8
        path = self.write("a.Ex01", build.build_ex01(data, chunk_size=1024))
        img = ewf2.Ewf2Image(path)
        img.seek(100)
        self.assertEqual(img.read(50), data[100:150])
        self.assertEqual(img.read(), data[150:])
        img.close()

    def test_info_reports_format_and_sizes(self):
        data = bytes(range(256)) * 8
        path = self.write("a.Ex01", build.build_ex01(data, chunk_size=1024))
        img = ewf2.Ewf2Image(path)
        info = img.info()
        self.assertEqual(info["format"], "EWF v2 (Ex01)")
        self.assertEqual(info["size"], len(data))
        self.assertEqual(info["chunk_size"], 1024)
        self.assertEqual(info["bytes_per_sector"], 512)
        img.close()


class PatternFill(TempDir):

    def test_pattern_fill_chunk_round_trips(self):
        pattern = b"\xAB\xCD\x00\x00\x00\x00\x00\x00"
        chunk0 = bytes(range(256)) * 8
        chunk1 = pattern * (2048 // 8)
        data = chunk0 + chunk1
        path = self.write("a.Ex01", build.build_ex01(
            data, chunk_size=2048, pattern_fill_chunks={1}))
        img = ewf2.Ewf2Image(path)
        self.assertEqual(img.read_at(0, img.size), data)
        # The pattern chunk costs (almost) nothing on disk.
        self.assertLess(os.path.getsize(path), len(data))
        img.close()


class Metadata(TempDir):

    def test_device_and_case_tags_are_read(self):
        data = bytes(range(256)) * 8
        path = self.write("a.Ex01", build.build_ex01(
            data, chunk_size=1024,
            device_tags={"sn": "SN-123", "md": "Model X"},
            case_tags={"nm": "Case name", "ex": "J Examiner"}))
        img = ewf2.Ewf2Image(path)
        self.assertEqual(img.header["drive_serial_number"], "SN-123")
        self.assertEqual(img.header["drive_model"], "Model X")
        self.assertEqual(img.header["description"], "Case name")
        self.assertEqual(img.header["examiner"], "J Examiner")
        img.close()

    def test_escaped_tabs_and_newlines_round_trip(self):
        data = bytes(range(256)) * 8
        path = self.write("a.Ex01", build.build_ex01(
            data, chunk_size=1024,
            case_tags={"nm": "Name\twith\ttabs\nand\nnewlines"}))
        img = ewf2.Ewf2Image(path)
        self.assertEqual(img.header["description"], "Name\twith\ttabs\nand\nnewlines")
        img.close()

    def test_sectors_per_chunk_from_case_data(self):
        data = bytes(range(256)) * 16
        path = self.write("a.Ex01", build.build_ex01(data, chunk_size=2048))
        img = ewf2.Ewf2Image(path)
        self.assertEqual(img.sectors_per_chunk, 4)
        self.assertEqual(img.chunk_size, 2048)
        img.close()


class Hashes(TempDir):

    def test_matching_stored_hashes_verify(self):
        data = bytes(range(256)) * 16
        md5, sha1 = hashlib.md5(data).digest(), hashlib.sha1(data).digest()
        path = self.write("a.Ex01", build.build_ex01(data, md5=md5, sha1=sha1))
        img = ewf2.Ewf2Image(path)
        result = img.verify()
        self.assertEqual(result["computed_md5"], md5.hex())
        self.assertTrue(result["md5_match"])
        self.assertTrue(result["sha1_match"])
        img.close()

    def test_mismatched_stored_hash_does_not_verify(self):
        data = bytes(range(256)) * 16
        path = self.write("a.Ex01", build.build_ex01(data, md5=b"\x00" * 16))
        img = ewf2.Ewf2Image(path)
        self.assertFalse(img.verify()["md5_match"])
        img.close()

    def test_no_stored_hash_reports_none(self):
        data = bytes(range(256)) * 16
        path = self.write("a.Ex01", build.build_ex01(data))
        img = ewf2.Ewf2Image(path)
        result = img.verify()
        self.assertIsNone(result["stored_md5"])
        self.assertFalse(result["md5_match"])
        img.close()


class Refusals(TempDir):

    def test_encrypted_volume_is_refused(self):
        path = self.write("a.Ex01", build.build_encrypted_ex01())
        with self.assertRaises(ewf2.Ewf2Error):
            ewf2.Ewf2Image(path)

    def test_bzip2_compression_is_refused(self):
        path = self.write("a.Ex01", build.build_bzip2_ex01())
        with self.assertRaises(ewf2.Ewf2Error):
            ewf2.Ewf2Image(path)

    def test_unknown_compression_method_is_refused(self):
        seg = build.SegmentBuilder(compression_method=99)
        path = self.write("a.Ex01", seg.finish())
        with self.assertRaises(ewf2.Ewf2Error):
            ewf2.Ewf2Image(path)

    def test_not_an_ewf2_file_is_refused(self):
        path = self.write("a.Ex01", b"hello world" * 10)
        with self.assertRaises(ewf2.Ewf2Error):
            ewf2.Ewf2Image(path)

    def test_no_chunk_table_is_refused(self):
        seg = build.SegmentBuilder()
        seg.add_object_section(build.SECTION_DEVICE, {"bp": 512, "ts": 4})
        path = self.write("a.Ex01", seg.finish())
        with self.assertRaises(ewf2.Ewf2Error):
            ewf2.Ewf2Image(path)

    def test_open_image_dispatches_and_wraps_unsupported(self):
        path = self.write("a.Ex01", build.build_bzip2_ex01())
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(path)


class Dispatch(TempDir):

    def test_open_image_reads_a_real_ex01(self):
        data = bytes(range(256)) * 16
        path = self.write("a.Ex01", build.build_ex01(data))
        img = ewf.open_image(path)
        self.assertIsInstance(img, ewf2.Ewf2Image)
        self.assertEqual(img.read_at(0, img.size), data)
        img.close()


class SegmentDiscovery(TempDir):
    """String-level only: discover_segments() just needs the right names
    and a plausible signature to find and order a multi-segment set."""

    def test_numbered_ex01_segments_are_found_in_order(self):
        self.write("eX1.Ex01", build.EVF2_SIG + bytes(24))
        self.write("eX1.Ex02", build.EVF2_SIG + bytes(24))
        found = ewf.discover_segments(os.path.join(self.dir, "eX1.Ex01"))
        self.assertEqual([os.path.basename(p) for p in found],
                         ["eX1.Ex01", "eX1.Ex02"])

    def test_lettered_segments_follow_ex99(self):
        self.write("b.Ex01", build.EVF2_SIG + bytes(24))
        self.write("b.Ex99", build.EVF2_SIG + bytes(24))
        self.write("b.ExAA", build.EVF2_SIG + bytes(24))
        found = ewf.discover_segments(os.path.join(self.dir, "b.Ex01"))
        names = [os.path.basename(p) for p in found]
        self.assertEqual(names[0], "b.Ex01")
        self.assertEqual(names[-1], "b.ExAA")

    def test_lx01_naming_is_also_discovered(self):
        self.write("c.Lx01", build.EVF2_SIG + bytes(24))
        self.write("c.Lx02", build.EVF2_SIG + bytes(24))
        found = ewf.discover_segments(os.path.join(self.dir, "c.Lx01"))
        self.assertEqual(len(found), 2)

    def test_single_segment_with_no_siblings(self):
        path = self.write("solo.Ex01", build.EVF2_SIG + bytes(24))
        found = ewf.discover_segments(path)
        self.assertEqual(found, [path])


class Resilience(TempDir):
    """Damage degrades to zero-filled bytes and a finding, the same
    resilience EWF1's reader applies to a bad chunk -- it does not make
    the rest of the image unreadable."""

    def test_corrupted_compressed_chunk_zero_fills_with_a_finding(self):
        data = (b"A" * 2048) + (b"B" * 2048)
        seg = build.SegmentBuilder()
        seg.add_object_section(build.SECTION_DEVICE, {"bp": 512, "ts": 8})
        seg.add_object_section(build.SECTION_CASE, {"sb": 4, "tb": 2})
        chunks = [data[0:2048], data[2048:4096]]
        sectors_start = seg.length
        sectors = bytearray()
        entries = []
        for chunk in chunks:
            stored, flags = build.chunk_entry(chunk, True)
            entries.append((sectors_start + len(sectors), len(stored), flags))
            sectors += stored
        seg.add_section(build.SECTION_SECTORS, bytes(sectors))
        seg.add_table(0, entries)
        raw = bytearray(seg.finish())
        # Corrupt a byte well inside the first chunk's compressed bytes.
        raw[entries[0][0] + 3] ^= 0xFF
        path = self.write("a.Ex01", bytes(raw))
        img = ewf2.Ewf2Image(path)
        got = img.read_at(0, img.size)
        self.assertEqual(got[2048:], data[2048:])          # second chunk unaffected
        self.assertNotEqual(got[:2048], data[:2048])
        self.assertTrue(img.findings)
        img.close()

    def test_gap_in_chunk_table_zero_fills_that_chunk(self):
        # Build two independent one-chunk images and splice the second
        # image's table entries in at chunk index 2, leaving chunk 1 with
        # no entry at all.
        seg = build.SegmentBuilder()
        seg.add_object_section(build.SECTION_DEVICE, {"bp": 512, "ts": 12})
        seg.add_object_section(build.SECTION_CASE, {"sb": 4, "tb": 3})
        chunk0 = bytes(range(256)) * 8
        chunk2 = b"Z" * 2048
        sectors = chunk0 + chunk2
        seg.add_section(build.SECTION_SECTORS, sectors)
        base = seg.length - len(sectors) - build.SECTION_DESC_SIZE
        entries = [
            (base, len(chunk0), 0),
            (base + len(chunk0), len(chunk2), 0),
        ]
        # Deliberately number these as chunks 0 and 2, skipping 1.
        def table_section(first_chunk, entry):
            header = struct.pack("<QII", first_chunk, 1, 0)
            header += struct.pack("<I", zlib.adler32(header) & 0xFFFFFFFF)
            header += bytes(12)
            body = struct.pack("<QII", *entry)
            footer = struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF)
            footer += bytes(12)
            return header + body + footer

        seg.add_section(build.SECTION_TABLE, table_section(0, entries[0]))
        seg.add_section(build.SECTION_TABLE, table_section(2, entries[1]))

        path = self.write("a.Ex01", seg.finish())
        img = ewf2.Ewf2Image(path)
        self.assertEqual(len(img.chunks), 3)
        got = img.read_at(0, img.size)
        self.assertEqual(got[0:2048], chunk0)
        self.assertEqual(got[2048:4096], bytes(2048))     # the gap
        self.assertEqual(got[4096:6144], chunk2)
        self.assertTrue(any("gap" in f for f in img.findings))
        img.close()


if __name__ == "__main__":
    unittest.main()
