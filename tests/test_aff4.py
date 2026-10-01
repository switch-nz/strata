"""Unit tests for engine.aff4, fed synthetic AFF4 volumes from
imagebuild_aff4 (built independently from the published AFF4 Standard and
from bytes observed in real pyaff4 output -- see that module's docstring).
No real AFF4 image is used or available; corroborate with another tool
before relying on this reader for a real exhibit (noted in docs/ROADMAP.md).
"""

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_aff4 as build                                   # noqa: E402
from engine import aff4                                           # noqa: E402


def _write(raw, name="test.aff4"):
    path = os.path.join(tempfile.gettempdir(), "strata_test_%s" % name)
    with open(path, "wb") as f:
        f.write(raw)
    return path


def _open(raw, name="test.aff4"):
    path = _write(raw, name)
    return aff4.Aff4Image(path, open(path, "rb"))


class LooksLikeAff4(unittest.TestCase):

    def test_extension_is_required(self):
        self.assertTrue(aff4.looks_like_aff4("/a/b/image.aff4"))
        self.assertTrue(aff4.looks_like_aff4("IMAGE.AFF4"))
        self.assertFalse(aff4.looks_like_aff4("/a/b/image.e01"))
        self.assertFalse(aff4.looks_like_aff4("/a/b/image.zip"))


class BareImageStream(unittest.TestCase):

    def test_small_uncompressed_round_trips(self):
        data = bytes(range(256)) * 4
        img = _open(build.build_bare_image_stream(
            data, chunk_size=256, compress=False))
        self.assertEqual(img.size, len(data))
        self.assertEqual(img.read_at(0, img.size), data)
        img.close()

    def test_compressed_multi_bevy_round_trips(self):
        data = (b"A" * 2000) + (b"B" * 2000) + bytes(range(256)) * 4
        img = _open(build.build_bare_image_stream(
            data, chunk_size=256, chunks_per_segment=3, compress=True))
        self.assertEqual(img.read_at(0, img.size), data)
        img.close()

    def test_partial_and_overlapping_reads(self):
        data = bytes((i * 7) & 0xFF for i in range(5000))
        img = _open(build.build_bare_image_stream(
            data, chunk_size=256, chunks_per_segment=4, compress=True))
        self.assertEqual(img.read_at(10, 100), data[10:110])
        self.assertEqual(img.read_at(250, 20), data[250:270])  # crosses a chunk
        self.assertEqual(img.read_at(4990, 100), data[4990:])  # past the end
        self.assertEqual(img.read_at(img.size, 10), b"")
        img.close()

    def test_read_seek_interface(self):
        data = bytes(range(256)) * 2
        img = _open(build.build_bare_image_stream(data, chunk_size=256))
        img.seek(100)
        self.assertEqual(img.read(50), data[100:150])
        self.assertEqual(img.read(), data[150:])
        img.close()

    def test_info_reports_bare_image_stream(self):
        img = _open(build.build_bare_image_stream(b"x" * 100, chunk_size=256))
        info = img.info()
        self.assertEqual(info["format"], "AFF4")
        self.assertEqual(info["size"], 100)
        self.assertEqual(info["acquisition"]["data stream"], "bare ImageStream")
        img.close()


class DiskImageViaMap(unittest.TestCase):

    def test_single_range_round_trips(self):
        data = bytes(range(256)) * 4
        img = _open(build.build_disk_image(
            [(0, data)], chunk_size=256, chunks_per_segment=3))
        self.assertEqual(img.read_at(0, img.size), data)
        img.close()

    def test_gap_reads_as_zero_by_default(self):
        ranges = [(0, b"A" * 500), (2000, b"B" * 500)]
        img = _open(build.build_disk_image(
            ranges, stream_size=3000, chunk_size=256, chunks_per_segment=3))
        got = img.read_at(0, img.size)
        self.assertEqual(got[0:500], b"A" * 500)
        self.assertEqual(got[500:2000], bytes(1500))
        self.assertEqual(got[2000:2500], b"B" * 500)
        self.assertEqual(got[2500:3000], bytes(500))
        img.close()

    def test_custom_gap_fill_pattern(self):
        ranges = [(500, b"A" * 500)]
        img = _open(build.build_disk_image(
            ranges, stream_size=1000, chunk_size=256, chunks_per_segment=3,
            gap_fill="aff4:SymbolicStreamFF"))
        got = img.read_at(0, img.size)
        self.assertEqual(got[0:500], b"\xff" * 500)
        self.assertEqual(got[500:1000], b"A" * 500)
        img.close()

    def test_multiple_disjoint_ranges(self):
        ranges = [(0, b"A" * 300), (1000, b"B" * 300), (5000, b"C" * 300)]
        img = _open(build.build_disk_image(
            ranges, stream_size=5300, chunk_size=256, chunks_per_segment=2))
        got = img.read_at(0, img.size)
        self.assertEqual(got[0:300], b"A" * 300)
        self.assertEqual(got[1000:1300], b"B" * 300)
        self.assertEqual(got[5000:5300], b"C" * 300)
        self.assertEqual(got[300:1000], bytes(700))
        img.close()

    def test_a_read_spanning_a_range_boundary(self):
        ranges = [(0, b"A" * 300), (300, b"B" * 300)]
        img = _open(build.build_disk_image(
            ranges, chunk_size=256, chunks_per_segment=2))
        self.assertEqual(img.read_at(290, 20), b"A" * 10 + b"B" * 10)
        img.close()

    def test_info_reports_map_over_stream_count(self):
        img = _open(build.build_disk_image(
            [(0, b"A" * 100)], chunk_size=256))
        self.assertIn("Map over 1 stream", img.info()["acquisition"]["data stream"])
        img.close()


class Hashes(unittest.TestCase):

    def test_matching_stored_hashes_verify(self):
        import hashlib
        data = bytes(range(256)) * 4
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        img = _open(build.build_disk_image(
            [(0, data)], chunk_size=256, chunks_per_segment=3,
            hash_md5=md5, hash_sha1=sha1))
        result = img.verify()
        self.assertEqual(result["computed_md5"], md5)
        self.assertEqual(result["computed_sha1"], sha1)
        self.assertTrue(result["md5_match"])
        self.assertTrue(result["sha1_match"])
        img.close()

    def test_mismatched_stored_hash_does_not_verify(self):
        data = bytes(range(256)) * 4
        img = _open(build.build_disk_image(
            [(0, data)], chunk_size=256, chunks_per_segment=3,
            hash_md5="00" * 16))
        result = img.verify()
        self.assertFalse(result["md5_match"])
        img.close()

    def test_no_stored_hash_reports_none(self):
        img = _open(build.build_bare_image_stream(b"x" * 300, chunk_size=256))
        result = img.verify()
        self.assertIsNone(result["stored_md5"])
        self.assertFalse(result["md5_match"])
        img.close()


class Zip64(unittest.TestCase):

    def test_zip64_container_is_read(self):
        volume_urn = "aff4://33333333-3333-3333-3333-333333333333"
        stream_urn = "%s/image.dd" % volume_urn
        data = bytes(range(256)) * 2
        bevy, index = build._bevy([data], 512, False)
        turtle = build._turtle([(stream_urn, [
            ("a", ["aff4:ImageStream"]),
            ("aff4:chunkSize", ["512"]),
            ("aff4:chunksInSegment", ["1"]),
            ("aff4:size", [str(len(data))]),
        ])])
        raw = build.build_zip64(
            [("image.dd/00000000", bevy),
             ("image.dd/00000000.index", index),
             ("information.turtle", turtle)],
            comment=volume_urn.encode("ascii"))
        img = _open(raw, "zip64.aff4")
        self.assertEqual(img.read_at(0, img.size), data)
        img.close()


class Refusals(unittest.TestCase):

    def _bare_volume_bytes(self):
        return build.build_bare_image_stream(bytes(range(256)), chunk_size=256)

    def test_missing_information_turtle_is_refused(self):
        zb = build.ZipBuilder()
        zb.add("version.txt", b"major=1\nminor=0\n")
        raw = zb.finish(comment=b"aff4://44444444-4444-4444-4444-444444444444")
        with self.assertRaises(aff4.Aff4Error):
            _open(raw, "no_turtle.aff4")

    def test_missing_volume_uri_is_refused(self):
        zb = build.ZipBuilder()
        zb.add("information.turtle", b"@prefix aff4: <http://aff4.org/Schema#> .\n")
        raw = zb.finish(comment=b"")
        with self.assertRaises(aff4.Aff4Error):
            _open(raw, "no_uri.aff4")

    def test_unsupported_compression_method_is_refused(self):
        volume_urn = "aff4://55555555-5555-5555-5555-555555555555"
        stream_urn = "%s/image.dd" % volume_urn
        turtle = build._turtle([(stream_urn, [
            ("a", ["aff4:ImageStream"]),
            ("aff4:chunkSize", ["512"]),
            ("aff4:chunksInSegment", ["1"]),
            ("aff4:size", ["512"]),
            ("aff4:compressionMethod", ["<http://code.google.com/p/snappy/>"]),
        ])])
        zb = build.ZipBuilder()
        zb.add("image.dd/00000000", bytes(512))
        zb.add("image.dd/00000000.index", struct.pack("<III", 0, 0, 512))
        zb.add("information.turtle", turtle)
        raw = zb.finish(comment=volume_urn.encode("ascii"))
        with self.assertRaises(aff4.Aff4Error):
            _open(raw, "snappy.aff4")

    def test_striped_volume_missing_target_is_refused(self):
        # A Map whose idx names a stream this volume does not have --
        # the shape of one volume of a striped/segmented AFF4 set.
        volume_urn = "aff4://66666666-6666-6666-6666-666666666666"
        disk_urn = "%s/disk0" % volume_urn
        map_urn = "%s/map0" % volume_urn
        missing_urn = "aff4://99999999-9999-9999-9999-999999999999/elsewhere"
        turtle = build._turtle([
            (disk_urn, [("a", ["aff4:DiskImage", "aff4:Image"]),
                       ("aff4:dataStream", ["<%s>" % map_urn]),
                       ("aff4:size", ["512"])]),
            (map_urn, [("a", ["aff4:Map"]), ("aff4:size", ["512"])]),
        ])
        zb = build.ZipBuilder()
        zb.add("map0/map", struct.pack("<QQQI", 0, 512, 0, 0))
        zb.add("map0/idx", missing_urn.encode("utf-8"))
        zb.add("information.turtle", turtle)
        raw = zb.finish(comment=volume_urn.encode("ascii"))
        with self.assertRaises(aff4.Aff4Error):
            _open(raw, "striped.aff4")

    def test_malformed_turtle_is_refused(self):
        zb = build.ZipBuilder()
        zb.add("information.turtle",
              b"@prefix aff4: <http://aff4.org/Schema#> .\n"
              b"<aff4://x> a aff4:ImageStream")  # no terminating '.'
        raw = zb.finish(comment=b"aff4://77777777-7777-7777-7777-777777777777")
        with self.assertRaises(aff4.Aff4Error):
            _open(raw, "bad_turtle.aff4")

    def test_not_a_zip_at_all_is_refused(self):
        path = _write(b"not a zip file" * 10, "notzip.aff4")
        with self.assertRaises(aff4.Aff4Error):
            aff4.Aff4Image(path, open(path, "rb"))


class Resilience(unittest.TestCase):
    """Damage to one chunk or bevy degrades to zero-filled bytes and a
    finding, the same resilience EWF applies to one bad chunk -- it does
    not make the rest of the image unreadable."""

    def test_corrupted_compressed_chunk_zero_fills_with_a_finding(self):
        data = (b"A" * 1024) + (b"B" * 1024)
        raw = bytearray(build.build_bare_image_stream(
            data, chunk_size=1024, chunks_per_segment=4, compress=True))
        # The bevy is the very first member written; corrupt a byte well
        # inside its first (compressed) chunk.
        idx = raw.index(b"PK\x03\x04")
        name_len = struct.unpack_from("<H", raw, idx + 26)[0]
        data_start = idx + 30 + name_len
        raw[data_start + 3] ^= 0xFF
        img = _open(bytes(raw), "corrupt.aff4")
        got = img.read_at(0, img.size)
        self.assertEqual(got[1024:], b"B" * 1024)  # second chunk unaffected
        self.assertNotEqual(got[:1024], b"A" * 1024)
        self.assertTrue(any("decompress" in f for f in img.findings))
        img.close()

    def test_malformed_bevy_index_zero_fills_that_bevy(self):
        # Built directly (not via build_bare_image_stream) so the index
        # member itself is short by one byte from the start -- surgically
        # truncating an already-assembled Zip would shift every later
        # offset in the file, corrupting far more than intended.
        volume_urn = "aff4://88888888-8888-8888-8888-888888888888"
        stream_urn = "%s/image.dd" % volume_urn
        data = (b"A" * 256) + (b"B" * 256)
        bevy, index = build._bevy(
            [data[0:256], data[256:512]], 256, False)
        turtle = build._turtle([(stream_urn, [
            ("a", ["aff4:ImageStream"]),
            ("aff4:chunkSize", ["256"]),
            ("aff4:chunksInSegment", ["4"]),
            ("aff4:size", [str(len(data))]),
        ])])
        zb = build.ZipBuilder()
        zb.add("image.dd/00000000", bevy)
        zb.add("image.dd/00000000.index", index[:-1])  # 23 bytes, not 24
        zb.add("information.turtle", turtle)
        raw = zb.finish(comment=volume_urn.encode("ascii"))
        img = _open(raw, "badindex.aff4")
        got = img.read_at(0, img.size)
        self.assertEqual(got, bytes(len(data)))
        self.assertTrue(any("index" in f for f in img.findings))
        img.close()


if __name__ == "__main__":
    unittest.main()
