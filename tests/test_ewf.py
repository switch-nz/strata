"""Unit tests for image containers (engine.ewf): EWF v1 segment sets, raw
images, split raw sets and OffsetReader, fed files from imagebuild_ewf."""

import gc
import hashlib
import io
import os
import struct
import sys
import tempfile
import unittest
import warnings
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagebuild_ewf as build                                    # noqa: E402
from engine import ewf                                            # noqa: E402

MEDIA = build.media()                  # 14 sectors: 3 full chunks + 1 short


class TempDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="strata-ewf-test-")
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def write_segments(self, segments, stem="x"):
        paths = [self.write(os.path.basename(n), s) for n, s in
                 zip(build.segment_names(stem, len(segments)), segments)]
        return paths[0]

    def open(self, path):
        img = ewf.open_image(path)
        self.addCleanup(img.close)
        return img


class SingleSegment(TempDir):
    def setUp(self):
        super(SingleSegment, self).setUp()
        self.img = self.open(self.write_segments(build.build_e01()))

    def test_opens_as_ewf(self):
        self.assertIsInstance(self.img, ewf.EwfImage)

    def test_volume_geometry(self):
        info = self.img.info()
        self.assertEqual(info["format"], "EWF v1 (E01)")
        self.assertEqual(info["segments"], ["x.E01"])
        self.assertEqual(info["size"], len(MEDIA))
        self.assertEqual(info["sector_count"], 14)
        self.assertEqual(info["bytes_per_sector"], 512)
        self.assertEqual(info["sectors_per_chunk"], build.SECTORS_PER_CHUNK)
        self.assertEqual(info["chunk_size"], build.CHUNK_SIZE)
        self.assertEqual(info["chunk_count"], 4)
        self.assertEqual(info["compressed_chunks"], 2)
        self.assertEqual(info["media_type"], 1)
        self.assertEqual(info["compression_level"], 1)
        self.assertEqual(info["findings"], [])

    def test_header_section(self):
        acq = self.img.info()["acquisition"]
        self.assertEqual(acq["case_number"], "CASE-1")
        self.assertEqual(acq["evidence_number"], "EV-7")
        self.assertEqual(acq["examiner"], "Examiner")
        self.assertEqual(acq["acquisition_date"], "2026 9 16 10 0 0")

    def test_read_back_mixed_chunks(self):
        self.assertEqual(self.img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(self.img.findings, [])

    def test_read_across_chunk_boundaries(self):
        for off, n in ((2000, 100), (4095, 2), (6000, 5000), (0, 1)):
            self.assertEqual(self.img.read_at(off, n), MEDIA[off:off + n])

    def test_read_past_end(self):
        self.assertEqual(self.img.read_at(len(MEDIA), 10), b"")
        with self.assertRaises(ValueError):
            self.img.read_at(-1, 10)

    def test_file_like_read_and_seek(self):
        self.img.seek(100)
        self.assertEqual(self.img.read(10), MEDIA[100:110])
        self.assertEqual(self.img.seek(5, io.SEEK_CUR), 115)
        self.img.seek(-12, io.SEEK_END)
        self.assertEqual(self.img.read(), MEDIA[-12:])

    def test_stored_md5_and_verify(self):
        md5 = hashlib.md5(MEDIA).hexdigest()
        self.assertEqual(self.img.stored_md5, md5)
        got = self.img.verify()
        self.assertEqual(got["computed_md5"], md5)
        self.assertEqual(got["computed_sha1"], hashlib.sha1(MEDIA).hexdigest())
        self.assertTrue(got["md5_match"])
        self.assertIsNone(got["stored_sha1"])

    def test_all_uncompressed_and_all_compressed(self):
        for name, fn in (("u", lambda i: False), ("c", lambda i: True)):
            path = self.write_segments(build.build_e01(compress=fn), name)
            img = self.open(path)
            self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
            self.assertEqual(img.findings, [])


class SplitSegments(TempDir):
    def test_e01_e02_read_back(self):
        segs = build.build_e01(per_segment=2)
        self.assertEqual(len(segs), 2)
        img = self.open(self.write_segments(segs))
        self.assertEqual(img.info()["segments"], ["x.E01", "x.E02"])
        self.assertEqual(len(img.chunks), 4)
        self.assertEqual([c.seg for c in img.chunks], [0, 0, 1, 1])
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertTrue(img.verify()["md5_match"])
        self.assertEqual(img.findings, [])

    def test_three_segments_opened_from_the_middle(self):
        self.write_segments(build.build_e01(per_segment=1), "m")
        img = self.open(os.path.join(self.dir, "m.E02"))
        self.assertEqual(len(img.segment_paths), 4)
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_discover_segments_orders_numerically(self):
        for ext in ("E10", "E02", "E01", "E09"):
            self.write("s." + ext, b"")
        self.write("other.E03", b"")
        got = [os.path.basename(p) for p in
               ewf.discover_segments(os.path.join(self.dir, "s.E01"))]
        self.assertEqual(got, ["s.E01", "s.E02", "s.E09", "s.E10"])

    # A three-letter sibling such as x.txt fits the lettered segment names
    # used past .E99, so it must not join a set that has no .E99.
    def test_unrelated_sidecar_file_is_not_a_segment(self):
        path = self.write_segments(build.build_e01())
        self.write("x.txt", b"acquisition notes\n")
        img = self.open(path)
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(img.info()["segments"], ["x.E01"])

    def test_lettered_segments_follow_e99_when_they_are_ewf(self):
        for n in range(1, 100):
            self.write("s.E%02d" % n, b"")
        self.write("s.EAB", ewf.EVF_SIG)
        self.write("s.EAA", ewf.EVF_SIG)
        self.write("s.txt", b"acquisition notes\n")
        got = [os.path.basename(p) for p in
               ewf.discover_segments(os.path.join(self.dir, "s.E01"))]
        self.assertEqual(got, ["s.E%02d" % n for n in range(1, 100)]
                         + ["s.EAA", "s.EAB"])


class Integrity(TempDir):
    def corrupt(self, index, fn):
        def mutate(i, raw):
            return fn(raw) if i == index else raw
        img = self.open(self.write_segments(
            build.build_e01(chunk_mutator=mutate)))
        return img, img.read_at(0, len(MEDIA))

    @staticmethod
    def flip(pos):
        def fn(raw):
            b = bytearray(raw)
            b[pos] ^= 0x01
            return bytes(b)
        return fn

    def test_uncompressed_chunk_checksum_mismatch_is_reported(self):
        img, data = self.corrupt(1, self.flip(5))
        self.assertNotEqual(data, MEDIA)
        self.assertTrue(any("Chunk 1" in f and "Adler-32" in f
                            for f in img.findings), img.findings)

    def test_corrupt_compressed_chunk_is_reported(self):
        img, data = self.corrupt(0, self.flip(20))
        self.assertEqual(len(data), len(MEDIA))
        self.assertEqual(data[:build.CHUNK_SIZE], bytes(build.CHUNK_SIZE))
        self.assertTrue(any("Chunk 0" in f for f in img.findings))

    def test_verify_detects_mismatch(self):
        img, _data = self.corrupt(1, self.flip(5))
        self.assertFalse(img.verify()["md5_match"])

    def test_truncated_compressed_chunk_is_reported(self):
        img, data = self.corrupt(0, lambda raw: raw[:len(raw) // 2])
        self.assertTrue(any("Chunk 0" in f for f in img.findings),
                        "short read (%d of %d bytes) with no finding"
                        % (len(data), len(MEDIA)))

    def test_truncated_chunk_does_not_end_the_read(self):
        # Chunk 0 is cut short; everything after it must still read, at the
        # right offsets, with the missing part of chunk 0 as zeros.
        img, data = self.corrupt(0, lambda raw: raw[:len(raw) // 2])
        cs = build.CHUNK_SIZE
        self.assertEqual(len(data), len(MEDIA))
        self.assertEqual(data[cs:], MEDIA[cs:])
        got = len(data[:cs].rstrip(b"\x00"))
        self.assertEqual(data[:got], MEDIA[:got])

    def test_damaged_compressed_chunk_is_zero_filled_not_partial(self):
        # Half the chunk as a flushed deflate block, then an invalid block.
        # What decoded before the error is unverified, so none of it is used.
        half = build.CHUNK_SIZE // 2

        def damaged(raw):
            co = zlib.compressobj()
            return (co.compress(MEDIA[:half]) + co.flush(zlib.Z_SYNC_FLUSH)
                    + b"\xff\xff\xff\xff")
        img, data = self.corrupt(0, damaged)
        self.assertTrue(any("Chunk 0" in f for f in img.findings))
        self.assertEqual(data[:build.CHUNK_SIZE], bytes(build.CHUNK_SIZE))
        self.assertEqual(data[build.CHUNK_SIZE:], MEDIA[build.CHUNK_SIZE:])

    def test_compressed_chunk_missing_only_its_checksum_is_reported(self):
        img, data = self.corrupt(0, lambda raw: raw[:-4])
        self.assertTrue(any("Chunk 0" in f and "verified" in f
                            for f in img.findings))
        self.assertEqual(data, MEDIA)

    def test_short_final_compressed_chunk_is_not_a_finding(self):
        img = self.open(self.write_segments(
            build.build_e01(compress=lambda i: True)))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual([f for f in img.findings if "Chunk" in f], [])

    def test_section_descriptor_checksum_mismatch_is_reported(self):
        seg = bytearray(build.build_e01()[0])
        seg[13 + 60] ^= 0xFF                 # padding of the header section
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertTrue(any("descriptor checksum" in f for f in img.findings))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_table_header_checksum_mismatch_is_reported(self):
        seg = bytearray(build.build_e01()[0])
        table = self.find_section(seg, "table")
        seg[table + build.DESC + 4] ^= 0xFF    # padding inside table header
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertTrue(any("Table header checksum" in f
                            for f in img.findings))

    @staticmethod
    def find_section(seg, type_):
        off = 13
        while True:
            name = bytes(seg[off:off + 16]).split(b"\x00")[0].decode()
            if name == type_:
                return off
            off = struct.unpack_from("<Q", seg, off + 16)[0]


class Robustness(TempDir):
    def test_garbage_after_signature(self):
        path = self.write("g.E01", build.EVF_SIG + bytes(500))
        with self.assertRaises(ewf.EwfError):
            ewf.EwfImage(path)

    def test_signature_only(self):
        with self.assertRaises(ewf.EwfError):
            ewf.EwfImage(self.write("s.E01", build.EVF_SIG))

    def test_not_ewf_at_all(self):
        with self.assertRaises(ewf.EwfError):
            ewf.EwfImage(self.write("n.E01", b"hello world" * 100))

    def test_malformed_ewf2_is_refused(self):
        # EWF2 is now read (engine/ewf2.py); a signature with no valid
        # section structure behind it still fails to open, as
        # UnsupportedContainer -- the same exception shape every other
        # recognised-but-unreadable container uses.
        with self.assertRaises(ewf.UnsupportedContainer):
            ewf.open_image(self.write("v2.Ex01", ewf.EVF2_SIG + bytes(100)))

    def test_known_unsupported_container(self):
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            ewf.open_image(self.write("q.qcow2", b"QFI\xfb" + bytes(100)))
        self.assertIn("QCOW", cm.exception.format)

    def test_truncated_at_every_section_boundary(self):
        seg = build.build_e01()[0]
        cuts = [13 + 38, len(seg) // 3, len(seg) // 2, len(seg) - 200,
                len(seg) - build.DESC - 10]
        for cut in cuts:
            path = self.write("t%d.E01" % cut, seg[:cut])
            try:
                img = ewf.EwfImage(path)
            except ewf.EwfError:
                continue
            try:
                img.read_at(0, len(MEDIA))
                img.info()
            finally:
                img.close()

    def test_truncated_before_hash_still_reads(self):
        seg = build.build_e01()[0]
        hash_at = Integrity.find_section(seg, "hash")
        img = self.open(self.write_segments([seg[:hash_at]]))
        self.assertIsNone(img.stored_md5)
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertFalse(img.verify()["md5_match"])

    def test_non_advancing_section_chain(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table2")
        struct.pack_into("<Q", seg, at + 16, at)
        struct.pack_into("<I", seg, at + 72, build.adler(bytes(seg[at:at + 72])))
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertTrue(any("non-advancing" in f for f in img.findings))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_backwards_section_pointer(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table2")
        struct.pack_into("<Q", seg, at + 16, 13)
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertTrue(img.findings)

    def test_implausible_table_entry_count(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table")
        struct.pack_into("<I", seg, at + build.DESC, 0xFFFFFFFF)
        at2 = Integrity.find_section(seg, "table2")
        struct.pack_into("<I", seg, at2 + build.DESC, 0)
        with self.assertRaises(ewf.EwfError):
            ewf.EwfImage(self.write_segments([bytes(seg)]))

    def test_section_size_beyond_file(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table")
        struct.pack_into("<Q", seg, at + 16, 1 << 40)
        img = self.open(self.write_segments([bytes(seg)]))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)


class HostileSizes(TempDir):
    """Sizes and offsets in a segment file are untrusted: none of them may
    decide how much is allocated.  Found by tests/fuzz.py, where each of
    these raised MemoryError, OverflowError or OSError."""

    HUGE = 1 << 62

    @staticmethod
    def set_size(seg, type_, size):
        at = Integrity.find_section(seg, type_)
        struct.pack_into("<Q", seg, at + 24, size)
        struct.pack_into("<I", seg, at + 72, build.adler(bytes(seg[at:at + 72])))
        return at

    def open_mutated(self, seg):
        return self.open(self.write_segments([bytes(seg)]))

    def assertFinding(self, img, text):
        self.assertTrue(any(text in f for f in img.findings), img.findings)

    def test_huge_volume_section(self):
        seg = bytearray(build.build_e01()[0])
        self.set_size(seg, "volume", self.HUGE)
        img = self.open_mutated(seg)
        self.assertFinding(img, "Section 'volume'")
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_huge_header_section(self):
        seg = bytearray(build.build_e01()[0])
        self.set_size(seg, "header", self.HUGE)
        img = self.open_mutated(seg)
        self.assertFinding(img, "Section 'header'")
        self.assertEqual(img.info()["acquisition"]["case_number"], "CASE-1")

    def test_huge_hash_section(self):
        seg = bytearray(build.build_e01()[0])
        self.set_size(seg, "hash", self.HUGE)
        img = self.open_mutated(seg)
        self.assertFinding(img, "Section 'hash'")
        self.assertEqual(img.stored_md5, hashlib.md5(MEDIA).hexdigest())

    def test_implausible_chunk_geometry(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "volume") + build.DESC
        struct.pack_into("<II", seg, at + 8, 0xFFFFFFFF, 0xFFFFFFFF)
        img = self.open_mutated(seg)
        self.assertFinding(img, "bytes per sector")
        self.assertFinding(img, "sectors per chunk")
        self.assertLessEqual(img.chunk_size, ewf.MAX_CHUNK_SIZE)
        img.read_at(0, len(MEDIA))

    def test_chunk_offset_past_end_of_segment(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table") + build.DESC
        struct.pack_into("<Q", seg, at + 8, self.HUGE)
        struct.pack_into("<I", seg, at + 20, build.adler(bytes(seg[at:at + 20])))
        img = self.open_mutated(seg)
        img.read_at(0, len(MEDIA))
        self.assertFinding(img, "Chunk 0 declares")

    def test_huge_final_chunk(self):
        # The last chunk's length runs to the end of the sectors section.
        seg = bytearray(build.build_e01()[0])
        self.set_size(seg, "sectors", self.HUGE)
        img = self.open_mutated(seg)
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertFinding(img, "Chunk 3 declares")

    def test_section_pointer_past_end_of_segment(self):
        seg = bytearray(build.build_e01()[0])
        at = Integrity.find_section(seg, "table2")
        struct.pack_into("<Q", seg, at + 16, (1 << 64) - 1)
        struct.pack_into("<I", seg, at + 72, build.adler(bytes(seg[at:at + 72])))
        img = self.open_mutated(seg)
        self.assertFinding(img, "past the end of segment")
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_failed_open_releases_the_file(self):
        path = self.write("g.E01", build.EVF_SIG + bytes(500))
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            with self.assertRaises(ewf.EwfError):
                ewf.EwfImage(path)
            gc.collect()
        self.assertEqual([w for w in caught
                          if issubclass(w.category, ResourceWarning)], [])


class Raw(TempDir):
    def test_raw_image(self):
        path = self.write("disk.dd", MEDIA)
        img = self.open(path)
        self.assertIsInstance(img, ewf.RawImage)
        self.assertEqual(img.size, len(MEDIA))
        self.assertEqual(img.read_at(1000, 50), MEDIA[1000:1050])
        self.assertEqual(img.read_at(len(MEDIA) - 5, 50), MEDIA[-5:])
        self.assertEqual(img.read_at(len(MEDIA), 1), b"")
        img.seek(-3, io.SEEK_END)
        self.assertEqual(img.read(), MEDIA[-3:])
        got = img.verify()
        self.assertEqual(got["computed_md5"], hashlib.md5(MEDIA).hexdigest())
        self.assertIsNone(got["md5_match"])
        self.assertEqual(img.info()["format"], "Raw / dd")

    def test_empty_raw_image(self):
        img = self.open(self.write("empty.img", b""))
        self.assertEqual(img.size, 0)
        self.assertEqual(img.read_at(0, 10), b"")

    def write_split(self, piece, first=1, skip=(), prefix="split",
                    style="ftk"):
        pieces = build.split_raw(MEDIA, piece)
        names = build.split_names(prefix, len(pieces), style=style,
                                  first=first)
        for i, data in enumerate(pieces):
            if first + i not in skip:
                self.write(names[i], data)
        return names

    def test_split_raw_set(self):
        names = self.write_split(3000)
        self.write("split.txt", b"acquisition notes\n")
        self.write("other.002", b"not part of the set")
        img = self.open(os.path.join(self.dir, "split.001"))
        self.assertEqual(img.size, len(MEDIA))
        self.assertEqual(img.read_at(2990, 20), MEDIA[2990:3010])
        self.assertEqual(img.read_at(0, len(MEDIA) + 10), MEDIA)
        self.assertEqual(img.verify()["computed_md5"],
                         hashlib.md5(MEDIA).hexdigest())
        self.assertEqual(img.info()["segments"], names)
        self.assertEqual(img.info()["findings"], [])

    def test_split_raw_set_opened_from_a_later_piece(self):
        self.write_split(3000)
        img = self.open(os.path.join(self.dir, "split.002"))
        self.assertEqual(img.size, len(MEDIA))
        self.assertEqual(img.read_at(0, 10), MEDIA[:10])

    def test_split_raw_set_numbered_from_zero(self):
        names = self.write_split(3000, first=0)
        img = self.open(os.path.join(self.dir, "split.000"))
        self.assertEqual(img.info()["segments"], names)
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_lone_numbered_file_is_a_single_image(self):
        self.write("disk.001", MEDIA)
        img = self.open(os.path.join(self.dir, "disk.001"))
        self.assertEqual(img.info()["segments"], ["disk.001"])
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(img.findings, [])

    def test_missing_piece_is_reported(self):
        self.assertGreater(len(MEDIA), 3 * 2000)
        self.write_split(2000, skip=(3,))
        img = self.open(os.path.join(self.dir, "split.001"))
        self.assertEqual(img.size, 4000)
        self.assertEqual(img.read_at(0, 4000), MEDIA[:4000])
        self.assertEqual(len(img.findings), 1)
        self.assertIn("missing split.003", img.findings[0])
        self.assertIn("split.004", img.findings[0])

        after = self.open(os.path.join(self.dir, "split.004"))
        self.assertEqual(after.info()["segments"], ["split.004"])
        self.assertEqual(after.read_at(0, 10), MEDIA[6000:6010])
        self.assertEqual(len(after.findings), 1)
        self.assertIn("read on its own", after.findings[0])
        self.assertIn("missing split.003", after.findings[0])

    def test_missing_piece_is_reported_when_both_0_and_1_are_absent(self):
        # Regression: when the earliest present piece index is >= 2, `run`
        # starts out empty (piece 1 itself is missing), which used to hit an
        # early return that silently dropped this finding entirely.
        self.assertGreater(len(MEDIA), 3 * 2000)
        self.write_split(2000, skip=(1, 2))
        img = self.open(os.path.join(self.dir, "split.003"))
        self.assertEqual(img.info()["segments"], ["split.003"])
        self.assertEqual(len(img.findings), 1)
        self.assertIn("read on its own", img.findings[0])
        self.assertIn("missing split.001", img.findings[0])

    def test_lone_file_with_a_numeric_extension_is_not_called_incomplete(self):
        self.write("capture.2024", MEDIA[:2000])
        img = self.open(os.path.join(self.dir, "capture.2024"))
        self.assertEqual(img.info()["segments"], ["capture.2024"])
        self.assertEqual(len(img.findings), 1)
        self.assertIn("no other piece is beside it", img.findings[0])
        self.assertNotIn("missing", img.findings[0])

    def test_piece_of_the_wrong_size_is_reported(self):
        self.write_split(3000)
        self.write("split.002", MEDIA[3000:5000])
        img = self.open(os.path.join(self.dir, "split.001"))
        self.assertEqual(len(img.findings), 1)
        self.assertIn("split.002 is 2000 bytes", img.findings[0])

    def test_guymager_four_digit_set(self):
        names = self.write_split(3000, first=0, prefix="gm",
                                 style="guymager")
        self.write("gm.info", b"guymager info\n")
        img = self.open(os.path.join(self.dir, "gm.0000"))
        self.assertEqual(img.info()["segments"], names)
        self.assertEqual(img.size, len(MEDIA))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(img.findings, [])

    def test_split_alphabetic_set(self):
        names = self.write_split(3000, first=0, prefix="disk.dd",
                                 style="split")
        img = self.open(os.path.join(self.dir, "disk.dd.aa"))
        self.assertEqual(img.info()["segments"], names)
        self.assertEqual(img.size, len(MEDIA))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(img.findings, [])

    def test_split_numeric_two_digit_set(self):
        names = self.write_split(3000, first=0, prefix="disk.dd",
                                 style="splitd")
        img = self.open(os.path.join(self.dir, "disk.dd.00"))
        self.assertEqual(img.info()["segments"], names)
        self.assertEqual(img.size, len(MEDIA))
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)
        self.assertEqual(img.findings, [])

    def test_ftk_summary_sidecar_is_not_a_piece(self):
        names = self.write_split(3000, prefix="ev")
        self.write("ev.001.txt", b"Image Summary\n")
        img = self.open(os.path.join(self.dir, "ev.001"))
        self.assertEqual(img.info()["segments"], names)
        self.assertNotIn("ev.001.txt", img.info()["segments"])
        self.assertEqual(img.read_at(0, len(MEDIA)), MEDIA)

    def test_alphabetic_run_must_start_at_aa(self):
        self.write("notes.ab", MEDIA[:100])
        self.write("notes.ac", MEDIA[100:200])
        img = self.open(os.path.join(self.dir, "notes.ab"))
        self.assertEqual(img.info()["segments"], ["notes.ab"])
        self.assertEqual(img.findings, [])

    def test_ordinary_lettered_files_are_not_a_set(self):
        self.write("report.txt", MEDIA[:100])
        self.write("report.log", MEDIA[100:200])
        img = self.open(os.path.join(self.dir, "report.txt"))
        self.assertEqual(img.info()["segments"], ["report.txt"])
        self.assertEqual(img.findings, [])

    def test_mixed_width_set_is_joined_with_a_finding(self):
        pieces = build.split_raw(MEDIA[:9000], 3000)
        self.assertEqual(len(pieces), 3)
        for name, data in zip(["ev.001", "ev.002", "ev.0003"], pieces):
            self.write(name, data)
        img = self.open(os.path.join(self.dir, "ev.001"))
        self.assertEqual(img.info()["segments"],
                         ["ev.001", "ev.002", "ev.0003"])
        self.assertEqual(img.read_at(0, 9000), MEDIA[:9000])
        self.assertEqual(len(img.findings), 1)
        self.assertIn("mixes", img.findings[0])

    def test_missing_piece_names_the_sets_own_width(self):
        self.assertGreater(len(MEDIA), 3 * 2000)
        self.write_split(2000, first=0, skip=(2,), prefix="gm",
                         style="guymager")
        img = self.open(os.path.join(self.dir, "gm.0000"))
        self.assertEqual(img.size, 4000)
        self.assertEqual(len(img.findings), 1)
        self.assertIn("gm.0002", img.findings[0])
        self.assertNotIn("gm.002;", img.findings[0])

    def test_many_pieces_keep_few_files_open(self):
        piece = len(MEDIA) // 40 + 1
        names = self.write_split(piece)
        self.assertGreater(len(names), ewf.RawImage.MAX_OPEN)
        img = self.open(os.path.join(self.dir, "split.001"))
        got = bytearray()
        for off in range(0, len(MEDIA), 777):
            got += img.read_at(off, 777)
        self.assertEqual(bytes(got), MEDIA)
        self.assertLessEqual(len(img._handles), ewf.RawImage.MAX_OPEN)


class OffsetReaderTests(unittest.TestCase):
    class Mem(object):
        bytes_per_sector = 4096

        def read_at(self, off, n):
            return MEDIA[off:off + n] if off >= 0 else b""

    def setUp(self):
        self.r = ewf.OffsetReader(self.Mem(), 1000, 2000, "p1")

    def test_window(self):
        self.assertEqual(self.r.bytes_per_sector, 4096)
        self.assertEqual(self.r.read_at(0, 10), MEDIA[1000:1010])
        self.assertEqual(self.r.read_at(1990, 100), MEDIA[2990:3000])
        self.assertEqual(self.r.read_at(2000, 1), b"")

    def test_negative_and_empty(self):
        self.assertEqual(self.r.read_at(-10, 20), b"")
        self.assertEqual(self.r.read_at(10, 0), b"")

    def test_read_and_seek(self):
        self.r.seek(-4, io.SEEK_END)
        self.assertEqual(self.r.read(), MEDIA[2996:3000])
        self.r.seek(0)
        self.assertEqual(len(self.r.read()), 2000)


if __name__ == "__main__":
    unittest.main()
