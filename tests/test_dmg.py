"""The Apple disk image (UDIF) reader (engine.dmg), against synthetic images
from imagebuild_dmg. The builder follows the published layout; no DMG written
by Apple's tools is in the repository to check either against."""

import os
import random
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_dmg as b                                    # noqa: E402
import imagebuild_fat                                         # noqa: E402
import lzfse_vectors                                          # noqa: E402
from engine import dmg, ewf                                   # noqa: E402


def disk(sectors, seed=1, holes=()):
    rng = random.Random(seed)
    out = bytearray()
    for s in range(sectors):
        if s in holes:
            out += bytes(512)
        else:
            out += bytes(rng.choice(b"abcdefgh \n") for _ in range(512))
    return bytes(out)


class Tmp(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-dmg-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))

    def write(self, data, name="t.dmg"):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def open(self, data):
        img = ewf.open_image(self.write(data))
        self.addCleanup(img.close)
        return img


class Reading(Tmp):

    def test_every_chunk_kind_reads_back_exactly(self):
        plain = disk(80, holes=range(16, 24))
        img = self.open(b.build([("disk image", 0, plain)]))
        self.assertIsInstance(img, dmg.DmgImage)
        self.assertEqual(img.size, len(plain))
        self.assertEqual(img.read_at(0, len(plain)), plain)
        kinds = img.info()["acquisition"]["chunk types"]
        for name in ("zlib", "bzip2", "LZMA", "raw", "LZFSE", "zero fill"):
            self.assertIn(name, kinds)
        self.assertEqual(img.findings, [])

    def test_reads_that_cross_chunks_and_start_anywhere(self):
        plain = disk(80)
        img = self.open(b.build([("disk image", 0, plain)]))
        rng = random.Random(2)
        for _ in range(200):
            off = rng.randrange(len(plain))
            n = rng.randint(1, 5000)
            self.assertEqual(img.read_at(off, n), plain[off:off + n])
        self.assertEqual(img.read_at(len(plain), 10), b"")
        self.assertEqual(img.read_at(-1, 10), b"")
        self.assertEqual(img.read_at(len(plain) - 3, 100), plain[-3:])

    def test_partitions_are_placed_by_their_first_sector_and_gaps_are_zeros(self):
        a, c = disk(16, seed=3), disk(16, seed=4)
        img = self.open(b.build([("gpt", 0, a), ("data", 40, c)],
                                total_sectors=64))
        self.assertEqual(img.size, 64 * 512)
        self.assertEqual(img.read_at(0, 16 * 512), a)
        self.assertEqual(img.read_at(16 * 512, 24 * 512), bytes(24 * 512))
        self.assertEqual(img.read_at(40 * 512, 16 * 512), c)
        self.assertEqual(img.read_at(56 * 512, 8 * 512), bytes(8 * 512))
        self.assertTrue(any("cover" in f for f in img.findings))

    def test_real_lzfse_chunk_from_apples_encoder(self):
        stream, plain = lzfse_vectors.unpack(lzfse_vectors.SECTORS)
        sectors = len(plain) // 512
        fork = stream
        table = b.mish(0, sectors, [(b.LZFSE, 0, sectors, 0, len(stream))])
        data = self.dmg_from(fork, [table], sectors)
        img = self.open(data)
        self.assertEqual(img.read_at(0, len(plain)), plain)

    def dmg_from(self, fork, tables, sectors):
        import plistlib
        entries = [{"Attributes": "0x0050", "CFName": "x", "Data": t,
                    "ID": "0", "Name": "x"} for t in tables]
        xml = plistlib.dumps({"resource-fork": {"blkx": entries}})
        tr = bytearray(512)
        tr[:4] = b"koly"
        struct.pack_into(">II", tr, 4, 4, 512)
        struct.pack_into(">IQQQQQII", tr, 12, 1, 0, 0, len(fork), 0, 0, 1, 1)
        struct.pack_into(">QQ", tr, 216, len(fork), len(xml))
        struct.pack_into(">IQ", tr, 488, 1, sectors)
        return fork + xml + bytes(tr)

    def test_verify_hashes_the_disk_as_read(self):
        import hashlib
        plain = disk(24)
        img = self.open(b.build([("d", 0, plain)]))
        got = img.verify()
        self.assertEqual(got["computed_md5"], hashlib.md5(plain).hexdigest())
        self.assertEqual(got["computed_sha1"], hashlib.sha1(plain).hexdigest())

    def test_a_filesystem_inside_is_found_and_listed(self):
        fat = imagebuild_fat.build_fat(16)
        fat += bytes(-len(fat) % 512)
        img = self.open(b.build([("disk image", 0, fat)], chunk_sectors=256))
        self.assertEqual(img.read_at(0, len(fat)), fat)
        from engine.fs.ntfs import open_fs
        from engine.ewf import OffsetReader
        fs = open_fs(OffsetReader(img, 0, img.size))
        names = {e["name"] for e in fs.listdir(fs.root_node)}
        self.assertTrue(names)

    def test_damaged_compressed_chunk_reads_as_zeros_and_says_so(self):
        plain = disk(16)
        data = bytearray(b.build([("d", 0, plain)], kinds=(b.ZLIB,),
                                 chunk_sectors=8))
        data[12:24] = b"\xff" * 12            # inside the first zlib payload
        img = self.open(bytes(data))
        got = img.read_at(0, len(plain))
        self.assertEqual(got[:4096], bytes(4096))
        self.assertEqual(got[4096:], plain[4096:])
        self.assertTrue(any("would not decompress" in f
                            for f in img.findings))

    def test_a_chunk_that_decompresses_short_is_padded_and_reported(self):
        plain = disk(8)
        data = b.build([("d", 0, plain)], kinds=(b.RAW,), chunk_sectors=8)
        # Rewrite the table: a zlib chunk of half a chunk's data.
        import zlib
        half = zlib.compress(plain[:2048])
        table = b.mish(0, 8, [(b.ZLIB, 0, 8, 0, len(half))])
        img = self.open(self.dmg_from(half, [table], 8))
        got = img.read_at(0, 4096)
        self.assertEqual(got[:2048], plain[:2048])
        self.assertEqual(got[2048:], bytes(2048))
        self.assertTrue(any("not the" in f for f in img.findings))


class Refusals(Tmp):

    def refused(self, data, text):
        with self.assertRaises(ewf.UnsupportedContainer) as cm:
            ewf.open_image(self.write(data))
        self.assertIn(text, str(cm.exception))
        return cm.exception

    def test_encrypted(self):
        data = b.build([("d", 0, disk(8))], prefix=b"encrcdsa" + bytes(100))
        self.refused(data, "encrypted")

    def test_segmented(self):
        self.refused(b.build([("d", 0, disk(8))], segments=3), "3 segments")

    def test_adc_chunks(self):
        e = self.refused(b.build([("d", 0, disk(8))], kinds=(b.ADC,)), "ADC")
        self.assertIn("hdiutil", e.advice)

    def test_an_unknown_chunk_type(self):
        self.refused(b.build([("d", 0, disk(8))], kinds=(0x80000063,)),
                     "0x80000063")

    def test_overlapping_chunks(self):
        data = b.build([("a", 0, disk(8)), ("b", 4, disk(8, seed=2))])
        self.refused(data, "overlap")

    def test_chunk_outside_the_file(self):
        def damage(plist):
            blob = bytearray(plist["resource-fork"]["blkx"][0]["Data"])
            struct.pack_into(">Q", blob, 204 + 24, 1 << 40)   # first offset
            plist["resource-fork"]["blkx"][0]["Data"] = bytes(blob)
        self.refused(b.build([("d", 0, disk(8))], plist_fixups=damage),
                     "outside the image file")

    def test_a_compressed_chunk_claiming_a_huge_size(self):
        def damage(plist):
            blob = bytearray(plist["resource-fork"]["blkx"][0]["Data"])
            struct.pack_into(">Q", blob, 204 + 16, 1 << 30)   # sectors
            plist["resource-fork"]["blkx"][0]["Data"] = bytes(blob)
        self.refused(b.build([("d", 0, disk(8))], kinds=(b.ZLIB,),
                             plist_fixups=damage), "more than Strata reads")

    def test_missing_or_garbage_plist(self):
        def garbage(trailer):
            struct.pack_into(">QQ", trailer, 216, 0, 0)
        self.refused(b.build([("d", 0, disk(8))], trailer_fixups=garbage),
                     "property list")

        def no_blkx(plist):
            plist["resource-fork"] = {}
        self.refused(b.build([("d", 0, disk(8))], plist_fixups=no_blkx),
                     "property list")

    def test_damaged_table(self):
        def damage(plist):
            plist["resource-fork"]["blkx"][0]["Data"] = b"mish" + bytes(10)
        self.refused(b.build([("d", 0, disk(8))], plist_fixups=damage),
                     "block table")

    def test_sparse_image_is_named_and_refused(self):
        self.refused(b"sprs" + bytes(600), "Apple sparse image")


class Detection(Tmp):

    def test_the_trailer_needs_its_version_and_size_not_just_the_word(self):
        tail = bytearray(512)
        tail[:4] = b"koly"
        self.assertFalse(dmg.looks_like_dmg(bytes(tail)))
        struct.pack_into(">II", tail, 4, 4, 512)
        self.assertTrue(dmg.looks_like_dmg(bytes(tail)))
        struct.pack_into(">II", tail, 4, 4, 100)
        self.assertFalse(dmg.looks_like_dmg(bytes(tail)))

    def test_a_raw_file_that_merely_ends_in_koly_is_still_raw(self):
        path = self.write(bytes(4096) + b"koly" + bytes(100))
        img = ewf.open_image(path)
        self.addCleanup(img.close)
        self.assertNotIsInstance(img, dmg.DmgImage)

    def test_a_small_file_is_not_a_dmg(self):
        img = ewf.open_image(self.write(b"x" * 100))
        self.addCleanup(img.close)
        self.assertNotIsInstance(img, dmg.DmgImage)

    def test_dmg_is_offered_when_browsing_for_images(self):
        from engine import server
        self.assertIn(".dmg", server.IMAGE_EXTS)


class Damage(Tmp):

    def test_random_damage_is_refused_or_read_never_crashes(self):
        base = b.build([("d", 0, disk(40))])
        rng = random.Random(6)
        for _ in range(300):
            data = bytearray(base)
            for _ in range(rng.randint(1, 20)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            path = self.write(bytes(data))
            try:
                img = ewf.open_image(path)
            except ewf.UnsupportedContainer:
                continue
            try:
                if isinstance(img, dmg.DmgImage):
                    for at in range(0, min(img.size, 8 << 20), 1 << 20):
                        img.read_at(at, 1 << 20)
                    img.info()
            finally:
                img.close()


if __name__ == "__main__":
    unittest.main()
