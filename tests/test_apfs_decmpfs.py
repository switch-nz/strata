"""Transparently compressed files (decmpfs) on APFS, read from synthetic
containers. The container is imagebuild_apfs's, with its catalog replaced by
one that holds compressed files: the compressed data is either in the
com.apple.decmpfs attribute itself or, for the resource-fork types, in a
com.apple.ResourceFork attribute whose value is a data stream."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_apfs as build                               # noqa: E402
import imagebuild_decmpfs as dc                               # noqa: E402
from engine import decmpfs                                    # noqa: E402
from engine.ewf import OffsetReader                           # noqa: E402
from engine.fs.ntfs import open_fs                            # noqa: E402

BIG = bytes((i * 7 + i // 251) & 0xFF for i in range(150000))
SMALL = b"held in the attribute " * 8
UF_COMPRESSED = 0x20


def xattr_rec(oid, name, flags, body):
    raw = name.encode() + b"\x00"
    key = struct.pack("<QH", (build.TYPE_XATTR << 60) | oid, len(raw)) + raw
    return key, struct.pack("<HH", flags, len(body)) + body


def embedded(oid, name, value):
    return xattr_rec(oid, name, 0x0002, value)


def stream(oid, name, obj, size):
    body = struct.pack("<QQQQQ", obj, size, size, 0, 0)
    return xattr_rec(oid, name, 0x0001, body)


class Volume(object):
    """A container with the given files, opened as the server would."""

    def __init__(self, files):
        # files: [(name, bsd_flags, [xattr records], fork bytes or None)]
        recs = [(struct.pack("<Q", (build.TYPE_INODE << 60) | 2),
                 build.inode_value(2, 0, 0, is_dir=True))]
        extra = bytearray()
        next_block = build.NEXT_FREE
        oid = 0x10
        self.oids = {}
        for name, flags, xattrs, fork in files:
            self.oids[name] = oid
            recs.append((struct.pack("<Q", (build.TYPE_INODE << 60) | oid),
                         build.inode_value(oid, 2, 0, bsd_flags=flags)))
            recs.append((build.drec_key(name), build.drec_value(oid)))
            for make in xattrs:
                recs.append(make(oid))
            if fork is not None:
                obj = oid + 0x1000
                blocks = -(-len(fork) // build.BLOCK_SIZE)
                recs.append((struct.pack("<QQ", (build.TYPE_FILE_EXTENT << 60) | obj, 0),
                             build.extent_value(blocks * build.BLOCK_SIZE,
                                                next_block)))
                extra += fork.ljust(blocks * build.BLOCK_SIZE, b"\x00")
                next_block += blocks
                self.forks = getattr(self, "forks", {})
                self.forks[name] = (obj, len(fork))
            oid += 1
        saved = build.LIVE_CATALOG
        build.LIVE_CATALOG = recs
        try:
            image = build.build_image(None, [
                (build.CATALOG_OID, build.BLK_CATALOG, build.LIVE_XID)])
        finally:
            build.LIVE_CATALOG = saved
        data = image + bytes(extra)
        self.image = _Mem(data)
        self.fs = open_fs(OffsetReader(self.image, 0, self.image.size))

    def entry(self, name):
        for e in self.fs.listdir(self.fs.root_node):
            if e["name"] == name:
                return e
        raise KeyError(name)


class _Mem(object):
    bytes_per_sector = 512

    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


def compressed_file(kind, data, name, stream_obj=None):
    """(name, flags, xattrs, fork) for `data` held as decmpfs `kind`."""
    if kind in (3, 7):
        codec = dc.zlib_block if kind == 3 else dc.lzvn_literals
        value = dc.inline_value(kind, len(data), codec(data))
        return (name, UF_COMPRESSED,
                [lambda oid: embedded(oid, "com.apple.decmpfs", value)], None)
    fork = (dc.zlib_fork([dc.zlib_block(b) for b in dc.split(data)])
            if kind == 4 else
            dc.lzvn_fork([dc.lzvn_literals(b) for b in dc.split(data)]))
    value = dc.header(kind, len(data))
    return (name, UF_COMPRESSED,
            [lambda oid: embedded(oid, "com.apple.decmpfs", value),
             lambda oid: stream(oid, "com.apple.ResourceFork",
                                oid + 0x1000, len(fork))], fork)


class Compressed(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.v = Volume([
            compressed_file(3, SMALL, "z-inline"),
            compressed_file(7, SMALL, "l-inline"),
            compressed_file(4, BIG, "z-fork"),
            compressed_file(8, BIG, "l-fork"),
            ("lzfse", UF_COMPRESSED,
             [lambda oid: embedded(oid, "com.apple.decmpfs",
                                   dc.header(11, 900) + b"bvx2")], None),
            ("flagged", UF_COMPRESSED, [], None),
            ("unflagged", 0,
             [lambda oid: embedded(oid, "com.apple.decmpfs",
                                   dc.inline_value(3, 4, dc.zlib_block(b"abcd")))],
             None),
        ])
        cls.fs = cls.v.fs

    def test_each_codec_and_place_decompresses(self):
        for name, want in (("z-inline", SMALL), ("l-inline", SMALL),
                           ("z-fork", BIG), ("l-fork", BIG)):
            e = self.v.entry(name)
            self.assertEqual(e["size"], len(want), name)
            self.assertEqual(self.fs.read_file(e), want, name)

    def test_ranges_and_limits(self):
        e = self.v.entry("z-fork")
        for off, n in ((0, 9), (dc.BLOCK - 3, 8), (140000, 50000)):
            self.assertEqual(self.fs.read_range(e, off, n), BIG[off:off + n])
        self.assertEqual(self.fs.read_file(e, 50), BIG[:50])

    def test_stat_describes_the_compression(self):
        info = self.fs.stat(self.v.entry("l-fork"))
        self.assertEqual(info["compression"]["uncompressed_size"], len(BIG))
        self.assertIn("LZVN", info["note"])

    def test_lzfse_is_reported_not_faked(self):
        e = self.v.entry("lzfse")
        self.assertTrue(e["compression_unsupported"])
        self.assertEqual(self.fs.read_file(e), b"")
        self.assertIn("LZFSE", self.fs.stat(e)["note"])
        self.assertTrue(any("does not decompress" in f
                            for f in self.fs.info()["findings"]))

    def test_flag_without_attribute_is_shown_as_stored(self):
        e = self.v.entry("flagged")
        self.assertTrue(e["compression_damaged"])
        self.assertEqual(e["size"], 0)
        self.assertIn("no readable", self.fs.stat(e)["note"])

    def test_attribute_without_the_flag_is_not_applied(self):
        e = self.v.entry("unflagged")
        self.assertNotIn("compression", e)
        self.assertEqual(e["size"], 0)

    def test_bad_table_raises(self):
        v = Volume([("bad", UF_COMPRESSED,
                     [lambda oid: embedded(oid, "com.apple.decmpfs",
                                           dc.header(4, 100)),
                      lambda oid: stream(oid, "com.apple.ResourceFork",
                                         oid + 0x1000, 64)],
                     b"\x00" * 64)])
        with self.assertRaises(decmpfs.DecmpfsError):
            v.fs.read_file(v.entry("bad"))


if __name__ == "__main__":
    unittest.main()
