"""HFS+ hard links and transparently compressed files, read from synthetic
volumes built by imagebuild_hfsplus (real B-trees, one extent per fork). The
builder's link layout was also opened with libfshfs, an independent reader,
which resolves the same hard link; these tests keep that result as data."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_decmpfs as dc                               # noqa: E402
import imagebuild_hfsplus as hb                               # noqa: E402
from engine import decmpfs                                    # noqa: E402
from engine.ewf import OffsetReader                           # noqa: E402
from engine.fs.ntfs import open_fs                            # noqa: E402

XATTR = "com.apple.decmpfs"


class Mem(object):
    bytes_per_sector = 512

    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


def mount(data):
    img = Mem(data)
    return open_fs(OffsetReader(img, 0, img.size))


def find(fs, name, node=None):
    for e in fs.listdir(fs.root_node if node is None else node):
        if e["name"] == name:
            return e
    raise KeyError(name)


def packed(kind, data, block=dc.BLOCK):
    """(xattr value, resource fork) for `data` compressed as decmpfs `kind`."""
    if kind == 3:
        return dc.inline_value(3, len(data), dc.zlib_block(data)), b""
    if kind == 7:
        return dc.inline_value(7, len(data), dc.lzvn_literals(data)), b""
    if kind == 4:
        forks = dc.zlib_fork([dc.zlib_block(b) for b in dc.split(data)])
    else:
        forks = dc.lzvn_fork([dc.lzvn_literals(b) for b in dc.split(data)])
    return dc.header(kind, len(data)), forks


def compressed(name, kind, data, **kw):
    value, fork = packed(kind, data)
    return hb.File(name, rsrc=fork, xattrs={XATTR: value},
                   owner_flags=0x20, **kw)


import lzfse_vectors                                          # noqa: E402

LZ_STREAM, LZ_PLAIN = lzfse_vectors.unpack(lzfse_vectors.V2)
BIG = bytes((i * 7 + i // 251) & 0xFF for i in range(150000))


class HardLinks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        node = hb.File("iNode100", b"shared contents",
                       xattrs={"user.tag": b"on the node"}, cnid=100,
                       times=1_600_000_000)
        cls.fs = mount(hb.build(
            [hb.File("plain.txt", b"plain"),
             hb.Dir("sub", [hb.Link("second", 100, times=1_650_000_000)]),
             hb.Link("first", 100, times=1_660_000_000),
             hb.Link("gone", 999),
             hb.DirLink("folder", 101)],
            private_files=[node],
            private_dirs=[hb.Dir("dir_101", [hb.File("inside", b"in")],
                                 cnid=101)]))

    def test_link_reads_the_shared_contents(self):
        for e in (find(self.fs, "first"),
                  find(self.fs, "second", find(self.fs, "sub")["cnid"])):
            self.assertEqual(e["size"], 15)
            self.assertEqual(self.fs.read_file(e), b"shared contents")
            self.assertEqual(self.fs.read_range(e, 7, 4), b"cont")

    def test_link_keeps_its_own_identity(self):
        first = find(self.fs, "first")
        second = find(self.fs, "second", find(self.fs, "sub")["cnid"])
        self.assertNotEqual(first["cnid"], second["cnid"])
        self.assertNotEqual(first["cnid"], 100)
        self.assertEqual(first["parent"], self.fs.root_node)
        self.assertTrue(first["hard_link"])
        self.assertEqual(first["link_inode"], 100)
        self.assertEqual(first["link_count"], 2)

    def test_times_are_the_nodes_but_created_is_the_links(self):
        first = find(self.fs, "first")
        self.assertTrue(first["modified"].startswith("2020-09-13"))
        self.assertTrue(first["created"].startswith("2022-08-08"))

    def test_stat_shows_link_and_the_nodes_attributes(self):
        info = self.fs.stat(find(self.fs, "first"))
        self.assertEqual(info["hard_link"]["link_count"], 2)
        self.assertIn("hard link", info["note"])
        self.assertEqual(info["xattrs"][0]["name"], "user.tag")
        self.assertTrue(info["runs"])

    def test_a_file_that_is_not_a_link_is_untouched(self):
        e = find(self.fs, "plain.txt")
        self.assertNotIn("hard_link", e)
        self.assertEqual(self.fs.read_file(e), b"plain")

    def test_missing_node_is_reported_not_guessed(self):
        e = find(self.fs, "gone")
        self.assertTrue(e["hard_link_unresolved"])
        self.assertEqual(e["size"], 0)
        self.assertEqual(self.fs.read_file(e), b"")
        self.assertIn("999", self.fs.stat(e)["note"])
        self.assertTrue(any("1 hard link" in f for f in self.fs.info()["findings"]))

    def test_directory_link_is_listed_but_not_descended_into(self):
        e = find(self.fs, "folder")
        self.assertFalse(e["is_dir"])
        self.assertTrue(e["hard_link_dir"])
        self.assertEqual(e["link_target_cnid"], 101)
        self.assertIn("dir_101", e["hard_link_target"])
        self.assertIn("directory hard link", self.fs.stat(e)["note"])

    def test_directory_link_content_is_at_the_private_folder(self):
        private = find(self.fs, hb.PRIVATE_DIRS)
        target = find(self.fs, "dir_101", private["cnid"])
        self.assertEqual(target["cnid"], 101)
        inside = find(self.fs, "inside", 101)
        self.assertEqual(self.fs.read_file(inside), b"in")


class Compression(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        node = compressed("iNode200", 8, BIG, cnid=200)
        node.name = "iNode200"
        cls.small = b"small file, held in the attribute " * 5
        cls.fs = mount(hb.build(
            [compressed("z-inline", 3, cls.small),
             compressed("z-fork", 4, BIG),
             compressed("l-inline", 7, cls.small),
             compressed("l-fork", 8, BIG),
             compressed("empty", 3, b""),
             hb.File("stored", rsrc=dc.zlib_fork([dc.zlib_block(b"raw!", True)]),
                     xattrs={XATTR: dc.header(4, 4)}, owner_flags=0x20),
             hb.File("raw", xattrs={XATTR: dc.header(9, 500) + b"\xcc"},
                     owner_flags=0x20),
             hb.File("lzfse", xattrs={XATTR: dc.header(
                 11, len(LZ_PLAIN)) + LZ_STREAM}, owner_flags=0x20),
             hb.File("noattr", b"stored text", owner_flags=0x20),
             hb.Link("linked", 200)],
            private_files=[node]))

    def test_each_codec_and_place_decompresses(self):
        for name, want in (("z-inline", self.small), ("z-fork", BIG),
                           ("l-inline", self.small), ("l-fork", BIG)):
            e = find(self.fs, name)
            self.assertEqual(e["size"], len(want), name)
            self.assertEqual(self.fs.read_file(e), want, name)

    def test_size_comes_from_the_header_not_the_empty_data_fork(self):
        e = find(self.fs, "z-fork")
        self.assertEqual(e["_data_extents"], [])
        self.assertEqual(e["size"], len(BIG))
        self.assertEqual(e["uncompressed_size"], len(BIG))
        self.assertIn("zlib", e["compression"])

    def test_ranges_within_and_across_blocks(self):
        e = find(self.fs, "l-fork")
        for off, n in ((0, 10), (dc.BLOCK - 5, 10), (dc.BLOCK, 3),
                       (len(BIG) - 4, 100), (70000, 90000)):
            self.assertEqual(self.fs.read_range(e, off, n), BIG[off:off + n])
        self.assertEqual(self.fs.read_range(e, len(BIG), 5), b"")

    def test_max_bytes_limits_the_read(self):
        e = find(self.fs, "z-fork")
        self.assertEqual(self.fs.read_file(e, 100), BIG[:100])

    def test_stored_block_and_empty_file(self):
        self.assertEqual(self.fs.read_file(find(self.fs, "stored")), b"raw!")
        self.assertEqual(self.fs.read_file(find(self.fs, "empty")), b"")

    def test_resource_fork_stream_is_still_the_raw_fork(self):
        e = find(self.fs, "z-fork")
        raw = self.fs.read_file(e, stream="rsrc")
        self.assertEqual(raw[:4], b"\x00\x00\x01\x00")
        self.assertEqual(len(raw), e["resource_size"])

    def test_stat_says_how_it_is_compressed(self):
        info = self.fs.stat(find(self.fs, "l-fork"))
        self.assertEqual(info["compression"]["uncompressed_size"], len(BIG))
        self.assertIn("LZVN", info["note"])

    def test_lzfse_is_decompressed(self):
        e = find(self.fs, "lzfse")
        self.assertEqual(e["size"], len(LZ_PLAIN))
        self.assertEqual(self.fs.read_file(e), LZ_PLAIN)
        self.assertIn("LZFSE", self.fs.stat(e)["note"])

    def test_a_method_that_is_not_read_is_reported_and_not_faked(self):
        e = find(self.fs, "raw")
        self.assertTrue(e["compression_unsupported"])
        self.assertEqual(e["size"], 0)
        self.assertEqual(self.fs.read_file(e), b"")
        self.assertEqual(e["uncompressed_size"], 500)
        self.assertIn("raw", self.fs.stat(e)["note"])
        self.assertTrue(any("does not decompress" in f
                            for f in self.fs.info()["findings"]))

    def test_flag_without_attribute_is_shown_as_stored(self):
        e = find(self.fs, "noattr")
        self.assertTrue(e["compression_damaged"])
        self.assertEqual(self.fs.read_file(e), b"stored text")
        self.assertTrue(any("no readable decmpfs" in f
                            for f in self.fs.info()["findings"]))

    def test_hard_link_to_a_compressed_file(self):
        e = find(self.fs, "linked")
        self.assertEqual(e["size"], len(BIG))
        self.assertEqual(self.fs.read_file(e), BIG)


class DamagedCompression(unittest.TestCase):

    def test_a_bad_block_reads_as_zeros_and_is_reported(self):
        blocks = [dc.zlib_block(b) for b in dc.split(BIG)]
        blocks[1] = b"\x78\x9c" + b"garbage"
        fs = mount(hb.build([hb.File(
            "f", rsrc=dc.zlib_fork(blocks),
            xattrs={XATTR: dc.header(4, len(BIG))}, owner_flags=0x20)]))
        e = find(fs, "f")
        data = fs.read_file(e)
        self.assertEqual(data[:dc.BLOCK], BIG[:dc.BLOCK])
        self.assertEqual(data[dc.BLOCK:2 * dc.BLOCK], bytes(dc.BLOCK))
        self.assertEqual(data[2 * dc.BLOCK:], BIG[2 * dc.BLOCK:])
        self.assertIn("could not be decompressed", fs.stat(e)["note"])

    def test_unreadable_table_raises_rather_than_returning_data(self):
        fs = mount(hb.build([hb.File(
            "f", rsrc=b"\x00" * 64, xattrs={XATTR: dc.header(4, 1000)},
            owner_flags=0x20)]))
        with self.assertRaises(decmpfs.DecmpfsError):
            fs.read_file(find(fs, "f"))
        self.assertIn("could not be read", fs.stat(find(fs, "f"))["note"])


if __name__ == "__main__":
    unittest.main()
