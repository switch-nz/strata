"""The cached NTFS tree of a differencing VHD depends on its parents too:
replacing a parent must not serve the listing built from the old one."""

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

os.environ.setdefault("STRATA_CONFIG_DIR",
                      tempfile.mkdtemp(prefix="strata-cfg-"))

import imagebuild_ntfs as ntfs_build                             # noqa: E402
import imagebuild_vhd as vhd_build                               # noqa: E402
from engine import server, treecache                             # noqa: E402

OLD = "hello.txt".encode("utf-16-le")
NEW = "howdy.txt".encode("utf-16-le")
BS = 4096


class Stamp(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-stamp-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.child = self.file("child.vhd", b"c" * 100)
        self.parent = self.file("base.vhd", b"p" * 200)

    def file(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_no_parents_stamps_as_it_always_did(self):
        st = os.stat(self.child)
        self.assertEqual(
            treecache.stamp(self.child, 0),
            "%d:%d:%s:%d:%d" % (treecache.VERSION, 0, None, st.st_size,
                                int(st.st_mtime)))
        self.assertEqual(treecache.stamp(self.child, 0, parents=[]),
                         treecache.stamp(self.child, 0))

    def test_a_parent_changing_size_or_time_changes_the_stamp(self):
        before = treecache.stamp(self.child, 0, parents=[self.parent])
        self.assertNotEqual(before, treecache.stamp(self.child, 0))
        self.assertEqual(before, treecache.stamp(self.child, 0,
                                                 parents=[self.parent]))
        os.utime(self.parent, (1, 1))
        self.assertNotEqual(before, treecache.stamp(self.child, 0,
                                                    parents=[self.parent]))
        mid = treecache.stamp(self.child, 0, parents=[self.parent])
        self.file("base.vhd", b"p" * 999)
        self.assertNotEqual(mid, treecache.stamp(self.child, 0,
                                                 parents=[self.parent]))

    def test_a_parent_that_is_gone_is_a_change(self):
        before = treecache.stamp(self.child, 0, parents=[self.parent])
        os.remove(self.parent)
        after = treecache.stamp(self.child, 0, parents=[self.parent])
        self.assertIsNotNone(after)
        self.assertNotEqual(before, after)


class ReplacedParent(unittest.TestCase):
    """End to end through the server: build and cache the tree, close the
    case, replace the parent with another disk that has the same
    identifier, and reopen."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strata-tree-parent-")
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.volume = ntfs_build.build_ntfs()
        self.assertIn(OLD, self.volume)
        self.uid = b"strata-tree-tst!!"[:16]
        self.child = os.path.join(self.dir, "child.vhd")
        data, _ = vhd_build.sparse(len(self.volume), {}, block_size=BS,
                                   parent=self.uid, parent_name="base.vhd")
        with open(self.child, "wb") as fh:
            fh.write(data)
        self.write_parent(self.volume)
        self.case = os.path.join(self.dir, "case.strata")

    def write_parent(self, volume):
        blocks = {i: (volume[i * BS:(i + 1) * BS].ljust(BS, b"\x00"), None)
                  for i in range((len(volume) + BS - 1) // BS)}
        data, _ = vhd_build.sparse(len(volume), blocks, block_size=BS,
                                   unique_id=self.uid)
        with open(os.path.join(self.dir, "base.vhd"), "wb") as fh:
            fh.write(data)

    def names(self):
        s = server.Session()
        s.open(self.child, self.case, "Alice")
        part = next(p for p in s.volumes["partitions"] if p.get("detected"))
        fs = s.fs(part["offset"])
        got = {e["name"] for e in fs.listdir(fs.root_node, "/")}
        cached = [n for n in os.listdir(s.case.cache_dir())
                  if n.startswith(treecache.PREFIX)]
        s.close_case()
        return got, cached

    def test_replacing_the_parent_discards_the_cached_listing(self):
        first, cached = self.names()
        self.assertIn("hello.txt", first)
        self.assertTrue(cached, "the tree should have been cached")
        # Same identifier, different content: one file renamed. It is a
        # later replacement, so the file is a minute newer.
        self.write_parent(self.volume.replace(OLD, NEW))
        base = os.path.join(self.dir, "base.vhd")
        later = os.stat(base).st_mtime + 60
        os.utime(base, (later, later))
        second, _ = self.names()
        self.assertIn("howdy.txt", second)
        self.assertNotIn("hello.txt", second)

    def test_an_unchanged_parent_still_uses_the_cache(self):
        self.names()
        cache = os.path.join(self.case, "cache")
        files = sorted(os.listdir(cache))
        stamps = {f: os.stat(os.path.join(cache, f)).st_mtime_ns
                  for f in files}
        self.names()
        again = {f: os.stat(os.path.join(cache, f)).st_mtime_ns
                 for f in os.listdir(cache) if f in stamps}
        self.assertEqual(stamps, again)


if __name__ == "__main__":
    unittest.main()
