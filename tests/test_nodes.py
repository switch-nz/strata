"""The handle a filesystem reader gives an entry (engine.nodes), and that
everything which walks or keys entries uses the one rule. HFS+ names its
entries by catalog node ID ("cnid"); most of the code once looked only for
the other readers' keys, so an HFS+ folder was never descended into and an
HFS+ file had no key to tag or hash it under."""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import imagebuild_hfsplus as hb                               # noqa: E402
from engine import filesearch, hashing, nodes, timeline       # noqa: E402
from engine.ewf import OffsetReader                           # noqa: E402
from engine.fs.ntfs import open_fs                            # noqa: E402


class Mem(object):
    bytes_per_sector = 512

    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


def hfs():
    data = hb.build([
        hb.Dir("Top", [hb.Dir("Inner", [hb.File("deep.txt", b"deep")]),
                       hb.File("a.txt", b"aa")]),
        hb.File("root.txt", b"rr")])
    return open_fs(OffsetReader(Mem(data), 0, len(data)))


class Rule(unittest.TestCase):

    def test_each_readers_key_is_found(self):
        for key in ("mft", "inode", "oid", "cnid", "start_cluster"):
            self.assertEqual(nodes.node_of({key: 7, "name": "x"}), 7, key)
            self.assertEqual(nodes.node_key({key: 7}), "7", key)

    def test_zero_is_a_handle(self):
        self.assertEqual(nodes.node_of({"start_cluster": 0}), 0)
        self.assertEqual(nodes.node_key({"mft": 0}), "0")

    def test_an_entry_with_no_handle_has_none(self):
        self.assertIsNone(nodes.node_of({"name": "x"}))
        self.assertIsNone(nodes.node_key({"name": "x"}))

    def test_the_older_names_for_it_are_the_same_function(self):
        entry = {"cnid": 21}
        self.assertEqual(hashing.node_of(entry), 21)
        self.assertEqual(hashing.node_key(entry), "21")
        self.assertEqual(timeline._node_id(entry), 21)


class Hfsplus(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fs = hfs()

    def test_the_shared_walker_descends_into_folders(self):
        got = filesearch.collect(self.fs, self.fs.root_node)
        self.assertEqual(sorted(e["path"] for e in got), [
            "/Top", "/Top/Inner", "/Top/Inner/deep.txt", "/Top/a.txt",
            "/root.txt"])

    def test_every_entry_has_a_handle_to_key_it_by(self):
        for e in filesearch.collect(self.fs, self.fs.root_node):
            self.assertIsNotNone(hashing.node_key(e), e["path"])

    def test_a_folder_lists_by_its_handle(self):
        top = next(e for e in self.fs.listdir(self.fs.root_node)
                   if e["name"] == "Top")
        kids = self.fs.listdir(nodes.node_of(top), top["path"])
        self.assertEqual(sorted(e["name"] for e in kids), ["Inner", "a.txt"])

    def test_an_entry_can_be_found_again_from_its_handle(self):
        deep = next(e for e in filesearch.collect(self.fs, self.fs.root_node)
                    if e["name"] == "deep.txt")
        again = self.fs.entry_by_node(nodes.node_of(deep))
        self.assertEqual(again["path"], "/Top/Inner/deep.txt")
        self.assertEqual(self.fs.read_file(again), b"deep")
        self.assertIsNone(self.fs.entry_by_node(999999))

    def test_the_server_rebuilds_a_readable_entry_from_a_bare_handle(self):
        from engine import server
        deep = next(e for e in filesearch.collect(self.fs, self.fs.root_node)
                    if e["name"] == "deep.txt")
        entry = server._entry_from_body(
            self.fs, {"node": str(nodes.node_of(deep)), "name": "wrong"})
        self.assertEqual(entry["name"], "deep.txt")
        self.assertEqual(self.fs.read_file(entry), b"deep")


class Drift(unittest.TestCase):
    """The rule is written in one place. A copy of it elsewhere is how HFS+
    was left out before, so a copy fails here rather than quietly going
    stale."""

    def source(self, path):
        with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
            return fh.read()

    def test_no_python_module_spells_the_chain_out_again(self):
        chain = re.compile(
            r"get\(\"mft\"\)\s+if\s+\w+\.get\(\"mft\"\)\s+is\s+not\s+None"
            r"|get\(\"oid\"\)\s+if\s+\w+\.get\(\"oid\"\)\s+is\s+not\s+None")
        for name in sorted(os.listdir(os.path.join(ROOT, "engine"))):
            if name.endswith(".py") and name != "nodes.py":
                self.assertIsNone(chain.search(self.source("engine/" + name)),
                                  name)

    def test_the_page_script_does_not_either(self):
        js = self.source("web/app.js")
        self.assertIsNone(re.search(r"\.mft\s*\?\?\s*\w+\.inode", js))
        self.assertIsNone(re.search(r"\.oid\s*\?\?\s*\w+\.mft", js))
        self.assertIn("'cnid'", js)

    def test_the_two_lists_of_keys_agree(self):
        js = self.source("web/app.js")
        found = re.search(r"const NODE_KEYS = \[([^\]]*)\]", js).group(1)
        self.assertEqual(re.findall(r"'(\w+)'", found), list(nodes.KEYS))


if __name__ == "__main__":
    unittest.main()
