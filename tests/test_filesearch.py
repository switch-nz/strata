import unittest

from engine import filesearch


class FakeFs:
    """node -> list of listdir() entries, keyed the way engine.fs.* keys
    a directory's contents (by mft here; the field itself doesn't matter
    to filesearch, which only ever reads is_dir/mft/inode/oid/
    start_cluster/name/path off each entry)."""

    def __init__(self, tree):
        self.tree = tree

    def listdir(self, node, path):
        return self.tree.get(node, [])


def build_fs():
    tree = {
        0: [
            {"name": "a.txt", "path": "/a.txt", "is_dir": False, "size": 3},
            {"name": "sub", "path": "/sub", "is_dir": True, "mft": 1},
        ],
        1: [
            {"name": "b.txt", "path": "/sub/b.txt", "is_dir": False, "size": 5},
            {"name": "deeper", "path": "/sub/deeper", "is_dir": True, "mft": 2},
        ],
        2: [
            {"name": "c.txt", "path": "/sub/deeper/c.txt", "is_dir": False,
             "size": 7},
        ],
    }
    return FakeFs(tree)


class WalkStream(unittest.TestCase):

    def test_visits_every_entry_in_the_same_order_as_collect(self):
        fs = build_fs()
        collected = filesearch.collect(fs, 0)
        seen = []
        n = filesearch.walk_stream(fs, 0, seen.append)
        self.assertEqual(seen, collected)
        self.assertEqual(n, len(collected))
        self.assertEqual(n, 5)

    def test_a_budget_stops_the_walk_and_marks_state_truncated(self):
        fs = build_fs()
        state = {}
        seen = []
        n = filesearch.walk_stream(fs, 0, seen.append, budget=2, state=state)
        self.assertEqual(n, 2)
        self.assertEqual(len(seen), 2)
        self.assertTrue(state.get("truncated"))

    def test_on_entry_is_called_immediately_not_batched(self):
        # The whole point of walk_stream over collect(): the caller finds
        # out about an entry as the walk reaches it. A callback that
        # raises must therefore stop the walk partway through, rather
        # than after a list was fully built.
        fs = build_fs()
        seen = []

        def on_entry(e):
            seen.append(e)
            if len(seen) == 2:
                raise RuntimeError("stop here")

        with self.assertRaises(RuntimeError):
            filesearch.walk_stream(fs, 0, on_entry)
        self.assertEqual(len(seen), 2)



class ContentFs(FakeFs):
    def __init__(self, files):
        super().__init__({0: [
            {"name": n, "path": "/" + n, "is_dir": False, "size": len(d),
             "mft": 10 + i} for i, (n, d) in enumerate(files.items())]})
        self.files = files

    def read_file(self, entry, max_bytes=None):
        return self.files[entry["name"]][:max_bytes]


class RegexContent(unittest.TestCase):

    def test_regex_finds_utf16le_content(self):
        fs = ContentFs({"notes.bin": b"\x07" + "key=ABC123".encode(
            "utf-16-le")})
        got = filesearch.search(fs, [r"key=\w+"], root_node=0, mode="content",
                                regex=True)
        self.assertEqual([(h["file_offset"], h["encoding"])
                          for h in got["hits"]], [(1, "utf-16le")])

    def test_regex_ascii_only_when_asked(self):
        fs = ContentFs({"a.bin": b"key=1 " + "key=2".encode("utf-16-le")})
        got = filesearch.search(fs, [r"key=\d"], root_node=0, mode="content",
                                regex=True, encodings=("ascii",))
        self.assertEqual([h["encoding"] for h in got["hits"]], ["ascii"])

if __name__ == "__main__":
    unittest.main()
