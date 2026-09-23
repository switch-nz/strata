import unittest
from unittest import mock

from engine import filesearch, textindex


class FakeFs:

    def __init__(self, tree, unreadable=(), content=None):
        self.tree = tree
        self.unreadable = set(unreadable)
        self.content = content or {}
        self.read_calls = []

    def listdir(self, node, path):
        return self.tree.get(node, [])

    def read_file(self, entry, max_bytes=None):
        name = entry["name"]
        self.read_calls.append(name)
        if name in self.unreadable:
            raise OSError("cannot read %s" % name)
        return self.content.get(name, b"")


def build_fs():
    tree = {
        0: [
            {"name": "doc1.txt", "path": "/doc1.txt", "is_dir": False,
             "size": 20, "mft": 10},
            {"name": "empty.txt", "path": "/empty.txt", "is_dir": False,
             "size": 0, "mft": 11},
            {"name": "bad.txt", "path": "/bad.txt", "is_dir": False,
             "size": 5, "mft": 12},
            {"name": "notes.dat", "path": "/notes.dat", "is_dir": False,
             "size": 20, "mft": 13},
            {"name": "sub", "path": "/sub", "is_dir": True, "mft": 14},
        ],
        14: [
            {"name": "doc2.txt", "path": "/sub/doc2.txt", "is_dir": False,
             "size": 20, "mft": 15},
        ],
    }
    content = {
        "doc1.txt": b"the quick brown fox jumps",
        "notes.dat": b"a note that should be filtered out",
        "doc2.txt": b"jumps over the lazy dog here",
    }
    return FakeFs(tree, unreadable=("bad.txt",), content=content)


def build_large_fs(n):
    entries = [{"name": "f%d.txt" % i, "path": "/f%d.txt" % i,
               "is_dir": False, "size": 10, "mft": i}
               for i in range(n)]
    content = {e["name"]: b"some readable text here" for e in entries}
    return FakeFs({0: entries}, content=content)


class FakeIndex:

    def __init__(self):
        self.batches = []
        self.executemany_calls = 0

    def execute(self, sql, params=()):
        return self

    def executemany(self, sql, rows):
        self.executemany_calls += 1
        self.batches.append(list(rows))

    def commit(self):
        pass


class FakeCase:

    def __init__(self):
        self.fts = True
        self.index = FakeIndex()
        self.meta = {}

    def set_index_meta(self, key, value):
        self.meta[key] = value

    def index_add(self, rows):
        self.index.executemany("INSERT", rows)

    def index_remove(self, where="", args=()):
        pass


class Build(unittest.TestCase):

    def test_never_collects_the_whole_tree_into_a_list_first(self):
        # The point of #81: build() must stream the walk, not materialise
        # every entry before indexing the first one.
        with mock.patch.object(filesearch, "collect",
                               side_effect=AssertionError(
                                   "build() must not call collect()")):
            case = FakeCase()
            r = textindex.build(FakeFs({}), case, 0, 0)
        self.assertEqual(r["indexed"], 0)

    def test_indexes_readable_files_and_counts_the_rest_as_skipped(self):
        case = FakeCase()
        r = textindex.build(build_fs(), case, 0, 0)
        self.assertEqual(r["indexed"], 3)
        self.assertEqual(r["candidates"], 5)
        self.assertEqual(r["skip"], {"empty": 1, "unreadable": 1, "no_text": 0})
        paths = {row[1] for batch in case.index.batches for row in batch}
        self.assertEqual(paths, {"/doc1.txt", "/notes.dat", "/sub/doc2.txt"})

    def test_filtered_out_entries_are_never_read(self):
        fs = build_fs()
        case = FakeCase()
        textindex.build(fs, case, 0, 0, filters={"extensions": ["txt"]})
        self.assertNotIn("notes.dat", fs.read_calls)

    def test_a_full_index_keeps_at_most_the_full_cap_of_text_per_file(self):
        fs = FakeFs({0: [{"name": "big.exe", "path": "/big.exe",
                          "is_dir": False, "size": 4000, "mft": 1},
                         {"name": "small.txt", "path": "/small.txt",
                          "is_dir": False, "size": 20, "mft": 2}]},
                    content={"big.exe": b"readable text\0" * 300,
                             "small.txt": b"just a little text"})
        case = FakeCase()
        with mock.patch.object(textindex, "FULL_TEXT_PER_FILE", 1000):
            r = textindex.build(fs, case, 0, 0, read_bytes=None,
                                max_text=None)
        bodies = {row[1]: row[2] for batch in case.index.batches
                  for row in batch}
        self.assertEqual(len(bodies["/big.exe"]), 1000)
        self.assertLess(len(bodies["/small.txt"]), 1000)
        self.assertEqual(r["text_capped"], 1)
        self.assertEqual(r["text_cap"], 1000)

    def test_rows_flush_in_batches_rather_than_once_at_the_end(self):
        case = FakeCase()
        textindex.build(build_fs(), case, 0, 0, batch=1)
        self.assertEqual(case.index.executemany_calls, 3)

    def test_live_names_cover_files_and_folders_by_mft(self):
        case = FakeCase()
        r = textindex.build(build_fs(), case, 0, 0, want_live_names=True)
        self.assertEqual(r["live_names"][10], {"doc1.txt"})
        self.assertEqual(r["live_names"][14], {"sub"})
        self.assertEqual(r["live_names"][15], {"doc2.txt"})

    def test_index_part_meta_records_the_indexed_count(self):
        case = FakeCase()
        textindex.build(build_fs(), case, 3, 0)
        self.assertEqual(case.meta["index_part_3"], "3")

    def test_progress_is_always_a_single_plain_float(self):
        # A caller indexing several partitions in one task (server's
        # whole-disk build) wraps this progress callback in a function
        # that takes exactly one positional argument and nothing else --
        # calling it any other way (e.g. with a count= kwarg) crashes
        # that caller outright.
        seen = []

        def strict_progress(frac):
            seen.append(frac)

        case = FakeCase()
        textindex.build(build_large_fs(80), case, 0, 0,
                        progress=strict_progress)
        self.assertGreater(len(seen), 0)
        self.assertTrue(all(isinstance(f, float) for f in seen))
        self.assertTrue(all(0 <= f <= 1 for f in seen))
        self.assertEqual(seen[-1], 1.0)
        self.assertEqual(seen, sorted(seen))


if __name__ == "__main__":
    unittest.main()
