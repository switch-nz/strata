"""The cross-check harness itself (tests/crosscheck.py): that it cuts images
into the same pieces on both sides, finds differences, keeps the baseline
honest, and withholds names. None of this needs a reference reader."""

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import crosscheck as cc                                       # noqa: E402
import crosscheck_lib as lib                                  # noqa: E402
import crosscheck_refs as refs                                # noqa: E402
import crosscheck_strata as ours                              # noqa: E402


def entry(path, kind="file", size=3, digest="aa", streams=None):
    return lib.entry_observation(path, kind, size, digest, streams)


class ChunkPlan(unittest.TestCase):

    def test_small_image_is_read_whole(self):
        self.assertEqual(lib.chunk_plan(3 * lib.CHUNK + 1), [0, 1, 2, 3])
        self.assertEqual(lib.chunk_plan(0), [])

    def test_budget_keeps_both_ends_and_is_repeatable(self):
        size = 100 * lib.CHUNK
        a = lib.chunk_plan(size, 30, seed=7)
        self.assertEqual(a, lib.chunk_plan(size, 30, seed=7))
        self.assertNotEqual(a, lib.chunk_plan(size, 30, seed=8))
        self.assertEqual(len(a), 30)
        self.assertTrue(set(range(8)) <= set(a))
        self.assertTrue(set(range(92, 100)) <= set(a))

    def test_slice_reads_the_same_bytes(self):
        data = bytes(range(256)) * 8
        s = lib.SliceIO(lib.BytesSource(data), 100, 1000)
        self.assertEqual(s.read(10), data[100:110])
        s.seek(-5, 2)
        self.assertEqual(s.read(50), data[1095:1100])
        self.assertEqual(s.read(5), b"")
        self.assertEqual(s.get_size(), 1000)


class Comparison(unittest.TestCase):

    def test_equal_trees_have_no_differences(self):
        t = [entry("/a"), entry("/d", "dir")]
        self.assertEqual(lib.compare_trees("c", t, list(t)), [])

    def test_each_kind_of_difference_is_named(self):
        ours_ = [entry("/a"), entry("/b", digest="x"), entry("/s")]
        theirs = [entry("/a"), entry("/b", digest="y"), entry("/r")]
        found = {(d["kind"], d["key"])
                 for d in lib.compare_trees("c", ours_, theirs)}
        self.assertEqual(found, {(lib.ONLY_STRATA, "/s"),
                                 (lib.ONLY_REF, "/r"),
                                 (lib.DIFFERS, "/b")})

    def test_streams_are_compared(self):
        a = [entry("/a", streams={"x": (1, "d")})]
        b = [entry("/a", streams={"x": (1, "e")})]
        self.assertEqual(len(lib.compare_trees("c", a, b)), 1)

    def test_disk_content_and_size(self):
        plan = [0]
        good = lib.disk_observation(lambda o, n: b"a" * n, 10, plan)
        bad = lib.disk_observation(lambda o, n: b"b" * n, 10, plan)
        self.assertEqual(lib.compare_disks("c", good, good), [])
        self.assertEqual([d["key"] for d in lib.compare_disks("c", good, bad)],
                         ["content"])
        short = lib.disk_observation(lambda o, n: b"a" * n, 11, plan)
        self.assertIn("size", [d["key"]
                               for d in lib.compare_disks("c", good, short)])

    def test_short_read_is_not_a_match(self):
        obs = lib.disk_observation(lambda o, n: b"a" * (n - 1), 10, [0])
        self.assertTrue(obs["digests"][0].startswith("short:"))


class Baseline(unittest.TestCase):

    def write(self, entries):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(entries, fh)
        self.addCleanup(os.unlink, path)
        return path

    def good(self, **kw):
        e = {"case": "synthetic:x", "facet": "fs", "kind": "differs",
             "key": "/a*", "reason": "because"}
        e.update(kw)
        return e

    def test_shipped_baseline_is_valid(self):
        for e in lib.load_baseline(cc.BASELINE):
            self.assertTrue(e["case"].startswith("synthetic:"))

    def test_entry_needs_a_reason(self):
        with self.assertRaises(lib.BaselineError):
            lib.load_baseline(self.write([self.good(reason="")]))

    def test_real_images_cannot_be_listed(self):
        with self.assertRaises(lib.BaselineError):
            lib.load_baseline(self.write([self.good(case="image:12345678")]))

    def test_unknown_kind_refused(self):
        with self.assertRaises(lib.BaselineError):
            lib.load_baseline(self.write([self.good(kind="odd")]))

    def test_classify(self):
        base = [self.good(), self.good(key="/never")]
        diffs = [lib.difference("fs", "synthetic:x", lib.DIFFERS, "/abc"),
                 lib.difference("fs", "synthetic:x", lib.DIFFERS, "/zzz"),
                 lib.difference("fs", "synthetic:x", lib.ONLY_REF, "/abc")]
        explained, unexplained, stale = lib.classify(diffs, base)
        self.assertEqual([d["key"] for d in explained], ["/abc"])
        self.assertEqual(len(unexplained), 2)
        self.assertEqual([e["key"] for e in stale], ["/never"])


class Redaction(unittest.TestCase):

    def test_names_are_replaced_stably(self):
        r = lib.Redactor(True)
        a = r.path("/Secret folder/plan.doc")
        self.assertNotIn("Secret", a)
        self.assertNotIn("plan", a)
        self.assertEqual(a, r.path("/Secret folder/plan.doc"))
        self.assertEqual(a.count("/"), 2)
        self.assertEqual(r.path("/Secret folder").split("/")[1],
                         a.split("/")[1])

    def test_summary_withholds_names_and_detail(self):
        d = [lib.difference("fs", "image:1", lib.DIFFERS, "/Secret/x.doc",
                            "size: Strata 1, reference 2")]
        text = "\n".join(lib.summarise(d, lib.Redactor(True)))
        self.assertNotIn("Secret", text)
        self.assertNotIn("x.doc", text)
        shown = "\n".join(lib.summarise(d, lib.Redactor(False)))
        self.assertIn("Secret", shown)


class Runner(unittest.TestCase):
    """The runner end to end, with only the always-present reference (the
    file itself) and Strata."""

    def run_case(self, name):
        case = next(c for c in cc.corpus.synthetic()
                    if c.id == "synthetic:" + name)
        opts = cc.argparse.Namespace(chunks=None, seed=1, hash_bytes=1 << 20,
                                     trace=False)
        run = cc.Run(opts)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "image" + case.suffix)
            with open(path, "wb") as fh:
                fh.write(case.build())
            cc.run_case(run, case.id, path)
        return run

    def test_raw_image_agrees_with_the_file(self):
        run = self.run_case("fat12")
        self.assertIn(("synthetic:fat12", "container", "the file itself",
                       cc.AGREE, ""), run.coverage)

    def test_every_case_opens_and_reads_back_as_itself(self):
        for case in cc.corpus.synthetic():
            with self.subTest(case=case.id):
                run = self.run_case(case.id.split(":")[1])
                bad = [d for d in run.diffs
                       if d["facet"] == "container"
                       and d["key"].startswith("strata")]
                self.assertEqual(bad, [])

    def test_a_reference_that_disagrees_is_reported(self):
        saved = list(refs.REFERENCES)

        def liar(path, plan, chunk, key=None):
            with open(path, "rb") as fh:
                size = os.path.getsize(path)
            return lib.disk_observation(lambda o, n: b"\xFF" * n, size,
                                        plan, chunk)
        refs.REFERENCES.append(refs.Reference(
            "container", ("raw",), "liar", (), (), liar, ""))
        try:
            run = self.run_case("ext2")
        finally:
            refs.REFERENCES[:] = saved
        self.assertTrue([d for d in run.diffs
                         if d["facet"] == "container"
                         and d["kind"] == lib.DIFFERS])

    def test_a_refusal_is_a_difference_not_a_crash(self):
        saved = list(refs.REFERENCES)

        def refuse(fileobj, hash_bytes):
            raise refs.Rejected("will not")
        refs.REFERENCES.append(refs.Reference(
            "fs", ("fat",), "refuser", (), (), refuse, ""))
        try:
            run = self.run_case("fat16")
        finally:
            refs.REFERENCES[:] = saved
        self.assertIn("refuser:refused", [d["key"] for d in run.diffs])

    def test_tree_matches_a_known_listing(self):
        case = next(c for c in cc.corpus.synthetic()
                    if c.id == "synthetic:hfsplus")
        from engine import ewf
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "i.img")
            with open(path, "wb") as fh:
                fh.write(case.build())
            img = ewf.open_image(path)
            try:
                fs = ours.open_partition(img, 0, img.size)
                paths = sorted(e["path"] for e in ours.tree(fs, 1 << 20))
            finally:
                img.close()
        self.assertEqual(paths, ["/Top", "/Top/Inner", "/Top/Inner/deep.txt",
                                 "/Top/a.txt", "/root.txt"])


if __name__ == "__main__":
    unittest.main()
