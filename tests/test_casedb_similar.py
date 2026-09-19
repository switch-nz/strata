import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import casedb, fuzzyhash                              # noqa: E402


def _pseudo_bytes(n, seed):
    out = bytearray()
    h = hashlib.sha256(seed).digest()
    counter = 0
    while len(out) < n:
        h = hashlib.sha256(h + counter.to_bytes(4, "big")).digest()
        out += h
        counter += 1
    return bytes(out[:n])


def insert_hash(case, evidence_id, part, node, fuzzy, sha256="", name="f",
                path="/f", size=8000):
    case.db.execute(
        "INSERT INTO file_hashes (evidence_id, part, node, path, name, size, "
        "deleted, md5, sha1, sha256, fuzzy, read_bytes, computed_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (evidence_id, part, node, path, name, size, 0, "0" * 32, "0" * 40,
         sha256, fuzzy, size, "2026-01-01T00:00:00Z"))
    case.db.commit()


class SimilarFiles(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.case = casedb.Case(os.path.join(self.tmp, "case.strata"),
                                name="t", examiner="ci")
        self.base = _pseudo_bytes(8000, b"near-base")
        mutated = bytearray(self.base)
        mutated[8000 // 3: 8000 // 3 + 1900] = _pseudo_bytes(1900, b"near-edit")
        self.mutated = bytes(mutated)
        self.h_base = fuzzyhash.hash_bytes(self.base)
        self.h_mutated = fuzzyhash.hash_bytes(self.mutated)
        self.h_unrelated = fuzzyhash.hash_bytes(
            _pseudo_bytes(8000, b"unrelated-1"))

    def tearDown(self):
        self.case.close()

    def test_two_alike_files_across_evidence_items_are_paired(self):
        insert_hash(self.case, 1, 0, "1", self.h_base, path="/a")
        insert_hash(self.case, 2, 0, "2", self.h_mutated, path="/b")
        out = self.case.similar_files()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["score"], 93)
        paths = {out[0]["a"]["path"], out[0]["b"]["path"]}
        self.assertEqual(paths, {"/a", "/b"})

    def test_unrelated_files_are_not_paired(self):
        insert_hash(self.case, 1, 0, "1", self.h_base, path="/a")
        insert_hash(self.case, 2, 0, "2", self.h_unrelated, path="/c")
        self.assertEqual(self.case.similar_files(), [])

    def test_a_pair_below_threshold_is_excluded(self):
        insert_hash(self.case, 1, 0, "1", self.h_base, path="/a")
        insert_hash(self.case, 2, 0, "2", self.h_mutated, path="/b")
        self.assertEqual(self.case.similar_files(threshold=94), [])

    def test_exact_duplicates_are_left_to_find_duplicates(self):
        insert_hash(self.case, 1, 0, "1", self.h_base, sha256="a" * 64,
                    path="/a")
        insert_hash(self.case, 2, 0, "2", self.h_base, sha256="a" * 64,
                    path="/b")
        self.assertEqual(self.case.similar_files(), [])

    def test_files_with_no_fuzzy_hash_are_never_compared(self):
        insert_hash(self.case, 1, 0, "1", None, path="/a")
        insert_hash(self.case, 2, 0, "2", self.h_mutated, path="/b")
        self.assertEqual(self.case.similar_files(), [])

    def test_results_are_sorted_highest_score_first(self):
        insert_hash(self.case, 1, 0, "1", self.h_base, path="/a")
        insert_hash(self.case, 2, 0, "2", self.h_mutated, path="/b")
        # A near-identical third copy should outscore the a/b pair.
        near_identical = bytearray(self.base)
        near_identical[0:5] = _pseudo_bytes(5, b"tiny-edit")
        insert_hash(self.case, 3, 0, "3",
                    fuzzyhash.hash_bytes(bytes(near_identical)), path="/c")
        out = self.case.similar_files()
        self.assertGreaterEqual(len(out), 2)
        self.assertGreaterEqual(out[0]["score"], out[-1]["score"])


if __name__ == "__main__":
    unittest.main()
