import unittest

from engine import fuzzyhash, hashing


class FakeFs:
    def __init__(self, data):
        self._data = data

    def read_file(self, entry, max_bytes=None):
        data = self._data
        return data[:max_bytes] if max_bytes is not None else data


class FakeCase:
    """Stubs the two casedb methods matched_hash_map depends on."""

    def __init__(self, hashes, hash_sets=None):
        self._hashes = hashes
        self._sets = hash_sets or {}
        self.match_calls = []

    def hash_map(self, evidence_id, part):
        return {k: dict(v) for k, v in self._hashes.items()}

    def match_hashes(self, digests):
        self.match_calls.append(list(digests))
        out = {}
        for d in digests:
            hits = self._sets.get(d.lower())
            if hits:
                out[d.lower()] = hits
        return out


class MatchedHashMap(unittest.TestCase):

    def test_a_node_with_no_hash_set_hit_is_left_unmarked(self):
        case = FakeCase({"5": {"md5": "aa", "sha1": "bb", "sha256": "cc"}})
        out = hashing.matched_hash_map(case, 1, 0)
        self.assertNotIn("match_kind", out["5"])
        self.assertNotIn("matches", out["5"])

    def test_a_matching_digest_is_labelled_with_its_kind(self):
        case = FakeCase(
            {"5": {"md5": "aa", "sha1": "bb", "sha256": "cc"}},
            {"cc": [{"algo": "sha256", "kind": "known_bad",
                     "set": "malware", "label": None}]})
        out = hashing.matched_hash_map(case, 1, 0)
        self.assertEqual(out["5"]["match_kind"], "known_bad")
        self.assertEqual(out["5"]["matches"][0]["set"], "malware")

    def test_known_bad_wins_over_notable_and_known_good(self):
        case = FakeCase(
            {"5": {"md5": "aa", "sha1": "bb", "sha256": "cc"}},
            {"aa": [{"algo": "md5", "kind": "known_good",
                     "set": "nsrl", "label": None}],
             "cc": [{"algo": "sha256", "kind": "known_bad",
                     "set": "malware", "label": None}]})
        out = hashing.matched_hash_map(case, 1, 0)
        self.assertEqual(out["5"]["match_kind"], "known_bad")
        self.assertEqual(len(out["5"]["matches"]), 2)

    def test_an_empty_hash_map_never_queries_hash_sets(self):
        case = FakeCase({})
        out = hashing.matched_hash_map(case, 1, 0)
        self.assertEqual(out, {})
        self.assertEqual(case.match_calls, [])

    def test_matching_is_scoped_to_the_digests_algorithm(self):
        # A sha256 that happens to equal a stored md5 digest must not match.
        case = FakeCase(
            {"5": {"md5": "aa", "sha1": "bb", "sha256": "cc"}},
            {"aa": [{"algo": "sha256", "kind": "known_bad",
                     "set": "malware", "label": None}]})
        out = hashing.matched_hash_map(case, 1, 0)
        self.assertNotIn("match_kind", out["5"])


class AnnotateHits(unittest.TestCase):

    def test_a_hit_whose_node_matches_gets_the_kind_and_matches(self):
        hits = [{"mft": 5, "name": "evil.exe"}, {"mft": 9, "name": "clean.txt"}]
        matched = {"5": {"match_kind": "known_bad",
                         "matches": [{"set": "malware"}]}}
        hashing.annotate_hits(hits, matched)
        self.assertEqual(hits[0]["match_kind"], "known_bad")
        self.assertEqual(hits[0]["matches"], [{"set": "malware"}])
        self.assertNotIn("match_kind", hits[1])

    def test_a_hit_with_no_resolvable_node_is_left_alone(self):
        hits = [{"name": "raw-hit-with-no-fs-node"}]
        hashing.annotate_hits(hits, {"5": {"match_kind": "known_bad"}})
        self.assertNotIn("match_kind", hits[0])

    def test_node_lookup_uses_inode_oid_and_start_cluster_too(self):
        hits = [{"inode": 7}, {"oid": 11}, {"start_cluster": 42}]
        matched = {"7": {"match_kind": "notable", "matches": []},
                   "11": {"match_kind": "known_good", "matches": []},
                   "42": {"match_kind": "known_bad", "matches": []}}
        hashing.annotate_hits(hits, matched)
        self.assertEqual([h["match_kind"] for h in hits],
                         ["notable", "known_good", "known_bad"])


class HashEntry(unittest.TestCase):

    def test_fuzzy_hash_matches_the_dedicated_module(self):
        data = b"some file content" * 50
        fs = FakeFs(data)
        row = hashing.hash_entry(fs, {"mft": 5, "size": len(data)})
        self.assertEqual(row["fuzzy"], fuzzyhash.hash_bytes(data))

    def test_an_empty_file_gets_no_fuzzy_hash(self):
        fs = FakeFs(b"")
        row = hashing.hash_entry(fs, {"mft": 5, "size": 0})
        self.assertIsNone(row["fuzzy"])


if __name__ == "__main__":
    unittest.main()
