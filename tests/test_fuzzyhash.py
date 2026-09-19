"""Fixtures below are literal digests captured from ppdeep (a third-party
pure-Python ssdeep implementation), used only while developing this module
to confirm byte-identical output -- ppdeep is not a dependency of Strata or
of this test. `_pseudo_bytes` is a small deterministic generator (built on
hashlib, which is stable across Python versions and platforms) used only to
reproduce those inputs here without embedding large byte literals."""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import fuzzyhash                                      # noqa: E402


def _pseudo_bytes(n, seed):
    out = bytearray()
    h = hashlib.sha256(seed).digest()
    counter = 0
    while len(out) < n:
        h = hashlib.sha256(h + counter.to_bytes(4, "big")).digest()
        out += h
        counter += 1
    return bytes(out[:n])


class HashBytes(unittest.TestCase):

    def test_empty_input(self):
        self.assertEqual(fuzzyhash.hash_bytes(b""), "3::")

    def test_one_byte(self):
        self.assertEqual(fuzzyhash.hash_bytes(b"a"), "3:E:E")

    def test_short_text(self):
        self.assertEqual(fuzzyhash.hash_bytes(b"hello world"), "3:iKFSMPn:rJPn")

    def test_a_run_of_one_byte_never_triggers_a_split(self):
        # A constant rolling hash over a repeated byte never satisfies the
        # trigger condition, so the whole input becomes a single character.
        self.assertEqual(fuzzyhash.hash_bytes(b"x" * 1000), "3:H:H")

    def test_a_two_byte_repeat_also_never_triggers(self):
        self.assertEqual(fuzzyhash.hash_bytes(b"ab" * 5000), "3:uy:uy")

    def test_all_byte_values_repeated(self):
        self.assertEqual(
            fuzzyhash.hash_bytes(bytes(range(256)) * 50),
            "192:znnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"
            "nnb:n")

    def test_block_size_search_retries_down_when_the_first_guess_is_too_short(self):
        # At the naive initial guess (1536, since 1536*64 >= 50000 > 768*64),
        # this input's first-half signature comes out under 32 characters,
        # which must retry down to 768 rather than being accepted as-is.
        data = _pseudo_bytes(50000, b"seed-2")
        self.assertEqual(fuzzyhash._initial_block_size(len(data)), 1536)
        got = fuzzyhash.hash_bytes(data)
        self.assertEqual(
            got,
            "768:nN7Y1aTPvISk8nJkXiLTmTGKxthhldLcHkoU6jweTE2bbUjNtPfxXS:"
            "nNksRjSXHiy/l1sLUMLbbcNRfxC")

    def test_rejects_non_bytes(self):
        with self.assertRaises(TypeError):
            fuzzyhash.hash_bytes("not bytes")

    def test_is_deterministic(self):
        data = _pseudo_bytes(20000, b"repeat-check")
        self.assertEqual(fuzzyhash.hash_bytes(data), fuzzyhash.hash_bytes(data))


class Compare(unittest.TestCase):

    def test_identical_hashes_score_100(self):
        h = fuzzyhash.hash_bytes(_pseudo_bytes(4000, b"self-compare"))
        self.assertEqual(fuzzyhash.compare(h, h), 100)

    def test_unrelated_files_score_zero(self):
        h1 = fuzzyhash.hash_bytes(_pseudo_bytes(8000, b"unrelated-1"))
        h2 = fuzzyhash.hash_bytes(_pseudo_bytes(8000, b"unrelated-2"))
        self.assertEqual(h1, "192:3PBq6jFxf7Moi4E70ZG4KddNbHES3ojV8fW/m4gZC4h"
                              "DH:3PBbjFyUE7k2d8S3ojO0+")
        self.assertEqual(h2, "192:XYvUpV3800tGdJUZ6KlnouD4ov0wnqsLKAq0lwPIAV"
                              "tDM3:IvUpq00tGK6KFFTnLLKAFOg6hO")
        self.assertEqual(fuzzyhash.compare(h1, h2), 0)

    def test_a_localised_edit_scores_high_but_not_perfect(self):
        base = _pseudo_bytes(8000, b"near-base")
        mutated = bytearray(base)
        edit = _pseudo_bytes(1900, b"near-edit")
        mutated[8000 // 3: 8000 // 3 + 1900] = edit
        h1 = fuzzyhash.hash_bytes(base)
        h2 = fuzzyhash.hash_bytes(bytes(mutated))
        score = fuzzyhash.compare(h1, h2)
        self.assertEqual(score, 93)
        self.assertLess(score, 100)

    def test_comparison_is_symmetric(self):
        h1 = fuzzyhash.hash_bytes(_pseudo_bytes(8000, b"near-base"))
        mutated = bytearray(_pseudo_bytes(8000, b"near-base"))
        mutated[100:400] = _pseudo_bytes(300, b"sym-edit")
        h2 = fuzzyhash.hash_bytes(bytes(mutated))
        self.assertEqual(fuzzyhash.compare(h1, h2), fuzzyhash.compare(h2, h1))

    def test_mismatched_block_sizes_score_zero_without_scanning(self):
        # Block size 3 vs 12288: neither equal nor a factor of two apart.
        self.assertEqual(fuzzyhash.compare("3:abc:abc", "12288:xyz:xyz"), 0)

    def test_block_size_double_the_other_is_still_compared(self):
        # Same content, doubled block size: the halves line up (sig2 of a
        # block_size=X pass is sig1 of a block_size=2X pass), so this must
        # not be short-circuited to zero the way an unrelated size is.
        data = _pseudo_bytes(20000, b"double-check")
        h = fuzzyhash.hash_bytes(data)
        bs, s1, s2 = h.split(":")
        doubled = "%d:%s:%s" % (int(bs) * 2, s2, s2)
        self.assertGreater(fuzzyhash.compare(h, doubled), 0)

    def test_rejects_non_string_arguments(self):
        with self.assertRaises(TypeError):
            fuzzyhash.compare(b"3::", "3::")

    def test_rejects_malformed_hash_strings(self):
        with self.assertRaises(ValueError):
            fuzzyhash.compare("not-a-fuzzy-hash", "3::")
        with self.assertRaises(ValueError):
            fuzzyhash.compare("nope:a:b", "3::")


if __name__ == "__main__":
    unittest.main()
