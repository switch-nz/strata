import unittest

from engine import profile


class BytesSource:
    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def read_at(self, off, n):
        return self.data[off:off + n]


class SearchTest(unittest.TestCase):

    def test_terms_matching_at_the_same_offset_are_both_reported(self):
        src = BytesSource(b"xxxx password yyyy")
        hits = profile.search(src, ["pass", "password"], encodings=("ascii",))
        self.assertEqual(sorted((h["term"], h["offset"]) for h in hits),
                         [("pass", 5), ("password", 5)])

    def test_hit_in_window_overlap_is_reported_once(self):
        # Window 4096, overlap 1024: the match sits in both windows.
        data = b"\x00" * 3500 + b"needle" + b"\x00" * 3000
        hits = profile.search(BytesSource(data), ["needle"],
                              encodings=("ascii",), window=4096)
        self.assertEqual([h["offset"] for h in hits], [3500])

    def test_regex_matches_utf16le_text_at_either_alignment(self):
        text = "pass=hunter2".encode("utf-16-le")
        data = b"\x01" + text + b"\x00\x00" + text + b"\xff" * 8
        hits = profile.search(BytesSource(data), [r"pass=\w+"], regex=True,
                              encodings=("utf-16le",))
        self.assertEqual([(h["offset"], h["length"], h["encoding"])
                          for h in hits],
                         [(1, len(text), "utf-16le"),
                          (1 + len(text) + 2, len(text), "utf-16le")])

    def test_regex_utf16le_is_not_thrown_off_by_surrogate_pairs(self):
        # A high/low surrogate pair before the match would decode to one
        # character for four bytes and shift every offset after it.
        data = b"\x00\xd8\x00\xdc" + "Страта".encode("utf-16-le")
        hits = profile.search(BytesSource(data), ["страта"], regex=True,
                              encodings=("utf-16le",))
        self.assertEqual([h["offset"] for h in hits], [4])

    def test_regex_respects_the_encodings_asked_for(self):
        data = b"ascii secret " + "wide secret".encode("utf-16-le")
        only_ascii = profile.search(BytesSource(data), ["secret"], regex=True,
                                    encodings=("ascii",))
        self.assertEqual([h["encoding"] for h in only_ascii], ["ascii"])
        both = profile.search(BytesSource(data), ["secret"], regex=True,
                              encodings=("ascii", "utf-16le"))
        self.assertEqual(sorted(h["encoding"] for h in both),
                         ["ascii", "utf-16le"])

    def test_hit_limit_is_reported_with_where_results_are_complete(self):
        data = b"ab " * 100
        cov = {}
        hits = profile.search(BytesSource(data), ["ab"], encodings=("ascii",),
                              max_hits=10, coverage=cov)
        self.assertEqual(len(hits), 10)
        self.assertTrue(cov["truncated"])
        self.assertEqual(cov["complete_to"], 30)
        self.assertTrue(all(h["offset"] < 30 for h in hits))

    def test_hit_limit_across_windows_keeps_every_hit_before_the_cut(self):
        data = (b"x" * 5000 + b"zz") * 40
        cov = {}
        hits = profile.search(BytesSource(data), ["zz"], encodings=("ascii",),
                              max_hits=5, window=8192, coverage=cov)
        self.assertTrue(cov["truncated"])
        want = [o for o in range(5000, len(data), 5002)
                if o < cov["complete_to"]]
        self.assertEqual([h["offset"] for h in hits], want[:5])

    def test_complete_search_is_not_truncated(self):
        cov = {}
        profile.search(BytesSource(b"one two"), ["two"], coverage=cov)
        self.assertEqual(cov, {"truncated": False, "complete_to": 7})



class CountingSource(BytesSource):
    def __init__(self, data):
        super().__init__(data)
        self.read = 0

    def read_at(self, off, n):
        got = super().read_at(off, n)
        self.read += len(got)
        return got


class CoreSample(unittest.TestCase):

    def test_small_scope_is_read_and_classified_whole(self):
        # Each bucket starts with zeros and ends with text: a single read at
        # the start of each bucket would call it all zeroed.
        data = (b"\x00" * 5000 + b"plain words here. " * 70 + b"\n") * 64
        src = CountingSource(data)
        got = profile.profile(src, buckets=64)
        self.assertEqual(src.read, len(data))
        self.assertEqual(got["coverage"], 1.0)
        self.assertIn("Every byte", got["note"])
        self.assertTrue(all(b[0] != profile.ZERO for b in got["buckets"]))

    def test_large_scope_reads_spread_windows_and_says_how_much(self):
        old = profile.FULL_READ_MAX
        profile.FULL_READ_MAX = 1 << 16
        self.addCleanup(setattr, profile, "FULL_READ_MAX", old)
        # 16 buckets of 64 KB: zeros, with random bytes in the last quarter.
        import random
        rng = random.Random(3)
        bucket = bytes(48 << 10) + bytes(rng.getrandbits(8)
                                         for _ in range(16 << 10))
        data = bucket * 16
        src = CountingSource(data)
        got = profile.profile(src, buckets=16, sample=512)
        self.assertEqual(src.read, 16 * profile.WINDOWS * 512)
        self.assertLess(got["coverage"], 1.0)
        self.assertIn("16 evenly spaced reads of 512 bytes", got["note"])
        # The windows reach the end of each bucket, so none reads as zeroed.
        self.assertTrue(all(b[0] != profile.ZERO for b in got["buckets"]))

if __name__ == "__main__":
    unittest.main()
