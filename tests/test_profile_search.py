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


if __name__ == "__main__":
    unittest.main()
