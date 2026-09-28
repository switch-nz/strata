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


if __name__ == "__main__":
    unittest.main()
