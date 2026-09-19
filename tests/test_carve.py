import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import carve                                          # noqa: E402


class FakeSource:

    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def read_at(self, pos, n):
        if pos < 0 or pos >= self.size:
            return b""
        return self.data[pos:pos + n]


TEST_SIG = carve.Signature("tst", "Test", b"HEAD", b"FOOT", strict=True,
                           max_size=1 << 20)


class ContiguousCarving(unittest.TestCase):

    def test_a_plain_header_to_footer_span_is_one_unfragmented_hit(self):
        data = b"X" * 100 + b"HEAD" + b"middle content" + b"FOOT" + b"Y" * 50
        src = FakeSource(data)
        hits = carve.carve(src, signatures=[TEST_SIG], alignment=1)
        self.assertEqual(len(hits), 1)
        h = hits[0]
        self.assertEqual(h["offset"], 100)
        self.assertEqual(h["method"], "footer")
        self.assertNotIn("fragments", h)
        self.assertNotIn("gap", h)
        self.assertEqual(data[h["offset"]:h["offset"] + h["length"]],
                         b"HEAD" + b"middle content" + b"FOOT")


class BifragmentGapCarving(unittest.TestCase):

    def _build(self, frag1, gap, frag2, prefix=b"", suffix=b""):
        header_and_frag1 = b"HEAD" + frag1
        gap_start = len(prefix) + len(header_and_frag1)
        gap_end = gap_start + len(gap)
        frag2_and_footer = frag2 + b"FOOT"
        data = prefix + header_and_frag1 + gap + frag2_and_footer + suffix
        return data, gap_start, gap_end

    def test_a_single_allocated_gap_splits_the_hit_into_two_fragments(self):
        data, gap_start, gap_end = self._build(
            b"first fragment content", b"UNRELATED-ALLOCATED-DATA-HERE",
            b"second fragment content")
        src = FakeSource(data)
        hits = carve.carve(src, signatures=[TEST_SIG], alignment=1,
                           exclude=[[gap_start, gap_end]])
        self.assertEqual(len(hits), 1)
        h = hits[0]
        # The outer span is unchanged -- jumpTo/bookmark/tag keep working.
        self.assertEqual(h["offset"], 0)
        self.assertEqual(h["offset"] + h["length"], len(data))
        self.assertIn("fragments", h)
        frag1, frag2 = h["fragments"]
        self.assertEqual(frag1, [0, gap_start])
        self.assertEqual(frag2, [gap_end, len(data) - gap_end])
        self.assertEqual(h["gap"], {"offset": gap_start,
                                    "length": gap_end - gap_start})
        # Concatenating the two fragments reconstructs the real file,
        # with the unrelated gap bytes excluded.
        reconstructed = (data[frag1[0]:frag1[0] + frag1[1]] +
                         data[frag2[0]:frag2[0] + frag2[1]])
        self.assertEqual(reconstructed,
                         b"HEAD" + b"first fragment content" +
                         b"second fragment content" + b"FOOT")

    def test_two_separate_gaps_are_left_unsplit(self):
        # More than one gap means more than two fragments, out of scope.
        data = (b"HEAD" + b"a" * 20 +
                b"GAP-ONE-------------" +
                b"b" * 20 +
                b"GAP-TWO-------------" +
                b"c" * 20 + b"FOOT")
        gap1 = (4 + 20, 4 + 20 + 21)
        gap2 = (gap1[1] + 20, gap1[1] + 20 + 21)
        src = FakeSource(data)
        hits = carve.carve(src, signatures=[TEST_SIG], alignment=1,
                           exclude=[list(gap1), list(gap2)])
        self.assertEqual(len(hits), 1)
        self.assertNotIn("fragments", hits[0])

    def test_a_gap_overlapping_the_header_is_rejected(self):
        # frag1 would be shorter than the header itself -- refuse to split.
        data = b"HEAD" + b"a" * 20 + b"middle" + b"FOOT"
        gap = [2, 12]  # starts 2 bytes into "HEAD"
        src = FakeSource(data)
        hits = carve.carve(src, signatures=[TEST_SIG], alignment=1,
                           exclude=[gap])
        self.assertEqual(len(hits), 1)
        self.assertNotIn("fragments", hits[0])

    def test_a_gap_overlapping_the_footer_is_rejected(self):
        # frag2 would be shorter than the footer itself -- refuse to split.
        data = b"HEAD" + b"a" * 20 + b"FOOT"
        gap = [19, 26]  # ends 2 bytes into "FOOT" (which starts at 24)
        src = FakeSource(data)
        hits = carve.carve(src, signatures=[TEST_SIG], alignment=1,
                           exclude=[gap])
        self.assertEqual(len(hits), 1)
        self.assertNotIn("fragments", hits[0])

    def test_a_second_gap_outside_the_span_does_not_block_the_split(self):
        data, gap_start, gap_end = self._build(
            b"first fragment content", b"UNRELATED-ALLOCATED-DATA-HERE",
            b"second fragment content", suffix=b"Z" * 40)
        far_gap = [len(data) - 10, len(data) - 5]
        src = FakeSource(data)
        hits = carve.carve(src, signatures=[TEST_SIG], alignment=1,
                           exclude=[[gap_start, gap_end], far_gap])
        self.assertEqual(len(hits), 1)
        h = hits[0]
        self.assertIn("fragments", h)
        self.assertEqual(h["gap"]["offset"], gap_start)

    def test_a_sizer_based_signature_is_never_split(self):
        # Only footer-confirmed lengths are trusted enough to split -- a
        # structural sizer crossing a gap is a correctness risk this pass
        # does not take on.
        sizer_sig = carve.Signature(
            "tst2", "Sized test", b"HEAD",
            sizer=lambda buf: 40 if len(buf) >= 40 else None, strict=True)
        data = b"HEAD" + b"a" * 20 + b"GAP-DATA-HERE-XXXXXX" + b"b" * 100
        gap = [4 + 20, 4 + 20 + 21]
        src = FakeSource(data)
        hits = carve.carve(src, signatures=[sizer_sig], alignment=1,
                           exclude=[gap])
        self.assertEqual(len(hits), 1)
        self.assertNotIn("fragments", hits[0])


if __name__ == "__main__":
    unittest.main()
