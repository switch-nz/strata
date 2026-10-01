"""The LZFSE decoder (engine.lzfse), against streams written by Apple's
reference encoder (embedded in lzfse_vectors) and against damage."""

import os
import random
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lzfse_vectors as vectors                               # noqa: E402
from engine import lzfse                                      # noqa: E402


class Reference(unittest.TestCase):

    def test_each_block_kind_from_the_reference_encoder(self):
        kinds = {"V2": b"bvx2", "LZVN": b"bvxn", "RAW": b"bvx-"}
        for name, magic in kinds.items():
            stream, plain = vectors.unpack(getattr(vectors, name))
            self.assertEqual(stream[:4], magic, name)
            self.assertEqual(lzfse.decode(stream), plain, name)

    def test_blocks_of_every_kind_in_one_stream(self):
        stream, plain = vectors.unpack(vectors.CHAIN)
        self.assertEqual(lzfse.decode(stream), plain)

    def test_the_v2_block_really_holds_literals_and_matches(self):
        stream, _ = vectors.unpack(vectors.V2)
        h, _size = lzfse._unpack_v2(stream, 0)
        self.assertGreater(h["n_literals"], 100)
        self.assertGreater(h["n_matches"], 500)

    def test_a_v1_block_is_read_too(self):
        """The same block with its tables written out in full (bvx1), as
        older encoders wrote it."""
        stream, plain = vectors.unpack(vectors.V2)
        h, size = lzfse._unpack_v2(stream, 0)
        payload = stream[size:size + h["n_literal_payload"]
                         + h["n_lmd_payload"]]
        head = b"bvx1" + struct.pack(
            "<IIIIIIi4HiHHH", h["n_raw"],
            len(payload), h["n_literals"], h["n_matches"],
            h["n_literal_payload"], h["n_lmd_payload"], h["literal_bits"],
            *h["literal_state"], h["lmd_bits"], h["l_state"], h["m_state"],
            h["d_state"])
        head += struct.pack("<%dH" % (20 + 20 + 64 + 256),
                            *(h["l_freq"] + h["m_freq"] + h["d_freq"]
                              + h["literal_freq"]))
        self.assertEqual(len(head), lzfse.V1_HEADER)
        self.assertEqual(lzfse.decode(head + payload + b"bvx$"), plain)


class Refusals(unittest.TestCase):

    def setUp(self):
        self.stream, self.plain = vectors.unpack(vectors.V2)

    def test_a_stream_without_its_end_marker(self):
        with self.assertRaises(lzfse.LzfseError):
            lzfse.decode(self.stream[:-4])

    def test_every_truncation_is_refused_not_decoded_short(self):
        for cut in range(0, len(self.stream) - 4, 37):
            with self.assertRaises(lzfse.LzfseError):
                lzfse.decode(self.stream[:cut])

    def test_an_unknown_block_marker(self):
        with self.assertRaises(lzfse.LzfseError):
            lzfse.decode(b"bvx?" + bytes(20))

    def test_output_is_capped(self):
        with self.assertRaises(lzfse.LzfseError):
            lzfse.decode(self.stream, max_size=len(self.plain) - 1)
        raw = b"bvx-" + struct.pack("<I", 1000) + bytes(1000) + b"bvx$"
        with self.assertRaises(lzfse.LzfseError):
            lzfse.decode(raw, max_size=999)
        self.assertEqual(len(lzfse.decode(raw, max_size=1000)), 1000)

    def test_a_block_whose_count_does_not_match_what_it_decodes(self):
        stream = bytearray(self.stream)
        struct.pack_into("<I", stream, 4, len(self.plain) + 1)
        with self.assertRaises(lzfse.LzfseError):
            lzfse.decode(bytes(stream))

    def test_a_raw_block_that_claims_more_than_it_holds(self):
        with self.assertRaises(lzfse.LzfseError):
            lzfse.decode(b"bvx-" + struct.pack("<I", 100) + bytes(10)
                         + b"bvx$")

    def test_damage_never_raises_anything_but_lzfse_error(self):
        rng = random.Random(8)
        stream, plain = vectors.unpack(vectors.CHAIN)
        survived = 0
        for _ in range(1500):
            data = bytearray(stream)
            for _ in range(rng.randint(1, 6)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                got = lzfse.decode(bytes(data), max_size=1 << 20)
                survived += got == plain
            except lzfse.LzfseError:
                pass
        # most single-byte changes are caught; a few land in padding
        self.assertLess(survived, 1500)


if __name__ == "__main__":
    unittest.main()
