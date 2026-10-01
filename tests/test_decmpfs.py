"""Unit tests for decmpfs (engine.decmpfs): the header, the LZVN decoder, and
the zlib and LZVN block layouts of compressed files.

The LZVN streams below were written by Apple's own liblzfse encoder; the
decoder here reproduces the data they were made from. Between them they use
every instruction LZVN has except the no-op."""

import os
import struct
import sys
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import decmpfs                                        # noqa: E402
import imagebuild_decmpfs as build                                # noqa: E402

FAR_BLOCK = bytes.fromhex(("9f41bd5bcbb0f1d7bda6ec8707d777c6f13fa60de6281c5f78de3f618b1a923f"
    "03bb3768472eeadec46328c3cc12239e9e71202100f8df0135c637f5fb2adf2a"
    "4a50f6328ae0ada0342ef0f7b032f7f7e4624c055c6a2aef254310544dd19a96"
    "0098adb556104f5ad14e7bb2502f7b78b42d0e41f9f005f3bf5bd867048cc96b"
    "5d6094d702730bb52e9ff4f4321ec13eedd1f17658835ae48640c6761b96bfc7"
    "cc5edc4b096ef2fa173557839c5ceb255746ecb38b174faf514e2dcc14a026b8"
    "b04fff7b29b80c14"))

# What the streams decode to: a few are repetitive enough to state as a
# recipe, the rest are held as bytes.
MED_BLOCK = bytes.fromhex(("3a5ef6602031b40b15233fcfff813566a407757c74637e92"))

PLAIN = {
    "medium": MED_BLOCK + b"\x00" * 2600 + MED_BLOCK + b"!",
    "single": b"a",
    "cycle": b"abcabcabc" * 20,
    "run": b"z" * 300,
    "far": FAR_BLOCK + b"\x00" * 16300 + FAR_BLOCK + b"end",
}
STREAMS = {
    "medium": bytes.fromhex(("e0093a5ef6602031b40b15233fcfff813566a407757c74637e92003801f0fff0"
            "fff0fff0fff0fff0fff0fff0fff0fff086a50129e1210600000000000000")),
    "single": bytes.fromhex(("e1610600000000000000")),
    "cycle": bytes.fromhex(("c803616263f09ce1630600000000000000")),
    "run": bytes.fromhex(("68017af0fff002e27a7a0600000000000000")),
    "far": bytes.fromhex(("e0b99f41bd5bcbb0f1d7bda6ec8707d777c6f13fa60de6281c5f78de3f618b1a"
            "923f03bb3768472eeadec46328c3cc12239e9e71202100f8df0135c637f5fb2a"
            "df2a4a50f6328ae0ada0342ef0f7b032f7f7e4624c055c6a2aef254310544dd1"
            "9a960098adb556104f5ad14e7bb2502f7b78b42d0e41f9f005f3bf5bd867048c"
            "c96b5d6094d702730bb52e9ff4f4321ec13eedd1f17658835ae48640c6761b96"
            "bfc7cc5edc4b096ef2fa173557839c5ceb255746ecb38b174faf514e2dcc14a0"
            "26b8b04fff7b29b80c14003801f0fff0fff0fff0fff0fff0fff0fff0fff0fff0"
            "fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0"
            "fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0"
            "fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0"
            "fff0fff0fff00d3f7440f0aee3656e640600000000000000")),
}
EMBEDDED = {
    "previous": {
        "plain": bytes.fromhex(("62626162626161616262616261616262626261616262626162616262616261")),
        "lzvn": bytes.fromhex(("c0036262614805614806625e62e861626162626162610600000000000000"))},
    "words": {
        "plain": bytes.fromhex(("464a7867e625464a7867e625691b2b6f5f260fd86bd34074a66b691b2b6f5f26"
            "0fd86b167d458360d2fdf52da0ef7fde5688ec67083cbd983521fbbb90f321a1"
            "e5691b2b6f5f260fd86b464a7867e625167d4583f52da0ef7fde563521fbbb90"
            "f321a1e52bf98574f57cb0ba513521fbbb90f321a1e5167d4583167d45833521"
            "fbbb90f321a1e5691b2b6f5f260fd86bf52da0ef7fde560efaeaa360d2fd88ec"
            "67083cbd982bf98574f57cb0ba51464a7867e6253521fbbb90f321a1e5691b2b"
            "6f5f260fd86bf52da0ef7fde563521fbbb90f321a1e52bf98574f57cb0ba5135"
            "21fbbb90f321a1e5464a7867e625f52da0ef7fde56f52da0ef7fde56691b2b6f"
            "5f260fd86b691b2b6f5f260fd86b3521fbbb90f321a1e5f52da0ef7fde56691b"
            "2b6f5f260fd86b167d45832474ecff9e691b2b6f5f260fd86b0efaeaa3167d45"
            "832bf98574f57cb0ba51691b2b6f5f260fd86b691b2b6f5f260fd86b464a7867"
            "e6250efaeaa3464a7867e6250efaeaa3cd7e55691b2b6f5f260fd86b2bf98574"
            "f57cb0ba513521fbbb90f321a1e5167d4583d34074a66b167d4583")),
        "lzvn": bytes.fromhex(("e6464a7867e6251806ee691b2b6f5f260fd86bd34074a66b300ee00e167d4583"
            "60d2fdf52da0ef7fde5688ec67083cbd983521fbbb90f321a1e530271844082d"
            "202a3023e92bf98574f57cb0ba513012082608043846f8203ce40efaeaa30074"
            "206d304118643836ff3872f001183a20282007303f3009302f3822f608ade524"
            "74ecff9e301208a20816306b384ef818740829380ac820cd7e55f53918fce9d3"
            "4074a66b167d45830600000000000000"))},
    "noise": {
        "plain": bytes.fromhex(("abba6a2b9dc7ef9484aaef6b4d9f8dc6dda345b8fe07322896709fa62e38c2af"
            "2ea1b70afc78fa392a0de4221c51f72e7b318c096a775961a99c1297343cb7e7"
            "5f005967f347db68dd1db0d48c5ff6098c9d4d184b8b8356f3944bf55ad1216b"
            "68d090a4895e7724289861907af532f7229b1759d2e4a900611b5390ea9d8a24"
            "53a1e0e490606d6efa397e4a7af8b56162f6dae928989842bdfb4d7f406a0551"
            "f1fb4e7ded49247a061fa89ff5713e4b0ac822d364037a888f463eef79c8093e"
            "7d44d827b8fd494b7e9bfe7984a5dd9ae1bee51e04c2204c4888b5569d4bbb87"
            "0676595caebed097210900408d74afea1be3af8b30036dc7ce6d9893b0b5f4a1"
            "a67bdbe9d7627964aedab832e64b77d4c2104dd600b1c76e9549a5c778e94f24"
            "2a7ab18ce37ff95489276c95")),
        "lzvn": bytes.fromhex(("e0ffabba6a2b9dc7ef9484aaef6b4d9f8dc6dda345b8fe07322896709fa62e38"
            "c2af2ea1b70afc78fa392a0de4221c51f72e7b318c096a775961a99c1297343c"
            "b7e75f005967f347db68dd1db0d48c5ff6098c9d4d184b8b8356f3944bf55ad1"
            "216b68d090a4895e7724289861907af532f7229b1759d2e4a900611b5390ea9d"
            "8a2453a1e0e490606d6efa397e4a7af8b56162f6dae928989842bdfb4d7f406a"
            "0551f1fb4e7ded49247a061fa89ff5713e4b0ac822d364037a888f463eef79c8"
            "093e7d44d827b8fd494b7e9bfe7984a5dd9ae1bee51e04c2204c4888b5569d4b"
            "bb870676595caebed097210900408d74afea1be3af8b30036dc7ce6d9893b0b5"
            "f4a1a67bdbe9d7627964aedab832e64b77e00dd4c2104dd600b1c76e9549a5c7"
            "78e94f242a7ab18ce37ff95489276c950600000000000000"))},
    "mixed": {
        "plain": bytes.fromhex(("8acf0c11bb3a44d115ca10a9f10655b86dfa11ff67b37c0c1fd71f389da5d3f3"
            "1cb6e522fe4ab4eb787878787878787878787878787878787878787878787878"
            "787878787878787878787878787878787878787878787878787870262e9c2f69"
            "cd29119f360b8e1ba961be12470e68656c6c6f20776f726c642c2068656c6c6f"
            "20776f726c642c2068656c6c6f20776f726c642192931ebe66")),
        "lzvn": bytes.fromhex(("e0198acf0c11bb3a44d115ca10a9f10655b86dfa11ff67b37c0c1fd71f389da5"
            "d3f31cb6e522fe4ab4eb783801f017e01170262e9c2f69cd29119f360b8e1ba9"
            "61be12470e68656c6c6f20776f726c642c20380dfee62192931ebe6606000000"
            "00000000"))},
}

CASES = {name: (PLAIN[name], STREAMS[name]) for name in PLAIN}
CASES.update({k: (v["plain"], v["lzvn"]) for k, v in EMBEDDED.items()})


def fork_reader(fork):
    return lambda off, n: fork[off:off + n]


def compressed(value, fork=None):
    h = decmpfs.parse_header(value)
    return decmpfs.Compressed(
        h, fork_reader(fork) if fork is not None else None,
        len(fork) if fork is not None else 0)


class Header(unittest.TestCase):

    def test_the_header_is_read(self):
        h = decmpfs.parse_header(build.header(7, 1234) + b"payload")
        self.assertEqual((h["type"], h["size"], h["codec"]),
                         (7, 1234, "LZVN"))
        self.assertFalse(h["in_resource_fork"])
        self.assertTrue(h["supported"])
        self.assertEqual(h["payload"], b"payload")

    def test_every_type_maps_to_a_codec_and_a_place(self):
        want = {3: ("zlib", False), 4: ("zlib", True), 7: ("LZVN", False),
                8: ("LZVN", True), 9: ("raw", False), 10: ("raw", True),
                11: ("LZFSE", False), 12: ("LZFSE", True)}
        for kind, (codec, fork) in want.items():
            h = decmpfs.parse_header(build.header(kind, 1))
            self.assertEqual((h["codec"], h["in_resource_fork"]), (codec, fork))
            self.assertEqual(h["supported"], codec in ("zlib", "LZVN", "LZFSE"))

    def test_other_values_are_not_headers(self):
        for value in (None, b"", b"fpmc", b"fpmc" + bytes(11),
                      b"cmpf" + bytes(12), bytes(16)):
            self.assertIsNone(decmpfs.parse_header(value))

    def test_an_unknown_type_is_a_header_that_is_not_supported(self):
        h = decmpfs.parse_header(build.header(99, 5))
        self.assertIsNone(h["codec"])
        self.assertFalse(h["supported"])
        self.assertIn("type 99", decmpfs.describe(h))

    def test_an_unsupported_codec_is_refused_by_name(self):
        for kind, text in ((9, "raw"), (10, "raw"), (5, "type 5")):
            h = decmpfs.parse_header(build.header(kind, 10))
            with self.assertRaises(decmpfs.DecmpfsError) as cm:
                decmpfs.Compressed(h)
            self.assertIn(text, str(cm.exception))


class Lzvn(unittest.TestCase):

    def test_streams_written_by_apples_encoder_decode_to_their_data(self):
        for name, (plain, stream) in CASES.items():
            self.assertEqual(decmpfs.lzvn_decode(stream, len(plain)), plain,
                             name)

    def test_between_them_the_streams_use_every_instruction_but_the_nop(self):
        seen = set()
        for _plain, stream in CASES.values():
            i = 0
            while i < len(stream):
                op = stream[i]
                kind = decmpfs._OPCODES[op]
                seen.add(kind)
                lit = 0
                if kind == "eos":
                    break
                elif kind == "sml_d":
                    lit, i = op >> 6, i + 2
                elif kind == "med_d":
                    lit, i = (op >> 3) & 3, i + 3
                elif kind == "lrg_d":
                    lit, i = op >> 6, i + 3
                elif kind == "pre_d":
                    lit, i = op >> 6, i + 1
                elif kind == "sml_m":
                    i += 1
                elif kind == "lrg_m":
                    i += 2
                elif kind == "sml_l":
                    lit, i = op & 15, i + 1
                elif kind == "lrg_l":
                    lit, i = stream[i + 1] + 16, i + 2
                i += lit
        self.assertEqual(seen, {"eos", "sml_d", "med_d", "lrg_d", "pre_d",
                                "sml_m", "lrg_m", "sml_l", "lrg_l"})

    def test_it_stops_at_the_size_asked_for_or_at_the_end_marker(self):
        plain, stream = CASES["words"]
        self.assertEqual(decmpfs.lzvn_decode(stream, 50), plain[:50])
        self.assertEqual(decmpfs.lzvn_decode(stream, len(plain) + 100), plain)

    def test_a_match_that_overlaps_itself_repeats_the_pattern(self):
        # 'ab' as literals, then a 7-byte match 2 back: ababababa.
        stream = bytes([0xE2]) + b"ab" + bytes([0x20 | (7 - 3) << 3 >> 3]) \
            if False else None
        # sml_d: LL=0, MMM=4 (match 7), D=2: 0b00_100_000, 0x02
        stream = bytes([0xE2]) + b"ab" + bytes([(4 << 3) | 0, 2]) + b"\x06" \
            + bytes(7)
        self.assertEqual(decmpfs.lzvn_decode(stream, 9), b"ababababa")

    def test_bad_streams_are_refused_not_guessed_at(self):
        bad = {
            "undefined opcode": bytes([0x70]),
            "another undefined": bytes([0xD0]),
            "distance zero": bytes([0xE1]) + b"a" + bytes([0x00, 0x00]),
            "before the start": bytes([0xE1]) + b"a" + bytes([0x00, 0x05]),
            "truncated literal": bytes([0xE5]) + b"ab",
            "truncated opcode": bytes([0x00]),
            "no end": b"",
        }
        for name, stream in bad.items():
            with self.assertRaises(decmpfs.DecmpfsError, msg=name):
                decmpfs.lzvn_decode(stream, 100)

    def test_a_no_op_is_skipped(self):
        stream = bytes([0x0E, 0x16]) + bytes([0xE1]) + b"x" + b"\x06" \
            + bytes(7)
        self.assertEqual(decmpfs.lzvn_decode(stream, 1), b"x")

    def test_arbitrary_bytes_are_decoded_or_refused_never_a_crash(self):
        import random
        rng = random.Random(11)
        for _ in range(3000):
            stream = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 40)))
            try:
                out = decmpfs.lzvn_decode(stream, rng.randint(0, 300))
            except decmpfs.DecmpfsError:
                continue
            self.assertIsInstance(out, bytes)


class Attribute(unittest.TestCase):
    """Types 3 and 7: the data is in the attribute."""

    def test_zlib(self):
        data = b"inline zlib data " * 100
        c = compressed(build.inline_value(3, len(data),
                                          build.zlib_block(data)))
        self.assertEqual(c.size, len(data))
        self.assertEqual(c.read_at(0, len(data)), data)
        self.assertEqual(c.read_at(5, 10), data[5:15])
        self.assertEqual(c.findings, [])

    def test_zlib_stored_uncompressed(self):
        data = b"not worth compressing"
        c = compressed(build.inline_value(
            3, len(data), build.zlib_block(data, stored=True)))
        self.assertEqual(c.read_at(0, 100), data)

    def test_lzvn(self):
        plain, stream = CASES["words"]
        c = compressed(build.inline_value(7, len(plain), stream))
        self.assertEqual(c.read_at(0, len(plain)), plain)
        self.assertEqual(c.read_at(3, 5), plain[3:8])

    def test_lzvn_stored_uncompressed(self):
        data = b"stored as it was"
        c = compressed(build.inline_value(
            7, len(data), build.lzvn_stored(data)))
        self.assertEqual(c.read_at(0, 100), data)

    def test_reads_are_bounded_by_the_size(self):
        data = b"0123456789"
        c = compressed(build.inline_value(3, 10, build.zlib_block(data)))
        self.assertEqual(c.read_at(10, 5), b"")
        self.assertEqual(c.read_at(-1, 5), b"")
        self.assertEqual(c.read_at(0, 0), b"")
        self.assertEqual(c.read_at(8, 50), b"89")

    def test_damaged_data_reads_as_zeros_and_says_so(self):
        data = b"payload " * 50
        value = bytearray(build.inline_value(3, len(data),
                                             build.zlib_block(data)))
        value[24:40] = bytes(16)
        c = compressed(bytes(value))
        self.assertEqual(c.read_at(0, len(data)), bytes(len(data)))
        self.assertTrue(any("could not be decompressed" in f
                            for f in c.findings))

    def test_short_output_is_padded_and_reported(self):
        data = b"only this much"
        c = compressed(build.inline_value(3, 100, build.zlib_block(data)))
        got = c.read_at(0, 100)
        self.assertEqual(got, data + bytes(100 - len(data)))
        self.assertTrue(any("of 100 bytes" in f for f in c.findings))

    def test_a_bomb_stops_at_the_size_the_header_declares(self):
        bomb = zlib.compress(bytes(50 * 1024 * 1024), 9)
        c = compressed(build.inline_value(3, 1000, bomb))
        self.assertEqual(c.read_at(0, 2000), bytes(1000))

    def test_a_huge_declared_size_is_refused_for_an_attribute(self):
        h = decmpfs.parse_header(build.header(3, 1 << 40))
        with self.assertRaises(decmpfs.DecmpfsError):
            decmpfs.Compressed(h)


class Lzfse(unittest.TestCase):
    """Types 11 and 12, with streams from Apple's encoder."""

    @classmethod
    def setUpClass(cls):
        import lzfse_vectors as v
        cls.stream, cls.plain = v.unpack(v.V2)

    def test_attribute_type(self):
        c = compressed(build.header(11, len(self.plain)) + self.stream)
        self.assertEqual(c.read_at(0, len(self.plain)), self.plain)
        self.assertEqual(c.read_at(100, 50), self.plain[100:150])

    def test_resource_fork_type_with_a_stored_block_and_a_compressed_one(self):
        first = bytes(range(256)) * 256               # a whole 64 KiB block
        fork = build.lzvn_fork([b"\xff" + first, self.stream])
        c = compressed(build.header(12, len(first) + len(self.plain)), fork)
        data = first + self.plain
        self.assertEqual(c.read_at(0, len(data)), data)
        self.assertEqual(c.read_at(65530, 20), data[65530:65550])
        self.assertEqual(c.findings, [])

    def test_a_damaged_block_reads_as_zeros_and_says_so(self):
        c = compressed(build.header(11, len(self.plain))
                       + self.stream[:len(self.stream) // 2])
        self.assertEqual(c.read_at(0, len(self.plain)), bytes(len(self.plain)))
        self.assertTrue(c.findings)


class ResourceFork(unittest.TestCase):
    """Types 4 and 8: 64 KiB blocks in the resource fork."""

    def data(self, n):
        import random
        rng = random.Random(n)
        return bytes(rng.choice(b"abcdef \n") for _ in range(n))

    def test_a_fork_that_reads_short_is_refused_not_misparsed(self):
        header = decmpfs.parse_header(build.header(4, 10))
        with self.assertRaises(decmpfs.DecmpfsError):
            decmpfs.Compressed(header, lambda off, n: b"\x00" * (n - 1), 4096)

    def test_zlib_blocks(self):
        for n in (1, 1000, 65536, 65537, 3 * 65536 + 17):
            data = self.data(n)
            blocks = [build.zlib_block(b) for b in build.split(data)]
            c = compressed(build.header(4, n), build.zlib_fork(blocks))
            self.assertEqual(c.read_at(0, n), data, n)
            self.assertEqual(c.findings, [])

    def test_zlib_blocks_stored_uncompressed_are_read(self):
        data = self.data(2 * 65536 + 5)
        parts = build.split(data)
        blocks = [build.zlib_block(parts[0], stored=True),
                  build.zlib_block(parts[1]),
                  build.zlib_block(parts[2], stored=True)]
        c = compressed(build.header(4, len(data)), build.zlib_fork(blocks))
        self.assertEqual(c.read_at(0, len(data)), data)

    def test_lzvn_blocks(self):
        for n in (10, 65536, 65537, 2 * 65536 + 100):
            data = self.data(n)
            blocks = [build.lzvn_literals(b) for b in build.split(data)]
            c = compressed(build.header(8, n), build.lzvn_fork(blocks))
            self.assertEqual(c.read_at(0, n), data, n)

    def test_lzvn_blocks_stored_uncompressed_are_read(self):
        data = self.data(65536 + 30)
        parts = build.split(data)
        blocks = [build.lzvn_stored(parts[0]), build.lzvn_literals(parts[1])]
        c = compressed(build.header(8, len(data)), build.lzvn_fork(blocks))
        self.assertEqual(c.read_at(0, len(data)), data)

    def test_a_read_decodes_only_the_blocks_it_needs(self):
        data = self.data(4 * 65536)
        blocks = [build.zlib_block(b) for b in build.split(data)]
        fork = build.zlib_fork(blocks)
        touched = []

        def reader(off, n):
            touched.append(off)
            return fork[off:off + n]

        c = decmpfs.Compressed(decmpfs.parse_header(build.header(4, len(data))),
                               reader, len(fork))
        del touched[:]
        self.assertEqual(c.read_at(2 * 65536 + 10, 20),
                         data[2 * 65536 + 10:2 * 65536 + 30])
        self.assertEqual(len(touched), 1)

    def test_a_read_across_blocks(self):
        data = self.data(3 * 65536)
        blocks = [build.zlib_block(b) for b in build.split(data)]
        c = compressed(build.header(4, len(data)), build.zlib_fork(blocks))
        at = 65536 - 30
        self.assertEqual(c.read_at(at, 100000), data[at:at + 100000])

    def test_a_damaged_block_is_zeros_the_others_are_read(self):
        data = self.data(3 * 65536)
        blocks = [build.zlib_block(b) for b in build.split(data)]
        blocks[1] = blocks[1][:2] + bytes(len(blocks[1]) - 2)
        c = compressed(build.header(4, len(data)), build.zlib_fork(blocks))
        self.assertEqual(c.read_at(0, 65536), data[:65536])
        self.assertEqual(c.read_at(65536, 65536), bytes(65536))
        self.assertEqual(c.read_at(2 * 65536, 65536), data[2 * 65536:])
        self.assertTrue(any("Block 1" in f for f in c.findings))

    def test_a_block_count_that_disagrees_with_the_size_is_reported(self):
        data = self.data(2 * 65536)
        blocks = [build.zlib_block(b) for b in build.split(data)]
        c = compressed(build.header(4, 3 * 65536), build.zlib_fork(blocks))
        self.assertEqual(c.read_at(0, 2 * 65536), data)
        self.assertEqual(c.read_at(2 * 65536, 10), bytes(10))
        self.assertTrue(any("lists 2 blocks" in f for f in c.findings))

    def test_a_table_that_is_not_laid_out_as_decmpfs_writes_it_is_refused(self):
        data = self.data(100)
        good = build.zlib_fork([build.zlib_block(data)])
        for name, fork in (
                ("wrong header size", b"\x00\x00\x02\x00" + good[4:]),
                ("no blocks", good[:0x104] + bytes(4) + good[0x108:]),
                ("too many", good[:0x104] + b"\xff\xff\xff\xff" + good[0x108:]),
                ("empty", b""),
                ("short", good[:0x106])):
            with self.assertRaises(decmpfs.DecmpfsError, msg=name):
                compressed(build.header(4, 100), fork)
        lz = build.lzvn_fork([build.lzvn_literals(data)])
        for name, fork in (("unaligned", b"\x05\x00\x00\x00" + lz[4:]),
                           ("zero", bytes(8)), ("empty", b"")):
            with self.assertRaises(decmpfs.DecmpfsError, msg=name):
                compressed(build.header(8, 100), fork)

    def test_a_block_outside_the_fork_reads_as_zeros(self):
        data = self.data(100)
        fork = bytearray(build.zlib_fork([build.zlib_block(data)]))
        struct.pack_into("<I", fork, 0x108, 1 << 30)       # block offset
        c = compressed(build.header(4, 100), bytes(fork))
        self.assertEqual(c.read_at(0, 100), bytes(100))
        self.assertTrue(c.findings)

    def test_a_resource_type_without_a_resource_fork_is_refused(self):
        with self.assertRaises(decmpfs.DecmpfsError):
            decmpfs.Compressed(decmpfs.parse_header(build.header(4, 10)))


if __name__ == "__main__":
    unittest.main()
