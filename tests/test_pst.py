import unittest

from engine import pst
from tests import imagebuild_pst as build


class PstAttachments(unittest.TestCase):

    def setUp(self):
        raw, self.node, self.nids = build.build_pst()
        self.pst = pst.open_pst(raw)
        self.assertIsNotNone(self.pst)

    def test_attachments_lists_the_nid_and_content_type(self):
        atts = self.pst.attachments(self.node)
        self.assertEqual(len(atts), 1)
        att = atts[0]
        self.assertEqual(att["nid"], self.nids[0])
        self.assertEqual(att["name"], build.ATTACHMENT_NAME)
        self.assertEqual(att["size"], len(build.ATTACHMENT_BYTES))
        self.assertEqual(att["content_type"], build.ATTACHMENT_MIME)

    def test_attachment_bytes_returns_the_exact_content(self):
        data = self.pst.attachment_bytes(self.node, self.nids[0])
        self.assertEqual(data, build.ATTACHMENT_BYTES)

    def test_attachment_bytes_is_none_for_an_id_not_in_this_message(self):
        data = self.pst.attachment_bytes(
            self.node, build.MISSING_ATTACHMENT_NID)
        self.assertIsNone(data)

    def test_attachment_bytes_rejects_a_non_attachment_nid(self):
        # A nid that resolves in the subnode tree but isn't an attachment
        # (wrong low 5 bits) must not be treated as one.
        folder_like_nid = (self.nids[0] & ~0x1F) | 0x02
        data = self.pst.attachment_bytes(self.node, folder_like_nid)
        self.assertIsNone(data)

    def test_attachments_are_reachable_through_a_real_nbt_lookup(self):
        # attachments()/attachment_bytes() are exercised above against a
        # hand-built node dict; the server endpoint instead resolves the
        # message through Pst.nbt(), so confirm that path resolves to the
        # same subnode tree and attachment.
        node = self.pst.nbt().get(build.MESSAGE_NID)
        self.assertIsNotNone(node)
        self.assertEqual(node["sub"], self.node["sub"])
        atts = self.pst.attachments(node)
        self.assertEqual(atts[0]["nid"], self.nids[0])
        self.assertEqual(self.pst.attachment_bytes(node, self.nids[0]),
                         build.ATTACHMENT_BYTES)

    def test_multiple_attachments_are_each_independently_addressable(self):
        raw, node, nids = build.build_pst(attachment_count=2)
        p = pst.open_pst(raw)
        atts = p.attachments(node)
        self.assertEqual(len(atts), 2)
        self.assertEqual({a["nid"] for a in atts}, set(nids))
        for nid in nids:
            self.assertEqual(p.attachment_bytes(node, nid),
                             build.ATTACHMENT_BYTES)


FORMATS = (("Unicode", False), ("ANSI", True))


def store(ansi, **kw):
    s = build.build_store(ansi=ansi, **kw)
    p = pst.open_pst(s.raw)
    assert p is not None
    return s, p


class BothFormats(unittest.TestCase):
    """The same content, written in each format's layout from [MS-PST], must
    read back the same."""

    def test_format_and_version_are_reported(self):
        for name, ansi in FORMATS:
            with self.subTest(name):
                s, p = store(ansi)
                self.assertTrue(p.valid)
                self.assertEqual(p.ansi, ansi)
                self.assertEqual(p.info()["format"],
                                 "ANSI (32-bit)" if ansi
                                 else "Unicode (64-bit)")
                self.assertEqual(p.findings != [], ansi)
                self.assertEqual(p.file_eof, len(s.raw))

    def test_ansi_versions_14_and_15_are_both_read(self):
        for version in (14, 15):
            with self.subTest(version):
                _, p = store(True, version=version)
                self.assertEqual(p.mail()["count"], 1)

    def test_message_folder_and_attachment_list(self):
        for name, ansi in FORMATS:
            with self.subTest(name):
                s, p = store(ansi)
                r = p.mail()
                self.assertEqual(r["count"], 1)
                m = r["messages"][0]
                self.assertEqual(m["subject"], build.MESSAGE_SUBJECT)
                self.assertEqual(m["folder"], "/%s/%s" % (
                    build.ROOT_NAME, build.INBOX_NAME))
                self.assertFalse(m["unlinked"])
                self.assertEqual([f["name"] for f in r["folders"]],
                                 [build.ROOT_NAME, build.INBOX_NAME])
                att = m["attachments"][0]
                self.assertEqual(att["nid"], s.attachment_nids[0])
                self.assertEqual(att["name"], build.ATTACHMENT_NAME)
                self.assertEqual(att["content_type"], build.ATTACHMENT_MIME)
                self.assertEqual(att["size"], len(build.ATTACHMENT_BYTES))

    def test_orphan_message_is_still_found(self):
        for name, ansi in FORMATS:
            with self.subTest(name):
                _, p = store(ansi, folders=False)
                m = p.mail()["messages"][0]
                self.assertTrue(m["unlinked"])

    def test_attachment_content_small_and_in_a_data_tree(self):
        for name, ansi in FORMATS:
            for label, kw, want in (
                    ("heap", {}, build.ATTACHMENT_BYTES),
                    ("xblock", {"attachment": build.ATTACHMENT_BIG},
                     build.ATTACHMENT_BIG),
                    ("xxblock", {"attachment": build.ATTACHMENT_BIG,
                                 "xx": True}, build.ATTACHMENT_BIG)):
                with self.subTest("%s %s" % (name, label)):
                    s, p = store(ansi, **kw)
                    node = p.nbt().get(s.message_nid)
                    self.assertEqual(
                        p.attachment_bytes(node, s.attachment_nids[0]), want)

    def test_two_level_btrees_and_a_subnode_index_block(self):
        for name, ansi in FORMATS:
            with self.subTest(name):
                s, p = store(ansi, tree_levels=2, sub_split=True,
                             attachment_count=3)
                self.assertGreater(len(p.nbt()), 3)
                node = p.nbt().get(s.message_nid)
                got = {a["nid"] for a in p.attachments(node)}
                self.assertEqual(got, set(s.attachment_nids))
                for nid in s.attachment_nids:
                    self.assertEqual(p.attachment_bytes(node, nid),
                                     build.ATTACHMENT_BYTES)
                self.assertEqual(p.mail()["count"], 1)

    def test_encoded_data_blocks_are_decoded(self):
        for name, ansi in FORMATS:
            for crypt in (build.CRYPT_PERMUTE, build.CRYPT_CYCLIC):
                with self.subTest("%s crypt %d" % (name, crypt)):
                    # BIDs with the high word set, as real files have
                    s, p = store(ansi, crypt=crypt, first_index=0x0ABC1234,
                                 attachment=build.ATTACHMENT_BIG)
                    self.assertEqual(p.crypt, crypt)
                    node = p.nbt().get(s.message_nid)
                    self.assertEqual(
                        p.attachment_bytes(node, s.attachment_nids[0]),
                        build.ATTACHMENT_BIG)
                    self.assertEqual(p.mail()["messages"][0]["subject"],
                                     build.MESSAGE_SUBJECT)


class AnsiText(unittest.TestCase):
    """ANSI text is PtypString8 in the message's own code page."""

    def subject(self, text, codepage):
        _, p = store(True, subject=text, codepage=codepage)
        return p.mail()["messages"][0]["subject"]

    def test_declared_code_pages_are_honoured(self):
        cases = ((u"Café", 1252),
                 (u"Привет", 1251),
                 (u"テスト", 932))
        for text, cp in cases:
            with self.subTest(cp):
                self.assertEqual(self.subject(text, cp), text)

    def test_no_declared_code_page_means_windows_1252(self):
        self.assertEqual(self.subject(u"Café", None), u"Café")

    def test_decode_string8_handles_unknown_and_utf8_code_pages(self):
        self.assertEqual(pst._decode_string8(b"a\xc3\xa9\x00", 65001),
                         u"aé")
        self.assertEqual(pst._decode_string8(b"caf\xe9", 99999), u"café")
        self.assertEqual(pst._decode_string8(b"caf\xe9", None), u"café")


class Damaged(unittest.TestCase):

    def test_truncated_files_do_not_raise(self):
        for name, ansi in FORMATS:
            s, _ = store(ansi)
            for cut in (14, 100, 511, 600, 1024, 2000, len(s.raw) // 2):
                with self.subTest("%s cut %d" % (name, cut)):
                    p = pst.open_pst(s.raw[:cut])
                    if p is not None:
                        self.assertLessEqual(p.mail()["count"], 1)

    def test_a_folder_name_of_the_wrong_type_is_ignored(self):
        # found by fuzzing: a binary display name crashed folders()
        for name, ansi in FORMATS:
            with self.subTest(name):
                _, p = store(ansi, binary_folder_name=True)
                r = p.mail()
                self.assertEqual(r["count"], 1)
                self.assertEqual([f["name"] for f in r["folders"]],
                                 ["(root)", "(root)"])

    def test_btree_entries_shorter_than_their_struct_are_skipped(self):
        # found by fuzzing: a corrupt cbEnt gave entries too short to unpack
        for name, ansi in FORMATS:
            with self.subTest(name):
                s, p = store(ansi)
                raw = bytearray(s.raw)
                body = 496 if ansi else 488
                for ib in (p.nbt_ib, p.bbt_ib):
                    raw[ib + body + 2] = 4                       # cbEnt
                p = pst.open_pst(bytes(raw))
                self.assertEqual(p.nbt(), {})
                self.assertEqual(p.bbt(), {})
                self.assertEqual(p.mail()["count"], 0)

    def test_ansi_header_shorter_than_512_bytes_is_refused(self):
        s, _ = store(True)
        self.assertIsNone(pst.open_pst(s.raw[:511]))

    def test_unknown_version_is_reported_not_read(self):
        s = build.build_store(version=99)
        p = pst.Pst(s.raw)
        self.assertFalse(p.valid)
        self.assertIn("Unknown PST version 99.", p.findings)


class Ciphers(unittest.TestCase):
    """The three 256-byte tables come from [MS-PST] 5.1 and are shared by
    both ciphers."""

    def test_tables_are_permutations_and_i_inverts_r(self):
        for t in (pst._MPBB_R, pst._MPBB_S, pst._MPBB_INV):
            self.assertEqual(sorted(t), list(range(256)))
        self.assertTrue(all(pst._MPBB_INV[pst._MPBB_R[b]] == b
                            for b in range(256)))

    def test_cyclic_is_symmetric_and_keyed_by_the_low_dword_of_the_bid(self):
        data = bytes(range(256)) * 3
        for key in (4, 0x12345678, 0xFFFFFFFC):
            enc = pst._cyclic(data, key)
            self.assertNotEqual(enc, data)
            self.assertEqual(pst._cyclic(enc, key), data)
        self.assertNotEqual(pst._cyclic(data, 4), pst._cyclic(data, 8))
        # the parser and the builder's separate transcription of the spec
        # agree, including for keys whose high word is set
        for key in (4, 0x0ABC1234 << 2, 0xFFFF0000, 0x89ABCDEC):
            self.assertEqual(
                pst._cyclic(data, key),
                build._encode(data, build.CRYPT_CYCLIC, key), hex(key))
        big = 0x1F00000008
        self.assertEqual(pst._cyclic(data, 8), pst.decode_block(
            pst._cyclic(data, 8), pst.CRYPT_NONE, big))
        self.assertEqual(pst.decode_block(pst._cyclic(data, 8),
                                          pst.CRYPT_CYCLIC, big), data)


if __name__ == "__main__":
    unittest.main()
