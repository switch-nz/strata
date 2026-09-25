"""Tests for legacy Office body text (engine.officedoc): the Word .doc
piece table, Excel .xls BIFF8 cell records, and PowerPoint .ppt slide
text atoms, fed images from imagebuild_office. The fixtures exist to be
read by this module only; malformed variants assert the proven-only
contract — a finding plus whatever text survives, never guessed bytes,
and the properties (metadata) always present."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import imagebuild_office as ib                                # noqa: E402
from engine import ole2, officedoc                                       # noqa: E402

WORD_TEXT = "First compressed piece. Second uncompressed pièce. "


def parse(data, name):
    return officedoc.parse_ole2_document(data, name)


def rewrap(streams):
    """Rebuild a CFB around already-decoded streams (padded to the
    4096-byte floor the builder promises)."""
    out = []
    for name, data in streams:
        data = bytes(data)
        if len(data) < 4096:
            data += b"\x00" * (4096 - len(data))
        out.append((name, data))
    return ib.build_cfb(out)


class WordPieceTable(unittest.TestCase):
    """Text via the Clx piece table in the table stream ([MS-DOC])."""

    def test_decodes_compressed_and_utf16_pieces_in_order(self):
        res = parse(ib.build_doc(), "t.doc")
        self.assertEqual(res["kind"], "Word document (legacy .doc)")
        self.assertEqual(res["family"], "ole2")
        self.assertEqual(res["text"],
                         ib.FIB_TEXT_PIECES_A + ib.FIB_TEXT_PIECES_U)
        self.assertEqual(res["sections"],
                         [{"name": "document", "text": res["text"]}])
        self.assertEqual(res["characters"], len(res["text"]))
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["note"],
                         "Document properties are written by the application "
                         "from whatever it was told and can be edited "
                         "afterwards. They are a record of what the file "
                         "claims, not of what happened.")

    def test_reads_the_table_stream_the_fib_names(self):
        # fWhichTblStm bit clear -> 0table. The piece table must be found
        # there, not in the 1table the default fixture writes.
        res = parse(ib.build_doc(table_stream="0table"), "t.doc")
        self.assertEqual(res["text"],
                         ib.FIB_TEXT_PIECES_A + ib.FIB_TEXT_PIECES_U)
        self.assertEqual(res["findings"], [])

    def test_carriage_returns_become_newlines(self):
        # \r (paragraph mark) and \x07 (cell/row mark) both become \n.
        # One piece keeps the byte offset arithmetic trivial.
        res = parse(ib.build_doc([("alpha\r beta\x07gamma", True)]), "t.doc")
        self.assertEqual(res["text"], "alpha\n beta\ngamma")

    def test_piece_pointing_outside_the_stream_is_dropped_with_a_finding(self):
        doc_bytes = ib.build_doc([("alpha ", True), ("beta", False)])
        o = ole2.Ole2(doc_bytes, "t.doc")
        wd = bytearray(o.read("WordDocument"))
        tbl = bytearray(o.read("1table"))
        plc = bytearray(tbl[5:5 + 0x1C])
        struct.pack_into("<HI", plc, 20, 0, 0x40000000 | 0x0FFFFFFF)
        tbl[5:5 + 0x1C] = plc
        res = parse(rewrap([("WordDocument", wd), ("1table", tbl)]), "t.doc")
        self.assertEqual(res["text"], "alpha ")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): piece 1 points "
                          "outside the WordDocument stream; it was "
                          "skipped."])
        self.assertIsInstance(res["metadata"], dict)

    def test_piece_beyond_the_2gb_limit_is_dropped_with_a_finding(self):
        doc_bytes = ib.build_doc([("alpha ", True), ("beta", False)])
        o = ole2.Ole2(doc_bytes, "t.doc")
        wd = bytearray(o.read("WordDocument"))
        tbl = bytearray(o.read("1table"))
        plc = bytearray(tbl[5:5 + 0x1C])
        struct.pack_into("<HI", plc, 20, 0, 0x80000000 | 0x123)
        tbl[5:5 + 0x1C] = plc
        res = parse(rewrap([("WordDocument", wd), ("1table", tbl)]), "t.doc")
        self.assertEqual(res["text"], "alpha ")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): piece 1 points past "
                          "the 2 GB text limit; it was skipped."])

    def test_corrupt_clx_yields_no_text_and_a_finding(self):
        res = parse(ib.build_doc(corrupt_clx=True), "t.doc")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): the piece table's "
                          "size does not match its structure; no text was "
                          "read."])
        self.assertIsInstance(res["metadata"], dict)

    def test_missing_pcdt_yields_no_text_and_a_finding(self):
        res = parse(ib.build_doc(drop_pcdt=True), "t.doc")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): the Clx holds no "
                          "piece table descriptor (Pcdt); no text was "
                          "read."])

    def test_nonmonotonic_character_positions_are_rejected(self):
        res = parse(ib.build_doc(nonmonotonic=True), "t.doc")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): the piece table's "
                          "character positions are not strictly increasing; "
                          "no text was read."])


class WordSpecOffsets(unittest.TestCase):
    """The piece table is written by Word, not by our fixture builder, so
    these build the stream straight from [MS-DOC] rather than through
    imagebuild_office: a reader and a fixture can agree with each other
    and both be wrong."""

    @staticmethod
    def _doc(fc, cps, text_at, text):
        worddoc = bytearray(0x800)
        struct.pack_into("<H", worddoc, 0, 0xA5EC)
        worddoc[text_at:text_at + len(text)] = text
        plc = struct.pack("<%dI" % len(cps), *cps)             + struct.pack("<HIH", 0, fc, 0)
        clx = b"" + struct.pack("<I", len(plc)) + plc
        struct.pack_into("<II", worddoc, 0x01A2, 0, len(clx))
        return bytes(worddoc), clx

    def test_compressed_piece_starts_at_half_its_fc(self):
        # FcCompressed: with fCompressed set the text starts at fc / 2.
        worddoc, clx = self._doc(0x40000000 | (0x200 << 1), (0, 5),
                                 0x200, b"Hello")
        findings = []
        self.assertEqual(officedoc._word_body(worddoc, clx, findings, "w"),
                         "Hello")
        self.assertEqual(findings, [])

    def test_uncompressed_piece_starts_at_its_fc(self):
        worddoc, clx = self._doc(0x200, (0, 2), 0x200,
                                 "Hi".encode("utf-16-le"))
        findings = []
        self.assertEqual(officedoc._word_body(worddoc, clx, findings, "w"),
                         "Hi")
        self.assertEqual(findings, [])


class WordRealWorldText(unittest.TestCase):
    """What Word actually writes: a stale second table stream, fields,
    special characters, smart quotes in 8-bit text, and text kept in parts
    (footnotes, headers, comments) that the character counts in the FIB
    separate. Built in code from [MS-DOC], not captured from any file."""

    def test_the_named_table_stream_wins_when_both_exist(self):
        # fWhichTblStm clear -> 0Table; a stale 1Table left by an earlier
        # save is not the piece table.
        stale = ("1table", bytes(4096))
        res = parse(ib.build_doc(table_stream="0table",
                                 extra_streams=[stale]), "t.doc")
        self.assertEqual(res["text"],
                         ib.FIB_TEXT_PIECES_A + ib.FIB_TEXT_PIECES_U)
        self.assertEqual(res["findings"], [])

    def test_a_missing_named_stream_falls_back_with_a_finding(self):
        data = ib.build_doc(table_stream="0table")
        o = ole2.Ole2(data, "t.doc")
        ents = dict(o.streams())
        worddoc = bytearray(o.read(ents["WordDocument"], 1 << 20))
        struct.pack_into("<H", worddoc, 0x0A, 0x0200)       # names 1Table
        table = o.read(ents["0table"], 1 << 20)
        res = parse(rewrap([("WordDocument", worddoc), ("0table", table)]),
                    "t.doc")
        self.assertEqual(res["text"],
                         ib.FIB_TEXT_PIECES_A + ib.FIB_TEXT_PIECES_U)
        self.assertEqual(res["findings"],
                         ["Word document (legacy .doc): the file header "
                          "names the 1table stream but only 0table exists; "
                          "it was read instead."])

    def text_of(self, s):
        return parse(ib.build_doc([(s, True)]), "t.doc")["text"]

    def test_a_field_shows_its_result_not_its_instruction(self):
        self.assertEqual(
            self.text_of('See \x13 HYPERLINK "http://x.test" \x14click here'
                         '\x15 now'), "See click here now")

    def test_nested_fields_show_only_the_outer_result(self):
        self.assertEqual(
            self.text_of("\x13 A \x13 B \x14 inner\x15 \x14outer\x15!"),
            "outer!")

    def test_a_field_with_no_result_shows_nothing(self):
        self.assertEqual(self.text_of("a\x13 PAGE \x15b"), "ab")

    def test_a_stray_field_end_mark_is_ignored(self):
        self.assertEqual(self.text_of("a\x15b"), "ab")

    def test_special_characters_are_mapped_or_dropped(self):
        # \x0b line break, \x1e non-breaking hyphen, \x01 and \x08 object
        # anchors, \x1f optional hyphen
        self.assertEqual(self.text_of("x\x0by\x1ez\x01\x08w\x1fv"),
                         "x\ny-zwv")

    def test_compressed_text_uses_the_characters_the_spec_names(self):
        # FcCompressed: 0x93/0x94 are the curly double quotes, 0x96 an en
        # dash, 0x92 the apostrophe, 0x85 an ellipsis.
        self.assertEqual(self.text_of("\x93q\x94 \x96 it\x92s\x85"),
                         "“q” – it’s…")

    def test_document_parts_are_split_by_the_fib_counts(self):
        data = ib.build_doc([("Body\rFoot\rHead\rNote\r", True)],
                            ccp=(5, 5, 5, 5, 0, 0, 0))
        res = parse(data, "t.doc")
        self.assertEqual(res["sections"],
                         [{"name": "document", "text": "Body"},
                          {"name": "footnotes", "text": "Foot"},
                          {"name": "headers", "text": "Head"},
                          {"name": "comments", "text": "Note"}])
        self.assertEqual(res["text"], "Body\n\nFoot\n\nHead\n\nNote")

    def test_counts_that_do_not_fit_the_text_leave_one_section(self):
        data = ib.build_doc([("Body\rFoot\rHead\rNote\r", True)],
                            ccp=(50, 5, 5, 5, 0, 0, 0))
        res = parse(data, "t.doc")
        self.assertEqual(res["sections"],
                         [{"name": "document",
                           "text": "Body\nFoot\nHead\nNote"}])

    def test_a_final_paragraph_mark_stays_with_the_last_part(self):
        data = ib.build_doc([("Body\r", True)], ccp=(4, 0, 0, 0, 0, 0, 0))
        res = parse(data, "t.doc")
        self.assertEqual(res["sections"],
                         [{"name": "document", "text": "Body"}])


class XlsCellRecords(unittest.TestCase):
    """Text via the SST and per-sheet BIFF8 cell records ([MS-XLS])."""

    SHEETS = [
        ("Prices", [("s", 0, 0, "Item"), ("s", 0, 1, "Cost"),
                    ("s", 1, 0, "Hammer"), ("n", 1, 1, 42),
                    ("s", 2, 0, "pi"), ("n", 2, 1, 7)]),
        ("Grid", [("n", 0, 0, 8), ("n", 0, 1, 9)]),
    ]

    def test_reads_sheets_cells_and_numbers(self):
        res = parse(ib.build_xls(self.SHEETS), "t.xls")
        self.assertEqual(res["kind"], "Excel workbook (legacy .xls)")
        self.assertEqual(res["text"],
                         "Prices\nItem\tCost\nHammer\t42\npi\t7\n"
                         "Grid\n8\t9")
        self.assertEqual(res["sections"],
                         [{"name": "workbook", "text": res["text"]}])
        self.assertEqual(res["findings"], [])
        self.assertIsInstance(res["metadata"], dict)

    def test_unicode_strings_survive(self):
        sheets = [("S", [("s", 0, 0, "pi\u00e8ce"), ("n", 1, 0, 2)])]
        res = parse(ib.build_xls(sheets), "t.xls")
        self.assertEqual(res["text"], "S\npi\u00e8ce\n2")

    def test_sst_index_past_the_end_gives_an_empty_cell(self):
        base = ole2.Ole2(ib.build_xls(
            [("S", [("s", 0, 0, "alpha"), ("s", 0, 1, "beta")])]), "t.xls")
        wb = bytearray(base.read("Workbook"))
        # SST body starts at 24 (cstTotal, cstUnique); raise cstUnique
        # past the strings the record actually holds.
        struct.pack_into("<I", wb, 28, 99)
        res = parse(rewrap([("Workbook", wb)]), "t.xls")
        self.assertEqual(res["findings"],
                         ["Excel workbook (legacy .xls): the shared-string "
                          "table names more strings than it holds; the rest "
                          "read as empty."])
        self.assertEqual(res["text"], "S\nalpha\tbeta")

    def test_record_running_past_the_stream_stops_parsing(self):
        base = ole2.Ole2(ib.build_xls(
            [("S", [("s", 0, 0, "alpha"), ("s", 0, 1, "beta")])]), "t.xls")
        wb = bytearray(base.read("Workbook"))
        # inflate the sheet substream's EOF (the last record in the
        # stream) so it claims past the stream end
        at, last = 0, None
        while at + 4 <= len(wb):
            rid, rlen = struct.unpack_from("<HH", wb, at)
            if rid == 0x000A:
                last = at
            if at + 4 + rlen > len(wb):
                break
            at += 4 + rlen
        at = last
        struct.pack_into("<H", wb, at + 2, 0xFFFF)
        res = parse(rewrap([("Workbook", wb)]), "t.xls")
        self.assertIn("Excel workbook (legacy .xls): the record stream is "
                      "cut short inside a record; parsing stops here.",
                      res["findings"])
        self.assertIn("Excel workbook (legacy .xls): sheet 0's record "
                      "stream is cut short; parsing stops here.",
                      res["findings"])

    def test_boundsheet_offset_outside_the_stream_is_skipped(self):
        base = ole2.Ole2(ib.build_xls(
            [("S", [("s", 0, 0, "alpha")])]), "t.xls")
        wb = bytearray(base.read("Workbook"))
        at = 20
        while struct.unpack_from("<H", wb, at)[0] != 0x0085:
            at += 4 + struct.unpack_from("<HH", wb, at)[1]
        struct.pack_into("<I", wb, at + 4, 0xFFFFFF)
        res = parse(rewrap([("Workbook", wb)]), "t.xls")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Excel workbook (legacy .xls): sheet 0 starts "
                          "outside the workbook stream; it was skipped."])
        self.assertIsInstance(res["metadata"], dict)

    def test_sheet_not_starting_at_a_bof_is_skipped(self):
        base = ole2.Ole2(ib.build_xls(
            [("S", [("s", 0, 0, "alpha")])]), "t.xls")
        wb = bytearray(base.read("Workbook"))
        at = 20
        while struct.unpack_from("<HH", wb, at)[0] != 0x0085:
            at += 4 + struct.unpack_from("<HH", wb, at)[1]
        struct.pack_into("<I", wb, at + 4, 20)   # point at the SST record
        res = parse(rewrap([("Workbook", wb)]), "t.xls")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["Excel workbook (legacy .xls): sheet 0 does not "
                          "start at a BOF record; it was skipped."])


class XlsRkNumbers(unittest.TestCase):
    """RK numbers ([MS-XLS] 2.5.122). Excel's default numeric encoding, so
    the non-integer branch matters as much as the integer one."""

    def test_float_rk_is_the_top_half_of_a_double(self):
        # 3.5 is 0x400C000000000000; the RK keeps 0x400C0000.
        self.assertEqual(officedoc._rk_value(0x400C0000), 3.5)

    def test_float_rk_with_the_divide_by_100_flag(self):
        # 314.0 is 0x4073A00000000000; flag bit 0 divides by 100.
        self.assertEqual(officedoc._rk_value(0x4073A000 | 0x01), 3.14)

    def test_integer_rk_signed_and_scaled(self):
        self.assertEqual(officedoc._rk_value((42 << 2) | 0x02), 42)
        self.assertEqual(officedoc._rk_value(((-5 & 0x3FFFFFFF) << 2) | 0x02),
                         -5)
        self.assertEqual(officedoc._rk_value((314 << 2) | 0x03), 3.14)

    def test_rk_and_mulrk_cells_reach_the_text(self):
        sheets = [("R", [("rk", 0, 0, 0x400C0000),
                         ("rk", 0, 1, (42 << 2) | 0x02),
                         ("mulrk", 1, 0, [0x4073A000 | 0x01,
                                          (7 << 2) | 0x02])])]
        res = parse(ib.build_xls(sheets), "t.xls")
        self.assertEqual(res["text"], "R\n3.5\t42\n3.14\t7")
        self.assertEqual(res["findings"], [])


class PptSlideText(unittest.TestCase):
    """Text via the UserEdit chain, persist directories and slide text
    atoms ([MS-PPT]); newest-wins persist semantics."""

    SLIDES = [["Hello title.", "Body text here."],
              ["Second slide", "caf\u00e9 utf16"]]

    def setUp(self):
        self.raw = ib.build_ppt(self.SLIDES)

    def doc_and_user(self, data=None):
        o = ole2.Ole2(data if data is not None else self.raw, "t.ppt")
        return o.read("PowerPoint Document"), o.read("Current User")

    def test_reads_the_newest_edit_only(self):
        res = parse(self.raw, "t.ppt")
        self.assertEqual(res["kind"],
                         "PowerPoint presentation (legacy .ppt)")
        self.assertEqual(res["text"],
                         "Hello title.\nBody text here.\n\n"
                         "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["sections"],
                         [{"name": "slides", "text": res["text"]}])
        self.assertEqual(res["findings"], [])
        self.assertNotIn("Outdated stale text.", res["text"])
        self.assertIsInstance(res["metadata"], dict)

    def test_unicode_runs_decode_as_utf16(self):
        res = parse(ib.build_ppt([["pi\u00e8ce unicode", "Body B."]]), "t.ppt")
        self.assertEqual(res["text"], "pi\u00e8ce unicode\nBody B.")
        self.assertEqual(res["findings"], [])

    def test_current_user_offset_outside_the_stream(self):
        doc, cu = self.doc_and_user(self.raw)
        cu = bytearray(cu)
        struct.pack_into("<I", cu, 16, 0xFFFF00)
        res = parse(ib.build_cfb([("PowerPoint Document", doc),
                                  ("Current User", bytes(cu))]), "t.ppt")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): the "
                          "Current User stream does not point at a "
                          "UserEditAtom inside the PowerPoint stream; no "
                          "text was read."])
        self.assertIsInstance(res["metadata"], dict)

    def test_current_user_stream_too_short(self):
        # build_cfb floors streams at 4096 bytes, so a genuinely short
        # Current User stream is exercised on the extractor directly.
        doc, _cu = self.doc_and_user(self.raw)
        findings = []
        text = officedoc._ppt_body(doc, b"\x00\x01\x02", findings,
                                   "PowerPoint presentation (legacy .ppt)")
        self.assertEqual(text, "")
        self.assertEqual(findings,
                         ["PowerPoint presentation (legacy .ppt): the "
                          "Current User stream is too short to hold a "
                          "CurrentUserAtom; no text was read."])

    def test_persist_directory_not_reachable(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # the newest UserEditAtom's persist-pointer offset -> outside
        struct.pack_into("<I", doc, 0x1CD + 20, 0xFFFF00)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): a persist "
                          "directory sits outside the PowerPoint stream; "
                          "the remaining edits were skipped.",
                          "PowerPoint presentation (legacy .ppt): no persist "
                          "directory could be read; no text was read."])

    def test_zero_persist_offset_is_skipped_without_a_finding(self):
        # [MS-PPT] "File Structure" lists a persist offset of 0 as an
        # ordinary entry in a real directory, so it is not an error.
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # newest directory maps persist id 2 (the second offset after
        # the info u32) -> offset 0
        struct.pack_into("<I", doc, 0x199 + 4 + 4, 0)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        # the stale slide the older directory gives id 2 is not used
        # (newest wins); the other slide survives.
        self.assertEqual(res["text"], "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["findings"], [])
        self.assertNotIn("Outdated stale text.", res["text"])

    def test_persist_offset_beyond_the_stream_is_reported(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        struct.pack_into("<I", doc, 0x199 + 4 + 4, len(doc) + 1000)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        self.assertEqual(res["text"], "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): a persist "
                          "record sits outside the PowerPoint stream; it "
                          "was skipped."])
        self.assertNotIn("Outdated stale text.", res["text"])

    def test_slide_container_overrun_keeps_the_proven_prefix(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # slide 1's record length shrunk so its children run past it
        struct.pack_into("<I", doc, 0x8C + 4, 60)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        self.assertEqual(res["text"], "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): a nested "
                          "record runs past its parent container; the rest "
                          "of the slide was skipped."])
        self.assertNotIn("Hello title.", res["text"])

    def test_text_run_overrun_yields_no_garbage_bytes(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # slide 1's TextBytesAtom claims 200 bytes, past the slide's end
        struct.pack_into("<I", doc, 0xD4, 200)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        self.assertEqual(res["text"], "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): a byte "
                          "text run is cut short; it was skipped.",
                          "PowerPoint presentation (legacy .ppt): a nested "
                          "record runs past its parent container; the rest "
                          "of the slide was skipped."])
        self.assertNotIn("\x9f\x0f", res["text"])

    def test_self_referential_edit_history_keeps_proven_slides(self):
        doc, cu = self.doc_and_user(self.raw)
        doc = bytearray(doc)
        # newest UserEditAtom's prev pointer loops back to itself
        struct.pack_into("<I", doc, 0x1CD + 16, 0x1CD)
        res = parse(rewrap([("PowerPoint Document", doc),
                            ("Current User", cu)]), "t.ppt")
        self.assertEqual(res["text"],
                         "Hello title.\nBody text here.\n\n"
                         "Second slide\ncaf\u00e9 utf16")
        self.assertEqual(res["findings"],
                         ["PowerPoint presentation (legacy .ppt): the edit "
                          "history is cut short; the remaining edits were "
                          "skipped."])


class XlsSharedStringLayout(unittest.TestCase):
    """XLUnicodeRichExtendedString ([MS-XLS] 2.5.293) from hand-assembled
    bytes, not the fixture builder: cch, flags, [cRun], [cbExtRst], the
    characters, and only then rgRun and ExtRst. A reader that skips that
    data before the characters loses step and garbles every later string,
    so each case ends with a plain string that must come out intact."""

    @staticmethod
    def sst(unique, first, *continues):
        head = struct.pack("<II", unique, unique) + first
        blob = struct.pack("<HH", officedoc.SST_RECORD, len(head)) + head
        for body in continues:
            blob += struct.pack("<HH", officedoc.CONTINUE_RECORD,
                                len(body)) + body
        return blob

    @staticmethod
    def read(blob):
        findings = []
        got, end = officedoc._xls_read_sst(blob, 0, findings, "x")
        return got, end, findings

    PLAIN = struct.pack("<HB", 2, 0) + b"de"

    def test_formatting_runs_follow_the_characters(self):
        rich = struct.pack("<HBH", 3, 0x08, 2) + b"abc" + b"R" * 8
        got, _end, findings = self.read(self.sst(2, rich + self.PLAIN))
        self.assertEqual(got, ["abc", "de"])
        self.assertEqual(findings, [])

    def test_phonetic_data_follows_the_characters(self):
        ext = struct.pack("<HBI", 3, 0x04, 6) + b"xyz" + b"P" * 6
        got, _end, findings = self.read(self.sst(2, ext + self.PLAIN))
        self.assertEqual(got, ["xyz", "de"])
        self.assertEqual(findings, [])

    def test_utf16_with_both_runs_and_phonetic_data(self):
        both = struct.pack("<HBHI", 2, 0x0D, 1, 4) \
            + "éé".encode("utf-16-le") + b"R" * 4 + b"P" * 4
        got, _end, findings = self.read(self.sst(2, both + self.PLAIN))
        self.assertEqual(got, ["éé", "de"])
        self.assertEqual(findings, [])

    def test_characters_continue_after_a_fresh_flags_byte(self):
        head = struct.pack("<HB", 6, 0) + b"abc"
        cont = b"\x00" + b"def" + struct.pack("<HB", 2, 0) + b"gh"
        got, _end, findings = self.read(self.sst(2, head, cont))
        self.assertEqual(got, ["abcdef", "gh"])
        self.assertEqual(findings, [])

    def test_a_continuation_may_change_the_character_width(self):
        head = struct.pack("<HB", 4, 0) + b"ab"
        cont = b"\x01" + "éé".encode("utf-16-le")
        got, _end, findings = self.read(self.sst(1, head, cont))
        self.assertEqual(got, ["abéé"])
        self.assertEqual(findings, [])

    def test_formatting_data_spans_a_continue_without_a_flags_byte(self):
        head = struct.pack("<HBH", 3, 0x08, 2) + b"abc" + b"R" * 4
        cont = b"R" * 4 + self.PLAIN
        got, _end, findings = self.read(self.sst(2, head, cont))
        self.assertEqual(got, ["abc", "de"])
        self.assertEqual(findings, [])

    def test_a_string_filling_a_record_leaves_the_next_without_flags(self):
        head = struct.pack("<HB", 2, 0) + b"ab"
        cont = struct.pack("<HB", 2, 0) + b"cd"
        got, _end, findings = self.read(self.sst(2, head, cont))
        self.assertEqual(got, ["ab", "cd"])
        self.assertEqual(findings, [])

    def test_the_offset_returned_is_past_the_continue_chain(self):
        blob = self.sst(1, struct.pack("<HB", 2, 0) + b"ab", b"", b"")
        _got, end, _findings = self.read(blob)
        self.assertEqual(end, len(blob))

    def test_a_table_naming_more_strings_than_it_holds(self):
        got, _end, findings = self.read(self.sst(3, self.PLAIN + self.PLAIN))
        self.assertEqual(got, ["de", "de"])
        self.assertEqual(findings,
                         ["x: the shared-string table names more strings "
                          "than it holds; the rest read as empty."])

    def test_strings_after_rich_and_phonetic_ones_survive_end_to_end(self):
        sheets = [("S", [("s", 0, 0, ib.Styled("Mixed", runs=2)),
                         ("s", 0, 1, ib.Styled("Kana", ext=b"\x01" * 6)),
                         ("s", 0, 2, "After"), ("n", 0, 3, 4)])]
        res = parse(ib.build_xls(sheets), "t.xls")
        self.assertEqual(res["text"], "S\nMixed\tKana\tAfter\t4")
        self.assertEqual(res["findings"], [])


class XlsTruncatedRecords(unittest.TestCase):
    """A record cut short must cost that record, never the whole parse."""

    @staticmethod
    def rec(rid, body):
        return struct.pack("<HH", rid, len(body)) + body

    def workbook(self, boundsheet_body):
        blob = self.rec(officedoc.BOF_RECORD, bytes(16)) \
            + self.rec(officedoc.BOUNDSHEET_RECORD, boundsheet_body) \
            + self.rec(officedoc.EOF_RECORD, b"")
        return ib.build_cfb([("Workbook", blob + bytes(4096 - len(blob)))])

    def test_a_boundsheet_too_short_for_its_name_does_not_fail_the_parse(self):
        # 6 bytes: lbPlyPos, hsState and dt and nothing more. 7 bytes: the
        # name's length byte but not its flags byte.
        for body in (struct.pack("<IBB", 0, 0, 0),
                     struct.pack("<IBBB", 0, 0, 0, 3)):
            res = parse(self.workbook(body), "t.xls")
            self.assertEqual(res["text"], "")
            self.assertIsInstance(res["metadata"], dict)

    def test_sheet_name_is_read_from_offset_6_of_boundsheet(self):
        # BoundSheet8 ([MS-XLS] 2.4.28): lbPlyPos (4), hsState (1), dt (1),
        # then stName at offset 6 -- assembled here by hand, not by the
        # fixture builder.
        bof = self.rec(officedoc.BOF_RECORD, bytes(16))
        eof = self.rec(officedoc.EOF_RECORD, b"")
        sheet = bof + self.rec(officedoc.NUMBER_RECORD,
                               struct.pack("<HHHd", 0, 0, 0, 7.0)) + eof

        def bound(lb):
            return self.rec(officedoc.BOUNDSHEET_RECORD,
                            struct.pack("<IBB", lb, 0, 0)
                            + struct.pack("<BB", 4, 0) + b"Data")

        globals_len = len(bof) + len(bound(0)) + len(eof)
        blob = bof + bound(globals_len) + eof + sheet
        blob += bytes(4096 - len(blob))
        res = parse(ib.build_cfb([("Workbook", blob)]), "t.xls")
        self.assertEqual(res["text"], "Data\n7")
        self.assertEqual(res["findings"], [])

    def test_an_unforeseen_failure_in_a_body_reader_costs_only_the_text(self):
        from unittest import mock
        data = ib.build_xls([("S", [("s", 0, 0, "kept?")])])
        with mock.patch.object(officedoc, "_xls_body",
                               side_effect=IndexError("boom")):
            res = parse(data, "t.xls")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["kind"], "Excel workbook (legacy .xls)")
        self.assertIsInstance(res["metadata"], dict)
        self.assertEqual(len(res["findings"]), 1)
        self.assertIn("could not be read", res["findings"][0])
        self.assertIn("IndexError", res["findings"][0])


class PptNestedShapes(unittest.TestCase):
    """Real slides nest their text a few containers deep, one shape per
    text box; the walk has to visit the siblings that follow each nested
    container, not only the first path down."""

    def test_text_in_shapes_after_the_first_container_is_read(self):
        res = parse(ib.build_ppt([["First shape", "Second shape",
                                   "Third shape"]], nested=True), "t.ppt")
        self.assertEqual(res["text"],
                         "First shape\nSecond shape\nThird shape")
        self.assertEqual(res["findings"], [])

    def test_every_slide_and_run_in_nested_drawings(self):
        res = parse(ib.build_ppt([["A1", "A2"], ["B1", "café 中"]],
                                 nested=True), "t.ppt")
        self.assertEqual(res["text"], "A1\nA2\n\nB1\ncafé 中")
        self.assertEqual(res["findings"], [])


class Ole2Framing(unittest.TestCase):
    """Kind selection, notes, and the raw-bytes entry contract."""

    def test_generic_compound_document_keeps_the_old_note(self):
        plain = ib.build_cfb([("SomeStream", b"\x00" * 4096)])
        res = parse(plain, "t")
        self.assertEqual(res["kind"], "OLE2 compound document")
        self.assertEqual(res["text"], "")
        self.assertEqual(res["sections"], [])
        self.assertEqual(res["note"],
                         "The body of a legacy Office document is a binary "
                         "format of its own \u2014 Word's piece table, "
                         "Excel's BIFF record stream \u2014 and is not "
                         "decoded here, so no text is offered rather than "
                         "text that might be wrong. The properties below "
                         "are from the document's own property set: they "
                         "are written by the application from whatever it "
                         "was told and can be edited.")

    def test_msg_kind_keeps_the_old_note(self):
        res = parse(ib.build_cfb(
            [("__properties_version1.0", b"\x00" * 4096)]), "m.msg")
        self.assertEqual(res["kind"], "Outlook message (.msg)")
        self.assertEqual(res["text"], "")
        self.assertTrue(res["note"].startswith(
            "The body of a legacy Office document"))

    def test_non_ole2_input_returns_none(self):
        self.assertIsNone(parse(b"not an ole2 file at all", "x"))

    def test_word_beats_other_kinds_when_streams_coexist(self):
        data = ib.build_cfb([
            ("WordDocument", b"\x00" * 4096),
            ("Workbook", b"\x00" * 4096),
            ("PowerPoint Document", b"\x00" * 4096)])
        res = parse(data, "t")
        self.assertEqual(res["kind"], "Word document (legacy .doc)")


if __name__ == "__main__":
    unittest.main()