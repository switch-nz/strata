import re
import struct
import xml.etree.ElementTree as ET

from . import archive
from . import ole2

MAX_TEXT = 8 << 20
MAX_PART = 64 << 20

_DOCTYPE = re.compile(rb"<!DOCTYPE", re.I)

WORD_PARTS = (
    ("word/document.xml", "document"),
    ("word/footnotes.xml", "footnotes"),
    ("word/endnotes.xml", "endnotes"),
    ("word/comments.xml", "comments"),
)
SLIDE_RE = re.compile(r"^ppt/slides/slide(\d+)\.xml$")
NOTES_RE = re.compile(r"^ppt/notesSlides/notesSlide(\d+)\.xml$")
SHEET_RE = re.compile(r"^xl/worksheets/sheet(\d+)\.xml$")
HEADER_RE = re.compile(r"^word/(header|footer)\d*\.xml$")

CORE_FIELDS = {
    "title": "Title", "subject": "Subject", "creator": "Author",
    "keywords": "Keywords", "description": "Description",
    "lastModifiedBy": "Last saved by", "revision": "Revision",
    "created": "Created", "modified": "Modified",
    "lastPrinted": "Last printed", "category": "Category",
    "contentStatus": "Status",
}
APP_FIELDS = {
    "Application": "Application", "AppVersion": "Application version",
    "Company": "Company", "Manager": "Manager", "Template": "Template",
    "TotalTime": "Editing time (minutes)", "Pages": "Pages", "Words": "Words",
    "Characters": "Characters", "Paragraphs": "Paragraphs",
    "Slides": "Slides", "Notes": "Notes", "HiddenSlides": "Hidden slides",
}
ODF_META = {
    "initial-creator": "Author", "creator": "Last saved by",
    "creation-date": "Created", "date": "Modified",
    "editing-cycles": "Revision", "editing-duration": "Editing time",
    "generator": "Application", "title": "Title", "subject": "Subject",
    "description": "Description", "keyword": "Keywords",
    "printed-by": "Last printed by", "print-date": "Last printed",
}

def _local(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag

def _xml(blob, findings, part):
    if not blob:
        return None
    if _DOCTYPE.search(blob[:4096]):
        findings.append(
            "%s carries a DOCTYPE declaration. No legitimate Office part has "
            "one, and it is where entity definitions live — the mechanism "
            "behind entity-expansion attacks. The part was not parsed." % part)
        return None
    try:
        return ET.fromstring(blob)
    except ET.ParseError as exc:
        findings.append("%s is not well-formed XML (%s); it was skipped."
                        % (part, exc))
        return None

def _text_of(node, sep=""):
    out = []
    for el in node.iter():
        if el.text:
            out.append(el.text)
    return sep.join(out)

def _word_text(root):
    lines, cur = [], []
    for el in root.iter():
        tag = _local(el.tag)
        if tag == "t" and el.text:
            cur.append(el.text)
        elif tag == "tab":
            cur.append("\t")
        elif tag in ("br", "cr"):
            cur.append("\n")
        elif tag == "p":
            if cur:
                lines.append("".join(cur))
                cur = []
    if cur:
        lines.append("".join(cur))
    return "\n".join(lines)

def _slide_text(root):
    lines, cur = [], []
    for el in root.iter():
        tag = _local(el.tag)
        if tag == "t" and el.text:
            cur.append(el.text)
        elif tag == "p":
            if cur:
                lines.append("".join(cur))
                cur = []
    if cur:
        lines.append("".join(cur))
    return "\n".join(lines)

def _shared_strings(root):
    out = []
    for si in root:
        if _local(si.tag) != "si":
            continue
        parts = [el.text for el in si.iter()
                 if _local(el.tag) == "t" and el.text]
        out.append("".join(parts))
    return out

def _col_key(ref):
    m = re.match(r"([A-Z]+)(\d+)$", ref or "")
    if not m:
        return (0, 0)
    col = 0
    for ch in m.group(1):
        col = col * 26 + (ord(ch) - 64)
    return (int(m.group(2)), col)

def _sheet_text(root, shared):
    rows = []
    for row in root.iter():
        if _local(row.tag) != "row":
            continue
        cells = []
        for c in row:
            if _local(c.tag) != "c":
                continue
            typ = c.get("t")
            val = ""
            if typ == "inlineStr":
                val = "".join(el.text for el in c.iter()
                              if _local(el.tag) == "t" and el.text)
            else:
                v = next((el for el in c if _local(el.tag) == "v"), None)
                if v is not None and v.text is not None:
                    if typ == "s":
                        try:
                            val = shared[int(v.text)]
                        except (ValueError, IndexError):
                            val = ""
                    else:
                        val = v.text
            cells.append((_col_key(c.get("r")), val))
        cells.sort(key=lambda x: x[0])
        line = "\t".join(v for _k, v in cells)
        if line.strip():
            rows.append(line)
    return "\n".join(rows)

def _sheet_names(root):
    out = {}
    for el in root.iter():
        if _local(el.tag) == "sheet":
            out[el.get("sheetId") or el.get("name")] = el.get("name")
    return out

def _core(root, findings):
    out = {}
    for el in root:
        name = _local(el.tag)
        label = CORE_FIELDS.get(name)
        if label and (el.text or "").strip():
            out[label] = el.text.strip()
    return out

def _app(root):
    out = {}
    for el in root:
        label = APP_FIELDS.get(_local(el.tag))
        if label and (el.text or "").strip():
            out[label] = el.text.strip()
    return out

def _odf_meta(root):
    out = {}
    for el in root.iter():
        label = ODF_META.get(_local(el.tag))
        if not label:
            continue
        txt = (el.text or "").strip()
        if not txt and _local(el.tag) == "editing-duration":
            txt = el.get("duration") or ""
        if txt:
            out.setdefault(label, txt)
    return out

def _odf_text(root):
    lines = []
    for el in root.iter():
        tag = _local(el.tag)
        if tag in ("p", "h"):
            txt = _text_of(el)
            if txt.strip():
                lines.append(txt)
        elif tag == "table-row":
            cells = []
            for c in el:
                if _local(c.tag) == "table-cell":
                    cells.append(_text_of(c))
            line = "\t".join(cells)
            if line.strip():
                lines.append(line)
    return "\n".join(lines)

def looks_like_office(head):
    return head[:2] in (b"PK", b"\x50\x4b")

def parse(data, name=""):
    if not data:
        return None
    if ole2.looks_like_ole2(data[:8]):
        return parse_ole2_document(data, name)
    if not looks_like_office(data[:4]):
        return None
    z = archive.Zip(data, name)
    if not z.valid or not z.entries:
        return None
    by_name = {e.name: e for e in z.entries}
    names = set(by_name)

    family = None
    if "word/document.xml" in names:
        family = "word"
    elif "xl/workbook.xml" in names:
        family = "excel"
    elif "ppt/presentation.xml" in names:
        family = "powerpoint"
    elif "content.xml" in names and "meta.xml" in names:
        family = "odf"
    elif "content.xml" in names:
        family = "odf"
    if not family:
        return None

    findings = list(z.findings)

    def part(pname):
        e = by_name.get(pname)
        if e is None:
            return None
        try:
            blob, notes = z.read(e, MAX_PART)
        except Exception as exc:
            findings.append("%s could not be decompressed (%s)."
                            % (pname, type(exc).__name__))
            return None
        for n in notes:
            findings.append("%s: %s" % (pname, n))
        return blob

    meta, sections = {}, []

    if family == "odf":
        m = _xml(part("meta.xml") or b"", findings, "meta.xml")
        if m is not None:
            meta = _odf_meta(m)
        c = _xml(part("content.xml") or b"", findings, "content.xml")
        if c is not None:
            sections.append(("content", _odf_text(c)))
        kind = {"application/vnd.oasis.opendocument.text": "OpenDocument text",
                "application/vnd.oasis.opendocument.spreadsheet":
                    "OpenDocument spreadsheet",
                "application/vnd.oasis.opendocument.presentation":
                    "OpenDocument presentation"}.get(
            (part("mimetype") or b"").decode("latin-1").strip(),
            "OpenDocument")
    else:
        core = _xml(part("docProps/core.xml") or b"", findings,
                    "docProps/core.xml")
        if core is not None:
            meta.update(_core(core, findings))
        app = _xml(part("docProps/app.xml") or b"", findings,
                   "docProps/app.xml")
        if app is not None:
            meta.update(_app(app))

        if family == "word":
            kind = "Word document"
            for pname, label in WORD_PARTS:
                if pname not in names:
                    continue
                root = _xml(part(pname) or b"", findings, pname)
                if root is not None:
                    sections.append((label, _word_text(root)))
            for pname in sorted(n for n in names if HEADER_RE.match(n)):
                root = _xml(part(pname) or b"", findings, pname)
                if root is not None:
                    t = _word_text(root)
                    if t.strip():
                        sections.append((pname.split("/")[-1], t))
        elif family == "excel":
            kind = "Excel workbook"
            shared = []
            if "xl/sharedStrings.xml" in names:
                root = _xml(part("xl/sharedStrings.xml") or b"", findings,
                            "xl/sharedStrings.xml")
                if root is not None:
                    shared = _shared_strings(root)
            wb = _xml(part("xl/workbook.xml") or b"", findings,
                      "xl/workbook.xml")
            titles = _sheet_names(wb) if wb is not None else {}
            ordered = sorted((n for n in names if SHEET_RE.match(n)),
                             key=lambda n: int(SHEET_RE.match(n).group(1)))
            for i, pname in enumerate(ordered, 1):
                root = _xml(part(pname) or b"", findings, pname)
                if root is None:
                    continue
                label = titles.get(str(i)) or ("sheet %d" % i)
                sections.append((label, _sheet_text(root, shared)))
        else:
            kind = "PowerPoint presentation"
            for rx, tmpl in ((SLIDE_RE, "slide %s"),
                             (NOTES_RE, "slide %s notes")):
                got = sorted((n for n in names if rx.match(n)),
                             key=lambda n: int(rx.match(n).group(1)))
                for pname in got:
                    root = _xml(part(pname) or b"", findings, pname)
                    if root is not None:
                        t = _slide_text(root)
                        if t.strip():
                            sections.append(
                                (tmpl % rx.match(pname).group(1), t))

    body, total, truncated = [], 0, False
    for label, txt in sections:
        if not txt.strip():
            continue
        if total + len(txt) > MAX_TEXT:
            txt = txt[:max(0, MAX_TEXT - total)]
            truncated = True
        body.append((label, txt))
        total += len(txt)
        if truncated:
            break
    if truncated:
        findings.append(
            "Text was truncated at %d characters. The document is longer; the "
            "whole of it is still in the evidence." % MAX_TEXT)

    return {
        "kind": kind,
        "family": family,
        "metadata": meta,
        "sections": [{"name": n, "text": t} for n, t in body],
        "text": "\n\n".join(t for _n, t in body),
        "characters": total,
        "parts": len(z.entries),
        "findings": findings,
        "note": ("Document properties are written by the application from "
                 "whatever it was told and can be edited afterwards. They are "
                 "a record of what the file claims, not of what happened."),
    }

PIDSI = {
    2: "Title", 3: "Subject", 4: "Author", 5: "Keywords", 6: "Comments",
    7: "Template", 8: "Last saved by", 9: "Revision",
    10: "Editing time", 11: "Last printed", 12: "Created",
    13: "Modified", 14: "Pages", 15: "Words", 16: "Characters",
    18: "Application", 19: "Security",
}
PIDDSI = {14: "Manager", 15: "Company", 3: "Slides", 5: "Paragraphs"}

def _prop_value(blob, at, findings):
    if at + 4 > len(blob):
        return None, False
    typ, = struct.unpack_from("<I", blob, at)
    v = at + 4
    if typ in (0x1E, 0x1F):
        if v + 4 > len(blob):
            return None, False
        n, = struct.unpack_from("<I", blob, v)
        if n > (1 << 20) or v + 4 + n > len(blob):
            return None, False
        raw = blob[v + 4:v + 4 + n]
        if typ == 0x1F:
            txt = raw.decode("utf-16-le", "replace")
        else:
            txt = raw.decode("latin-1", "replace")
        return txt.split("\x00", 1)[0].strip() or None, True
    if typ == 0x40:
        if v + 8 > len(blob):
            return None, False
        ft, = struct.unpack_from("<Q", blob, v)
        return ole2.filetime(ft), True
    if typ == 0x03:
        return (struct.unpack_from("<i", blob, v)[0], True) if v + 4 <= len(blob) else (None, False)
    if typ == 0x02:
        return (struct.unpack_from("<h", blob, v)[0], True) if v + 2 <= len(blob) else (None, False)
    if typ == 0x0B:
        return (bool(struct.unpack_from("<h", blob, v)[0]), True) if v + 2 <= len(blob) else (None, False)
    if typ == 0x47:
        return None, True
    return None, True

def _property_set(blob, names, findings, label):
    out = {}
    if len(blob) < 48:
        return out
    if blob[:2] != b"\xfe\xff":
        findings.append("%s does not begin with the property-set byte-order "
                        "mark; it was not read." % label)
        return out
    n_sections, = struct.unpack_from("<I", blob, 24)
    if not 0 < n_sections < 16:
        findings.append("%s declares %d sections, which is implausible."
                        % (label, n_sections))
        return out
    for i in range(n_sections):
        base = 28 + i * 20
        if base + 20 > len(blob):
            break
        off, = struct.unpack_from("<I", blob, base + 16)
        if off + 8 > len(blob):
            continue
        _size, count = struct.unpack_from("<II", blob, off)
        if count > 4096:
            findings.append("%s declares %d properties in one section; not "
                            "read." % (label, count))
            continue
        for p in range(count):
            e = off + 8 + p * 8
            if e + 8 > len(blob):
                break
            pid, poff = struct.unpack_from("<II", blob, e)
            name = names.get(pid)
            if not name:
                continue
            val, ok = _prop_value(blob, off + poff, findings)
            if not ok:
                findings.append("%s: property %d could not be decoded and was "
                                "skipped." % (label, pid))
                continue
            if val not in (None, ""):
                if name == "Editing time" and isinstance(val, str):
                    continue
                out[name] = val
    return out

def _word_body(worddoc, table, findings, label):
    """Text of a WordDocument stream via its piece table ([MS-DOC]). The
    Clx in the table stream is walked for Prcs and the final Pcdt; each
    PCD names a byte range of the WordDocument stream, compressed
    (latin-1, fc halved) or not (UTF-16LE). Only proven pieces are
    returned: a piece that cannot be decoded in full is dropped, not
    guessed at."""
    if len(worddoc) < 0x01AA or struct.unpack_from("<H", worddoc, 0)[0] != 0xA5EC:
        findings.append("%s: the WordDocument stream does not begin with a "
                        "Word 97 FIB; no text was read." % label)
        return ""
    fcclx, lcbclx = struct.unpack_from("<II", worddoc, 0x01A2)
    tblname = "1table" if struct.unpack_from("<H", worddoc, 0x000A)[0] & 0x0200 \
        else "0table"
    if table is None or len(table) < fcclx + lcbclx:
        findings.append("%s: the piece table (%s) is missing or shorter "
                        "than the FIB records; no text was read."
                        % (label, tblname))
        return ""
    clx = table[fcclx:fcclx + lcbclx]

    at, pieces = 0, None
    while at < len(clx):
        clxt = clx[at]
        if clxt == 0x01:                       # Prc: skip its PrcData
            if at + 3 > len(clx):
                findings.append("%s: a piece-table property modifier is "
                                "cut short; the piece table ends here."
                                % label)
                break
            cb, = struct.unpack_from("<H", clx, at + 1)
            at += 3 + cb
        elif clxt == 0x02:                     # Pcdt: the PlcPcd follows
            if at + 5 > len(clx):
                findings.append("%s: the piece table descriptor is cut "
                                "short; no text was read." % label)
                return ""
            lcb, = struct.unpack_from("<I", clx, at + 1)
            plc = clx[at + 5:at + 5 + lcb]
            if len(plc) < lcb or lcb < 12 or (lcb - 4) % 12:
                findings.append("%s: the piece table's size does not "
                                "match its structure; no text was read."
                                % label)
                return ""
            pieces = plc
            break
        else:
            findings.append("%s: the piece table holds an unknown Clxt "
                            "value (0x%02X); the piece table ends here."
                            % (label, clxt))
            break
    if pieces is None:
        findings.append("%s: the Clx holds no piece table descriptor "
                        "(Pcdt); no text was read." % label)
        return ""

    n = (len(pieces) - 4) // 12
    cps = struct.unpack_from("<%dI" % (n + 1), pieces, 0)
    if any(cps[i] >= cps[i + 1] for i in range(n)):
        findings.append("%s: the piece table's character positions are "
                        "not strictly increasing; no text was read."
                        % label)
        return ""

    out = []
    for i in range(n):
        pcd = pieces[4 * (n + 1) + 8 * i:4 * (n + 1) + 8 * (i + 1)]
        _flags, fc = struct.unpack_from("<HI", pcd, 0)
        span = cps[i + 1] - cps[i]
        if fc & 0x80000000:
            findings.append("%s: piece %d points past the 2 GB text "
                            "limit; it was skipped." % (label, i))
            continue
        comp = bool(fc & 0x40000000)
        off = fc & 0x3FFFFFFF
        if comp:
            off >>= 1
        end = off + span * (2 if not comp else 1)
        if off < 0 or end > len(worddoc) or off > end:
            findings.append("%s: piece %d points outside the "
                            "WordDocument stream; it was skipped."
                            % (label, i))
            continue
        raw = worddoc[off:end]
        try:
            txt = raw.decode("latin-1" if comp else "utf-16-le")
            if comp:
                txt = txt.translate(_WORD_ANSI)
        except UnicodeDecodeError:
            findings.append("%s: piece %d is not decodable %s text; it "
                            "was skipped."
                            % (label, i,
                               "latin-1" if comp else "UTF-16LE"))
            continue
        if len(txt) != span:
            findings.append("%s: piece %d decodes to %d characters, not "
                            "the %d its character positions promise; it "
                            "was skipped." % (label, i, len(txt), span))
            continue
        out.append(txt)
    return "".join(out)

# [MS-DOC] FcCompressed: in 8-bit ("compressed") text these bytes stand for
# these characters (Word's smart quotes, dashes and so on); every other
# byte is its own code point.
_WORD_ANSI = {
    0x82: "\u201a", 0x83: "\u0192", 0x84: "\u201e", 0x85: "\u2026",
    0x86: "\u2020", 0x87: "\u2021", 0x88: "\u02c6", 0x89: "\u2030",
    0x8a: "\u0160", 0x8b: "\u2039", 0x8c: "\u0152", 0x91: "\u2018",
    0x92: "\u2019", 0x93: "\u201c", 0x94: "\u201d", 0x95: "\u2022",
    0x96: "\u2013", 0x97: "\u2014", 0x98: "\u02dc", 0x99: "\u2122",
    0x9a: "\u0161", 0x9b: "\u203a", 0x9c: "\u0153", 0x9f: "\u0178",
}

# Word's special characters in the text stream. Line, page and column
# breaks and the paragraph and cell marks become newlines; the
# non-breaking hyphen becomes a hyphen; the optional hyphen and the
# anchors for pictures, drawn objects and footnote/comment references
# carry no text and are dropped. Field marks are handled separately.
_WORD_CHARS = {
    "\r": "\n", "\x07": "\n", "\x0b": "\n", "\x0c": "\n", "\x0e": "\n",
    "\x1e": "-",
}
_WORD_FIELD_BEGIN, _WORD_FIELD_SEP, _WORD_FIELD_END = "\x13", "\x14", "\x15"

# FibRgLw97 counts, in the order the document parts follow one another in
# the character-position space ([MS-DOC] FibRgLw97): main text, footnotes,
# headers and footers, comments, endnotes, text boxes, header text boxes.
_WORD_STORIES = ("document", "footnotes", "headers", "comments", "endnotes",
                 "text boxes", "header text boxes")


def _word_clean(text):
    """The text as Word displays it: a field shows its result and not its
    instruction (`HYPERLINK "..."`, `PAGE`, `FORMTEXT`), and the special
    characters are mapped as _WORD_CHARS says. A field mark that has no
    partner is ignored rather than allowed to hide the text after it."""
    out, fields = [], []      # fields: True while inside an instruction
    for ch in text:
        if ch == _WORD_FIELD_BEGIN:
            fields.append(True)
        elif ch == _WORD_FIELD_SEP:
            if fields:
                fields[-1] = False
        elif ch == _WORD_FIELD_END:
            if fields:
                fields.pop()
        elif any(fields):
            continue
        elif ch in _WORD_CHARS:
            out.append(_WORD_CHARS[ch])
        elif ch >= " " or ch == "\t":
            out.append(ch)
    return "".join(out)


def _word_sections(worddoc, text):
    """Split the piece-table text into its document parts by the FIB's
    character counts, and clean each. When the counts do not account for
    the text (or the piece table lost pieces, so positions no longer
    line up) the whole text is one section rather than mislabelled."""
    sections = [("document", text)]
    if len(worddoc) >= 0x6C:
        text_c, ftn, hdd, _r, atn, edn, txbx, hdr_txbx = struct.unpack_from(
            "<8i", worddoc, 0x4C)
        counts = [text_c, ftn, hdd, atn, edn, txbx, hdr_txbx]
        total = sum(counts)
        if all(c >= 0 for c in counts) and 0 < total <= len(text) \
                and len(text) - total <= 1:
            sections, at = [], 0
            for name, n in zip(_WORD_STORIES, counts):
                if n:
                    sections.append((name, text[at:at + n]))
                    at += n
            if at < len(text) and sections:    # the final paragraph mark
                name, last = sections[-1]
                sections[-1] = (name, last + text[at:])
    out = []
    for name, part in sections:
        part = _word_clean(part).rstrip("\n")
        if part.strip():
            out.append((name, part))
    return out


BOF_RECORD = 0x0809
SST_RECORD = 0x00FC
CONTINUE_RECORD = 0x003C
BOUNDSHEET_RECORD = 0x0085
LABELSST_RECORD = 0x00FD
NUMBER_RECORD = 0x0203
RK_RECORD = 0x027E
MULRK_RECORD = 0x00BD
EOF_RECORD = 0x000A

def _rk_value(rk):
    """The number an RK value encodes ([MS-XLS] 2.5.122): a signed
    30-bit integer or the top 32 bits of a double, divided by 100 when
    the low flag is set."""
    div = 100.0 if rk & 0x01 else 1.0
    if rk & 0x02:
        v = rk >> 2
        if v & 0x20000000:
            v -= 0x40000000
        return v / div
    bits = b"\x00" * 4 + struct.pack("<I", rk & 0xFFFFFFFC)
    return struct.unpack("<d", bits)[0] / div

def _xls_number_text(v):
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e16:
        return str(int(v))
    return repr(v)


def _xls_short_string(body, at):
    """A ShortXLUnicodeString: cch u8, flags u8, then cch characters
    (UTF-16LE when the high-byte flag is set). Returns (text, offset
    just past the string)."""
    if at + 2 > len(body):
        return "", at
    cch = body[at]
    high = bool(body[at + 1] & 0x01)
    raw = body[at + 2:at + 2 + cch * (2 if high else 1)]
    try:
        return raw.decode("utf-16-le" if high else "latin-1"), at + 2 + len(raw)
    except UnicodeDecodeError:
        return "", at + 2

def _xls_body(blob, findings, label):
    """Text of a Workbook stream in BIFF8 ([MS-XLS]): the SST holds the
    strings, BOUNDSHEET records name sheets and point at their
    substreams, and the substreams' LABELSST/NUMBER/RK/MULRK records
    carry the cells. Only proven cells are emitted: an SST index past
    the end yields an empty cell, never a guess."""
    at, sst, sheets = 0, [], []
    while at + 4 <= len(blob):
        rid, rlen = struct.unpack_from("<HH", blob, at)
        body = blob[at + 4:at + 4 + rlen]
        if len(body) < rlen:
            findings.append("%s: the record stream is cut short inside a "
                            "record; parsing stops here." % label)
            break
        at += 4 + rlen
        if rid == SST_RECORD:
            sst, at = _xls_read_sst(blob, at - 4 - rlen, findings, label)
            continue
        if rid == BOUNDSHEET_RECORD and len(body) >= 6:
            # BoundSheet8 ([MS-XLS] 2.4.28): lbPlyPos (4), hsState (1),
            # dt (1), then stName, a ShortXLUnicodeString, at offset 6.
            lb, hs, dt = struct.unpack_from("<IBB", body, 0)
            name, _rest = _xls_short_string(body, 6)
            sheets.append((lb, dt, name))
            continue
    # Sheets are parsed from their substreams below, keyed by the BOUNDSHEET
    # entry order.
    out = []
    for si, (lb, dt, name) in enumerate(sheets):
        if lb < 0 or lb + 4 > len(blob):
            findings.append("%s: sheet %d starts outside the workbook "
                            "stream; it was skipped." % (label, si))
            continue
        rid, rlen = struct.unpack_from("<HH", blob, lb)
        if rid != BOF_RECORD:
            findings.append("%s: sheet %d does not start at a BOF "
                            "record; it was skipped." % (label, si))
            continue
        grid, at = {}, lb + 4 + rlen
        ended = False
        while not ended and at + 4 <= len(blob):
            rid, rlen = struct.unpack_from("<HH", blob, at)
            body = blob[at + 4:at + 4 + rlen]
            if len(body) < rlen:
                findings.append("%s: sheet %d's record stream is cut "
                                "short; parsing stops here." % (label, si))
                break
            at += 4 + rlen
            if rid == BOF_RECORD:
                break
            if rid == EOF_RECORD:
                ended = True
                break
            if rid == LABELSST_RECORD and len(body) >= 10:
                row, col, _xf, isst = struct.unpack_from("<HHHI", body, 0)
                grid[(row, col)] = sst[isst] if 0 <= isst < len(sst) else ""
            elif rid == NUMBER_RECORD and len(body) >= 14:
                row, col, _xf = struct.unpack_from("<HHH", body, 0)
                v, = struct.unpack_from("<d", body, 6)
                grid[(row, col)] = _xls_number_text(v)
            elif rid == RK_RECORD and len(body) >= 10:
                row, col, _xf, rk = struct.unpack_from("<HHHI", body, 0)
                grid[(row, col)] = _xls_number_text(_rk_value(rk))
            elif rid == MULRK_RECORD and len(body) >= 10:
                row, col_first = struct.unpack_from("<HH", body, 0)
                col_last, = struct.unpack_from("<H", body, len(body) - 2)
                for k, pos in enumerate(range(4, len(body) - 2, 6)):
                    _xf, rk = struct.unpack_from("<HI", body, pos)
                    grid[(row, col_first + k)] = _xls_number_text(_rk_value(rk))
                if col_first + (len(body) - 6) // 6 - 1 != col_last:
                    findings.append("%s: sheet %d holds a multi-cell "
                                    "record whose column count does not "
                                    "match its span; the columns it "
                                    "covers were still read."
                                    % (label, si))
        rows = {}
        for (r, c) in sorted(grid):
            rows.setdefault(r, []).append((c, grid[(r, c)]))
        lines = ["\t".join(v for _c, v in sorted(cells))
                 for _r, cells in sorted(rows.items())]
        lines = [ln for ln in lines if ln.strip()]
        if lines:
            out.append(name if name else "sheet %d" % (si + 1))
            out.extend(lines)
    return "\n".join(out)

def _xls_read_sst(blob, at, findings, label):
    """Parse one SST record plus its CONTINUE tail. Returns (strings,
    offset just past the CONTINUE chain).

    Each string is an XLUnicodeRichExtendedString ([MS-XLS] 2.5.293):
    cch (2), flags (1), cRun (2, when the rich flag is set), cbExtRst (4,
    when the phonetic flag is set), the characters, then rgRun (4 bytes
    per cRun) and ExtRst (cbExtRst bytes) AFTER the characters. The
    formatting and phonetic data is skipped, but it must be skipped from
    the right place or every later string reads out of step.

    A string's characters may continue into a CONTINUE record, which then
    starts with a fresh flags byte (only the width bit matters); the
    formatting and phonetic tails carry no such byte."""
    rid, rlen = struct.unpack_from("<HH", blob, at)
    unique, = struct.unpack_from("<I", blob, at + 8)
    segs = [(at + 12, at + 4 + rlen)]
    skip = at + 4 + rlen
    while skip + 4 <= len(blob):
        nrid, nlen = struct.unpack_from("<HH", blob, skip)
        if nrid != CONTINUE_RECORD:
            break
        segs.append((skip + 4, skip + 4 + nlen))
        skip += 4 + nlen

    seg, pos = 0, segs[0][0]

    def room():
        """Advance past exhausted records; True while bytes remain."""
        nonlocal seg, pos
        while seg < len(segs) and pos >= segs[seg][1]:
            seg += 1
            if seg < len(segs):
                pos = segs[seg][0]
        return seg < len(segs)

    def take(n):
        nonlocal pos
        out = bytearray()
        while len(out) < n:
            if not room():
                return None
            k = min(segs[seg][1] - pos, n - len(out))
            out += blob[pos:pos + k]
            pos += k
        return bytes(out)

    strings = []
    while len(strings) < unique:
        head = take(3)
        if head is None:
            findings.append("%s: the shared-string table names more "
                            "strings than it holds; the rest read as "
                            "empty." % label)
            break
        cch, = struct.unpack_from("<H", head, 0)
        flags = head[2]
        runs = take(2) if flags & 0x08 else bytes(2)
        ext = take(4) if flags & 0x04 else bytes(4)
        if runs is None or ext is None:
            findings.append("%s: a shared string is cut short; the rest "
                            "of the table was not read." % label)
            break
        crun, = struct.unpack("<H", runs)
        cb_ext, = struct.unpack("<I", ext)

        high = bool(flags & 0x01)
        left, pieces, whole = cch, [], True
        while left > 0:
            before = seg
            if not room():
                whole = False
                break
            if seg != before:
                # The characters continue in a CONTINUE record, which
                # starts with a fresh flags byte (width bit only).
                high = bool(blob[pos] & 0x01)
                pos += 1
                if not room():
                    whole = False
                    break
            width = 2 if high else 1
            n = min(left, (segs[seg][1] - pos) // width)
            if n == 0:
                whole = False
                break
            pieces.append(blob[pos:pos + n * width].decode(
                "utf-16-le" if high else "latin-1", "replace"))
            pos += n * width
            left -= n
        if not whole:
            findings.append("%s: a shared string runs past the end of its "
                            "record; the rest of the table was not read."
                            % label)
            break
        if take(4 * crun) is None or take(cb_ext) is None:
            findings.append("%s: a shared string's formatting data is cut "
                            "short; the rest of the table was not read."
                            % label)
            strings.append("".join(pieces))
            break
        strings.append("".join(pieces))
    return strings, skip


# PowerPoint record types ([MS-PPT]; ids per POI RecordTypes).
PPT_SLIDE = 0x03EE
PPT_DOCUMENT = 0x03E8
PPT_TEXT_HEADER = 0x0F9F
PPT_TEXT_CHARS = 0x0FA0
PPT_ESCHER_CLIENT = 0xF00D
PPT_TEXT_BYTES = 0x0FA8
PPT_USER_EDIT = 0x0FF5
PPT_PERSIST_DIR = 0x1772
PPT_PERSIST_DIR_FULL = 0x1771


def _ppt_text_records(blob, top, findings, label):
    """Text runs of one Slide container: a bounded recursive walk of
    nested containers (records whose instance/version field is 0xF)
    collecting TextHeaderAtom + TextCharsAtom/TextBytesAtom pairs. Text
    whose header is missing or whose bytes cannot be decoded in full is
    dropped, not guessed at. Returns a list of run strings."""
    runs = []
    stack = [(top, top + 8 + struct.unpack_from("<I", blob, top + 4)[0])]
    while stack:
        # Every pass either pops a frame or consumes at least one 8-byte
        # record header, so the walk ends by itself; only depth needs a cap.
        if len(stack) > 64:
            findings.append("%s: a slide holds too many nested records "
                            "to walk; the rest was skipped." % label)
            break
        base, limit = stack[-1]
        if base + 8 > limit:
            stack.pop()
            continue
        ver, rid, rlen = struct.unpack_from("<HHI", blob, base)
        end = base + 8 + rlen
        if end > limit or end > len(blob):
            findings.append("%s: a nested record runs past its parent "
                            "container; the rest of the slide was "
                            "skipped." % label)
            break
        if ver & 0x000F == 0x000F or rid == PPT_ESCHER_CLIENT:
            # Containers (0xF) descend; Escher client-textbox wrappers
            # are formally atoms but their body is a record list. The
            # rest of this frame is kept, so siblings after the container
            # are still visited once it is done.
            stack[-1] = (end, limit)
            stack.append((base + 8, end))
            continue
        stack[-1] = (end, limit)
        if rid == PPT_TEXT_HEADER:
            _ver, _ttype, tlen = struct.unpack_from("<HHI", blob, base)
            nxt = base + 8 + tlen
            if tlen < 4 or nxt + 8 > limit or nxt + 8 > len(blob):
                findings.append("%s: a text header is cut short; its "
                                "text was skipped." % label)
                continue
            nver, nrid, nlen = struct.unpack_from("<HHI", blob, nxt)
            if nrid == PPT_TEXT_CHARS:
                txt = blob[nxt + 8:min(nxt + 8 + nlen, limit)]
                if len(txt) != nlen or nlen % 2:
                    findings.append("%s: a unicode text run is cut "
                                    "short; it was skipped." % label)
                    continue
                runs.append(txt.decode("utf-16-le"))
            elif nrid == PPT_TEXT_BYTES:
                txt = blob[nxt + 8:min(nxt + 8 + nlen, limit)]
                if len(txt) != nlen:
                    findings.append("%s: a byte text run is cut "
                                    "short; it was skipped." % label)
                    continue
                runs.append(txt.decode("latin-1"))
    return runs


def _ppt_body(doc, current, findings, label):
    """Text of a PowerPoint Document stream: from the Current User
    stream, walk the chain of UserEditAtoms newest to oldest, merge
    their persist directories (first record seen for a persist id
    wins), then read each persist record the directories point at and
    pull the text runs out of Slide containers. Only text that can be
    proven from well-formed records is returned."""
    if len(current) < 32:
        findings.append("%s: the Current User stream is too short to "
                        "hold a CurrentUserAtom; no text was read." % label)
        return ""
    offset, = struct.unpack_from("<I", current, 16)
    if not offset or offset >= len(doc) or offset + 8 > len(doc):
        findings.append("%s: the Current User stream does not point at "
                        "a UserEditAtom inside the PowerPoint stream; "
                        "no text was read." % label)
        return ""
    persist = {}
    edits = 0
    while offset and len(persist) < 4096:
        edits += 1
        if edits > 64 or offset + 8 > len(doc):
            findings.append("%s: the edit history is cut short; the "
                            "remaining edits were skipped." % label)
            break
        ver, rid, rlen = struct.unpack_from("<HHI", doc, offset)
        end = offset + 8 + rlen
        if rid != PPT_USER_EDIT or end > len(doc) or rlen < 0x18 \
                or rlen > 0x20:
            findings.append("%s: the edit history does not lead through "
                            "well-formed UserEditAtoms; the remaining "
                            "edits were skipped." % label)
            break
        pptr, = struct.unpack_from("<I", doc, offset + 8 + 12)
        prev, = struct.unpack_from("<I", doc, offset + 8 + 8)
        if pptr + 8 > len(doc):
            findings.append("%s: a persist directory sits outside the "
                            "PowerPoint stream; the remaining edits "
                            "were skipped." % label)
            break
        pver, prid, plen = struct.unpack_from("<HHI", doc, pptr)
        if prid not in (PPT_PERSIST_DIR, PPT_PERSIST_DIR_FULL):
            findings.append("%s: a UserEditAtom does not point at a "
                            "persist directory; the remaining edits "
                            "were skipped." % label)
            break
        blob = doc[pptr + 8:min(pptr + 8 + plen, len(doc))]
        at = 0
        while at + 4 <= len(blob):
            info, = struct.unpack_from("<I", blob, at)
            first, count = info & 0xFFFFF, info >> 20
            if count and at + 4 + 4 * count > len(blob):
                findings.append("%s: a persist directory entry names "
                                "records past the end of the stream; "
                                "it was skipped." % label)
                at = len(blob)
                break
            for i in range(count):
                pos, = struct.unpack_from("<I", blob, at + 4 + 4 * i)
                if first + i not in persist:
                    persist[first + i] = pos
            at += 4 + 4 * count
            if count == 0:
                at += 4
        offset = prev
    if not persist:
        findings.append("%s: no persist directory could be read; no "
                        "text was read." % label)
        return ""

    out = []
    for pid in sorted(persist):
        pos = persist[pid]
        if not pos:
            continue                          # a freed persist slot
        if pos + 8 > len(doc):
            findings.append("%s: a persist record sits outside the "
                            "PowerPoint stream; it was skipped." % label)
            continue
        ver, rid, rlen = struct.unpack_from("<HHI", doc, pos)
        if (ver & 0x000F) != 0x000F or rid != PPT_SLIDE:
            continue                          # Document, fonts, etc.
        runs = _ppt_text_records(doc, pos, findings, label)
        if runs:
            out.append("\n".join(runs))
    return "\n\n".join(out)


def _guarded(reader, findings, label, *args):
    """Run one body reader. A record cut short in a way the reader did not
    anticipate costs the text, with a finding, and never the parse: the
    properties are always returned."""
    try:
        return reader(*args, findings, label)
    except (IndexError, struct.error, ValueError, OverflowError) as exc:
        findings.append("%s: the body could not be read (%s: %s); no text "
                        "was offered." % (label, type(exc).__name__, exc))
        return ""


def parse_ole2_document(data, name=""):
    if not ole2.looks_like_ole2(data[:8]):
        return None
    o = ole2.Ole2(data, name)
    if not o.valid:
        return None
    findings = list(o.findings)
    names = {n.lstrip("\x05").lower(): e for n, e in o.streams()}

    meta = {}
    for key, table, label in (
            ("summaryinformation", PIDSI, "SummaryInformation"),
            ("documentsummaryinformation", PIDDSI, "DocumentSummaryInformation")):
        ent = names.get(key)
        if ent is None:
            continue
        meta.update(_property_set(o.read(ent, 1 << 20), table, findings, label))

    kinds = [(("worddocument",), "Word document (legacy .doc)"),
             (("workbook", "book"), "Excel workbook (legacy .xls)"),
             (("powerpoint document",), "PowerPoint presentation (legacy .ppt)"),
             (("__properties_version1.0",), "Outlook message (.msg)")]
    kind = "OLE2 compound document"
    for keys, label in kinds:
        if any(k in names for k in keys):
            kind = label
            break

    # Body text for the three formats we decode. The Outlook message
    # kind and plain compound documents keep the properties-only note.
    sections = []
    if kind == "Word document (legacy .doc)":
        worddoc = o.read(names["worddocument"], MAX_PART)
        table = None
        # The FIB's fWhichTblStm names the table stream; a file can hold
        # both 0Table and 1Table (an earlier save's copy is left behind),
        # and reading the wrong one gives a stale or unusable piece table.
        named = "1table" if len(worddoc) > 0x0B \
            and struct.unpack_from("<H", worddoc, 0x0A)[0] & 0x0200 \
            else "0table"
        other = "0table" if named == "1table" else "1table"
        tent = names.get(named)
        if tent is None and names.get(other) is not None:
            tent = names[other]
            findings.append("%s: the file header names the %s stream but "
                            "only %s exists; it was read instead."
                            % (kind, named, other))
        if tent is not None:
            table = o.read(tent, MAX_PART)
        txt = _guarded(_word_body, findings, kind, worddoc, table)
        if txt.strip():
            sections.extend(_word_sections(worddoc, txt))
    elif kind == "Excel workbook (legacy .xls)":
        sent = names.get("workbook") or names.get("book")
        txt = _guarded(_xls_body, findings, kind, o.read(sent, MAX_PART))
        if txt.strip():
            sections.append(("workbook", txt))
    elif kind == "PowerPoint presentation (legacy .ppt)":
        doc = o.read(names["powerpoint document"], MAX_PART)
        current = b""
        cuent = names.get("current user")
        if cuent is not None:
            current = o.read(cuent, MAX_PART)
        txt = _guarded(_ppt_body, findings, kind, doc, current)
        if txt.strip():
            sections.append(("slides", txt))

    body, total, truncated = [], 0, False
    for label2, txt in sections:
        if not txt.strip():
            continue
        if total + len(txt) > MAX_TEXT:
            txt = txt[:max(0, MAX_TEXT - total)]
            truncated = True
        body.append((label2, txt))
        total += len(txt)
        if truncated:
            break
    if truncated:
        findings.append(
            "Text was truncated at %d characters. The document is longer; the "
            "whole of it is still in the evidence." % MAX_TEXT)

    if kind in ("Outlook message (.msg)", "OLE2 compound document"):
        note = ("The body of a legacy Office document is a binary format of "
                "its own — Word's piece table, Excel's BIFF record stream — "
                "and is not decoded here, so no text is offered rather than "
                "text that might be wrong. The properties below are from the "
                "document's own property set: they are written by the "
                "application from whatever it was told and can be edited.")
    else:
        note = ("Document properties are written by the application from "
                "whatever it was told and can be edited afterwards. They are "
                "a record of what the file claims, not of what happened.")

    return {
        "kind": kind,
        "family": "ole2",
        "metadata": meta,
        "sections": [{"name": n, "text": t} for n, t in body],
        "text": "\n\n".join(t for _n, t in body),
        "characters": total,
        "parts": len(o.entries),
        "streams": [n for n, _e in o.streams()][:64],
        "findings": findings,
        "note": note,
    }
