"""Build minimal synthetic legacy Office files (Word .doc, Excel .xls,
PowerPoint .ppt) for testing engine.officedoc against, following
[MS-DOC]/[MS-XLS]/[MS-PPT] -- narrowed to exactly what
engine.officedoc.parse_ole2_document actually reads, since nothing here
needs to satisfy Office itself.

Everything is wrapped in a Compound File Binary (CFB, [MS-CFB]) container
built by build_cfb(): 512-byte sectors, one FAT sector, a flat directory
(root child pointer unset -- engine.ole2 collects streams from the
directory entries themselves), and every stream padded to a whole sector
and sized >= 4096 bytes so the mini-FAT is never exercised.

build_doc() produces a WordDocument stream whose FIB points at a Clx in
the table stream; the Clx is a single Pcdt whose PlcPcd describes text
pieces stored in the WordDocument stream (one latin-1 "compressed" piece,
one UTF-16LE piece). build_xls() produces one Workbook stream with a
BOF/SST/BOUNDSHEET globals block followed by one sheet substream per
sheet (LABELSST/NUMBER/RK/MULRK cells). build_ppt() produces a PowerPoint
Document stream (one SlideContainer per slide, holding text atoms) and a
Current User stream wiring the UserEdit chain to a PersistDirectoryAtom
that maps persist ids to those slide containers.

Malformed variants of each are produced by the same functions with
deliberately damaged input (see the callers in tests/test_officedoc.py).
"""

import struct

SECT = 512
SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
NOSTREAM = 0xFFFFFFFF
DIFAT_SECT = 0xFFFFFFFD

STREAM = 2
ROOT = 5

MINI_CUTOFF = 0x1000


def _dirent(name, kind, start, size):
    e = bytearray(128)
    nm = name.encode("utf-16-le") + b"\x00\x00"
    e[0:len(nm)] = nm
    struct.pack_into("<H", e, 64, len(nm))
    e[66] = kind
    struct.pack_into("<III", e, 68, NOSTREAM, NOSTREAM, NOSTREAM)
    struct.pack_into("<IQ", e, 116, start, size)
    return bytes(e)


def build_cfb(streams):
    """streams: list of (name, data >= 4096 bytes). Returns CFB bytes.

    Layout: header (sector "none", file offset 0), FAT in sector 0,
    directory in sector 1 (must fit one sector: <= 3 streams), stream
    data from sector 2 up."""
    assert len(streams) <= 3, "one directory sector holds 4 entries"
    assert all(len(d) >= MINI_CUTOFF for _n, d in streams), \
        "streams must be >= 4096 bytes so the mini-FAT is never used"
    data_start = 2
    cursor = data_start
    entries = [_dirent("Root Entry", ROOT, ENDOFCHAIN, 0)]
    for name, data in streams:
        entries.append(_dirent(name, STREAM, cursor, len(data)))
        cursor += (len(data) + SECT - 1) // SECT
    dirsect = b"".join(entries)
    dirsect += b"\x00" * (SECT - len(dirsect))

    fat = [DIFAT_SECT, ENDOFCHAIN] + [FREESECT] * 126
    cursor = data_start
    for _name, data in streams:
        n = (len(data) + SECT - 1) // SECT
        for i in range(n):
            fat[cursor + i] = cursor + i + 1 if i < n - 1 else ENDOFCHAIN
        cursor += n
    assert cursor <= 128, "fixture FAT spans more than one sector"

    header = bytearray()
    header += SIG
    header += b"\x00" * (24 - 8)
    header += struct.pack("<HHHHH", 0x003E, 3, 0xFFFE, 9, 6)
    header += b"\x00" * (40 - 34)
    header += struct.pack("<IIIIIIIII",
                          0,            # n_dir_sectors (3.x must be 0)
                          1,            # n_fat_sectors
                          1,            # first_dir sector
                          0,            # transaction mark
                          MINI_CUTOFF,  # mini stream cutoff
                          ENDOFCHAIN,   # first mini FAT sector
                          0,            # n mini FAT sectors
                          ENDOFCHAIN,   # first DIFAT sector
                          0)            # n DIFAT sectors
    header += struct.pack("<109I", 0, *([FREESECT] * 108))
    assert len(header) == SECT

    out = bytearray(header)
    out += struct.pack("<128I", *fat)
    out += dirsect
    for _name, data in streams:
        out += data
        pad = (SECT - len(data) % SECT) % SECT
        out += b"\x00" * pad
    return bytes(out)


# --- Word (.doc) -------------------------------------------------------

FIB_TEXT_PIECES_A = "First compressed piece. "          # latin-1 piece
FIB_TEXT_PIECES_U = "Second uncompressed pi\u00e8ce. "  # UTF-16LE piece


def _fib():
    """A WordDocument stream FIB: header fields the extractor reads
    (wIdent, nFib, fWhichTblStm bit, csw/cslw/cbRgFcLcb) with the
    fcClx/lcbClx slot zeroed for the caller to patch."""
    fib = bytearray()
    fib += struct.pack("<HH", 0xA5EC, 0x00C1)      # @0x0000 wIdent, nFib
    fib += b"\x00" * (0x000A - 4)
    fib += struct.pack("<H", 0x0200)               # @0x000A fWhichTblStm -> 1table
    fib += b"\x00" * (0x0020 - 0x000C)
    fib += struct.pack("<H", 0x000E)               # @0x0020 csw
    fib += b"\x00" * (0x003E - 0x0022)             # fibRgW97
    fib += struct.pack("<H", 0x0016)               # @0x003E cslw
    fib += b"\x00" * (0x0098 - 0x0040)             # fibRgLw97
    fib += struct.pack("<H", 0x005D)               # @0x0098 cbRgFcLcb
    # fibRgFcLcb97 starts at 0x009A; entry 33 (fcClx/lcbClx) at
    # 0x009A + 33*8 = 0x01A2. The whole FIB is 0x009A + 0x005D*8 bytes.
    assert len(fib) == 0x009A
    fib += b"\x00" * (0x005D * 8)
    assert len(fib) == 0x009A + 0x005D * 8
    struct.pack_into("<I", fib, 0x01A2, 0)         # fcClx (patched by caller)
    struct.pack_into("<I", fib, 0x01A6, 0)         # lcbClx (patched by caller)
    return fib


def build_doc(pieces=None, corrupt_clx=False, drop_pcdt=False,
              nonmonotonic=False, table_stream="1table", ccp=None,
              extra_streams=()):
    """Returns .doc bytes. pieces: list of (str, compressed) pairs making
    up the document text; defaults to a two-piece body. The FIB's
    fWhichTblStm names table_stream. ccp: the seven FibRgLw97 counts (main
    text, footnotes, headers, comments, endnotes, text boxes, header text
    boxes) when the text should be split into document parts.
    extra_streams: more (name, data) streams, e.g. a stale table stream."""
    if pieces is None:
        pieces = [(FIB_TEXT_PIECES_A, True), (FIB_TEXT_PIECES_U, False)]

    text = b""
    offs = []
    pos = 0x009A + 0x005D * 8             # text lives right after the FIB
    for s, comp in pieces:
        if comp:
            blob = s.encode("latin-1")
        else:
            blob = s.encode("utf-16-le")
        offs.append((pos, blob, comp))
        text += blob
        pos += len(blob)

    worddoc = bytearray(_fib())
    struct.pack_into("<H", worddoc, 0x000A,
                     0x0200 if table_stream == "1table" else 0)
    if ccp is not None:
        # FibRgLw97 ccpText, ccpFtn, ccpHdd, reserved3, ccpAtn, ccpEdn,
        # ccpTxbx, ccpHdrTxbx, starting at 0x4C.
        struct.pack_into("<8i", worddoc, 0x4C, ccp[0], ccp[1], ccp[2], 0,
                         ccp[3], ccp[4], ccp[5], ccp[6])
    worddoc += text
    worddoc += b"\x00" * 4096             # pad so the stream is >= 4096

    # Clx: Prcs then Pcdt. CPCs count characters; each piece spans
    # (cp[i+1]-cp[i]) characters.
    cps, pcds = [0], []
    for off, blob, comp in offs:
        nchars = len(blob) // 2 if not comp else len(blob)
        cps.append(cps[-1] + nchars)
        # PCD FcCompressed: bit 30 = fCompressed, bits 0-29 = fc. A
        # compressed piece stores twice its byte offset ([MS-DOC]
        # FcCompressed: the text starts at fc/2); an uncompressed piece
        # stores the raw offset.
        fc = off << 1 if comp else off
        if comp:
            fc |= 0x40000000
        pcds.append(struct.pack("<HI", 0, fc) + struct.pack("<H", 0))
    if nonmonotonic:
        cps[1] = cps[0]
    plcpcd = b"".join(struct.pack("<I", c) for c in cps) + b"".join(pcds)
    pcdt = struct.pack("<BI", 0x02, len(plcpcd)) + plcpcd
    if drop_pcdt:
        pcdt = b""
    clx = pcdt
    if corrupt_clx:
        clx = pcdt[:-3]                   # cut the last PCD short

    table = bytearray(clx)
    table += b"\x00" * max(0, 4096 - len(table))

    struct.pack_into("<I", worddoc, 0x01A2, 0)   # fcClx (into table stream)
    struct.pack_into("<I", worddoc, 0x01A6, len(clx))

    return build_cfb([("WordDocument", bytes(worddoc)),
                      (table_stream, bytes(table))] + list(extra_streams))

XL_SHEET_VISIBLE = 0
BOUNDSHEET_RECORD = 0x0085
SST_RECORD = 0x00FC
LABELSST_RECORD = 0x00FD
MULRK_RECORD = 0x00BD
NUMBER_RECORD = 0x0203
RK_RECORD = 0x027E
EOF_RECORD = 0x000A
BOF_RECORD = 0x0809


def _xlstr(s):
    """An XLUnicodeString without Rich/Ext: cch u16, flags u8, chars."""
    raw = s.encode("utf-16-le") if any(ord(ch) > 255 for ch in s) \
        else s.encode("latin-1")
    high = any(ord(ch) > 255 for ch in s)
    return struct.pack("<HB", len(s), 0x01 if high else 0x00) + raw


def _short_xlstr(s):
    """ShortXLUnicodeString (BOUNDSHEET stName): cch u8, flags u8, chars."""
    raw = s.encode("utf-16-le") if any(ord(ch) > 255 for ch in s) \
        else s.encode("latin-1")
    high = any(ord(ch) > 255 for ch in s)
    return struct.pack("<BB", len(s), 0x01 if high else 0x00) + raw


class Styled(str):
    """A shared string carrying formatting runs and/or phonetic data, as
    Excel writes for a cell with mixed formatting or East Asian text.
    The reader must skip both to stay in step with the strings after it."""

    def __new__(cls, text, runs=0, ext=b""):
        obj = super().__new__(cls, text)
        obj.runs = runs
        obj.ext = ext
        return obj


def _record(rid, body):
    return struct.pack("<HH", rid, len(body)) + body


def build_xls(sheets):
    """sheets: list of (name, cells) where cells is a list of tuples:
    ("s", row, col, str) | ("n", row, col, float) | ("rk", row, col, rk).
    Returns .xls bytes: one Workbook stream with a globals substream
    (BOF, SST, one BOUNDSHEET per sheet) followed by one substream per
    sheet (BOF, cell records, EOF)."""
    bof8 = struct.pack("<HHHHH", 0x0600, 0x0005, 0, 0, 0) + struct.pack("<HHH", 0, 0, 0)
    strings, isst = {}, {}
    for _name, cells in sheets:
        for c in cells:
            if c[0] == "s" and c[3] not in isst:
                isst[c[3]] = len(strings)
                strings[c[3]] = True
    sst_body = struct.pack("<II", len(strings), len(strings))
    for s in strings:
        raw = s.encode("utf-16-le") if any(ord(ch) > 255 for ch in s) \
            else s.encode("latin-1")
        high = any(ord(ch) > 255 for ch in s)
        runs = getattr(s, "runs", 0)
        ext = getattr(s, "ext", b"")
        flags = (0x01 if high else 0x00) | (0x08 if runs else 0) \
            | (0x04 if ext else 0)
        # [MS-XLS] 2.5.293: cch, flags, [cRun], [cbExtRst], characters,
        # then rgRun (4 bytes per run) and ExtRst AFTER the characters.
        sst_body += struct.pack("<HB", len(s), flags)
        if runs:
            sst_body += struct.pack("<H", runs)
        if ext:
            sst_body += struct.pack("<I", len(ext))
        sst_body += raw + b"\x01\x00\x02\x00" * runs + ext
    # one BOUNDSHEET placeholder per sheet; lbPlyPos patched after sizes settle
    bounds = b""
    for name, _cells in sheets:
        bounds += _record(BOUNDSHEET_RECORD,
                          struct.pack("<IBB", 0, XL_SHEET_VISIBLE, 0)
                          + _short_xlstr(name))
    globals_sub = _record(BOF_RECORD, bof8) + _record(SST_RECORD, sst_body) + bounds
    # Substreams follow. Sizes first (BOUNDSHEET needs absolute offsets),
    # so compute each sheet's bytes, then place.
    body_parts = []
    offsets = []
    pos = len(globals_sub) + 4  # after the globals EOF record
    for name, cells in sheets:
        offsets.append(pos)
        sub = _record(BOF_RECORD, struct.pack("<HHHHH", 0x0600, 0x0010, 0, 0, 0)
                      + struct.pack("<HHH", 0, 0, 0))
        for c in cells:
            kind, row, col = c[0], c[1], c[2]
            if kind == "s":
                sub += _record(LABELSST_RECORD,
                               struct.pack("<HHHI", row, col, 0, isst[c[3]]))
            elif kind == "n":
                sub += _record(NUMBER_RECORD,
                               struct.pack("<HHH", row, col, 0)
                               + struct.pack("<d", c[3]))
            elif kind == "rk":
                sub += _record(RK_RECORD, struct.pack("<HHHI", row, col, 0, c[3]))
            elif kind == "mulrk":
                _k, row, col_first, rks = c[1], c[1], c[2], c[3]
                body = struct.pack("<HH", row, col_first)
                for rk in rks:
                    body += struct.pack("<HI", 0, rk)
                body += struct.pack("<H", col_first + len(rks) - 1)
                sub += _record(MULRK_RECORD, body)
        sub += _record(EOF_RECORD, b"")
        body_parts.append(sub)
        pos += len(sub)
    workbook = bytearray(globals_sub + _record(EOF_RECORD, b"") + b"".join(body_parts))
    # Patch lbPlyPos in each BOUNDSHEET (fixed 4+2+1 header before the name).
    for i, off in enumerate(offsets):
        base = len(_record(BOF_RECORD, bof8)) + len(_record(SST_RECORD, sst_body))
        for j in range(i):
            base += len(_record(BOUNDSHEET_RECORD,
                                struct.pack("<IBB", 0, XL_SHEET_VISIBLE, 0)
                                + _short_xlstr(sheets[j][0])))
        struct.pack_into("<I", workbook, base + 4, off)
    if len(workbook) < 4096:
        workbook += b"\x00" * (4096 - len(workbook))
    return build_cfb([("Workbook", bytes(workbook))])


# --- PowerPoint (.ppt) -------------------------------------------------

PPT_SLIDE = 0x03EE                  # Slide container (1006)
PPT_TEXT_HEADER = 0x0F9F            # TextHeaderAtom (3999)
PPT_TEXT_CHARS = 0x0FA0             # TextCharsAtom (4000), UTF-16LE
PPT_TEXT_BYTES = 0x0FA8             # TextBytesAtom (4008), latin-1
PPT_USER_EDIT = 0x0FF5              # UserEditAtom (4085)
PPT_CURRENT_USER = 0x0FF6           # CurrentUserAtom (4086)
PPT_PERSIST_PTR_INCREMENTAL = 0x1772  # PersistPtrIncrementalBlock (6002)


def _ppt_atom(rid, body, ver_inst=0x0000):
    return struct.pack("<HHI", ver_inst, rid, len(body)) + body


def _ppt_container(rid, children):
    body = b"".join(children)
    return _ppt_atom(rid, body, ver_inst=0x000F)


def _ppt_slide_kids(texts, nested=False):
    """A Slide container's children: SlideAtom, then one PPDrawing
    holding an Escher client-textbox with a TextHeaderAtom + text atom
    pair per run — the nesting real slides use."""
    slideatom = _ppt_atom(0x03E7, struct.pack("<12sIIHH", b"\x00" * 12,
                                              0x80000000, 0, 7, 0))
    runs = b""
    for t in texts:
        runs += _ppt_atom(PPT_TEXT_HEADER, struct.pack("<I", 0))
        if any(ord(ch) > 255 for ch in t):
            runs += _ppt_atom(PPT_TEXT_CHARS, t.encode("utf-16-le"))
        else:
            runs += _ppt_atom(PPT_TEXT_BYTES, t.encode("latin-1"))
    if nested:
        return [slideatom, _ppt_container(0x040C, [_ppt_shapes(texts)])]
    return [slideatom,
            _ppt_container(0x040C, [_ppt_atom(0xF00D, runs)])]


def _ppt_shapes(texts):
    """An Escher drawing the way PowerPoint writes it: a DgContainer
    holding an SpgrContainer of shapes, the first a background shape with
    no text and then one text shape (SpContainer with a client textbox)
    per string, and a trailing shape outside the group. Most of the text
    sits after the first nested container."""
    def textbox(t):
        run = _ppt_atom(PPT_TEXT_HEADER, struct.pack("<I", 0))
        if any(ord(ch) > 255 for ch in t):
            run += _ppt_atom(PPT_TEXT_CHARS, t.encode("utf-16-le"))
        else:
            run += _ppt_atom(PPT_TEXT_BYTES, t.encode("latin-1"))
        return _ppt_atom(0xF00D, run)

    def shape(*kids):
        return _ppt_container(0xF004, [_ppt_atom(0xF00A, bytes(8))]
                              + list(kids))

    group = [shape()] + [shape(_ppt_atom(0xF00B, bytes(4)), textbox(t))
                         for t in texts]
    return _ppt_container(0xF002, [_ppt_atom(0xF008, bytes(8)),
                                   _ppt_container(0xF003, group),
                                   shape()])


def build_ppt(slides, nested=False):
    """slides: list of lists of text strings (one list per slide).
    Returns .ppt bytes: a PowerPoint Document stream holding a Document
    container (persist id 1), a stale copy of slide 1, one Slide
    container per slide, and two UserEditAtoms. Edit 0's persist
    directory maps persist id 2 to the stale copy; edit 1's directory
    re-maps id 2 to the fresh slide and adds the rest, so a reader must
    honour newest-wins to read the right text. The Current User stream
    points at edit 1."""
    doc = bytearray()
    stale_off = len(doc)
    doc += _ppt_container(PPT_SLIDE, _ppt_slide_kids(["Outdated stale text."]))
    doc_off = len(doc)
    doc += _ppt_container(0x03E8, [_ppt_atom(0x03E9, b"\x00" * 28)])
    fresh = []
    for texts in slides:
        off = len(doc)
        doc += _ppt_container(PPT_SLIDE, _ppt_slide_kids(texts, nested))
        fresh.append(off)
    dir0 = struct.pack("<I", (2 << 20) | 1) + struct.pack("<II", doc_off, stale_off)
    dir1 = struct.pack("<I", ((len(fresh) + 1) << 20) | 1) \
        + struct.pack("<I", doc_off) + b"".join(struct.pack("<I", o) for o in fresh)
    dir0_off = len(doc)
    doc += _ppt_atom(PPT_PERSIST_PTR_INCREMENTAL, dir0)
    dir1_off = len(doc)
    doc += _ppt_atom(PPT_PERSIST_PTR_INCREMENTAL, dir1)
    ue0_off = len(doc)
    doc += _ppt_atom(PPT_USER_EDIT,
                     struct.pack("<IIIIIIHH", 1, 0x03000000, 0,
                                 dir0_off, 1, 2, 1, 0))
    ue1_off = len(doc)
    doc += _ppt_atom(PPT_USER_EDIT,
                     struct.pack("<IIIIIIHH", 2, 0x03000000, ue0_off,
                                 dir1_off, 1, len(fresh) + 1, 1, 0))
    if len(doc) < 4096:
        doc += b"\x00" * (4096 - len(doc))
    # CurrentUserAtom ([MS-PPT] / POI CurrentUserAtom.writeOut): the
    # atom length field is 20 + ascii username + release version; the
    # UTF-16 username copy trails beyond it. offsetToCurrentEdit sits at
    # stream offset 16.
    cu = struct.pack("<HHI", 0, PPT_CURRENT_USER, 28)
    cu += struct.pack("<I", 20)                      # size of details
    cu += b"\x5f\xc0\x91\xe3"                        # non-encrypted token
    cu += struct.pack("<I", ue1_off)                 # offsetToCurrentEdit
    cu += struct.pack("<HHBBH", 4, 0x03F4, 3, 0, 0)  # cch, version, major, minor
    cu += b"orca"                                    # ascii username
    cu += struct.pack("<I", 8)                       # releaseVersion
    cu += "orca".encode("utf-16-le")                 # unicode username
    cu += b"\x00" * max(0, 4096 - len(cu))
    return build_cfb([("PowerPoint Document", bytes(doc)),
                      ("Current User", bytes(cu))])