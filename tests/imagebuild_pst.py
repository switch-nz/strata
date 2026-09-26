"""Build synthetic PST files (Unicode and ANSI) for testing engine.pst
against, following [MS-PST]: Outlook Personal Folders (.pst) File Format.
Every layout below is written from the spec's own field tables (the
"Unicode:" / "ANSI:" pairs in 2.2.2 and 2.3), not from engine.pst, so a
misreading in the parser cannot be repeated here. Only what engine.pst reads
is meaningful: page and block CRCs and signatures are left zero, and the
allocation maps are not written.

What build_store() produces, for either format:

    0x0000  header (1024 bytes): magic, version, ROOT with the NBT and BBT
            references, sentinel and crypt method. The offsets differ
            between the formats (ANSI ROOT at 164, Unicode at 180).
    ...     blocks, each padded so data + trailer is a multiple of 64 bytes
            (BLOCKTRAILER is 16 bytes Unicode, 12 ANSI, with bid and CRC in
            opposite order).
    ...     512-byte BTPAGEs for the NBT and BBT (one leaf each, or a level-1
            root over two leaves when tree_levels=2).

Content: one message with attachments, in a folder hierarchy of a root folder
and an Inbox, each folder with a property context (PC) and the root with a
hierarchy table and the Inbox with a contents table (TC). Property values of
up to 3000 bytes live in the heap-on-node; larger ones go to a subnode whose
data is a single block, or an XBLOCK / XXBLOCK data tree.
"""

import struct
from collections import namedtuple

from engine import pst as _pst          # cipher tables only, see _encode()

MAGIC = b"!BDN"
MAGIC_CLIENT = b"SM"
VER_ANSI = 14
VER_UNICODE = 23

CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC = 0, 1, 2

HN_SIG = 0xEC
CLIENT_PC = 0xBC
CLIENT_TC = 0x7C
BTH_SIG = 0xB5

PTYPE_BBT = 0x80
PTYPE_NBT = 0x81

NID_TYPE_NORMAL_FOLDER = 0x02
NID_TYPE_NORMAL_MESSAGE = 0x04
NID_TYPE_ATTACHMENT = 0x05
NID_TYPE_HIERARCHY_TABLE = 0x0D
NID_TYPE_CONTENTS_TABLE = 0x0E
NID_TYPE_LTP = 0x1F

PT_INT32 = 0x0003
PT_STRING8 = 0x001E
PT_STRING = 0x001F
PT_BINARY = 0x0102

PID_SUBJECT = 0x0037
PID_MESSAGE_FLAGS = 0x0E07
PID_DISPLAY_NAME = 0x3001
PID_ATTACH_DATA_BIN = 0x3701
PID_ATTACH_LONG_FILENAME = 0x3707
PID_ATTACH_MIME_TAG = 0x370E
PID_ATTACH_SIZE = 0x0E20
PID_MESSAGE_CODEPAGE = 0x3FFD
PID_LTP_ROW_ID = 0x67F2
PID_LTP_ROW_VER = 0x67F3

MSG_FLAG_HAS_ATTACH = 0x10

HEADER_SIZE = 1024
PAGE_SIZE = 512
INLINE_MAX = 3000            # larger property values go to a subnode
CHUNK = 8000                 # data per data block when a value is split

# A deterministic, recognisable payload -- not a real PDF, just something
# attachment_bytes() should return byte-for-byte.
ATTACHMENT_BYTES = bytes((i * 13 + 7) & 0xFF for i in range(300))
ATTACHMENT_BIG = bytes((i * 7 + 3) & 0xFF for i in range(20000))
ATTACHMENT_NAME = "invoice.pdf"
ATTACHMENT_MIME = "application/pdf"

# An attachment nid guaranteed absent from the subnode tree, for the
# "wrong id" case -- well past any index build_store() itself hands out.
MISSING_ATTACHMENT_NID = (99 << 5) | NID_TYPE_ATTACHMENT

MESSAGE_NID = (1 << 5) | NID_TYPE_NORMAL_MESSAGE
MESSAGE_SUBJECT = "Q3 invoice"
ROOT_FOLDER_NID = 0x122
INBOX_NID = (0x401 << 5) | NID_TYPE_NORMAL_FOLDER
ROOT_NAME = "Top of Personal Folders"
INBOX_NAME = "Inbox"

Store = namedtuple("Store", "raw node attachment_nids message_nid")


# --- heap-on-node ----------------------------------------------------------

class HeapBuilder:
    """One heap-on-node (HN) block: the 12-byte HNHDR followed by sequential
    allocations, each retrievable by a heap ID (HID), then the page map."""

    def __init__(self, client_sig):
        self.client_sig = client_sig
        self.allocs = []

    def alloc(self, data):
        """Adds a heap allocation and returns its HID (block 0)."""
        self.allocs.append(bytes(data))
        return len(self.allocs) << 5

    def build(self, user_root):
        offsets = [12]
        for a in self.allocs:
            offsets.append(offsets[-1] + len(a))
        body = b"".join(self.allocs)
        page_map = struct.pack("<HH", len(self.allocs), 0)
        page_map += b"".join(struct.pack("<H", o) for o in offsets)
        # ibHnpm, bSig, bClientSig, hidUserRoot, rgbFillLevel
        header = struct.pack("<HBBI", 12 + len(body), HN_SIG,
                             self.client_sig, user_root) + bytes(4)
        return header + body + page_map


def _bth(hn, records, cb_key, cb_ent):
    """A one-level BTH in `hn`; returns the HID of its header."""
    root = hn.alloc(b"".join(records)) if records else 0
    return hn.alloc(struct.pack("<BBBBI", BTH_SIG, cb_key, cb_ent, 0, root))


class _Values:
    """Turns property values into BTH record bytes, spilling big ones to a
    subnode through the `spill` callback (returns the local NID)."""

    def __init__(self, ansi):
        self.ansi = ansi

    def text(self, s, cp=1252):
        if self.ansi:
            return PT_STRING8, s.encode("cp%d" % cp)
        return PT_STRING, s.encode("utf-16-le")


def _property_context(properties, spill):
    """properties: list of (pid, ptype, value); an int for PT_INT32, bytes
    otherwise. Returns the HN block bytes (client_sig CLIENT_PC)."""
    hn = HeapBuilder(CLIENT_PC)
    records = []
    for pid, ptype, value in sorted(properties, key=lambda p: p[0]):
        if ptype == PT_INT32:
            hnid = value & 0xFFFFFFFF
        elif len(value) > INLINE_MAX:
            hnid = spill(value)
        else:
            hnid = hn.alloc(value)
        records.append(struct.pack("<HHI", pid, ptype, hnid))
    return hn.build(_bth(hn, records, 2, 6))


def _table_context(row_ids, ansi):
    """A TC with the two mandatory columns (row id, row version) and one
    row per id. TCROWID records are 8 bytes Unicode, 6 bytes ANSI."""
    hn = HeapBuilder(CLIENT_TC)
    row_index = [struct.pack("<I" + ("H" if ansi else "I"), rid, i)
                 for i, rid in enumerate(row_ids)]
    hid_index = _bth(hn, row_index, 4, 2 if ansi else 4)
    rows = b"".join(struct.pack("<II", rid, 0) + b"\xc0" for rid in row_ids)
    hid_rows = hn.alloc(rows) if rows else 0
    cols = [(PID_LTP_ROW_ID << 16 | PT_INT32, 0, 4, 0),
            (PID_LTP_ROW_VER << 16 | PT_INT32, 4, 4, 1)]
    info = struct.pack("<BB4HIII", CLIENT_TC, len(cols), 8, 8, 8, 9,
                       hid_index, hid_rows, 0)
    info += b"".join(struct.pack("<IHBB", *c) for c in cols)
    return hn.build(hn.alloc(info))


# --- ciphers (written from [MS-PST] 5.1 and 5.2) ---------------------------

def _encode(data, crypt, bid):
    """Encode a data block the way the spec's CryptPermute / CryptCyclic
    do. The three 256-byte tables are format constants, verified against
    the spec when they were added, and shared with the parser."""
    r, s, i = _pst._MPBB_R, _pst._MPBB_S, _pst._MPBB_INV
    if crypt == CRYPT_PERMUTE:
        return bytes(r[b] for b in data)
    if crypt != CRYPT_CYCLIC:
        return data
    out = bytearray()
    w = ((bid & 0xFFFFFFFF) ^ ((bid & 0xFFFFFFFF) >> 16)) & 0xFFFF
    for b in data:
        b = (b + (w & 0xFF)) & 0xFF
        b = r[b]
        b = (b + (w >> 8)) & 0xFF
        b = s[b]
        b = (b - (w >> 8)) & 0xFF
        b = i[b]
        b = (b - (w & 0xFF)) & 0xFF
        out.append(b)
        w = (w + 1) & 0xFFFF
    return bytes(out)


# --- file layout -----------------------------------------------------------

class Layout:
    """Accumulates blocks and pages after the header. BIDs are 32-bit in
    ANSI and 64-bit in Unicode; so are IBs."""

    def __init__(self, ansi, crypt, first_index=1):
        self.ansi, self.crypt = ansi, crypt
        self.w = 4 if ansi else 8
        self.chunks = [bytes(HEADER_SIZE)]
        self.length = HEADER_SIZE
        self.bbt = []                       # (bid, ib, cb)
        self._index = first_index
        self._page_bid = 0x4000

    def _bid(self, internal):
        bid = (self._index << 2) | (2 if internal else 0)
        self._index += 1
        return bid

    def _uint(self, v):
        return struct.pack("<I" if self.ansi else "<Q", v)

    def add_block(self, data, internal=False):
        """Adds a block and returns its BID. Data blocks are encoded when
        the file's crypt method says so; internal blocks (XBLOCK, XXBLOCK,
        SLBLOCK, SIBLOCK) never are."""
        bid = self._bid(internal)
        stored = data if internal else _encode(bytes(data), self.crypt, bid)
        trailer_len = 12 if self.ansi else 16
        total = -(-(len(stored) + trailer_len) // 64) * 64
        pad = total - trailer_len - len(stored)
        if self.ansi:                       # cb, wSig, bid, dwCRC
            trailer = struct.pack("<HHII", len(data), 0, bid, 0)
        else:                               # cb, wSig, dwCRC, bid
            trailer = struct.pack("<HHIQ", len(data), 0, 0, bid)
        ib = self.length
        self.chunks.append(stored + bytes(pad) + trailer)
        self.length += total
        self.bbt.append((bid, ib, len(data)))
        return bid

    def add_page(self, entries, cb_ent, ptype, level=0):
        """A 512-byte BTPAGE; returns (ib, page bid)."""
        body = 496 if self.ansi else 488
        page = bytearray(PAGE_SIZE)
        for i, e in enumerate(entries):
            assert len(e) <= cb_ent
            page[i * cb_ent:i * cb_ent + len(e)] = e
        page[body:body + 4] = bytes((len(entries), body // cb_ent, cb_ent,
                                     level))
        t = body + (4 if self.ansi else 8)  # PAGETRAILER
        bid = self._page_bid
        self._page_bid += 4
        page[t:t + 4] = bytes((ptype, ptype, 0, 0))
        if self.ansi:                       # bid, dwCRC
            page[t + 4:t + 8] = struct.pack("<I", bid)
        else:                               # dwCRC, bid
            page[t + 8:t + 16] = struct.pack("<Q", bid)
        ib = self.length
        self.chunks.append(bytes(page))
        self.length += PAGE_SIZE
        return ib, bid

    def btree(self, entries, key_of, ptype, levels):
        """The root BREF (bid, ib) of a BTree over leaf `entries` (bytes),
        one leaf page, or two leaves under a level-1 root."""
        cb = 12 if self.ansi else 24
        cb_leaf = len(entries[0]) if entries else cb
        if levels == 1 or len(entries) < 2:
            ib, bid = self.add_page(entries, cb_leaf, ptype)
            return bid, ib
        half = len(entries) // 2
        refs = []
        for part in (entries[:half], entries[half:]):
            ib, bid = self.add_page(part, cb_leaf, ptype)
            # BTENTRY: btkey, then BREF (bid, ib)
            refs.append(self._uint(key_of(part[0])) + self._uint(bid)
                        + self._uint(ib))
        ib, bid = self.add_page(refs, 3 * self.w, ptype, level=1)
        return bid, ib

    def data_tree(self, data, xx=False):
        """The BID of `data` stored as one block, or as an XBLOCK (or an
        XXBLOCK over two XBLOCKs) of data blocks."""
        parts = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
        if len(parts) == 1:
            return self.add_block(parts[0])
        bids = [self.add_block(p) for p in parts]
        if not xx:
            return self._xblock(1, bids, len(data))
        half = len(bids) // 2
        xs = [self._xblock(1, bids[:half], half * CHUNK),
              self._xblock(1, bids[half:], len(data) - half * CHUNK)]
        return self._xblock(2, xs, len(data))

    def _xblock(self, level, bids, total):
        raw = struct.pack("<BBHI", 0x01, level, len(bids), total)
        raw += b"".join(self._uint(b) for b in bids)
        return self.add_block(raw, internal=True)

    def subnode_tree(self, entries, split=False):
        """BID of a subnode BTree over (nid, bidData, bidSub) entries: one
        SLBLOCK, or (split) two under an SIBLOCK."""
        def slblock(part):
            head = struct.pack("<BBH", 0x02, 0, len(part))
            if not self.ansi:
                head += bytes(4)            # dwPadding
            body = b"".join(b"".join(self._uint(v) for v in e) for e in part)
            return self.add_block(head + body, internal=True)
        if not split or len(entries) < 2:
            return slblock(entries)
        half = len(entries) // 2
        parts = (entries[:half], entries[half:])
        sl = [(p[0][0], slblock(p)) for p in parts]
        head = struct.pack("<BBH", 0x02, 1, len(sl))
        if not self.ansi:
            head += bytes(4)
        body = b"".join(self._uint(n) + self._uint(b) for n, b in sl)
        return self.add_block(head + body, internal=True)

    def nbt_entry(self, nid, data_bid, sub_bid, parent=0):
        if self.ansi:
            return struct.pack("<IIII", nid, data_bid, sub_bid, parent)
        return struct.pack("<QQQII", nid, data_bid, sub_bid, parent, 0)

    def bbt_entry(self, bid, ib, cb):
        if self.ansi:
            return struct.pack("<IIHH", bid, ib, cb, 2)
        return struct.pack("<QQHHI", bid, ib, cb, 2, 0)

    def finish(self, version, nbt, bbt, crypt):
        raw = bytearray(b"".join(self.chunks))
        struct.pack_into("<4s", raw, 0, MAGIC)
        struct.pack_into("<2s", raw, 8, MAGIC_CLIENT)
        struct.pack_into("<HH", raw, 10, version, 19)
        raw[14] = raw[15] = 1               # bPlatformCreate / Access
        if self.ansi:                       # ROOT at 164 (40 bytes)
            struct.pack_into("<I", raw, 168, len(raw))         # ibFileEof
            struct.pack_into("<4I", raw, 184, nbt[0], nbt[1], bbt[0], bbt[1])
            raw[200] = 2                                       # fAMapValid
            raw[204:460] = b"\xff" * 256                       # rgbFM, rgbFP
            raw[460], raw[461] = 0x80, crypt
        else:                               # ROOT at 180 (72 bytes)
            struct.pack_into("<Q", raw, 184, len(raw))
            struct.pack_into("<4Q", raw, 216, nbt[0], nbt[1], bbt[0], bbt[1])
            raw[248] = 2
            raw[256:512] = b"\xff" * 256
            raw[512], raw[513] = 0x80, crypt
        return bytes(raw)


# --- the store -------------------------------------------------------------

def build_store(ansi=False, crypt=CRYPT_NONE, attachment_count=1,
                attachment=ATTACHMENT_BYTES, tree_levels=1, xx=False,
                sub_split=False, folders=True, subject=MESSAGE_SUBJECT,
                codepage=None, version=None, first_index=1,
                binary_folder_name=False):
    """A store holding one message. Returns a Store: the raw bytes, a
    stand-in `node` dict for Pst.attachments(), the attachment nids, and
    the message nid.

    tree_levels=2   put the NBT and BBT under a level-1 root page
    xx              split a big attachment under an XXBLOCK
    sub_split       put the message's subnodes under an SIBLOCK
    folders         link the message into Inbox under a root folder;
                    otherwise it is an orphan
    codepage        declared in PidTagMessageCodepage (ANSI text in it)
    binary_folder_name  store the folder names as PtypBinary, a wrong type
    first_index     where BID numbering starts; a large value gives BIDs
                    with the high word set, which the cyclic cipher keys on"""
    lay = Layout(ansi, crypt, first_index)
    text = _Values(ansi).text
    cp = codepage or 1252

    att_nids, sub_entries = [], []
    for i in range(attachment_count):
        nid = ((i + 1) << 5) | NID_TYPE_ATTACHMENT
        own = []                            # the attachment's own subnodes

        def spill(value, own=own):
            local = ((len(own) + 1) << 5) | NID_TYPE_LTP
            own.append((local, lay.data_tree(value, xx), 0))
            return local

        pc = _property_context([
            (PID_ATTACH_LONG_FILENAME,) + text(ATTACHMENT_NAME),
            (PID_ATTACH_MIME_TAG,) + text(ATTACHMENT_MIME),
            (PID_ATTACH_SIZE, PT_INT32, len(attachment)),
            (PID_ATTACH_DATA_BIN, PT_BINARY, attachment),
        ], spill)
        data_bid = lay.add_block(pc)
        sub_bid = lay.subnode_tree(own) if own else 0
        att_nids.append(nid)
        sub_entries.append((nid, data_bid, sub_bid))
    msg_sub = lay.subnode_tree(sub_entries, sub_split)

    props = [(PID_SUBJECT,) + text(subject, cp),
             (PID_MESSAGE_FLAGS, PT_INT32, MSG_FLAG_HAS_ATTACH)]
    if ansi and codepage:
        props.append((PID_MESSAGE_CODEPAGE, PT_INT32, codepage))
    msg_data = lay.add_block(_property_context(props, lambda v: 0))

    nodes = [(MESSAGE_NID, msg_data, msg_sub, INBOX_NID if folders else 0)]
    if folders:
        def folder(nid, name, table_rows, table_type):
            named = ((PID_DISPLAY_NAME, PT_BINARY, name.encode("ascii"))
                     if binary_folder_name
                     else (PID_DISPLAY_NAME,) + text(name))
            pc_bid = lay.add_block(_property_context([named], lambda v: 0))
            tc_bid = lay.add_block(_table_context(table_rows, ansi))
            return [(nid, pc_bid, 0, 0),
                    ((nid & ~0x1F) | table_type, tc_bid, 0, 0)]
        nodes += folder(ROOT_FOLDER_NID, ROOT_NAME, [INBOX_NID],
                        NID_TYPE_HIERARCHY_TABLE)
        nodes += folder(INBOX_NID, INBOX_NAME, [MESSAGE_NID],
                        NID_TYPE_CONTENTS_TABLE)
    nodes.sort(key=lambda n: n[0])

    bbt_entries = [lay.bbt_entry(*e) for e in lay.bbt]
    nbt_entries = [lay.nbt_entry(*n) for n in nodes]
    nbt = lay.btree(nbt_entries, lambda e: struct.unpack_from(
        "<I" if ansi else "<Q", e, 0)[0], PTYPE_NBT, tree_levels)
    bbt = lay.btree(bbt_entries, lambda e: struct.unpack_from(
        "<I" if ansi else "<Q", e, 0)[0], PTYPE_BBT, tree_levels)
    raw = lay.finish(version or (VER_ANSI if ansi else VER_UNICODE),
                     nbt, bbt, crypt)
    return Store(raw, {"data": 0, "sub": msg_sub}, att_nids, MESSAGE_NID)


def build_pst(attachment_count=1):
    """The original single-message Unicode fixture: (bytes, node,
    attachment_nids), the message an orphan in no folder."""
    s = build_store(ansi=False, attachment_count=attachment_count,
                    folders=False)
    return s.raw, s.node, s.attachment_nids
