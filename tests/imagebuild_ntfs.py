"""Synthetic NTFS volume (and GPT disk) builders for the parser tests.

Returns ``bytes`` built in code — the repository carries no binary fixtures.
The layout is fixed and described in ``build_ntfs``'s docstring so tests can
assert exact record numbers, cluster offsets and timestamps, and so the image
can later seed a fuzzer. This module does not import the engine: it encodes
the on-disk format directly (MFT FILE records with update sequence arrays,
resident/non-resident attributes, run lists, $I30 index roots).
"""

import binascii
import datetime
import struct
import uuid

SECTOR = 512
SECTORS_PER_CLUSTER = 2
CLUSTER = SECTOR * SECTORS_PER_CLUSTER          # 1024
RECORD = 1024
TOTAL_CLUSTERS = 128
MFT_LCN = 4
MFT_RECORDS = 32
MFTMIRR_LCN = 36
BITMAP_LCN = 90
ROOT_INDX_LCN = 100
INDEX_BLOCK = CLUSTER                            # clusters-per-index 1
SERIAL = 0x0123456789ABCDEF
USN = b"\x42\x42"
VOLUME_LABEL = "STRATA"

# Record numbers of the user-visible content.
REC = {
    "hello": 16, "big": 17, "ads": 18, "deleted": 19, "docs": 20,
    "note": 21, "sparse": 22, "compressed": 23, "twonames": 24,
    "fixup": 25, "torn": 26, "extension": 27,
}

HELLO_TEXT = b"Hello, NTFS!\n"
BIG_SIZE = 3 * CLUSTER - 300                     # slack of 300 in last cluster
BIG_RUNS = ((40, 2), (60, 1))                    # fragmented, backwards jump
ADS_MAIN = b"main stream\n"
ZONE_ID = b"[ZoneTransfer]\r\nZoneId=3\r\n"
SECRET_LCN = 70
SECRET_SIZE = 100
DELETED_TEXT = b"gone but not forgotten\n"
NOTE_TEXT = b"a note inside Docs\n"
SPARSE_RUNS = ((50, 1), (None, 2), (51, 1))
SPARSE_SIZE = 4 * CLUSTER
COMPRESSED_LCN = 80
COMPRESSED_TEXT = b"abc" * 400                   # 1200 bytes
FIXUP_SIZE = 700                                 # resident, spans byte 510
SLACK_MARK = b"NTFSSLACK"

SI_TIMES = {
    "created": datetime.datetime(2021, 1, 2, 3, 4, 5),
    "modified": datetime.datetime(2022, 6, 7, 8, 9, 10),
    "mft_modified": datetime.datetime(2022, 6, 7, 8, 9, 11),
    "accessed": datetime.datetime(2023, 1, 1, 0, 0, 0),
}
# $FILE_NAME times deliberately differ from $STANDARD_INFORMATION, as they
# would after a timestamp-tampering tool rewrote only $SI.
FN_TIMES = {
    "created": datetime.datetime(2019, 5, 5, 5, 5, 5),
    "modified": datetime.datetime(2019, 5, 5, 5, 5, 6),
    "mft_modified": datetime.datetime(2019, 5, 5, 5, 5, 7),
    "accessed": datetime.datetime(2019, 5, 5, 5, 5, 8),
}


def pattern(length, seed):
    return bytes(((i * 29 + seed * 13 + (i >> 7)) & 0xFF) for i in range(length))


def fill(length, text):
    return (text * (length // len(text) + 1))[:length]


def big_content():
    return pattern(BIG_SIZE, 1)


def secret_content():
    return pattern(SECRET_SIZE, 2)


def sparse_content():
    """What reading the sparse file must yield: data, zeros, data."""
    return (pattern(CLUSTER, 3) + bytes(2 * CLUSTER) + pattern(CLUSTER, 4))


def fixup_content():
    return pattern(FIXUP_SIZE, 5)


def iso(dt):
    return dt.isoformat() + "Z"


def filetime(dt):
    delta = dt - datetime.datetime(1601, 1, 1)
    return (delta.days * 86400 + delta.seconds) * 10 ** 7 \
        + delta.microseconds * 10


def _align8(n):
    return (n + 7) & ~7


def encode_runs(runs):
    """NTFS mapping pairs. ``runs`` is (lcn or None for sparse, length)."""
    out = bytearray()
    prev = 0
    for lcn, length in runs:
        lb = (length.bit_length() + 8) // 8
        lbytes = length.to_bytes(lb, "little")
        if lcn is None:
            out.append(lb)
            out += lbytes
            continue
        delta = lcn - prev
        prev = lcn
        ob = 1
        while True:
            try:
                obytes = delta.to_bytes(ob, "little", signed=True)
                break
            except OverflowError:
                ob += 1
        out.append((ob << 4) | lb)
        out += lbytes + obytes
    out.append(0)
    return bytes(out)


def resident_attr(type_id, body, name="", attr_id=0, indexed=False):
    name_u = name.encode("utf-16-le")
    header_len = 24
    name_off = header_len
    content_off = _align8(header_len + len(name_u))
    length = _align8(content_off + len(body))
    a = bytearray(length)
    struct.pack_into("<IIBBHHH", a, 0, type_id, length, 0, len(name),
                     name_off, 0, attr_id)
    struct.pack_into("<IHBB", a, 16, len(body), content_off,
                     1 if indexed else 0, 0)
    a[name_off:name_off + len(name_u)] = name_u
    a[content_off:content_off + len(body)] = body
    return bytes(a)


def nonresident_attr(type_id, runs, real_size, name="", attr_id=0, flags=0,
                     compression_unit=0):
    name_u = name.encode("utf-16-le")
    header_len = 72 if compression_unit else 64
    name_off = header_len
    run_off = _align8(header_len + len(name_u))
    mp = encode_runs(runs)
    length = _align8(run_off + len(mp))
    clusters = sum(n for _, n in runs)
    alloc = clusters * CLUSTER
    a = bytearray(length)
    struct.pack_into("<IIBBHHH", a, 0, type_id, length, 1, len(name),
                     name_off, flags, attr_id)
    struct.pack_into("<QQHH", a, 16, 0, clusters - 1, run_off,
                     compression_unit)
    struct.pack_into("<QQQ", a, 40, alloc, real_size, real_size)
    if compression_unit:
        struct.pack_into("<Q", a, 64, sum(n for l, n in runs if l is not None)
                         * CLUSTER)
    a[name_off:name_off + len(name_u)] = name_u
    a[run_off:run_off + len(mp)] = mp
    return bytes(a)


def std_info(times=None, flags=0x20):
    t = times or SI_TIMES
    body = struct.pack("<QQQQIIII", filetime(t["created"]),
                       filetime(t["modified"]), filetime(t["mft_modified"]),
                       filetime(t["accessed"]), flags, 0, 0, 0)
    return body + bytes(72 - len(body))


def file_name_body(name, parent, size=0, times=None, namespace=3,
                   is_dir=False, parent_seq=None):
    t = times or FN_TIMES
    seq = parent if parent_seq is None else parent_seq
    ref = parent | ((seq & 0xFFFF) << 48)
    alloc = (size + CLUSTER - 1) // CLUSTER * CLUSTER
    body = struct.pack("<QQQQQQQII", ref, filetime(t["created"]),
                       filetime(t["modified"]), filetime(t["mft_modified"]),
                       filetime(t["accessed"]), alloc, size,
                       0x10000000 if is_dir else 0x20, 0)
    body += struct.pack("<BB", len(name), namespace) + name.encode("utf-16-le")
    return body


def _index_entries(entries, subnode_vcn=None):
    blob = bytearray()
    for ref, fn in entries:
        length = _align8(16 + len(fn))
        e = bytearray(length)
        struct.pack_into("<QHHI", e, 0, ref | (ref << 48), length, len(fn), 0)
        e[16:16 + len(fn)] = fn
        blob += e
    if subnode_vcn is None:
        blob += struct.pack("<QHHI", 0, 16, 0, 0x02)          # last entry
    else:
        blob += struct.pack("<QHHIQ", 0, 24, 0, 0x03, subnode_vcn)
    return bytes(blob)


def index_root(entries, subnode_vcn=None):
    """$INDEX_ROOT body for a $I30 index. With ``subnode_vcn`` None the
    ``entries`` (a sorted list of (mft_ref, file_name_body)) sit in the root
    node; otherwise the root holds only an end entry pointing at that VCN
    of $INDEX_ALLOCATION and the "large index" flag is set."""
    blob = _index_entries(entries if subnode_vcn is None else [],
                          subnode_vcn)
    header = struct.pack("<IIIB3x", 16, 16 + len(blob), 16 + len(blob),
                         0 if subnode_vcn is None else 1)
    root = struct.pack("<IIIB3x", 0x30, 1, INDEX_BLOCK, 1)
    return root + header + blob


def _apply_usa(body, usa_off):
    usa_count = len(body) // SECTOR + 1
    body[usa_off:usa_off + 2] = USN
    for i in range(1, usa_count):
        end = i * SECTOR
        body[usa_off + 2 * i:usa_off + 2 * i + 2] = body[end - 2:end]
        body[end - 2:end] = USN


def indx_block(entries, vcn=0):
    """One INDX record (INDEX_BLOCK bytes, fixups applied) holding sorted
    leaf ``entries``."""
    body = bytearray(INDEX_BLOCK)
    usa_off = 0x28
    usa_count = INDEX_BLOCK // SECTOR + 1
    first = _align8(usa_off + usa_count * 2)
    blob = _index_entries(entries)
    assert first + len(blob) <= INDEX_BLOCK, "INDX block overflows"
    body[0:4] = b"INDX"
    struct.pack_into("<HHQQ", body, 4, usa_off, usa_count, 0, vcn)
    struct.pack_into("<IIIB", body, 0x18, first - 0x18,
                     first - 0x18 + len(blob), INDEX_BLOCK - 0x18, 0)
    body[first:first + len(blob)] = blob
    _apply_usa(body, usa_off)
    return bytes(body)


def mft_record(number, attrs, in_use=True, is_dir=False, seq=None,
               tear=False, base_reference=0):
    """A FILE record: header, update sequence array (USN + one saved pair
    per 512-byte stride), attributes, 0xFFFFFFFF end marker, then fixups
    applied. ``tear`` corrupts the second stride's check value so the record
    fails fixup verification, as a torn write would."""
    strides = RECORD // SECTOR
    usa_off = 0x30
    usa_count = strides + 1
    first_attr = _align8(usa_off + usa_count * 2)
    body = bytearray(RECORD)
    body[0:4] = b"FILE"
    flags = (0x01 if in_use else 0) | (0x02 if is_dir else 0)
    pos = first_attr
    for k, a in enumerate(attrs):
        a = bytearray(a)
        struct.pack_into("<H", a, 14, k)
        body[pos:pos + len(a)] = a
        pos += len(a)
    body[pos:pos + 4] = b"\xFF\xFF\xFF\xFF"
    used = _align8(pos + 8)
    assert used <= RECORD, "record %d overflows" % number
    struct.pack_into("<HHQHHHHIIQHHI", body, 4, usa_off, usa_count, 0,
                     number if seq is None else seq, 1, first_attr, flags,
                     used, RECORD, base_reference, len(attrs), 0, number)
    _apply_usa(body, usa_off)
    if tear:
        body[2 * SECTOR - 2:2 * SECTOR] = b"\x00\x00"
    return bytes(body)


def _named_file(number, name, parent, data_attrs, size=0, in_use=True,
                is_dir=False, extra=()):
    fn = file_name_body(name, parent, size=size, is_dir=is_dir)
    attrs = [resident_attr(0x10, std_info()),
             resident_attr(0x30, fn, indexed=True)]
    attrs += list(extra) + list(data_attrs)
    return mft_record(number, attrs, in_use=in_use, is_dir=is_dir), fn


def build_ntfs():
    """An NTFS volume: 512-byte sectors, 2 sectors/cluster (1024-byte
    clusters), 128 clusters, 1024-byte FILE records.

    Boot sector at 0 (OEM "NTFS    ", MFT at LCN 4, $MFTMirr at LCN 36,
    clusters-per-record 0xF6 = 2^10 bytes, clusters-per-index 1) and a backup
    boot sector in the volume's last sector. The MFT is 32 records at
    LCN 4-35 (its own $DATA run list says so); $MFTMirr holds copies of
    records 0-3; $Bitmap's data sits at LCN 90. Every record carries a
    3-entry update sequence array (USN 0x4242) with fixups applied.

    Records 0-11 are the system files ($MFT, $MFTMirr, $LogFile, $Volume with
    $VOLUME_NAME "STRATA", $AttrDef, the root ".", $Bitmap, $Boot, $BadClus,
    $Secure, $UpCase, $Extend); the root has a $I30 $INDEX_ROOT listing its
    children in an INDX block at LCN 100 ($INDEX_ROOT flags it as a large
    index; $INDEX_ALLOCATION and $BITMAP "$I30" accompany it; the index holds
    the in-use user files only, Win32 names). Records 12-15 are unused-but-formatted. Then:

      16 hello.txt      resident $DATA "Hello, NTFS!\\n"
      17 big.bin        non-resident, runs (LCN 40 x2)(LCN 60 x1), 2772 bytes;
                        the 300 slack bytes in LCN 60 are painted NTFSSLACK
      18 ads.txt        resident "main stream\\n" + resident ADS
                        "Zone.Identifier" + non-resident ADS "secret"
                        (100 bytes at LCN 70)
      19 deleted.txt    record flags 0 (not in use), resident data
      20 Docs           directory with $INDEX_ROOT listing note.txt
      21 note.txt       resident, parent Docs
      22 sparse.bin     runs (LCN 50 x1)(sparse x2)(LCN 51 x1), 4096 bytes
      23 compressed.txt LZNT1-compressed $DATA, compression unit 16 clusters:
                        (LCN 80 x1)(sparse x15); decompresses to "abc" * 400
      24 two-name file  Win32 name "Long filename document.txt" and DOS name
                        "LONGFI~1.TXT"
      25 fixup.txt      700-byte resident $DATA straddling the stride end at
                        byte 510, so it is only correct once fixups apply
      26 torn.txt       fixup check value wrong in stride 2 (torn write)
      27 (extension)    in use, no $FILE_NAME: an overflow record of
                        hello.txt's, base_reference pointing back at it, as
                        a real file's $ATTRIBUTE_LIST would reference
      28-31             zeroed — never formatted

    Every user file's $STANDARD_INFORMATION times are ``SI_TIMES`` and its
    $FILE_NAME times ``FN_TIMES``.
    """
    img = bytearray(TOTAL_CLUSTERS * CLUSTER)

    def put_lcn(lcn, data):
        img[lcn * CLUSTER:lcn * CLUSTER + len(data)] = data

    boot = bytearray(SECTOR)
    boot[0:3] = b"\xEB\x52\x90"
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 11, SECTOR, SECTORS_PER_CLUSTER)
    boot[21] = 0xF8
    struct.pack_into("<HHI", boot, 24, 63, 255, 0)
    struct.pack_into("<I", boot, 36, 0x00800080)
    struct.pack_into("<QQQ", boot, 40, TOTAL_CLUSTERS * SECTORS_PER_CLUSTER
                     - 1, MFT_LCN, MFTMIRR_LCN)
    boot[64] = 0xF6
    boot[68] = 0x01
    struct.pack_into("<Q", boot, 72, SERIAL)
    boot[510:512] = b"\x55\xAA"
    img[0:SECTOR] = boot
    img[len(img) - SECTOR:] = boot

    records = {}
    root_children = []

    def sysfile(n, name, data_attrs=(), is_dir=False, extra=()):
        rec, fn = _named_file(n, name, 5, data_attrs, is_dir=is_dir,
                              extra=extra)
        records[n] = rec
        return fn

    mft_bytes = MFT_RECORDS * RECORD
    sysfile(0, "$MFT", [nonresident_attr(
        0x80, [(MFT_LCN, mft_bytes // CLUSTER)], mft_bytes)])
    sysfile(1, "$MFTMirr", [nonresident_attr(
        0x80, [(MFTMIRR_LCN, 4)], 4 * RECORD)])
    sysfile(2, "$LogFile", [resident_attr(0x80, b"")])
    sysfile(3, "$Volume", [resident_attr(0x80, b"")], extra=[
        resident_attr(0x60, VOLUME_LABEL.encode("utf-16-le")),
        resident_attr(0x70, struct.pack("<QBBH", 0, 3, 1, 0))])
    sysfile(4, "$AttrDef", [resident_attr(0x80, b"")])
    sysfile(6, "$Bitmap", [nonresident_attr(
        0x80, [(BITMAP_LCN, 1)], (TOTAL_CLUSTERS + 7) // 8)])
    sysfile(7, "$Boot", [nonresident_attr(0x80, [(0, 1)], CLUSTER)])
    sysfile(8, "$BadClus", [resident_attr(0x80, b"")])
    sysfile(9, "$Secure", [resident_attr(0x80, b"", name="$SDS")])
    sysfile(10, "$UpCase", [resident_attr(0x80, b"")])
    sysfile(11, "$Extend", [], is_dir=True)
    for n in range(12, 16):
        records[n] = mft_record(n, [], in_use=False)

    def user(key, name, data_attrs, size, parent=5, in_use=True,
             is_dir=False, extra=()):
        n = REC[key]
        rec, fn = _named_file(n, name, parent, data_attrs, size=size,
                              in_use=in_use, is_dir=is_dir, extra=extra)
        records[n] = rec
        if parent == 5 and in_use:
            root_children.append((n, fn))
        return fn

    user("hello", "hello.txt", [resident_attr(0x80, HELLO_TEXT)],
         len(HELLO_TEXT))

    user("big", "big.bin", [nonresident_attr(0x80, BIG_RUNS, BIG_SIZE)],
         BIG_SIZE)
    data = big_content()
    put_lcn(40, data[:2 * CLUSTER])
    put_lcn(60, data[2 * CLUSTER:]
            + fill(3 * CLUSTER - BIG_SIZE, SLACK_MARK))

    user("ads", "ads.txt", [
        resident_attr(0x80, ADS_MAIN),
        resident_attr(0x80, ZONE_ID, name="Zone.Identifier"),
        nonresident_attr(0x80, [(SECRET_LCN, 1)], SECRET_SIZE, name="secret"),
    ], len(ADS_MAIN))
    put_lcn(SECRET_LCN, secret_content())

    user("deleted", "deleted.txt", [resident_attr(0x80, DELETED_TEXT)],
         len(DELETED_TEXT), in_use=False)

    note_fn = file_name_body("note.txt", REC["docs"], size=len(NOTE_TEXT))
    user("docs", "Docs", [], 0, is_dir=True, extra=[
        resident_attr(0x90, index_root([(REC["note"], note_fn)]),
                      name="$I30")])
    user("note", "note.txt", [resident_attr(0x80, NOTE_TEXT)],
         len(NOTE_TEXT), parent=REC["docs"])

    user("sparse", "sparse.bin", [nonresident_attr(
        0x80, SPARSE_RUNS, SPARSE_SIZE, flags=0x8000)], SPARSE_SIZE)
    sc = sparse_content()
    put_lcn(50, sc[:CLUSTER])
    put_lcn(51, sc[3 * CLUSTER:])

    user("compressed", "compressed.txt", [nonresident_attr(
        0x80, [(COMPRESSED_LCN, 1), (None, 15)], len(COMPRESSED_TEXT),
        flags=0x0001, compression_unit=4)], len(COMPRESSED_TEXT))
    # One LZNT1 chunk: literals "abc", then a back-reference (offset 3,
    # length 1197). Header 0xB005 = compressed | signature 3 | size-1 = 5.
    put_lcn(COMPRESSED_LCN, bytes([0x05, 0xB0, 0x08, 0x61, 0x62, 0x63])
            + struct.pack("<H", (2 << 12) | (1197 - 3)) + b"\x00\x00")

    n = REC["twonames"]
    win32 = file_name_body("Long filename document.txt", 5, size=4,
                           namespace=1)
    dos = file_name_body("LONGFI~1.TXT", 5, size=4, namespace=2)
    records[n] = mft_record(n, [
        resident_attr(0x10, std_info()), resident_attr(0x30, dos, indexed=True),
        resident_attr(0x30, win32, indexed=True),
        resident_attr(0x80, b"two\n")])
    root_children.append((n, win32))

    user("fixup", "fixup.txt", [resident_attr(0x80, fixup_content())],
         FIXUP_SIZE)
    n = REC["torn"]
    fn = file_name_body("torn.txt", 5, size=5)
    records[n] = mft_record(n, [
        resident_attr(0x10, std_info()), resident_attr(0x30, fn, indexed=True),
        resident_attr(0x80, b"torn\n")], tear=True)
    root_children.append((n, fn))

    # An extension record: attributes overflowed out of hello.txt's own MFT
    # record into this one, the way a real $ATTRIBUTE_LIST does. It has no
    # $FILE_NAME of its own and must never appear as a tree node in its own
    # right (issue: real volumes with any such record listed thousands of
    # them under the root with a numeric placeholder name).
    records[REC["extension"]] = mft_record(
        REC["extension"], [resident_attr(0x100, b"extra attribute data")],
        base_reference=(7 << 48) | REC["hello"])

    root_children_sorted = sorted(
        root_children,
        key=lambda item: item[1][66:].decode("utf-16-le").upper())
    root_fn = file_name_body(".", 5, is_dir=True)
    records[5] = mft_record(5, [
        resident_attr(0x10, std_info()),
        resident_attr(0x30, root_fn, indexed=True),
        resident_attr(0x90, index_root([], subnode_vcn=0), name="$I30"),
        nonresident_attr(0xA0, [(ROOT_INDX_LCN, 1)], INDEX_BLOCK,
                         name="$I30"),
        resident_attr(0xB0, b"\x01\x00\x00\x00\x00\x00\x00\x00",
                      name="$I30"),
    ], is_dir=True)
    put_lcn(ROOT_INDX_LCN, indx_block(root_children_sorted))

    for n, rec in records.items():
        at = MFT_LCN * CLUSTER + n * RECORD
        img[at:at + RECORD] = rec
    for n in range(4):
        at = MFTMIRR_LCN * CLUSTER + n * RECORD
        img[at:at + RECORD] = records[n]

    used = set(range(0, MFT_LCN + MFT_RECORDS)) | set(range(MFTMIRR_LCN, 40))
    used |= {40, 41, 60, SECRET_LCN, 50, 51, COMPRESSED_LCN, BITMAP_LCN, ROOT_INDX_LCN,
             TOTAL_CLUSTERS - 1}
    bitmap = bytearray((TOTAL_CLUSTERS + 7) // 8)
    for c in used:
        bitmap[c // 8] |= 1 << (c % 8)
    put_lcn(BITMAP_LCN, bytes(bitmap))
    return bytes(img)


# --------------------------------------------------------------------------
# GPT
# --------------------------------------------------------------------------

BASIC_DATA = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
GPT_ENTRIES = 128
GPT_ENTRY_SIZE = 128
GPT_ARRAY_SECTORS = 32


def _gpt_header(this_lba, alt_lba, entry_lba, first, last, disk_guid,
                array_crc):
    h = bytearray(92)
    h[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ16sQIII", h, 8, 0x00010000, 92, 0, 0,
                     this_lba, alt_lba, first, last, disk_guid, entry_lba,
                     GPT_ENTRIES, GPT_ENTRY_SIZE, array_crc)
    struct.pack_into("<I", h, 16, binascii.crc32(bytes(h)) & 0xFFFFFFFF)
    return bytes(h) + bytes(SECTOR - 92)


def wrap_gpt(volume, start_lba=2048, name="Strata data"):
    """A GPT disk holding ``volume`` as partition 1 (Microsoft Basic Data).

    LBA 0 protective MBR (type 0xEE); LBA 1 primary header; LBA 2-33 the
    128-entry partition array; ``volume`` from ``start_lba``; the backup
    array and header occupy the last 33 LBAs. Both CRC32s are valid.
    """
    count = (len(volume) + SECTOR - 1) // SECTOR
    total = start_lba + count + 1 + GPT_ARRAY_SECTORS
    last_lba = total - 1
    disk = bytearray(total * SECTOR)

    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\x00\x02\x00", 0xEE,
                               b"\xFF\xFF\xFF", 1, min(last_lba, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xAA"
    disk[0:SECTOR] = mbr

    entry = bytearray(GPT_ENTRY_SIZE)
    entry[0:16] = uuid.UUID(BASIC_DATA).bytes_le
    entry[16:32] = uuid.UUID("5c1b2a3d-0000-4000-8000-000000000001").bytes_le
    struct.pack_into("<QQQ", entry, 32, start_lba, start_lba + count - 1, 0)
    nm = name.encode("utf-16-le")[:72]
    entry[56:56 + len(nm)] = nm
    array = bytes(entry) + bytes((GPT_ENTRIES - 1) * GPT_ENTRY_SIZE)
    crc = binascii.crc32(array) & 0xFFFFFFFF
    disk_guid = uuid.UUID("5c1b2a3d-0000-4000-8000-0000000000aa").bytes_le
    first_usable = 2 + GPT_ARRAY_SECTORS
    last_usable = last_lba - 1 - GPT_ARRAY_SECTORS

    disk[SECTOR:2 * SECTOR] = _gpt_header(1, last_lba, 2, first_usable,
                                          last_usable, disk_guid, crc)
    disk[2 * SECTOR:2 * SECTOR + len(array)] = array
    disk[start_lba * SECTOR:start_lba * SECTOR + len(volume)] = volume
    backup_array_lba = last_lba - GPT_ARRAY_SECTORS
    disk[backup_array_lba * SECTOR:backup_array_lba * SECTOR
         + len(array)] = array
    disk[last_lba * SECTOR:] = _gpt_header(last_lba, 1, backup_array_lba,
                                           first_usable, last_usable,
                                           disk_guid, crc)
    return bytes(disk)
