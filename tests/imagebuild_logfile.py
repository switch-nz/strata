"""Build synthetic NTFS $LogFile images.

A $LogFile is two restart pages ("RSTR") then log pages ("RCRD"), 4096 bytes
each, every one protected by an update sequence array. The layout follows
ntfs-3g's logfile.h. Log records are packed one after another through the
pages' data areas, and one that does not fit runs on into the next page, as
Windows writes them. The LSN of each record encodes its file offset, so it is
computed from where the record lands.

The repository has no real $LogFile to check this against; the builder is
independent of engine/logfile.py only in that it is written from the format
description, not from the parser."""

import struct

import imagebuild_ntfs as ntfs

PAGE = 4096
SECTOR = 512
DATA_OFF = 0x40
SEQ_BITS = 40
HEADER = 48


def filetime(dt):
    return ntfs.filetime(dt)


def lsn_for(seq, offset):
    return (seq << (64 - SEQ_BITS)) | (offset // 8)


def with_usa(page, usn=b"\x5a\x5a", usa_off=0x28):
    """Protect `page`: the last two bytes of each sector go into the array
    and are replaced by the sequence number."""
    page = bytearray(page)
    count = len(page) // SECTOR + 1
    page[usa_off:usa_off + 2] = usn
    for i in range(1, count):
        end = i * SECTOR
        page[usa_off + 2 * i:usa_off + 2 * i + 2] = page[end - 2:end]
        page[end - 2:end] = usn
    struct.pack_into("<HH", page, 4, usa_off, count)
    return bytes(page)


def restart_page(current_lsn, clean=True, minor=1, major=1, name="NTFS",
                 chkdsk_lsn=0, page_size=PAGE, log_size=None,
                 data_off=DATA_OFF, open_count=1, tear=False):
    page = bytearray(PAGE)
    page[0:4] = b"RSTR"
    struct.pack_into("<QIIHhh", page, 8, chkdsk_lsn, page_size, page_size,
                     0x30, minor, major)
    area = 0x30
    # restart area: 0x30 bytes, then one 0xA0-byte client record
    struct.pack_into("<QHhhHIHHqIHHI", page, area, current_lsn, 1, -1, 0,
                     0x0002 if clean else 0, SEQ_BITS, 0x30 + 0xA0, 0x30,
                     log_size or PAGE * 8, 0x58, HEADER, data_off, open_count)
    client = area + 0x30
    struct.pack_into("<QQhhH", page, client, current_lsn, current_lsn, -1, -1,
                     0)
    raw = name.encode("utf-16-le")
    struct.pack_into("<I", page, client + 28, len(raw))
    page[client + 32:client + 32 + len(raw)] = raw
    out = with_usa(page, usa_off=0x1E)
    if tear:
        out = bytearray(out)
        out[SECTOR - 2:SECTOR] = b"\x00\x00"
        out = bytes(out)
    return out


def file_name(name, parent=5, times=None, namespace=1, size=0):
    t = filetime(times or ntfs.FN_TIMES["created"])
    raw = name.encode("utf-16-le")
    return (struct.pack("<QQQQQ", parent | (1 << 48), t, t, t, t)
            + struct.pack("<QQII", size, size, 0x20, 0)
            + bytes([len(name), namespace]) + raw)


def index_entry(ref, name, **kw):
    key = file_name(name, **kw)
    length = (16 + len(key) + 7) & ~7
    return (struct.pack("<QHHH", ref | (3 << 48), length, len(key), 0)
            + b"\x00\x00" + key).ljust(length, b"\x00")


def client_data(redo_op, undo_op, redo=b"", undo=b"", attr=0, lcns=(),
                rec_off=0, attr_off=0, cluster_index=0, vcn=0):
    head_len = 32 + 8 * len(lcns)
    redo_at = head_len
    undo_at = redo_at + ((len(redo) + 7) & ~7)
    head = struct.pack("<11H", redo_op, undo_op, redo_at if redo else 0,
                       len(redo), undo_at if undo else 0, len(undo), attr,
                       len(lcns), rec_off, attr_off, cluster_index)
    head += struct.pack("<H", 0) + struct.pack("<Q", vcn)
    head += b"".join(struct.pack("<Q", x) for x in lcns)
    return head + redo + bytes(undo_at - redo_at - len(redo)) + undo


def record(lsn, data, tx=0, prev=0, undo_next=0, rtype=1, flags=0,
           client=(0, 0)):
    head = struct.pack("<QQQIHHIIH", lsn, prev, undo_next, len(data),
                       client[0], client[1], rtype, tx, flags)
    return head.ljust(HEADER, b"\x00") + data


def logfile(specs, log_pages=6, seq=7, clean=True, tear_page=None,
            restarts_lsn=None, blank=True):
    """The $LogFile bytes. `specs` are dicts for client_data() plus
    optional tx, type ("standard"/"checkpoint"), raw (data bytes for a
    checkpoint) and lsn_shift (added to the LSN to break the position
    match). Records fill the pages' data areas in order, from page 2."""
    area = PAGE - DATA_OFF
    stream = bytearray()
    starts = []
    for spec in specs:
        pos = (len(stream) + 7) & ~7
        stream += bytes(pos - len(stream))
        page, within = divmod(pos, area)
        offset = (2 + page) * PAGE + DATA_OFF + within
        starts.append(offset)
        kind = spec.get("type", "standard")
        if kind == "checkpoint":
            data = spec.get("raw", bytes(48))
        else:
            data = client_data(**{k: v for k, v in spec.items() if k in (
                "redo_op", "undo_op", "redo", "undo", "attr", "lcns",
                "rec_off", "attr_off", "cluster_index", "vcn")})
        lsn = lsn_for(seq, offset) + spec.get("lsn_shift", 0)
        stream += record(lsn, data, tx=spec.get("tx", 0),
                         rtype=2 if kind == "checkpoint" else 1,
                         prev=spec.get("prev", 0))
    n_used = max(1, -(-len(stream) // area))
    if n_used > log_pages:
        raise ValueError("records do not fit in %d pages" % log_pages)
    last_lsn = lsn_for(seq, starts[-1]) if starts else lsn_for(seq, 0)
    pages = []
    for p in range(log_pages):
        body = bytes(stream[p * area:(p + 1) * area])
        if p >= n_used:
            pages.append(b"\xff" * PAGE if blank else bytes(PAGE))
            continue
        page = bytearray(PAGE)
        page[0:4] = b"RCRD"
        end = DATA_OFF + len(body)
        # A record ends on the page unless the data runs to its last byte and
        # the stream carries on into the next page.
        continues = p + 1 < n_used and len(body) == area
        struct.pack_into("<QIHH", page, 8, last_lsn, 0 if continues else 1,
                         1, p)
        struct.pack_into("<H", page, 24, PAGE if continues else end)
        struct.pack_into("<Q", page, 32, last_lsn)
        page[DATA_OFF:DATA_OFF + len(body)] = body
        out = with_usa(page)
        if tear_page == p:
            out = bytearray(out)
            out[SECTOR - 2:SECTOR] = b"\x00\x00"
            out = bytes(out)
        pages.append(out)
    lsn0 = restarts_lsn if restarts_lsn is not None else last_lsn
    return (restart_page(lsn0, clean=clean) + restart_page(lsn0, clean=clean)
            + b"".join(pages)), starts


def ntfs_with_logfile(log):
    """A synthetic NTFS volume whose $LogFile (record 2) holds `log`, in
    free clusters 101 onward."""
    img = bytearray(ntfs.build_ntfs())
    clusters = -(-len(log) // ntfs.CLUSTER)
    first = 101
    assert first + clusters < ntfs.TOTAL_CLUSTERS - 1
    img[first * ntfs.CLUSTER:first * ntfs.CLUSTER + len(log)] = log
    rec, _fn = ntfs._named_file(2, "$LogFile", 5, [ntfs.nonresident_attr(
        0x80, [(first, clusters)], len(log))])
    for base in (ntfs.MFT_LCN * ntfs.CLUSTER,
                 ntfs.MFTMIRR_LCN * ntfs.CLUSTER):
        at = base + 2 * ntfs.RECORD
        img[at:at + ntfs.RECORD] = rec
    return bytes(img)
