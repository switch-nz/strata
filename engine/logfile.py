"""The NTFS transaction log, $LogFile: what its restart areas and log records
say, reported as they are found.

$LogFile is Microsoft's crash-recovery log and is not officially documented.
The layout here follows the third-party descriptions (ntfs-3g's logfile.h and
the parsers built on it), and the operation names are those the same sources
give. Nothing is inferred: a record is shown with the numbers it holds, a name
or timestamp is shown only where the payload is a plain $FILE_NAME or index
entry that passes sanity checks, and no sequence of events is reconstructed.
The log is a ring, so what survives is whatever was written most recently
plus older records not yet overwritten; it is not a complete history.

Layout: two restart pages ("RSTR") at the start, then log pages ("RCRD") of
the same size. A log record has a 48-byte header (LSN, transaction, client)
followed by the client's data; a record can run on into the next page. Every
page carries an update sequence array that is checked and removed."""

import struct

from .text import t as _t

PAGE = 4096
SECTOR = 512
HEADER = 48
RCRD_FIRST = 2                     # pages 0 and 1 are the restart pages
MAX_CLIENT_DATA = 1 << 20
MAX_RECORDS = 200000
MAX_LCNS = 16

STANDARD, CHECKPOINT = 1, 2
_TYPES = {STANDARD: "standard", CHECKPOINT: "checkpoint"}

# Operation codes for the redo and undo halves of a record, as the
# third-party documentation names them. The code is always reported too.
OPERATIONS = {
    0x00: "Noop", 0x01: "CompensationLogRecord",
    0x02: "InitializeFileRecordSegment", 0x03: "DeallocateFileRecordSegment",
    0x04: "WriteEndOfFileRecordSegment", 0x05: "CreateAttribute",
    0x06: "DeleteAttribute", 0x07: "UpdateResidentValue",
    0x08: "UpdateNonresidentValue", 0x09: "UpdateMappingPairs",
    0x0A: "DeleteDirtyClusters", 0x0B: "SetNewAttributeSizes",
    0x0C: "AddIndexEntryRoot", 0x0D: "DeleteIndexEntryRoot",
    0x0E: "AddIndexEntryAllocation", 0x0F: "DeleteIndexEntryAllocation",
    0x10: "WriteEndOfIndexBuffer", 0x11: "SetIndexEntryVcnRoot",
    0x12: "SetIndexEntryVcnAllocation", 0x13: "UpdateFileNameRoot",
    0x14: "UpdateFileNameAllocation", 0x15: "SetBitsInNonresidentBitMap",
    0x16: "ClearBitsInNonresidentBitMap", 0x17: "HotFix",
    0x18: "EndTopLevelAction", 0x19: "PrepareTransaction",
    0x1A: "CommitTransaction", 0x1B: "ForgetTransaction",
    0x1C: "OpenNonresidentAttribute", 0x1D: "OpenAttributeTableDump",
    0x1E: "AttributeNamesDump", 0x1F: "DirtyPageTableDump",
    0x20: "TransactionTableDump", 0x21: "UpdateRecordDataRoot",
    0x22: "UpdateRecordDataAllocation",
}

_INDEX_ENTRY_OPS = (0x0C, 0x0D, 0x0E, 0x0F)
_FILE_NAME_OPS = (0x13, 0x14)

_FILETIME_MIN = 116444736000000000 + 20 * 365 * 86400 * 10 ** 7   # ~1990
_FILETIME_MAX = 116444736000000000 + 130 * 365 * 86400 * 10 ** 7  # ~2100


class LogFileError(ValueError):
    pass


def operation_name(code):
    return OPERATIONS.get(code, "unknown")


def _align8(n):
    return (n + 7) & ~7


def apply_fixups(page):
    """The page with its update sequence array removed, or None if any
    sector's last two bytes do not match the sequence number (a torn write:
    the page is not trusted)."""
    if len(page) < SECTOR:
        return None
    usa_off, usa_count = struct.unpack_from("<HH", page, 4)
    if usa_count < 2 or usa_off < 8 or usa_off + 2 * usa_count > len(page) \
            or (usa_count - 1) * SECTOR > len(page):
        return None
    usn = page[usa_off:usa_off + 2]
    out = bytearray(page)
    for i in range(1, usa_count):
        end = i * SECTOR
        if out[end - 2:end] != usn:
            return None
        out[end - 2:end] = page[usa_off + 2 * i:usa_off + 2 * i + 2]
    return bytes(out)


def filetime(v):
    """ISO time for a FILETIME that falls between 1990 and 2100, else None."""
    if not _FILETIME_MIN <= v <= _FILETIME_MAX:
        return None
    import datetime
    epoch = datetime.datetime(1601, 1, 1)
    return (epoch + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"


def _lsn_offset(lsn, seq_bits):
    """The file offset an LSN encodes (its low bits, in 8-byte units)."""
    if not 0 < seq_bits < 64:
        return None
    return (lsn & ((1 << (64 - seq_bits)) - 1)) * 8


# -- restart areas ----------------------------------------------------------------

def parse_restart(page):
    """The fields of a restart page (dict) or None if it is not usable."""
    if page[:4] != b"RSTR":
        return None
    fixed = apply_fixups(page)
    if fixed is None:
        return {"valid": False, "reason": _t("logfile.torn_page")}
    (chkdsk_lsn, sys_page, log_page, area_off, minor, major) = \
        struct.unpack_from("<QIIHhh", fixed, 8)
    if area_off < 0x20 or area_off + 48 > len(fixed):
        return {"valid": False, "reason": _t("logfile.restart_bad_area")}
    a = area_off
    (current_lsn, clients, free_list, in_use, flags, seq_bits, area_len,
     client_off, file_size, last_len, rec_hdr_len, data_off,
     open_count) = struct.unpack_from("<QHhhHIHHqIHHI", fixed, a)
    out = {
        "valid": True, "chkdsk_lsn": chkdsk_lsn, "system_page_size": sys_page,
        "log_page_size": log_page, "version": "%d.%d" % (major, minor),
        "current_lsn": current_lsn, "clients": clients,
        "clean_shutdown": bool(flags & 0x0002), "flags": flags,
        "seq_number_bits": seq_bits, "log_size": file_size,
        "last_lsn_data_length": last_len, "record_header_length": rec_hdr_len,
        "page_data_offset": data_off, "open_count": open_count,
        "client_names": [],
    }
    at = a + client_off
    for _ in range(min(clients, 8)):
        if at + 0xA0 > len(fixed):
            break
        oldest, restart_lsn = struct.unpack_from("<QQ", fixed, at)
        name_len = struct.unpack_from("<I", fixed, at + 28)[0]
        name = fixed[at + 32:at + 32 + min(name_len, 128)].decode(
            "utf-16-le", "replace")
        out["client_names"].append(name)
        out.setdefault("client_oldest_lsn", oldest)
        out.setdefault("client_restart_lsn", restart_lsn)
        at += 0xA0
    return out


# -- log records -------------------------------------------------------------------

def _file_name(buf, off, need_entry):
    """(fields, bytes used) for a $FILE_NAME (or the index entry holding one)
    at `off`, or None unless every length and time is plausible."""
    key = off
    ref = None
    if need_entry:
        if off + 16 > len(buf):
            return None
        ref, entry_len, key_len = struct.unpack_from("<QHH", buf, off)
        if entry_len < 16 + key_len or off + entry_len > len(buf) \
                or key_len < 66:
            return None
        key = off + 16
    elif off + 66 > len(buf):
        return None
    parent, c, m, mm, a = struct.unpack_from("<QQQQQ", buf, key)
    name_len = buf[key + 64]
    end = key + 66 + 2 * name_len
    if not name_len or end > len(buf):
        return None
    if need_entry and end > off + 16 + key_len:
        return None
    if not all(v == 0 or _FILETIME_MIN <= v <= _FILETIME_MAX
               for v in (c, m, mm, a)):
        return None
    name = buf[key + 66:end].decode("utf-16-le", "replace")
    if any(ord(ch) < 32 for ch in name) or "�" in name:
        return None
    out = {"name": name, "namespace": buf[key + 65],
           "parent_reference": parent & 0xFFFFFFFFFFFF,
           "parent_sequence": parent >> 48,
           "times": {"created": filetime(c), "modified": filetime(m),
                     "mft_modified": filetime(mm), "accessed": filetime(a)}}
    if ref is not None:
        out["file_reference"] = ref & 0xFFFFFFFFFFFF
        out["file_sequence"] = ref >> 48
    return out


def _payload_name(op, data):
    """Name fields from a redo/undo payload, where it is a plain index entry
    (add/delete index entry) or $FILE_NAME (update file name); else None."""
    if op in _INDEX_ENTRY_OPS:
        got = _file_name(data, 0, True)
        if got:
            got["source"] = "index entry"
        return got
    if op in _FILE_NAME_OPS:
        got = _file_name(data, 0, False)
        if got:
            got["source"] = "$FILE_NAME"
        return got
    return None


def parse_record(buf, offset, stats, seq_bits):
    """One log record from its full bytes (header and client data), as a
    dict."""
    (lsn, prev_lsn, undo_next, data_len, client_seq, client_idx, rtype, tx,
     flags) = struct.unpack_from("<QQQIHHIIH", buf, 0)
    rec = {
        "lsn": lsn, "offset": offset,
        "client_previous_lsn": prev_lsn, "client_undo_next_lsn": undo_next,
        "client": [client_seq, client_idx],
        "type": _TYPES.get(rtype, "unknown"), "transaction": tx,
        "flags": flags, "data_length": data_len,
    }
    lsn_at = _lsn_offset(lsn, seq_bits)
    if lsn_at is not None:
        rec["lsn_offset"] = lsn_at
        rec["lsn_position_matches"] = lsn_at == offset
    data = buf[HEADER:HEADER + data_len]
    if rtype != STANDARD or len(data) < 32:
        return rec
    (redo_op, undo_op, redo_off, redo_len, undo_off, undo_len, attr, lcns,
     rec_off, attr_off, cluster_index) = struct.unpack_from("<11H", data, 0)
    vcn = struct.unpack_from("<Q", data, 24)[0]
    rec.update({
        "redo_op": redo_op, "redo_name": operation_name(redo_op),
        "undo_op": undo_op, "undo_name": operation_name(undo_op),
        "redo_length": redo_len, "undo_length": undo_len,
        "target_attribute": attr, "record_offset": rec_off,
        "attribute_offset": attr_off, "cluster_index": cluster_index,
        "target_vcn": vcn,
    })
    if 0 < lcns <= MAX_LCNS and 32 + 8 * lcns <= len(data):
        rec["lcns"] = list(struct.unpack_from("<%dQ" % lcns, data, 32))
    for which, op, off, length in (("redo", redo_op, redo_off, redo_len),
                                   ("undo", undo_op, undo_off, undo_len)):
        if not length or off + length > len(data):
            continue
        got = _payload_name(op, data[off:off + length])
        if got:
            got["from"] = which
            rec.setdefault("names", []).append(got)
            stats["names"] += 1
    return rec


class _Walker:
    """Cuts the data areas of successive log pages into records, joining a
    record that runs from one page into the next."""

    def __init__(self, seq_bits, stats, sink):
        self.seq_bits, self.stats, self.sink = seq_bits, stats, sink
        self.pending = b""
        self.pending_at = 0
        self.need = 0

    def _emit(self, raw, at):
        self.stats["records"] += 1
        rec = parse_record(raw, at, self.stats, self.seq_bits)
        self.sink(rec)

    def _drop_pending(self):
        if self.pending:
            self.stats["incomplete"] += 1
        self.pending = b""
        self.need = 0

    def feed(self, region, base):
        """`region` is a page's data area; `base` its offset in the file."""
        i = 0
        while i < len(region):
            if self.pending:
                if len(self.pending) < HEADER:
                    take = region[i:i + HEADER - len(self.pending)]
                    self.pending += take
                    i += len(take)
                    if len(self.pending) < HEADER:
                        return
                    self.need = self._total(self.pending)
                    if self.need is None:
                        self.stats["stopped"] += 1
                        self._drop_pending()
                        return
                take = region[i:i + self.need - len(self.pending)]
                self.pending += take
                i += len(take)
                if len(self.pending) < self.need:
                    return
                self._emit(self.pending, self.pending_at)
                self.pending, self.need = b"", 0
                i = _align8(i)
                continue
            if len(region) - i < HEADER:
                self.pending, self.pending_at = region[i:], base + i
                return
            total = self._total(region[i:i + HEADER])
            if total is None:
                self.stats["stopped"] += 1
                return
            if i + total <= len(region):
                self._emit(region[i:i + total], base + i)
                i += _align8(total)
            else:
                self.pending, self.pending_at = region[i:], base + i
                self.need = total
                return

    @staticmethod
    def _total(head):
        lsn = struct.unpack_from("<Q", head, 0)[0]
        data_len, _seq, _idx, rtype = struct.unpack_from("<IHHI", head, 24)
        if not lsn or rtype not in (STANDARD, CHECKPOINT) \
                or data_len > MAX_CLIENT_DATA:
            return None
        return HEADER + data_len


def parse(read, size, progress=None):
    """Read a $LogFile through read(offset, length) over `size` bytes.
    Returns (report, records): the report holds the restart areas, the
    page tally and the record counts; records are ordered by LSN."""
    stats = {"pages": 0, "restart_pages": 0, "log_pages": 0,
             "unused_pages": 0, "torn_pages": 0, "unrecognised_pages": 0,
             "records": 0, "names": 0, "incomplete": 0, "stopped": 0,
             "truncated": False, "position_matches": 0}
    findings = []
    restarts = []
    page_size = PAGE
    for n in range(2):
        raw = read(n * page_size, page_size)
        if len(raw) < page_size:
            continue
        got = parse_restart(raw)
        if got is None:
            continue
        got["page"] = n
        restarts.append(got)
    usable = [r for r in restarts if r.get("valid")]
    if not usable:
        raise LogFileError(_t("logfile.no_restart"))
    stats["restart_pages"] = len(usable)
    newest = max(usable, key=lambda r: r["current_lsn"])
    if newest["log_page_size"] != PAGE or newest["system_page_size"] != PAGE:
        findings.append(_t("logfile.page_size") % (
            newest["system_page_size"], newest["log_page_size"]))
    data_off = newest["page_data_offset"]
    if not 0x28 <= data_off < PAGE or data_off % 8:
        data_off = 0x40
        findings.append(_t("logfile.data_offset_default"))
    if len(usable) == 2 and usable[0]["current_lsn"] != usable[1]["current_lsn"]:
        findings.append(_t("logfile.restarts_differ"))
    if not newest["clean_shutdown"]:
        findings.append(_t("logfile.not_clean"))

    records = []

    def sink(rec):
        if len(records) >= MAX_RECORDS:
            stats["truncated"] = True
            return
        if rec.get("lsn_position_matches"):
            stats["position_matches"] += 1
        records.append(rec)

    walker = _Walker(newest["seq_number_bits"], stats, sink)
    total_pages = size // PAGE
    for n in range(RCRD_FIRST, total_pages):
        if progress and n % 256 == 0:
            progress(n / total_pages)
        at = n * PAGE
        raw = read(at, PAGE)
        if len(raw) < PAGE:
            break
        stats["pages"] += 1
        magic = raw[:4]
        if magic == b"\xff\xff\xff\xff" or not any(raw[:64]):
            stats["unused_pages"] += 1
            walker._drop_pending()
            continue
        if magic != b"RCRD":
            stats["unrecognised_pages"] += 1
            walker._drop_pending()
            continue
        page = apply_fixups(raw)
        if page is None:
            stats["torn_pages"] += 1
            walker._drop_pending()
            continue
        stats["log_pages"] += 1
        flags = struct.unpack_from("<I", page, 16)[0]
        next_off = struct.unpack_from("<H", page, 24)[0]
        end = next_off if flags & 1 and data_off < next_off <= PAGE else PAGE
        walker.feed(page[data_off:end], at + data_off)
    walker._drop_pending()
    records.sort(key=lambda r: (r["lsn"], r["offset"]))
    if records:
        stats["first_lsn"] = records[0]["lsn"]
        stats["last_lsn"] = records[-1]["lsn"]
    stats["transactions"] = len({r["transaction"] for r in records
                                 if r["transaction"]})
    if stats["torn_pages"]:
        findings.append(_t("logfile.torn_pages") % stats["torn_pages"])
    if stats["unrecognised_pages"]:
        findings.append(_t("logfile.unrecognised_pages")
                        % stats["unrecognised_pages"])
    if stats["truncated"]:
        findings.append(_t("logfile.truncated") % MAX_RECORDS)
    report = {"restart": [{k: v for k, v in r.items()} for r in restarts],
              "newest_restart": newest["page"], "stats": stats,
              "findings": findings, "size": size}
    return report, records


def find(fs):
    """The $LogFile's unnamed data attribute on an NTFS volume, or None."""
    try:
        rec = fs.record(2)
    except Exception:
        return None
    if not rec:
        return None
    for a in rec.data_attrs():
        if not a.name:
            return a
    return None


def read_volume(fs, attr, progress=None):
    size = attr.real_size if not attr.resident else len(attr.body or b"")
    return parse(lambda off, n: fs.read_attr_range(attr, off, n), size,
                 progress=progress)
