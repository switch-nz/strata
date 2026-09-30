import datetime
import struct
import uuid

from . import eventids

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = b"\x2a\x2a\x00\x00"

HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_DATA_START = 0x200

TOK_EOF = 0x00
TOK_OPEN_START = 0x01
TOK_CLOSE_START = 0x02
TOK_CLOSE_EMPTY = 0x03
TOK_END_ELEMENT = 0x04
TOK_VALUE = 0x05
TOK_ATTRIBUTE = 0x06
TOK_CDATA = 0x07
TOK_CHARREF = 0x08
TOK_ENTITYREF = 0x09
TOK_TEMPLATE = 0x0C
TOK_NORMAL_SUB = 0x0D
TOK_OPTIONAL_SUB = 0x0E
TOK_FRAGMENT = 0x0F

LEVELS = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning",
          4: "Information", 5: "Verbose"}

def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def _sid(raw):
    if len(raw) < 8:
        return None
    rev = raw[0]
    count = raw[1]
    if len(raw) < 8 + count * 4:
        return None
    auth = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack_from("<%dI" % count, raw, 8)
    return "S-%d-%d-%s" % (rev, auth, "-".join(str(s) for s in subs))

class _Chunk:

    def __init__(self, data, base):
        self.data = data
        self.base = base
        self.names = {}
        self.templates = {}

    def name_at(self, offset):
        if offset in self.names:
            return self.names[offset]
        d = self.data
        if offset + 8 > len(d):
            return ""
        n_chars = struct.unpack_from("<H", d, offset + 6)[0]
        raw = d[offset + 8: offset + 8 + n_chars * 2]
        name = raw.decode("utf-16-le", "replace")
        self.names[offset] = name
        return name

def _value(vtype, raw, chunk=None):
    if vtype & 0x80:
        base = vtype & 0x7F
        return _array(base, raw, chunk)
    try:
        if vtype == 0x00:
            return None
        if vtype == 0x01:
            return raw.decode("utf-16-le", "replace").rstrip("\x00")
        if vtype == 0x02:
            return raw.decode("latin-1", "replace").rstrip("\x00")
        if vtype == 0x03:
            return struct.unpack_from("<b", raw, 0)[0]
        if vtype == 0x04:
            return raw[0]
        if vtype == 0x05:
            return struct.unpack_from("<h", raw, 0)[0]
        if vtype == 0x06:
            return struct.unpack_from("<H", raw, 0)[0]
        if vtype == 0x07:
            return struct.unpack_from("<i", raw, 0)[0]
        if vtype == 0x08:
            return struct.unpack_from("<I", raw, 0)[0]
        if vtype == 0x09:
            return struct.unpack_from("<q", raw, 0)[0]
        if vtype == 0x0A:
            return struct.unpack_from("<Q", raw, 0)[0]
        if vtype == 0x0B:
            return struct.unpack_from("<f", raw, 0)[0]
        if vtype == 0x0C:
            return struct.unpack_from("<d", raw, 0)[0]
        if vtype == 0x0D:
            return bool(struct.unpack_from("<I", raw, 0)[0])
        if vtype == 0x0E:
            return raw.hex()
        if vtype == 0x0F:
            return str(uuid.UUID(bytes_le=raw[:16]))
        if vtype == 0x10:
            return int.from_bytes(raw, "little")
        if vtype == 0x11:
            return filetime(struct.unpack_from("<Q", raw, 0)[0])
        if vtype == 0x12:
            y, mo, _, d, h, mi, s, ms = struct.unpack_from("<8H", raw, 0)
            return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (y, mo, d, h, mi, s, ms)
        if vtype == 0x13:
            return _sid(raw)
        if vtype == 0x14:
            return "0x%08X" % struct.unpack_from("<I", raw, 0)[0]
        if vtype == 0x15:
            return "0x%016X" % struct.unpack_from("<Q", raw, 0)[0]
        if vtype == 0x21 and chunk is not None:
            return _parse_fragment(chunk, raw, 0, [], depth=1)[0]
    except (struct.error, ValueError, IndexError):
        return None
    return raw.hex() if raw else None

def _array(base, raw, chunk):
    out = []
    if base == 0x01:
        for part in raw.decode("utf-16-le", "replace").split("\x00"):
            if part:
                out.append(part)
        return out
    widths = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4,
              0x09: 8, 0x0A: 8, 0x0B: 4, 0x0C: 8, 0x0F: 16, 0x11: 8,
              0x14: 4, 0x15: 8}
    w = widths.get(base)
    if not w:
        return raw.hex()
    for i in range(0, len(raw) - w + 1, w):
        out.append(_value(base, raw[i:i + w], chunk))
    return out

def _parse_fragment(chunk, data, pos, subs, depth=0, data_offset=None):
    if depth > 24:
        return None, pos
    root = None
    stack = []
    unsupported = set()

    while pos < len(data):
        token = data[pos]
        base = token & 0x0F
        more = bool(token & 0x40)

        if base == TOK_EOF:
            pos += 1
            break

        if base == TOK_FRAGMENT:
            pos += 4
            continue

        if base == TOK_OPEN_START:
            pos += 1
            pos += 2
            pos += 4
            if pos + 4 > len(data):
                break
            name_off = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if name_off + 8 > len(chunk.data):
                unsupported.add("name offset outside chunk")
                break
            name = chunk.name_at(name_off)
            if data_offset is not None and name_off == data_offset + pos:
                n_chars = struct.unpack_from("<H", chunk.data, name_off + 6)[0]
                pos += 10 + n_chars * 2
            if more:
                pos += 4
            el = {"name": name, "attrs": {}, "children": [], "text": None}
            if stack:
                stack[-1]["children"].append(el)
            elif root is None:
                root = el
            stack.append(el)
            continue

        if base == TOK_ATTRIBUTE:
            pos += 1
            if pos + 4 > len(data):
                break
            name_off = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if name_off + 8 > len(chunk.data):
                unsupported.add("attribute name outside chunk")
                break
            aname = chunk.name_at(name_off)
            if data_offset is not None and name_off == data_offset + pos:
                n_chars = struct.unpack_from("<H", chunk.data, name_off + 6)[0]
                pos += 10 + n_chars * 2
            val, pos = _attr_value(chunk, data, pos, subs, depth, data_offset)
            if stack:
                stack[-1]["attrs"][aname] = val
            continue

        if base == TOK_CLOSE_START:
            pos += 1
            continue

        if base == TOK_CLOSE_EMPTY:
            pos += 1
            if stack:
                stack.pop()
            continue

        if base == TOK_END_ELEMENT:
            pos += 1
            if stack:
                stack.pop()
            continue

        if base == TOK_VALUE:
            pos += 1
            vtype = data[pos]
            pos += 1
            if vtype == 0x01:
                n = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                text = data[pos:pos + n * 2].decode("utf-16-le", "replace")
                pos += n * 2
                if stack:
                    stack[-1]["text"] = ((stack[-1]["text"] or "") + text)
            else:
                unsupported.add("value type 0x%02X" % vtype)
                break
            continue

        if base in (TOK_NORMAL_SUB, TOK_OPTIONAL_SUB):
            pos += 1
            index, vtype = struct.unpack_from("<HB", data, pos)
            pos += 3
            val = subs[index] if index < len(subs) else None
            if stack:
                if isinstance(val, dict):
                    stack[-1]["children"].append(val)
                else:
                    prev = stack[-1]["text"]
                    stack[-1]["text"] = val if prev is None else \
                        "%s%s" % (prev, val if val is not None else "")
            continue

        if base == TOK_CHARREF:
            pos += 3
            continue

        if base == TOK_ENTITYREF:
            pos += 5
            continue

        if base == TOK_CDATA:
            pos += 1
            n = struct.unpack_from("<H", data, pos)[0]
            pos += 2 + n * 2
            continue

        if base == TOK_TEMPLATE:
            el, pos = _template_instance(chunk, data, pos, depth, data_offset)
            if el is not None:
                if stack:
                    stack[-1]["children"].append(el)
                elif root is None:
                    root = el
            continue

        unsupported.add("token 0x%02X" % token)
        break

    if root is not None and unsupported:
        root.setdefault("_unsupported", sorted(unsupported))
    return root, pos

def _attr_value(chunk, data, pos, subs, depth, data_offset=None):
    if pos >= len(data):
        return None, pos
    token = data[pos] & 0x0F
    if token == TOK_VALUE:
        pos += 1
        vtype = data[pos]
        pos += 1
        if vtype == 0x01:
            n = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            v = data[pos:pos + n * 2].decode("utf-16-le", "replace")
            pos += n * 2
            return v, pos
        return None, pos
    if token in (TOK_NORMAL_SUB, TOK_OPTIONAL_SUB):
        pos += 1
        index, _vtype = struct.unpack_from("<HB", data, pos)
        pos += 3
        return (subs[index] if index < len(subs) else None), pos
    return None, pos

def _template_instance(chunk, data, pos, depth, data_offset=None):
    pos += 1
    pos += 1
    _tid = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    def_off = struct.unpack_from("<I", data, pos)[0]
    pos += 4

    cd = chunk.data
    if def_off + 24 > len(cd):
        return None, pos
    data_size = struct.unpack_from("<I", cd, def_off + 20)[0]
    tdata = chunk.templates.get(def_off)
    if tdata is None:
        tdata = cd[def_off + 24: def_off + 24 + data_size]
        chunk.templates[def_off] = tdata

    if data_offset is not None and def_off == data_offset + pos:
        pos += 24 + data_size

    if not tdata:
        return None, pos

    if pos + 4 > len(data):
        return None, pos
    count = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    if count > 4096:
        return None, pos
    descriptors = []
    for _ in range(count):
        if pos + 4 > len(data):
            return None, pos
        size, vtype = struct.unpack_from("<HB", data, pos)
        pos += 4
        descriptors.append((size, vtype))
    subs = []
    for size, vtype in descriptors:
        raw = data[pos:pos + size]
        pos += size
        subs.append(_value(vtype, raw, chunk))

    el, _ = _parse_fragment(chunk, tdata, 0, subs, depth + 1,
                            data_offset=def_off + 24)
    return el, pos

def _flatten(el, out=None, path=""):
    if out is None:
        out = {}
    if not isinstance(el, dict):
        return out
    name = el.get("name") or ""
    here = "%s/%s" % (path, name) if path else name
    attrs = el.get("attrs") or {}

    if name == "Data" and attrs.get("Name"):
        out["%s/%s" % (path, attrs["Name"])] = el.get("text")
        return out

    for k, v in attrs.items():
        _put(out, "%s@%s" % (here, k), v)
    if el.get("text") is not None:
        _put(out, here, el["text"])
    for child in el.get("children") or []:
        _flatten(child, out, here)
    return out

def _put(out, key, value):
    if key not in out:
        out[key] = value
        return
    if out[key] == value:
        return
    i = 2
    while "%s#%d" % (key, i) in out:
        i += 1
    out["%s#%d" % (key, i)] = value

def _summarise(flat):
    def pick(*keys):
        for k in keys:
            for f, v in flat.items():
                if f.endswith(k):
                    return v
        return None

    level = pick("System/Level")
    if isinstance(level, str):
        try:
            level = int(level.strip())
        except ValueError:
            pass            # not a number: shown as written
    return {
        "event_id": pick("System/EventID"),
        "level": LEVELS.get(level, level) if isinstance(level, int) else level,
        "provider": pick("Provider@Name"),
        "channel": pick("System/Channel"),
        "computer": pick("System/Computer"),
        "security_sid": pick("Security@UserID"),
        "created": pick("TimeCreated@SystemTime"),
        "task": pick("System/Task"),
        "opcode": pick("System/Opcode"),
        "process_id": pick("Execution@ProcessID"),
    }

def count_records(data):
    if len(data) < HEADER_SIZE or data[:8] != FILE_MAGIC:
        return 0
    total = 0
    pos = HEADER_SIZE
    while pos + CHUNK_SIZE <= len(data):
        cdata = data[pos:pos + CHUNK_SIZE]
        if cdata[:8] != CHUNK_MAGIC:
            break
        free_offset, = struct.unpack_from("<I", cdata, 0x30)
        limit = min(free_offset if free_offset > CHUNK_DATA_START else CHUNK_SIZE,
                    CHUNK_SIZE)
        rp = CHUNK_DATA_START
        while rp + 24 <= limit:
            if cdata[rp:rp + 4] != RECORD_MAGIC:
                break
            size, = struct.unpack_from("<I", cdata, rp + 4)
            if size < 24 or rp + size > CHUNK_SIZE:
                break
            total += 1
            rp += size
        pos += CHUNK_SIZE
    return total

def _header_info(head):
    """The file header's fields and the findings it implies."""
    (first_chunk, last_chunk, next_record) = struct.unpack_from("<QQQ", head, 8)
    header_size, minor, major = struct.unpack_from("<IHH", head, 32)
    chunk_count, = struct.unpack_from("<H", head, 42)
    flags, = struct.unpack_from("<I", head, 120)
    info = {
        "version": "%d.%d" % (major, minor),
        "chunk_count": chunk_count,
        "next_record_id": next_record,
        "dirty": bool(flags & 0x01),
        "full": bool(flags & 0x02),
    }
    findings = []
    if flags & 0x01:
        findings.append(
            "The log was not closed cleanly (dirty flag set); the last chunk "
            "may hold records the header does not count.")
    return info, findings

def _record_spans(cdata, findings):
    """(offset, size) of each whole record in one chunk, in order."""
    free_offset, = struct.unpack_from("<I", cdata, 0x30)
    limit = min(free_offset if free_offset > CHUNK_DATA_START else CHUNK_SIZE,
                CHUNK_SIZE)
    rp = CHUNK_DATA_START
    while rp + 24 <= limit:
        if cdata[rp:rp + 4] != RECORD_MAGIC:
            break
        size, = struct.unpack_from("<I", cdata, rp + 4)
        if size < 24 or rp + size > CHUNK_SIZE:
            findings.append(
                "A record at chunk offset 0x%X declares an impossible size."
                % rp)
            break
        yield rp, size
        rp += size

def _decode_record(chunk, cdata, rp, size, findings, keep_fields=True):
    """One record as a dict. `keep_fields` keeps every flattened field, a
    few KB a record; a summary of a whole log has no use for them."""
    rec_id, = struct.unpack_from("<Q", cdata, rp + 8)
    written, = struct.unpack_from("<Q", cdata, rp + 16)
    payload = cdata[rp + 24: rp + size - 4]
    try:
        el, _ = _parse_fragment(chunk, payload, 0, [], data_offset=rp + 24)
    except Exception as exc:
        el = None
        findings.append("Record %d: %s" % (rec_id, exc))
    rec = {"record_id": rec_id, "written_at": filetime(written)}
    if el is None:
        rec["unsupported"] = "binary XML could not be decoded"
    else:
        flat = _flatten(el)
        rec.update(_summarise(flat))
        rec["description"] = eventids.describe(
            rec.get("provider"), rec.get("event_id"), flat)
        if keep_fields:
            rec["fields"] = flat
        if el.get("_unsupported"):
            rec["unsupported"] = ", ".join(el["_unsupported"])
    return rec

def parse(data, max_records=None, progress=None, offset=0):
    out = {"records": [], "findings": [], "chunks": 0}
    if len(data) < HEADER_SIZE or data[:8] != FILE_MAGIC:
        return None

    out["header"], notes = _header_info(data)
    out["findings"].extend(notes)

    pos = HEADER_SIZE
    seen_records = 0
    skipped = 0
    span = max(1, len(data) - HEADER_SIZE)
    while pos + CHUNK_SIZE <= len(data):
        if progress:
            progress((pos - HEADER_SIZE) / span)
        cdata = data[pos:pos + CHUNK_SIZE]
        if cdata[:8] != CHUNK_MAGIC:
            break
        out["chunks"] += 1
        chunk = _Chunk(cdata, pos)
        for rp, size in _record_spans(cdata, out["findings"]):
            if skipped < offset:
                skipped += 1
                continue
            out["records"].append(
                _decode_record(chunk, cdata, rp, size, out["findings"]))
            seen_records += 1
            if max_records and seen_records >= max_records:
                out["more"] = True
                out["offset"] = offset
                if progress:
                    progress(1.0)
                return out
        pos += CHUNK_SIZE

    out["offset"] = offset
    out["more"] = False
    if progress:
        progress(1.0)
    return out

class LogScan:
    """An event log read one 64 KiB chunk at a time, so what is held is a
    chunk and not the file. `read_at(offset, length)` reads the log and
    `size` is its length. `valid` says whether it has an event-log header;
    records() yields the log's records without their flattened fields, and
    fills in `header`, `findings` and `chunks` as it goes."""

    def __init__(self, read_at, size):
        self.read_at = read_at
        self.size = size
        self.header = None
        self.findings = []
        self.chunks = 0
        head = read_at(0, HEADER_SIZE) if size >= HEADER_SIZE else b""
        self.valid = len(head) >= HEADER_SIZE and head[:8] == FILE_MAGIC
        if self.valid:
            self.header, notes = _header_info(head)
            self.findings.extend(notes)
        self.position = HEADER_SIZE

    def records(self):
        if not self.valid:
            return
        while self.position + CHUNK_SIZE <= self.size:
            cdata = self.read_at(self.position, CHUNK_SIZE)
            if len(cdata) < CHUNK_SIZE or cdata[:8] != CHUNK_MAGIC:
                break
            self.chunks += 1
            chunk = _Chunk(cdata, self.position)
            for rp, size in _record_spans(cdata, self.findings):
                yield _decode_record(chunk, cdata, rp, size, self.findings,
                                     keep_fields=False)
            self.position += CHUNK_SIZE

class _Bytes:
    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def read_at(self, offset, length):
        return self.data[offset:offset + length]

SWEEP_MAX_EVENTS = 100000
LOG_READ_MAX = 256 << 20

def sweep(logs, progress=None, max_events=SWEEP_MAX_EVENTS):
    """Every record in several event logs from one volume, merged into one
    timeline. `logs` is [(name, source path, reader, size, deleted)], the
    last two optional. `reader` is an object with `size` and
    `read_at(offset, length)`, read a chunk at a time, or a callable that
    returns the log's bytes. A log that is a deleted file is marked so, and
    so is every event read from it: its clusters may have been reused since.

    Memory does not grow with the logs: each is read a chunk at a time, and
    only the `max_events` newest events overall are kept, so past that the
    oldest are dropped as the sweep goes. `progress` is called between
    chunks, so a cancellation it raises takes effect within one chunk.
    Returns per-log summaries and the events, oldest first."""
    import heapq
    summaries, kept = [], []
    found = 0
    seq = 0
    total = max(1, len(logs))
    for i, item in enumerate(logs):
        name, source, reader = item[:3]
        size = item[3] if len(item) > 3 else None
        deleted = bool(item[4]) if len(item) > 4 else False
        if progress:
            progress(i / total)
        row = {"name": name, "source": source, "records": 0,
               "deleted": deleted}
        summaries.append(row)
        try:
            if not hasattr(reader, "read_at"):
                reader = _Bytes(reader())
            scan = LogScan(reader.read_at, min(reader.size, LOG_READ_MAX))
        except Exception as exc:
            row["error"] = str(exc) or type(exc).__name__
            continue
        if not scan.valid:
            row["error"] = "not an event log (no ElfFile header)"
            continue
        row["findings"] = scan.findings
        row["dirty"] = bool(scan.header.get("dirty"))
        if size and size > LOG_READ_MAX:
            row["partial"] = True
            scan.findings.append(
                "This log is %d bytes; only the first %d were read, so "
                "records after that point are not in the timeline."
                % (size, LOG_READ_MAX))
        records = scan.records()
        chunks_seen = 0
        while True:
            # Reading and decoding may fail on a damaged log; a cancellation
            # raised by `progress` below is not caught here.
            try:
                x = next(records)
            except StopIteration:
                break
            except Exception as exc:
                row["error"] = str(exc) or type(exc).__name__
                break
            if progress and scan.chunks != chunks_seen:
                chunks_seen = scan.chunks
                span = max(1, scan.size - HEADER_SIZE)
                progress((i + min(1.0, (scan.position - HEADER_SIZE) / span))
                         / total)
            row["records"] += 1
            # A time is text. One that a substitution decoded to something
            # else falls back to the record's own write time, so a single
            # odd record cannot stop the logs being merged and sorted.
            when = x.get("created")
            if not isinstance(when, str) or not when:
                when = x.get("written_at")
            if when:
                if "first" not in row or when < row["first"]:
                    row["first"] = when
                if "last" not in row or when > row["last"]:
                    row["last"] = when
            if not row.get("channel") and x.get("channel"):
                row["channel"] = x["channel"]
            event = {
                "time": when, "log": len(summaries) - 1,
                "record_id": x.get("record_id"),
                "event_id": x.get("event_id"), "provider": x.get("provider"),
                "level": x.get("level"), "channel": x.get("channel"),
                "computer": x.get("computer"),
                "description": x.get("description"),
                "undecoded": bool(x.get("unsupported")),
                "deleted": deleted,
            }
            found += 1
            seq += 1
            key = (event["time"] or "", event["log"],
                   event["record_id"] or 0, seq)
            if len(kept) < max_events:
                heapq.heappush(kept, (key, event))
            else:
                heapq.heappushpop(kept, (key, event))
    if progress:
        progress(1.0)
    events = [event for _, event in sorted(kept, key=lambda k: k[0])]
    return {"logs": summaries, "events": events, "total_events": found,
            "truncated": found > max_events,
            "note": eventids.NOTE}
