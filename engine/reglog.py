import struct

from . import native

MASK = 0xFFFFFFFF
MARVIN_SEED = 0x82EF4D887A4E55C5

LOG_ENTRY_START = 512
HIVE_BASE_BLOCK = 4096
ENTRY_SIGNATURE = b"HvLE"
HIVE_SIGNATURE = b"regf"

def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & MASK

def _mix(lo, hi, val):
    lo = (lo + val) & MASK
    hi ^= lo
    lo = (_rotl(lo, 20) + hi) & MASK
    hi = _rotl(hi, 9) ^ lo
    lo = (_rotl(lo, 27) + hi) & MASK
    hi = _rotl(hi, 19)
    return lo, hi

def marvin32(data, seed=MARVIN_SEED):
    """Marvin32, seeded — Windows' checksum for registry hive and
    transaction-log entries. Dirty logs run to tens of megabytes, and this
    is a pure-Python fallback for a hash that mixes 4 bytes at a time, so
    the native sidecar (identical output, verified below and at its own
    load-time self-test) is used when available."""
    if native.available():
        try:
            return native.marvin32(bytes(data), seed)
        except native.NativeError:
            pass
    return _marvin32_py(data, seed)

def _marvin32_py(data, seed=MARVIN_SEED):
    lo = seed & MASK
    hi = (seed >> 32) & MASK
    n = len(data)
    whole = n - (n % 4)
    if whole:
        # Same as calling _mix(lo, hi, val) per word, inlined and fed from
        # one bulk unpack instead of 4 bytes' worth of Python-level call
        # overhead per word — the checksum can cover a whole dirty hive or
        # transaction log (tens of MB), where that overhead dominates.
        for (val,) in struct.iter_unpack("<I", memoryview(data)[:whole]):
            lo = (lo + val) & MASK
            hi ^= lo
            lo = (((lo << 20) & MASK | (lo >> 12)) + hi) & MASK
            hi = ((hi << 9) & MASK | (hi >> 23)) ^ lo
            lo = (((lo << 27) & MASK | (lo >> 5)) + hi) & MASK
            hi = (hi << 19) & MASK | (hi >> 13)
    i = whole
    rest = n - i
    if rest == 0:
        final = 0x80
    elif rest == 1:
        final = 0x8000 | data[i]
    elif rest == 2:
        final = 0x800000 | struct.unpack_from("<H", data, i)[0]
    else:
        final = (0x80000000 | (data[i + 2] << 16)
                 | struct.unpack_from("<H", data, i)[0])
    lo, hi = _mix(lo, hi, final)
    lo, hi = _mix(lo, hi, 0)
    return ((hi << 32) | lo) & 0xFFFFFFFFFFFFFFFF

def base_checksum(block):
    acc = 0
    for i in range(0, 508, 4):
        acc ^= struct.unpack_from("<I", block, i)[0]
    if acc == 0:
        return 1
    if acc == MASK:
        return MASK - 1
    return acc

def hive_sequences(hive):
    if len(hive) < HIVE_BASE_BLOCK or hive[:4] != HIVE_SIGNATURE:
        return None
    seq1, seq2 = struct.unpack_from("<II", hive, 4)
    hbins, = struct.unpack_from("<I", hive, 40)
    return seq1, seq2, hbins

def parse_log(raw):
    out = {"entries": [], "findings": [], "base_sequence": None}
    if len(raw) < LOG_ENTRY_START:
        out["findings"].append("The log is shorter than its own base block.")
        return out
    if raw[:4] == HIVE_SIGNATURE:
        seq1, _seq2 = struct.unpack_from("<II", raw, 4)
        out["base_sequence"] = seq1

    pos = LOG_ENTRY_START
    while pos + 40 <= len(raw):
        if raw[pos:pos + 4] != ENTRY_SIGNATURE:
            break
        size, flags, seq, hbins, pages = struct.unpack_from("<IIIII", raw,
                                                            pos + 4)
        if size < 512 or size % 512 or pos + size > len(raw):
            out["findings"].append(
                "A log entry at 0x%X declares an implausible size (%d); the "
                "log was read up to that point." % (pos, size))
            break
        stored1, stored2 = struct.unpack_from("<QQ", raw, pos + 24)
        if marvin32(raw[pos + 40:pos + size]) != stored1:
            out["findings"].append(
                "A log entry at 0x%X fails its data hash and was not used. "
                "That is where this log stops being current." % pos)
            break
        if marvin32(raw[pos:pos + 32]) != stored2:
            out["findings"].append(
                "A log entry at 0x%X fails its header hash and was not used."
                % pos)
            break

        refs, ok = [], True
        need = 40 + pages * 8
        if need > size:
            out["findings"].append(
                "A log entry at 0x%X claims %d dirty pages, more than it has "
                "room for." % (pos, pages))
            break
        data_at = pos + need
        for k in range(pages):
            off, length = struct.unpack_from("<II", raw, pos + 40 + k * 8)
            if data_at + length > pos + size:
                out["findings"].append(
                    "A dirty page in the entry at 0x%X runs past the end of "
                    "it." % pos)
                ok = False
                break
            refs.append((off, length, data_at))
            data_at += length
        if not ok:
            break

        out["entries"].append({
            "sequence": seq, "flags": flags, "hbins_size": hbins,
            "pages": refs, "offset": pos, "size": size,
        })
        pos += size
    return out

def recover(hive, logs):
    report = {"dirty": False, "recovered": False, "applied": [],
              "pages_written": 0, "bytes_written": 0, "findings": [],
              "primary": None, "secondary": None, "log_sequences": []}

    seqs = hive_sequences(hive)
    if seqs is None:
        report["findings"].append("This is not a registry hive.")
        return None, report
    seq1, seq2, hbins = seqs
    report["primary"], report["secondary"] = seq1, seq2
    report["dirty"] = seq1 != seq2

    entries = {}
    for raw in logs or ():
        got = parse_log(raw)
        report["findings"].extend(got["findings"])
        for e in got["entries"]:
            entries.setdefault(e["sequence"], (e, raw))
    report["log_sequences"] = sorted(entries)

    if not report["dirty"]:
        report["findings"].append(
            "The hive was cleanly unmounted, so there is nothing to replay.")
        return None, report
    if not entries:
        report["findings"].append(
            "The hive is dirty and no usable transaction log was found "
            "beside it. What the last transaction changed is not recoverable "
            "from this evidence.")
        return None, report

    start = seq2
    if start not in entries:
        oldest = min(entries)
        report["findings"].append(
            "The hive is at sequence %d but the oldest surviving log entry is "
            "%d. The transactions in between have been overwritten — a "
            "transaction log is circular — so this hive cannot be brought up "
            "to date from these logs. It is reported as it stands, dirty."
            % (seq2, oldest))
        return None, report

    ordered = []
    want = start
    while want in entries:
        ordered.append(entries[want])
        want += 1
    if len(ordered) != len(entries):
        report["findings"].append(
            "%d log entr%s beyond a gap in the sequence were not applied."
            % (len(entries) - len(ordered),
               "y" if len(entries) - len(ordered) == 1 else "ies"))

    out = bytearray(hive)
    pages = written = 0
    last_seq = None
    for entry, raw in ordered:
        need = HIVE_BASE_BLOCK + entry["hbins_size"]
        if need > len(out):
            out.extend(bytes(need - len(out)))
        for off, length, at in entry["pages"]:
            dest = HIVE_BASE_BLOCK + off
            if dest + length > len(out):
                out.extend(bytes(dest + length - len(out)))
            out[dest:dest + length] = raw[at:at + length]
            pages += 1
            written += length
        last_seq = entry["sequence"]
        report["applied"].append(entry["sequence"])

    struct.pack_into("<II", out, 4, last_seq, last_seq)
    struct.pack_into("<I", out, 40, ordered[-1][0]["hbins_size"])
    struct.pack_into("<I", out, 508, base_checksum(bytes(out[:508])))

    report["recovered"] = True
    report["pages_written"] = pages
    report["bytes_written"] = written
    report["sequence_after"] = last_seq
    return bytes(out), report

def summarise(report):
    if not report.get("dirty"):
        return "Cleanly unmounted; no replay needed."
    if report.get("recovered"):
        return ("Recovered from the transaction log: %d page(s), %d bytes, "
                "sequence %d to %d."
                % (report["pages_written"], report["bytes_written"],
                   report["secondary"], report["sequence_after"]))
    return ("Dirty and not recoverable from the logs present — shown as it "
            "stands, which is the state before the last transaction.")
