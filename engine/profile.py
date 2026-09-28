import re
from . import entropy as entropy_mod

ZERO = 0
TEXT = 1
STRUCTURED = 2
DENSE = 3
ENCRYPTED = 4
SPARSE_FF = 5

CLASS_NAMES = {
    ZERO: "zeroed", TEXT: "text", STRUCTURED: "structured",
    DENSE: "dense", ENCRYPTED: "high entropy", SPARSE_FF: "0xFF fill",
}

def classify(buf):
    if not buf:
        return ZERO, 0.0
    counts = bytearray(256)
    counts = [0] * 256
    printable = 0
    for b in buf:
        counts[b] += 1
        if 32 <= b < 127 or b in (9, 10, 13):
            printable += 1
    n = len(buf)
    if counts[0] == n:
        return ZERO, 0.0
    if counts[255] == n:
        return SPARSE_FF, 0.0
    h = entropy_mod.from_counts(counts, n)
    if counts[0] / n > 0.9:
        return ZERO, h
    if printable / n > 0.85 and h < 6.0:
        return TEXT, h
    if h > 7.6:
        return ENCRYPTED, h
    if h > 6.0:
        return DENSE, h
    return STRUCTURED, h

def profile(source, buckets=2048, sample=4096, start=0, end=None,
            progress=None):
    end = end if end is not None else source.size
    span = end - start
    if span <= 0:
        return {"buckets": [], "bucket_size": 0, "start": start, "end": end}
    buckets = max(16, min(buckets, 8192))
    step = span / buckets
    out = []
    for i in range(buckets):
        off = start + int(i * step)
        n = min(sample, max(1, int(step)))
        buf = source.read_at(off, n)
        cls, h = classify(buf)
        out.append([cls, round(h, 2)])
        if progress and i % 64 == 0:
            progress(i / buckets)
    return {"buckets": out, "bucket_size": step, "start": start, "end": end,
            "sample": sample, "classes": CLASS_NAMES,
            "note": "Sampled profile — %d bytes read per bucket." % sample}

ENCODINGS = {
    "ascii": lambda s: s.encode("latin-1", "ignore"),
    "utf-16le": lambda s: s.encode("utf-16-le"),
    "utf-16be": lambda s: s.encode("utf-16-be"),
    "utf-8": lambda s: s.encode("utf-8"),
}

def search(source, terms, encodings=("ascii", "utf-16le"), regex=False,
           case_sensitive=False, start=0, end=None, max_hits=5000,
           window=8 << 20, context=32, progress=None):
    end = end if end is not None else source.size
    patterns = []
    if regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        for t in terms:
            patterns.append((t, "regex", re.compile(t.encode("latin-1"), flags)))
    else:
        for t in terms:
            for enc in encodings:
                needle = ENCODINGS[enc](t)
                if not needle:
                    continue
                if case_sensitive:
                    patterns.append((t, enc, re.compile(re.escape(needle))))
                else:
                    patterns.append((t, enc, re.compile(re.escape(needle),
                                                        re.IGNORECASE)))
    hits = []
    pos = start
    overlap = 1024
    total = max(1, end - start)
    while pos < end and len(hits) < max_hits:
        buf = source.read_at(pos, min(window, end - pos))
        if not buf:
            break
        for term, enc, pat in patterns:
            for m in pat.finditer(buf):
                abs_pos = pos + m.start()
                if abs_pos >= end:
                    break
                lo = max(0, m.start() - context)
                hi = min(len(buf), m.end() + context)
                hits.append({
                    "offset": abs_pos, "term": term, "encoding": enc,
                    "length": m.end() - m.start(),
                    "context": buf[lo:hi].decode("latin-1"),
                    "context_offset": pos + lo,
                    "match_at": m.start() - lo,
                    "id": "hit:%d:%s" % (abs_pos, enc),
                })
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break
        pos += max(1, len(buf) - overlap)
        if progress:
            progress(min(1.0, (pos - start) / total))

    seen, out = set(), []
    for h in sorted(hits, key=lambda x: x["offset"]):
        # Windows overlap, so one match can be found twice; two terms that
        # match at the same offset are two hits, not one.
        key = (h["offset"], h["encoding"], h["term"])
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out
