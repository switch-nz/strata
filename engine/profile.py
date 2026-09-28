import itertools
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

# Surrogate code units (high byte D8-DF) are moved out of the surrogate
# range before decoding, so every two bytes become exactly one character and
# a character index maps straight back to a byte offset. Raw media is full of
# byte pairs that would otherwise pair up into one astral character.
_NO_SURROGATES = bytes(0xFF if 0xD8 <= b <= 0xDF else b for b in range(256))

def utf16le_text(buf, align=0):
    """buf read as UTF-16LE from byte `align`, one character per two bytes:
    character i is the code unit at byte align + 2 * i."""
    b = bytearray(buf[align:])
    if len(b) % 2:
        del b[-1]
    b[1::2] = bytes(b[1::2]).translate(_NO_SURROGATES)
    return b.decode("utf-16-le")

REGEX_ENCODINGS = ("ascii", "utf-16le")

def _regex_patterns(terms, encodings, flags):
    """(term, encoding, compiled, utf16) for each term and each encoding a
    regular expression can be run in. A pattern is matched against ASCII
    (latin-1) bytes directly, and against UTF-16LE as decoded text."""
    out = []
    for t in terms:
        for enc in encodings:
            if enc == "ascii":
                try:
                    raw = t.encode("latin-1")
                except UnicodeEncodeError:
                    continue
                out.append((t, enc, re.compile(raw, flags), False))
            elif enc == "utf-16le":
                out.append((t, enc, re.compile(t, flags), True))
    return out

def search(source, terms, encodings=("ascii", "utf-16le"), regex=False,
           case_sensitive=False, start=0, end=None, max_hits=5000,
           window=8 << 20, context=32, progress=None, coverage=None):
    """Hits for `terms` in source[start:end], sorted by offset.

    If `coverage` is a dict it is filled in with "truncated" and
    "complete_to": when the hit limit is reached the search stops, and every
    hit before complete_to is in the results while nothing at or after it is.
    """
    end = end if end is not None else source.size
    flags = 0 if case_sensitive else re.IGNORECASE
    patterns = []
    if regex:
        patterns = _regex_patterns(terms, encodings, flags)
    else:
        for t in terms:
            for enc in encodings:
                needle = ENCODINGS[enc](t)
                if not needle:
                    continue
                patterns.append((t, enc, re.compile(re.escape(needle), flags),
                                 False))
    found = {}
    pos = start
    overlap = 1024
    total = max(1, end - start)
    stopped = None
    while pos < end:
        buf = source.read_at(pos, min(window, end - pos))
        if not buf:
            break
        texts = {}
        for term, enc, pat, utf16 in patterns:
            if utf16:
                matches = []
                for align in (0, 1):
                    if align not in texts:
                        texts[align] = utf16le_text(buf, align)
                    matches.extend((align + 2 * m.start(), align + 2 * m.end())
                                   for m in itertools.islice(
                                       pat.finditer(texts[align]),
                                       max_hits + 1))
                matches.sort()
            else:
                matches = ((m.start(), m.end()) for m in pat.finditer(buf))
            # Past max_hits + 1 matches of one pattern in one window, every
            # further match lies beyond where the results are cut anyway.
            for m_start, m_end in itertools.islice(matches, max_hits + 1):
                abs_pos = pos + m_start
                if abs_pos >= end:
                    continue
                # Windows overlap, so one match can be found twice; two terms
                # that match at the same offset are two hits, not one.
                key = (abs_pos, enc, term)
                if key in found:
                    continue
                lo = max(0, m_start - context)
                hi = min(len(buf), m_end + context)
                found[key] = {
                    "offset": abs_pos, "term": term, "encoding": enc,
                    "length": m_end - m_start,
                    "context": buf[lo:hi].decode("latin-1"),
                    "context_offset": pos + lo,
                    "match_at": m_start - lo,
                    "id": "hit:%d:%s" % (abs_pos, enc),
                }
        if pos + len(buf) >= end:
            nxt = end
        else:
            nxt = pos + max(1, len(buf) - overlap)
        if progress:
            progress(min(1.0, (nxt - start) / total))
        if len(found) > max_hits and nxt < end:
            # Matches starting before the next window's start (and no longer
            # than the overlap) have all been seen; later ones have not.
            stopped = nxt
            break
        pos = nxt

    out = sorted(found.values(), key=lambda h: (h["offset"], h["encoding"],
                                                h["term"]))
    cut = end if stopped is None else stopped
    if len(out) > max_hits:
        cut = min(cut, out[max_hits]["offset"])
    out = [h for h in out if h["offset"] < cut][:max_hits]
    if coverage is not None:
        coverage["truncated"] = cut < end
        coverage["complete_to"] = cut
    return out
