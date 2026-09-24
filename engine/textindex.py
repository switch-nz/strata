import codecs
import re
import threading
import unicodedata
import zlib

from . import filesearch
from . import entropy as entropy_mod
from . import officedoc as officedoc_mod

MAX_TEXT_PER_FILE = 256 * 1024

FULL_TEXT_PER_FILE = 8 << 20

DEFAULT_READ_BYTES = 2 << 20

MIN_RUN = 4
_WS = re.compile(r"\s+")

def structured_text(data, name=""):
    try:
        got = officedoc_mod.parse(data, name)
    except Exception:
        return None
    if not got:
        return None
    meta = " ".join("%s %s" % (k, v) for k, v in (got.get("metadata") or {}).items())
    body = " ".join(x for x in (meta, got.get("text") or "") if x).strip()
    return body or None

def image_metadata_text(data):
    if not data or len(data) < 16:
        return None
    jpeg = bytes([0xFF, 0xD8])
    png = bytes([0x89]) + b"PNG" + bytes([0x0D, 0x0A, 0x1A, 0x0A])
    if not (data[:2] == jpeg or data[:8] == png
            or data[:2] in (b"II", b"MM")):
        return None
    try:
        from . import exif as exif_mod
        got = exif_mod.parse(data)
    except Exception:
        return None
    if not got:
        return None
    bits = []
    for v in (got.get("summary") or {}).values():
        if isinstance(v, str) and v and not v.startswith("EXIF timestamps"):
            bits.append(v)
    co = got.get("coordinates") or {}
    if isinstance(co, dict) and co.get("latitude") is not None:
        bits.append("%.6f %.6f" % (co["latitude"], co["longitude"]))
    return " ".join(bits) or None

def extract_text(data, limit=MAX_TEXT_PER_FILE, min_run=MIN_RUN,
                 wide_ascii_only=False):
    out = []
    total = 0
    for run in _ascii_runs(data, min_run):
        out.append(run)
        total += len(run)
        if total >= limit:
            return _WS.sub(" ", " ".join(out)).strip()[:limit]
    for run in _wide_runs(data, min_run, wide_ascii_only):
        out.append(run)
        total += len(run)
        if total >= limit:
            break
    return _WS.sub(" ", " ".join(out)).strip()[:limit]

# Text stored as UTF-16
#
# Any two bytes decode as some UTF-16 character, most of them printable, so
# keeping every printable run filled the index with text that never existed:
# binary, and text read one byte out of step, decode to plausible-looking
# ideographs and syllables. The data is decoded at both byte alignments -- a
# string can start on an odd byte -- and split wherever the script changes,
# and a run in another script is kept only when it reads like text: long
# enough, mostly unaccented if Latin, and for ideographs and Hangul not one of
# the patterns binary and misaligned text leave. ASCII stored as UTF-16 is
# kept as it always was, whatever surrounds it.

_WIDE_ASCII = {}
_ASCII_RE = {}
_CLASSES = None
_CLASSES_LOCK = threading.Lock()
_EAST_ASIAN = frozenset(("CJK", "HIRAGANA", "KATAKANA", "BOPOMOFO",
                         "IDEOGRAPHIC", "HALFWIDTH"))
# A run: one script, with spaces, digits, punctuation and combining marks
# inside it. Plain ASCII is left to its own pass, so a Latin run is only
# looked for where an accented letter sits against another letter -- binary
# is full of lone ones -- and is widened afterwards to take in the
# unaccented letters before it. For any other script the pattern asks for
# four of its letters, so what cannot be kept is never returned.
_SCRIPT_RUN = re.compile(r"(?:(?<=a)l|l(?=[al]))[ald.m]*"
                         r"|([^ald.mz#])(?=(?:[.dmz]*\1){3})(?:\1|[.dmz])*")

def _ascii_runs(data, min_run):
    pattern = _ASCII_RE.get(min_run)
    if pattern is None:
        pattern = _ASCII_RE[min_run] = re.compile(
            rb"[\x20-\x7e]{%d,}" % min_run)
    for m in pattern.finditer(data):
        run = m.group().decode("ascii")
        if len(run.strip()) >= min_run:
            yield run

def _big(cp):
    return 0x3400 <= cp <= 0x9FFF or 0xAC00 <= cp <= 0xD7A3

def _class_of(cp, scripts):
    # One letter per character: "a" ASCII letter, "d" other printable ASCII,
    # "m" combining mark, "." space, digit or punctuation from elsewhere,
    # "z" (below), "l" accented Latin, "E" East Asian, "K" Hangul, a letter
    # of its own for each other script, "#" anything that ends a run.
    if 0xD800 <= cp <= 0xDFFF or cp == 0xFFFD:
        return "#"
    if cp & 0xFF == 0 and 0x20 <= cp >> 8 <= 0x7E:
        # UTF-16 ASCII read one byte out of step decodes to nothing but
        # these ("o" then a zero byte is U+6F00). They may sit inside a run
        # of real text -- U+4E00 is the character for "one" -- but cannot
        # start one, so a stretch made only of them is never considered.
        return "z"
    ch = chr(cp)
    if 0x21 <= cp <= 0x7E:
        return "a" if ch.isalpha() else "d"
    cat = unicodedata.category(ch)
    if cat[0] == "M":
        # Devanagari and Thai vowels among them; they belong to the run.
        return "m"
    if ch.isspace() or cat[0] in "PNZ" or cat in ("Sm", "Sc", "Sk"):
        return "." if (ch == " " or ch.isprintable()) else "#"
    if not ch.isprintable() or cat[0] == "C" or cat == "So":
        return "#"
    word = unicodedata.name(ch, "?").split(" ")[0]
    if word in _EAST_ASIAN:
        return "E"
    if word == "HANGUL":
        return "K"
    if word == "LATIN":
        return "l"
    got = scripts.get(word)
    if got is None:
        got = scripts[word] = chr(0x100 + len(scripts))
    return got

def _classes():
    # Built on first use rather than at import: a pass over every BMP
    # character, as translate tables so a whole string is classified, and
    # a run judged, at C speed.
    global _CLASSES
    with _CLASSES_LOCK:
        if _CLASSES is None:
            scripts = {}
            cls, facts = {}, {}
            for cp in range(0x10000):
                cls[cp] = _class_of(cp, scripts)
                if _big(cp):
                    # Three characters per ideograph or syllable: its high
                    # byte, its low byte, and whether both are printable
                    # ASCII. Anything else translates to nothing.
                    hi, lo = cp >> 8, cp & 0xFF
                    both = 0x20 <= lo <= 0x7E and 0x20 <= hi <= 0x7E
                    facts[cp] = (chr(0x100 + hi) + chr(0x100 + lo)
                                 + ("1" if both else "0"))
                else:
                    facts[cp] = None
            _CLASSES = (str.maketrans(cls), str.maketrans(facts))
        return _CLASSES

def _crowded(s):
    # Three in four sharing one value.
    return len(s) >= 4 and max(map(s.count, set(s))) >= 0.75 * len(s)

def _reads_as_text(text, cls, min_run, facts_t):
    kind = cls[0]
    if kind in "ald":
        n = len(cls) - cls.count(".") - cls.count("m") - cls.count("z")
        latin = cls.count("l")
        # Real Latin text is mostly unaccented letters.
        return n >= min_run and latin <= n - latin
    if cls.count(kind) < min_run:
        return False
    if kind not in "EK":
        return True
    facts = text.translate(facts_t)
    n = len(facts) // 3
    if n < 4:
        return True
    # ASCII read one byte out of step: both bytes printable.
    if facts[2::3].count("1") >= 0.6 * n:
        return False
    # Repeated binary, or UTF-16 text read out of step: nearly every
    # ideograph or syllable sharing a byte. Kana are left out of this --
    # they fit in one 256-character block, so real Japanese shares a high
    # byte too.
    return not (_crowded(facts[0::3]) or _crowded(facts[1::3]))

def _wide_runs(data, min_run, ascii_only=False):
    pattern = _WIDE_ASCII.get(min_run)
    if pattern is None:
        pattern = _WIDE_ASCII[min_run] = re.compile(
            r"[\x20-\x7e]{%d,}" % min_run)
    tables = None if ascii_only else _classes()
    for align in (0, 1):
        body = data[align:]
        text = body[:len(body) & ~1].decode("utf-16-le", "replace")
        for m in pattern.finditer(text):
            run = m.group().strip()
            if len(run) >= min_run:
                yield run
        if tables is None:
            continue
        cls = text.translate(tables[0])
        for m in _SCRIPT_RUN.finditer(cls):
            a, b = m.span()
            if cls[a] == "l":
                # Take in the unaccented letters of the word it starts in.
                while a and cls[a - 1] == "a":
                    a -= 1
            if _reads_as_text(text[a:b], cls[a:b], min_run, tables[1]):
                yield text[a:b].strip()

RAW_CHUNK = 64 << 10

RAW_MIN_RUN = 8

RAW_MAX_ENTROPY = entropy_mod.INDEX_SKIP_ABOVE

RAW_TEXT_BUDGET = 64 << 20

def usn_documents(records, live_names=None):
    folded = {}
    for r in records:
        name = r.get("name")
        if not name:
            continue
        key = (name.lower(), r.get("mft"))
        got = folded.get(key)
        if got is None:
            got = folded[key] = {
                "name": name, "mft": r.get("mft"),
                "parent_mft": r.get("parent_mft"),
                "count": 0, "reasons": set(),
                "first": r.get("timestamp"), "last": r.get("timestamp"),
                "usn": r.get("usn"), "is_dir": bool(r.get("is_dir")),
            }
        got["count"] += 1
        got["reasons"].update(r.get("reasons") or ())
        ts = r.get("timestamp")
        if ts:
            if not got["first"] or ts < got["first"]:
                got["first"] = ts
            if not got["last"] or ts > got["last"]:
                got["last"] = ts

    out = []
    for (lname, mft), d in folded.items():
        known = live_names.get(mft) if live_names is not None else None
        gone = (live_names is not None
                and "deleted" in d["reasons"]
                and lname not in (known or set()))
        d["gone"] = gone
        d["reasons"] = sorted(d["reasons"])
        out.append(d)
    out.sort(key=lambda d: (not d["gone"], d["name"].lower()))
    return out

def build_usn(fs, case, part, live_names=None, progress=None, evidence=None,
              batch=400):
    if not getattr(case, "fts", False):
        return {"error": "This SQLite has no FTS5; indexed search "
                         "is unavailable."}
    try:
        from . import usnjrnl as usnjrnl_mod
    except ImportError:
        return {"present": False, "note": "No journal reader in this build."}

    found = usnjrnl_mod.find(fs)
    if not found:
        return {"present": False, "documents": 0, "note":
                "This volume has no $Extend\\$UsnJrnl."}
    _ent, j_attr, _mx = found
    recs, stats = usnjrnl_mod.read(
        fs, j_attr, progress=(lambda f: progress(f * 0.8)) if progress else None)

    docs = usn_documents(recs, live_names)
    rows, gone = [], 0
    for i, d in enumerate(docs):
        if progress and i % 256 == 0:
            progress(0.8 + 0.2 * i / max(1, len(docs)))
        if d["gone"]:
            gone += 1
        what = ", ".join(d["reasons"]) or "changed"
        body = "%s %s" % (d["name"], what)
        ctx = "%s · %d journal record%s%s" % (
            what, d["count"], "" if d["count"] == 1 else "s",
            " · the MFT no longer produces this name"
            if d["gone"] else "")
        rows.append((d["name"], ctx, body,
                     str(d["mft"] if d["mft"] is not None else ""),
                     part, 0, 1 if d["gone"] else 0, d["last"] or "",
                     "", "usn",
                     str(evidence if evidence is not None else "")))
        if len(rows) >= batch:
            _flush(case, rows)
            rows = []
    if rows:
        _flush(case, rows)
    if progress:
        progress(1.0)
    return {"present": True, "documents": len(docs), "records": stats["records"],
            "resyncs": stats["resyncs"], "names_gone_from_mft": gone,
            "sparse_skipped": stats["sparse_skipped"]}

def free_regions(fs, part_offset, part_size, min_size=RAW_CHUNK):
    get = getattr(fs, "allocated_extents", None)
    if not callable(get):
        return None
    try:
        extents = sorted(get())
    except Exception:
        return None
    out = []
    cursor = 0
    for start, end in extents:
        start = max(0, min(start, part_size))
        end = max(0, min(end, part_size))
        if start > cursor:
            out.append((part_offset + cursor, part_offset + start))
        cursor = max(cursor, end)
    if cursor < part_size:
        out.append((part_offset + cursor, part_offset + part_size))
    return [(a, b) for a, b in out if b - a >= min_size]

def build_region(source, case, part, start, size, label, kind="unallocated",
                 progress=None, chunk=RAW_CHUNK, min_run=RAW_MIN_RUN,
                 max_entropy=RAW_MAX_ENTROPY, batch=200,
                 budget=RAW_TEXT_BUDGET, base=0, evidence=None):
    rows = []
    docs = 0
    read_total = text_total = 0
    skipped_entropy = skipped_empty = 0
    truncated = False

    end = start + size
    total = max(1, size)
    pos = start
    while pos < end:
        if progress:
            progress((pos - start) / total)
        want = min(chunk, end - pos)
        try:
            data = source.read_at(pos, want)
        except Exception:
            break
        if not data:
            break
        read_total += len(data)
        if not any(data):
            skipped_empty += len(data)
            pos += len(data)
            continue
        if max_entropy and entropy_mod.of(data) > max_entropy:
            skipped_entropy += len(data)
            pos += len(data)
            continue
        body = extract_text(data, limit=len(data), min_run=min_run,
                            wide_ascii_only=True)
        if body:
            text_total += len(body)
            at = base + pos
            rows.append((("0x%012X" % at), label, body, str(at), part,
                         len(data), 1, "", str(at), kind,
                         str(evidence if evidence is not None else "")))
            docs += 1
            if len(rows) >= batch:
                _flush(case, rows)
                rows = []
            if budget and text_total >= budget:
                truncated = True
                pos += len(data)
                break
        pos += len(data)

    if rows:
        _flush(case, rows)
    if progress:
        progress(1.0)
    return {"kind": kind, "label": label, "offset": base + start,
            "size": size,
            "documents": docs, "bytes_read": read_total,
            "bytes_scanned": pos - start,
            "text_indexed": text_total,
            "skipped_high_entropy": skipped_entropy,
            "skipped_zeroed": skipped_empty,
            "budget_reached": truncated}

def build(fs, case, part, root_node, progress=None, want_live_names=False,
          read_bytes=DEFAULT_READ_BYTES,
          filters=None, batch=400, max_text=MAX_TEXT_PER_FILE, evidence=None):
    if not getattr(case, "fts", False):
        return {"error": "This SQLite has no FTS5; indexed search is unavailable."}

    case.index_remove("part = ? AND evidence = ?",
                      (part, str(evidence if evidence is not None else "")))

    walk = {}
    live_names = {} if want_live_names else None
    rows = []
    if not max_text:
        max_text = FULL_TEXT_PER_FILE
    counts = {"candidates": 0, "indexed": 0, "read_total": 0,
             "with_exif": 0, "structured": 0, "text_capped": 0}
    skip = {"empty": 0, "unreadable": 0, "no_text": 0}
    evidence_key = str(evidence if evidence is not None else "")

    # A streaming walk: each entry is read and indexed as the walk finds
    # it, rather than the whole tree being collected into memory first
    # (#81) -- at a large collection, walking alone was 40+ seconds and
    # 2.5 GB before a single file was even read.
    def on_entry(e):
        if live_names is not None:
            n = e.get("mft")
            if n is not None:
                live_names.setdefault(n, set()).add(
                    (e.get("name") or "").lower())
        if e.get("is_dir") or not filesearch.matches_filters(e, filters):
            return
        counts["candidates"] += 1
        if progress and counts["candidates"] % 32 == 0:
            # No total is known without walking the tree twice, so this
            # approaches 1 as candidates grows without ever reaching it
            # (progress(1.0) below marks the real end) -- a single float,
            # since a caller indexing several partitions in one task
            # (server's whole-disk build) wraps this into its own overall
            # fraction and does not accept anything else.
            progress(counts["candidates"] / (counts["candidates"] + 200))
        if not e.get("size"):
            skip["empty"] += 1
            return
        try:
            data = fs.read_file(e, read_bytes if read_bytes
                                else (e.get("size") or None))
        except Exception:
            skip["unreadable"] += 1
            return
        if not data:
            skip["unreadable"] += 1
            return
        counts["read_total"] += len(data)
        body = structured_text(data, e.get("name") or "")
        if body:
            counts["structured"] += 1
            body = body[:max_text]
        else:
            body = extract_text(data, max_text)
        meta = image_metadata_text(data)
        if meta:
            counts["with_exif"] += 1
            body = (meta + " " + (body or "")).strip()[:max_text]
        if not body:
            skip["no_text"] += 1
            return
        if len(body) >= max_text:
            counts["text_capped"] += 1
        node = (e.get("mft") if e.get("mft") is not None
                else e.get("inode") if e.get("inode") is not None
                else e.get("oid") if e.get("oid") is not None
                else e.get("start_cluster"))
        rows.append((e.get("name") or "", e.get("path") or "", body,
                     str(node), part, e.get("size") or 0,
                     int(bool(e.get("deleted"))), e.get("modified") or "",
                     "", "file", evidence_key))
        counts["indexed"] += 1
        if len(rows) >= batch:
            _flush(case, rows)
            rows.clear()

    filesearch.walk_stream(fs, root_node, on_entry, state=walk)
    if rows:
        _flush(case, rows)

    indexed = counts["indexed"]
    case.set_index_meta("index_part_%d" % part, str(indexed))
    if progress:
        progress(1.0)
    with_content = indexed + skip["unreadable"] + skip["no_text"]
    out = {"indexed": indexed, "candidates": counts["candidates"],
           "with_content": with_content, "skip": skip,
           "skipped": sum(skip.values()),
           "coverage": round(indexed / with_content, 4) if with_content else 1.0,
           "bytes_read": counts["read_total"],
           "structured": counts["structured"],
           "with_exif": counts["with_exif"],
           "text_capped": counts["text_capped"],
           "text_cap": max_text,
           "walk_truncated": bool(walk.get("truncated"))}
    if want_live_names:
        out["live_names"] = live_names
    return out

def _flush(case, rows):
    case.index_add(list(rows))

def _documents(case):
    # Where one row per indexed document can be counted: content_docs for a
    # compressed index, without going through FTS5 at all.
    fn = getattr(case, "index_documents", None)
    return fn() if fn else "content_index"

def _scope(part, evidence):
    if part is None:
        return "", ()
    if evidence is None:
        return " WHERE part=?", (part,)
    return " WHERE part=? AND evidence=?", (part, str(evidence))

def status(case, part=None, evidence=None):
    if not getattr(case, "fts", False):
        return {"available": False, "built": False, "documents": 0}
    try:
        where, args = _scope(part, evidence)
        n = case.index.execute(
            "SELECT COUNT(*) c FROM " + _documents(case) + where,
            args).fetchone()["c"]
    except Exception:
        return {"available": True, "built": False, "documents": 0}
    out = {"available": True, "built": n > 0, "documents": n}
    out.update(coverage(case, part, evidence))
    return out

def coverage(case, part=None, evidence=None):
    out = {"swept_raw": False, "raw_documents": 0, "file_documents": 0,
           "usn_documents": 0}
    try:
        where, args = _scope(part, evidence)
        sql = ("SELECT kind, COUNT(*) c FROM " + _documents(case) + where
               + " GROUP BY kind")
        rows = case.index.execute(sql, args)
        for r in rows:
            kind = r["kind"] or ""
            if kind in ("", "file"):
                out["file_documents"] += r["c"]
            elif kind == "usn":
                out["usn_documents"] += r["c"]
            else:
                out["raw_documents"] += r["c"]
                out["swept_raw"] = True
    except Exception:
        pass
    return out

def _fts_query(terms, mode):
    parts = []
    for t in terms:
        t = t.strip().replace('"', '""')
        if not t:
            continue
        parts.append('"%s"' % t)
    if not parts:
        return None
    return (" OR " if mode != "all" else " AND ").join(parts)

def query(case, terms, part=None, mode="any", limit=1000, snippet=True,
          evidence=None):
    st = status(case, part, evidence)
    if not st["available"]:
        return {"error": "This SQLite has no FTS5; indexed search is unavailable."}
    if not st["built"]:
        return {"error": "No index yet for this partition. Build one first."}

    expr = _fts_query(terms, mode)
    if not expr:
        return {"hits": [], "indexed_documents": st["documents"]}

    try:
        if getattr(case, "index_layout", None) == "compressed":
            rows = _compressed_hits(case, expr, terms, part, evidence, limit,
                                    snippet)
        else:
            rows = _plain_hits(case, expr, part, evidence, limit, snippet)
    except Exception as exc:
        return {"error": "Index query failed: %s" % exc}

    hits = []
    for r in rows:
        kind = r["kind"] or "file"
        try:
            offset = int(r["abs_offset"]) if r["abs_offset"] else None
        except (TypeError, ValueError):
            offset = None
        hits.append({
            "name": r["name"], "path": r["path"], "size": r["size"],
            "deleted": bool(r["deleted"]), "modified": r["modified"],
            "is_dir": False, "where": "content", "context": r["ctx"],
            "node": r["node"], "part": r["part"], "term": None,
            "file_offset": None, "indexed": True,
            "kind": kind, "offset": offset, "raw": kind != "file",
            "evidence": (int(r["evidence"]) if str(r["evidence"] or "").isdigit()
                         else None),
        })
    return {"hits": hits, "indexed_documents": st["documents"],
            "truncated": len(hits) >= limit,
            "coverage": _coverage_note(st, len(hits))}

_COLS = ("name", "path", "node", "part", "size", "deleted", "modified",
         "abs_offset", "kind", "evidence")

def _plain_hits(case, expr, part, evidence, limit, snippet):
    sn = ("snippet(content_index, 2, '', '', '…', 12)" if snippet else "''")
    sql = ("SELECT %s, %s AS ctx FROM content_index "
           "WHERE content_index MATCH ?" % (", ".join(_COLS), sn))
    args = [expr]
    if part is not None:
        sql += " AND part = ?"
        args.append(part)
        if evidence is not None:
            sql += " AND evidence = ?"
            args.append(str(evidence))
    sql += " ORDER BY rank LIMIT ?"
    args.append(limit)
    return case.index.execute(sql, args).fetchall()

def _compressed_hits(case, expr, terms, part, evidence, limit, snippet):
    # Ranking needs only FTS5's own index, and the scope columns are plain
    # columns of content_docs, so the hit list is found without reading any
    # document's text. Text is then read only for the hits being returned,
    # and only as far as the snippet needs.
    sql = ("SELECT f.rowid AS id, %s%s FROM content_index f "
           "JOIN content_docs d ON d.id = f.rowid "
           "WHERE content_index MATCH ?"
           % (", ".join("d." + c for c in _COLS),
              ", d.body AS blob" if snippet else ""))
    args = [expr]
    if part is not None:
        sql += " AND d.part = ?"
        args.append(part)
        if evidence is not None:
            sql += " AND d.evidence = ?"
            args.append(str(evidence))
    sql += " ORDER BY f.rank LIMIT ?"
    args.append(limit)
    rows = case.index.execute(sql, args).fetchall()
    rx = _term_pattern(terms) if snippet else None
    out = []
    for r in rows:
        hit = {c: r[c] for c in _COLS}
        hit["ctx"] = ""
        if snippet:
            hit["ctx"] = _snippet(case, expr, rx, r)
        out.append(hit)
    return out

SNIPPET_TOKENS = 12
_SNIPPET_CHUNK = 64 << 10
_SNIPPET_REACH = 600
# unicode61's token characters are letters and digits; underscore and
# everything else separate tokens.
_TOKEN = re.compile(r"[^\W_]+")

def _term_pattern(terms):
    alts = []
    for t in terms:
        words = _TOKEN.findall(t or "")
        if words:
            alts.append(r"(?<![^\W_])" + r"[\W_]+".join(map(re.escape, words))
                        + r"(?![^\W_])")
    return re.compile("|".join(alts), re.IGNORECASE) if alts else None

def _window(text, start, end, at_end):
    before = list(_TOKEN.finditer(text, max(0, start - _SNIPPET_REACH), start))
    after = list(_TOKEN.finditer(text, end, min(len(text),
                                                end + _SNIPPET_REACH)))
    want = SNIPPET_TOKENS - 1
    take_before = min(len(before), want // 2)
    take_after = min(len(after), want - take_before)
    take_before = min(len(before), want - take_after)
    a = before[-take_before].start() if take_before else start
    b = after[take_after - 1].end() if take_after else end
    return (("" if a == 0 else "…") + text[a:b]
            + ("" if at_end and b >= len(text.rstrip()) else "…"))

def _opening(blob):
    text = zlib.decompressobj().decompress(blob[:_SNIPPET_CHUNK])
    text = text.decode("utf-8", "ignore")
    words = list(_TOKEN.finditer(text))
    if not words:
        return text[:200]
    end = words[min(len(words), SNIPPET_TOKENS) - 1].end()
    more = end < len(text.rstrip()) or len(blob) > _SNIPPET_CHUNK
    return text[:end] + ("…" if more else "")

def _find_passage(blob, rx):
    z = zlib.decompressobj()
    dec = codecs.getincrementaldecoder("utf-8")("ignore")
    text, scanned = "", 0
    pos, n = 0, len(blob)
    while pos < n or not z.eof:
        chunk = blob[pos:pos + _SNIPPET_CHUNK]
        pos += len(chunk)
        text += dec.decode(z.decompress(chunk) if chunk else z.flush(),
                           final=pos >= n)
        m = rx.search(text, max(0, scanned - _SNIPPET_REACH))
        if m:
            # Read a little further so the passage can run on past the hit.
            while pos < n and len(text) - m.end() < _SNIPPET_REACH:
                chunk = blob[pos:pos + _SNIPPET_CHUNK]
                pos += len(chunk)
                text += dec.decode(z.decompress(chunk), final=pos >= n)
            return _window(text, m.start(), m.end(), pos >= n)
        scanned = len(text)
        if not chunk:
            break
    return None

def _snippet(case, expr, rx, row):
    blob = row["blob"]
    if not blob:
        return ""
    if rx is not None:
        found = _find_passage(blob, rx)
        if found is not None:
            return found
        where = "%s %s" % (row["name"] or "", row["path"] or "")
        if rx.search(where):
            # The match is in the name or path, not the text. FTS5 shows the
            # text's opening words then, and so does this.
            return _opening(blob)
    got = case.index.execute(
        "SELECT snippet(content_index, 2, '', '', '…', 12) FROM content_index "
        "WHERE content_index MATCH ? AND rowid = ?",
        (expr, row["id"])).fetchone()
    return got[0] if got else ""

def _coverage_note(st, found):
    note = dict(st)
    note.pop("available", None)
    note.pop("built", None)
    if st.get("swept_raw"):
        bits = ["%s regions of unallocated space, unparsed partitions and "
                "unpartitioned gaps" % format(st.get("raw_documents", 0), ",")]
        if st.get("usn_documents"):
            bits.append("%s filenames from the change journal"
                        % format(st.get("usn_documents", 0), ","))
        note["summary"] = (
            "Searched %s indexed documents, including %s."
            % (format(st.get("documents", 0), ","), " and ".join(bits)))
    else:
        held = ["%s files" % format(st.get("file_documents", 0), ",")]
        if st.get("usn_documents"):
            held.append("%s filenames from the change journal"
                        % format(st.get("usn_documents", 0), ","))
        note["summary"] = (
            "This index covers %s. Free space inside volumes, unparsed "
            "partitions and unpartitioned gaps were never read, so a term "
            "surviving only in deleted or carved content would not appear "
            "here. %s"
            % (" and ".join(held),
               "Press “Build index of whole disk” before treating this "
               "as an absence." if not found else
               "Press “Build index of whole disk” to cover them too."))
    note["complete"] = bool(st.get("swept_raw"))
    return note

def clear(case, part=None, evidence=None):
    if not getattr(case, "fts", False):
        return 0
    if part is None:
        case.index_remove()
    elif evidence is None:
        case.index_remove("part=?", (part,))
    else:
        case.index_remove("part=? AND evidence=?", (part, str(evidence)))
    return 1
