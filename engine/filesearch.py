import re

from . import profile
from .text import t as _t

DEFAULT_SCAN_BYTES = 64 << 20
MAX_CONTEXT = 60

def _needles(terms, encodings, case_sensitive):
    out = []
    for t in terms:
        for enc in encodings:
            try:
                codec = "utf-16-le" if enc in ("utf-16le", "utf16", "utf-16") else "ascii"
                raw = t.encode(codec, "strict")
            except (UnicodeEncodeError, LookupError):
                continue
            out.append({"term": t, "encoding": enc, "raw": raw,
                        "cmp": raw if case_sensitive else raw.lower()})
    return out

def _context(data, pos, length):
    lo = max(0, pos - MAX_CONTEXT // 2)
    hi = min(len(data), pos + length + MAX_CONTEXT // 2)
    chunk = data[lo:hi]
    text = "".join(chr(c) if 32 <= c < 127 else "·" for c in chunk)
    return text.strip()

PROGRESS_EVERY = 512

def _walk(fs, root_node, path, out, depth, max_depth, seen, progress=None,
          budget=None, state=None):
    if depth > max_depth:
        return
    try:
        entries = fs.listdir(root_node, path)
    except Exception:
        return
    for e in entries:
        if budget is not None and len(out) >= budget:
            if state is not None:
                state["truncated"] = True
            return
        out.append(e)
        if progress is not None and len(out) % PROGRESS_EVERY == 1:
            progress(len(out))
        if e.get("is_dir"):
            node = (e.get("mft") if e.get("mft") is not None
                    else e.get("inode") if e.get("inode") is not None
                    else e.get("oid") if e.get("oid") is not None
                    else e.get("start_cluster"))
            if node is None or node in seen:
                continue
            seen.add(node)
            _walk(fs, node, e.get("path") or path, out, depth + 1, max_depth,
                  seen, progress, budget, state)

DEFAULT_BUDGET = 5000000

def collect(fs, root_node, path="/", max_depth=64, budget=DEFAULT_BUDGET,
            state=None, progress=None):
    out = []
    _walk(fs, root_node, path, out, 0, max_depth, {root_node},
          progress=progress, budget=budget,
          state=state if state is not None else {})
    return out

class _StreamSink:
    """Duck-types list's append()/len() for _walk(), so on_entry() sees
    each entry as the walk reaches it instead of the whole tree being
    held in memory first."""

    __slots__ = ("on_entry", "count")

    def __init__(self, on_entry):
        self.on_entry = on_entry
        self.count = 0

    def append(self, e):
        self.count += 1
        self.on_entry(e)

    def __len__(self):
        return self.count

def walk_stream(fs, root_node, on_entry, path="/", max_depth=64,
                budget=DEFAULT_BUDGET, state=None):
    """Like collect(), but calls on_entry(e) for each entry as the walk
    reaches it rather than returning them all in one list -- for a caller
    that reads and processes a file immediately (engine.textindex.build),
    so the cost of walking a large tree is not paid twice: once to build
    the list, once to use it. Returns the number of entries walked."""
    sink = _StreamSink(on_entry)
    _walk(fs, root_node, path, sink, 0, max_depth, {root_node},
          budget=budget, state=state if state is not None else {})
    return sink.count

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?Z?)?$")
_TIME_FILTERS = ("modified_after", "modified_before", "created_after",
                 "created_before", "accessed_after", "accessed_before")
_FLAG_FILTERS = ("deleted_only", "hide_deleted", "files_only")
MAX_EXTENSIONS = 64
MAX_NAME_FILTER = 255


def clean_filters(f):
    """Filters as a client sent them, checked and normalised for
    matches_filters(); raises ValueError naming what is wrong. Unknown keys
    are refused rather than ignored, so a misspelt filter cannot quietly
    match everything."""
    if f in (None, {}):
        return None
    if not isinstance(f, dict):
        raise ValueError(_t("filters.not_object"))
    out = {}
    for key, v in f.items():
        if v is None or v is False:
            continue
        if key == "name":
            if not isinstance(v, str) or len(v) > MAX_NAME_FILTER:
                raise ValueError(_t("filters.name_bad") % MAX_NAME_FILTER)
            if v.strip():
                out[key] = v.strip()
        elif key == "extensions":
            if not isinstance(v, list) or len(v) > MAX_EXTENSIONS \
                    or not all(isinstance(x, str) for x in v):
                raise ValueError(_t("filters.extensions_bad") % MAX_EXTENSIONS)
            exts = [x.strip().lstrip(".").lower() for x in v]
            exts = [x for x in exts if x]
            if exts:
                out[key] = exts
        elif key in ("min_size", "max_size"):
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError(_t("filters.size_bad") % key)
            out[key] = v
        elif key in _TIME_FILTERS:
            if not isinstance(v, str) or not _DATE.match(v):
                raise ValueError(_t("filters.date_bad") % key)
            out[key] = v
        elif key in _FLAG_FILTERS:
            if v is not True:
                raise ValueError(_t("filters.flag_bad") % key)
            out[key] = True
        else:
            raise ValueError(_t("filters.unknown") % key)
    if out.get("deleted_only") and out.get("hide_deleted"):
        raise ValueError(_t("filters.deleted_conflict"))
    lo, hi = out.get("min_size"), out.get("max_size")
    if lo is not None and hi is not None and lo > hi:
        raise ValueError(_t("filters.size_range"))
    for a, b in (("modified_after", "modified_before"),
                 ("created_after", "created_before"),
                 ("accessed_after", "accessed_before")):
        if a in out and b in out and out[a] > out[b]:
            raise ValueError(_t("filters.date_range") % a.split("_")[0])
    return out or None


def matches_filters(e, f):
    if not f:
        return True
    name = (e.get("name") or "")
    if f.get("name") and f["name"].lower() not in name.lower():
        return False
    exts = f.get("extensions")
    if exts:
        dot = name.rfind(".")
        ext = name[dot + 1:].lower() if dot >= 0 else ""
        if ext not in exts:
            return False
    size = e.get("size") or 0
    if f.get("min_size") is not None and size < f["min_size"]:
        return False
    if f.get("max_size") is not None and size > f["max_size"]:
        return False
    if f.get("deleted_only") and not e.get("deleted"):
        return False
    if f.get("hide_deleted") and e.get("deleted"):
        return False
    if f.get("files_only") and e.get("is_dir"):
        return False
    for key, lo, hi in (("modified", "modified_after", "modified_before"),
                        ("created", "created_after", "created_before"),
                        ("accessed", "accessed_after", "accessed_before")):
        v = e.get(key)
        if f.get(lo) and (not v or v < f[lo]):
            return False
        if f.get(hi) and (not v or v > f[hi]):
            return False
    return True

def search(fs, terms, root_node=5, mode="both", encodings=("ascii", "utf-16le"),
           regex=False, case_sensitive=False, filters=None,
           scan_bytes=DEFAULT_SCAN_BYTES, max_hits=5000, max_per_file=20,
           progress=None):
    walk = {}
    entries = collect(fs, root_node, state=walk)
    entries = [e for e in entries if matches_filters(e, filters)]
    total = max(1, len(entries))

    rx = None
    if regex:
        try:
            rx = re.compile("|".join(terms),
                            0 if case_sensitive else re.IGNORECASE)
            rx_encodings = [enc for enc in encodings
                            if enc in profile.REGEX_ENCODINGS]
        except re.error as exc:
            return {"error": "Bad regular expression: %s" % exc, "hits": [],
                    "searched": 0}

    needles = None if regex else _needles(terms, encodings, case_sensitive)
    want_name = mode in ("name", "both")
    want_content = mode in ("content", "both")

    hits = []
    searched = 0
    read_bytes = 0
    unreadable = 0
    truncated_files = 0
    skipped_bytes = 0
    partial_names = []
    for i, e in enumerate(entries):
        if progress and i % 64 == 0:
            progress(i / total)
        if len(hits) >= max_hits:
            break

        if want_name:
            name = e.get("name") or ""
            hay = name if case_sensitive else name.lower()
            if rx is not None:
                if rx.search(name):
                    hits.append(_hit(e, "name", name, None, None))
            else:
                for n in needles:
                    if n["encoding"] != "ascii":
                        continue
                    t = n["term"] if case_sensitive else n["term"].lower()
                    if t and t in hay:
                        hits.append(_hit(e, "name", name, n["term"], None))
                        break

        if not want_content or e.get("is_dir") or not e.get("size"):
            continue

        try:
            data = fs.read_file(e, scan_bytes if scan_bytes else (e.get("size")
                                                                  or None))
        except Exception:
            unreadable += 1
            continue
        if not data:
            unreadable += 1
            continue
        searched += 1
        read_bytes += len(data)
        if (e.get("size") or 0) > len(data):
            truncated_files += 1
            skipped_bytes += e["size"] - len(data)
            partial_names.append(e.get("path") or e.get("name"))

        in_file = 0
        more = 0

        if rx is not None:
            found = []
            for enc in rx_encodings:
                if enc == "ascii":
                    found.extend((m.start(), m.end() - m.start(), m.group(0),
                                  enc)
                                 for m in rx.finditer(data.decode("latin-1")))
                    continue
                for align in (0, 1):
                    found.extend((align + 2 * m.start(),
                                  2 * (m.end() - m.start()), m.group(0), enc)
                                 for m in rx.finditer(
                                     profile.utf16le_text(data, align)))
            found.sort()
            for pos, length, matched, enc in found:
                if in_file >= max_per_file:
                    more += 1
                    continue
                hits.append(_hit(e, "content", _context(data, pos, length),
                                 matched, pos, enc))
                in_file += 1
                if len(hits) >= max_hits:
                    break
        else:
            hay = data if case_sensitive else data.lower()
            for n in needles:
                pos = hay.find(n["cmp"])
                while pos != -1:
                    if in_file >= max_per_file:
                        more += 1
                    else:
                        hits.append(_hit(e, "content",
                                         _context(data, pos, len(n["raw"])),
                                         n["term"], pos, n["encoding"]))
                        in_file += 1
                        if len(hits) >= max_hits:
                            break
                    pos = hay.find(n["cmp"], pos + max(1, len(n["cmp"])))
                if len(hits) >= max_hits:
                    break

        if more and in_file:
            hits[-1]["more_in_file"] = more

    if progress:
        progress(1.0)
    return {"hits": hits, "entries": len(entries), "searched": searched,
            "bytes_read": read_bytes, "truncated": len(hits) >= max_hits,
            "walk_truncated": bool(walk.get("truncated")),
            "unreadable": unreadable,
            "partial_files": truncated_files,
            "skipped_bytes": skipped_bytes,
            "partial_examples": partial_names[:12],
            "scan_limit": scan_bytes}

def _hit(e, where, context, term=None, offset=None, encoding=None):
    return {
        "name": e.get("name"), "path": e.get("path"), "size": e.get("size"),
        "is_dir": bool(e.get("is_dir")), "deleted": bool(e.get("deleted")),
        "modified": e.get("modified"), "created": e.get("created"),
        "accessed": e.get("accessed"),
        "mft": e.get("mft"), "inode": e.get("inode"), "oid": e.get("oid"),
        "start_cluster": e.get("start_cluster"),
        "where": where, "term": term, "context": context,
        "file_offset": offset, "encoding": encoding,
        "entry": e,
    }
