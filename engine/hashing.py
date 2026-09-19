import csv
import hashlib
import io
import os
import re

from . import filesearch
from . import fuzzyhash

_HEX = re.compile(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")

ALGO_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}

def node_of(entry):
    for key in ("mft", "inode", "oid", "start_cluster"):
        v = entry.get(key)
        if v is not None:
            return v
    return None

def node_key(entry):
    v = node_of(entry)
    return None if v is None else str(v)

def hash_entry(fs, entry, max_bytes=None):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = entry.get("size") or 0
    data = fs.read_file(entry, max_bytes if max_bytes else size or None)
    if data is None:
        data = b""
    md5.update(data)
    sha1.update(data)
    sha256.update(data)
    return {
        "node": node_key(entry), "name": entry.get("name"),
        "path": entry.get("path"),
        "size": size, "read": len(data), "deleted": bool(entry.get("deleted")),
        "md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "fuzzy": fuzzyhash.hash_bytes(data) if data else None,
        "partial": bool(size and len(data) < size),
    }

def hash_many(fs, entries, progress=None, max_bytes=None):
    out = []
    total = max(1, len(entries))
    for i, e in enumerate(entries):
        if progress and i % 16 == 0:
            progress(i / total)
        if e.get("is_dir"):
            continue
        try:
            out.append(hash_entry(fs, e, max_bytes))
        except Exception:
            continue
    if progress:
        progress(1.0)
    return out

def collect_scope(fs, root_node, scope="all", entry=None, filters=None):
    if scope == "item" and entry:
        return [entry]
    if scope == "folder" and entry:
        node = node_of(entry)
        out = []
        filesearch._walk(fs, node, entry.get("path") or "/", out, 0, 64,
                         {node})
        return [e for e in out if not e.get("is_dir")
                and filesearch.matches_filters(e, filters)]
    out = filesearch.collect(fs, root_node)
    return [e for e in out if not e.get("is_dir")
            and filesearch.matches_filters(e, filters)]

def parse_hash_list(text, default_label=None):
    out = []
    seen = set()

    head = text[:4096].lower()
    looks_csv = ("," in head and
                 any(k in head for k in ("sha-1", "sha1", "md5", "sha-256",
                                         "sha256", "filename")))
    if looks_csv:
        try:
            rdr = csv.DictReader(io.StringIO(text))
            fields = {(f or "").strip().lower().replace('"', ''): f
                      for f in (rdr.fieldnames or [])}
            col = {}
            for want, names in (("md5", ("md5",)),
                                ("sha1", ("sha-1", "sha1")),
                                ("sha256", ("sha-256", "sha256"))):
                for n in names:
                    if n in fields:
                        col[want] = fields[n]
                        break
            namecol = fields.get("filename") or fields.get("name")
            if col:
                for row in rdr:
                    label = (row.get(namecol) or default_label) if namecol else default_label
                    for algo, c in col.items():
                        v = (row.get(c) or "").strip().strip('"').lower()
                        if len(v) in ALGO_BY_LEN and _HEX.fullmatch(v):
                            key = (algo, v)
                            if key not in seen:
                                seen.add(key)
                                out.append((algo, v, label))
                if out:
                    return out
        except Exception:
            pass

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        m = _HEX.search(line)
        if not m:
            continue
        digest = m.group(1).lower()
        algo = ALGO_BY_LEN.get(len(digest))
        if not algo:
            continue
        rest = (line[:m.start()] + line[m.end():]).strip(" *\t,\"")
        key = (algo, digest)
        if key in seen:
            continue
        seen.add(key)
        out.append((algo, digest, rest or default_label))
    return out

# The only three the schema, the UI and the stylesheet know about.
HASH_SET_KINDS = ("known_bad", "known_good", "notable")

def import_hash_set(case, path, name=None, kind="known_bad"):
    if kind not in HASH_SET_KINDS:
        return {"error": "Unknown hash set kind %r — expected one of %s."
                         % (kind, ", ".join(HASH_SET_KINDS))}
    if not os.path.isfile(path):
        return {"error": "File not found: %s" % path}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as exc:
        return {"error": str(exc)}
    digests = parse_hash_list(text)
    if not digests:
        return {"error": "No hashes found in %s." % os.path.basename(path)}
    name = name or os.path.splitext(os.path.basename(path))[0]
    res = case.add_hash_set(name, kind, path, digests)
    return {"name": name, "kind": kind, **res}

def matched_hash_map(case, evidence_id, part):
    """Like case.hash_map, but each already-hashed node also carries
    match_kind/matches when its digest is in an imported hash set —
    the same lookup annotate_matches does for a hash run, applied to
    whatever has been hashed already so folder and search views can
    show it without hashing anything themselves."""
    hashes = case.hash_map(evidence_id, part)
    if not hashes:
        return hashes
    digests = []
    for h in hashes.values():
        digests += [h.get("md5"), h.get("sha1"), h.get("sha256")]
    found = case.match_hashes([d for d in digests if d])
    if not found:
        return hashes
    for h in hashes.values():
        hits = []
        for algo in ("md5", "sha1", "sha256"):
            for m in found.get((h.get(algo) or "").lower(), []):
                if m["algo"] == algo:
                    hits.append(m)
        if hits:
            h["matches"] = hits
            kinds = {m["kind"] for m in hits}
            h["match_kind"] = ("known_bad" if "known_bad" in kinds
                               else "notable" if "notable" in kinds
                               else "known_good")
    return hashes

def annotate_hits(hits, matched_map):
    """Marks each hit whose filesystem node is in matched_map (from
    matched_hash_map) with its match_kind/matches, in place."""
    for h in hits:
        info = matched_map.get(node_key(h))
        if info and info.get("match_kind"):
            h["match_kind"] = info["match_kind"]
            h["matches"] = info["matches"]
    return hits

def annotate_matches(case, rows):
    digests = []
    for r in rows:
        digests += [r.get("md5"), r.get("sha1"), r.get("sha256")]
    found = case.match_hashes([d for d in digests if d])
    if not found:
        return rows
    for r in rows:
        hits = []
        for algo in ("md5", "sha1", "sha256"):
            for m in found.get((r.get(algo) or "").lower(), []):
                if m["algo"] == algo:
                    hits.append(m)
        if hits:
            r["matches"] = hits
            kinds = {m["kind"] for m in hits}
            r["match_kind"] = ("known_bad" if "known_bad" in kinds
                               else "notable" if "notable" in kinds
                               else "known_good")
    return rows
