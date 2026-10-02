import datetime
import struct

V1_SIZE = 544
V2_MIN = 28

def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).isoformat() + "Z"
    except (OverflowError, ValueError):
        return None

def parse_i(data):
    if len(data) < V2_MIN:
        return None
    version, size, deleted = struct.unpack_from("<QQQ", data, 0)
    if version == 1:
        if len(data) < V1_SIZE:
            return None
        raw = data[24:24 + 520]
    elif version == 2:
        if len(data) < 32:
            return None
        chars = struct.unpack_from("<I", data, 24)[0]
        if chars > 32768:
            return None
        raw = data[28:28 + chars * 2]
    else:
        return None
    path = raw.decode("utf-16-le", "replace").split("\x00")[0]
    return {
        "version": version,
        "original_path": path,
        "original_name": path.replace("/", "\\").rsplit("\\", 1)[-1],
        "size": size,
        "deleted_at": filetime(deleted),
    }

INFO2_RECORD = 800

def parse_info2(data):
    out = []
    if len(data) < 20:
        return out
    rec_size = struct.unpack_from("<I", data, 12)[0]
    if rec_size not in (280, 800):
        rec_size = INFO2_RECORD
    pos = 20
    while pos + rec_size <= len(data):
        rec = data[pos:pos + rec_size]
        pos += rec_size
        ascii_path = rec[0:260].split(b"\x00")[0].decode("latin-1", "replace")
        try:
            index, drive, deleted, size = struct.unpack_from("<IIQI", rec, 260)
        except struct.error:
            continue
        wide = ""
        if rec_size >= 800:
            wide = rec[280:800].decode("utf-16-le", "replace").split("\x00")[0]
        path = wide or ascii_path
        if not path:
            continue
        out.append({
            "version": 0,
            "index": index,
            "drive": chr(ord("A") + drive) if 0 <= drive < 26 else None,
            "original_path": path,
            "original_name": path.replace("/", "\\").rsplit("\\", 1)[-1],
            "size": size,
            "deleted_at": filetime(deleted),
        })
    return out

from .nodes import node_of as _node_of

def scan(fs, listdir, root_node, progress=None):
    out = []
    findings = []

    roots = []
    try:
        for e in listdir(root_node, "/"):
            n = (e.get("name") or "").lower()
            if e.get("is_dir") and n in ("$recycle.bin", "recycler", "recycled"):
                roots.append(e)
    except Exception:
        return {"items": [], "findings": ["Could not read the volume root."]}

    if not roots:
        return {"items": [], "findings": [], "bins": 0}

    bins = 0
    for root in roots:
        try:
            users = listdir(_node_of(root), root.get("path") or "/")
        except Exception:
            findings.append("Could not read %s." % root.get("name"))
            continue
        for u in users:
            if not u.get("is_dir"):
                continue
            bins += 1
            sid = u.get("name")
            try:
                entries = listdir(_node_of(u), u.get("path") or "/")
            except Exception:
                findings.append("Could not read %s\\%s."
                                % (root.get("name"), sid))
                continue

            meta, content = {}, {}
            for e in entries:
                nm = e.get("name") or ""
                if len(nm) > 2 and nm[0] == "$" and nm[1] in "IiRr":
                    key = nm[2:]
                    (meta if nm[1] in "Ii" else content)[key.lower()] = e
            for key, ie in meta.items():
                rec = None
                try:
                    rec = parse_i(fs.read_file(ie, 64 * 1024))
                except Exception:
                    rec = None
                item = {
                    "sid": sid, "bin": root.get("name"),
                    "i_name": ie.get("name"), "i_path": ie.get("path"),
                    "deleted_entry": bool(ie.get("deleted")),
                }
                re_ = content.get(key)
                if re_:
                    item.update({"r_name": re_.get("name"),
                                 "r_path": re_.get("path"),
                                 "recoverable_size": re_.get("size"),
                                 "entry": re_})
                else:
                    item["orphan"] = "metadata"
                    findings.append(
                        "%s has no $R counterpart — the record of the deletion "
                        "survives but the content does not." % ie.get("name"))
                if rec:
                    item.update(rec)
                else:
                    item["unparsed"] = True
                    findings.append("Could not parse %s as a $I record."
                                    % ie.get("name"))
                out.append(item)

            for key, re_ in content.items():
                if key in meta:
                    continue
                out.append({
                    "sid": sid, "bin": root.get("name"),
                    "r_name": re_.get("name"), "r_path": re_.get("path"),
                    "recoverable_size": re_.get("size"), "entry": re_,
                    "orphan": "content",
                    "original_path": None, "deleted_at": None,
                })
                findings.append(
                    "%s has no $I counterpart — the content is recoverable but "
                    "its original path and deletion time are not."
                    % re_.get("name"))

            for e in entries:
                if (e.get("name") or "").lower() != "info2":
                    continue
                try:
                    recs = parse_info2(fs.read_file(e, 8 << 20))
                except Exception:
                    findings.append("Could not read INFO2 for %s." % sid)
                    continue
                for r in recs:
                    out.append({"sid": sid, "bin": root.get("name"),
                                "source": "INFO2", **r})

    legacy_present = any((r.get("name") or "").lower() != "$recycle.bin"
                         for r in roots)
    if legacy_present:
        findings.append("A legacy RECYCLER/RECYCLED folder is present, which "
                        "means this volume was used by Windows XP or earlier.")

    out.sort(key=lambda r: (r.get("deleted_at") or "", r.get("original_name") or ""))
    return {"items": out, "findings": findings, "bins": bins,
            "legacy": legacy_present}
