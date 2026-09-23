import json
import os
import sqlite3

VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS node (
  mft INTEGER PRIMARY KEY,
  parent INTEGER,
  name TEXT,
  is_dir INTEGER,
  deleted INTEGER,
  size INTEGER,
  created TEXT,
  modified TEXT,
  accessed TEXT,
  mft_modified TEXT,
  fn_created TEXT,
  fn_modified TEXT,
  resident INTEGER,
  fixup_ok INTEGER,
  streams TEXT
);
CREATE INDEX IF NOT EXISTS ix_node_parent ON node(parent);
"""

_COLS = ("mft", "parent", "name", "is_dir", "deleted", "size", "created",
         "modified", "accessed", "mft_modified", "fn_created", "fn_modified",
         "resident", "fixup_ok", "streams")

def stamp(image_path, offset):
    try:
        st = os.stat(image_path)
    except OSError:
        return None
    return "%d:%d:%d:%d" % (VERSION, offset, st.st_size, int(st.st_mtime))

PREFIX = "mft-"

def prefix_for(image_path):
    base = os.path.basename(image_path or "") or "image"
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in base)[:60]
    return "%s%s-" % (PREFIX, safe)

def path_for(cache_dir, image_path, offset):
    return os.path.join(cache_dir,
                        "%s%d.sqlite" % (prefix_for(image_path), offset))

def save(path, tree, built_from):
    if not built_from:
        return False
    nodes, _children = tree
    tmp = path + ".part"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        for leftover in (tmp, tmp + "-journal"):
            if os.path.exists(leftover):
                os.remove(leftover)
        db = sqlite3.connect(tmp)
        try:
            db.executescript(SCHEMA)
            db.execute("INSERT OR REPLACE INTO meta VALUES ('stamp',?)",
                       (built_from,))
            db.executemany(
                "INSERT INTO node (%s) VALUES (%s)"
                % (",".join(_COLS), ",".join("?" * len(_COLS))),
                (_row(n, d) for n, d in nodes.items()))
            db.commit()
        finally:
            db.close()
        os.replace(tmp, path)
        return True
    except Exception:
        for leftover in (tmp, tmp + "-journal"):
            try:
                if os.path.exists(leftover):
                    os.remove(leftover)
            except OSError:
                pass
        return False

def _row(n, d):
    streams = d.get("streams")
    return (n, d.get("parent"), d.get("name"),
            1 if d.get("is_dir") else 0, 1 if d.get("deleted") else 0,
            d.get("size"), d.get("created"), d.get("modified"),
            d.get("accessed"), d.get("mft_modified"), d.get("fn_created"),
            d.get("fn_modified"),
            None if d.get("resident") is None else int(d["resident"]),
            None if d.get("fixup_ok") is None else int(d["fixup_ok"]),
            json.dumps(streams) if streams else None)

def load(path, want_stamp):
    if not want_stamp or not os.path.isfile(path):
        return None
    try:
        db = sqlite3.connect("file:%s?mode=ro" % path.replace("?", "%3f"),
                             uri=True)
    except Exception:
        return None
    try:
        row = db.execute("SELECT v FROM meta WHERE k='stamp'").fetchone()
        if not row or row[0] != want_stamp:
            return None
        nodes, children = {}, {}
        for (mft, parent, name, is_dir, deleted, size, created, modified,
             accessed, mft_modified, fn_created, fn_modified, resident,
             fixup_ok, streams) in db.execute(
                "SELECT %s FROM node" % ",".join(_COLS)):
            nodes[mft] = {
                "mft": mft, "name": name, "is_dir": bool(is_dir),
                "deleted": bool(deleted), "size": size,
                "parent": parent, "created": created, "modified": modified,
                "accessed": accessed, "mft_modified": mft_modified,
                "resident": None if resident is None else bool(resident),
                "streams": json.loads(streams) if streams else [],
                "system": mft < 16,
                "fixup_ok": None if fixup_ok is None else bool(fixup_ok),
                "id": "mft:%d" % mft,
            }
            if fn_created is not None:
                nodes[mft]["fn_created"] = fn_created
            if fn_modified is not None:
                nodes[mft]["fn_modified"] = fn_modified
            children.setdefault(parent, []).append(mft)
        if not nodes:
            return None
        return nodes, children
    except Exception:
        return None
    finally:
        db.close()
