import datetime
import json
import os
import math
import sqlite3
import threading
import time
import uuid

from .filesearch import DEFAULT_BUDGET, PROGRESS_EVERY

FIELDS = [
    ("created", "created", "standard"),
    ("modified", "modified", "standard"),
    ("accessed", "accessed", "standard"),
    ("changed", "metadata changed", "standard"),
    ("mft_modified", "MFT record changed", "standard"),
    ("deleted_at", "deleted", "standard"),
    ("added", "added to directory", "standard"),
    ("fn_created", "created", "$FILE_NAME"),
    ("fn_modified", "modified", "$FILE_NAME"),
    ("fn_accessed", "accessed", "$FILE_NAME"),
    ("fn_mft_modified", "MFT record changed", "$FILE_NAME"),
]

MAX_DEPTH = 64

BATCH = 5000

PAGE_MAX = 2000

NOTE = ("Times are as recorded on the media. No timezone conversion has been "
        "applied: FAT and exFAT store local time with no offset, while NTFS, "
        "ext and APFS store UTC. On a disk carrying both, they are not "
        "directly comparable without knowing the machine's timezone.")

_UTC = datetime.timezone.utc

def _parse(ts):
    if not ts or not isinstance(ts, str):
        return None
    try:
        t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=_UTC)

def _node_id(entry):
    for key in ("mft", "inode", "oid", "cnid", "start_cluster"):
        if entry.get(key) is not None:
            return entry[key]
    return None

def root_of(fs):
    root = getattr(fs, "root_node", None)
    if root is None:
        root = {"NTFS": 5, "ext4": 2, "ext3": 2, "ext2": 2,
                "APFS": 2}.get(fs.name, 0)
    return root

def walk(fs, root=None, path="/", budget=DEFAULT_BUDGET, state=None,
         progress=None):
    if root is None:
        root = root_of(fs)
    stack = [(root, path, 0)]
    seen = set()
    count = 0
    while stack:
        node, cur, depth = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        try:
            entries = fs.listdir(node, cur)
        except Exception:
            if state is not None:
                state["unreadable"] = state.get("unreadable", 0) + 1
            continue
        for e in entries:
            if count >= budget:
                if state is not None:
                    state["truncated"] = True
                return
            count += 1
            if progress is not None and count % PROGRESS_EVERY == 1:
                progress(count)
            yield e
            if e.get("is_dir") and not e.get("deleted"):
                nid = _node_id(e)
                if nid is None:
                    continue
                if depth + 1 > MAX_DEPTH:
                    if state is not None:
                        state["too_deep"] = state.get("too_deep", 0) + 1
                    continue
                stack.append((nid, e.get("path", cur), depth + 1))

def anomalies(entry):
    out = []
    si_c = _parse(entry.get("created"))
    si_m = _parse(entry.get("modified"))
    fn_c = _parse(entry.get("fn_created"))
    fn_m = _parse(entry.get("fn_modified"))

    if si_c and fn_c and si_c < fn_c:
        out.append({
            "kind": "si_before_fn",
            "detail": "The $STANDARD_INFORMATION creation time is earlier than "
                      "the $FILE_NAME creation time. Only the first is "
                      "writable from user space, so a file appearing to "
                      "predate its own name entry is the usual result of "
                      "backdating.",
            "severity": "high",
        })
    if si_c and si_m and si_c > si_m:
        out.append({
            "kind": "created_after_modified",
            "detail": "Creation time is later than modification time. This "
                      "happens legitimately when a file is copied, so it is "
                      "weak on its own.",
            "severity": "low",
        })
    whole = [t for t in (si_c, si_m) if t and t.microsecond == 0]
    fractional = [t for t in (fn_c, fn_m) if t and t.microsecond != 0]
    if len(whole) == 2 and fractional:
        out.append({
            "kind": "second_granularity",
            "detail": "$STANDARD_INFORMATION times land exactly on whole "
                      "seconds while $FILE_NAME keeps sub-second precision. "
                      "Timestamps written by the kernel normally retain "
                      "fractions; several timestomping tools do not.",
            "severity": "medium",
        })
    return out

def _bounds(start, end):
    lo = _parse(start) if isinstance(start, str) else start
    hi = _parse(end) if isinstance(end, str) else end
    return lo, hi

def _offset_of(fs, entry, part_offset):
    try:
        runs = fs.stat(entry).get("runs") or []
    except Exception:
        return None
    live = [r for r in runs if not r.get("sparse")]
    return live[0]["offset"] + part_offset if live else None

def events_of(entry, offset, include_accessed=True, lo=None, hi=None):
    marks = anomalies(entry)
    out = []
    for key, label, source in FIELDS:
        if key == "accessed" and not include_accessed:
            continue
        t = _parse(entry.get(key))
        if not t:
            continue
        if lo and t < lo:
            continue
        if hi and t > hi:
            continue
        out.append({
            "time": entry[key],
            "sort": t.timestamp(),
            "action": label,
            "source": source,
            "name": entry.get("name"),
            "path": entry.get("path", entry.get("name")),
            "is_dir": bool(entry.get("is_dir")),
            "deleted": bool(entry.get("deleted")),
            "size": entry.get("size", 0),
            "node": _node_id(entry),
            "offset": offset,
            "flagged": bool(marks),
        })
    return out, marks

def flag_record(entry, offset, marks):
    return {
        "path": entry.get("path", entry.get("name")),
        "name": entry.get("name"),
        "node": _node_id(entry),
        "offset": offset,
        "observations": marks,
        "created": entry.get("created"),
        "fn_created": entry.get("fn_created"),
        "modified": entry.get("modified"),
        "fn_modified": entry.get("fn_modified"),
    }

def _order(e):
    return (e["sort"], e["path"] or "", e["action"])

def build(fs, part_offset=0, start=None, end=None, include_accessed=True,
          max_entries=DEFAULT_BUDGET, progress=None):
    lo, hi = _bounds(start, end)
    events, flagged = [], []
    files = deleted = 0
    state = {}
    tick = (lambda n: progress(0.0, count=n)) if progress else None
    for entry in walk(fs, budget=max_entries, state=state, progress=tick):
        files += 1
        if entry.get("deleted"):
            deleted += 1
        offset = _offset_of(fs, entry, part_offset)
        evs, marks = events_of(entry, offset, include_accessed, lo, hi)
        if marks:
            flagged.append(flag_record(entry, offset, marks))
        events.extend(evs)

    events.sort(key=_order)
    span = None
    if events:
        span = {"first": events[0]["time"], "last": events[-1]["time"]}
    return {
        "events": events,
        "count": len(events),
        "files": files,
        "deleted_files": deleted,
        "span": span,
        "flagged": flagged,
        "truncated": bool(state.get("truncated")),
        "too_deep": state.get("too_deep", 0),
        "filesystem": fs.name,
        "note": NOTE,
    }

# Each file's path and name are stored once, in files, and events refer to
# them by fid. fids and aids are handed out in path and action order, so
# ordering events by (sort, fid, aid, id) is the same order as by
# (sort, path, action, id). The events and flags views give readers the
# columns a timeline has always had.
SCHEMA = """
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE files (fid INTEGER PRIMARY KEY, path TEXT NOT NULL, name TEXT);
CREATE TABLE actions (aid INTEGER PRIMARY KEY, action TEXT NOT NULL);
CREATE TABLE labels (lid INTEGER PRIMARY KEY, label TEXT NOT NULL);
CREATE TABLE ev (
    id INTEGER PRIMARY KEY,
    sort REAL NOT NULL, time TEXT NOT NULL,
    aid INTEGER NOT NULL, src INTEGER,
    fid INTEGER NOT NULL, name TEXT,
    is_dir INTEGER NOT NULL, deleted INTEGER NOT NULL, size INTEGER,
    node TEXT, offset INTEGER, flagged INTEGER NOT NULL,
    ev INTEGER, xid INTEGER, part INTEGER, tags TEXT,
    partial INTEGER NOT NULL);
CREATE TABLE fl (
    ev INTEGER, part INTEGER, node TEXT, fid INTEGER NOT NULL, name TEXT,
    offset INTEGER, observations TEXT NOT NULL,
    created TEXT, fn_created TEXT, modified TEXT, fn_modified TEXT);
CREATE VIEW events AS
    SELECT e.id, e.sort, e.time, a.action, s.label AS source,
           COALESCE(e.name, f.name) AS name, f.path, e.is_dir, e.deleted,
           e.size, e.node, e.offset, e.flagged, e.ev, x.label AS exhibit,
           e.part, e.tags, e.partial, e.fid, e.aid
    FROM ev e JOIN files f ON f.fid = e.fid JOIN actions a ON a.aid = e.aid
    LEFT JOIN labels s ON s.lid = e.src LEFT JOIN labels x ON x.lid = e.xid;
CREATE VIEW flags AS
    SELECT l.ev, l.part, l.node, f.path, COALESCE(l.name, f.name) AS name,
           l.offset, l.observations, l.created, l.fn_created, l.modified,
           l.fn_modified
    FROM fl l JOIN files f ON f.fid = l.fid;
"""

# Rows are staged against provisional file and action numbers while the
# timeline is built, because the final numbering depends on every path.
_STAGE = """
CREATE TABLE s_ev (
    id INTEGER PRIMARY KEY, sort REAL, time TEXT, pa INTEGER, src INTEGER,
    pf INTEGER, name TEXT, is_dir INTEGER, deleted INTEGER, size INTEGER,
    node TEXT, offset INTEGER, flagged INTEGER, ev INTEGER, xid INTEGER,
    part INTEGER, tags TEXT, partial INTEGER);
CREATE TABLE s_fl (
    seq INTEGER PRIMARY KEY, ev INTEGER, part INTEGER, node TEXT, pf INTEGER,
    name TEXT, offset INTEGER, observations TEXT, created TEXT,
    fn_created TEXT, modified TEXT, fn_modified TEXT);
"""

_INSERT_EVENT = (
    "INSERT INTO s_ev (sort,time,pa,src,pf,name,is_dir,deleted,size,node,"
    "offset,flagged,ev,xid,part,tags,partial) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")

def _replace(src, dest, tries=30):
    for i in range(tries):
        try:
            os.replace(src, dest)
            return
        except PermissionError:
            if i == tries - 1:
                raise
            time.sleep(0.1)

class Writer:

    def __init__(self, dest):
        self.dest = dest
        self.part = "%s.%s.part" % (dest, uuid.uuid4().hex[:12])
        self.stage = self.part + ".stage"
        self.db = sqlite3.connect(self.stage)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.executescript(_STAGE)
        self._pending = []
        self.count = 0
        self.flags = 0
        self._minutes = {}
        self._files = {}
        self._actions = {}
        self._labels = {}

    def _file(self, path, name):
        got = self._files.get(path)
        if got is None:
            got = self._files[path] = (len(self._files) + 1, name)
        return got[0], (None if name == got[1] else name)

    def _action(self, action):
        got = self._actions.get(action)
        if got is None:
            got = self._actions[action] = len(self._actions) + 1
        return got

    def _label(self, label):
        if label is None:
            return None
        got = self._labels.get(label)
        if got is None:
            got = self._labels[label] = len(self._labels) + 1
        return got

    def add_events(self, events, ev=None, exhibit=None, part=None, tags=None,
                   partial=False):
        xid = self._label(exhibit)
        for e in events:
            m = int(e["sort"] // 60)
            got = self._minutes.get(m)
            if got is None:
                got = self._minutes[m] = [0, 0]
            got[0] += 1
            if e["flagged"]:
                got[1] += 1
            pf, name = self._file(e["path"] or "", e["name"])
            self._pending.append((
                e["sort"], e["time"], self._action(e["action"]),
                self._label(e["source"]), pf, name,
                int(e["is_dir"]), int(e["deleted"]),
                e["size"], None if e["node"] is None else str(e["node"]),
                e["offset"], int(e["flagged"]), ev, xid, part, tags,
                int(bool(partial))))
        self.count += len(events)
        if len(self._pending) >= BATCH:
            self._flush()

    def add_flag(self, flag, ev=None, part=None):
        pf, name = self._file(flag["path"] or "", flag["name"])
        self.db.execute(
            "INSERT INTO s_fl (ev,part,node,pf,name,offset,observations,"
            "created,fn_created,modified,fn_modified) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (ev, part, None if flag["node"] is None else str(flag["node"]),
             pf, name, flag["offset"],
             json.dumps(flag["observations"]), flag["created"],
             flag["fn_created"], flag["modified"], flag["fn_modified"]))
        self.flags += 1

    def _flush(self):
        if self._pending:
            self.db.executemany(_INSERT_EVENT, self._pending)
            self._pending = []

    def finish(self, summary):
        self._flush()
        paths = sorted(self._files)
        actions = sorted(self._actions)
        # Provisional number -> final number, kept beside the staged rows so
        # the renumbering is a join rather than a pass through Python.
        self.db.execute("CREATE TABLE pmap (prov INTEGER PRIMARY KEY, "
                        "fid INTEGER NOT NULL)")
        self.db.executemany("INSERT INTO pmap VALUES (?,?)",
                            ((self._files[p][0], i + 1)
                             for i, p in enumerate(paths)))
        self.db.execute("CREATE TABLE amap (prov INTEGER PRIMARY KEY, "
                        "aid INTEGER NOT NULL)")
        self.db.executemany("INSERT INTO amap VALUES (?,?)",
                            ((self._actions[a], i + 1)
                             for i, a in enumerate(actions)))
        self.db.commit()
        self.db.close()

        self.db = sqlite3.connect(self.part)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.executescript(SCHEMA)
        self.db.executemany("INSERT INTO files VALUES (?,?,?)",
                            ((i + 1, p, self._files[p][1])
                             for i, p in enumerate(paths)))
        self.db.executemany("INSERT INTO actions VALUES (?,?)",
                            ((i + 1, a) for i, a in enumerate(actions)))
        self.db.executemany("INSERT INTO labels VALUES (?,?)",
                            ((i, l) for l, i in self._labels.items()))
        self.db.execute("ATTACH DATABASE ? AS stage", (self.stage,))
        self.db.execute(
            "INSERT INTO ev SELECT s.id, s.sort, s.time, a.aid, s.src, p.fid, "
            "s.name, s.is_dir, s.deleted, s.size, s.node, s.offset, "
            "s.flagged, s.ev, s.xid, s.part, s.tags, s.partial "
            "FROM stage.s_ev s JOIN stage.pmap p ON p.prov = s.pf "
            "JOIN stage.amap a ON a.prov = s.pa ORDER BY s.id")
        self.db.execute(
            "INSERT INTO fl SELECT s.ev, s.part, s.node, p.fid, s.name, "
            "s.offset, s.observations, s.created, s.fn_created, s.modified, "
            "s.fn_modified FROM stage.s_fl s "
            "JOIN stage.pmap p ON p.prov = s.pf ORDER BY s.seq")
        self.db.commit()
        self.db.execute("DETACH DATABASE stage")
        _unlink(self.stage)
        self.db.execute("CREATE INDEX ev_order ON ev(sort, fid, aid)")
        self.db.execute("CREATE INDEX fl_item ON fl(ev, part, node)")
        self.db.execute(_BUCKETS_TABLE % "buckets")
        self.db.executemany(
            "INSERT INTO buckets VALUES (?,?,?)",
            ((m, c[0], c[1]) for m, c in self._minutes.items()))
        order = " ORDER BY sort %s, fid %s, aid %s, id %s LIMIT 1"
        first = self.db.execute(
            "SELECT time FROM ev" + order % (("ASC",) * 4)).fetchone()
        last = self.db.execute(
            "SELECT time FROM ev" + order % (("DESC",) * 4)).fetchone()
        out = dict(summary)
        out["count"] = self.count
        out["flagged"] = self.flags
        out["span"] = ({"first": first[0], "last": last[0]}
                       if first else None)
        self.db.execute("INSERT INTO meta VALUES ('summary', ?)",
                        (json.dumps(out, default=str),))
        self.db.commit()
        self.db.close()
        _replace(self.part, self.dest)
        return out

    def abandon(self):
        try:
            self.db.close()
        except Exception:
            pass
        _unlink(self.part)
        _unlink(self.stage)

def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass

def _open(path):
    if not path or not os.path.isfile(path):
        return None
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db

def summary(path):
    db = _open(path)
    if db is None:
        return None
    try:
        row = db.execute("SELECT v FROM meta WHERE k='summary'").fetchone()
        return json.loads(row[0]) if row else None
    finally:
        db.close()

def _row(r):
    d = dict(r)
    d.pop("fid", None)
    d.pop("aid", None)
    for k in ("is_dir", "deleted", "flagged", "partial"):
        d[k] = bool(d[k])
    return d

def _normalised(db):
    # A timeline written before paths were stored once keeps its events
    # table as it was, and is read the way it always was.
    return _has_table(db, "files")

def _event_rows(db):
    # For what needs only an event's own columns -- times, flags -- the
    # table itself, without joining in paths it would not use.
    return "ev" if _normalised(db) else "events"

def _filters(q=None, flagged=False, start=None, end=None):
    where, args = [], []
    if q:
        like = "%" + (q.replace("\\", "\\\\").replace("%", "\\%")
                      .replace("_", "\\_")) + "%"
        where.append("(path LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\')")
        args += [like, like]
    if flagged:
        where.append("flagged = 1")
    if start is not None:
        where.append("sort >= ?")
        args.append(float(start))
    if end is not None:
        where.append("sort < ?")
        args.append(float(end))
    return where, args

def page(path, cursor=None, limit=400, q=None, flagged=False, start=None,
         end=None):
    db = _open(path)
    if db is None:
        return None
    try:
        where, args = _filters(q, flagged, start, end)
        # fid and aid follow path and action order, so ordering by them is
        # ordering by path and action.
        k1, k2 = ("fid", "aid") if _normalised(db) else ("path", "action")

        matched = None
        if cursor is None:
            matched = db.execute(
                "SELECT COUNT(*) FROM %s" % (_event_rows(db) if not q
                                             else "events")
                + (" WHERE " + " AND ".join(where) if where else ""),
                args).fetchone()[0]

        keyed, kargs = list(where), list(args)
        if cursor is not None:
            s, p, a, i = cursor
            keyed.append(
                "(sort > ? OR (sort = ? AND (%s > ? OR (%s = ? AND "
                "(%s > ? OR (%s = ? AND id > ?))))))" % (k1, k1, k2, k2))
            kargs += [s, s, p, p, a, a, i]
        limit = max(1, min(int(limit), PAGE_MAX))
        rows = db.execute(
            "SELECT * FROM events"
            + (" WHERE " + " AND ".join(keyed) if keyed else "")
            + " ORDER BY sort, %s, %s, id LIMIT ?" % (k1, k2),
            kargs + [limit + 1]).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        nxt = ([rows[-1]["sort"], rows[-1][k1], rows[-1][k2],
                rows[-1]["id"]] if rows else cursor)
        return {"rows": [_row(r) for r in rows], "cursor": nxt,
                "done": not more, "matched": matched}
    finally:
        db.close()

TAIL = 0.001

_BUCKETS_TABLE = ("CREATE TABLE %s (m INTEGER PRIMARY KEY, "
                  "n INTEGER NOT NULL, f INTEGER NOT NULL)")

_BAR = "b0 - (? + b0 * ? > sort) + (? + (b0 + 1) * ? <= sort)"

_bucket_lock = threading.Lock()

def _has_table(db, name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                      "AND name=?", (name,)).fetchone() is not None

_minutes_cache = {}

def _count_minutes(db):
    minutes = {}
    for sort, flagged in db.execute("SELECT sort, flagged FROM %s"
                                    % _event_rows(db)):
        m = int(sort // 60)
        got = minutes.get(m)
        if got is None:
            got = minutes[m] = [0, 0]
        got[0] += 1
        got[1] += flagged
    return minutes

def _cached_minutes(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (os.path.abspath(path), st.st_size, st.st_mtime_ns)
    got = _minutes_cache.get(key)
    if got is None:
        db = _open(path)
        if db is None:
            return None
        try:
            got = _count_minutes(db)
        finally:
            db.close()
        for k in [k for k in _minutes_cache if k[0] == key[0]]:
            del _minutes_cache[k]
        _minutes_cache[key] = got
    return got

def _ensure_buckets(path):
    db = _open(path)
    if db is None:
        return False
    try:
        if _has_table(db, "buckets"):
            return True
    finally:
        db.close()
    with _bucket_lock:
        db = _open(path)
        try:
            if db is None or _has_table(db, "buckets"):
                return db is not None
        finally:
            if db is not None:
                db.close()
        minutes = _cached_minutes(path)
        if minutes is None:
            return False
        try:
            db = sqlite3.connect(path, timeout=15)
        except sqlite3.Error:
            return False
        try:
            db.execute("BEGIN IMMEDIATE")
            if _has_table(db, "buckets"):
                db.rollback()
                return True
            db.execute("DROP TABLE IF EXISTS buckets_building")
            db.execute(_BUCKETS_TABLE % "buckets_building")
            db.executemany(
                "INSERT INTO buckets_building VALUES (?,?,?)",
                ((m, c[0], c[1]) for m, c in minutes.items()))
            db.execute("ALTER TABLE buckets_building RENAME TO buckets")
            db.commit()
            return True
        except sqlite3.Error:
            try:
                db.rollback()
            except sqlite3.Error:
                pass
            return False
        finally:
            db.close()

def _empty(bins):
    return {"lo": 0.0, "hi": 60.0, "width": 60.0 / bins, "bins": [0] * bins,
            "before": 0, "after": 0, "total": 0, "full": None,
            "trimmed": False, "by": "event"}

def _minute(t):
    return (t // 60) * 60

def histogram(path, bins=300, start=None, end=None, q=None, flagged=False):
    db = _open(path)
    if db is None:
        return None
    db.close()
    fast = _ensure_buckets(path)
    db = _open(path)
    try:
        rows_of = _event_rows(db)
        if not fast:
            minutes = _cached_minutes(path)
            if minutes is not None:
                db.execute("PRAGMA query_only=OFF")
                db.execute("CREATE TEMP TABLE buckets (m INTEGER PRIMARY KEY, "
                           "n INTEGER NOT NULL, f INTEGER NOT NULL)")
                db.executemany(
                    "INSERT INTO temp.buckets VALUES (?,?,?)",
                    ((m, c[0], c[1]) for m, c in minutes.items()))
                db.execute("PRAGMA query_only=ON")
                fast = True
        bins = max(1, min(int(bins), 1000))
        if fast:
            m0, m1, total_all = db.execute(
                "SELECT MIN(m), MAX(m), SUM(n) FROM buckets").fetchone()
            if m0 is None:
                return _empty(bins)
            full_lo = float(m0 * 60)
            full_hi = float((m1 + 1) * 60)
        else:
            s0, s1, total_all = db.execute(
                "SELECT MIN(sort), MAX(sort), COUNT(*) FROM %s"
                % rows_of).fetchone()
            if s0 is None:
                return _empty(bins)
            full_lo = _minute(s0)
            full_hi = _minute(s1) + 60

        trimmed = False
        if start is None or end is None:
            lo, hi = full_lo, full_hi
            k = int(total_all * TAIL)
            if k > 0:
                first = db.execute("SELECT sort FROM %s ORDER BY sort "
                                   "LIMIT 1 OFFSET ?" % rows_of,
                                   (k,)).fetchone()
                last = db.execute("SELECT sort FROM %s ORDER BY sort DESC "
                                  "LIMIT 1 OFFSET ?" % rows_of,
                                  (k,)).fetchone()
                if first and last:
                    t_lo, t_hi = _minute(first[0]), _minute(last[0]) + 60
                    if t_lo < t_hi and (t_hi - t_lo) < 0.5 * (full_hi - full_lo):
                        lo, hi, trimmed = t_lo, t_hi, True
        else:
            lo, hi = float(start), float(end)
        if hi <= lo:
            hi = lo + 60

        width = (hi - lo) / bins
        if width >= 60:
            width = math.ceil(width / 60) * 60
            lo = _minute(lo)
            n = max(1, int(math.ceil((hi - lo) / width)))
            hi = lo + n * width
        else:
            n = bins
            hi = lo + n * width

        counts = [0] * n
        before = after = 0
        col = "f" if flagged else "n"
        if fast and not q and width >= 60:
            by = "minute"
            m_lo = int(lo // 60)
            step = int(width // 60)
            m_hi = m_lo + n * step
            for b, c in db.execute(
                    "SELECT (m - ?) / ?, SUM(%s) FROM buckets "
                    "WHERE m >= ? AND m < ? GROUP BY 1" % col,
                    (m_lo, step, m_lo, m_hi)):
                counts[int(b)] = int(c or 0)
            before = db.execute("SELECT COALESCE(SUM(%s), 0) FROM buckets "
                                "WHERE m < ?" % col, (m_lo,)).fetchone()[0]
            after = db.execute("SELECT COALESCE(SUM(%s), 0) FROM buckets "
                               "WHERE m >= ?" % col, (m_hi,)).fetchone()[0]
        elif fast and not q:
            by = "event"
            where, args = _filters(None, flagged, lo, hi)
            for b, c in db.execute(
                    "SELECT " + _BAR + " AS b, COUNT(*) FROM (SELECT sort, "
                    "CAST((sort - ?) / ? AS INTEGER) AS b0 FROM " + rows_of
                    + " WHERE " + " AND ".join(where) + ") GROUP BY b",
                    [lo, width, lo, width, lo, width] + args):
                counts[max(0, min(int(b), n - 1))] += c
            edge_lo, edge_hi = _minute(lo), _minute(hi)
            if hi > edge_hi:
                edge_hi += 60
            w, a = _filters(None, flagged, edge_lo, lo)
            before = (db.execute("SELECT COALESCE(SUM(%s), 0) FROM buckets "
                                 "WHERE m < ?" % col,
                                 (int(edge_lo // 60),)
                                 ).fetchone()[0]
                      + db.execute("SELECT COUNT(*) FROM " + rows_of + " WHERE "
                                   + " AND ".join(w), a).fetchone()[0])
            w, a = _filters(None, flagged, hi, edge_hi)
            after = (db.execute("SELECT COALESCE(SUM(%s), 0) FROM buckets "
                                "WHERE m >= ?" % col,
                                (int(edge_hi // 60),)
                                ).fetchone()[0]
                     + db.execute("SELECT COUNT(*) FROM " + rows_of + " WHERE "
                                  + " AND ".join(w), a).fetchone()[0])
        else:
            by = "event"
            where, args = _filters(q, flagged)
            clause = (" WHERE " + " AND ".join(where)) if where else ""
            for b, c in db.execute(
                    "SELECT CASE WHEN sort < ? THEN -1 WHEN sort >= ? THEN -2 "
                    "ELSE " + _BAR + " END AS b, COUNT(*) FROM (SELECT sort, "
                    "CAST((sort - ?) / ? AS INTEGER) AS b0 FROM "
                    + ("events" if q else rows_of) + clause + ") GROUP BY b",
                    [lo, hi, lo, width, lo, width, lo, width] + args):
                b = int(b)
                if b == -1:
                    before += c
                elif b == -2:
                    after += c
                else:
                    counts[max(0, min(b, n - 1))] += c

        return {"lo": lo, "hi": hi, "width": width, "bins": counts,
                "before": int(before), "after": int(after),
                "total": int(sum(counts) + before + after),
                "full": {"lo": full_lo, "hi": full_hi},
                "trimmed": trimmed, "by": by}
    finally:
        db.close()

def observations(path, ev, part, node):
    db = _open(path)
    if db is None:
        return None
    try:
        r = db.execute(
            "SELECT * FROM flags WHERE ev IS ? AND part IS ? AND node IS ? "
            "LIMIT 1", (ev, part, node)).fetchone()
        if r is None:
            return None
        out = dict(r)
        out["observations"] = json.loads(out["observations"])
        return out
    finally:
        db.close()

def build_volume(writer, fs, ev=None, exhibit=None, part_offset=0,
                 include_accessed=True, start=None, end=None,
                 budget=DEFAULT_BUDGET, progress=None, extra=None):
    lo, hi = _bounds(start, end)
    state = {}
    files = deleted = 0
    for entry in walk(fs, budget=budget, state=state, progress=progress):
        files += 1
        if entry.get("deleted"):
            deleted += 1
        offset = _offset_of(fs, entry, part_offset)
        evs, marks = events_of(entry, offset, include_accessed, lo, hi)
        writer.add_events(evs, ev, exhibit, part_offset)
        if marks:
            writer.add_flag(flag_record(entry, offset, marks), ev, part_offset)
    out = {
        "scope": "volume", "files": files, "deleted_files": deleted,
        "truncated": bool(state.get("truncated")),
        "too_deep": state.get("too_deep", 0),
        "unreadable": state.get("unreadable", 0),
        "budget": budget, "filesystem": fs.name,
        "sources": [exhibit] if exhibit else [],
    }
    out.update(extra or {})
    return writer.finish(out)

def resolve(fs, path, node=None, cache=None):
    names = [p for p in (path or "").split("/") if p]
    if not names:
        return None, "not_found"
    cache = {} if cache is None else cache
    handle, cur = root_of(fs), "/"
    want = None if node in (None, "", "None", "null") else str(node)
    for i, name in enumerate(names):
        key = (handle, cur)
        entries = cache.get(key)
        if entries is None:
            try:
                entries = fs.listdir(handle, cur)
            except Exception:
                return None, "not_found"
            cache[key] = entries
        cands = [e for e in entries if e.get("name") == name]
        if not cands:
            return None, "not_found"
        if i == len(names) - 1:
            if want is not None:
                hit = next((e for e in cands if str(_node_id(e)) == want),
                           None)
                if hit is not None:
                    return hit, "handle"
            if len(cands) == 1:
                return cands[0], "name"
            return None, "ambiguous"
        dirs = [e for e in cands if e.get("is_dir")]
        pick = next((e for e in dirs if not e.get("deleted")),
                    dirs[0] if dirs else None)
        if pick is None or _node_id(pick) is None:
            return None, "not_found"
        handle = _node_id(pick)
        cur = pick.get("path") or (cur.rstrip("/") + "/" + name)
    return None, "not_found"

def entry_from_tag(row):
    return {
        "name": row.get("name"),
        "path": row.get("path") or row.get("name") or "",
        "is_dir": bool(row.get("is_dir")),
        "deleted": bool(row.get("deleted")),
        "size": row.get("size") or 0,
        "modified": row.get("modified"),
        "accessed": row.get("accessed"),
        "created": row.get("file_created"),
    }

def build_tagged(writer, rows, open_volume, include_accessed=True,
                 start=None, end=None, budget=DEFAULT_BUDGET, progress=None,
                 extra=None):
    lo, hi = _bounds(start, end)
    items = {}
    for r in rows:
        k = (r["evidence_id"], r["part"], r.get("node"), r.get("path"))
        it = items.setdefault(k, dict(r, tags=[]))
        if r["tag"] not in it["tags"]:
            it["tags"].append(r["tag"])

    written = set()
    unresolved = []
    counts = {"files": 0, "deleted": 0, "by_name": 0}
    state = {}
    volumes, caches, folders = {}, {}, []

    def emit(entry, fs, ev, label, part, tags, partial):
        nid = _node_id(entry)
        key = (ev, part, ("n", str(nid)) if nid is not None
               else ("p", entry.get("path")))
        if key in written:
            return
        written.add(key)
        counts["files"] += 1
        if entry.get("deleted"):
            counts["deleted"] += 1
        offset = None if partial else _offset_of(fs, entry, part)
        evs, marks = events_of(entry, offset, include_accessed, lo, hi)
        writer.add_events(evs, ev, label, part,
                          ", ".join(tags) if tags else None, partial)
        if marks and not partial:
            writer.add_flag(flag_record(entry, offset, marks), ev, part)
        if progress is not None and counts["files"] % PROGRESS_EVERY == 1:
            progress(counts["files"])

    ordered = sorted(items.items(),
                     key=lambda kv: (kv[0][0] or 0, kv[0][1] or 0,
                                     kv[0][3] or ""))
    for (ev, part, node, path), it in ordered:
        if counts["files"] >= budget:
            state["truncated"] = True
            break
        vol = volumes.get((ev, part))
        if vol is None:
            try:
                vol = open_volume(ev, part)
            except LookupError as exc:
                vol = exc
            volumes[(ev, part)] = vol
        label = it.get("exhibit")
        if isinstance(vol, LookupError):
            entry, how = None, str(vol.args[0] if vol.args else "not_found")
        else:
            entry, how = resolve(vol, path, node,
                                 caches.setdefault((ev, part), {}))
        if entry is None:
            unresolved.append({"path": path, "name": it.get("name"),
                               "exhibit": label, "part": part,
                               "reason": how, "tags": it["tags"]})
            emit(entry_from_tag(it), None, ev, label, part, it["tags"], True)
            continue
        if how == "name":
            counts["by_name"] += 1
        emit(entry, vol, ev, label, part, it["tags"], False)
        if entry.get("is_dir"):
            folders.append((vol, entry, ev, label, part, it["tags"]))

    for fs, entry, ev, label, part, tags in folders:
        nid = _node_id(entry)
        if nid is None or state.get("truncated"):
            continue
        for child in walk(fs, root=nid, path=entry.get("path") or "/",
                          budget=max(0, budget - counts["files"]),
                          state=state):
            emit(child, fs, ev, label, part, tags, False)

    names = sorted({v.name for v in volumes.values()
                    if not isinstance(v, LookupError)})
    out = {
        "scope": "tagged",
        "files": counts["files"], "deleted_files": counts["deleted"],
        "tagged": len(items),
        "resolved_by_name": counts["by_name"],
        "unresolved": unresolved[:500],
        "unresolved_count": len(unresolved),
        "truncated": bool(state.get("truncated")),
        "too_deep": state.get("too_deep", 0),
        "budget": budget,
        "filesystem": ", ".join(names) or None,
        "sources": sorted({it.get("exhibit") or "" for it in items.values()}
                          - {""}),
    }
    out.update(extra or {})
    return writer.finish(out)
