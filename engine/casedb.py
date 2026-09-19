import functools
import hashlib
import json
import os
import sqlite3
import threading
import time
from urllib.request import pathname2url

from . import fuzzyhash
from . import version as version_mod
from .text import t as _t

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    label TEXT,
    format TEXT,
    size INTEGER,
    stored_md5 TEXT,
    stored_sha1 TEXT,
    verified_md5 TEXT,
    verified_sha1 TEXT,
    verified_at TEXT,
    kind TEXT,
    added_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    length INTEGER NOT NULL DEFAULT 1,
    label TEXT,
    note TEXT,
    tags TEXT,
    source TEXT,
    -- A category groups marks by what they are *for* ("Boot record",
    -- "Deleted file header", "Timestamp anomaly"); the colour is how it reads
    -- on the map and in the hex view. `in_report` is separate from both,
    -- because an examiner marks far more than they will produce — working
    -- marks and exhibit marks are different things, and a report that
    -- includes every byte anyone ever looked at is not a report.
    category TEXT,
    colour TEXT,
    in_report INTEGER NOT NULL DEFAULT 1,
    -- What `offset` counts from. 'media' is a place in the image, which is
    -- what every mark was before a file could be scoped to; 'file' is a
    -- file's own byte zero, and then `part` and `node` say which file, so the
    -- mark can be reopened where it was made. Without this the number in the
    -- report names a place on the disk that the examiner never looked at.
    frame TEXT NOT NULL DEFAULT 'media',
    part INTEGER,
    node TEXT,
    stream TEXT,
    -- The file's name as it read when the mark was made. `node` is what
    -- reopens it; this is what the report prints, and it is stored rather
    -- than looked up later so the report quotes the record instead of
    -- re-deriving it from evidence that may since have been removed.
    mark_in TEXT,
    created_at TEXT NOT NULL,
    examiner TEXT);

-- A tagged item is a *file*, not a byte range — that is what separates it
-- from a bookmark. It is identified by the filesystem's own handle (MFT
-- record, inode, object id, start cluster) so it survives reopening the case,
-- and it carries a copy of the metadata so a report can be written without
-- re-reading the evidence. `contiguous` is exFAT-specific: a NoFatChain
-- stream is read by extent rather than by walking the FAT, and getting that
-- wrong on a deleted item silently returns the wrong content (#94).
CREATE TABLE IF NOT EXISTS tagged_items (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL,
    part INTEGER NOT NULL DEFAULT 0,
    node TEXT,
    path TEXT,
    name TEXT,
    size INTEGER,
    is_dir INTEGER DEFAULT 0,
    deleted INTEGER DEFAULT 0,
    tag TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL,
    examiner TEXT,
    modified TEXT,
    accessed TEXT,
    file_created TEXT,
    contiguous INTEGER,
    UNIQUE (evidence_id, part, node, tag));

CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    examiner TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    prev_hash TEXT,
    hash TEXT NOT NULL);

-- A saved search is the query *and* the hits it produced. Keeping the hits
-- matters: re-running a search later can return something different once the
-- examiner has learned more, and a report has to cite what was actually seen.
CREATE TABLE IF NOT EXISTS saved_searches (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER,
    name TEXT NOT NULL,
    query TEXT,
    part INTEGER,
    hit_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    examiner TEXT);

CREATE TABLE IF NOT EXISTS search_hits (
    id INTEGER PRIMARY KEY,
    search_id INTEGER NOT NULL,
    name TEXT, path TEXT, node TEXT, size INTEGER,
    is_dir INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0,
    where_found TEXT, term TEXT, context TEXT,
    file_offset INTEGER, encoding TEXT, modified TEXT);

-- Hashes are cached because computing them costs a full read of every file,
-- and because a hash-set match is only meaningful against a recorded digest.
CREATE TABLE IF NOT EXISTS file_hashes (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL,
    part INTEGER NOT NULL DEFAULT 0,
    node TEXT, path TEXT, name TEXT, size INTEGER,
    deleted INTEGER DEFAULT 0,
    md5 TEXT, sha1 TEXT, sha256 TEXT,
    -- ssdeep-style context-triggered piecewise hash (engine/fuzzyhash.py):
    -- unlike the three above, a partial match here means the files are
    -- alike, not identical.
    fuzzy TEXT,
    -- How many bytes the digests were actually taken over. Equal to `size`
    -- for a file that read whole. Stored because a digest over a short read
    -- is not the file's digest, and sixty-four hex characters say nothing
    -- about which of the two they are -- that has to travel with them or it
    -- is lost the moment the case is closed.
    read_bytes INTEGER,
    computed_at TEXT NOT NULL,
    UNIQUE (evidence_id, part, node));

-- A parsed artefact, kept so that reading one is something an examiner does
-- once rather than once per session. Reading a change journal is half a minute
-- on a real volume and a browser sweep is longer; losing that on closing the
-- case is the difference between a tool you explore with and one you plan
-- around.
--
-- The payload is the parser's own output as JSON rather than a table per
-- artefact. That is a deliberate limit: this is a *cache of a parse*, not a
-- second copy of the evidence, and it is not queryable. Anything that needs to
-- be searched across cases — hashes, tags, search hits — has its own table
-- above and keeps it.
--
-- `parser_version` is what makes the cache safe. A stored payload was produced
-- by the code of the day, and presenting an old parse as a current one is
-- exactly the quiet wrongness this tool exists to avoid. A mismatch discards
-- the row rather than trusting it, the same way the content index is dropped
-- when its schema moves.
CREATE TABLE IF NOT EXISTS artefacts (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL,
    part INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL,
    parser_version INTEGER NOT NULL DEFAULT 1,
    ran_at TEXT NOT NULL,
    examiner TEXT,
    bytes INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL,
    UNIQUE (evidence_id, part, kind));

-- An ATT&CK attribution: this finding evidences that behaviour.
--
-- Deliberately its own table rather than a column on tagged_items. A technique
-- can be attached to a file, a bookmarked byte range, or a row in an artefact,
-- and one finding can evidence several — none of which a column on the file
-- table could express.
--
-- `target_kind` and `target_ref` say what is being attributed. A file is
-- ("file", node); a bookmark is ("bookmark", its id); an artefact row is
-- ("artefact", "kind:index"). Keeping the reference opaque means a new kind of
-- finding becomes attributable without another migration.
--
-- `asserted` is the field that matters. An examiner saying a Run key is
-- persistence is a judgement they are answerable for; the tool proposing it is
-- not the same statement, and a report that presented the two identically
-- would read as though the software had concluded an intrusion. Suggestions
-- are stored only once accepted, and what accepted them is recorded.
CREATE TABLE IF NOT EXISTS attack_tags (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL,
    part INTEGER NOT NULL DEFAULT 0,
    target_kind TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    technique TEXT NOT NULL,
    technique_name TEXT,
    tactic TEXT,
    note TEXT,
    asserted INTEGER NOT NULL DEFAULT 1,
    catalogue TEXT,
    created_at TEXT NOT NULL,
    examiner TEXT,
    UNIQUE (evidence_id, part, target_kind, target_ref, technique));

CREATE TABLE IF NOT EXISTS hash_sets (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'known_bad',   -- known_good | known_bad | notable
    source TEXT,
    imported_at TEXT NOT NULL,
    examiner TEXT,
    entries INTEGER DEFAULT 0);

CREATE TABLE IF NOT EXISTS hash_entries (
    set_id INTEGER NOT NULL,
    algo TEXT NOT NULL,        -- md5 | sha1 | sha256
    digest TEXT NOT NULL,      -- lowercase hex
    label TEXT);

-- File-type verification results. Only mismatches are stored: the census is
-- a handful of numbers and the matches are the overwhelming majority, so
-- keeping every row would bloat the case for no benefit. Re-running replaces
-- the rows for that partition, because the answer is about the evidence as it
-- is now, not a history of scans.
CREATE TABLE IF NOT EXISTS type_mismatches (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL,
    part INTEGER NOT NULL DEFAULT 0,
    node TEXT, path TEXT, name TEXT, size INTEGER,
    deleted INTEGER DEFAULT 0,
    modified TEXT,
    extension TEXT,
    extension_says TEXT,
    detected TEXT,
    content_is TEXT,
    severity TEXT,
    why TEXT,
    found_at TEXT NOT NULL,
    UNIQUE (evidence_id, part, node, name));

CREATE INDEX IF NOT EXISTS idx_tm ON type_mismatches(evidence_id, part);
CREATE INDEX IF NOT EXISTS idx_bm_ev ON bookmarks(evidence_id, offset);
CREATE INDEX IF NOT EXISTS idx_tag_ev ON tagged_items(evidence_id, tag);
CREATE INDEX IF NOT EXISTS idx_hits ON search_hits(search_id);
CREATE INDEX IF NOT EXISTS idx_fh ON file_hashes(evidence_id, part);
CREATE INDEX IF NOT EXISTS idx_fh_md5 ON file_hashes(md5);
CREATE INDEX IF NOT EXISTS idx_fh_sha1 ON file_hashes(sha1);
CREATE INDEX IF NOT EXISTS idx_he ON hash_entries(digest, algo);
"""

INDEX_META_SCHEMA = """
CREATE TABLE IF NOT EXISTS index_meta (key TEXT PRIMARY KEY, value TEXT);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS content_index USING fts5(
    name, path, body,
    node UNINDEXED, part UNINDEXED, size UNINDEXED,
    deleted UNINDEXED, modified UNINDEXED,
    abs_offset UNINDEXED, kind UNINDEXED, evidence UNINDEXED,
    tokenize = 'unicode61');
"""

FTS_COLUMNS = {"name", "path", "body", "node", "part", "size", "deleted",
               "modified", "abs_offset", "kind", "evidence"}

ARTEFACT_VERSION = {
    "browser": 2, "recyclebin": 1, "lnk": 2, "appcompat": 1, "prefetch": 1,
    "shellbags": 1, "mail": 1, "leveldb": 1, "vss": 1, "usn": 1,
    "carve": 1, "timeline": 1, "evtx": 1, "wallets": 1,
}

ARTEFACT_MAX_BYTES = 64 << 20

DEFAULT_TAGS = [
    "Evidence", "Relevant", "For review", "Contraband", "Exculpatory",
    "Encrypted", "Export",
]

MARK_CATEGORIES = [
    {"name": "Evidence",       "colour": "#c4614c"},
    {"name": "Structure",      "colour": "#4e7c9b"},
    {"name": "Deleted",        "colour": "#b98a4e"},
    {"name": "Timestamp",      "colour": "#6fa8a0"},
    {"name": "Encrypted",      "colour": "#8f6bb0"},
    {"name": "Anomaly",        "colour": "#d08a2f"},
    {"name": "Working note",   "colour": "#6e8290"},
]

_CASE_LOCKS = {}
_LOCKS_GUARD = threading.Lock()

def _case_lock(path):
    key = os.path.abspath(path)
    with _LOCKS_GUARD:
        lock = _CASE_LOCKS.get(key)
        if lock is None:
            lock = _CASE_LOCKS[key] = threading.RLock()
        return lock

def _writes(fn):
    @functools.wraps(fn)
    def wrapper(self, *a, **kw):
        with _case_lock(self.path):
            return fn(self, *a, **kw)
    return wrapper

def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

DB_NAME = "case.sqlite"
INDEX_NAME = "content-index.sqlite"
CACHE_DIR = "cache"

def infer_kind(path, fmt):
    if path and os.path.isdir(path):
        return "folder"
    known = {_t("logical.format_folder"): "folder",
             _t("logical.format_zip"): "zip",
             _t("logical.format_file"): "file"}
    return known.get(fmt, "image")

_SQLITE_MAGIC = b"SQLite format 3\x00"
_CASE_TABLES = ("meta", "evidence", "audit")

class NotACase(ValueError):
    pass

def _looks_like_case_db(db_file):
    # Decides from the header and a read-only open, so a file that is not a
    # case is never written, locked for writing, or given -journal/-wal/-shm
    # siblings: what gets pointed at here is often evidence.
    try:
        with open(db_file, "rb") as fh:
            header = fh.read(100)
    except OSError:
        return False
    if len(header) < 100 or not header.startswith(_SQLITE_MAGIC):
        return False
    if header[18] != 1 or header[19] != 1:
        # WAL mode. Strata never puts a case in WAL, and reading one would
        # need a -shm file beside it.
        return False
    uri = "file:%s?mode=ro" % pathname2url(os.path.abspath(db_file))
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return False
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if not all(t in tables for t in _CASE_TABLES):
            return False
        audit_cols = {r[1] for r in conn.execute("PRAGMA table_info(audit)")}
        return {"prev_hash", "hash"} <= audit_cols
    except sqlite3.Error:
        return False
    finally:
        conn.close()

def is_case(path):
    if not path or not os.path.isdir(path):
        return False
    return _looks_like_case_db(os.path.join(path, DB_NAME))

def _refuse_if_not_case(path):
    # A case is a folder. Nothing that already exists at the path is written
    # to unless it is one — a new case may only go where nothing is, or into
    # a folder that does not yet hold a case record.
    if not os.path.exists(path):
        return
    if not os.path.isdir(path):
        raise NotACase(_t("casedb.not_a_case") % path)
    record = os.path.join(path, DB_NAME)
    if os.path.lexists(record) and not _looks_like_case_db(record):
        raise NotACase(_t("casedb.not_a_case") % path)

def db_path(case_path):
    return os.path.join(case_path, DB_NAME)

def cache_dir(case_path, create=False):
    d = os.path.join(case_path, CACHE_DIR)
    if create:
        os.makedirs(d, exist_ok=True)
    return d

class Case:
    def __init__(self, path, name=None, examiner=None, read_only=False):
        _refuse_if_not_case(path)
        self.path = path
        self.db_path = db_path(path)
        self.examiner = examiner or os.environ.get("STRATA_EXAMINER",
                                                   "unattributed")
        if read_only:
            # A preview must not write at all: no folder creation, no schema
            # upgrade, no migrations, no cache/ index. Open the record
            # through a mode=ro URI — same pattern _looks_like_case_db uses —
            # so SQLite itself refuses every write and no -journal/-wal/-shm
            # sibling can appear.
            uri = "file:%s?mode=ro" % pathname2url(os.path.abspath(self.db_path))
            self.db = sqlite3.connect(uri, uri=True, check_same_thread=False,
                                      timeout=30.0)
            self.db.row_factory = sqlite3.Row
            self.index_reset = False
            self.index_db = None
            self.index_pending = 0
            self.index = self.db
            self.fts = False
            return
        fresh = not os.path.isfile(self.db_path)
        os.makedirs(path, exist_ok=True)
        self.db = sqlite3.connect(self.db_path, check_same_thread=False,
                                  timeout=30.0)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._migrate_bookmarks()
        self._migrate_file_hashes()
        self._migrate_fuzzy_hash()
        self._migrate_bookmark_frame()
        self._migrate_evidence_kind()
        self._migrate_tagged_items()
        self.index_reset = False
        self.index_db = None
        self.index_pending = 0
        self.index = self.db
        try:
            self._open_index()
            self.fts = True
            self.index_reset = self._migrate_fts() or self.index_reset
        except sqlite3.OperationalError:
            self.fts = False
        if fresh:
            self._set("name", name or os.path.splitext(os.path.basename(path))[0])
            self._set("created_at", utcnow())
            self._set("created_by", self.examiner)
            self.log("case.create", {"name": self.get("name"),
                                     "tool": version_mod.label()})
        self.db.commit()

    def close(self):
        for conn in (getattr(self, "index_db", None), getattr(self, "db", None)):
            if conn is None:
                continue
            try:
                conn.close()
            except Exception:
                pass
        self.index_db = None
        self.index = None

    def cache_dir(self, create=False):
        return cache_dir(self.path, create=create)

    def _migrate_evidence_kind(self):
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(evidence)")}
        if "kind" in cols:
            return
        self.db.execute("ALTER TABLE evidence ADD COLUMN kind TEXT")
        for row in self.db.execute(
                "SELECT id, path, format FROM evidence").fetchall():
            self.db.execute("UPDATE evidence SET kind=? WHERE id=?",
                            (infer_kind(row["path"], row["format"]),
                             row["id"]))
        self.db.commit()

    def _migrate_tagged_items(self):
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(tagged_items)")}
        if "contiguous" not in cols:
            self.db.execute(
                "ALTER TABLE tagged_items ADD COLUMN contiguous INTEGER")
            self.db.commit()

    def _migrate_bookmarks(self):
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(bookmarks)")}
        for name, decl in (("category", "TEXT"), ("colour", "TEXT"),
                           ("in_report", "INTEGER NOT NULL DEFAULT 1")):
            if name not in cols:
                self.db.execute("ALTER TABLE bookmarks ADD COLUMN %s %s"
                                % (name, decl))
        self.db.commit()

    def _migrate_file_hashes(self):
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(file_hashes)")}
        if "read_bytes" not in cols:
            self.db.execute("ALTER TABLE file_hashes ADD COLUMN "
                            "read_bytes INTEGER")
        self.db.commit()

    def _migrate_fuzzy_hash(self):
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(file_hashes)")}
        if "fuzzy" not in cols:
            self.db.execute("ALTER TABLE file_hashes ADD COLUMN fuzzy TEXT")
        self.db.commit()

    def _migrate_bookmark_frame(self):
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(bookmarks)")}
        if "frame" not in cols:
            self.db.execute("ALTER TABLE bookmarks ADD COLUMN "
                            "frame TEXT NOT NULL DEFAULT 'media'")
        for name, kind in (("part", "INTEGER"), ("node", "TEXT"),
                           ("stream", "TEXT"), ("mark_in", "TEXT")):
            if name not in cols:
                self.db.execute("ALTER TABLE bookmarks ADD COLUMN %s %s"
                                % (name, kind))
        self.db.commit()

    def set_index_meta(self, key, value):
        if self.index is self.db:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",
                            (key, value))
        else:
            self.index.execute(
                "INSERT OR REPLACE INTO index_meta VALUES (?,?)", (key, value))
        self.index.commit()

    def _forget_coverage(self):
        if self.index is self.db:
            self.db.execute("DELETE FROM meta WHERE key LIKE 'index_part_%'")
        else:
            try:
                self.index.execute("DELETE FROM index_meta")
            except sqlite3.Error:
                pass

    def _open_index(self):
        try:
            n = self.db.execute(
                "SELECT COUNT(*) c FROM content_index").fetchone()["c"]
        except sqlite3.Error:
            n = 0
        cache = self.cache_dir(create=True)
        self.index_db = sqlite3.connect(os.path.join(cache, INDEX_NAME),
                                        check_same_thread=False, timeout=30.0)
        self.index_db.row_factory = sqlite3.Row
        self.index_db.executescript(FTS_SCHEMA)
        self.index_db.executescript(INDEX_META_SCHEMA)
        self.index_db.commit()
        if n:
            cols = {r[1] for r in self.db.execute(
                "PRAGMA table_info(content_index)")}
            if FTS_COLUMNS <= cols:
                self.index_pending = n
                self.index = self.db
            else:
                self.db.execute("DROP TABLE IF EXISTS content_index")
                self.db.execute(
                    "DELETE FROM meta WHERE key LIKE 'index_part_%'")
                self.db.commit()
                self.index = self.index_db
                self.index_reset = True
                self.log("index.reset", {
                    "documents": n,
                    "reason": _t("casedb.index_reset_reason")})
                self.db.commit()
        else:
            self.index = self.index_db

    def relocate_index(self, progress=None):
        if not self.index_pending or self.index_db is None:
            return {"moved": 0}
        want = self.index_pending
        cache_path = os.path.join(self.cache_dir(create=True), INDEX_NAME)
        if progress:
            progress(0.05)
        self.db.execute("ATTACH DATABASE ? AS idx", (cache_path,))
        try:
            self.db.execute("DELETE FROM idx.content_index")
            self.db.execute(
                "INSERT INTO idx.content_index "
                "(name,path,body,node,part,size,deleted,modified,abs_offset,"
                " kind,evidence) "
                "SELECT name,path,body,node,part,size,deleted,modified,"
                "abs_offset,kind,evidence FROM main.content_index")
            got = self.db.execute(
                "SELECT COUNT(*) c FROM idx.content_index").fetchone()["c"]
            for row in self.db.execute(
                    "SELECT key, value FROM main.meta "
                    "WHERE key LIKE 'index_part_%'"):
                self.db.execute(
                    "INSERT OR REPLACE INTO idx.index_meta VALUES (?,?)",
                    (row["key"], row["value"]))
            self.db.commit()
        finally:
            self.db.execute("DETACH DATABASE idx")
        if progress:
            progress(0.6)
        if got != want:
            self.log("index.relocate.failed", {"expected": want, "copied": got})
            self.db.commit()
            return {"moved": 0, "expected": want, "copied": got}

        self.db.execute("DROP TABLE IF EXISTS content_index")
        self.db.execute("DELETE FROM meta WHERE key LIKE 'index_part_%'")
        self.db.commit()
        if progress:
            progress(0.7)
        self.db.execute("VACUUM")
        self.db.commit()
        self.index_pending = 0
        self.index = self.index_db
        self.log("index.relocated", {
            "documents": got, "to": os.path.join(CACHE_DIR, INDEX_NAME),
            "note": _t("casedb.index_relocated")})
        self.db.commit()
        if progress:
            progress(1.0)
        return {"moved": got}

    def _migrate_fts(self):
        cols = {r[1] for r in self.index.execute(
            "PRAGMA table_info(content_index)")}
        if FTS_COLUMNS <= cols:
            return False
        try:
            n = self.index.execute(
                "SELECT COUNT(*) c FROM content_index").fetchone()["c"]
        except sqlite3.OperationalError:
            n = 0
        self.index.execute("DROP TABLE IF EXISTS content_index")
        self.index.executescript(FTS_SCHEMA)
        self._forget_coverage()
        self.index.commit()
        if n:
            self.log("index.reset", {
                "documents": n,
                "reason": _t("casedb.index_reset_reason")})
            self.db.commit()
        return bool(n)

    @_writes
    def _set(self, k, v):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, str(v)))

    def get(self, k, default=None):
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (k,)).fetchone()
        return r["value"] if r else default

    def pulse(self):
        row = self.db.execute(
            "SELECT examiner FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return {
            "bookmarks": self.db.execute(
                "SELECT COUNT(*) c FROM bookmarks").fetchone()["c"],
            "tags": self.db.execute(
                "SELECT COUNT(*) c FROM tagged_items").fetchone()["c"],
            "audit": self.db.execute(
                "SELECT COUNT(*) c FROM audit").fetchone()["c"],
            "latest": row["examiner"] if row else None,
        }

    def summary(self):
        return {"name": self.get("name"), "created_at": self.get("created_at"),
                "created_by": self.get("created_by"), "path": self.path,
                "examiner": self.examiner,
                "evidence": [dict(r) for r in self.db.execute(
                    "SELECT * FROM evidence ORDER BY id")],
                "bookmark_count": self.db.execute(
                    "SELECT COUNT(*) c FROM bookmarks").fetchone()["c"],
                "tagged_count": self.db.execute(
                    "SELECT COUNT(*) c FROM tagged_items").fetchone()["c"],
                "audit_entries": self.db.execute(
                    "SELECT COUNT(*) c FROM audit").fetchone()["c"]}

    EVIDENCE_TABLES = ("bookmarks", "tagged_items", "saved_searches",
                       "file_hashes", "artefacts", "attack_tags",
                       "type_mismatches")

    def evidence_holdings(self, evidence_id):
        out = {}
        for table in self.EVIDENCE_TABLES:
            try:
                n = self.db.execute(
                    "SELECT COUNT(*) c FROM %s WHERE evidence_id=?" % table,
                    (evidence_id,)).fetchone()["c"]
            except sqlite3.Error:
                continue
            if n:
                out[table] = n
        try:
            n = self.index.execute(
                "SELECT COUNT(*) c FROM content_index WHERE evidence=?",
                (str(evidence_id),)).fetchone()["c"]
            if n:
                out["content_index"] = n
        except sqlite3.Error:
            pass
        return out

    @_writes
    def remove_evidence(self, evidence_id):
        row = self.db.execute("SELECT * FROM evidence WHERE id=?",
                              (evidence_id,)).fetchone()
        if row is None:
            return None
        holdings = self.evidence_holdings(evidence_id)
        self.log("evidence.remove", {
            "evidence_id": int(evidence_id), "path": row["path"],
            "label": row["label"], "removed": holdings,
            "note": _t("casedb.evidence_removed_note"),
        })
        for table in self.EVIDENCE_TABLES:
            try:
                self.db.execute("DELETE FROM %s WHERE evidence_id=?" % table,
                                (evidence_id,))
            except sqlite3.Error:
                continue
        try:
            self.index.execute("DELETE FROM content_index WHERE evidence=?",
                               (str(evidence_id),))
            self.index.commit()
        except sqlite3.Error:
            pass
        self.db.execute("DELETE FROM evidence WHERE id=?", (evidence_id,))
        self.db.commit()
        return {"path": row["path"], "label": row["label"],
                "removed": holdings}

    def log(self, action, detail=None):
        with _case_lock(self.path):
            row = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC "
                                  "LIMIT 1").fetchone()
            prev = row["hash"] if row else ""
            at = utcnow()
            payload = json.dumps(detail or {}, sort_keys=True, default=str)
            h = hashlib.sha256(
                ("%s|%s|%s|%s|%s" % (prev, at, self.examiner, action, payload))
                .encode("utf-8")).hexdigest()
            self.db.execute(
                "INSERT INTO audit (at, examiner, action, detail, prev_hash, "
                "hash) VALUES (?,?,?,?,?,?)",
                (at, self.examiner, action, payload, prev, h))
            self.db.commit()
            return h

    def audit(self, limit=500):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))]

    def verify_audit(self):
        prev = ""
        for r in self.db.execute("SELECT * FROM audit ORDER BY seq"):
            h = hashlib.sha256(
                ("%s|%s|%s|%s|%s" % (prev, r["at"], r["examiner"], r["action"],
                                     r["detail"])).encode("utf-8")).hexdigest()
            if h != r["hash"] or r["prev_hash"] != prev:
                return {"intact": False, "broken_at": r["seq"]}
            prev = r["hash"]
        return {"intact": True, "broken_at": None}

    @_writes
    def add_evidence(self, path, info, label=None):
        row = self.db.execute("SELECT id FROM evidence WHERE path=?",
                              (path,)).fetchone()
        if row:
            return row["id"]
        kind = (info.get("kind") or "file") if info.get("logical") else "image"
        cur = self.db.execute(
            "INSERT INTO evidence (path,label,format,size,stored_md5,stored_sha1,"
            "kind,added_at) VALUES (?,?,?,?,?,?,?,?)",
            (path, label or os.path.basename(path), info.get("format"),
             info.get("size"), info.get("stored_md5"), info.get("stored_sha1"),
             kind, utcnow()))
        self.db.commit()
        self.log("evidence.add", {"path": path, "size": info.get("size"),
                                  "stored_md5": info.get("stored_md5")})
        return cur.lastrowid

    def evidence_kind(self, path):
        row = self.db.execute("SELECT * FROM evidence WHERE path=?",
                              (path,)).fetchone()
        if row is None:
            return None
        kind = row["kind"] if "kind" in row.keys() else None
        return kind or infer_kind(row["path"], row["format"])

    @_writes
    def save_type_scan(self, evidence_id, part, result):
        self.db.execute(
            "DELETE FROM type_mismatches WHERE evidence_id=? AND part=?",
            (evidence_id, part))
        rows = [(evidence_id, part, str(m.get("node")), m.get("path"),
                 m.get("name"), m.get("size"), int(bool(m.get("deleted"))),
                 m.get("modified"), m.get("extension"),
                 m.get("extension_says"), m.get("detected"),
                 m.get("content_is"), m.get("severity"), m.get("why"),
                 utcnow())
                for m in result.get("mismatches") or []]
        self.db.executemany(
            "INSERT OR REPLACE INTO type_mismatches (evidence_id,part,node,"
            "path,name,size,deleted,modified,extension,extension_says,"
            "detected,content_is,severity,why,found_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        self._set("typescan_%d_%d" % (evidence_id, part),
                  json.dumps({"checked": result.get("checked"),
                              "census": result.get("census"),
                              "at": utcnow()}))
        self.db.commit()
        self.log("filetype.scan", {"evidence_id": evidence_id, "part": part,
                                   "checked": result.get("checked"),
                                   "mismatches": len(rows)})
        return len(rows)

    def type_mismatches(self, evidence_id=None):
        sql = "SELECT * FROM type_mismatches"
        args = ()
        if evidence_id is not None:
            sql += " WHERE evidence_id=?"
            args = (evidence_id,)
        sql += " ORDER BY CASE severity WHEN 'high' THEN 0 ELSE 1 END, path"
        return [dict(r) for r in self.db.execute(sql, args)]

    def type_scan_summary(self):
        out = {}
        for r in self.db.execute(
                "SELECT key, value FROM meta WHERE key LIKE 'typescan_%'"):
            try:
                _, ev, part = r["key"].split("_")
                out["%s:%s" % (ev, part)] = json.loads(r["value"])
            except (ValueError, TypeError):
                continue
        return out

    @_writes
    def record_verification(self, evidence_id, result):
        self.db.execute(
            "UPDATE evidence SET verified_md5=?, verified_sha1=?, verified_at=? "
            "WHERE id=?", (result.get("computed_md5"), result.get("computed_sha1"),
                           utcnow(), evidence_id))
        self.db.commit()
        self.log("evidence.verify", {"evidence_id": evidence_id, **result})

    @_writes
    def add_bookmark(self, evidence_id, offset, length=1, label="", note="",
                     tags=None, source="", category="", colour="",
                     in_report=True, frame="media", part=None, node=None,
                     stream=None, mark_in=None):
        frame = "file" if frame == "file" else "media"
        cur = self.db.execute(
            "INSERT INTO bookmarks (evidence_id,offset,length,label,note,tags,"
            "source,category,colour,in_report,frame,part,node,stream,"
            "mark_in,created_at,examiner) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (evidence_id, offset, length, label, note,
             ",".join(tags or []), source, category or "", colour or "",
             int(bool(in_report)), frame, part,
             None if node is None else str(node), stream or None,
             mark_in or None, utcnow(), self.examiner))
        self.db.commit()
        self.log("bookmark.add", {"evidence_id": evidence_id, "offset": offset,
                                  "length": length, "label": label,
                                  "category": category or None,
                                  "frame": frame, "part": part,
                                  "node": None if node is None else str(node),
                                  "in_file": mark_in or None,
                                  "in_report": bool(in_report)})
        return cur.lastrowid

    @_writes
    def update_bookmark(self, bid, **fields):
        allowed = ("label", "note", "category", "colour", "in_report")
        sets, vals = [], []
        for k in allowed:
            if k in fields:
                sets.append("%s=?" % k)
                vals.append(int(bool(fields[k])) if k == "in_report"
                            else (fields[k] or ""))
        if not sets:
            return False
        row = self.db.execute("SELECT * FROM bookmarks WHERE id=?",
                              (bid,)).fetchone()
        if not row:
            return False
        vals.append(bid)
        self.db.execute("UPDATE bookmarks SET %s WHERE id=?" % ",".join(sets),
                        vals)
        self.db.commit()
        self.log("bookmark.update", {
            "id": bid, "offset": row["offset"],
            "changed": {k: fields[k] for k in allowed if k in fields}})
        return True

    def bookmarks(self, evidence_id=None):
        if evidence_id is None:
            rows = self.db.execute("SELECT * FROM bookmarks ORDER BY offset")
        else:
            rows = self.db.execute(
                "SELECT * FROM bookmarks WHERE evidence_id=? ORDER BY offset",
                (evidence_id,))
        out = []
        for r in rows:
            d = dict(r)
            d["tags"] = [t for t in (d["tags"] or "").split(",") if t]
            d["in_report"] = bool(d.get("in_report", 1))
            out.append(d)
        return out

    @_writes
    def remove_bookmark(self, bid):
        r = self.db.execute("SELECT * FROM bookmarks WHERE id=?", (bid,)).fetchone()
        if not r:
            return False
        self.db.execute("DELETE FROM bookmarks WHERE id=?", (bid,))
        self.db.commit()
        self.log("bookmark.remove", {"id": bid, "offset": r["offset"],
                                     "label": r["label"]})
        return True

    @_writes
    def tag_item(self, evidence_id, item, tag, note="", part=0):
        node = str(item.get("mft") if item.get("mft") is not None
                   else item.get("inode") if item.get("inode") is not None
                   else item.get("oid") if item.get("oid") is not None
                   else item.get("start_cluster"))
        cur = self.db.execute(
            "INSERT INTO tagged_items (evidence_id,part,node,path,name,size,"
            "is_dir,deleted,tag,note,created_at,examiner,modified,accessed,"
            "file_created,contiguous) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(evidence_id,part,node,tag) DO UPDATE SET note=excluded.note",
            (evidence_id, part, node, item.get("path"), item.get("name"),
             item.get("size"), int(bool(item.get("is_dir"))),
             int(bool(item.get("deleted"))), tag, note, utcnow(), self.examiner,
             item.get("modified"), item.get("accessed"), item.get("created"),
             int(bool(item.get("contiguous")))
             if item.get("contiguous") is not None else None))
        self.db.commit()
        self.log("item.tag", {"path": item.get("path"), "name": item.get("name"),
                              "tag": tag, "node": node})
        return cur.lastrowid

    @_writes
    def untag_item(self, item_id):
        r = self.db.execute("SELECT * FROM tagged_items WHERE id=?",
                            (item_id,)).fetchone()
        if not r:
            return False
        self.db.execute("DELETE FROM tagged_items WHERE id=?", (item_id,))
        self.db.commit()
        self.log("item.untag", {"id": item_id, "path": r["path"], "tag": r["tag"]})
        return True

    def tagged(self, evidence_id=None, tag=None):
        q = "SELECT * FROM tagged_items"
        where, args = [], []
        if evidence_id is not None:
            where.append("evidence_id=?")
            args.append(evidence_id)
        if tag:
            where.append("tag=?")
            args.append(tag)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY tag, name"
        return [dict(r) for r in self.db.execute(q, args)]

    def tag_counts(self):
        return {r["tag"]: r["n"] for r in self.db.execute(
            "SELECT tag, COUNT(*) n FROM tagged_items GROUP BY tag ORDER BY tag")}

    @_writes
    def save_search(self, evidence_id, name, query, hits, part=None):
        cur = self.db.execute(
            "INSERT INTO saved_searches (evidence_id,name,query,part,hit_count,"
            "created_at,examiner) VALUES (?,?,?,?,?,?,?)",
            (evidence_id, name, json.dumps(query, default=str), part,
             len(hits), utcnow(), self.examiner))
        sid = cur.lastrowid
        self.db.executemany(
            "INSERT INTO search_hits (search_id,name,path,node,size,is_dir,"
            "deleted,where_found,term,context,file_offset,encoding,modified) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(sid, h.get("name"), h.get("path"),
              str(h.get("mft") if h.get("mft") is not None
                  else h.get("inode") if h.get("inode") is not None
                  else h.get("oid") if h.get("oid") is not None
                  else h.get("start_cluster")),
              h.get("size"), int(bool(h.get("is_dir"))),
              int(bool(h.get("deleted"))), h.get("where"), h.get("term"),
              h.get("context"), h.get("file_offset"), h.get("encoding"),
              h.get("modified")) for h in hits])
        self.db.commit()
        self.log("search.save", {"name": name, "hits": len(hits),
                                 "query": query})
        return sid

    def searches(self):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM saved_searches ORDER BY created_at DESC")]

    def search_hits(self, search_id):
        row = self.db.execute("SELECT * FROM saved_searches WHERE id=?",
                              (search_id,)).fetchone()
        if not row:
            return None
        out = dict(row)
        out["query"] = json.loads(out["query"] or "{}")
        out["hits"] = [dict(r) for r in self.db.execute(
            "SELECT * FROM search_hits WHERE search_id=? ORDER BY id",
            (search_id,))]
        return out

    @_writes
    def delete_search(self, search_id):
        row = self.db.execute("SELECT name FROM saved_searches WHERE id=?",
                              (search_id,)).fetchone()
        if not row:
            return False
        self.db.execute("DELETE FROM search_hits WHERE search_id=?", (search_id,))
        self.db.execute("DELETE FROM saved_searches WHERE id=?", (search_id,))
        self.db.commit()
        self.log("search.delete", {"id": search_id, "name": row["name"]})
        return True

    @_writes
    def record_hashes(self, evidence_id, rows, part=0):
        self.db.executemany(
            "INSERT INTO file_hashes (evidence_id,part,node,path,name,size,"
            "deleted,md5,sha1,sha256,fuzzy,read_bytes,computed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(evidence_id,part,node) DO UPDATE SET "
            "md5=excluded.md5, sha1=excluded.sha1, sha256=excluded.sha256, "
            "fuzzy=excluded.fuzzy, "
            "read_bytes=excluded.read_bytes, computed_at=excluded.computed_at",
            [(evidence_id, part, r["node"], r.get("path"), r.get("name"),
              r.get("size"), int(bool(r.get("deleted"))), r.get("md5"),
              r.get("sha1"), r.get("sha256"), r.get("fuzzy"), r.get("read"),
              utcnow())
             for r in rows])
        self.db.commit()
        return len(rows)

    @_writes
    def save_artefact(self, evidence_id, part, kind, payload):
        blob = json.dumps(payload, separators=(",", ":"), default=str)
        if len(blob) > ARTEFACT_MAX_BYTES:
            self.log("artefact.too_large", {
                "kind": kind, "part": part, "bytes": len(blob),
                "limit": ARTEFACT_MAX_BYTES,
                "reason": _t("casedb.artefact_too_large_reason")})
            self.db.commit()
            return 0
        self.db.execute(
            "INSERT INTO artefacts (evidence_id,part,kind,parser_version,"
            "ran_at,examiner,bytes,payload) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(evidence_id,part,kind) DO UPDATE SET "
            "parser_version=excluded.parser_version, ran_at=excluded.ran_at, "
            "examiner=excluded.examiner, bytes=excluded.bytes, "
            "payload=excluded.payload",
            (evidence_id, part, kind, ARTEFACT_VERSION.get(kind, 1), utcnow(),
             self.examiner, len(blob), blob))
        self.log("artefact.saved", {"kind": kind, "part": part,
                                    "bytes": len(blob)})
        self.db.commit()
        return len(blob)

    @_writes
    def artefacts(self, evidence_id):
        out, stale = {}, []
        for r in self.db.execute(
                "SELECT * FROM artefacts WHERE evidence_id=?", (evidence_id,)):
            want = ARTEFACT_VERSION.get(r["kind"], 1)
            if r["parser_version"] != want:
                stale.append({"kind": r["kind"], "part": r["part"],
                              "was": r["parser_version"], "now": want})
                continue
            try:
                payload = json.loads(r["payload"])
            except ValueError:
                stale.append({"kind": r["kind"], "part": r["part"],
                              "was": "unreadable", "now": want})
                continue
            out["%s:%s" % (r["kind"], r["part"])] = {
                "kind": r["kind"], "part": r["part"], "ran_at": r["ran_at"],
                "examiner": r["examiner"], "bytes": r["bytes"],
                "payload": payload}
        if stale:
            self.db.executemany(
                "DELETE FROM artefacts WHERE evidence_id=? AND part=? AND kind=?",
                [(evidence_id, x["part"], x["kind"]) for x in stale])
            self.log("artefact.reset", {
                "dropped": stale,
                "reason": _t("casedb.artefact_reset_reason")})
            self.db.commit()
        return {"items": out, "dropped": stale}

    def hashes(self, evidence_id=None, limit=5000):
        q = "SELECT * FROM file_hashes"
        args = []
        if evidence_id is not None:
            q += " WHERE evidence_id=?"
            args.append(evidence_id)
        q += " ORDER BY name LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.db.execute(q, args)]

    @_writes
    def attack_tag(self, evidence_id, part, target_kind, target_ref, technique,
                   technique_name=None, tactic=None, note="", asserted=True,
                   catalogue=None):
        cur = self.db.execute(
            "INSERT INTO attack_tags (evidence_id,part,target_kind,target_ref,"
            "technique,technique_name,tactic,note,asserted,catalogue,"
            "created_at,examiner) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(evidence_id,part,target_kind,target_ref,technique) "
            "DO UPDATE SET note=excluded.note, asserted=excluded.asserted, "
            "technique_name=excluded.technique_name, tactic=excluded.tactic",
            (evidence_id, part, target_kind, str(target_ref), technique,
             technique_name, tactic, note, int(bool(asserted)), catalogue,
             utcnow(), self.examiner))
        self.log("attack.tag", {"technique": technique, "target": target_kind,
                                "ref": str(target_ref),
                                "asserted": bool(asserted)})
        self.db.commit()
        return cur.lastrowid

    @_writes
    def attack_untag(self, tag_id):
        row = self.db.execute("SELECT * FROM attack_tags WHERE id=?",
                              (tag_id,)).fetchone()
        if not row:
            return False
        self.db.execute("DELETE FROM attack_tags WHERE id=?", (tag_id,))
        self.log("attack.untag", {"technique": row["technique"],
                                  "target": row["target_kind"],
                                  "ref": row["target_ref"]})
        self.db.commit()
        return True

    def attack_tags(self, evidence_id=None, technique=None):
        q = "SELECT * FROM attack_tags"
        where, args = [], []
        if evidence_id is not None:
            where.append("evidence_id=?")
            args.append(evidence_id)
        if technique:
            where.append("technique=?")
            args.append(technique)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY tactic, technique, created_at"
        return [dict(r) for r in self.db.execute(q, args)]

    def attack_summary(self, evidence_id=None):
        out = {}
        for r in self.attack_tags(evidence_id):
            key = r["technique"]
            e = out.setdefault(key, {
                "technique": key, "technique_name": r["technique_name"],
                "tactic": r["tactic"], "asserted": 0, "proposed": 0})
            e["asserted" if r["asserted"] else "proposed"] += 1
        return sorted(out.values(), key=lambda x: (x["tactic"] or "",
                                                   x["technique"]))

    @_writes
    def set_attack_catalogue(self, techniques, version=None):
        self._set("attack_catalogue", json.dumps(
            {"version": version, "techniques": techniques},
            separators=(",", ":")))
        self.log("attack.catalogue", {"techniques": len(techniques),
                                      "version": version})
        self.db.commit()
        return len(techniques)

    def attack_catalogue(self):
        raw = self.get("attack_catalogue")
        if not raw:
            return None
        try:
            d = json.loads(raw)
        except ValueError:
            return None
        return d.get("techniques") or None, d.get("version")

    def hash_map(self, evidence_id, part):
        return {r["node"]: {"md5": r["md5"], "sha1": r["sha1"],
                            "sha256": r["sha256"], "fuzzy": r["fuzzy"]}
                for r in self.db.execute(
                    "SELECT node,md5,sha1,sha256,fuzzy FROM file_hashes "
                    "WHERE evidence_id=? AND part=?", (evidence_id, part))
                if r["node"] is not None}

    def hash_for(self, evidence_id, part, node):
        r = self.db.execute(
            "SELECT * FROM file_hashes WHERE evidence_id=? AND part=? AND node=?",
            (evidence_id, part, str(node))).fetchone()
        return dict(r) if r else None

    def duplicate_files(self):
        """Files whose SHA-256 was seen under more than one evidence item
        -- only among files a hash run has actually covered, since a
        digest is never computed implicitly here. Largest group first."""
        rows = self.db.execute(
            "SELECT h.* FROM file_hashes h JOIN ("
            " SELECT sha256 FROM file_hashes"
            " WHERE sha256 IS NOT NULL AND sha256 != ''"
            " GROUP BY sha256 HAVING COUNT(DISTINCT evidence_id) > 1"
            ") dup ON h.sha256 = dup.sha256 "
            "ORDER BY h.sha256, h.evidence_id, h.part").fetchall()
        groups = {}
        for r in rows:
            groups.setdefault(r["sha256"], []).append(dict(r))
        out = [{"sha256": k, "items": v} for k, v in groups.items()]
        out.sort(key=lambda g: len(g["items"]), reverse=True)
        return out

    def similar_files(self, threshold=60, limit=500):
        """Pairs of files whose fuzzy hashes are alike (score >= threshold),
        across all evidence -- like duplicate_files, this only compares what
        a hash run has already fuzzy-hashed, never hashes anything itself.
        Unlike an exact digest, ssdeep similarity isn't transitive, so
        results are scored pairs rather than groups, and exact duplicates
        (same SHA-256) are left to Find Duplicates rather than repeated here.

        ssdeep hashes only ever score non-zero when their block sizes match
        or one is double the other, so files are bucketed by block size
        first -- comparing every fuzzy-hashed file against every other
        would be needless work on a case of any size."""
        rows = [dict(r) for r in self.db.execute(
            "SELECT * FROM file_hashes WHERE fuzzy IS NOT NULL AND fuzzy != ''")]
        buckets = {}
        for r in rows:
            try:
                bs = int(r["fuzzy"].split(":", 1)[0])
            except (ValueError, IndexError):
                continue
            buckets.setdefault(bs, []).append(r)

        def consider(a, b, pairs, seen):
            key = (a["id"], b["id"]) if a["id"] < b["id"] else (b["id"], a["id"])
            if key in seen:
                return
            seen.add(key)
            if a["sha256"] and b["sha256"] and a["sha256"] == b["sha256"]:
                return
            score = fuzzyhash.compare(a["fuzzy"], b["fuzzy"])
            if score >= threshold:
                pairs.append((score, a, b))

        pairs, seen = [], set()
        for bs, group in buckets.items():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    consider(group[i], group[j], pairs, seen)
            for other in buckets.get(bs * 2, []):
                for a in group:
                    for b in other:
                        consider(a, b, pairs, seen)

        pairs.sort(key=lambda p: -p[0])
        return [{"score": score, "a": a, "b": b}
                for score, a, b in pairs[:limit]]

    @_writes
    def add_hash_set(self, name, kind, source, digests):
        self.db.execute(
            "INSERT INTO hash_sets (name,kind,source,imported_at,examiner,entries)"
            " VALUES (?,?,?,?,?,0) ON CONFLICT(name) DO UPDATE SET "
            "kind=excluded.kind, source=excluded.source, "
            "imported_at=excluded.imported_at", (name, kind, source, utcnow(),
                                                 self.examiner))
        sid = self.db.execute("SELECT id FROM hash_sets WHERE name=?",
                              (name,)).fetchone()["id"]
        self.db.execute("DELETE FROM hash_entries WHERE set_id=?", (sid,))
        self.db.executemany(
            "INSERT INTO hash_entries (set_id,algo,digest,label) VALUES (?,?,?,?)",
            [(sid, a, d.lower(), lab) for a, d, lab in digests])
        n = self.db.execute("SELECT COUNT(*) c FROM hash_entries WHERE set_id=?",
                            (sid,)).fetchone()["c"]
        self.db.execute("UPDATE hash_sets SET entries=? WHERE id=?", (n, sid))
        self.db.commit()
        self.log("hashset.import", {"name": name, "kind": kind,
                                    "entries": n, "source": source})
        return {"id": sid, "entries": n}

    def hash_sets(self):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM hash_sets ORDER BY name")]

    @_writes
    def delete_hash_set(self, set_id):
        row = self.db.execute("SELECT name FROM hash_sets WHERE id=?",
                              (set_id,)).fetchone()
        if not row:
            return False
        self.db.execute("DELETE FROM hash_entries WHERE set_id=?", (set_id,))
        self.db.execute("DELETE FROM hash_sets WHERE id=?", (set_id,))
        self.db.commit()
        self.log("hashset.delete", {"id": set_id, "name": row["name"]})
        return True

    def match_hashes(self, digests):
        out = {}
        if not digests:
            return out
        vals = [d.lower() for d in digests if d]
        for i in range(0, len(vals), 500):
            chunk = vals[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for r in self.db.execute(
                    "SELECT e.digest, e.algo, e.label, s.name, s.kind "
                    "FROM hash_entries e JOIN hash_sets s ON s.id = e.set_id "
                    "WHERE e.digest IN (%s)" % marks, chunk):
                out.setdefault(r["digest"], []).append(
                    {"set": r["name"], "kind": r["kind"], "algo": r["algo"],
                     "label": r["label"]})
        return out

    def report(self):
        s = self.summary()
        s["bookmarks"] = self.bookmarks()
        s["tagged"] = self.tagged()
        s["tag_counts"] = self.tag_counts()
        s["attack"] = self.attack_tags()
        s["attack_summary"] = self.attack_summary()
        cat = self.attack_catalogue()
        s["attack_catalogue"] = {"source": "imported", "version": cat[1]} if cat \
            else {"source": "built-in", "version": None}
        s["audit"] = self.audit(limit=100000)[::-1]
        s["audit_integrity"] = self.verify_audit()
        s["generated_at"] = utcnow()
        return s
