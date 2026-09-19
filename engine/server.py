import base64
import csv
import hashlib
import json
import mimetypes
import os
import re
import tempfile
import threading
import time
import traceback
import uuid
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import carve as carve_mod
from . import volmap as volmap_mod
from . import nativedialog
from . import attack as attack_mod
from . import wallets as wallets_mod
from . import timeline as timeline_mod
from . import profile as profile_mod
from . import filesearch as filesearch_mod
from . import hashing as hashing_mod
from . import textindex as textindex_mod
from . import appcompat as appcompat_mod
from . import browser as browser_mod
from . import shellbags as shellbags_mod
from . import evtx as evtx_mod
from . import leveldb as leveldb_mod
from . import mbox as mbox_mod
from . import pst as pst_mod
from . import bitlocker as bitlocker_mod
from . import pdfdoc as pdfdoc_mod
from . import saferender as saferender_mod
from . import timezone as timezone_mod
from . import archive as archive_mod
from . import sqlitehints as sqlitehints_mod
from . import prefs as prefs_mod
from . import recents as recents_mod
from .text import t as _t
from . import usnjrnl as usnjrnl_mod
from . import entropy as entropy_mod
from . import exif as exif_mod
from . import officedoc as officedoc_mod
from . import report as report_mod
from . import filetype as filetype_mod
from . import regreport as regreport_mod
from . import luks as luks_mod
from . import prefetch as prefetch_mod
from . import sqlitedb as sqlitedb_mod
from . import lnk as lnk_mod
from . import jumplist as jumplist_mod
from . import esedb as esedb_mod
from . import recyclebin as recyclebin_mod
from . import registry as registry_mod
from . import reglog as reglog_mod
from . import vss as vss_mod
from . import structure as structure_mod
from . import volume as volume_mod
from . import logical as logical_mod
from . import casedb as casedb_mod
from .casedb import Case
from .ewf import open_image, OffsetReader
from . import ewf as ewf_mod
from . import artifacts as artifacts_mod
from . import sessions as sessions_mod
from . import treecache as treecache_mod
from . import version as version_mod
from .fs import ntfs as ntfs_mod
from .fs import streams as streams_mod

WEB_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "web")

_BOUND = {"host": "127.0.0.1", "port": 8722}

_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "[::1]"}

def set_bound_address(host, port):
    _BOUND["host"] = host or "127.0.0.1"
    _BOUND["port"] = int(port)

def _split_host(value):
    v = (value or "").strip()
    if v.startswith("["):
        close = v.find("]")
        if close < 0:
            return v.lower(), None
        host, rest = v[:close + 1], v[close + 1:]
        port = rest[1:] if rest.startswith(":") else None
        return host.lower(), port or None
    host, sep, port = v.partition(":")
    return host.lower(), (port if sep else None)

def _is_ip_literal(host):
    h = host.strip("[]")
    if ":" in h:
        return all(c in "0123456789abcdefABCDEF:." for c in h)
    parts = h.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts)

def host_allowed(value):
    host, port = _split_host(value)
    if not host:
        return False
    if port is not None and port != str(_BOUND["port"]):
        return False
    bound = (_BOUND["host"] or "").lower()
    if bound in ("0.0.0.0", "::", "[::]", ""):
        return host in _LOOPBACK_NAMES or _is_ip_literal(host)
    if bound in _LOOPBACK_NAMES:
        return host in _LOOPBACK_NAMES
    return host == bound or host == "[%s]" % bound

def origin_allowed(origin, host_header):
    o = (origin or "").strip()
    if not o:
        return True
    if "://" not in o:
        return False
    scheme, _, authority = o.partition("://")
    if scheme.lower() not in ("http", "https"):
        return False
    if not host_allowed(authority):
        return False
    return _split_host(authority)[0] == _split_host(host_header)[0]

def _within(root, candidate):
    try:
        root = os.path.abspath(root)
        candidate = os.path.abspath(candidate)
    except (OSError, ValueError):
        return False
    if os.path.normcase(root) == os.path.normcase(candidate):
        return True
    prefix = root if root.endswith(os.sep) else root + os.sep
    return os.path.normcase(candidate).startswith(os.path.normcase(prefix))

class TaskCancelled(Exception):
    pass

class FileRegion:

    def __init__(self, fs, entry, size, stream="", cache=None):
        self.fs = fs
        self.entry = entry
        self.stream = stream
        self.size = int(size or 0)
        self._cache = cache if cache is not None else {}

    def _key(self):
        e = self.entry
        node = (e.get("oid") if e.get("oid") is not None else
                e.get("mft") if e.get("mft") is not None else
                e.get("inode") if e.get("inode") is not None else
                e.get("start_cluster"))
        return (id(self.fs), str(node),
                e.get("path") or e.get("name") or "", self.stream)

    WHOLE_MAX = 64 << 20

    def _content(self):
        key = self._key()
        got = self._cache.get(key)
        if got is None:
            try:
                got = self.fs.read_file(self.entry, stream=self.stream) \
                    if self.stream else self.fs.read_file(self.entry)
            except TypeError:
                got = self.fs.read_file(self.entry)
            got = got or b""
            self._cache.clear()
            self._cache[key] = got
        return got

    def read_at(self, off, length):
        if off < 0 or length <= 0 or off >= self.size:
            return b""
        length = min(length, self.size - off)

        ranged = getattr(self.fs, "read_range", None)
        if ranged is not None:
            try:
                return ranged(self.entry, off, length, self.stream) \
                    if self.stream else ranged(self.entry, off, length)
            except TypeError:
                pass

        if self.size <= self.WHOLE_MAX:
            data = self._content()
            return data[off:off + length] if off < len(data) else b""

        try:
            data = self.fs.read_file(self.entry, max_bytes=off + length,
                                     stream=self.stream) \
                if self.stream else \
                self.fs.read_file(self.entry, max_bytes=off + length)
        except TypeError:
            data = self.fs.read_file(self.entry)
        return data[off:off + length] if off < len(data) else b""

class Evidence:

    def __init__(self, path, evidence_id, image=None):
        self.path = path
        self.evidence_id = evidence_id
        self.image = image or open_image(path)
        self.volumes = volume_mod.scan(self.image)
        self.label = os.path.basename(path)
        self.fs_cache = {}
        self._structures = None
        self.index_tasks = {}
        self.hive_cache = {}
        self.unlocked = {}
        self.vault_cache = {}
        self.reader_cache = {}
        self.tz_candidates = []
        self.tz_scanned = False
        self.usn = None
        self.file_bytes = {}

    def brief(self):
        return {
            "evidence_id": self.evidence_id, "path": self.path,
            "label": self.label,
            "format": self.image.info().get("format"),
            "size": self.image.size,
            "partitions": len(self.volumes.get("partitions") or []),
            "volumes": self.volumes,
            "unlocked": sorted(self.unlocked),
        }

REGISTRY = None

class Session:

    _PER_EVIDENCE = (
        "image", "path", "volumes", "fs_cache", "index_tasks", "hive_cache",
        "unlocked", "vault_cache", "reader_cache", "tz_candidates",
        "tz_scanned", "evidence_id", "_structures", "usn", "file_bytes",
    )

    def __init__(self):
        self.case = None
        self.items = {}
        self.active_id = None
        self.tasks = {}
        self.lock = threading.Lock()
        self.fs_lock = threading.Lock()
        self._timeline_tmp = None

    @property
    def current(self):
        return self.items.get(self.active_id)

    def __getattr__(self, name):
        if name in Session._PER_EVIDENCE:
            cur = self.__dict__.get("items", {}).get(
                self.__dict__.get("active_id"))
            if cur is None:
                return None if name != "fs_cache" else {}
            return getattr(cur, name)
        raise AttributeError(name)

    def __setattr__(self, name, value):
        if name in Session._PER_EVIDENCE and self.__dict__.get("items"):
            cur = self.items.get(self.active_id)
            if cur is not None:
                setattr(cur, name, value)
                return
        object.__setattr__(self, name, value)

    def timeline_path(self, key, create=False):
        base = self.case.cache_dir(create=create) if self.case else None
        if not base:
            if self._timeline_tmp is None and create:
                self._timeline_tmp = tempfile.mkdtemp(prefix="strata-timeline-")
            base = self._timeline_tmp
        if not base:
            return None
        return os.path.join(base, "timeline-%s.sqlite" % key)

    def drop_timelines(self, evidence_id, tagged=False):
        probe = self.timeline_path("x")
        if not probe:
            return []
        base = os.path.dirname(probe)
        keys = r"ev%d-p\d+" % int(evidence_id)
        if tagged:
            keys += "|tagged"
        pattern = re.compile(r"^timeline-(%s)\.sqlite(-wal|-shm|-journal)?$"
                             % keys)
        try:
            names = os.listdir(base)
        except OSError:
            return []
        gone = []
        for name in sorted(names):
            if not pattern.match(name):
                continue
            try:
                os.remove(os.path.join(base, name))
                gone.append(name)
            except OSError:
                pass
        return gone

    def evidence(self, which=None):
        if which in (None, ""):
            return self.current
        try:
            return self.items.get(int(which))
        except (TypeError, ValueError):
            return None

    def _use_case(self, case_path, examiner=None, name=None):
        old = getattr(self, "case", None)
        if old is not None:
            try:
                old.close()
            except Exception:
                pass
        self.case = Case(case_path, name=name, examiner=examiner)
        try:
            recents_mod.note(self.case.examiner, self.case.path,
                             self.case.get("name"))
        except Exception:
            pass
        return self.case

    def running_tasks(self):
        return [t for t in self.tasks.values() if t.get("state") == "running"]

    def new_case(self, case_path, name=None, examiner=None):
        self._use_case(case_path, examiner, name=name)
        self.items = {}
        self.active_id = None
        return self.state()

    def close_case(self):
        case = getattr(self, "case", None)
        if case is None:
            return {"closed": False, "error": _t("server.export.case_open")}
        path = case.path
        try:
            case.log("case.close", {"path": path, "exhibits": len(self.items)})
            case.db.commit()
        except Exception:
            pass
        try:
            case.close()
        except Exception:
            pass
        self.case = None
        self.items = {}
        self.active_id = None
        self.tasks = {}
        if REGISTRY is not None:
            REGISTRY.release_images()
        out = self.state()
        out["closed"] = True
        out["closed_case"] = path
        return out

    def open(self, path, case_path=None, examiner=None, add=False,
             logical=False):
        if REGISTRY is not None:
            img = REGISTRY.image(path, logical=logical)
        else:
            img = logical_mod.open_logical(path) if logical else open_image(path)
        try:
            return self._open(path, img, case_path, examiner, add)
        finally:
            if REGISTRY is not None:
                REGISTRY.done_opening(path, logical=logical)

    def _open(self, path, img, case_path, examiner, add):
        if not add or self.case is None:
            case_path = case_path or os.path.splitext(path)[0] + ".strata"
            if self.case is None or (case_path and
                                     os.path.abspath(case_path) !=
                                     os.path.abspath(self.case.path)):
                self._use_case(case_path, examiner)
            if not add:
                self.items = {}
                self.active_id = None
        ev_id = self.case.add_evidence(path, img.info())
        item = Evidence(path, ev_id, image=img)
        self.items[ev_id] = item
        self.active_id = ev_id
        self.case.log("evidence.open", {"path": path, "evidence_id": ev_id,
                                        "alongside": len(self.items) - 1,
                                        "tool": version_mod.label()})
        return self.state()

    def open_case(self, case_path, examiner=None):
        self._use_case(case_path, examiner)
        self.items = {}
        self.active_id = None
        self.case.log("case.open", {"path": case_path, "evidence": 0,
                                    "tool": version_mod.label(),
                                    "note": _t("server.opened_evidence")})
        return self.state()

    def close(self, ev_id):
        item = self.items.pop(int(ev_id), None)
        if item is None:
            return False
        if self.active_id == int(ev_id):
            self.active_id = next(iter(self.items), None)
        self.case.log("evidence.close", {"evidence_id": int(ev_id),
                                         "path": item.path})
        return True

    def state(self):
        cur = self.current
        if cur is None:
            return {"open": False,
                    "case": self.case.summary() if self.case else None}
        return {
            "open": True, "path": cur.path,
            "image": cur.image.info(),
            "volumes": cur.volumes,
            "case": self.case.summary() if self.case else None,
            "case_path": getattr(self.case, "path", None) if self.case else None,
            "evidence_id": cur.evidence_id,
            "evidence": [i.brief() for i in self.items.values()],
            "active_id": self.active_id,
            "index_reset": bool(getattr(self.case, "index_reset", False)),
            "index_pending": int(getattr(self.case, "index_pending", 0) or 0),
        }

    def reader(self, offset, size, slot="?", ev=None):
        ev = ev or self.current
        if ev is None:
            return None
        vault = ev.unlocked.get(offset)
        if vault is None:
            v = self.vault(offset, ev=ev)
            if v is None or not getattr(v, "unlocked", False):
                return None
            vault = v
        got = ev.reader_cache.get(offset)
        if got is None:
            got = DecryptedReader(vault, size, slot)
            ev.reader_cache[offset] = got
        return got

    def region(self, offset, size=None, ev=None):
        ev = ev or self.current
        if offset in (None, 0) and size is None:
            return ev.image
        for p in ev.volumes["partitions"]:
            if p["offset"] == offset:
                dec = self.reader(offset, p["size"], p["slot"], ev=ev)
                if dec is not None:
                    return dec
                return OffsetReader(ev.image, p["offset"], p["size"], p["slot"])
        return OffsetReader(ev.image, offset, size or (ev.image.size - offset))

    def hive(self, offset, entry, ev=None):
        key = (offset, entry.get("mft") or entry.get("inode")
               or entry.get("oid") or entry.get("start_cluster"), entry.get("name"))
        ev = ev or self.current
        if key in ev.hive_cache:
            return ev.hive_cache[key]
        fs = self.fs(offset, ev=ev)
        data = fs.read_file(entry, MAX_HIVE)
        data, replay = self._replay(fs, entry, data)
        h = registry_mod.open_hive(data, entry.get("path") or entry.get("name", ""))
        if h is not None:
            h.replay = replay
        ev.hive_cache[key] = h
        return h

    def _replay(self, fs, entry, data):
        seqs = reglog_mod.hive_sequences(data)
        if seqs is None or seqs[0] == seqs[1]:
            return data, None

        logs = []
        parent = entry.get("parent")
        name = (entry.get("name") or "").lower()
        if parent is not None and name:
            try:
                for sib in fs.listdir(parent):
                    sn = (sib.get("name") or "").lower()
                    if sn in (name + ".log1", name + ".log2") and sib.get("size"):
                        logs.append(fs.read_file(sib, MAX_HIVE))
            except Exception:
                pass
        try:
            new, report = reglog_mod.recover(data, logs)
        except Exception as exc:
            return data, {"dirty": True, "recovered": False,
                          "findings": ["The transaction logs could not be "
                                       "read (%s); the hive is shown as it "
                                       "stands." % exc]}
        report["summary"] = reglog_mod.summarise(report)
        return (new or data), report

    def ensure_index(self, offset, fs, ev=None):
        ev = ev or self.current
        with self.lock:
            task = ev.index_tasks.get(offset)
            if task and task["state"] in ("running", "done"):
                return task

            def build(progress):
                nodes, _ = fs.build_tree(progress=progress)
                return {"records": len(nodes)}

            task = self.start_task("mft-index", build,
                                   label="Indexing the master file table",
                                   detail="One pass over every MFT record.")
            ev.index_tasks[offset] = task
            return task

    def structures(self, ev=None):
        ev = ev or self.current
        if ev._structures is None:
            ev._structures = structure_mod.map_image(ev.image, ev.volumes)
        return ev._structures

    def fs(self, offset, ev=None):
        ev = ev or self.current
        if ev is None:
            raise ValueError(_t("server.evidence_open"))
        made = getattr(ev.image, "filesystem", None)
        if made is not None:
            ev.fs_cache[offset] = made
            return made
        hit = ev.fs_cache.get(offset)
        if hit is not None:
            return hit
        with self.fs_lock:
            hit = ev.fs_cache.get(offset)
            if hit is not None:
                return hit
            part = None
            for p in ev.volumes["partitions"]:
                if p["offset"] == offset:
                    part = p
                    break
            size = part["size"] if part else ev.image.size - offset
            dec = self.reader(offset, size, part["slot"] if part else "?",
                              ev=ev)
            src = dec if dec is not None else OffsetReader(ev.image, offset,
                                                           size)
            if REGISTRY is not None:
                fs = REGISTRY.shared("fs", ev.path, offset,
                                     lambda: ntfs_mod.open_fs(src))
            else:
                fs = ntfs_mod.open_fs(src)
            self._attach_tree_cache(fs, ev, offset)
            ev.fs_cache[offset] = fs
            return fs

    def _attach_tree_cache(self, fs, ev, offset):
        if not hasattr(fs, "tree_store"):
            return
        if fs.tree_store is not None or self.case is None:
            return
        cache = self.case.cache_dir(create=True)
        if not cache:
            return
        path = treecache_mod.path_for(cache, ev.path, offset)
        want = treecache_mod.stamp(ev.path, offset)
        fs.tree_store = (lambda: treecache_mod.load(path, want),
                         lambda tree: treecache_mod.save(path, tree, want))

    def vault(self, offset, ev=None):
        ev = ev or self.current
        if offset in ev.vault_cache:
            return ev.vault_cache[offset]
        part = next((p for p in ev.volumes["partitions"]
                     if p["offset"] == offset), None)
        if part is None:
            return None
        size = part["size"]

        def build():
            src = OffsetReader(ev.image, offset, size)
            head = src.read_at(0, 4096)
            if bitlocker_mod.looks_like_bitlocker(head):
                return bitlocker_mod.BitLocker(src, size)
            if luks_mod.looks_like_luks(head):
                return luks_mod.Luks(src, size)
            return None

        v = (REGISTRY.shared("vault", ev.path, offset, build)
             if REGISTRY is not None else build())
        ev.vault_cache[offset] = v
        if v is not None and getattr(v, "unlocked", False):
            ev.unlocked[offset] = v
            self._note_unlock(offset, v, ev)
        return v

    def _note_unlock(self, offset, vault, ev):
        if self.case is None:
            return
        seen = getattr(ev, "unlock_noted", None)
        if seen is None:
            seen = ev.unlock_noted = set()
        if offset in seen:
            return
        seen.add(offset)
        info = {}
        try:
            info = vault.info() or {}
        except Exception:
            pass
        self.case.log("volume.unlock.inherited", {
            "part": offset,
            "encryption": info.get("encryption") or info.get("method"),
            "note": _t("server.unlock.inherited")})

    def keep_artefact(self, kind, part, payload):
        if not self.case or self.evidence_id is None or not payload:
            return None
        try:
            return self.case.save_artefact(self.evidence_id, part, kind, payload)
        except Exception:
            return None

    def start_task(self, name, fn, label=None, detail=None, keep=None):
        tid = uuid.uuid4().hex[:12]
        task = {"id": tid, "name": name, "label": label or name,
                "detail": detail, "progress": 0.0, "state": "running",
                "result": None, "error": None, "cancel": False,
                "started_at": time.time(), "finished_at": None}
        self.tasks[tid] = task

        def run():
            try:
                def progress(p, partial=None, count=None):
                    if task["cancel"]:
                        raise TaskCancelled()
                    task["progress"] = round(p, 4)
                    if count is not None:
                        task["found"] = count
                    if partial is not None:
                        task["partial"] = partial
                        task["found"] = len(partial)
                task["result"] = fn(progress)
                task["state"] = "done"
                task["progress"] = 1.0
                if keep:
                    self.keep_artefact(keep[0], keep[1], task["result"])
            except TaskCancelled:
                task["state"] = "cancelled"
                task["error"] = "Cancelled by the examiner."
            except Exception as exc:
                task["state"] = "error"
                task["error"] = "%s: %s" % (type(exc).__name__, exc)
                task["trace"] = traceback.format_exc()
            finally:
                task["finished_at"] = time.time()
        threading.Thread(target=run, daemon=True).start()
        return task

    def cancel_task(self, tid):
        t = self.tasks.get(tid)
        if not t or t["state"] != "running":
            return False
        t["cancel"] = True
        return True

    def task_list(self):
        now = time.time()
        out = []
        for t in sorted(self.tasks.values(), key=lambda x: x["started_at"]):
            out.append({
                "id": t["id"], "name": t["name"], "label": t["label"],
                "detail": t["detail"], "state": t["state"],
                "progress": t["progress"], "error": t["error"],
                "found": t.get("found"),
                "elapsed": round((t["finished_at"] or now) - t["started_at"], 1),
            })
        return out

    def forget_finished(self):
        for tid in [k for k, t in self.tasks.items() if t["state"] != "running"]:
            self.tasks.pop(tid, None)

SESSION = Session()

REGISTRY = sessions_mod.Registry(factory=Session, opener=open_image,
                                 logical_opener=logical_mod.open_logical)
REGISTRY.adopt_local(SESSION)

class Handler(BaseHTTPRequestHandler):
    server_version = "Strata/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _begin_request(self):
        # Keep-alive reuses one handler instance for every request on the
        # connection, so anything derived from a request must be cleared here
        # or the next request inherits it.
        self._sess = None
        self._sid = None
        self._new_cookie = None

    def _session(self):
        got = getattr(self, "_sess", None)
        if got is not None:
            return got
        cookie = sessions_mod.parse_cookie(self.headers.get("Cookie"))
        sess = REGISTRY.get(cookie)
        sid = cookie
        if sess is None:
            if cookie:
                sid, sess = REGISTRY.create()
                self._new_cookie = sid
            else:
                sid, sess = REGISTRY.default()
        self._sid = sid
        self._sess = sess
        return sess

    def _cookie_header(self):
        # Every response that follows a create() must carry the cookie, 304
        # included: a session the client is never told about is a session it
        # cannot reach, and the pending value must not survive into the next
        # response on this connection.
        if getattr(self, "_new_cookie", None):
            self.send_header("Set-Cookie",
                             sessions_mod.set_cookie_value(self._new_cookie))
            self._new_cookie = None

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self._cookie_header()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data, ctype, csp):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _parse_range(self, total):
        rng = self.headers.get("Range", "")
        start, end = 0, total - 1
        partial = False
        m = re.match(r"bytes=(\d*)-(\d*)", rng or "")
        if m and total:
            g1, g2 = m.group(1), m.group(2)
            if g1:
                start = min(int(g1), max(0, total - 1))
                end = int(g2) if g2 else total - 1
            elif g2:
                start = max(0, total - int(g2))
            end = min(end, total - 1)
            if start > end:
                start, end = 0, total - 1
            else:
                partial = True
        return start, end, partial

    def _write_range(self, body, ctype, start, end, total, partial):
        self.send_response(206 if partial else 200)
        self.send_header("Content-Type", ctype)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(len(body)))
        if partial:
            self.send_header("Content-Range",
                             "bytes %d-%d/%d" % (start, end, total))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_range(self, data, ctype):
        total = len(data)
        start, end, partial = self._parse_range(total)
        self._write_range(data[start:end + 1], ctype, start, end, total,
                          partial)

    def _send_range_region(self, region, total, ctype):
        """Like _send_range, but reads only the bytes a Range request asks
        for from `region` (a FileRegion) instead of the whole file --
        region.read_at() already seeks directly via fs.read_range() where
        the filesystem supports it, or caches a small file's full content
        across requests rather than re-reading it from the image every
        time (#78)."""
        start, end, partial = self._parse_range(total)
        body = region.read_at(start, end - start + 1) if total else b""
        self._write_range(body, ctype, start, end, total, partial)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except ValueError:
            return {}

    def _q(self, key, default=None, cast=None):
        v = self.query.get(key, [default])[0]
        if v is None:
            return default
        if cast:
            try:
                return cast(v)
            except (TypeError, ValueError):
                return default
        return v

    def _gate(self):
        host = self.headers.get("Host")
        if not host_allowed(host):
            self._send(421, {"error": _t("server.gate.host")})
            return False
        origin = self.headers.get("Origin")
        site = (self.headers.get("Sec-Fetch-Site") or "").lower()
        if site and site not in ("same-origin", "same-site", "none"):
            self._send(403, {"error": _t("server.gate.origin")})
            return False
        if not origin_allowed(origin, host):
            self._send(403, {"error": _t("server.gate.origin")})
            return False
        return True

    def _fail(self, exc):
        ref = uuid.uuid4().hex[:12]
        print("Strata error %s: %s\n%s"
              % (ref, exc, traceback.format_exc()))
        return self._send(500, {"error": str(exc), "ref": ref})

    def do_GET(self):
        self._begin_request()
        u = urlparse(self.path)
        self.query = parse_qs(u.query)
        try:
            if not self._gate():
                return
            if u.path.startswith("/api/"):
                return self._api_get(u.path)
            if u.path in ("/", "/index.html"):
                if not sessions_mod.parse_cookie(self.headers.get("Cookie")):
                    self._new_cookie = REGISTRY.create()[0]
            return self._static(u.path)
        except Exception as exc:
            return self._fail(exc)

    def do_POST(self):
        self._begin_request()
        u = urlparse(self.path)
        self.query = parse_qs(u.query)
        try:
            if not self._gate():
                return
            return self._api_post(u.path, self._body())
        except Exception as exc:
            return self._fail(exc)

    def _static(self, path):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.normpath(os.path.join(WEB_ROOT, rel))
        if not _within(WEB_ROOT, full) or not os.path.isfile(full):
            return self._send(404, "Not found", "text/plain")
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            data = f.read()

        etag = '"%s"' % hashlib.sha256(data).hexdigest()[:32]
        if (self.headers.get("If-None-Match") or "").strip() == etag:
            self.send_response(304)
            self._cookie_header()
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return

        self.send_response(200)
        self._cookie_header()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(data)

    def _who(self, s, stated=None):
        return ((stated or "").strip()
                or REGISTRY.name(getattr(self, "_sid", None))
                or getattr(getattr(s, "case", None), "examiner", None)
                or os.environ.get("STRATA_EXAMINER", "unattributed"))

    def _claim(self, s, body):
        stated = (body.get("examiner") or "").strip()
        if stated:
            REGISTRY.name(getattr(self, "_sid", None), stated)
        return self._who(s, stated)

    def _tasks_busy(self, s, doing):
        running = s.running_tasks()
        return {
            "error": _t("server.while_still_running") % (
                doing,
                ("%d tasks are" % len(running)) if len(running) != 1
                else "a task is"),
            "tasks": [{"id": t["id"], "label": t.get("label") or t["name"],
                       "progress": t.get("progress", 0.0)} for t in running],
            "advice": _t("server.wait_finish_cancel_task"),
        }

    def _api_get(self, path):
        s = self._session()
        if path == "/api/case/pulse":
            if not s.case:
                return self._send(200, {"open": False})
            out = s.case.pulse()
            out["open"] = True
            return self._send(200, out)

        if path == "/api/index/relocate":
            if not s.case:
                return self._send(400, {"error": _t("server.export.case_open")})
            if not getattr(s.case, "index_pending", 0):
                return self._send(200, {"moved": 0, "nothing_to_do": True})

            def run(progress):
                return s.case.relocate_index(progress=progress)

            return self._send(200, s.start_task(
                "index-relocate", run,
                label=_t("server.index_relocate.label"),
                detail=_t("server.index_relocate.detail")))

        if path == "/api/version":
            return self._send(200, {"name": version_mod.NAME,
                                    "version": version_mod.__version__,
                                    "label": version_mod.label(),
                                    "stale": _engine_changed()})

        if path == "/api/state":
            return self._send(200, s.state())

        if path == "/api/whoami":
            return self._send(200, {
                "name": REGISTRY.name(getattr(self, "_sid", None)),
                "session": bool(getattr(self, "_sid", None)),
                "note": _t("server.whoami.name_what_audit_log"),
            })

        if path == "/api/analysts":
            REGISTRY.sweep()
            out = REGISTRY.describe()
            out.update(REGISTRY.stats())
            return self._send(200, out)

        if path == "/api/carve/types":
            return self._send(200, {
                "types": carve_mod.catalogue(),
                "categories": list(carve_mod.CATEGORIES),
                "limits": carve_mod.CUSTOM_LIMITS,
            })

        if path == "/api/prefs":
            who = self._who(s, self._q("examiner", ""))
            return self._send(200, {"examiner": who,
                                    "prefs": prefs_mod.get(who),
                                    "path": prefs_mod.path()})

        if path == "/api/browse":
            root = self._q("path", os.path.expanduser("~"))
            kind = self._q("for", "image")
            exts = {"case": CASE_EXTS, "any": None}.get(kind, IMAGE_EXTS)
            return self._send(200, _browse(root, exts))

        if path == "/api/case/recent":
            who = self._who(s, self._q("examiner", ""))
            return self._send(200, {"examiner": who,
                                    "cases": recents_mod.entries(who),
                                    "path": recents_mod.path()})

        if path == "/api/case/peek":
            p = self._q("path", "")
            if not p or not casedb_mod.is_case(p):
                return self._send(400, {"error": _t(
                    "casedb.not_a_case" if p and os.path.exists(p)
                    else "server.case_peek.such_case_file") % p})
            try:
                c = Case(p, read_only=True)
                out = c.summary()
                out["audit_integrity"] = c.verify_audit()
                c.close()
                return self._send(200, out)
            except Exception as exc:
                return self._send(400, {"error": _t("server.case_peek.strata_case_file") % exc})

        if not s.image:
            return self._send(409, {"error": _t("server.case_peek.evidence_open")})

        if path == "/api/hex":
            off = self._q("offset", 0, int)
            length = min(self._q("length", 4096, int), 1 << 20)
            src = self._region_from_query()
            data = src.read_at(off, length)
            return self._send(200, {"offset": off, "length": len(data),
                                    "data": base64.b64encode(data).decode(),
                                    "source_size": src.size})

        if path == "/api/dir":
            off = self._q("part", 0, int)
            ev = s.evidence(self._q("ev", None)) or s.current
            try:
                fs = s.fs(off, ev=ev)
            except ntfs_mod.EncryptedVolume as exc:
                return self._send(200, {"entries": [], "encrypted": True,
                                        "kind": exc.kind, "part": off,
                                        "error": str(exc)})
            node = self._q("node", None)
            root = getattr(fs, "root_node", None)
            if root is None:
                root = {"NTFS": 5, "ext4": 2, "ext3": 2, "ext2": 2,
                        "APFS": 2}.get(fs.name, 0)
            handle = int(node) if node not in (None, "") else root
            if getattr(fs, "index_pending", None) and fs.index_pending():
                return self._send(200, {"building": True,
                                        "task": s.ensure_index(off, fs,
                                                               ev=ev)})
            entries = fs.listdir(handle, self._q("path", "/"))
            typed = capped = 0
            if self._q("types", "") in ("1", "true"):
                for e in entries:
                    if e.get("is_dir"):
                        continue
                    if typed >= TYPE_CHECK_CAP:
                        capped += 1
                        continue
                    size = e.get("size") or 0
                    data = b""
                    if size:
                        try:
                            data = fs.read_file(e, filetype_mod.HEAD_BYTES)
                        except Exception:
                            data = None
                    e["type_check"] = filetype_mod.examine(
                        data, e.get("name"), size=size)
                    typed += 1
            return self._send(200, {"entries": entries, "fs": fs.info(),
                                    "part": off, "root_node": root,
                                    "types_checked": typed,
                                    "types_skipped": capped})

        if path == "/api/stat":
            off = self._q("part", 0, int)
            fs = s.fs(off)
            entry = json.loads(self._q("entry", "{}"))
            stream = self._q("stream", "")
            try:
                info = fs.stat(entry, stream) if stream else fs.stat(entry)
            except TypeError:
                info = fs.stat(entry)
                if stream:
                    info["stream_unsupported"] = True
            info["partition_offset"] = off
            if "runs" in info:
                for r in info["runs"]:
                    if r.get("offset") is not None:
                        r["absolute"] = r["offset"] + off
            if info.get("slack"):
                info["slack"]["absolute"] = info["slack"]["offset"] + off

            if (s.case and s.evidence_id is not None
                    and not entry.get("is_dir") and not stream):
                node = hashing_mod.node_key(entry)
                got = s.case.hash_for(s.evidence_id, off, node) if node else None
                if got:
                    digests = [got.get("md5"), got.get("sha1"),
                               got.get("sha256")]
                    matches = s.case.match_hashes([d for d in digests if d])
                    hits = []
                    for d in digests:
                        for m in matches.get((d or "").lower(), []):
                            hits.append(m)
                    got["matches"] = hits
                    read = got.get("read_bytes")
                    claimed = got.get("size")
                    got["partial"] = (read is not None and claimed is not None
                                      and read < claimed)
                    got["read_unknown"] = read is None
                    got["claimed_size"] = claimed
                    info["hashes"] = got
            if not entry.get("is_dir") and (entry.get("size") or 0) > 0:
                try:
                    sample = fs.read_file(entry, 1 << 20)
                    if sample:
                        e = entropy_mod.describe(sample)
                        e["sampled"] = len(sample) < (entry.get("size") or 0)
                        info["entropy"] = e
                        got = exif_mod.parse(sample)
                        if got:
                            info["exif"] = got
                except Exception:
                    pass
            return self._send(200, info)

        if path == "/api/preview":
            off = self._q("part", 0, int)
            fs = s.fs(off)
            entry = json.loads(self._q("entry", "{}"))
            n = min(self._q("length", 65536, int), 1 << 20)
            stream = self._q("stream", "")
            try:
                data = fs.read_file(entry, n, stream) if stream \
                    else fs.read_file(entry, n)
            except _STREAM_ERRORS as exc:
                return self._send(400, _stream_error(exc, stream))
            size = entry.get("size", 0)
            if stream:
                size = next((t["size"] for t in _streams_of(fs, entry)
                             if t["name"] == stream), len(data))
            return self._send(200, {"data": base64.b64encode(data).decode(),
                                    "length": len(data),
                                    "stream": stream or None,
                                    "size": size})

        if path == "/api/volumemap":
            part = self._q("part", None, int)
            if part is None:
                return self._send(200, {"covered": False, "spans": [],
                                        "note": _t("server.volumemap.volume_map_needs_volume")})
            ev = s.evidence(self._q("ev", None)) or s.current
            if ev is None:
                return self._send(409, {"error": _t("server.case_peek.evidence_open")})
            size = next((p2["size"] for p2 in ev.volumes["partitions"]
                         if p2["offset"] == part), None)
            try:
                fs = s.fs(part, ev=ev)
            except ntfs_mod.EncryptedVolume as exc:
                return self._send(200, {"covered": False, "spans": [],
                                        "encrypted": True, "kind": exc.kind,
                                        "note": str(exc)})
            except Exception as exc:
                return self._send(200, {"covered": False, "spans": [],
                                        "note": str(exc)})
            got = volmap_mod.volume_map(fs, size)
            got["part"] = part
            return self._send(200, got)

        if path == "/api/structure":
            part = self._q("part", None, int)
            structs = s.structures()
            if part is None:
                return self._send(200, {"structures": structs, "base": 0})
            region = None
            for p in s.volumes["partitions"]:
                if p["offset"] == part:
                    region = p
                    break
            lo = part
            hi = part + (region["size"] if region else (s.image.size - part))
            out = []
            for st in structs:
                if not (lo <= st["offset"] < hi):
                    continue
                st = dict(st, offset=st["offset"] - lo,
                          fields=[dict(f, offset=f["offset"] - lo)
                                  for f in st["fields"]])
                out.append(st)
            return self._send(200, {"structures": out, "base": lo})

        if path == "/api/registry":
            off = self._q("part", 0, int)
            entry = json.loads(self._q("entry", "{}"))
            hive = s.hive(off, entry)
            if hive is None:
                return self._send(400, {"error": _t("server.registry.registry_hive")})
            keypath = self._q("key", "")
            k = hive.open_path(keypath)
            if not k:
                return self._send(404, {"error": _t("server.registry.such_key") % keypath})
            info = hive.info()
            info["replay"] = getattr(hive, "replay", None)
            return self._send(200, {
                "info": info, "path": keypath,
                "key": k,
                "subkeys": hive.subkeys(k),
                "values": hive.values(k),
            })

        if path == "/api/registry/value":
            off = self._q("part", 0, int)
            entry = json.loads(self._q("entry", "{}"))
            hive = s.hive(off, entry)
            if hive is None:
                return self._send(400, {"error": _t("server.registry.registry_hive")})
            vk_offset = self._q("offset", -1, int)
            v = hive.value(vk_offset, inline=False)
            if v is None:
                return self._send(404, {"error": _t("server.registry.such_value")})
            raw = hive.value_bytes(vk_offset)
            v["value"] = hive.decode(v["type_id"], raw)
            v.pop("truncated", None)
            return self._send(200, v)

        if path == "/api/mail/attachment":
            off = self._q("part", 0, int)
            fs = s.fs(off)
            entry = json.loads(self._q("entry", "{}"))
            data = fs.read_file(entry, 512 << 20)
            p = pst_mod.open_pst(data) if pst_mod.looks_like_pst(data[:8]) \
                else None
            if p is None:
                return self._send(400,
                                  {"error": _t("server.mail.not_pst")})
            node = p.nbt().get(self._q("msg", -1, int))
            if not node:
                return self._send(404,
                                  {"error": _t("server.mail.no_message")})
            att_nid = self._q("att", -1, int)
            content = p.attachment_bytes(node, att_nid)
            if content is None:
                return self._send(404,
                                  {"error": _t("server.mail.no_attachment")})
            ctype = None
            for a in p.attachments(node):
                if a.get("nid") == att_nid:
                    ctype = a.get("content_type")
                    break
            return self._send(200, {
                "bytes": len(content), "content_type": ctype or _sniff_mime(content),
                "preview": base64.b64encode(content[:MAX_INLINE]).decode(),
                "truncated": len(content) > MAX_INLINE,
            })

        if path == "/api/registry/deleted":
            off = self._q("part", 0, int)
            entry = json.loads(self._q("entry", "{}"))
            hive = s.hive(off, entry)
            if hive is None:
                return self._send(400, {"error": _t("server.registry.registry_hive")})
            return self._send(200, hive.carve_deleted())

        if path == "/api/file":
            off = self._q("part", 0, int)
            fs = s.fs(off)
            entry = json.loads(self._q("entry", "{}"))
            try:
                info = fs.stat(entry)
            except Exception:
                info = {}
            size = info.get("size")
            if size is None:
                size = entry.get("size") or 0
            size = min(size, MAX_STREAM)
            cur = s.current
            region = FileRegion(fs, entry, size, "",
                                cur.file_bytes if cur is not None else None)
            ctype = _sniff_mime(region.read_at(0, 64))
            return self._send_range_region(region, size, ctype)

        if path == "/api/thumbnail":
            off = self._q("part", 0, int)
            fs = s.fs(off)
            entry = json.loads(self._q("entry", "{}"))
            try:
                sample = fs.read_file(entry, 1 << 20)
            except Exception:
                sample = None
            thumb = exif_mod.thumbnail(sample) if sample else None
            if not thumb:
                return self._send(404,
                                  {"error": _t("server.thumbnail.no_thumbnail")})
            return self._send_range(thumb, _sniff_mime(thumb))

        if path == "/api/document":
            off = self._q("part", 0, int)
            fs = s.fs(off)
            entry = json.loads(self._q("entry", "{}"))
            size = int(entry.get("size") or 0)
            if size > MAX_ARCHIVE:
                return self._send(400, {
                    "error": _t("server.document.document_ceiling_reading_one") % (fmt_bytes(size), fmt_bytes(MAX_ARCHIVE))})
            got = officedoc_mod.parse(fs.read_file(entry, MAX_ARCHIVE),
                                      entry.get("name") or "")
            if not got:
                return self._send(200, {
                    "document": False,
                    "note": _t("server.document.office_document_its_content")})
            got["document"] = True
            return self._send(200, got)

        if path == "/api/archive":
            off = self._q("part", 0, int)
            fs = s.fs(off)
            entry = json.loads(self._q("entry", "{}"))
            inner = self._q("inner", None)
            size = int(entry.get("size") or 0)
            if size > MAX_ARCHIVE:
                return self._send(400, {
                    "error": _t("server.archive.archive_ceiling_opening_one")
                             % (fmt_bytes(size), fmt_bytes(MAX_ARCHIVE))})
            blob = fs.read_file(entry, min(size or MAX_ARCHIVE, MAX_ARCHIVE))
            z = archive_mod.Zip(blob, entry.get("name") or "")
            if not z.valid:
                return self._send(400, {
                    "error": _t("server.archive.readable_archive"),
                    "findings": z.findings})
            if inner is None:
                return self._send(200, z.info())
            data, notes = z.read({"name": inner})
            return self._send(200, {
                "name": inner, "bytes": len(data), "notes": notes,
                "preview": base64.b64encode(data[:MAX_INLINE]).decode(),
                "truncated": len(data) > MAX_INLINE,
            })

        if path == "/api/timezone":
            applied = s.case.get("timezone_offset")
            return self._send(200, {
                "candidates": s.tz_candidates,
                "detected": s.tz_scanned,
                "applied": json.loads(applied) if applied else None,
                "note": _t("server.timezone.timestamps_stored_reported_utc"),
            })

        if path == "/api/render":
            off = self._q("part", 0, int)
            fs = s.fs(off)
            entry = json.loads(self._q("entry", "{}"))
            size = int(entry.get("size") or 0)
            data = fs.read_file(entry, min(size or MAX_STREAM, MAX_STREAM))
            want = self._q("as", "")

            if pdfdoc_mod.looks_like_pdf(data[:5]):
                doc = pdfdoc_mod.Pdf(data)
                if want == "bytes":
                    clean = doc.sanitised()
                    if clean is None:
                        return self._send(409, {
                            "error": _t("server.render.pdf_could_made_inert"),
                            "findings": doc.findings})
                    s.case.log("preview.render", {
                        "path": entry.get("path"), "type": "pdf",
                        "neutralised": [a["key"] for a in doc.active
                                        if a.get("neutralised")]})
                    return self._send_bytes(clean, "application/pdf",
                                            saferender_mod.CSP_PDF)
                info = doc.info()
                info["text"] = doc.text(20000)
                return self._send(200, info)

            kind = _markup_kind(data, entry.get("name") or "")
            if kind:
                r = saferender_mod.sanitise_html(data, is_svg=(kind == "svg"))
                if not r["ok"]:
                    return self._send(200, {"type": kind, "renderable": False,
                                            "findings": r["findings"]})
                if want == "bytes":
                    s.case.log("preview.render", {
                        "path": entry.get("path"), "type": kind,
                        "removed": len(r["findings"])})
                    body = ("<!doctype html><meta charset=utf-8>"
                            "<style>body{font:13px system-ui;margin:12px;"
                            "color:#c6d2da;background:#171f26}"
                            "img{max-width:100%}</style>" + r["html"])
                    return self._send_bytes(body.encode("utf-8"),
                                            "text/html; charset=utf-8",
                                            saferender_mod.CSP)
                return self._send(200, {"type": kind, "renderable": True,
                                        "findings": r["findings"],
                                        "removed": len(r["findings"])})

            return self._send(400, {"error": _t("server.render.nothing_here_needs_sanitising")})

        if path == "/api/task":
            tid = self._q("id")
            t = s.tasks.get(tid)
            if not t:
                return self._send(200, {"error": _t("server.task.such_task")})
            out = {k: v for k, v in t.items() if k != "partial"}
            live = t.get("partial")
            if live is not None:
                n = len(live)
                since = min(self._q("since", 0, int), n)
                out["found"] = n
                out["new"] = live[since:min(n, since + 2000)]
            return self._send(200, out)

        if path == "/api/artefacts":
            if not s.case or s.evidence_id is None:
                return self._send(200, {"items": {}, "dropped": [],
                                        "note": _t("server.artefacts.case_file_so_nothing")})
            return self._send(200, s.case.artefacts(s.evidence_id))

        if path == "/api/tasks":
            items = s.task_list()
            return self._send(200, {
                "tasks": items,
                "running": sum(1 for t in items if t["state"] == "running"),
            })

        if path == "/api/searches":
            return self._send(200, {"searches": s.case.searches()})

        if path == "/api/search/saved":
            got = s.case.search_hits(self._q("id", 0, int))
            if not got:
                return self._send(404, {"error": _t("server.search_saved.such_saved_search")})
            return self._send(200, got)

        if path == "/api/encryption":
            part = self._q("part", 0, int)
            v = s.vault(part)
            if v is None:
                return self._send(200, {"encrypted": False, "part": part})
            info = v.info()
            info["encrypted"] = True
            info["part"] = part
            info["unlocked"] = part in s.unlocked
            return self._send(200, info)

        if path == "/api/index/status":
            part = self._q("part", None, int)
            return self._send(200, textindex_mod.status(
                s.case, part, None if part is None else s.evidence_id))

        if path == "/api/hashes":
            return self._send(200, {"items": s.case.hashes(s.evidence_id)})

        if path == "/api/hashmap":
            if not s.case or s.evidence_id is None:
                return self._send(200, {"map": {}})
            return self._send(200, {
                "map": hashing_mod.matched_hash_map(
                    s.case, s.evidence_id, self._q("part", 0, int))})

        if path == "/api/attack":
            cat = None
            if s.case:
                got = s.case.attack_catalogue()
                if got:
                    cat = attack_mod.imported(got[0], got[1])
            cat = cat or attack_mod.builtin()
            out = {"catalogue": cat}
            if s.case and s.evidence_id is not None:
                out["tags"] = s.case.attack_tags(s.evidence_id)
                out["summary"] = s.case.attack_summary(s.evidence_id)
            else:
                out["tags"], out["summary"] = [], []
            kind = self._q("suggest")
            if kind:
                out["suggestions"] = attack_mod.suggestions_for(
                    kind, cat["techniques"] and
                    [(t["id"], t["name"], t["tactic"]) for t in cat["techniques"]])
            return self._send(200, out)

        if path == "/api/hashsets":
            return self._send(200, {"sets": s.case.hash_sets()})

        if path == "/api/hashes/duplicates":
            if not s.case:
                return self._send(200, {"groups": []})
            groups = s.case.duplicate_files()
            for g in groups:
                for it in g["items"]:
                    held = s.items.get(it.get("evidence_id"))
                    it["exhibit"] = held.label if held else None
            return self._send(200, {"groups": groups})

        if path == "/api/hashes/similar":
            if not s.case:
                return self._send(200, {"pairs": []})
            pairs = s.case.similar_files(
                threshold=self._q("threshold", 60, int))
            for p in pairs:
                for side in ("a", "b"):
                    held = s.items.get(p[side].get("evidence_id"))
                    p[side]["exhibit"] = held.label if held else None
            return self._send(200, {"pairs": pairs})

        if path == "/api/recyclebin":
            part = self._q("part", 0, int)
            fs = s.fs(part)
            root = _root_node(fs)
            out = recyclebin_mod.scan(fs, lambda node, p: fs.listdir(node, p),
                                      root)
            s.keep_artefact("recyclebin", part, out)
            return self._send(200, out)

        if path == "/api/lnk":
            part = self._q("part", 0, int)
            fs = s.fs(part)
            entry = json.loads(self._q("entry", "{}"))
            jump_suffixes = (".automaticdestinations-ms",
                             ".customdestinations-ms")
            if entry:
                if (entry.get("name") or "").lower().endswith(jump_suffixes):
                    data = fs.read_file(entry, 16 << 20)
                    r = jumplist_mod.parse(data, entry.get("name") or "")
                    if not r:
                        return self._send(400, {"error": _t("server.lnk.jump_list")})
                    return self._send(200, r)
                data = fs.read_file(entry, 1 << 20)
                r = lnk_mod.parse(data)
                if not r:
                    return self._send(400, {"error": _t("server.lnk.shortcut_file")})
                return self._send(200, r)
            root = _root_node(fs)
            found, jumps = [], []
            stat = {"seen": 0, "empty": 0, "unparsed": 0,
                    "jumplists": 0, "jumplists_empty": 0,
                    "jumplists_unparsed": 0}
            for e in filesearch_mod.collect(fs, root):
                if e.get("is_dir"):
                    continue
                nm = (e.get("name") or "").lower()
                if nm.endswith(jump_suffixes):
                    stat["jumplists"] += 1
                    try:
                        data = fs.read_file(e, 16 << 20)
                    except Exception:
                        data = b""
                    if not data:
                        stat["jumplists_empty"] += 1
                        continue
                    try:
                        r = jumplist_mod.parse(data, e.get("name") or "")
                    except Exception:
                        r = None
                    if not r:
                        stat["jumplists_unparsed"] += 1
                        continue
                    r["source"] = e.get("path")
                    r["source_name"] = e.get("name")
                    r["app_id"] = (e.get("name") or "").split(".", 1)[0]
                    r["entry"] = e
                    jumps.append(r)
                    continue
                if not nm.endswith(".lnk"):
                    continue
                stat["seen"] += 1
                try:
                    data = fs.read_file(e, 1 << 20)
                except Exception:
                    data = b""
                if not data:
                    stat["empty"] += 1
                    continue
                try:
                    r = lnk_mod.parse(data)
                except Exception:
                    r = None
                if not r:
                    stat["unparsed"] += 1
                    continue
                r["source"] = e.get("path")
                r["source_name"] = e.get("name")
                r["entry"] = e
                found.append(r)
            out = {"items": found, "jumplists": jumps, "stat": stat,
                   "scanned": stat["seen"] + stat["jumplists"]}
            s.keep_artefact("lnk", part, out)
            return self._send(200, out)

        if path == "/api/vss":
            part = self._q("part", 0, int)
            region = s.region(part)
            r = vss_mod.snapshots(region)
            if not r.get("present"):
                r["note"] = ("No shadow copy store on this volume — the VSS "
                             "volume header at 0x1E00 is absent or empty.")
            s.keep_artefact("vss", part, r)
            return self._send(200, r)

        if path in ("/api/timeline/summary", "/api/timeline/page",
                    "/api/timeline/flag", "/api/timeline/histogram"):
            key = self._q("key", "") or ""
            if not _TIMELINE_KEY.match(key):
                return self._send(400, {"error": _t("server.timeline.bad_key")})
            store = s.timeline_path(key)

            def span():
                a = self._q("start", "") or ""
                b = self._q("end", "") or ""
                if a == "" and b == "":
                    return None, None
                lo, hi = float(a), float(b)
                if not (lo < hi) or abs(lo) > 3e11 or abs(hi) > 3e11:
                    raise ValueError((a, b))
                return lo, hi

            if path == "/api/timeline/histogram":
                try:
                    lo, hi = span()
                except ValueError:
                    return self._send(400, {"error": _t("server.timeline.bad_range")})
                got = timeline_mod.histogram(
                    store, bins=self._q("bins", 300, int), start=lo, end=hi,
                    q=(self._q("q", "") or "").strip() or None,
                    flagged=self._q("flagged", "") in ("1", "true"))
                if got is None:
                    return self._send(404, {"error": _t("server.timeline.not_built")})
                return self._send(200, got)
            if path == "/api/timeline/summary":
                got = timeline_mod.summary(store)
                return self._send(200, {"exists": got is not None,
                                        "key": key, "summary": got})
            if path == "/api/timeline/page":
                raw = self._q("cursor", "") or ""
                try:
                    cursor = json.loads(raw) if raw else None
                    if cursor is not None and not (
                            isinstance(cursor, list) and len(cursor) == 4):
                        raise ValueError(raw)
                except ValueError:
                    return self._send(400, {"error": _t("server.timeline.bad_cursor")})
                try:
                    lo, hi = span()
                except ValueError:
                    return self._send(400, {"error": _t("server.timeline.bad_range")})
                got = timeline_mod.page(
                    store, cursor=cursor, limit=self._q("limit", 400, int),
                    q=(self._q("q", "") or "").strip() or None,
                    flagged=self._q("flagged", "") in ("1", "true"),
                    start=lo, end=hi)
                if got is None:
                    return self._send(404, {"error": _t("server.timeline.not_built")})
                return self._send(200, got)
            got = timeline_mod.observations(
                store, self._q("ev", None, int), self._q("part", None, int),
                self._q("node", "") or None)
            return self._send(200, {"flag": got})

        if path == "/api/tags":
            return self._send(200, {
                "items": s.case.tagged(s.evidence_id, self._q("tag") or None),
                "counts": s.case.tag_counts(),
                "suggested": casedb_mod.DEFAULT_TAGS,
            })

        if path == "/api/bookmarks":
            return self._send(200, s.case.bookmarks(s.evidence_id))

        if path == "/api/bookmark/categories":
            return self._send(200, {"categories": casedb_mod.MARK_CATEGORIES})

        if path == "/api/audit":
            return self._send(200, {"entries": s.case.audit(),
                                    "integrity": s.case.verify_audit()})

        if path == "/api/filetypes":
            ev = s.evidence(self._q("evidence", None))
            return self._send(200, {
                "mismatches": s.case.type_mismatches(
                    ev.evidence_id if ev else None),
                "scans": s.case.type_scan_summary(),
            })

        if path == "/api/registry/report":
            return self._send(200, {"hives": getattr(s, "reg_report", []) or []})

        if path == "/api/usn":
            got = getattr(s, "usn", None)
            if not got:
                return self._send(200, {"loaded": False, "records": [],
                                        "total": 0})
            recs = got["records"]
            q = (self._q("q", "") or "").lower()
            reason = self._q("reason", "") or ""
            if q:
                recs = [r for r in recs if q in (r.get("name") or "").lower()]
            if reason:
                recs = [r for r in recs if reason in r.get("reasons", [])]
            total = len(recs)
            off = max(0, self._q("offset", 0, int) or 0)
            n = min(2000, max(1, self._q("limit", 200, int) or 200))
            return self._send(200, {
                "loaded": True, "total": total, "offset": off,
                "records": recs[off:off + n],
                "stats": got["stats"], "journal": got["journal"],
                "part": got["part"],
                "reasons": sorted({x for r in got["records"]
                                   for x in r.get("reasons", [])}),
            })

        if path == "/api/artifacts":
            avail, why = set(), {}
            ev = s.current
            if ev is not None:
                parts = [p for p in ev.volumes["partitions"]
                         if p.get("allocated") and p.get("detected")]
                kinds = {p.get("detected") for p in parts}
                has_ntfs = "NTFS" in kinds
                has_fs = bool(parts)
                for a in artifacts_mod.CATALOGUE:
                    ok, reason = True, None
                    if "NTFS" in a["needs"] and not has_ntfs:
                        ok, reason = False, "No NTFS volume on this image."
                    elif "Windows volume" in a["needs"] and not has_ntfs:
                        ok, reason = False, "No Windows volume on this image."
                    elif "filesystem walk" in a["needs"] and not has_fs:
                        ok = False
                        reason = "No readable filesystem on this image."
                    if ok:
                        avail.add(a["id"])
                    else:
                        why[a["id"]] = reason
            rows = artifacts_mod.catalogue(avail if ev is not None else None)
            for r in rows:
                if r["id"] in why:
                    r["unavailable_because"] = why[r["id"]]
            return self._send(200, {
                "artifacts": rows,
                "triage": artifacts_mod.TRIAGE,
                "open": ev is not None,
                "note": _t("server.artifacts.cost_what_will_take"),
            })

        if path == "/api/artifacts/presence":
            ev = s.current
            agg = {"recyclebin": {"found": False, "count": 0},
                  "prefetch": {"found": False, "count": 0},
                  "browser": {"found": False, "profiles": []}}
            if ev is not None:
                parts = [p for p in ev.volumes["partitions"]
                        if p.get("allocated") and p.get("detected")]
                for p in parts:
                    try:
                        fs = s.fs(p["offset"])
                    except Exception:
                        continue
                    got = artifacts_mod.presence(fs, _root_node(fs))
                    for key in ("recyclebin", "prefetch"):
                        agg[key]["found"] = agg[key]["found"] or got[key]["found"]
                        agg[key]["count"] += got[key]["count"]
                    if got["browser"]["found"]:
                        agg["browser"]["found"] = True
                        agg["browser"]["profiles"] += got["browser"]["profiles"]
            return self._send(200, agg)

        if path == "/api/triage":
            return self._send(200, _triage(s))

        if path == "/api/evidence":
            return self._send(200, {
                "items": [i.brief() for i in s.items.values()],
                "active_id": s.active_id,
                "case": s.case.summary() if s.case else None,
            })

        if path == "/api/report":
            if self._q("format", "") == "html":
                return self._send(200, _render_report(s), "text/html; charset=utf-8")
            return self._send(200, s.case.report())

        return self._send(404, {"error": _t("server.report.unknown_route")})

    def _region_from_query(self):
        sess = self._session()
        part = self._q("part", None, int)
        raw = self._q("entry", "")
        if raw:
            fs = sess.fs(part or 0)
            entry = json.loads(raw)
            stream = self._q("stream", "")
            try:
                info = fs.stat(entry, stream) if stream else fs.stat(entry)
            except Exception:
                info = {}
            size = info.get("size")
            if size is None:
                size = entry.get("size") or 0
            cur = sess.current
            return FileRegion(fs, entry, size, stream,
                              cur.file_bytes if cur is not None else None)
        if part is None:
            return sess.image
        return sess.region(part)

    def _api_post(self, path, body):
        s = self._session()
        if path == "/api/whoami":
            name = (body.get("name") or "").strip()
            if not name:
                return self._send(400, {"error": _t("server.whoami.examiner_name_needed_what")})
            REGISTRY.name(getattr(self, "_sid", None), name)
            if s.case is not None and s.case.examiner != name:
                before = s.case.examiner
                s.case.examiner = name
                s.case.log("examiner.change", {"from": before, "to": name})
            return self._send(200, {"name": name})

        if path == "/api/prefs":
            who = self._who(s, body.get("examiner"))
            return self._send(200, {"examiner": who,
                                    "prefs": prefs_mod.put(who, body)})

        if path == "/api/carve/signature":
            try:
                _, canon = carve_mod.custom_signature(body.get("signature"))
            except carve_mod.SignatureError as exc:
                return self._send(400, {"error": _carve_error(exc),
                                        "field": exc.key})
            return self._send(200, {"signature": canon})

        if path == "/api/prefs/reset":
            who = self._who(s, body.get("examiner"))
            return self._send(200, {"examiner": who,
                                    "prefs": prefs_mod.forget(who)})

        if path == "/api/open":
            p = body.get("path")
            kind = body.get("kind")
            if kind is None and body.get("logical"):
                kind = "logical"
            if kind is None and p and s.case:
                kind = s.case.evidence_kind(p)
            kind = "file" if kind == "zip" else (kind or "image")
            if kind not in ("image", "file", "folder", "logical"):
                return self._send(400, {"error": _t("server.open.bad_kind") % kind})
            if not p or not os.path.exists(p):
                return self._send(400, {"error": _t("server.open.file_found") % p})
            if kind in ("image", "file") and os.path.isdir(p):
                return self._send(400, {"error": _t("server.open.not_a_file") % p})
            if kind == "folder" and not os.path.isdir(p):
                return self._send(400, {"error": _t("server.open.not_a_folder") % p})
            want_logical = kind != "image"
            if not body.get("add") and s.running_tasks():
                return self._send(409, self._tasks_busy(s, "replace what is open"))
            try:
                return self._send(200, s.open(p, body.get("case"),
                                              self._claim(s, body),
                                              add=bool(body.get("add")),
                                              logical=want_logical))
            except casedb_mod.NotACase as exc:
                return self._send(400, {"error": str(exc)})
            except ewf_mod.UnsupportedContainer as exc:
                return self._send(400, {
                    "error": _t("server.open.read_by_strata") % exc.format,
                    "format": exc.format, "advice": exc.advice})

        if path == "/api/report/write":
            if not s.case:
                return self._send(400, {"error": _t("server.export.case_open")})
            dest = body.get("path") or os.path.join(
                os.path.dirname(s.case.path),
                "%s-report.html" % os.path.splitext(
                    os.path.basename(s.case.path))[0])
            try:
                got = report_mod.write(dest, _render_report(s))
            except ValueError as exc:
                return self._send(400, {"error": str(exc)})
            except OSError as exc:
                return self._send(400, {"error": _t("server.report_write.could_write") % exc})
            s.case.log("report.write", {"path": got["path"],
                                        "bytes": got["bytes"]})
            return self._send(200, got)

        if path == "/api/registry/report":
            across = bool(body.get("all_evidence"))
            targets = (list(s.items.values()) if across
                       else ([s.current] if s.current else []))

            def run(progress):
                out = []
                jobs = []
                for ev in targets:
                    for p in ev.volumes["partitions"]:
                        if p.get("allocated") and p.get("detected"):
                            jobs.append((ev, p))
                for n, (ev, p) in enumerate(jobs):
                    progress(n / max(1, len(jobs)))
                    try:
                        fs = s.fs(p["offset"], ev=ev)
                        entries = filesearch_mod.collect(fs, _root_node(fs))
                    except Exception:
                        continue
                    for e in entries:
                        nm = (e.get("name") or "").lower()
                        if nm not in ("system", "software", "sam", "security",
                                      "ntuser.dat", "usrclass.dat"):
                            continue
                        if e.get("is_dir"):
                            continue
                        hive, head = None, None
                        try:
                            if (e.get("size") or 0) >= 4096:
                                hive = s.hive(p["offset"], e, ev=ev)
                        except Exception:
                            hive = None
                        if hive is None:
                            try:
                                fsx = s.fs(p["offset"], ev=ev)
                                head = fsx.read_file(e, 8 << 20)
                            except Exception:
                                head = None
                        rep = regreport_mod.report(
                            hive, e.get("path") or e.get("name"), data=head,
                            whole=head is not None
                            and len(head) >= (e.get("size") or 0))
                        if not rep.get("kind") and not rep.get("unreadable"):
                            continue
                        rep["exhibit"] = ev.label
                        rep["evidence"] = ev.evidence_id
                        rep["part"] = p["offset"]
                        rep["partition"] = p["slot"]
                        rep["size"] = e.get("size")
                        out.append(rep)
                progress(1.0)
                s.reg_report = out
                s.case.log("registry.report", {
                    "hives": len(out),
                    "unreadable": sum(1 for r in out if r.get("unreadable"))})
                return {"hives": out}

            return self._send(200, s.start_task(
                "registry", run, label="Reading well-known registry keys",
                detail="Machine identity, USB devices, networks joined, "
                       "auto-start programs, installed software, accounts and "
                       "user activity — read from the hives rather than "
                       "navigated to by hand."))

        if path == "/api/filetypes/scan":
            across = bool(body.get("all_evidence"))
            targets = (list(s.items.values()) if across
                       else ([s.current] if s.current else []))
            want_part = body.get("part")

            def run(progress):
                out = []
                jobs = []
                for ev in targets:
                    for p in ev.volumes["partitions"]:
                        if not (p.get("allocated") and p.get("detected")):
                            continue
                        if want_part is not None and p["offset"] != int(want_part):
                            continue
                        jobs.append((ev, p))
                for n, (ev, p) in enumerate(jobs):
                    base = n / max(1, len(jobs))
                    span = 1.0 / max(1, len(jobs))

                    def sub(frac, base=base, span=span):
                        progress(min(0.999, base + span * frac))

                    try:
                        fs = s.fs(p["offset"], ev=ev)
                        entries = filesearch_mod.collect(fs, _root_node(fs))
                    except Exception as exc:
                        out.append({"exhibit": ev.label, "partition": p["slot"],
                                    "error": str(exc)})
                        continue
                    r = filetype_mod.scan(fs, entries, progress=sub)
                    s.case.save_type_scan(ev.evidence_id, p["offset"], r)
                    out.append({
                        "exhibit": ev.label, "evidence": ev.evidence_id,
                        "partition": p["slot"], "part": p["offset"],
                        "filesystem": fs.name,
                        "checked": r["checked"],
                        "mismatches": r["mismatch_count"],
                        "high": sum(1 for m in r["mismatches"]
                                    if m["severity"] == "high"),
                        "census": r["census"],
                    })
                progress(1.0)
                return {"scans": out,
                        "mismatches": s.case.type_mismatches(),
                        "note": filetype_mod.scan(None, [])["note"]}

            return self._send(200, s.start_task(
                "filetypes", run, label="Verifying file types",
                detail="Reading the first few hundred bytes of every file and "
                       "comparing what it holds against what its name claims."))

        if path == "/api/dir/recurse":
            part = int(body.get("part") or 0)
            ev = s.evidence(body.get("ev")) or s.current
            try:
                fs = s.fs(part, ev=ev)
            except ntfs_mod.EncryptedVolume as exc:
                return self._send(200, {"entries": [], "encrypted": True,
                                        "kind": exc.kind, "part": part,
                                        "error": str(exc)})
            if getattr(fs, "index_pending", None) and fs.index_pending():
                return self._send(200, {"building": True,
                                        "task": s.ensure_index(part, fs,
                                                               ev=ev)})
            node = body.get("node")
            handle = int(node) if node not in (None, "") else _root_node(fs)
            start = body.get("path") or "/"

            def run(progress):
                state = {}
                entries = filesearch_mod.collect(
                    fs, handle, path=start, state=state,
                    progress=lambda n: progress(0.0, count=n))
                progress(1.0, count=len(entries))
                return {
                    "entries": entries,
                    "part": part,
                    "root_path": start,
                    "truncated": bool(state.get("truncated")),
                    "budget": filesearch_mod.DEFAULT_BUDGET,
                }

            return self._send(200, s.start_task(
                "recurse", run,
                label=_t("server.recurse.label")
                      % (body.get("name") or start),
                detail=_t("server.recurse.detail")))

        if path == "/api/evidence/select":
            ev = s.evidence(body.get("evidence_id"))
            if ev is None:
                return self._send(400, {"error": _t("server.evidence_select.such_evidence_item")})
            s.active_id = ev.evidence_id
            return self._send(200, s.state())

        if path == "/api/evidence/holdings":
            if not s.case:
                return self._send(400, {"error": _t("server.export.case_open")})
            ev_id = body.get("evidence_id")
            row = next((i for i in s.case.summary()["evidence"]
                        if i["id"] == ev_id), None)
            if row is None:
                return self._send(400, {"error": _t("server.evidence_select.such_evidence_item")})
            return self._send(200, {
                "evidence_id": ev_id, "path": row["path"],
                "label": row["label"],
                "holdings": s.case.evidence_holdings(ev_id),
            })

        if path == "/api/evidence/remove":
            if not s.case:
                return self._send(400, {"error": _t("server.export.case_open")})
            ev_id = body.get("evidence_id")
            gone = s.case.remove_evidence(ev_id)
            if gone is None:
                return self._send(400, {"error": _t("server.evidence_select.such_evidence_item")})
            gone["timelines"] = s.drop_timelines(
                ev_id, tagged=bool(gone.get("removed")))
            s.close(ev_id)
            state = s.state()
            state["removed"] = gone
            return self._send(200, state)

        if path == "/api/evidence/close":
            if not s.close(body.get("evidence_id")):
                return self._send(400, {"error": _t("server.evidence_select.such_evidence_item")})
            return self._send(200, s.state())

        if path == "/api/case/new":
            cp = (body.get("path") or "").strip()
            if not cp:
                return self._send(400, {"error": _t("server.case_new.path_new_case")})
            cp = os.path.abspath(os.path.expanduser(cp))
            if not cp.lower().endswith(".strata"):
                cp += ".strata"
            if os.path.exists(cp):
                return self._send(400, {
                    "error": _t("server.case_new.there_already_file_open") % cp,
                    "exists": cp})
            parent = os.path.dirname(cp)
            if parent and not os.path.isdir(parent):
                return self._send(400, {
                    "error": _t("server.case_new.there_folder") % parent})
            if s.running_tasks():
                return self._send(409, self._tasks_busy(s, "start a new case"))
            try:
                return self._send(200, s.new_case(
                    cp, body.get("name"), self._claim(s, body)))
            except Exception as exc:
                return self._send(400, {
                    "error": _t("server.case_new.could_create_case") % exc})

        if path == "/api/case/close":
            if not s.case:
                return self._send(400, {"error": _t("server.export.case_open")})
            if s.running_tasks():
                return self._send(409, self._tasks_busy(s, "close the case"))
            return self._send(200, s.close_case())

        if path == "/api/case/forget":
            who = self._who(s, body.get("examiner"))
            cp = body.get("path")
            left = recents_mod.forget(who, cp)
            return self._send(200, {"cases": recents_mod.entries(who),
                                    "forgotten": cp, "remaining": len(left),
                                    "note": _t("server.case_forget.removed_from_list_only")})

        if path == "/api/case/open":
            cp = body.get("path")
            if not cp or not casedb_mod.is_case(cp):
                return self._send(400, {"error": _t(
                    "casedb.not_a_case" if cp and os.path.exists(cp)
                    else "server.case_peek.such_case_file") % cp})
            who = self._claim(s, body)
            if s.running_tasks():
                return self._send(409, self._tasks_busy(s, "open another case"))
            try:
                peek = Case(cp, read_only=True)
                items = peek.summary()["evidence"]
                peek.close()
            except Exception as exc:
                return self._send(400, {"error": _t("server.case_peek.strata_case_file") % exc})
            if not items:
                return self._send(200, s.open_case(cp, who))
            want = body.get("evidence_path")
            wanted = [want] if want else [i["path"] for i in items]

            kinds = {i["path"]: (i.get("kind")
                                 or casedb_mod.infer_kind(i["path"],
                                                          i.get("format")))
                     for i in items}
            here, missing = [], []
            for path in wanted:
                k = kinds.get(path) or "image"
                there = (os.path.isdir(path) if k == "folder"
                         else os.path.isfile(path))
                (here if there else missing).append(path)

            if not here:
                return self._send(400, {
                    "error": _t("server.case_open.case_refers_evidence_move") % missing[0],
                    "missing_evidence": missing[0],
                    "missing": missing, "case": cp})

            state = None
            failed = []
            for n, path in enumerate(here):
                try:
                    state = s.open(path, cp, who, add=n > 0,
                                   logical=(kinds.get(path) or "image")
                                   != "image")
                except Exception as exc:
                    failed.append({"path": path, "error": str(exc)})
            if state is None:
                return self._send(400, {
                    "error": _t("server.case_open.none_case_evidence_could"),
                    "failed": failed, "case": cp})
            if missing:
                state["missing_evidence_files"] = missing
            if failed:
                state["unreadable_evidence"] = failed
            return self._send(200, state)

        if path == "/api/pick":
            host = (self.client_address or ("",))[0]
            if host not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                return self._send(200, {"unavailable":
                    _t("server.pick.interface_running_same_machine")})
            if body.get("mode") == "probe":
                ok, why = nativedialog.available()
                return self._send(200, {"ok": ok} if ok
                                  else {"ok": False, "unavailable": why})
            try:
                chosen = nativedialog.ask(
                    body.get("mode") or "open",
                    title=body.get("title") or "",
                    initial_dir=body.get("dir") or "",
                    initial_file=body.get("file") or "",
                    kind=body.get("kind") or "image")
            except RuntimeError as exc:
                return self._send(200, {"unavailable": str(exc)})
            return self._send(200, {"path": chosen, "cancelled": not chosen})

        if not s.image:
            return self._send(409, {"error": _t("server.case_peek.evidence_open")})

        if path == "/api/verify":
            def run(progress):
                r = s.image.verify(progress)
                s.case.record_verification(s.evidence_id, r)
                return r
            return self._send(200, s.start_task("Verify acquisition hashes", run))

        if path == "/api/profile":
            part = body.get("part")
            entry = body.get("entry")
            if entry:
                fs = s.fs(part or 0)
                stream = body.get("stream") or ""
                try:
                    info = fs.stat(entry, stream) if stream else fs.stat(entry)
                except Exception:
                    info = {}
                size = info.get("size")
                if size is None:
                    size = entry.get("size") or 0
                cur = s.current
                src = FileRegion(fs, entry, size, stream,
                                 cur.file_bytes if cur is not None else None)
            else:
                src = s.region(part) if part is not None else s.image
            buckets = int(body.get("buckets", 2048))
            def run(progress):
                return profile_mod.profile(src, buckets=buckets, progress=progress)
            return self._send(200, s.start_task("Profile evidence", run))

        if path == "/api/carve":
            part = body.get("part")
            src = s.region(part) if part is not None else s.image
            exts = body.get("extensions")
            custom = body.get("custom") or []
            if exts is not None and not (isinstance(exts, list) and all(
                    isinstance(e, str) for e in exts)):
                return self._send(400, {"error": _t("server.carve.bad_types")})
            if not isinstance(custom, list) or \
                    len(custom) > carve_mod.CUSTOM_LIMITS["count"]:
                return self._send(400, {"error": _t(
                    "server.carve.too_many_custom",
                    carve_mod.CUSTOM_LIMITS["count"])})
            try:
                sigs, custom = carve_mod.signatures_for(exts, custom)
            except carve_mod.SignatureError as exc:
                return self._send(400, {"error": _carve_error(exc),
                                        "field": exc.key})
            if not sigs:
                return self._send(400, {"error": _t("server.carve.nothing_selected")})
            unalloc = body.get("unallocated_only", True)
            alignment = int(body.get("alignment", 512))
            exclude = []
            align_base = 0
            if part is not None:
                try:
                    fs = s.fs(part)
                    align_base = getattr(fs, "data_offset", 0)
                    if alignment == 0:
                        alignment = fs.cluster_size
                    if unalloc:
                        exclude = fs.allocated_extents()
                except Exception:
                    pass

            def run(progress):
                hits = carve_mod.carve(src, exclude=exclude,
                                       alignment=alignment, align_base=align_base,
                                       progress=progress, signatures=sigs)
                s.case.log("carve.run", {"part": part, "hits": len(hits),
                                         "unallocated_only": unalloc,
                                         "alignment": alignment,
                                         "types": (sorted(set(exts))
                                                   if exts is not None
                                                   else "all"),
                                         "custom": custom})
                return {"hits": hits, "excluded_ranges": len(exclude),
                        "base": part or 0}
            return self._send(200, s.start_task(
                "Carve for files", run, keep=("carve", part or 0)))

        if path == "/api/search":
            part = body.get("part")
            src = s.region(part) if part is not None else s.image
            terms = [t for t in body.get("terms", []) if t]
            if not terms:
                return self._send(400, {"error": _t("server.search.enter_least_one_term")})
            encs = body.get("encodings", ["ascii", "utf-16le"])
            rx = bool(body.get("regex"))

            def run(progress):
                hits = profile_mod.search(src, terms, encodings=encs, regex=rx,
                                          case_sensitive=body.get("case_sensitive",
                                                                  False),
                                          progress=progress)
                s.case.log("search.run", {"terms": terms, "encodings": encs,
                                          "regex": rx, "hits": len(hits)})
                return {"hits": hits, "base": part or 0}
            return self._send(200, s.start_task("Search evidence", run))

        if path == "/api/timeline":
            scope = body.get("scope") or "volume"
            include_accessed = bool(body.get("include_accessed", True))
            extra = {"built_at": casedb_mod.utcnow(),
                     "examiner": s.case.examiner if s.case else None,
                     "include_accessed": include_accessed,
                     "note": timeline_mod.NOTE}

            if scope == "tagged":
                if not s.case:
                    return self._send(400, {"error": _t("server.export.case_open")})
                rows = s.case.tagged()
                if not rows:
                    return self._send(400, {"error": _t("server.timeline.nothing_tagged")})
                for r in rows:
                    held = s.items.get(r["evidence_id"])
                    r["exhibit"] = held.label if held else None
                key = "tagged"
                dest = s.timeline_path(key, create=True)
                label = _t("server.timeline.tagged_label")

                def run(progress):
                    def open_volume(ev_id, part):
                        ev = s.items.get(ev_id)
                        if ev is None:
                            raise LookupError("exhibit_not_open")
                        try:
                            fs = s.fs(part, ev=ev)
                        except ntfs_mod.EncryptedVolume:
                            raise LookupError("volume_locked")
                        except Exception:
                            raise LookupError("volume_unreadable")
                        if getattr(fs, "index_pending", None) \
                                and fs.index_pending():
                            fs.build_tree(progress=lambda p: progress(p * 0.5))
                        return fs

                    writer = timeline_mod.Writer(dest)
                    try:
                        out = timeline_mod.build_tagged(
                            writer, rows, open_volume,
                            include_accessed=include_accessed,
                            start=body.get("start"), end=body.get("end"),
                            progress=lambda n: progress(0.5, count=n),
                            extra=extra)
                    except BaseException:
                        writer.abandon()
                        raise
                    s.case.log("timeline.build", {
                        "scope": "tagged", "events": out["count"],
                        "files": out["files"], "flagged": out["flagged"],
                        "tagged": out["tagged"],
                        "unresolved": out["unresolved_count"],
                        "truncated": out["truncated"]})
                    out["key"] = key
                    return out
            else:
                part = body.get("part")
                if part is None:
                    return self._send(400, {"error":
                                            _t("server.timeline.choose_partition_build_timeline")})
                part = int(part)
                ev = s.evidence(body.get("ev"))
                if ev is None:
                    return self._send(400, {"error": _t("server.evidence_select.such_evidence_item")})
                try:
                    fs = s.fs(part, ev=ev)
                except ntfs_mod.EncryptedVolume as exc:
                    return self._send(400, {"error": str(exc)})
                key = "ev%d-p%d" % (ev.evidence_id, part)
                dest = s.timeline_path(key, create=True)
                label = ev.label

                def run(progress):
                    if getattr(fs, "index_pending", None) and fs.index_pending():
                        fs.build_tree(progress=lambda p: progress(p * 0.3))
                    writer = timeline_mod.Writer(dest)
                    try:
                        out = timeline_mod.build_volume(
                            writer, fs, ev=ev.evidence_id, exhibit=ev.label,
                            part_offset=part, include_accessed=include_accessed,
                            start=body.get("start"), end=body.get("end"),
                            progress=lambda n: progress(0.3, count=n),
                            extra=extra)
                    except BaseException:
                        writer.abandon()
                        raise
                    if s.case:
                        s.case.log("timeline.build", {
                            "scope": "volume", "evidence_id": ev.evidence_id,
                            "part": part, "events": out["count"],
                            "files": out["files"], "flagged": out["flagged"],
                            "truncated": out["truncated"]})
                    out["key"] = key
                    return out

            return self._send(200, s.start_task(
                "timeline", run,
                label=_t("server.timeline.label") % label,
                detail=_t("server.timeline.detail")))

        if path == "/api/journal":
            part = body.get("part")
            fs = s.fs(part if part is not None else 0)
            if not hasattr(fs, "journal_info"):
                return self._send(400, {"error": _t("server.journal.filesystem_journal_strata_read")})
            info = fs.journal_info()
            node = body.get("inode")
            if node:
                versions = fs.journal.inode_versions(int(node))
                info["versions"] = [
                    {k: v for k, v in ver.items() if k != "inode"}
                    for ver in versions]
            s.case.log("journal.read", {"part": part, "inode": node})
            return self._send(200, info)

        if path == "/api/bookmark":
            bid = s.case.add_bookmark(
                s.evidence_id, int(body["offset"]), int(body.get("length", 1)),
                body.get("label", ""), body.get("note", ""),
                body.get("tags", []), body.get("source", ""),
                category=body.get("category", ""),
                colour=body.get("colour", ""),
                in_report=body.get("in_report", True),
                frame=body.get("frame", "media"),
                part=body.get("part"), node=body.get("node"),
                stream=body.get("stream"), mark_in=body.get("mark_in"))
            return self._send(200, {"id": bid})

        if path == "/api/bookmark/update":
            fields = {k: body[k] for k in
                      ("label", "note", "category", "colour", "in_report")
                      if k in body}
            ok = s.case.update_bookmark(int(body["id"]), **fields)
            return self._send(200 if ok else 404,
                              {"updated": ok} if ok else
                              {"error": _t("server.bookmark_update.such_bookmark")})

        if path == "/api/bookmark/remove":
            ok = s.case.remove_bookmark(int(body["id"]))
            return self._send(200, {"removed": ok})

        if path == "/api/tag":
            items = body.get("items") or ([body["item"]] if body.get("item") else [])
            tag = (body.get("tag") or "").strip()
            if not tag:
                return self._send(400, {"error": _t("server.tag.tag_needs_name")})
            if not items:
                return self._send(400, {"error": _t("server.tag.nothing_tag")})
            ids = [s.case.tag_item(s.evidence_id, it, tag, body.get("note", ""),
                                   int(body.get("part") or 0)) for it in items]
            return self._send(200, {"ids": ids, "count": len(ids),
                                    "counts": s.case.tag_counts()})

        if path == "/api/tag/remove":
            ok = s.case.untag_item(int(body["id"]))
            return self._send(200, {"removed": ok, "counts": s.case.tag_counts()})

        if path == "/api/search/files":
            terms = [t for t in body.get("terms", []) if t]
            if not terms:
                return self._send(400, {"error": _t("server.search.enter_least_one_term")})

            raw_part = body.get("part")
            one = None if raw_part in (None, "") else int(raw_part)

            targets = []
            skipped = []
            for p in (s.volumes.get("partitions") or []):
                if one is not None and p.get("offset") != one:
                    continue
                if one is None and not (p.get("allocated")
                                        and p.get("detected")):
                    continue
                try:
                    targets.append((p, s.fs(p["offset"])))
                except Exception as exc:
                    skipped.append({"part": p.get("offset"),
                                    "label": p.get("slot"),
                                    "reason": str(exc)})
            if one is not None and not targets:
                return self._send(400, {
                    "error": _t("server.search_files.supported_filesystem_partition")})
            if not targets:
                return self._send(400, {
                    "error": _t("server.search_files.filesystem_image_search_use"),
                    "skipped": skipped})

            def run(progress):
                merged = None
                n = len(targets)
                for i, (p, fs) in enumerate(targets):
                    root = getattr(fs, "root_node", None)
                    if root is None:
                        root = {"NTFS": 5, "ext4": 2, "ext3": 2, "ext2": 2,
                                "APFS": 2}.get(fs.name, 0)
                    got = filesearch_mod.search(
                        fs, terms, root_node=root,
                        mode=body.get("mode", "both"),
                        encodings=body.get("encodings",
                                           ["ascii", "utf-16le"]),
                        regex=bool(body.get("regex")),
                        case_sensitive=bool(body.get("case_sensitive")),
                        filters=body.get("filters"),
                        scan_bytes=(None if body.get("full") else
                                    int(body.get("scan_bytes")
                                        or filesearch_mod.DEFAULT_SCAN_BYTES)),
                        progress=(lambda f, i=i: progress((i + f) / n)))
                    if got.get("error"):
                        return got
                    if s.case and s.evidence_id is not None:
                        matched = hashing_mod.matched_hash_map(
                            s.case, s.evidence_id, p["offset"])
                        if matched:
                            hashing_mod.annotate_hits(
                                got.get("hits") or [], matched)
                    for h in got.get("hits") or []:
                        h["part"] = p["offset"]
                        h["volume"] = p.get("slot")
                    merged = _merge_search(merged, got)
                merged["partitions_searched"] = [
                    {"part": p["offset"], "label": p.get("slot"),
                     "fs": p.get("detected")} for p, _fs in targets]
                merged["partitions_skipped"] = skipped
                return merged

            label = ("Searching files" if one is not None
                     else "Searching every filesystem")
            t = s.start_task("search-files", run, label=label,
                             detail="Reading each allocated file in turn.")
            s.case.log("search.files", {"terms": terms,
                                        "part": one if one is not None
                                        else "all",
                                        "mode": body.get("mode", "both")})
            return self._send(200, t)

        if path == "/api/evtx":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            entry = body.get("entry")
            if not entry:
                return self._send(400, {"error": _t("server.evtx.pick_evtx_file")})
            limit = int(body.get("limit") or 2000)
            offset = int(body.get("offset") or 0)

            def run(progress):
                data = fs.read_file(entry, 256 << 20)
                r = evtx_mod.parse(data, max_records=limit, progress=progress,
                                   offset=offset)
                if r is None:
                    return {"error": _t("server.evtx.event_log")}
                r["total"] = evtx_mod.count_records(data)
                return r

            return self._send(200, s.start_task(
                "evtx", run, label="Decoding %s" % (entry.get("name") or "event log"),
                detail="Resolving binary XML templates for every record."))

        if path == "/api/sqlite":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            entry = body.get("entry")
            if not entry:
                return self._send(400, {"error": _t("server.sqlite.pick_database")})

            def run(progress):
                progress(0.05)
                data = fs.read_file(entry, 512 << 20)
                db = sqlitedb_mod.open_db(data)
                if not db:
                    return {"error": _t("server.sqlite.sqlite_database")}
                progress(0.3)
                out = {"info": db.info(), "tables": [], "kind": None}
                for t in db.tables():
                    out["tables"].append({"name": t["name"],
                                          "columns": t["columns"],
                                          "sql": t.get("sql")})
                out["kind"] = browser_mod.identify(db)
                progress(0.5)
                want = body.get("table")
                if want:
                    got = db.read_table(want, int(body.get("limit") or 5000))
                    cols, decoded = sqlitehints_mod.decode_rows(
                        want, got.get("columns"), got.get("rows"))
                    got["decoded_columns"] = cols
                    got["decoded"] = decoded
                    out["table"] = got
                if body.get("recover"):
                    progress(0.7)
                    out["recovered"] = db.recover(
                        limit=int(body.get("recover_limit") or 5000))
                progress(1.0)
                return out

            return self._send(200, s.start_task(
                "sqlite", run,
                label="Reading %s" % (entry.get("name") or "database"),
                detail="Walking b-tree pages directly, not through a driver."))

        if path == "/api/ese":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            entry = body.get("entry")
            if not entry:
                return self._send(400, {"error": _t("server.sqlite.pick_database")})

            def run(progress):
                progress(0.05)
                data = fs.read_file(entry, 512 << 20)
                db = esedb_mod.open_db(data)
                if not db:
                    return {"error": _t("server.ese.not_ese")}
                progress(0.3)
                info = db.info()
                size = entry.get("size") or 0
                if size > len(data):
                    info["findings"].append(
                        _t("server.ese.truncated", len(data), size))
                out = {"info": info, "tables": info.get("tables") or []}
                want = body.get("table")
                if want:
                    try:
                        table = db.table(want)
                    except esedb_mod.EseError:
                        table = None
                    if table is None:
                        out["error_table"] = _t("server.ese.no_table", want)
                    else:
                        progress(0.5)
                        limit = int(body.get("limit") or 2000)
                        got = db.rows(table, limit=limit)
                        named = [(c["name"] or "column_%d" % c["id"], c)
                                 for c in table["columns"]]
                        cols = [n for n, _c in named]
                        seen = set(cols)
                        for row in got["rows"]:
                            for k in row:
                                if k not in seen:
                                    seen.add(k)
                                    cols.append(k)
                        out["table"] = {
                            "name": want, "columns": cols,
                            "types": {n: c.get("type_name") for n, c in named},
                            "rows": [{k: _ese_cell(v) for k, v in row.items()}
                                     for row in got["rows"]],
                            "read": got.get("read", 0),
                            "skipped": got.get("skipped", 0),
                            "markers": got.get("markers", 0),
                            "truncated": bool(got.get("truncated")),
                            "limit": limit, "note": got.get("note"),
                        }
                progress(1.0)
                return out

            return self._send(200, s.start_task(
                "ese", run,
                label="Reading %s" % (entry.get("name") or "database"),
                detail="Walking ESE pages directly, not through Windows."))

        if path == "/api/browser":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            root = _root_node(fs)

            def run(progress):
                found, history, downloads, cookies = [], [], [], []
                entries = filesearch_mod.collect(fs, root)
                total = max(1, len(entries))
                for i, e in enumerate(entries):
                    if i % 64 == 0:
                        progress(i / total)
                    if e.get("is_dir") or not (e.get("size") or 0):
                        continue
                    nm = (e.get("name") or "").lower()
                    if not (nm in ("history", "places.sqlite", "cookies",
                                   "web data", "login data", "downloads.sqlite")
                            or nm.endswith(".sqlite")):
                        continue
                    try:
                        head = fs.read_file(e, 16)
                    except Exception:
                        continue
                    if not sqlitedb_mod.looks_like_sqlite(head):
                        continue
                    try:
                        db = sqlitedb_mod.open_db(fs.read_file(e, 256 << 20))
                    except Exception:
                        continue
                    if not db:
                        continue
                    kind = browser_mod.identify(db)
                    product = browser_mod.product_from_path(e.get("path"))
                    found.append({"path": e.get("path"), "name": e.get("name"),
                                  "kind": kind, "product": product,
                                  "size": e.get("size")})
                    h = browser_mod.history(db) or []
                    for r in h:
                        r["product"] = product
                        r["db"] = e.get("path")
                    history += h
                    for d in browser_mod.downloads(db) or []:
                        d["product"] = product
                        downloads.append(d)
                    for c in browser_mod.cookies(db) or []:
                        c["product"] = product
                        c["db"] = e.get("path")
                        cookies.append(c)
                    if body.get("recover"):
                        for r in browser_mod.recovered_urls(db):
                            r["product"] = product
                            r["db"] = e.get("path")
                            history.append(r)
                history.sort(key=lambda r: r.get("visited_at") or "",
                             reverse=True)
                progress(1.0)
                cookies.sort(key=lambda c: (c.get("host") or "",
                                            c.get("name") or ""))
                return {"databases": found, "history": history[:20000],
                        "downloads": downloads,
                        "cookies": cookies[:20000],
                        "cookie_count": len(cookies),
                        "history_count": len(history)}

            return self._send(200, s.start_task(
                "browser", run, label="Collecting browser history",
                detail="Identifying databases by schema, then joining visits "
                       "to URLs.",
                keep=("browser", part)))

        if path == "/api/leveldb":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            entry = body.get("entry")

            def run(progress):
                if entry:
                    data = fs.read_file(entry, 256 << 20)
                    nm = (entry.get("name") or "").lower()
                    r = (leveldb_mod.read_log(data) if nm.endswith(".log")
                         else leveldb_mod.read_sst(data))
                    if not r:
                        return {"error": _t("server.leveldb.leveldb_table_log")}
                    progress(1.0)
                    return {"rows": leveldb_mod.summarise(r["entries"]),
                            "local_storage": leveldb_mod.local_storage(
                                r["entries"]),
                            "findings": r.get("findings", []),
                            "count": len(r["entries"])}
                root = _root_node(fs)
                entries = filesearch_mod.collect(fs, root)
                total = max(1, len(entries))
                rows, stores, failed = [], {}, 0
                for i, e in enumerate(entries):
                    if i % 64 == 0:
                        progress(i / total)
                    if e.get("is_dir") or not (e.get("size") or 0):
                        continue
                    nm = (e.get("name") or "").lower()
                    pth = e.get("path") or ""
                    is_tbl = nm.endswith((".ldb", ".sst"))
                    is_log = nm.endswith(".log") and any(
                        k in pth for k in ("Local Storage", "Session Storage",
                                           "IndexedDB", "Sync Data", "leveldb"))
                    if not (is_tbl or is_log):
                        continue
                    try:
                        data = fs.read_file(e, 128 << 20)
                        r = (leveldb_mod.read_log(data) if is_log
                             else leveldb_mod.read_sst(data))
                    except Exception:
                        failed += 1
                        continue
                    if not r:
                        failed += 1
                        continue
                    store = next((k for k in ("Local Storage", "Session Storage",
                                              "IndexedDB", "Sync Data")
                                  if k in pth), "other")
                    stores[store] = stores.get(store, 0) + len(r["entries"])
                    for row in leveldb_mod.local_storage(r["entries"]):
                        row["store"] = store
                        row["file"] = e.get("path")
                        rows.append(row)
                progress(1.0)
                return {"local_storage": rows[:20000], "stores": stores,
                        "unreadable": failed, "total": len(rows)}

            return self._send(200, s.start_task(
                "leveldb", run, label="Reading LevelDB stores",
                detail="Snappy-compressed tables plus the write-ahead logs, "
                       "where the most recent writes live.",
                keep=("leveldb", part)))

        if path == "/api/appcompat":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            root = _root_node(fs)

            def run(progress):
                out = {"amcache": None, "shimcache": [], "findings": []}
                wanted = {"amcache.hve": None, "system": None}
                entries = filesearch_mod.collect(fs, root)
                total = max(1, len(entries))
                for i, e in enumerate(entries):
                    if i % 128 == 0:
                        progress(0.6 * i / total)
                    nm = (e.get("name") or "").lower()
                    pth = (e.get("path") or "").lower()
                    if nm == "amcache.hve" and "appcompat" in pth:
                        wanted["amcache.hve"] = e
                    elif nm == "system" and "config" in pth and "regback" not in pth:
                        wanted["system"] = e
                progress(0.65)
                if wanted["amcache.hve"]:
                    h = registry_mod.open_hive(
                        fs.read_file(wanted["amcache.hve"], 512 << 20), "Amcache")
                    if h:
                        out["amcache"] = appcompat_mod.parse_amcache(h)
                else:
                    out["findings"].append("No Amcache.hve on this volume.")
                progress(0.85)
                if wanted["system"]:
                    h = registry_mod.open_hive(
                        fs.read_file(wanted["system"], 512 << 20), "SYSTEM")
                    if h:
                        out["shimcache"] = appcompat_mod.shimcache_from_system(h)
                else:
                    out["findings"].append("No SYSTEM hive on this volume.")
                progress(1.0)
                return out

            return self._send(200, s.start_task(
                "appcompat", run, label="Reading Amcache and ShimCache",
                detail="Program presence and execution evidence from the "
                       "compatibility caches.",
                keep=("appcompat", part)))

        if path == "/api/usn":
            part = int(body.get("part") or 0)
            fs = s.fs(part)

            def run(progress):
                found = usnjrnl_mod.find(fs)
                if not found:
                    return {"present": False, "records": 0, "note":
                            _t("server.usn.volume_extend_usnjrnl_journal")}
                ent, j, mx = found
                info = usnjrnl_mod.journal_info(
                    fs.read_attr(mx) if mx is not None else None)
                recs, st = usnjrnl_mod.read(fs, j, progress=progress)
                s.usn = {"part": part, "records": recs, "stats": st,
                         "journal": info, "mft": ent.get("mft")}
                s.case.log("usn.read", {"part": part, "records": st["records"],
                                        "resyncs": st["resyncs"],
                                        "journal_id": info.get("journal_id")})
                return {"present": True, "records": st["records"],
                        "stats": st, "journal": info}

            return self._send(200, s.start_task(
                "usn", run, label="Reading the change journal",
                detail="$Extend\\$UsnJrnl records what happened to files — "
                       "creations, renames, moves and deletions — including "
                       "for files whose MFT records have since been reused."))

        if path == "/api/shellbags":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            root = _root_node(fs)

            def run(progress):
                out = {"users": [], "findings": []}
                entries = filesearch_mod.collect(fs, root)
                total = max(1, len(entries))
                hives = []
                for i, e in enumerate(entries):
                    if i % 128 == 0:
                        progress(0.5 * i / total)
                    nm = (e.get("name") or "").lower()
                    if nm in ("usrclass.dat", "ntuser.dat"):
                        hives.append(e)
                for j, e in enumerate(hives):
                    progress(0.5 + 0.5 * j / max(1, len(hives)))
                    try:
                        h = registry_mod.open_hive(
                            fs.read_file(e, 256 << 20), e.get("name"))
                    except Exception:
                        continue
                    if not h:
                        continue
                    r = shellbags_mod.parse(h, e.get("path"))
                    if r["entries"]:
                        r["user"] = _user_from_path(e.get("path"))
                        out["users"].append(r)
                if not out["users"]:
                    out["findings"].append(
                        "No shellbags found. On Windows 10 they live in "
                        "UsrClass.dat under AppData\\Local\\Microsoft\\Windows.")
                progress(1.0)
                return out

            return self._send(200, s.start_task(
                "shellbags", run, label="Reading shellbags",
                detail="Reconstructing folder access from BagMRU shell items.",
                keep=("shellbags", part)))

        if path == "/api/mail":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            entry = body.get("entry")

            def parse_store(data, progress=None):
                if pst_mod.looks_like_pst(data[:8]):
                    p = pst_mod.open_pst(data)
                    if p is None:
                        return None
                    r = p.mail(progress=progress)
                    r["format"] = p.info()["format"]
                    r["kind"] = "pst"
                    return r
                if mbox_mod.looks_like_mbox(data[:8]):
                    r = mbox_mod.parse(data, progress=progress)
                    r["kind"] = "mbox"
                    r.setdefault("folders", [])
                    return r
                return None

            def run(progress):
                if entry:
                    data = fs.read_file(entry, 512 << 20)
                    r = parse_store(data, progress)
                    if r is None:
                        return {"stores": [], "messages": [], "count": 0,
                                "findings": ["Not a recognised mail store."]}
                    return r
                root = _root_node(fs)
                entries = filesearch_mod.collect(fs, root)
                total = max(1, len(entries))
                stores, messages, findings = [], [], []
                for i, e in enumerate(entries):
                    if i % 64 == 0:
                        progress(i / total)
                    if e.get("is_dir") or (e.get("size") or 0) < 32:
                        continue
                    try:
                        head = fs.read_file(e, 8)
                    except Exception:
                        continue
                    if not (mbox_mod.looks_like_mbox(head)
                            or pst_mod.looks_like_pst(head)):
                        continue
                    try:
                        r = parse_store(fs.read_file(e, 512 << 20))
                    except Exception:
                        continue
                    if r is None:
                        continue
                    stores.append({"path": e.get("path"), "name": e.get("name"),
                                   "size": e.get("size"), "kind": r["kind"],
                                   "format": r.get("format"),
                                   "folders": r.get("folders") or [],
                                   "messages": r["count"]})
                    for f in r.get("findings") or []:
                        findings.append("%s: %s" % (e.get("path"), f))
                    store_entry = {
                        "name": e.get("name"), "path": e.get("path"),
                        "size": e.get("size"), "deleted": e.get("deleted"),
                        "mft": e.get("mft"), "inode": e.get("inode"),
                        "oid": e.get("oid"),
                        "start_cluster": e.get("start_cluster")}
                    for m in r["messages"]:
                        m["store"] = e.get("path")
                        m["store_entry"] = store_entry
                        messages.append(m)
                progress(1.0)
                messages.sort(key=lambda m: m.get("date") or "", reverse=True)
                return {"stores": stores, "messages": messages[:20000],
                        "count": len(messages), "findings": findings}

            return self._send(200, s.start_task(
                "mail", run, label="Reading mail stores",
                detail="Identifying mbox and Outlook PST stores by content and "
                       "parsing every message, including any the client marked "
                       "deleted.",
                keep=("mail", part)))

        if path == "/api/prefetch":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            root = _root_node(fs)

            def run(progress):
                entries = filesearch_mod.collect(fs, root)
                total = max(1, len(entries))
                items, undecoded, failed = [], 0, 0
                for i, e in enumerate(entries):
                    if i % 64 == 0:
                        progress(i / total)
                    if e.get("is_dir") or not (e.get("size") or 0):
                        continue
                    if not (e.get("name") or "").lower().endswith(".pf"):
                        continue
                    try:
                        r = prefetch_mod.parse(fs.read_file(e, 8 << 20))
                    except Exception:
                        failed += 1
                        continue
                    if r is None:
                        failed += 1
                        continue
                    if r.get("undecoded"):
                        undecoded += 1
                    r["source"] = e.get("path")
                    r["entry"] = e
                    items.append(r)
                progress(1.0)
                items.sort(key=lambda r: r.get("last_run") or "", reverse=True)
                return {"items": items, "undecoded": undecoded,
                        "failed": failed,
                        "decompressor": prefetch_mod.decompression_available()}

            return self._send(200, s.start_task(
                "prefetch", run, label="Reading prefetch",
                detail="Execution evidence: what ran, when, how often, and "
                       "which files each program opened at startup.",
                keep=("prefetch", part)))

        if path == "/api/task/cancel":
            return self._send(200, {"cancelled": s.cancel_task(body.get("id"))})

        if path == "/api/tasks/clear":
            s.forget_finished()
            return self._send(200, {"tasks": s.task_list()})

        if path == "/api/search/index":
            full = bool(body.get("full"))
            if "whole_disk" in body:
                whole = bool(body.get("whole_disk"))
            else:
                whole = body.get("part") in (None, "")

            if not whole:
                part = int(body.get("part") or 0)
                fs = s.fs(part)
                root = _root_node(fs)

                ev_here = s.current

                def run(progress):
                    return textindex_mod.build(
                        fs, s.case, part, root, progress=progress,
                        filters=body.get("filters"),
                        read_bytes=None if full
                        else textindex_mod.DEFAULT_READ_BYTES,
                        max_text=None if full
                        else textindex_mod.MAX_TEXT_PER_FILE,
                        evidence=ev_here.evidence_id if ev_here else None)

                t = s.start_task(
                    "index-build", run,
                    label="Building content index",
                    detail=("Reading every file in full." if full else
                            "Reading the first %s of each file."
                            % fmt_bytes(textindex_mod.DEFAULT_READ_BYTES)))
                s.case.log("index.build", {"part": part, "full": full})
                return self._send(200, t)

            across = bool(body.get("all_evidence"))
            targets = (list(s.items.values()) if across
                       else ([s.current] if s.current else []))

            def run(progress):
                filesystems, regions, findings = [], [], []
                covered = 0
                grand = max(1, sum((p.get("size") or 0)
                                   for ev in targets
                                   for p in ev.volumes["partitions"]))
                done = 0

                def sub(base, weight):
                    def inner(frac):
                        progress(min(0.999, (base + weight * frac) / grand))
                    return inner

                for ev in targets:
                    tag = ev.label if len(targets) > 1 else None
                    for p in ev.volumes["partitions"]:
                        off = p["offset"]
                        sz = p.get("size") or 0
                        label = "%s - %s" % (p.get("slot") or "?",
                                             p.get("detected") or p.get("type")
                                             or "unknown")
                        if tag:
                            label = "%s / %s" % (tag, label)

                        opened = None
                        if p.get("allocated") and p.get("detected"):
                            try:
                                opened = s.fs(off, ev=ev)
                            except Exception as exc:
                                findings.append(
                                    "%s: filesystem did not open (%s); indexed "
                                    "as raw bytes instead." % (label, exc))

                        if opened is not None:
                            is_ntfs = (p.get("detected") or "").upper()                                .startswith("NTFS")
                            try:
                                r = textindex_mod.build(
                                    opened, s.case, off, _root_node(opened),
                                    progress=sub(done, sz * 0.7),
                                    want_live_names=is_ntfs,
                                    read_bytes=None if full
                                    else textindex_mod.DEFAULT_READ_BYTES,
                                    max_text=None if full
                                    else textindex_mod.MAX_TEXT_PER_FILE,
                                    evidence=ev.evidence_id)
                            except Exception as exc:
                                r = {"error": str(exc)}
                            live = r.pop("live_names", None)

                            if is_ntfs:
                                try:
                                    u = textindex_mod.build_usn(
                                        opened, s.case, off, live_names=live,
                                        evidence=ev.evidence_id)
                                except Exception as exc:
                                    u = {"error": str(exc)}
                                if u.get("error"):
                                    findings.append(
                                        "%s: the change journal could not be "
                                        "indexed (%s). Filenames that survive "
                                        "only there are not searchable."
                                        % (label, u["error"]))
                                elif u.get("present"):
                                    r["usn"] = u
                                    if u.get("resyncs"):
                                        findings.append(
                                            "%s: %d point(s) in the change "
                                            "journal could not be followed, so "
                                            "some names it held are missing "
                                            "from the index."
                                            % (label, u["resyncs"]))

                            r["partition"] = label
                            r["offset"] = off
                            r["evidence"] = ev.evidence_id
                            r["exhibit"] = ev.label
                            filesystems.append(r)
                            covered += sz

                            free = textindex_mod.free_regions(opened, 0, sz)
                            if free is None:
                                findings.append(
                                    "%s: this filesystem cannot report its "
                                    "allocation map, so free space inside it "
                                    "was not swept. Files still in the file "
                                    "table are indexed; content in reclaimed "
                                    "clusters is not." % label)
                            else:
                                free_bytes = sum(b - a for a, b in free)
                                acc = None
                                for a, b in free:
                                    rr = textindex_mod.build_region(
                                        s.region(off, ev=ev), s.case, off,
                                        a, b - a,
                                        "%s / unallocated and metadata" % label,
                                        kind="unallocated", base=off,
                                        evidence=ev.evidence_id,
                                        progress=sub(
                                            done + sz * 0.7,
                                            sz * 0.3 * ((b - a)
                                                        / max(1, free_bytes))))
                                    acc = _merge_region(acc, rr)
                                if acc:
                                    acc["label"] = ("%s / unallocated and "
                                                    "metadata" % label)
                                    acc["extents"] = len(free)
                                    acc["evidence"] = ev.evidence_id
                                    acc["exhibit"] = ev.label
                                    regions.append(acc)
                        else:
                            kind = ("gap" if not p.get("allocated")
                                    else "unparsed")
                            gap_label = (label if p.get("allocated") else
                                         "%s%s (unpartitioned)"
                                         % (("%s / " % tag) if tag else "",
                                            p.get("slot") or "gap"))
                            rr = textindex_mod.build_region(
                                s.region(off, ev=ev), s.case, off, 0, sz,
                                gap_label, kind=kind, base=off,
                                evidence=ev.evidence_id,
                                progress=sub(done, sz))
                            rr["evidence"] = ev.evidence_id
                            rr["exhibit"] = ev.label
                            regions.append(rr)
                            covered += sz
                        done += sz

                progress(1.0)
                for r in regions:
                    if r.get("budget_reached"):
                        findings.append(
                            "%s: the text budget was reached after %s; the "
                            "rest of the region is not in the index."
                            % (r["label"], fmt_bytes(r["bytes_scanned"])))
                total_docs = (sum(f.get("indexed") or 0 for f in filesystems)
                              + sum(r.get("documents") or 0 for r in regions))
                media = sum(ev.image.size for ev in targets)
                return {
                    "whole_disk": True,
                    "evidence_count": len(targets),
                    "exhibits": [ev.label for ev in targets],
                    "image_size": media,
                    "bytes_covered": covered,
                    "coverage": round(covered / max(1, media), 4),
                    "documents": total_docs,
                    "filesystems": filesystems,
                    "regions": regions,
                    "findings": findings,
                }

            t = s.start_task(
                "index-build", run,
                label="Indexing the whole disk",
                detail="Every filesystem, plus unpartitioned gaps, unparsed "
                       "partitions and free space — so unallocated content is "
                       "searchable, not just files.")
            s.case.log("index.build", {"whole_disk": True, "full": full})
            return self._send(200, t)

        if path == "/api/search/indexed":
            terms = [t for t in body.get("terms", []) if t]
            if not terms:
                return self._send(400, {"error": _t("server.search.enter_least_one_term")})
            part = body.get("part")
            return self._send(200, textindex_mod.query(
                s.case, terms, part=part,
                mode=body.get("match", "any"),
                limit=int(body.get("limit") or 1000),
                evidence=None if part is None else s.evidence_id))

        if path == "/api/unlock":
            part = int(body.get("part") or 0)
            secret = body.get("secret") or ""
            v = s.vault(part)
            if v is None:
                return self._send(400, {
                    "error": _t("server.unlock.partition_encrypted_volume_tool")})
            if not secret:
                return self._send(400, {"error": _t("server.unlock.enter_password_key")})

            def run(progress):
                r = v.unlock(secret, progress=progress)
                if r.get("unlocked"):
                    s.unlocked[part] = v
                    s.fs_cache.pop(part, None)
                    s.reader_cache.pop(part, None)
                    if REGISTRY is not None and s.current is not None:
                        REGISTRY.drop_shared("fs", s.current.path, part)
                    s._structures = None
                    s.case.log("volume.unlock", {
                        "part": part, "method": r.get("protector")
                        or ("key slot %s" % r.get("slot")),
                        "encryption": r.get("encryption"),
                        "verified": r.get("verified")})
                else:
                    s.case.log("volume.unlock.failed", {"part": part})
                r["part"] = part
                return r

            return self._send(200, s.start_task(
                "unlock", run, label="Unlocking volume",
                detail="Deriving the key. The format specifies about a million "
                       "rounds of hashing, which takes a second or two and is "
                       "the whole point — it is what stops a short password "
                       "being guessed quickly."))

        if path == "/api/timezone/detect":
            parts = [p for p in s.volumes["partitions"]
                     if p.get("allocated") and p.get("detected")]

            def run(progress):
                found = []
                for n, p in enumerate(parts):
                    progress(n / max(1, len(parts)))
                    try:
                        fs = s.fs(p["offset"])
                    except Exception:
                        continue
                    for tz in _detect_timezone(s, fs, p):
                        d = tz.info()
                        d["partition"] = p["slot"]
                        d["part"] = p["offset"]
                        d["filesystem"] = fs.name
                        d["filesystem_records_local"] =                             timezone_mod.fs_records_local_time(fs.name)
                        found.append(d)
                progress(1.0)
                s.tz_candidates = found
                s.tz_scanned = True
                return {"candidates": found}

            return self._send(200, s.start_task(
                "timezone", run, label="Looking for the time zone",
                detail="Reading the SYSTEM hive and the Unix zone files. On "
                       "NTFS the first directory read builds the master file "
                       "table index, which is the slow part."))

        if path == "/api/timezone/apply":
            tz = body.get("timezone")
            if tz is None:
                s.case.db.execute("DELETE FROM meta WHERE key='timezone_offset'")
                s.case.db.commit()
                s.case.log("timezone.clear", {})
                return self._send(200, {"applied": None})
            if not isinstance(tz, dict) or "offset_minutes" not in tz:
                return self._send(400, {"error": _t("server.timezone_apply.need_offset_minutes")})
            s.case.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",
                              ("timezone_offset", json.dumps(tz)))
            s.case.db.commit()
            s.case.log("timezone.apply", {
                "name": tz.get("name"), "offset_minutes": tz.get("offset_minutes"),
                "source": tz.get("source"), "confidence": tz.get("confidence")})
            return self._send(200, {"applied": tz})

        if path == "/api/lock":
            part = int(body.get("part") or 0)
            s.unlocked.pop(part, None)
            s.vault_cache.pop(part, None)
            s.fs_cache.pop(part, None)
            s.reader_cache.pop(part, None)
            s._structures = None
            s.case.log("volume.lock", {"part": part})
            return self._send(200, {"locked": True, "part": part})

        if path == "/api/index/clear":
            part = body.get("part")
            ev_id = None if part is None else s.evidence_id
            textindex_mod.clear(s.case, part, ev_id)
            s.case.log("index.clear", {"part": part,
                                       "evidence_id": ev_id})
            return self._send(200, {"cleared": True})

        if path == "/api/search/save":
            name = (body.get("name") or "").strip()
            if not name:
                return self._send(400, {"error": _t("server.search_save.saved_search_needs_name")})
            sid = s.case.save_search(s.evidence_id, name, body.get("query") or {},
                                     body.get("hits") or [], body.get("part"))
            return self._send(200, {"id": sid, "searches": s.case.searches()})

        if path == "/api/search/delete":
            ok = s.case.delete_search(int(body["id"]))
            return self._send(200, {"removed": ok, "searches": s.case.searches()})

        if path == "/api/hash":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            root = _root_node(fs)
            scope = body.get("scope", "all")
            entry = body.get("entry")

            def run(progress):
                targets = hashing_mod.collect_scope(
                    fs, root, scope, entry, body.get("filters"))
                rows = hashing_mod.hash_many(fs, targets, progress=progress)
                hashing_mod.annotate_matches(s.case, rows)
                s.case.record_hashes(s.evidence_id, rows, part)
                counts = {}
                for r in rows:
                    if r.get("match_kind"):
                        counts[r["match_kind"]] = counts.get(r["match_kind"], 0) + 1
                return {"hashed": len(rows), "rows": rows[:2000],
                        "match_counts": counts,
                        "truncated": len(rows) > 2000}

            t = s.start_task("hash", run, label="Hashing files",
                              detail="MD5, SHA-1, SHA-256 and a fuzzy hash "
                                      "in one pass per file.")
            s.case.log("hash.run", {"part": part, "scope": scope})
            return self._send(200, t)

        if path == "/api/hashset/import":
            r = hashing_mod.import_hash_set(
                s.case, body.get("path", ""), body.get("name"),
                body.get("kind", "known_bad"))
            if r.get("error"):
                return self._send(400, r)
            return self._send(200, {**r, "sets": s.case.hash_sets()})

        if path == "/api/hashset/delete":
            ok = s.case.delete_hash_set(int(body["id"]))
            return self._send(200, {"removed": ok, "sets": s.case.hash_sets()})

        if path == "/api/attack/tag":
            tid = (body.get("technique") or "").strip()
            if not attack_mod.TECHNIQUE_ID.match(tid):
                return self._send(400, {
                    "error": _t("server.attack_tag.r_att_ck_technique") % tid})
            rid = s.case.attack_tag(
                s.evidence_id, int(body.get("part") or 0),
                body.get("target_kind") or "file",
                body.get("target_ref") or "",
                tid, body.get("technique_name"), body.get("tactic"),
                note=body.get("note") or "",
                asserted=bool(body.get("asserted", True)),
                catalogue=body.get("catalogue"))
            return self._send(200, {"id": rid,
                                    "tags": s.case.attack_tags(s.evidence_id),
                                    "summary": s.case.attack_summary(s.evidence_id)})

        if path == "/api/attack/untag":
            ok = s.case.attack_untag(int(body.get("id") or 0))
            return self._send(200, {"removed": ok,
                                    "tags": s.case.attack_tags(s.evidence_id),
                                    "summary": s.case.attack_summary(s.evidence_id)})

        if path == "/api/attack/import":
            p = body.get("path") or ""
            if not os.path.isfile(p):
                return self._send(400, {"error": _t("server.attack_import.such_file") % p})
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    techniques = attack_mod.parse_stix(f.read())
            except ValueError as exc:
                return self._send(400, {"error": str(exc)})
            except Exception as exc:
                return self._send(400, {
                    "error": _t("server.attack_import.could_read_as_stix") % exc})
            n = s.case.set_attack_catalogue(techniques, body.get("version"))
            return self._send(200, {
                "techniques": n,
                "catalogue": attack_mod.imported(techniques,
                                                 body.get("version"))})

        if path == "/api/wallets":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            root = _root_node(fs)

            def run(progress):
                entries = filesearch_mod.collect(fs, root)
                total = max(1, len(entries))
                phrases, near, addrs, files = [], [], [], []
                for i, e in enumerate(entries):
                    if i % 32 == 0:
                        progress(i / total)
                    if e.get("is_dir") or not (e.get("size") or 0):
                        continue
                    try:
                        data = fs.read_file(e, 8 << 20)
                    except Exception:
                        continue
                    if not data:
                        continue
                    what = wallets_mod.identify_wallet(e.get("name"), data[:512])
                    if what:
                        files.append({"path": e.get("path"), "name": e.get("name"),
                                      "size": e.get("size"), "kind": what[0],
                                      "form": what[1], "entry": e})
                    text = textindex_mod.extract_text(data, limit=1 << 20)
                    if not text:
                        continue
                    for hit in wallets_mod.find_mnemonics(text):
                        hit["path"] = e.get("path")
                        hit["name"] = e.get("name")
                        (phrases if hit["valid"] else near).append(hit)
                    for hit in wallets_mod.find_addresses(text):
                        hit["path"] = e.get("path")
                        addrs.append(hit)

                out = {
                    "phrases": phrases,
                    "near_misses": near[:NEAR_CAP],
                    "near_miss_count": len(near),
                    "addresses": addrs[:ADDR_CAP],
                    "address_count": len(addrs),
                    "files": files,
                    "wordlist": wallets_mod.wordlist_status(),
                }

                def strip(rows):
                    return [{k: v for k, v in r.items()
                             if k not in ("phrase", "entry")} for r in rows]
                s.keep_artefact("wallets", part, {
                    **out,
                    "phrases": strip(phrases),
                    "near_misses": strip(near[:NEAR_CAP]),
                    "files": strip(files),
                    "redacted": True,
                })
                if phrases and s.case:
                    s.case.log("wallets.found", {
                        "part": part, "phrases": len(phrases),
                        "note": _t("server.wallets.phrase_text_deliberately_recorded")})
                progress(1.0)
                return out

            return self._send(200, s.start_task(
                "wallets", run, label="Looking for wallets and seed phrases",
                detail="BIP-39 phrases are checked against their own checksum "
                       "rather than matched by shape, and addresses against "
                       "theirs. Recovered phrases stay in this session and are "
                       "never written to the case."))

        if path == "/api/export/file":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            entry = body.get("entry") or _entry_from_body(fs, body)
            out_dir = body.get("dir") or os.path.join(
                os.path.dirname(s.path), "strata-export")
            try:
                rec, safe, n = _export_one(
                    fs, entry, out_dir, s, dest=body.get("dest"),
                    manifest=body.get("manifest", True),
                    stream=body.get("stream") or "")
            except _STREAM_ERRORS as exc:
                return self._send(400,
                                  _stream_error(exc, body.get("stream") or ""))
            out = {"path": safe, "bytes": n,
                   "stream": body.get("stream") or None,
                   "sha256": rec["sha256"], "manifest": rec}
            if body.get("add_exhibit") and s.case:
                try:
                    out["exhibit"] = _add_derived(
                        s, safe, s.current, entry.get("path"), rec["sha256"],
                        body.get("add_as") or "auto")
                except Exception as exc:
                    out["exhibit"] = {"added": False, "error": str(exc)}
            return self._send(200, out)

        if path == "/api/export/folder":
            part = int(body.get("part") or 0)
            fs = s.fs(part)
            entry = body.get("entry")
            if not entry or not entry.get("is_dir"):
                return self._send(400, {"error": _t("server.export_folder.folder")})
            base = (entry.get("path") or "").rstrip("/\\")
            out_dir = body.get("dest") or os.path.join(
                os.path.dirname(s.path), "strata-export")
            out_dir = os.path.abspath(os.path.expanduser(out_dir))

            ev_at_start = s.current

            def run(progress):
                targets = hashing_mod.collect_scope(
                    fs, _root_node(fs), "folder", entry, None)
                done = failed = written = 0
                for i, t in enumerate(targets):
                    progress(i / max(1, len(targets)))
                    p = t.get("path") or t.get("name") or "item"
                    rel = p[len(base):] if base and p.startswith(base) else p
                    try:
                        rec, _, n = _export_one(fs, t, out_dir, s, rel=rel)
                        written += n
                        done += 1
                    except TaskCancelled:
                        raise
                    except Exception:
                        failed += 1
                s.case.log("export.folder", {"path": entry.get("path"),
                                             "dest": out_dir, "files": done,
                                             "failed": failed})
                out = {"dir": out_dir, "files": done, "failed": failed,
                       "bytes": written, "considered": len(targets)}
                if body.get("add_exhibit") and s.case and done:
                    try:
                        out["exhibit"] = _add_derived(
                            s, out_dir, ev_at_start, entry.get("path"), None,
                            "logical")
                    except Exception as exc:
                        out["exhibit"] = {"added": False, "error": str(exc)}
                return out

            return self._send(200, s.start_task(
                "export-folder", run,
                label="Exporting %s" % (entry.get("name") or "folder"),
                detail="Every file beneath it, structure preserved."))

        if path == "/api/export/manifest":
            out_dir = body.get("dir") or os.path.join(
                os.path.dirname(s.path), "strata-export")
            rows = body.get("rows") or []
            return self._send(200, _write_manifest(out_dir, rows, s))

        if path == "/api/export":
            part = body.get("part", 0)
            off = int(body["offset"]) + int(part or 0)
            length = int(body["length"])
            fragments = body.get("fragments")
            if fragments is not None and not (
                    isinstance(fragments, list) and fragments and all(
                        isinstance(fr, (list, tuple)) and len(fr) == 2
                        for fr in fragments)):
                return self._send(400, {"error": "Invalid fragments."})
            chosen = body.get("dest")
            if chosen:
                dest = os.path.abspath(os.path.expanduser(chosen))
                out_dir = os.path.dirname(dest)
            else:
                out_dir = body.get("dir") or os.path.join(
                    os.path.dirname(s.path), "strata-export")
                name = body.get("name") or ("%016x.%s"
                                            % (off, body.get("ext", "bin")))
                dest = os.path.join(out_dir, name)
            os.makedirs(out_dir or ".", exist_ok=True)
            src = s.region(part) if part else s.image

            def read_range(rel_offset, rel_length, f):
                pos = int(rel_offset)
                remaining = int(rel_length)
                n = 0
                while remaining > 0:
                    chunk = src.read_at(pos, min(1 << 20, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    n += len(chunk)
                    pos += len(chunk)
                    remaining -= len(chunk)
                return n

            written = 0
            with open(dest, "wb") as f:
                if fragments:
                    for frag_off, frag_len in fragments:
                        written += read_range(frag_off, frag_len, f)
                else:
                    written = read_range(body["offset"], length, f)
            h = hashlib.sha256()
            with open(dest, "rb") as f:
                for blk in iter(lambda: f.read(1 << 20), b""):
                    h.update(blk)
            s.case.log("export.file", {"offset": off, "length": written,
                                       "dest": dest, "sha256": h.hexdigest()})
            return self._send(200, {"path": dest, "bytes": written,
                                    "sha256": h.hexdigest()})

        return self._send(404, {"error": _t("server.report.unknown_route")})

_TIMELINE_KEY = re.compile(r"^(tagged|ev[0-9]+-p[0-9]+)$")

MAX_HIVE = 512 << 20

MAX_STREAM = 256 << 20

EXPORT_CHUNK = 8 << 20

MAX_ARCHIVE = 512 << 20
MAX_INLINE = 2 << 20

TYPE_CHECK_CAP = 2000

_MIME_MAGIC = [
    (b"\x89PNG", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"BM", "image/bmp"),
    (b"II*\x00", "image/tiff"),
    (b"MM\x00*", "image/tiff"),
    (b"ID3", "audio/mpeg"),
    (b"OggS", "audio/ogg"),
    (b"fLaC", "audio/flac"),
    (b"\x1a\x45\xdf\xa3", "video/webm"),
]

_FTYP_MIME = {
    "qt": "video/quicktime", "heic": "image/heic", "heix": "image/heic",
    "mif1": "image/heic", "avif": "image/avif",
}

MANIFEST_COLS = ["source", "exported_to", "bytes", "md5", "sha1", "sha256",
                 "deleted", "modified", "exported_at", "examiner"]

def _safe_stream_name(stream):
    out = "".join(c if (c.isalnum() or c in "-_.") else "_"
                  for c in stream)[:64]
    while ".." in out:
        out = out.replace("..", ".")
    return out.strip(".") or "unnamed"

_STREAM_ERRORS = (streams_mod.NoSuchStream, streams_mod.UnsupportedStream)

def _stream_error(exc, stream):
    out = {"error": str(exc), "stream": stream}
    if isinstance(exc, streams_mod.NoSuchStream):
        out["available"] = exc.available
    else:
        out["unsupported"] = True
    return out

def _streams_of(fs, entry):
    fn = getattr(fs, "streams", None)
    if fn is not None:
        try:
            return fn(entry)
        except Exception:
            return []
    return list(entry.get("streams") or [])

def _exhibit_kind(path, asked="auto"):
    if asked in ("image", "logical"):
        return asked
    if os.path.isdir(path):
        return "logical"
    try:
        img = open_image(path)
    except Exception:
        return "logical"
    try:
        if not isinstance(img, ewf_mod.RawImage):
            return "image"
        scan = volume_mod.scan(img)
        if scan.get("scheme") in ("MBR", "GPT"):
            return "image"
        for p in scan.get("partitions") or []:
            if p.get("detected"):
                return "image"
        return "logical"
    except Exception:
        return "logical"
    finally:
        closer = getattr(img, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:
                pass

def _add_derived(s, path, parent, source_path, digest, asked="auto"):
    kind = _exhibit_kind(path, asked)
    s.case.log("exhibit.derived", {
        "dest": path,
        "kind": kind,
        "from_evidence": getattr(parent, "evidence_id", None),
        "from_exhibit": getattr(parent, "label", None),
        "from_image": getattr(parent, "path", None),
        "source_path": source_path,
        "sha256": digest,
    })
    state = s.open(path, add=True, logical=(kind == "logical"))
    return {"added": True, "as": kind, "path": path, "state": state}

def _ranged_read(fs, entry, stream):
    ranged = getattr(fs, "read_range", None)
    if ranged is None:
        return None
    try:
        ranged(entry, 0, 1, stream) if stream else ranged(entry, 0, 1)
    except Exception:
        return None
    if stream:
        return lambda off, n: ranged(entry, off, n, stream)
    return lambda off, n: ranged(entry, off, n)

def _chunks(fs, entry, stream, size):
    reader = _ranged_read(fs, entry, stream) if size else None
    if reader is not None:
        at = 0
        while at < size:
            piece = reader(at, min(EXPORT_CHUNK, size - at))
            if not piece:
                break
            yield piece
            at += len(piece)
        return
    data = fs.read_file(entry, MAX_STREAM, stream) if stream \
        else fs.read_file(entry, MAX_STREAM)
    if data:
        yield data

def _stream_size(fs, entry, stream):
    for st in _streams_of(fs, entry):
        if (st.get("name") or "") == (stream or ""):
            return st.get("size") or 0
    return 0 if stream else (entry.get("size") or 0)

def _entry_from_body(fs, body):
    """Reconstruct a minimal entry from a bare node handle: a caller that
    has only the filesystem handle (mft/inode/oid/start_cluster) rather than
    a full listdir() entry -- the bulk "export tagged items" action is the
    one in-app case, since a tagged item is stored by handle. Any of the
    fields below that the caller does have are used, so a deleted file
    exported this way is still read the way engine.fs.* expects a deleted
    entry to be read, rather than as if it were live, and the export
    manifest records what the caller actually knew about it. `contiguous`
    is exFAT-specific: a NoFatChain stream is read by extent rather than by
    walking the FAT (#94)."""
    node = body.get("node")
    n = None if node in (None, "", "null") else int(node)
    entry = {"name": body.get("name"), "path": body.get("path"),
             "size": body.get("size"), "is_dir": False,
             "deleted": bool(body.get("deleted")),
             "contiguous": bool(body.get("contiguous")),
             "modified": body.get("modified"),
             "accessed": body.get("accessed"),
             "created": body.get("created")}
    fsname = (fs.name or "").upper()
    if fsname.startswith("NTFS"):
        entry["mft"] = n
    elif fsname.startswith("EXT"):
        entry["inode"] = n
    elif fsname.startswith("APFS") or fsname.startswith("LOGICAL"):
        entry["oid"] = n
    else:
        entry["start_cluster"] = n
    return entry

def _export_one(fs, entry, out_dir, session, rel=None, dest=None,
                manifest=True, stream=""):
    if dest:
        safe = os.path.abspath(os.path.expanduser(dest))
        out_dir = os.path.dirname(safe)
    else:
        if rel is None:
            rel = entry.get("path") or entry.get("name") or "item"
        rel = rel.lstrip("/\\").replace("\\", "/")
        if stream:
            rel = "%s.stream-%s" % (rel, _safe_stream_name(stream))
        safe = os.path.normpath(os.path.join(out_dir, rel))
        if not _within(out_dir, safe):
            safe = os.path.join(out_dir, os.path.basename(rel) or "item")
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.dirname(safe) or out_dir, exist_ok=True)
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    written = 0
    try:
        with open(safe, "wb") as f:
            for piece in _chunks(fs, entry, stream,
                                 _stream_size(fs, entry, stream)):
                f.write(piece)
                md5.update(piece)
                sha1.update(piece)
                sha256.update(piece)
                written += len(piece)
    except BaseException:
        try:
            os.unlink(safe)
        except OSError:
            pass
        raise
    digest = sha256.hexdigest()
    session.case.log("export.item", {"path": entry.get("path"),
                                     "stream": stream or None,
                                     "dest": safe, "bytes": written,
                                     "sha256": digest})
    rec = {"source": (entry.get("path") or entry.get("name"))
           + (":" + stream if stream else ""),
           "exported_to": os.path.relpath(safe, out_dir),
           "bytes": written,
           "md5": md5.hexdigest(),
           "sha1": sha1.hexdigest(),
           "sha256": digest,
           "deleted": bool(entry.get("deleted")),
           "modified": entry.get("modified"),
           "exported_at": casedb_mod.utcnow(),
           "examiner": session.case.examiner}
    if manifest:
        _append_manifest(out_dir, rec, session)
    return rec, safe, written

def _append_manifest(out_dir, rec, session):
    path = os.path.join(out_dir, "manifest.csv")
    fresh = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_COLS, extrasaction="ignore")
        if fresh:
            w.writeheader()
        w.writerow(_csv_safe(rec))
    return path

def _csv_safe(row):
    out = {}
    for k, v in row.items():
        if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
            v = "'" + v
        out[k] = v
    return out

def _write_manifest(out_dir, rows, session):
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, "manifest.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_COLS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(_csv_safe(r))
    meta = {
        "case": session.case.summary() if session.case else None,
        "evidence": session.path,
        "image": session.image.info() if session.image else None,
        "generated_at": casedb_mod.utcnow(),
        "examiner": session.case.examiner if session.case else None,
        "items": rows,
        "audit_integrity": session.case.verify_audit() if session.case else None,
    }
    json_path = os.path.join(out_dir, "manifest.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, default=str)
    if session.case:
        session.case.log("export.manifest", {"dir": out_dir, "items": len(rows)})
    return {"csv": csv_path, "json": json_path, "items": len(rows)}

def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%g %s" % (round(n, 1), unit)
        n /= 1024.0

def _user_from_path(path):
    parts = (path or "").replace("\\", "/").split("/")
    for i, seg in enumerate(parts):
        if seg.lower() == "users" and i + 1 < len(parts):
            return parts[i + 1]
    return None

class DecryptedReader:

    CACHE_BLOCKS = 512

    def __init__(self, vault, size, slot="?"):
        self.vault = vault
        self.size = size
        self.slot = slot
        self.bytes_per_sector = getattr(vault, "sector_size", 512)
        self._cache = {}
        self._order = []
        self.blocks_read = 0

    def _block(self, n):
        got = self._cache.get(n)
        if got is not None:
            return got
        data = self.vault.read(n << 16, 1 << 16)
        self.blocks_read += 1
        self._cache[n] = data
        self._order.append(n)
        if len(self._order) > self.CACHE_BLOCKS:
            self._cache.pop(self._order.pop(0), None)
        return data

    def read_at(self, offset, length):
        if offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        pos = offset
        while len(out) < length:
            n = pos >> 16
            blk = self._block(n)
            if not blk:
                break
            start = pos - (n << 16)
            take = min(len(blk) - start, length - len(out))
            if take <= 0:
                break
            out += blk[start:start + take]
            pos += take
        return bytes(out)

    def info(self):
        return {"decrypted": True, "slot": self.slot, "size": self.size}

def _merge_region(acc, r):
    if acc is None:
        return dict(r)
    for k in ("documents", "bytes_read", "bytes_scanned", "text_indexed",
              "skipped_high_entropy", "skipped_zeroed"):
        acc[k] = (acc.get(k) or 0) + (r.get(k) or 0)
    acc["budget_reached"] = acc.get("budget_reached") or r.get("budget_reached")
    return acc

NEAR_CAP = 2000
ADDR_CAP = 5000

def _code_stamp(here=None):
    here = here or os.path.dirname(os.path.abspath(__file__))
    newest = 0.0
    for dirpath, dirs, names in os.walk(here):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for n in names:
            if n.endswith(".py"):
                try:
                    newest = max(newest,
                                 os.stat(os.path.join(dirpath, n)).st_mtime)
                except OSError:
                    pass
    return newest

_STARTED_STAMP = _code_stamp()

def _engine_changed():
    return _code_stamp() > _STARTED_STAMP + 1

_CARVE_ERRORS = {
    "not_a_signature": lambda *a: _t("carve.custom.not_a_signature", *a),
    "bad_byte": lambda *a: _t("carve.custom.bad_byte", *a),
    "not_ascii": lambda *a: _t("carve.custom.not_ascii", *a),
    "bad_name": lambda *a: _t("carve.custom.bad_name", *a),
    "bad_ext": lambda *a: _t("carve.custom.bad_ext", *a),
    "header_too_long": lambda *a: _t("carve.custom.header_too_long", *a),
    "header_too_short": lambda *a: _t("carve.custom.header_too_short", *a),
    "header_starts_wild": lambda *a: _t("carve.custom.header_starts_wild", *a),
    "footer_too_long": lambda *a: _t("carve.custom.footer_too_long", *a),
    "footer_ends_wild": lambda *a: _t("carve.custom.footer_ends_wild", *a),
    "bad_header_offset": lambda *a: _t("carve.custom.bad_header_offset", *a),
    "bad_footer_extra": lambda *a: _t("carve.custom.bad_footer_extra", *a),
    "bad_max_size": lambda *a: _t("carve.custom.bad_max_size", *a),
    "bad_choice": lambda *a: _t("carve.custom.bad_choice", *a),
    "bad_id": lambda *a: _t("carve.custom.bad_id", *a),
}

def _carve_error(exc):
    say = _CARVE_ERRORS.get(exc.key, _CARVE_ERRORS["not_a_signature"])
    return say(*exc.args_)

def _root_node(fs):
    root = getattr(fs, "root_node", None)
    if root is None:
        root = {"NTFS": 5, "ext4": 2, "ext3": 2, "ext2": 2,
                "APFS": 2}.get(fs.name, 0)
    return root

def _detect_timezone(s, fs, part):
    out = []
    for path in ("/Windows/System32/config/SYSTEM",
                 "/WINDOWS/system32/config/system",
                 "/Windows.old/Windows/System32/config/SYSTEM"):
        e = _resolve_path(fs, path)
        if not e or e.get("is_dir") or (e.get("size") or 0) < 4096:
            continue
        try:
            hive = s.hive(part["offset"], e)
            tz = timezone_mod.from_registry(hive)
        except Exception:
            continue
        if tz:
            tz.source = "%s — %s" % (e.get("path") or path, tz.source)
            out.append(tz)
        break

    for cand in ("/etc/timezone", "/private/etc/timezone"):
        e = _resolve_path(fs, cand)
        if not e or e.get("is_dir"):
            continue
        try:
            body = fs.read_file(e, 256).decode("utf-8", "replace").strip()
        except Exception:
            continue
        tz = timezone_mod.from_iana(body.splitlines()[0] if body else "", cand)
        if tz:
            out.append(tz)
    for cand in ("/etc/localtime", "/private/etc/localtime"):
        e = _resolve_path(fs, cand)
        if not e:
            continue
        target = e.get("link_target") or e.get("symlink")
        if not target:
            try:
                target = fs.read_file(e, 4096)
            except Exception:
                continue
        tz = timezone_mod.from_localtime_link(target, cand)
        if tz:
            out.append(tz)
    return out

def _resolve_path(fs, path):
    node = _root_node(fs)
    here = ""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    for i, want in enumerate(parts):
        try:
            listing = fs.listdir(node, here or "/")
        except Exception:
            return None
        hit = None
        for e in listing:
            if (e.get("name") or "").lower() == want.lower():
                hit = e
                break
        if hit is None:
            return None
        if i == len(parts) - 1:
            return hit
        if not hit.get("is_dir"):
            return None
        node = (hit.get("mft") if hit.get("mft") is not None
                else hit.get("inode") if hit.get("inode") is not None
                else hit.get("oid") if hit.get("oid") is not None
                else hit.get("cnid") if hit.get("cnid") is not None
                else hit.get("start_cluster"))
        here = hit.get("path") or (here + "/" + want)
    return None

def _markup_kind(data, name=""):
    head = data[:4096].lstrip()[:512].lower()
    if b"<svg" in head or (name.lower().endswith(".svg") and b"<" in head):
        return "svg"
    if (head.startswith(b"<!doctype html") or head.startswith(b"<html")
            or b"<html" in head or b"<body" in head
            or (name.lower().endswith((".html", ".htm", ".xhtml", ".mht"))
                and b"<" in head)):
        return "html"
    return None

def _sniff_mime(data):
    head = data[:16]
    for sig, mime in _MIME_MAGIC:
        if head.startswith(sig):
            return mime
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12].decode("ascii", "replace").strip().lower()
        return _FTYP_MIME.get(brand, "video/mp4")
    if len(data) >= 12 and data[:4] == b"RIFF":
        form = data[8:12]
        if form == b"WEBP":
            return "image/webp"
        if form == b"WAVE":
            return "audio/wav"
        if form == b"AVI ":
            return "video/x-msvideo"
    return "application/octet-stream"

IMAGE_EXTS = (
    ".e01", ".ex01", ".l01",
    ".dd", ".raw", ".img", ".001", ".bin",
    ".vhdx", ".avhdx",
    ".vmdk",
    ".vhd", ".vdi", ".qcow", ".qcow2", ".ad1", ".aff",
)
CASE_EXTS = (".strata",)

def _browse(root, exts=IMAGE_EXTS):
    root = os.path.abspath(os.path.expanduser(root))
    if not os.path.isdir(root):
        root = os.path.dirname(root) or "/"
    items = []
    try:
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            try:
                is_dir = os.path.isdir(full)
                size = 0 if is_dir else os.path.getsize(full)
            except OSError:
                continue
            if name.startswith("."):
                continue
            case = is_dir and casedb_mod.is_case(full)
            if is_dir or exts is None \
                    or os.path.splitext(name)[1].lower() in exts:
                items.append({"name": name, "path": full,
                              "dir": is_dir and not case, "case": case,
                              "size": size})
    except PermissionError:
        pass
    return {"path": root, "parent": os.path.dirname(root), "items": items}

class _Server(ThreadingHTTPServer):

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port

def serve(host="127.0.0.1", port=8722, image=None, examiner=None):
    if image:
        SESSION.open(image, examiner=examiner)
    set_bound_address(host, port)
    httpd = _Server((host, port), Handler)
    print("Strata engine listening on http://%s:%d" % (host, port))
    if image:
        print("Evidence: %s" % image)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")

def _merge_search(into, got):
    if into is None:
        return dict(got)
    into["hits"] = (into.get("hits") or []) + (got.get("hits") or [])
    for k in ("entries", "searched", "bytes_read", "partial_files",
              "skipped_bytes", "unreadable"):
        if isinstance(got.get(k), (int, float)):
            into[k] = (into.get(k) or 0) + got[k]
    for k in ("truncated", "walk_truncated"):
        into[k] = bool(into.get(k)) or bool(got.get(k))
    into["partial_examples"] = ((into.get("partial_examples") or [])
                                + (got.get("partial_examples") or []))[:12]
    return into

def _render_report(s):
    data = s.case.report()
    detail = [{"label": ev.label,
               "partitions": ev.volumes.get("partitions") or []}
              for ev in s.items.values()]

    applied = s.case.get("timezone_offset")
    tz = json.loads(applied) if applied else None

    status = None
    try:
        st = textindex_mod.status(s.case)
        if st.get("built"):
            status = ("A content index of %s documents was built for this "
                      "case. Keyword results quoted here were answered from "
                      "it, and an index is a snapshot: it reflects the "
                      "evidence as it was when built."
                      % format(st["documents"], ","))
        elif not st.get("available"):
            status = ("This SQLite build has no FTS5, so no content index "
                      "could be built. Searches were run live against the "
                      "filesystem.")
    except Exception:
        status = None
    return report_mod.render(data, evidence_detail=detail, tz=tz,
                             index_status=status)

def _ese_cell(v):
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return b[:256].hex() + ("\u2026" if len(b) > 256 else "")
    if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
        return str(v)
    if isinstance(v, dict):
        return {k: _ese_cell(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_ese_cell(x) for x in v]
    return v

def _triage(s):
    out = []
    if not s.case:
        return {"findings": [], "note": _t("server.export.case_open")}

    enc, blind, gap_bytes, media = [], [], 0, 0
    for ev in s.items.values():
        media += ev.image.size
        for p in ev.volumes["partitions"]:
            if not p.get("allocated"):
                gap_bytes += p.get("size") or 0
                continue
            det = p.get("detected")
            if det in ("BitLocker", "LUKS"):
                enc.append({"exhibit": ev.label, "slot": p["slot"],
                            "type": det, "part": p["offset"],
                            "evidence": ev.evidence_id,
                            "unlocked": p["offset"] in ev.unlocked})
            elif not det:
                blind.append({"exhibit": ev.label, "slot": p["slot"],
                              "note": p.get("note"), "size": p.get("size")})

    if enc:
        locked = [e for e in enc if not e["unlocked"]]
        out.append({
            "kind": "encrypted", "severity": "high" if locked else "info",
            "title": "%d encrypted volume%s" % (len(enc), "" if len(enc) == 1 else "s"),
            "detail": ("%d still locked. Nothing on a locked volume is "
                       "searchable, indexable or hashable until it is opened."
                       % len(locked)) if locked else
                      "All are unlocked and readable.",
            "items": enc, "action": "unlock",
        })
    if blind:
        out.append({
            "kind": "unreadable", "severity": "medium",
            "title": "%d partition%s with no readable filesystem"
                     % (len(blind), "" if len(blind) == 1 else "s"),
            "detail": "Declared in the partition table but presenting nothing "
                      "this tool recognises. The notes say why for each.",
            "items": blind, "action": None,
        })
    if gap_bytes:
        out.append({
            "kind": "unallocated", "severity": "info",
            "title": "%s claimed by no partition" % fmt_bytes(gap_bytes),
            "detail": "Space outside every partition. A whole-disk index or a "
                      "carve is what reaches it; a filesystem walk never will.",
            "items": [], "action": "index",
        })

    scans = s.case.type_scan_summary()
    mism = s.case.type_mismatches()
    if not scans:
        out.append({
            "kind": "filetype", "severity": "info", "not_run": True,
            "title": "File types not verified",
            "detail": "Nothing has been checked for a name that disagrees "
                      "with its content. This has not been looked for, which "
                      "is not the same as nothing being there.",
            "items": [], "action": "filetypes",
        })
    else:
        high = [m for m in mism if m.get("severity") == "high"]
        checked = sum(v.get("checked") or 0 for v in scans.values())
        out.append({
            "kind": "filetype",
            "severity": "high" if high else "info",
            "title": "%d file%s whose content contradicts its name"
                     % (len(mism), "" if len(mism) == 1 else "s"),
            "detail": "%d of them %s a text extension over real binary "
                      "content, which is the shape of something renamed to be "
                      "overlooked. %s files checked."
                      % (len(high), "is" if len(high) == 1 else "are",
                         format(checked, ",")),
            "items": mism[:200], "action": "filetypes",
        })

    for ev in s.items.values():
        for p in ev.volumes["partitions"]:
            if not (p.get("allocated") and p.get("detected") == "NTFS"):
                continue
            got = getattr(ev, "usn", None)
            if got and got.get("part") == p["offset"]:
                st = got["stats"]
                recs = got["records"]
                dels = sum(1 for r in recs if "deleted" in r.get("reasons", []))
                ren = sum(1 for r in recs if "renamed from" in r.get("reasons", []))
                out.append({
                    "kind": "usn",
                    "severity": "medium" if st.get("resyncs") else "info",
                    "title": "%s change journal records on %s"
                             % (format(st["records"], ","), ev.label),
                    "detail": ("%s deletions and %s renames. These outlive the "
                               "MFT records they describe, so a name here may "
                               "be the only surviving record of a file."
                               % (format(dels, ","), format(ren, ",")))
                              + ((" %s point(s) could not be followed and were "
                                  "skipped." % format(st["resyncs"], ","))
                                 if st.get("resyncs") else ""),
                    "items": [{"exhibit": ev.label, "section": k, "count": v}
                              for k, v in (("deletions recorded", dels),
                                           ("renames recorded", ren),
                                           ("records total", st["records"]))],
                    "action": "usn", "part": p["offset"],
                })
                continue
            try:
                fs = s.fs(p["offset"], ev=ev)
                present = usnjrnl_mod.find(fs) is not None
            except Exception:
                present = False
            if present:
                out.append({
                    "kind": "usn", "severity": "info", "not_run": True,
                    "title": "Change journal present on %s, not read"
                             % ev.label,
                    "detail": "$UsnJrnl records what happened to files rather "
                              "than what they are — creations, renames, moves "
                              "and deletions — and its entries survive the MFT "
                              "records being reused. It has not been read.",
                    "items": [], "action": "usn", "part": p["offset"],
                })

    reg = getattr(s, "reg_report", None)
    if not reg:
        out.append({
            "kind": "registry", "severity": "info", "not_run": True,
            "title": "Registry not read",
            "detail": "Machine identity, USB devices attached, networks "
                      "joined, auto-start programs and local accounts all sit "
                      "in the hives and have not been looked at.",
            "items": [], "action": "registry",
        })
    else:
        rows, bad, blank = [], [], []
        for h in reg:
            if h.get("unreadable"):
                (blank if h.get("empty") else bad).append({
                    "hive": h.get("hive") or "(unnamed hive)",
                    "exhibit": h.get("exhibit"),
                    "section": ("allocated but never written"
                                if h.get("empty") else "would not parse"),
                    "note": h.get("why"),
                    "count": h.get("size")})
                continue
            label = h.get("kind")
            if label in ("NTUSER", "USRCLASS"):
                parts = [x for x in (h.get("hive") or "").replace(
                    "\\", "/").split("/") if x]
                who = next((parts[i + 1] for i, x in enumerate(parts[:-1])
                            if x.lower() in ("users", "serviceprofiles",
                                             "documents and settings")), None)
                if who:
                    label = "%s (%s)" % (label, who)
            for sec in h.get("sections") or []:
                if sec.get("count"):
                    rows.append({"hive": label,
                                 "exhibit": h.get("exhibit"),
                                 "section": sec["title"],
                                 "count": sec["count"]})
        interesting = [r for r in rows if r["section"] in
                       ("USB storage attached", "Networks joined",
                        "Auto-start programs (machine)",
                        "Auto-start programs (user)", "Local accounts")]
        detail = ""
        if bad:
            detail += ("%d hive%s has a valid header but would not parse — "
                       "that is damage, and it is listed first. "
                       % (len(bad), "" if len(bad) == 1 else "s"))
        if blank:
            detail += ("%d hive%s allocated and never written, which is "
                       "normal and means nothing is missing. "
                       % (len(blank), " was" if len(blank) == 1 else "s were"))
        out.append({
            "kind": "registry",
            "severity": "medium" if bad else "info",
            "title": "%d registry section%s with content across %d hive%s"
                     % (len(rows), "" if len(rows) == 1 else "s",
                        len(reg), "" if len(reg) == 1 else "s"),
            "detail": detail + "Machine identity, attached USB devices, "
                               "networks joined, auto-start programs and "
                               "accounts.",
            "items": bad + (interesting or rows) + blank,
            "action": "registry",
        })

    try:
        hs = s.case.hash_sets()
    except Exception:
        hs = []
    if not hs:
        out.append({
            "kind": "hashsets", "severity": "info", "not_run": True,
            "title": "No hash sets imported",
            "detail": "Without a known-bad or known-good list there is nothing "
                      "to match computed hashes against.",
            "items": [], "action": "hashes",
        })

    tags = s.case.tag_counts()
    if tags:
        out.append({
            "kind": "tagged", "severity": "info",
            "title": "%d tagged item%s" % (sum(tags.values()),
                                           "" if sum(tags.values()) == 1 else "s"),
            "detail": ", ".join("%s: %d" % (k, v) for k, v in sorted(tags.items())),
            "items": [], "action": "tags",
        })

    try:
        st = textindex_mod.status(s.case)
    except Exception:
        st = {"built": False}
    if not st.get("built"):
        out.append({
            "kind": "index", "severity": "info", "not_run": True,
            "title": "No content index",
            "detail": "Keyword searches will re-read the evidence each time, "
                      "and unallocated space is not covered at all until a "
                      "whole-disk sweep is run.",
            "items": [], "action": "index",
        })

    order = {"high": 0, "medium": 1, "info": 2}
    out.sort(key=lambda f: (order.get(f["severity"], 3), f["kind"]))
    return {
        "findings": out,
        "evidence": len(s.items),
        "media_bytes": media,
        "note": _t("server.export.everything_here_either_free"),
    }
