"""RAID 0, 1 and 5 sets reassembled from member images.

A set is defined by an examiner (name, level, chunk size, RAID 5 layout, and
the members in slot order, each with the offset where the array's data starts
on it), checked here once, and stored whole in the case. Reading is a mapping
from the array's bytes to member bytes; nothing is written and nothing is
guessed: what the members hold is reported as observed (mirrors that differ,
parity that does not match), never as a verdict on the set.

Layout names and formulas follow Linux md:
  left-symmetric   parity moves from the last member backwards; data starts on
                   the member after parity and wraps (md's default)
  left-asymmetric  parity as above; data fills the other members in order
  right-symmetric  parity moves from the first member forwards; data wraps
  right-asymmetric parity as above; data fills the other members in order
Hardware controllers name these differently; the chunk placement is what
matters, and the definition says it explicitly."""

import hashlib
import io
import json
import os
import re
import threading

from .text import t as _t

LEVELS = (0, 1, 5)
LAYOUTS = ("left-symmetric", "left-asymmetric", "right-symmetric",
           "right-asymmetric")
DEFAULT_LAYOUT = "left-symmetric"

MIN_CHUNK = 512
MAX_CHUNK = 64 << 20
MAX_MEMBERS = 32
MAX_NAME = 80
MAX_OFFSET = 1 << 50

# How much a consistency report lists; the counts are always complete.
MAX_REPORTED_RANGES = 20
SECTOR = 512
_BLOCK = 1 << 20


class RaidError(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice


# -- the definition -----------------------------------------------------------

def _bad(key, *args):
    raise ValueError(_t(key) % args if args else _t(key))


def _whole(v, what):
    if isinstance(v, bool) or not isinstance(v, int):
        _bad("raid.not_whole_number", what)
    return v


def clean_definition(d):
    """A set definition as the client sent it, checked and normalised:
    {"name", "level", "chunk", "layout", "members": [{"path", "offset"}],
    "primary"}. A member with no path is a slot whose disk is missing, which
    RAID 5 (one) and RAID 1 (all but one) can be read without. Raises
    ValueError with a message an examiner can act on."""
    if not isinstance(d, dict):
        _bad("raid.not_object")
    name = d.get("name")
    if not isinstance(name, str):
        _bad("raid.name_missing")
    name = name.strip()
    if not name:
        _bad("raid.name_missing")
    if len(name) > MAX_NAME:
        _bad("raid.name_long", MAX_NAME)
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        _bad("raid.name_control")
    level = d.get("level")
    if isinstance(level, bool) or level not in LEVELS:
        _bad("raid.level_unknown", level)

    chunk = None
    if level in (0, 5):
        chunk = _whole(d.get("chunk"), "chunk size")
        if not MIN_CHUNK <= chunk <= MAX_CHUNK or chunk % SECTOR:
            _bad("raid.chunk_range", MIN_CHUNK, MAX_CHUNK)

    layout = None
    if level == 5:
        layout = d.get("layout") or DEFAULT_LAYOUT
        if layout not in LAYOUTS:
            _bad("raid.layout_unknown", layout)

    raw = d.get("members")
    if not isinstance(raw, list):
        _bad("raid.members_missing")
    least = {0: 2, 1: 2, 5: 3}[level]
    if not least <= len(raw) <= MAX_MEMBERS:
        _bad("raid.member_count", level, least, MAX_MEMBERS)
    members, seen = [], set()
    for i, m in enumerate(raw, 1):
        if not isinstance(m, dict):
            _bad("raid.not_object")
        path = m.get("path")
        off = m.get("offset", 0)
        off = _whole(0 if off is None else off, "offset (member %d)" % i)
        if not 0 <= off <= MAX_OFFSET:
            _bad("raid.offset_range", i, MAX_OFFSET)
        if path in (None, ""):
            path = None
        else:
            if not isinstance(path, str) or "\x00" in path:
                _bad("raid.path_bad", i)
            path = os.path.abspath(path)
            key = os.path.normcase(path)
            if key in seen:
                _bad("raid.member_twice", i, os.path.basename(path))
            seen.add(key)
        members.append({"path": path, "offset": off})
    missing = [i for i, m in enumerate(members) if m["path"] is None]
    if level == 0 and missing:
        _bad("raid.raid0_missing")
    if level == 5 and len(missing) > 1:
        _bad("raid.raid5_two_missing")
    if level == 1 and len(missing) >= len(members):
        _bad("raid.no_member_present")

    primary = None
    if level == 1:
        primary = d.get("primary")
        if primary is None:
            primary = next(i for i, m in enumerate(members) if m["path"])
        primary = _whole(primary, "primary member")
        if not 0 <= primary < len(members) or members[primary]["path"] is None:
            _bad("raid.primary_bad")
    return {"name": name, "level": level, "chunk": chunk, "layout": layout,
            "members": members, "primary": primary}


def set_id(defn):
    """A name for the exhibit that is the same for the same definition and
    different for a different one, so the case and every cache keyed on it
    cannot mix two sets that happen to share a name. It is an identifier,
    not a file."""
    blob = json.dumps(defn, sort_keys=True).encode("utf-8")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", defn["name"])[:40].strip("_") or "set"
    return "strata-raid-%s-%s" % (hashlib.sha256(blob).hexdigest()[:12], safe)


def member_paths(defn):
    return [m["path"] for m in defn["members"] if m["path"]]


def is_set_id(path):
    return isinstance(path, str) and path.startswith("strata-raid-") \
        and os.sep not in path and "/" not in path


# -- geometry -----------------------------------------------------------------

def parity_disk(layout, row, n):
    if layout.startswith("left"):
        return (n - 1) - (row % n)
    return row % n


def data_disk(layout, row, k, n):
    """The member that holds data chunk `k` (0-based, within the row)."""
    pd = parity_disk(layout, row, n)
    if layout.endswith("symmetric") and not layout.endswith("asymmetric"):
        return (pd + 1 + k) % n
    return k if k < pd else k + 1


def _human(n):
    for unit in ("bytes", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return "%d %s" % (n, unit) if unit == "bytes" else "%.1f %s" % (n, unit)
        n /= 1024.0


class RaidImage:
    """A set opened for reading. Only the array is exposed."""

    def __init__(self, definition, opener=None):
        self.definition = clean_definition(definition)
        d = self.definition
        self.label = d["name"]
        self.path = set_id(d)
        self.level = d["level"]
        self.chunk = d["chunk"]
        self.layout = d["layout"]
        self.findings = []
        self._pos = 0
        self._lock = threading.Lock()
        self._reconstructed = 0
        self._short = False
        self.consistency = None
        self._members = []
        self.segment_paths = member_paths(d)
        if opener is None:
            from .ewf import open_image as opener
        try:
            for i, m in enumerate(d["members"]):
                self._members.append(self._open_member(i, m, opener))
            self._geometry()
        except BaseException:
            self.close()
            raise
        self.stamp_path = self.segment_paths[0]
        self.stamp_extra = hashlib.sha256(json.dumps(
            d, sort_keys=True).encode("utf-8")).hexdigest()[:16]
        for i, m in enumerate(self._members):
            if m is not None:
                self.bytes_per_sector = getattr(m, "bytes_per_sector", 512)
                break

    def _open_member(self, i, m, opener):
        if m["path"] is None:
            return None
        try:
            img = opener(m["path"])
        except Exception as exc:
            # A file that is not there, a folder, or something that is not an
            # image all come back as the reason it could not be read.
            raise RaidError(
                _t("raid.member_unreadable") % (
                    i + 1, os.path.basename(m["path"]),
                    getattr(exc, "message", None) or str(exc)),
                "Every member of the set must be an image file that can be "
                "read.")
        if getattr(img, "size", 0) <= m["offset"]:
            getattr(img, "close", lambda: None)()
            raise RaidError(_t("raid.member_too_small") % (
                i + 1, os.path.basename(m["path"]), m["offset"]))
        return img

    def _geometry(self):
        d = self.definition
        n = len(self._members)
        self._n = n
        usable = [m.size - d["members"][i]["offset"]
                  for i, m in enumerate(self._members) if m is not None]
        smallest = min(usable)
        if len(set(usable)) > 1:
            self.findings.append(
                "The members are not the same size after their data offsets "
                "(%s). The smallest sets the size of the array; the rest of "
                "each larger member is not part of it." % ", ".join(
                    _human(u) for u in usable))
        if self.level == 1:
            self._per = smallest
            self.size = smallest
            present = sum(1 for m in self._members if m is not None)
            if present < n:
                self.findings.append(
                    "%d of the %d mirror members are missing; the array is "
                    "read from the members present." % (n - present, n))
        else:
            c = self.chunk
            self._per = (smallest // c) * c
            if self._per <= 0:
                raise RaidError(_t("raid.smaller_than_chunk"))
            if self._per != smallest:
                self.findings.append(
                    "The last %s of the smallest member is less than a whole "
                    "chunk and is not part of the array." % _human(
                        smallest - self._per))
            data = n if self.level == 0 else n - 1
            self.size = data * self._per
            if self.level == 5:
                gone = [i for i, m in enumerate(self._members) if m is None]
                self._missing = gone[0] if gone else None
                if self._missing is not None:
                    self.findings.append(
                        "Member %d is missing. The chunks that would be on "
                        "it are rebuilt by XOR from the other members, and "
                        "with no redundancy left nothing can be checked "
                        "against parity. Every rebuilt range is data the "
                        "set no longer holds directly." % (self._missing + 1))
        if not hasattr(self, "_missing"):
            self._missing = None

    # -- reading ---------------------------------------------------------

    def _read_member(self, i, at, length):
        m = self._members[i]
        got = m.read_at(self.definition["members"][i]["offset"] + at, length)
        if len(got) < length:
            with self._lock:
                if not self._short:
                    self._short = True
                    self.findings.append(
                        "Member %d ended before the array's size implied; "
                        "what is missing reads as zeros." % (i + 1))
            got = got + bytes(length - len(got))
        return got

    def _rebuild(self, at, length, skip):
        acc = 0
        for i, m in enumerate(self._members):
            if i == skip or m is None:
                continue
            acc ^= int.from_bytes(self._read_member(i, at, length), "big")
        with self._lock:
            self._reconstructed += length
        return acc.to_bytes(length, "big")

    def _segment(self, v, length):
        """(bytes, consumed) for the array's bytes at `v`, from one chunk of
        one member."""
        if self.level == 1:
            n = min(length, self._per - v)
            if n <= 0:
                return b"", length
            i = self.definition["primary"]
            return self._read_member(i, v, n), n
        c = self.chunk
        s, within = divmod(v, c)
        n = min(length, c - within)
        if self.level == 0:
            row, disk = divmod(s, self._n)
            return self._read_member(disk, row * c + within, n), n
        nd = self._n - 1
        row, k = divmod(s, nd)
        disk = data_disk(self.layout, row, k, self._n)
        at = row * c + within
        if disk == self._missing:
            return self._rebuild(at, n, disk), n
        return self._read_member(disk, at, n), n

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        while length > 0:
            data, n = self._segment(offset, length)
            out += data
            offset += n
            length -= n
        return bytes(out)

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = off
        elif whence == io.SEEK_CUR:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos

    def close(self):
        for m in self._members:
            closer = getattr(m, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass
        self._members = []

    def parent_paths(self):
        """The files this exhibit reads through: the case records them, and
        the saved file listing is checked against them."""
        return list(self.segment_paths)

    # -- what the members hold, as observed --------------------------------

    def check_consistency(self, progress=None):
        """Compare what the members hold that should agree, and report what
        was found. A mirror's members should be identical; the chunks of a
        RAID 5 row should XOR to zero. Neither says which member is right, or
        that the set is wrong: a mismatch can come from a write in progress,
        a member that was out of date when it was taken, or a definition
        that does not match how the set was built. RAID 0 has nothing to
        compare, and a RAID 5 set missing a member has no redundancy left."""
        if self.level == 1 and sum(m is not None for m in self._members) > 1:
            r = self._check_mirror(progress)
        elif self.level == 5 and self._missing is None:
            r = self._check_parity(progress)
        else:
            r = {"kind": None, "summary": _t("raid.nothing_to_compare")}
        self.consistency = r
        return r

    def _ranges(self, hits, limit):
        """Merge (start, end) hits that touch into ranges."""
        merged = []
        for a, b in hits:
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        return merged, [{"start": a, "end": b} for a, b in merged[:limit]]

    def _check_mirror(self, progress):
        primary = self.definition["primary"]
        others = [i for i, m in enumerate(self._members)
                  if m is not None and i != primary]
        hits, differing = [], set()
        pos = 0
        while pos < self._per:
            n = min(_BLOCK, self._per - pos)
            base = self._read_member(primary, pos, n)
            for i in others:
                other = self._read_member(i, pos, n)
                if other == base:
                    continue
                for s in range(0, n, SECTOR):
                    if other[s:s + SECTOR] != base[s:s + SECTOR]:
                        hits.append((pos + s, pos + min(s + SECTOR, n)))
                        differing.add(i + 1)
            pos += n
            if progress:
                progress(min(1.0, pos / float(self._per)))
        hits.sort()
        merged, listed = self._ranges(hits, MAX_REPORTED_RANGES)
        total = sum(b - a for a, b in merged)
        r = {"kind": "mirror", "checked_bytes": self._per,
             "members_compared": len(others) + 1,
             "differing_ranges": len(merged), "differing_bytes": total,
             "differing_members": sorted(differing), "ranges": listed,
             "listed_all": len(listed) == len(merged)}
        if not merged:
            r["summary"] = _t("raid.mirror_identical") % (
                len(others) + 1, _human(self._per))
        else:
            r["summary"] = _t("raid.mirror_differs") % (
                len(merged), _human(total), ", ".join(
                    str(i) for i in sorted(differing)), listed[0]["start"])
        return r

    def _check_parity(self, progress):
        c, n = self.chunk, self._n
        rows = self._per // c
        bad = []
        for row in range(rows):
            acc = 0
            for i in range(n):
                acc ^= int.from_bytes(self._read_member(i, row * c, c), "big")
            if acc:
                bad.append(row)
            if progress and (row & 63 == 0 or row == rows - 1):
                progress((row + 1) / float(rows))
        span = c * (n - 1)
        merged, listed = self._ranges(
            [(r * span, (r + 1) * span) for r in bad], MAX_REPORTED_RANGES)
        r = {"kind": "parity", "rows_checked": rows,
             "rows_inconsistent": len(bad), "ranges": listed,
             "listed_all": len(listed) == len(merged)}
        if not bad:
            r["summary"] = _t("raid.parity_matches") % rows
        else:
            r["summary"] = _t("raid.parity_differs") % (
                len(bad), rows, listed[0]["start"])
        return r

    # -- the usual image surface -------------------------------------------

    def verify(self, progress=None):
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        pos = 0
        while pos < self.size:
            d = self.read_at(pos, _BLOCK)
            if not d:
                break
            md5.update(d)
            sha1.update(d)
            pos += len(d)
            if progress:
                progress(0.5 * pos / float(self.size))
        r = self.check_consistency(
            (lambda f: progress(0.5 + 0.5 * f)) if progress else None)
        note = _t("raid.stores_no_hash") + " " + r["summary"]
        return {"computed_md5": md5.hexdigest(),
                "computed_sha1": sha1.hexdigest(),
                "stored_md5": None, "stored_sha1": None,
                "md5_match": None, "sha1_match": None, "note": note,
                "raid": r}

    def _title(self):
        n = len(self._members)
        if self.level == 0:
            return "RAID 0 (%d members, %s chunk)" % (n, _human(self.chunk))
        if self.level == 1:
            return "RAID 1 (%d members)" % n
        return "RAID 5 (%d members, %s chunk, %s)" % (
            n, _human(self.chunk), self.layout)

    def info(self):
        d = self.definition
        acq = {"set name": d["name"], "level": "RAID %d" % self.level,
               "members": len(d["members"]),
               "members present": sum(1 for m in d["members"] if m["path"])}
        if self.chunk:
            acq["chunk size"] = self.chunk
        if self.layout:
            acq["layout"] = self.layout
        if self.level == 1:
            acq["read from"] = "member %d" % (d["primary"] + 1)
        acq["size per member used"] = self._per
        for i, m in enumerate(d["members"], 1):
            acq["member %d" % i] = (
                "missing" if m["path"] is None else
                "%s (data starts at %d)" % (m["path"], m["offset"]))
        if self.level == 5 and self._missing is not None:
            acq["bytes rebuilt from parity so far"] = self._reconstructed
        findings = list(self.findings)
        if self.consistency:
            findings.append(self.consistency["summary"])
        return {
            "format": self._title(),
            "raid": True,
            # The set's own name, not its members' files: the interface
            # titles an exhibit by it, and the members are listed under
            # acquisition.
            "segments": [d["name"]],
            "size": self.size,
            "sector_count": self.size // (getattr(self, "bytes_per_sector", 512) or 512),
            "bytes_per_sector": getattr(self, "bytes_per_sector", 512),
            "chunk_size": self.chunk or _BLOCK,
            "acquisition": acq,
            "findings": findings,
        }
