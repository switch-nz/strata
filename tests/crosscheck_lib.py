"""Cross-checking Strata's readers against established ones.

Nothing here imports a third-party package. A reference reader is only ever
reached through the adapters in crosscheck_refs.py, which are skipped when the
package behind them is not installed; this module holds what is common to all
of them:

  * how an image is cut into the pieces both sides are asked to read, so a
    disagreement can be pinned to a byte range rather than to a whole disk;
  * the shape of what each side reports (an "observation": plain dicts and
    lists, so it can be saved and compared later);
  * the comparison itself, which names every difference and says which side
    it is in;
  * the baseline of differences that are understood and accepted, each with
    its reason, so a new difference fails a run and a known one does not;
  * the report, which can leave out names (a real image's file and folder
    names are evidence, and must not end up in anything that is published).

A difference is never resolved by deciding which reader is right. The two
disagree; a person finds out why."""

import fnmatch
import hashlib
import json
import os
import random

CHUNK = 1 << 20
HASH_LEN = 16                        # hex digits kept of each digest

# What a difference is in. The report groups on these.
ONLY_STRATA, ONLY_REF, DIFFERS, ERROR = (
    "only_strata", "only_ref", "differs", "error")
KINDS = (ONLY_STRATA, ONLY_REF, DIFFERS, ERROR)


def sha(data):
    return hashlib.sha256(data).hexdigest()[:HASH_LEN]


class SliceIO(object):
    """A file object over part of anything with read_at(offset, length) and a
    size: how a reference reader is given Strata's view of a partition (so a
    filesystem is compared on the same bytes on both sides) or a synthetic
    image held in memory."""

    def __init__(self, source, offset=0, size=None):
        self._source = source
        self._offset = offset
        self._size = (source.size - offset) if size is None else size
        self._pos = 0

    def read(self, n=-1):
        if n is None or n < 0:
            n = self._size - self._pos
        n = max(0, min(n, self._size - self._pos))
        if not n:
            return b""
        data = self._source.read_at(self._offset + self._pos, n)
        self._pos += len(data)
        return data

    def seek(self, offset, whence=0):
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        else:
            self._pos = self._size + offset
        self._pos = max(0, self._pos)
        return self._pos

    def tell(self):
        return self._pos

    def get_size(self):
        return self._size

    def close(self):
        pass

    def seekable(self):
        return True

    def readable(self):
        return True


class BytesSource(object):
    """read_at over bytes."""
    bytes_per_sector = 512

    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


# -- cutting an image into pieces ---------------------------------------------

def chunk_plan(size, budget=None, seed=1, chunk=CHUNK, edge=8):
    """The chunk numbers to read: all of them when the image is small enough
    (or `budget` is None), otherwise the first and last `edge` and a seeded
    random choice between, so both sides are asked for the same ranges and a
    run can be repeated exactly."""
    total = -(-size // chunk) if size else 0
    everything = list(range(total))
    if budget is None or total <= budget:
        return everything
    pick = set(everything[:edge]) | set(everything[-edge:])
    rng = random.Random(seed)
    middle = everything[edge:-edge] if total > 2 * edge else []
    pick.update(rng.sample(middle, min(len(middle),
                                       max(0, budget - len(pick)))))
    return sorted(pick)


def digest_chunks(read_at, size, plan, chunk=CHUNK):
    """{chunk number: digest of what read_at returns for it}, over `plan`."""
    out = {}
    for n in plan:
        want = min(chunk, size - n * chunk)
        data = read_at(n * chunk, want) if want > 0 else b""
        out[n] = sha(data) if len(data) == want else \
            "short:%d" % len(data)
    return out


# -- observations --------------------------------------------------------------

def disk_observation(read_at, size, plan, chunk=CHUNK):
    return {"size": size, "chunk": chunk,
            "digests": digest_chunks(read_at, size, plan, chunk)}


def entry_observation(path, kind, size=None, digest=None, streams=None):
    """One file or folder. `digest` is of the content's first bytes only (as
    many as the run was told to read); `streams` is {name: (size, digest)}
    for the extra streams a filesystem has (NTFS alternate data streams, an
    HFS+ resource fork)."""
    out = {"path": path, "kind": kind}
    if kind == "file":
        out["size"] = size
        out["digest"] = digest
    if streams:
        out["streams"] = {k: list(v) for k, v in sorted(streams.items())}
    return out


# -- differences -----------------------------------------------------------------

def difference(facet, case, kind, key, detail=""):
    return {"facet": facet, "case": case, "kind": kind, "key": key,
            "detail": detail}


def compare_disks(case, ours, ref, facet="container"):
    out = []
    if ours["size"] != ref["size"]:
        out.append(difference(facet, case, DIFFERS, "size",
                              "Strata %d, reference %d"
                              % (ours["size"], ref["size"])))
    bad = sorted(n for n in set(ours["digests"]) & set(ref["digests"])
                 if ours["digests"][n] != ref["digests"][n])
    if bad:
        chunk = ours["chunk"]
        first = bad[0] * chunk
        out.append(difference(
            facet, case, DIFFERS, "content",
            "%d of %d chunks differ; the first at byte %d"
            % (len(bad), len(set(ours["digests"]) & set(ref["digests"])),
               first)))
    for n in sorted(set(ours["digests"]) ^ set(ref["digests"])):
        out.append(difference(facet, case, ERROR, "chunk %d" % n,
                              "read on one side only"))
    return out


def compare_lists(case, facet, ours, ref, key):
    """Two lists of dicts compared by `key(item)`: what is on one side only,
    and which fields differ where both have it."""
    a = {key(x): x for x in ours}
    b = {key(x): x for x in ref}
    out = []
    for k in sorted(set(a) - set(b)):
        out.append(difference(facet, case, ONLY_STRATA, k))
    for k in sorted(set(b) - set(a)):
        out.append(difference(facet, case, ONLY_REF, k))
    for k in sorted(set(a) & set(b)):
        fields = sorted(f for f in set(a[k]) | set(b[k])
                        if f != "path" and a[k].get(f) != b[k].get(f))
        if fields:
            out.append(difference(
                facet, case, DIFFERS, k, "; ".join(
                    "%s: Strata %r, reference %r"
                    % (f, a[k].get(f), b[k].get(f)) for f in fields)))
    return out


def compare_trees(case, ours, ref):
    return compare_lists(case, "fs", ours, ref, lambda e: e["path"])


# -- the baseline ------------------------------------------------------------------

class BaselineError(ValueError):
    pass


def load_baseline(path):
    """The accepted differences, checked. Each says which case, facet and kind
    it covers, a pattern for the key, and why it is accepted; an entry
    without a reason is refused, and so is one about a real image, so the file
    can never name anyone's evidence."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        entries = json.load(fh)
    for i, e in enumerate(entries):
        for need in ("case", "facet", "kind", "key", "reason"):
            if not e.get(need):
                raise BaselineError("baseline entry %d has no %s" % (i, need))
        if not e["case"].startswith("synthetic:"):
            raise BaselineError(
                "baseline entry %d is about %r; only synthetic cases may be "
                "listed" % (i, e["case"]))
        if e["kind"] not in KINDS:
            raise BaselineError("baseline entry %d: unknown kind %r"
                                % (i, e["kind"]))
    return entries


def covers(entry, diff):
    return (fnmatch.fnmatchcase(diff["case"], entry["case"])
            and entry["facet"] == diff["facet"]
            and entry["kind"] == diff["kind"]
            and fnmatch.fnmatchcase(diff["key"], entry["key"]))


def classify(diffs, baseline):
    """(explained, unexplained, stale): differences a baseline entry covers,
    those none does, and baseline entries nothing matched."""
    used = set()
    explained, unexplained = [], []
    for d in diffs:
        hit = next((i for i, e in enumerate(baseline) if covers(e, d)), None)
        if hit is None:
            unexplained.append(d)
        else:
            used.add(hit)
            explained.append(dict(d, reason=baseline[hit]["reason"]))
    stale = [e for i, e in enumerate(baseline) if i not in used]
    return explained, unexplained, stale


# -- reporting ----------------------------------------------------------------------

class Redactor(object):
    """Replaces names with stable tokens, so a report of a real image can say
    how many files differ, and where in the tree, without saying what they
    are called."""

    def __init__(self, enabled):
        self.enabled = enabled

    def path(self, p):
        if not self.enabled or not p.startswith("/"):
            return p
        parts = [x for x in p.split("/") if x]
        return "/" + "/".join("#" + sha(x.encode("utf-8", "replace"))[:6]
                              for x in parts)

    def text(self, s):
        return s if not self.enabled else "(withheld)"


def summarise(diffs, redact):
    """Lines for the console: counts per facet and kind, then each
    difference."""
    lines = []
    for facet in sorted({d["facet"] for d in diffs}):
        mine = [d for d in diffs if d["facet"] == facet]
        counts = ", ".join("%d %s" % (sum(1 for d in mine if d["kind"] == k),
                                      k.replace("_", " "))
                           for k in KINDS
                           if any(d["kind"] == k for d in mine))
        lines.append("  %s: %s" % (facet, counts))
    for d in diffs:
        key = redact.path(d["key"]) if d["facet"] == "fs" else d["key"]
        detail = d.get("detail") or ""
        if d["facet"] == "fs" and redact.enabled:
            detail = redact.text(detail) if detail else ""
        lines.append("    [%s] %s %s%s" % (
            d["kind"], d["case"], key, (" -- " + detail) if detail else ""))
    return lines
