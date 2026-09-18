"""Compare two filesearch listings per path.

Issue #74: diff two images, or two snapshots of one volume. Both sides are
listings as produced by engine.filesearch.collect() over the respective
filesystem handles; the comparison is keyed by PATH, not by filesystem node,
because node identity (MFT record / inode) is stable within an image but not
across acquisitions of the same volume into another image (ROADMAP debt note).
Node numbers are carried in the entries but never used to decide "changed".

No ordering is assumed: FAT listdir does not sort, and NTFS sorts folders
first, so entries are keyed by path here.
"""

_FIELDS = ("size", "modified", "created", "accessed", "deleted")


def _key(e, ignore_case):
    path = e.get("path") or "/" + (e.get("name") or "")
    return path.casefold() if ignore_case else path


def _fields(e):
    return {f: e.get(f) for f in _FIELDS}


def _differs(a, b):
    for f in _FIELDS:
        if a.get(f) != b.get(f):
            return True
    return False


def compare(entries_a, entries_b, ignore_case=False):
    """Compare two filesearch listings per path.

    entries_*: lists of entry dicts as produced by filesearch.collect()
    (fields used: path, name, size, modified, created, accessed, deleted;
    is_dir rows are compared on presence + times like files).

    Returns:
      {"added":    [row...],   # only in b;  row = {"path", "b": fields}
       "removed":  [row...],   # only in a;  row = {"path", "a": fields}
       "changed":  [row...],   # in both, differs; row = {"path", "a": f, "b": f}
       "unchanged_count": N,
       "compared": len(union of keys)}
    where fields = {"size", "modified", "created", "accessed", "deleted"}.
    Rows sorted by path. mft/inode/oid are NOT compared (they differ across
    acquisitions -- ROADMAP debt note). A row is "changed" iff any compared
    field differs; node-only differences are ignored by design. Missing
    timestamps (None) compare as equal to None, different from a value.
    """
    a = {}
    b = {}
    for e in entries_a:
        k = _key(e, ignore_case)
        if k not in a:
            a[k] = e
    for e in entries_b:
        k = _key(e, ignore_case)
        if k not in b:
            b[k] = e

    added, removed, changed = [], [], []
    unchanged = 0
    for k in sorted(set(a) | set(b)):
        ea, eb = a.get(k), b.get(k)
        if eb is None:
            removed.append({"path": _key(ea, False), "a": _fields(ea)})
        elif ea is None:
            added.append({"path": _key(eb, False), "b": _fields(eb)})
        elif _differs(ea, eb):
            changed.append({"path": _key(ea, False),
                            "a": _fields(ea), "b": _fields(eb)})
        else:
            unchanged += 1
    return {"added": added, "removed": removed, "changed": changed,
            "unchanged_count": unchanged, "compared": len(set(a) | set(b))}