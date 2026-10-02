#!/usr/bin/env python3
"""Compare what Strata reads with what established readers read.

  python3 tests/crosscheck.py                  the synthetic corpus, against
                                               every reference that is installed
  python3 tests/crosscheck.py --list           what is installed, and the cases
  python3 tests/crosscheck.py --case 'hfs*'    only cases matching a pattern
  python3 tests/crosscheck.py --images PATH... real images (names withheld)

A run reads each image with Strata and with each reference reader that
handles its format, layer by layer (the disk container, the partition table,
each filesystem), always giving both the same input, and reports every
difference. A difference is not a verdict: either reader may be the one that
is wrong. The ones that are understood are listed, with their reasons, in
tests/crosscheck_baseline.json; a run fails on any that are not, and (with
--strict) on baseline entries that no longer match anything.

Real images. Names of files and folders are evidence. For --images they are
withheld from everything printed and saved unless --names is given, nothing
about such an image is ever written to the baseline, and results are saved
only under --out (default: crosscheck-out/, which is ignored by git).

Needs nothing but the standard library to run; each reference reader is used
only if its package (or program) is installed, and is reported as missing
otherwise. See the output of --list, and docs/CROSSCHECK.md."""

import argparse
import fnmatch
import json
import os
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import crosscheck_corpus as corpus                            # noqa: E402
import crosscheck_lib as lib                                  # noqa: E402
import crosscheck_refs as refs                                # noqa: E402
import crosscheck_strata as ours                              # noqa: E402

BASELINE = os.path.join(HERE, "crosscheck_baseline.json")

# coverage statuses
AGREE, DIFFER, NO_REF, MISSING = "agree", "differ", "no reference", "missing"


class Run(object):
    """Everything one invocation found."""

    def __init__(self, opts):
        self.opts = opts
        self.diffs = []
        self.coverage = []          # (case, layer, reference, status, note)

    def cover(self, case, layer, reference, status, note=""):
        self.coverage.append((case, layer, reference, status, note))

    def add(self, found):
        self.diffs.extend(found)


def guarded(run, case, facet, label, fn):
    """fn() -> result, or None after recording the exception as a
    difference: an error on either side is a finding, not a crash."""
    try:
        return fn()
    except refs.Rejected as exc:
        run.add([lib.difference(facet, case, lib.ERROR, label + ":refused",
                                str(exc))])
    except Exception as exc:                                   # noqa: BLE001
        if run.opts.trace:
            traceback.print_exc()
        run.add([lib.difference(
            facet, case, lib.ERROR, label + ":" + type(exc).__name__,
            str(exc)[:240])])
    return None


def check_container(run, case, path, img):
    key = ours.image_format(img)
    plan = lib.chunk_plan(img.size, run.opts.chunks, run.opts.seed)
    mine = guarded(run, case, "container", "strata",
                   lambda: ours.container(img, plan))
    candidates = refs.references_for("container", key)
    if not candidates:
        run.cover(case, "container", "-", NO_REF, "format %s" % key)
        return
    for ref in candidates:
        ok, why = ref.available()
        if not ok:
            run.cover(case, "container", ref.name, MISSING, why)
            continue
        theirs = guarded(run, case, "container", ref.name,
                         lambda: ref.run(path, plan, lib.CHUNK, key))
        if mine is None or theirs is None:
            run.cover(case, "container", ref.name, DIFFER, "one side failed")
            continue
        found = lib.compare_disks(case, mine, theirs)
        run.add(found)
        run.cover(case, "container", ref.name, DIFFER if found else AGREE)


def check_volumes(run, case, img):
    layout, mine = ours.partitions(img)
    scheme = layout.get("scheme")
    if scheme != "GPT":
        return layout, mine
    for ref in refs.references_for("volumes", "gpt"):
        ok, why = ref.available()
        if not ok:
            run.cover(case, "volumes", ref.name, MISSING, why)
            continue
        theirs = guarded(run, case, "volumes", ref.name,
                         lambda: ref.run(lib.SliceIO(img)))
        if theirs is None:
            run.cover(case, "volumes", ref.name, DIFFER, "reference failed")
            continue
        found = lib.compare_lists(case, "volumes", mine, theirs,
                                  lambda p: "partition %s" % p["index"])
        run.add(found)
        run.cover(case, "volumes", ref.name, DIFFER if found else AGREE)
    return layout, mine


def check_filesystems(run, case, img):
    layout = ours.volume.scan(img)
    for p in layout["partitions"]:
        if p.get("allocated") is False or not p.get("detected"):
            continue
        label = "%s@%d" % (p["detected"], p["offset"])
        try:
            fs = ours.open_partition(img, p["offset"], p["size"])
        except Exception as exc:                               # noqa: BLE001
            run.cover(case, "fs " + label, "-", NO_REF,
                      "Strata cannot open it: %s" % type(exc).__name__)
            continue
        kind = ours.fs_kind(fs)
        candidates = refs.references_for("fs", kind)
        if not candidates:
            run.cover(case, "fs " + label, "-", NO_REF, "filesystem %s" % kind)
            continue
        mine = guarded(run, case, "fs", "strata",
                       lambda: ours.tree(fs, run.opts.hash_bytes))
        for ref in candidates:
            ok, why = ref.available()
            if not ok:
                run.cover(case, "fs " + label, ref.name, MISSING, why)
                continue
            theirs = guarded(
                run, case, "fs", ref.name,
                lambda: ref.run(lib.SliceIO(img, p["offset"], p["size"]),
                                run.opts.hash_bytes))
            if mine is None or theirs is None:
                run.cover(case, "fs " + label, ref.name, DIFFER,
                          "one side failed")
                continue
            found = lib.compare_trees(case, mine, theirs)
            run.add(found)
            run.cover(case, "fs " + label, ref.name,
                      DIFFER if found else AGREE,
                      "%d entries / %d" % (len(mine), len(theirs)))


def run_case(run, case_id, path):
    try:
        img = ours.open_image(path)
    except Exception as exc:                                   # noqa: BLE001
        run.add([lib.difference("container", case_id, lib.ERROR,
                                "strata:open", "%s: %s" % (
                                    type(exc).__name__, str(exc)[:200]))])
        return
    try:
        check_container(run, case_id, path, img)
        check_volumes(run, case_id, img)
        check_filesystems(run, case_id, img)
    finally:
        img.close()


def synthetic_cases(opts):
    wanted = opts.case or ["*"]
    return [c for c in corpus.synthetic()
            if any(fnmatch.fnmatchcase(c.id, "synthetic:" + w)
                   or fnmatch.fnmatchcase(c.id, w) for w in wanted)]


def real_case_id(path):
    return "image:" + lib.sha(os.path.abspath(path).encode())[:8]


def print_list():
    print("Reference readers:")
    for r in refs.REFERENCES:
        ok, why = r.available()
        print("  %-10s %-12s %-22s %s" % (
            r.facet, r.name, ",".join(r.keys), "ok" if ok else why))
    print("\nSynthetic cases:")
    for c in corpus.synthetic():
        print("  " + c.id)


def report(run, baseline, redact):
    explained, unexplained, stale = lib.classify(run.diffs, baseline)
    print("\nCoverage")
    width = max([len(c[0]) for c in run.coverage] + [10])
    for case, layer, ref, status, note in run.coverage:
        print("  %-*s  %-22s %-12s %-12s %s" % (
            width, case, layer, ref, status, note))
    print("\n%d difference(s): %d explained by the baseline, %d not"
          % (len(run.diffs), len(explained), len(unexplained)))
    for line in lib.summarise(unexplained, redact):
        print(line)
    if stale:
        print("\n%d baseline entr%s match nothing now:" % (
            len(stale), "y" if len(stale) == 1 else "ies"))
        for e in stale:
            print("    %s %s %s %s" % (e["case"], e["facet"], e["kind"],
                                       e["key"]))
    return explained, unexplained, stale


def save(run, out_dir, explained, unexplained, stale, redact):
    os.makedirs(out_dir, exist_ok=True)

    def shown(d):
        d = dict(d)
        if d["facet"] == "fs":
            d["key"] = redact.path(d["key"])
            d["detail"] = redact.text(d["detail"]) if (
                redact.enabled and d["detail"]) else d["detail"]
        return d
    name = os.path.join(out_dir, "crosscheck-%d.json" % int(time.time()))
    with open(name, "w", encoding="utf-8") as fh:
        json.dump({
            "coverage": [list(c) for c in run.coverage],
            "unexplained": [shown(d) for d in unexplained],
            "explained": [shown(d) for d in explained],
            "stale_baseline": stale,
            "names_withheld": redact.enabled}, fh, indent=2)
    print("\nSaved %s" % name)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--case", action="append", metavar="PATTERN")
    ap.add_argument("--images", nargs="+", metavar="PATH")
    ap.add_argument("--names", action="store_true",
                    help="show file and folder names of real images")
    ap.add_argument("--baseline", default=BASELINE)
    ap.add_argument("--strict", action="store_true",
                    help="also fail on baseline entries that match nothing")
    ap.add_argument("--chunks", type=int, default=None,
                    help="read at most this many 1 MiB chunks of each disk")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--hash-bytes", type=int, default=1 << 20,
                    help="content digested per file (the first N bytes)")
    ap.add_argument("--out", default=os.path.join(
        os.path.dirname(HERE), "crosscheck-out"))
    ap.add_argument("--no-save", action="store_true")
    ap.add_argument("--trace", action="store_true")
    opts = ap.parse_args(argv)

    if opts.list:
        print_list()
        return 0

    run = Run(opts)
    real = bool(opts.images)
    redact = lib.Redactor(real and not opts.names)
    with tempfile.TemporaryDirectory(prefix="crosscheck-") as tmp:
        if real:
            for p in opts.images:
                if not os.path.isfile(p):
                    print("not a file: %s" % ("(withheld)" if redact.enabled
                                              else p), file=sys.stderr)
                    return 2
                cid = real_case_id(p)
                print("running %s" % cid)
                run_case(run, cid, p)
        else:
            for case in synthetic_cases(opts):
                print("running %s" % case.id)
                folder = os.path.join(tmp, case.id.split(":")[1])
                os.makedirs(folder)
                path = os.path.join(folder, "image" + case.suffix)
                with open(path, "wb") as fh:
                    fh.write(case.build())
                for name, data in case.companions().items():
                    with open(os.path.join(folder, name), "wb") as fh:
                        fh.write(data)
                run_case(run, case.id, path)

    baseline = [] if real else lib.load_baseline(opts.baseline)
    explained, unexplained, stale = report(run, baseline, redact)
    if not opts.no_save:
        save(run, opts.out, explained, unexplained, stale, redact)
    failed = bool(unexplained) or (opts.strict and bool(stale))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
