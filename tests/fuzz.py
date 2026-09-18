"""Mutation fuzzing for the parsers that read untrusted evidence.

Seeds are the synthetic images from tests/imagebuild_*.py.  Each case takes
one seed, applies a few random mutations (bit flips, interesting integers,
truncation, duplicated spans) and drives the same entry points the app uses:
open the filesystem and walk it, open a hive and walk it, open an E01 or a
VMDK and read and verify it, open an AD1 and walk and read its files.

What counts as a finding:

  hang       a single case ran past --case-timeout
  memory     the worker died or raised MemoryError under --memory-mb
  exception  anything other than a clean error (ValueError and the engine's
             own exception classes).  Reported, but only fails the run with
             --strict, since the server turns these into a 500 rather than
             losing the session.

Cases run in a child worker so a hang or an out-of-memory kill takes down
only the worker; the parent records the input and starts a new one.  Every
finding's input is written to --out with a JSON summary, and can be replayed:

    python3 tests/fuzz.py --minutes 5
    python3 tests/fuzz.py --target ext4 --cases 2000 --seed 7
    python3 tests/fuzz.py --replay fuzz-findings/ext4-hang-1a2b3c4d.bin

This is meant for CI (see .github/workflows/fuzz.yml).  The memory cap uses
RLIMIT_AS and is only enforced on Linux.
"""

import argparse
import hashlib
import json
import os
import queue
import random
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

# Hard caps inside each case, so a finding is about the parser rather than
# about the harness asking for too much.
WALK_BUDGET = 2000
WALK_DEPTH = 16
READ_FILES = 40
READ_BYTES = 1 << 16
HIVE_KEYS = 2000


# --- targets ---------------------------------------------------------------

class BytesImage:
    """ewf.RawImage stand-in over bytes."""

    bytes_per_sector = 512

    def __init__(self, data):
        self.data = data
        self.size = len(data)
        self.findings = []

    def read_at(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        return self.data[offset:offset + length]


def _root_handle(fs):
    root = getattr(fs, "root_node", None)
    if root is None:
        root = {"NTFS": 5, "ext4": 2, "ext3": 2, "ext2": 2,
                "APFS": 2}.get(getattr(fs, "name", ""), 0)
    return root


def run_fs(data):
    from engine import filesearch
    from engine.ewf import OffsetReader
    from engine.fs import ntfs
    src = OffsetReader(BytesImage(data), 0, len(data))
    fs = ntfs.open_fs(src)
    if hasattr(fs, "info"):
        fs.info()
    entries = filesearch.collect(fs, _root_handle(fs), budget=WALK_BUDGET,
                                 max_depth=WALK_DEPTH)
    read = 0
    for e in entries:
        if hasattr(fs, "stat"):
            fs.stat(e)
        if e.get("is_dir") or read >= READ_FILES:
            continue
        fs.read_file(e, READ_BYTES)
        read += 1


def run_volume(data):
    from engine import volume
    volume.scan(BytesImage(data))


def run_hive(data):
    from engine import registry
    hive = registry.open_hive(data, "SOFTWARE")
    if not hive:
        return
    seen = 0
    stack = [hive.root()]
    visited = set()
    while stack and seen < HIVE_KEYS:
        key = stack.pop()
        if not key:
            continue
        marker = key.get("offset", id(key))
        if marker in visited:
            continue
        visited.add(marker)
        seen += 1
        hive.values(key)
        stack.extend(hive.subkeys(key))
    hive.carve_deleted(limit=500)


def run_reglog(data, _pair=[]):
    import imagebuild_registry
    from engine import reglog
    if not _pair:
        _pair.extend(imagebuild_registry.build_dirty_pair()[:2])
    reglog.recover(_pair[0], [data])


def run_ewf(data, _dir=[], name="case.E01"):
    from engine import ewf
    if not _dir:
        _dir.append(tempfile.mkdtemp(prefix="strata-fuzz-"))
    path = os.path.join(_dir[0], name)
    with open(path, "wb") as fh:
        fh.write(data)
    img = ewf.open_image(path)
    try:
        step = max(1, min(img.size, 1 << 20) // 64)
        for off in range(0, min(img.size, 1 << 20), step):
            img.read_at(off, 4096)
        img.verify()
    finally:
        img.close()


def run_vmdk(data):
    run_ewf(data, name="disk.vmdk")


def _seeds_fs():
    import imagebuild_apfs
    import imagebuild_ext4
    import imagebuild_fat
    out = {
        "fat12": lambda: imagebuild_fat.build_fat(12),
        "fat16": lambda: imagebuild_fat.build_fat(16),
        # No fat32: its seed is ~34 MB of mostly zeros, so mutations land in
        # empty space.  fat12 and fat16 drive the same FatFS code paths.
        "exfat": imagebuild_fat.build_exfat,
        "ext4": imagebuild_ext4.build_ext4,
        "ext2": imagebuild_ext4.build_ext2_legacy,
        "apfs": imagebuild_apfs.build_apfs,
    }
    try:
        import imagebuild_ntfs
        out["ntfs"] = imagebuild_ntfs.build_ntfs
    except ImportError:
        pass
    return out


def targets():
    """name -> (seed builder, runner)."""
    import imagebuild_ad1
    import imagebuild_ewf
    import imagebuild_fat
    import imagebuild_registry
    import imagebuild_vmdk
    out = {}
    for name, build in _seeds_fs().items():
        out[name] = (build, run_fs)
    out["mbr"] = (lambda: imagebuild_fat.wrap_mbr(imagebuild_fat.build_fat(16)),
                  run_volume)
    try:
        import imagebuild_ntfs
        out["gpt"] = (lambda: imagebuild_ntfs.wrap_gpt(
            imagebuild_ntfs.build_ntfs()), run_volume)
    except ImportError:
        pass
    out["hive"] = (imagebuild_registry.build_hive, run_hive)
    out["reglog"] = (lambda: imagebuild_registry.build_dirty_pair()[1],
                     run_reglog)
    out["ewf"] = (lambda: imagebuild_ewf.build_e01()[0], run_ewf)
    out["vmdk-sparse"] = (imagebuild_vmdk.build_sparse, run_vmdk)
    out["vmdk-stream"] = (lambda: imagebuild_vmdk.build_stream_optimized()[0],
                          run_vmdk)
    # An AD1 opens through the filesystem dispatcher, like a volume.
    out["ad1"] = (lambda: imagebuild_ad1.build_ad1()[0], run_fs)
    return out


# --- mutation --------------------------------------------------------------

INTERESTING = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF,
               0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


def mutate(seed, rng):
    data = bytearray(seed)
    for _ in range(rng.randint(1, 8)):
        if not data:
            break
        op = rng.random()
        pos = rng.randrange(len(data))
        if op < 0.35:
            data[pos] ^= 1 << rng.randrange(8)
        elif op < 0.55:
            data[pos] = rng.choice((0, 0xFF, 0x7F, 0x80, rng.randrange(256)))
        elif op < 0.85:
            width, fmt = rng.choice(((2, "<H"), (4, "<I"), (8, "<Q")))
            if pos + width <= len(data):
                v = rng.choice(INTERESTING) & ((1 << (8 * width)) - 1)
                struct.pack_into(fmt, data, pos, v)
        elif op < 0.93:
            size = rng.randint(1, 512)
            src = rng.randrange(len(data))
            chunk = data[src:src + size]
            data[pos:pos + len(chunk)] = chunk
        else:
            del data[rng.randint(len(data) // 2, len(data)):]
    return bytes(data)


# --- classification --------------------------------------------------------

def _clean_types():
    """Exception classes a parser may raise to say "this input is bad"."""
    from engine import ewf
    from engine.fs import ntfs
    types = [ValueError]
    for mod in (ewf, ntfs):
        for obj in vars(mod).values():
            if (isinstance(obj, type) and issubclass(obj, Exception)
                    and obj.__module__.startswith("engine")):
                types.append(obj)
    return tuple(types)


def _where(tb):
    """Innermost engine frame, which is what identifies a bug."""
    frames = traceback.extract_tb(tb)
    for fr in reversed(frames):
        rel = os.path.relpath(fr.filename, ROOT)
        if rel.startswith("engine"):
            return "%s:%d" % (rel.replace(os.sep, "/"), fr.lineno)
    fr = frames[-1] if frames else None
    return "%s:%d" % (fr.filename, fr.lineno) if fr else "?"


# --- worker ----------------------------------------------------------------

def worker(args):
    if args.memory_mb and sys.platform.startswith("linux"):
        import resource
        cap = args.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    sys.setrecursionlimit(4000)
    table = targets()
    clean = _clean_types()
    seeds = {}
    out = sys.stdout
    for line in sys.stdin:
        name, case_seed = line.split()
        build, run = table[name]
        if name not in seeds:
            seeds[name] = build()
        data = mutate(seeds[name], random.Random(int(case_seed)))
        out.write("start\n")
        out.flush()
        result = {"ok": True}
        try:
            run(data)
        except clean:
            pass
        except MemoryError:
            result = {"ok": False, "kind": "memory", "type": "MemoryError",
                      "where": _where(sys.exc_info()[2])}
        except RecursionError:
            result = {"ok": False, "kind": "exception",
                      "type": "RecursionError",
                      "where": _where(sys.exc_info()[2])}
        except Exception as exc:
            result = {"ok": False, "kind": "exception",
                      "type": type(exc).__name__, "message": str(exc)[:200],
                      "where": _where(sys.exc_info()[2])}
        out.write(json.dumps(result) + "\n")
        out.flush()


class Worker:

    def __init__(self, args):
        cmd = [sys.executable, os.path.abspath(__file__), "--worker",
               "--memory-mb", str(args.memory_mb)]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     universal_newlines=True, bufsize=1)
        self.lines = queue.Queue()
        t = threading.Thread(target=self._pump, daemon=True)
        t.start()

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def run(self, name, case_seed, timeout):
        """Returns a result dict, with kind hang/memory on worker loss."""
        try:
            self.proc.stdin.write("%s %d\n" % (name, case_seed))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            return {"ok": False, "kind": "memory", "type": "worker died"}
        started = False
        deadline = time.time() + timeout + 60     # seed build on first use
        while True:
            try:
                line = self.lines.get(timeout=max(0.1, deadline - time.time()))
            except queue.Empty:
                if started:
                    return {"ok": False, "kind": "hang",
                            "type": "timeout %ss" % timeout}
                return {"ok": False, "kind": "hang",
                        "type": "seed build timed out"}
            if line is None:
                if not started:
                    # Died before the case began: an import error or a
                    # broken seed, not a finding.  Stop rather than respawn.
                    raise RuntimeError("fuzz worker failed to start %s"
                                       % name)
                return {"ok": False, "kind": "memory", "type": "worker died",
                        "returncode": self.proc.poll()}
            if line.strip() == "start":
                started = True
                deadline = time.time() + timeout
                continue
            return json.loads(line)

    def kill(self):
        try:
            self.proc.kill()
            self.proc.wait(5)
        except Exception:
            pass


# --- driver ----------------------------------------------------------------

def record(args, name, case_seed, result, findings):
    build, _ = targets()[name]
    data = mutate(build(), random.Random(case_seed))
    key = "%s|%s|%s|%s" % (name, result["kind"], result.get("type"),
                           result.get("where"))
    if key in findings:
        findings[key]["count"] += 1
        return False
    digest = hashlib.sha256(key.encode()).hexdigest()[:8]
    stem = "%s-%s-%s" % (name, result["kind"], digest)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, stem + ".bin"), "wb") as fh:
        fh.write(data)
    entry = dict(result, target=name, case_seed=case_seed, count=1,
                 input=stem + ".bin")
    entry.pop("ok", None)
    findings[key] = entry
    return True


def fuzz(args):
    table = targets()
    names = sorted(table) if args.target == "all" else [args.target]
    unknown = [n for n in names if n not in table]
    if unknown:
        sys.exit("unknown target: %s (have: %s)"
                 % (", ".join(unknown), ", ".join(sorted(table))))
    rng = random.Random(args.seed)
    stop_at = time.time() + args.minutes * 60 if args.minutes else None
    findings = {}
    counts = dict((n, 0) for n in names)
    w = Worker(args)
    done = 0
    try:
        while True:
            if args.cases and done >= args.cases:
                break
            if stop_at and time.time() >= stop_at:
                break
            name = names[done % len(names)]
            case_seed = rng.getrandbits(48)
            result = w.run(name, case_seed, args.case_timeout)
            done += 1
            counts[name] += 1
            if result.get("ok"):
                continue
            if record(args, name, case_seed, result, findings):
                print("finding: %s %s %s at %s" % (
                    name, result["kind"], result.get("type"),
                    result.get("where", "?")))
                sys.stdout.flush()
            if result["kind"] in ("hang", "memory"):
                w.kill()
                w = Worker(args)
    finally:
        w.kill()

    summary = {"cases": done, "per_target": counts,
               "findings": sorted(findings.values(),
                                  key=lambda f: (f["kind"], f["target"]))}
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    kinds = {}
    for f in findings.values():
        kinds[f["kind"]] = kinds.get(f["kind"], 0) + 1
    print("fuzz: %d cases, %d distinct findings %s"
          % (done, len(findings), json.dumps(kinds, sort_keys=True)))
    fatal = kinds.get("hang", 0) + kinds.get("memory", 0)
    if args.strict:
        fatal += kinds.get("exception", 0)
    return 1 if fatal else 0


def replay(args):
    name = os.path.basename(args.replay).split("-")[0]
    table = targets()
    if name not in table:
        sys.exit("cannot tell the target from %s" % args.replay)
    with open(args.replay, "rb") as fh:
        data = fh.read()
    table[name][1](data)
    print("replay: %s returned without raising" % name)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target", default="all")
    ap.add_argument("--minutes", type=float, default=0)
    ap.add_argument("--cases", type=int, default=0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--case-timeout", type=float, default=10)
    ap.add_argument("--memory-mb", type=int, default=1024)
    ap.add_argument("--out", default=os.path.join(ROOT, "fuzz-findings"))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--replay")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.worker:
        return worker(args)
    if args.replay:
        return replay(args)
    if not args.minutes and not args.cases:
        args.cases = 500
    return fuzz(args)


if __name__ == "__main__":
    sys.exit(main())
