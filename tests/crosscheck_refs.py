"""The reference readers: established tools that read the same formats as
Strata, reached through a thin adapter each so that what they report has the
same shape as what crosscheck_strata reports.

An adapter is registered with its facet, the formats it can check, and what it
needs (Python modules, or programs on the PATH). One whose needs are missing is
listed as unavailable and skipped; nothing here is imported until it is used,
so Strata's own tests need none of them.

Most are the Python bindings of the libyal libraries (libewf, libvhdi,
libqcow, libvmdk, libvsgpt, libfsntfs, libfshfs, libfsext, libfsfat, ...),
which are written and maintained independently of Strata and are what many
other forensic tools build on. `qemu-img` is the reference for the virtual
disk formats it reads (QCOW2, VDI, VHD, VMDK, DMG)."""

import importlib
import os
import shutil
import subprocess
import tempfile

import crosscheck_lib as lib


class Rejected(Exception):
    """The reference reader refused the input or could not finish reading it.
    Not a disagreement about content, and not agreement either; it is
    reported, and has to be explained in the baseline."""


class Reference(object):

    def __init__(self, facet, keys, name, modules, tools, run, hint):
        self.facet, self.keys, self.name = facet, tuple(keys), name
        self.modules, self.tools, self.run, self.hint = modules, tools, run, hint

    def available(self):
        """(True, "") or (False, what is missing)."""
        for m in self.modules:
            try:
                importlib.import_module(m)
            except Exception:                              # noqa: BLE001
                return False, "needs the Python module %s%s" % (
                    m, (" (" + self.hint + ")") if self.hint else "")
        for t in self.tools:
            if not shutil.which(t):
                return False, "needs %s on the PATH%s" % (
                    t, (" (" + self.hint + ")") if self.hint else "")
        return True, ""


REFERENCES = []


def reference(facet, keys, name, modules=(), tools=(), hint=""):
    def register(fn):
        REFERENCES.append(Reference(facet, keys, name, modules, tools, fn,
                                    hint))
        return fn
    return register


def references_for(facet, key):
    return [r for r in REFERENCES if r.facet == facet and key in r.keys]


# -- whole-disk formats ---------------------------------------------------------

def _from_handle(handle, plan, chunk):
    size = handle.media_size

    def read_at(offset, length):
        return handle.read_buffer_at_offset(length, offset)
    return lib.disk_observation(read_at, size, plan, chunk)


@reference("container", ("raw",), "the file itself")
def _raw(path, plan, chunk, key=None):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        def read_at(offset, length):
            fh.seek(offset)
            return fh.read(length)
        return lib.disk_observation(read_at, size, plan, chunk)


@reference("container", ("ewf",), "libewf", modules=("pyewf",),
           hint="pip install libewf-python")
def _libewf(path, plan, chunk, key=None):
    import pyewf
    handle = pyewf.handle()
    handle.open(pyewf.glob(path))
    try:
        return _from_handle(handle, plan, chunk)
    finally:
        handle.close()


@reference("container", ("vhd", "vhdx"), "libvhdi", modules=("pyvhdi",),
           hint="pip install libvhdi-python")
def _libvhdi(path, plan, chunk, key=None):
    import pyvhdi
    disk, parent = pyvhdi.file(), None
    disk.open(path)
    try:
        name = disk.parent_filename
        if name:
            beside = os.path.join(os.path.dirname(path),
                                  os.path.basename(name.replace("\\", "/")))
            if not os.path.exists(beside):
                raise Rejected("the parent disk %r is not beside it" % name)
            parent = pyvhdi.file()
            parent.open(beside)
            disk.set_parent(parent)
        return _from_handle(disk, plan, chunk)
    finally:
        disk.close()
        if parent:
            parent.close()


@reference("container", ("qcow2",), "libqcow", modules=("pyqcow",),
           hint="pip install libqcow-python")
def _libqcow(path, plan, chunk, key=None):
    import pyqcow
    handle = pyqcow.file()
    handle.open(path)
    try:
        return _from_handle(handle, plan, chunk)
    finally:
        handle.close()


@reference("container", ("vmdk",), "libvmdk", modules=("pyvmdk",),
           hint="pip install libvmdk-python")
def _libvmdk(path, plan, chunk, key=None):
    import pyvmdk
    handle = pyvmdk.handle()
    handle.open(path)
    try:
        handle.open_extent_data_files()
        return _from_handle(handle, plan, chunk)
    finally:
        handle.close()


QEMU_FORMATS = {"qcow2": "qcow2", "vdi": "vdi", "vhd": "vpc", "vmdk": "vmdk",
                "dmg": "dmg"}


@reference("container", tuple(QEMU_FORMATS), "qemu-img", tools=("qemu-img",),
           hint="apt-get install qemu-utils")
def _qemu(path, plan, chunk, key=None):
    out = tempfile.mkdtemp(prefix="crosscheck-qemu-")
    try:
        raw = os.path.join(out, "disk.raw")
        cmd = ["qemu-img", "convert", "-f", QEMU_FORMATS[key], "-O", "raw",
               path, raw]
        done = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=600)
        if done.returncode:
            raise Rejected(done.stderr.decode("utf-8", "replace").strip()[:200])
        return _raw(raw, plan, chunk)
    finally:
        shutil.rmtree(out, ignore_errors=True)


# -- partition tables -------------------------------------------------------------

@reference("volumes", ("gpt",), "libvsgpt", modules=("pyvsgpt",),
           hint="pip install libvsgpt-python")
def _libvsgpt(fileobj):
    import pyvsgpt
    volume = pyvsgpt.volume()
    volume.open_file_object(fileobj)
    try:
        return [{"index": p.entry_index, "offset": p.volume_offset,
                 "size": p.size,
                 "type": str(p.type_identifier).strip("{}").lower(),
                 "identifier": str(p.identifier).strip("{}").lower()}
                for p in volume.partitions]
    finally:
        volume.close()


# -- filesystems ----------------------------------------------------------------

MAX_DEPTH = 64
MAX_ENTRIES = 500000
S_IFMT, S_IFDIR, S_IFLNK = 0o170000, 0o040000, 0o120000


def _digest(read, size, hash_bytes):
    if not size:
        return lib.sha(b"")
    try:
        return lib.sha(read(min(size, hash_bytes)))
    except Exception as exc:                               # noqa: BLE001
        return "error:" + type(exc).__name__


def _walk(root, hash_bytes, describe):
    """Every file and folder below `root` (which has no name of its own),
    depth first. `describe(entry)` gives (name, kind, size, read, streams,
    children): `read(n)` returns the first n bytes, `streams` is
    {name: (size, digest)} and `children` is a list for a folder, else None."""
    out = []
    stack = [("", c, 1) for c in reversed(describe(root)[5] or [])]
    while stack and len(out) < MAX_ENTRIES:
        base, entry, depth = stack.pop()
        name, kind, size, read, streams, kids = describe(entry)
        path = base + "/" + name
        out.append(lib.entry_observation(
            path, kind, size,
            _digest(read, size, hash_bytes) if kind != "dir" else None,
            streams))
        if kids is not None and depth < MAX_DEPTH:
            stack.extend((path, k, depth + 1) for k in reversed(kids))
    out.sort(key=lambda e: e["path"])
    return out


def _reader(entry):
    def read(n):
        entry.seek_offset(0)
        return entry.read_buffer(n)
    return read


def _posix_kind(entry):
    mode = entry.file_mode & S_IFMT
    return ("dir" if mode == S_IFDIR else "link" if mode == S_IFLNK
            else "file")


@reference("fs", ("ntfs",), "libfsntfs", modules=("pyfsntfs",),
           hint="pip install libfsntfs-python")
def _libfsntfs(fileobj, hash_bytes):
    import pyfsntfs
    volume = pyfsntfs.volume()
    try:
        volume.open_file_object(fileobj)
    except OSError as exc:
        raise Rejected(str(exc)[:240])
    try:
        def describe(e):
            is_dir = e.has_directory_entries_index()
            streams = {}
            for i in range(e.number_of_alternate_data_streams):
                s = e.get_alternate_data_stream(i)
                streams[s.name] = (s.size, _digest(
                    _reader(s), s.size, hash_bytes))
            return (e.name, "dir" if is_dir else "file", e.size,
                    _reader(e), streams,
                    list(e.sub_file_entries) if is_dir else None)
        root = volume.get_root_directory()
        return _walk(root, hash_bytes, describe)
    finally:
        volume.close()


@reference("fs", ("hfsplus",), "libfshfs", modules=("pyfshfs",),
           hint="pip install libfshfs-python")
def _libfshfs(fileobj, hash_bytes):
    import pyfshfs
    volume = pyfshfs.volume()
    try:
        volume.open_file_object(fileobj)
    except OSError as exc:
        raise Rejected(str(exc)[:240])
    try:
        def describe(e):
            kind = _posix_kind(e)
            streams = {}
            if kind == "file" and e.has_resource_fork():
                fork = e.get_resource_fork()
                streams["rsrc"] = (fork.size, _digest(
                    _reader(fork), fork.size, hash_bytes))
            return (e.name, kind, e.size, _reader(e), streams,
                    list(e.sub_file_entries) if kind == "dir" else None)
        return _walk(volume.root_directory, hash_bytes, describe)
    finally:
        volume.close()


@reference("fs", ("ext",), "libfsext", modules=("pyfsext",),
           hint="pip install libfsext-python")
def _libfsext(fileobj, hash_bytes):
    import pyfsext
    volume = pyfsext.volume()
    try:
        volume.open_file_object(fileobj)
    except OSError as exc:
        raise Rejected(str(exc)[:240])
    try:
        def describe(e):
            kind = _posix_kind(e)
            return (e.name, kind, e.size, _reader(e), {},
                    list(e.sub_file_entries) if kind == "dir" else None)
        try:
            return _walk(volume.root_directory, hash_bytes, describe)
        except OSError as exc:
            raise Rejected(str(exc)[:240])
    finally:
        volume.close()


@reference("fs", ("fat",), "libfsfat", modules=("pyfsfat",),
           hint="pip install libfsfat-python")
def _libfsfat(fileobj, hash_bytes):
    import pyfsfat
    volume = pyfsfat.volume()
    try:
        volume.open_file_object(fileobj)
    except OSError as exc:
        raise Rejected(str(exc)[:240])
    try:
        def describe(e):
            flags = e.file_attribute_flags      # none for the root
            is_dir = flags is None or bool(flags & 0x10)
            return (e.name, "dir" if is_dir else "file", e.size,
                    _reader(e), {},
                    list(e.sub_file_entries) if is_dir else None)
        return _walk(volume.root_directory, hash_bytes, describe)
    finally:
        volume.close()
