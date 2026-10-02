"""What Strata reports, in the form crosscheck_lib compares.

Every function goes through the same engine entry points the application uses
(ewf.open_image, volume.scan, fs.open_fs, and the walker that search, hashing
and indexing share), not a private shortcut, so what is compared is what an
examiner would be shown."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crosscheck_lib as lib                                  # noqa: E402
from engine import ewf, filesearch, volume                    # noqa: E402
from engine.fs.ntfs import open_fs                            # noqa: E402

# The class name of the image object Strata made -> the format it read.
FORMATS = {
    "EwfImage": "ewf", "RawImage": "raw", "VhdImage": "vhd",
    "VhdxImage": "vhdx", "VmdkImage": "vmdk", "Qcow2Image": "qcow2",
    "VdiImage": "vdi", "DmgImage": "dmg", "Aff4Image": "aff4",
    "Ad1Image": "ad1", "RaidImage": "raid", "LogicalImage": "logical",
}

# fs.name -> the key references are registered under
FS_KINDS = (("NTFS", "ntfs"), ("EXFAT", "exfat"), ("EXT", "ext"),
            ("HFS", "hfsplus"), ("APFS", "apfs"), ("FAT", "fat"))


def image_format(img):
    return FORMATS.get(type(img).__name__, type(img).__name__.lower())


def fs_kind(fs):
    name = (getattr(fs, "name", "") or "").upper()
    for prefix, kind in FS_KINDS:
        if name.startswith(prefix):
            return kind
    return None


def open_image(path):
    return ewf.open_image(path)


def container(img, plan, chunk=lib.CHUNK):
    return lib.disk_observation(img.read_at, img.size, plan, chunk)


def partitions(img):
    """The GPT partitions Strata found, one dict each, with what a
    reference partition reader also reports."""
    layout = volume.scan(img)
    out = []
    for p in layout["partitions"]:
        if p.get("allocated") is False or p.get("scheme") != "GPT":
            continue
        out.append({"index": p["index"], "offset": p["offset"],
                    "size": p["size"], "type": p["type_id"],
                    "identifier": p.get("guid")})
    return layout, out


def open_partition(img, offset, size):
    return open_fs(ewf.OffsetReader(img, offset, size))


def _read(fs, entry, limit, stream=""):
    try:
        data = fs.read_file(entry, limit, stream=stream) if stream \
            else fs.read_file(entry, limit)
    except Exception as exc:                       # noqa: BLE001
        return "error:" + type(exc).__name__
    return lib.sha(data or b"")


def tree(fs, hash_bytes, budget=500000):
    """Every live file and folder, as the shared walker finds them."""
    root = getattr(fs, "root_node", 0)
    entries = filesearch.collect(fs, root, budget=budget)
    skipped = []                       # a deleted folder's contents are too
    out = []
    for e in entries:
        path = e.get("path") or ""
        if e.get("deleted") or any(path.startswith(s + "/") for s in skipped):
            if e.get("is_dir"):
                skipped.append(path)
            continue
        if e.get("is_dir"):
            out.append(lib.entry_observation(path, "dir"))
            continue
        size = e.get("size") or 0
        streams = {}
        if hasattr(fs, "streams"):
            try:
                for s in fs.streams(e):
                    if not s.get("default"):
                        streams[s["name"]] = (
                            s["size"], _read(fs, e, hash_bytes, s["name"]))
            except Exception:                      # noqa: BLE001
                pass
        if e.get("resource_size"):
            streams["rsrc"] = (e["resource_size"],
                               _read(fs, e, hash_bytes, "rsrc"))
        out.append(lib.entry_observation(
            path, "file", size, _read(fs, e, min(size, hash_bytes))
            if size else lib.sha(b""), streams))
    return out
