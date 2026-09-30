import struct
import uuid

from .text import t as _t
from .volume import MBR_TYPES, GPT_GUIDS

SECTOR = 512

_INT_KINDS = {
    "u8": (1, False), "u16": (2, False), "u32": (4, False), "u64": (8, False),
    "i8": (1, True), "i16": (2, True), "i32": (4, True), "i64": (8, True),
}

def _hexdump(raw, limit=16):
    s = " ".join("%02X" % b for b in raw[:limit])
    return s + (" …" if len(raw) > limit else "")

def _decode(kind, raw):
    if kind in _INT_KINDS:
        _, signed = _INT_KINDS[kind]
        return int.from_bytes(raw, "little", signed=signed)
    if kind == "hex":
        return "0x" + raw[::-1].hex().upper() if len(raw) > 1 else \
               "0x%02X" % (raw[0] if raw else 0)
    if kind == "sig":
        return "0x" + raw.hex().upper()
    if kind == "ascii":
        return raw.decode("ascii", "replace").rstrip("\x00 ") or "—"
    if kind == "utf16":
        return raw.decode("utf-16-le", "replace").split("\x00")[0] or "—"
    if kind == "guid":
        try:
            return str(uuid.UUID(bytes_le=raw))
        except ValueError:
            return _hexdump(raw)
    if kind == "bytes":
        return _hexdump(raw)
    return _hexdump(raw)

def apply(template, data, base, struct_off=0):
    out = []
    for off, size, name, kind, note in template:
        s = struct_off + off
        raw = data[s:s + size]
        if len(raw) < size:
            continue
        out.append({
            "name": name,
            "offset": base + s,
            "size": size,
            "kind": kind,
            "value": _decode(kind, raw),
            "raw": _hexdump(raw, 24),
            "note": note,
        })
    return out

# -- Templates written by an examiner ---------------------------------------
#
# A template is data, not code: a name and rows of (offset, size, name, kind,
# note) that apply() reads, exactly as the built-in ones above. Everything an
# examiner types is checked here, once, so what is stored in a case and what
# is applied to bytes is always a well-formed template of bounded size.

TEMPLATE_KINDS = tuple(_INT_KINDS) + ("hex", "sig", "ascii", "utf16",
                                      "guid", "bytes")
MAX_TEMPLATE_FIELDS = 512
MAX_FIELD_SIZE = 4096
MAX_TEMPLATE_EXTENT = 1 << 16     # bytes a preview reads to apply one
MAX_FIELD_OFFSET = 1 << 24
MAX_NAME = 80
MAX_NOTE = 200
MAX_DESCRIPTION = 500


def _bad(key, *args):
    raise ValueError(_t(key) % args if args else _t(key))


def _text(v, limit, key_missing=None, key_long=None):
    if v is None:
        v = ""
    if not isinstance(v, str):
        _bad("template.not_text")
    v = v.strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in v):
        _bad("template.control_chars")
    if not v and key_missing:
        _bad(key_missing)
    if len(v) > limit:
        _bad(key_long, limit)
    return v


def _whole(v, what):
    if isinstance(v, bool) or not isinstance(v, int):
        _bad("template.not_whole_number", what)
    return v


def validate_template(t):
    """A template as the editor sends it, checked and normalised:
    {"name", "description", "fields": [{"offset", "size", "name", "kind",
    "note"}]}. Raises ValueError with a message an examiner can act on."""
    if not isinstance(t, dict):
        _bad("template.not_object")
    name = _text(t.get("name"), MAX_NAME, "template.name_missing",
                 "template.name_long")
    desc = _text(t.get("description"), MAX_DESCRIPTION,
                 key_long="template.description_long")
    fields = t.get("fields")
    if not isinstance(fields, list) or not fields:
        _bad("template.no_fields")
    if len(fields) > MAX_TEMPLATE_FIELDS:
        _bad("template.too_many_fields", MAX_TEMPLATE_FIELDS)
    out = []
    for n, f in enumerate(fields, 1):
        if not isinstance(f, dict):
            _bad("template.not_object")
        fname = _text(f.get("name"), MAX_NAME, None, "template.field_name_long")
        if not fname:
            _bad("template.field_name_missing", n)
        kind = f.get("kind")
        if kind not in TEMPLATE_KINDS:
            _bad("template.kind_unknown", n, fname, kind)
        off = _whole(f.get("offset"), "offset (field %d)" % n)
        size = _whole(f.get("size"), "size (field %d)" % n)
        if not 0 <= off <= MAX_FIELD_OFFSET:
            _bad("template.offset_range", n, fname, MAX_FIELD_OFFSET)
        if not 1 <= size <= MAX_FIELD_SIZE:
            _bad("template.size_range", n, fname, MAX_FIELD_SIZE)
        want = _INT_KINDS[kind][0] if kind in _INT_KINDS else (
            16 if kind == "guid" else None)
        if want is not None and size != want:
            _bad("template.size_for_kind", n, fname, kind, want)
        if kind == "hex" and size > 32:
            _bad("template.size_range", n, fname, 32)
        if off + size > MAX_TEMPLATE_EXTENT:
            _bad("template.extent", n, fname, MAX_TEMPLATE_EXTENT)
        note = _text(f.get("note"), MAX_NOTE, None, "template.note_long")
        out.append({"offset": off, "size": size, "name": fname,
                    "kind": kind, "note": note})
    return {"name": name, "description": desc, "fields": out}


def template_rows(t):
    """The (offset, size, name, kind, note) rows apply() takes."""
    return [(f["offset"], f["size"], f["name"], f["kind"], f["note"] or None)
            for f in t["fields"]]


def preview(t, data, base):
    """A validated template applied to `data`, which was read at image
    offset `base`. Fields that run past the end of the data are left out and
    counted, so a short read is not shown as a template that fits."""
    rows = template_rows(t)
    fields = apply(rows, data, base)
    return {"fields": fields, "skipped": len(rows) - len(fields),
            "extent": max(o + n for o, n, *_ in rows)}


MBR_ENTRY = [
    (0, 1, "Status", "hex", "0x80 = bootable, 0x00 = not"),
    (1, 3, "First sector (CHS)", "bytes", "legacy geometry, ignored by LBA"),
    (4, 1, "Partition type", "hex", None),
    (5, 3, "Last sector (CHS)", "bytes", None),
    (8, 4, "First sector (LBA)", "u32", "start, in sectors from the disk start"),
    (12, 4, "Sector count", "u32", None),
]

MBR = [
    (0, 440, "Bootstrap code", "bytes", None),
    (440, 4, "Disk signature", "hex", "Windows NT disk identifier"),
    (444, 2, "Reserved", "hex", None),
    (510, 2, "Boot signature", "sig", "must be 0x55AA"),
]

GPT_HEADER = [
    (0, 8, "Signature", "ascii", "must be 'EFI PART'"),
    (8, 4, "Revision", "hex", None),
    (12, 4, "Header size", "u32", "bytes, normally 92"),
    (16, 4, "Header CRC32", "hex", "computed with this field zeroed"),
    (20, 4, "Reserved", "u32", None),
    (24, 8, "Current LBA", "u64", "where this header lives"),
    (32, 8, "Backup LBA", "u64", "the mirror at the end of the disk"),
    (40, 8, "First usable LBA", "u64", None),
    (48, 8, "Last usable LBA", "u64", None),
    (56, 16, "Disk GUID", "guid", None),
    (72, 8, "Entry array LBA", "u64", "start of the partition entries"),
    (80, 4, "Number of entries", "u32", "normally 128"),
    (84, 4, "Entry size", "u32", "bytes per entry, normally 128"),
    (88, 4, "Entry array CRC32", "hex", None),
]

GPT_ENTRY = [
    (0, 16, "Type GUID", "guid", None),
    (16, 16, "Unique GUID", "guid", "identifies this partition, not its type"),
    (32, 8, "First LBA", "u64", None),
    (40, 8, "Last LBA", "u64", "inclusive"),
    (48, 8, "Attributes", "hex", "bit 0 required, bit 60 read-only, bit 63 no-automount"),
    (56, 72, "Name", "utf16", None),
]

NTFS_BOOT = [
    (0, 3, "Jump instruction", "bytes", None),
    (3, 8, "OEM name", "ascii", "'NTFS    ' identifies the volume"),
    (11, 2, "Bytes per sector", "u16", None),
    (13, 1, "Sectors per cluster", "u8", None),
    (14, 2, "Reserved sectors", "u16", "always 0 on NTFS"),
    (21, 1, "Media descriptor", "hex", None),
    (24, 2, "Sectors per track", "u16", None),
    (26, 2, "Heads", "u16", None),
    (28, 4, "Hidden sectors", "u32", "offset of this partition from the disk start"),
    (40, 8, "Total sectors", "u64", None),
    (48, 8, "$MFT cluster", "u64", "start of the master file table"),
    (56, 8, "$MFTMirr cluster", "u64", "the backup copy of the first MFT records"),
    (64, 1, "Clusters per MFT record", "i8", "negative means 2^-n bytes"),
    (68, 1, "Clusters per index buffer", "i8", None),
    (72, 8, "Volume serial", "hex", None),
    (80, 4, "Checksum", "hex", None),
    (510, 2, "Boot signature", "sig", "0x55AA"),
]

EXFAT_BOOT = [
    (0, 3, "Jump instruction", "bytes", None),
    (3, 8, "OEM name", "ascii", "'EXFAT   '"),
    (64, 8, "Partition offset", "u64", "sectors from the disk start"),
    (72, 8, "Volume length", "u64", "sectors"),
    (80, 4, "FAT offset", "u32", "sectors from the volume start"),
    (84, 4, "FAT length", "u32", "sectors"),
    (88, 4, "Cluster heap offset", "u32", "sectors"),
    (92, 4, "Cluster count", "u32", None),
    (96, 4, "Root directory cluster", "u32", None),
    (100, 4, "Volume serial", "hex", None),
    (104, 2, "Filesystem revision", "hex", None),
    (106, 2, "Volume flags", "hex", "bit 1 set means the volume is dirty"),
    (108, 1, "Bytes per sector (shift)", "u8", "as a power of two"),
    (109, 1, "Sectors per cluster (shift)", "u8", "as a power of two"),
    (110, 1, "Number of FATs", "u8", None),
    (111, 1, "Drive select", "hex", None),
    (112, 1, "Percent in use", "u8", "0xFF means unknown"),
    (510, 2, "Boot signature", "sig", "0x55AA"),
]

FAT_BOOT = [
    (0, 3, "Jump instruction", "bytes", None),
    (3, 8, "OEM name", "ascii", "written by the formatting tool, not a type field"),
    (11, 2, "Bytes per sector", "u16", None),
    (13, 1, "Sectors per cluster", "u8", None),
    (14, 2, "Reserved sectors", "u16", "includes the boot sector itself"),
    (16, 1, "Number of FATs", "u8", "normally 2"),
    (17, 2, "Root directory entries", "u16", "0 on FAT32"),
    (19, 2, "Total sectors (16-bit)", "u16", "0 when the 32-bit field is used"),
    (21, 1, "Media descriptor", "hex", None),
    (22, 2, "Sectors per FAT (16-bit)", "u16", "0 on FAT32"),
    (24, 2, "Sectors per track", "u16", None),
    (26, 2, "Heads", "u16", None),
    (28, 4, "Hidden sectors", "u32", None),
    (32, 4, "Total sectors (32-bit)", "u32", None),
    (510, 2, "Boot signature", "sig", "0x55AA"),
]

FAT32_EXT = [
    (36, 4, "Sectors per FAT (32-bit)", "u32", None),
    (40, 2, "Flags", "hex", None),
    (42, 2, "Version", "hex", None),
    (44, 4, "Root directory cluster", "u32", "usually 2"),
    (48, 2, "FSInfo sector", "u16", None),
    (50, 2, "Backup boot sector", "u16", "usually 6"),
    (64, 1, "Drive number", "hex", None),
    (66, 1, "Extended boot signature", "hex", "0x29 means the next three fields are present"),
    (67, 4, "Volume serial", "hex", None),
    (71, 11, "Volume label", "ascii", None),
    (82, 8, "Filesystem type", "ascii", "a label, not authoritative"),
]

FAT16_EXT = [
    (36, 1, "Drive number", "hex", None),
    (38, 1, "Extended boot signature", "hex", "0x29"),
    (39, 4, "Volume serial", "hex", None),
    (43, 11, "Volume label", "ascii", None),
    (54, 8, "Filesystem type", "ascii", "a label, not authoritative"),
]

EXT4_SB = [
    (0, 4, "Inode count", "u32", None),
    (4, 4, "Block count (low)", "u32", None),
    (8, 4, "Reserved blocks (low)", "u32", None),
    (12, 4, "Free blocks (low)", "u32", None),
    (16, 4, "Free inodes", "u32", None),
    (20, 4, "First data block", "u32", "1 when the block size is 1 KiB, else 0"),
    (24, 4, "Block size (shift)", "u32", "block size = 1024 << this"),
    (32, 4, "Blocks per group", "u32", None),
    (40, 4, "Inodes per group", "u32", None),
    (44, 4, "Last mount time", "u32", "Unix seconds"),
    (48, 4, "Last write time", "u32", "Unix seconds"),
    (52, 2, "Mount count", "u16", None),
    (56, 2, "Magic", "hex", "0xEF53"),
    (58, 2, "State", "u16", "1 = cleanly unmounted, 2 = errors detected"),
    (64, 4, "Last check time", "u32", "Unix seconds"),
    (76, 4, "Revision level", "u32", None),
    (88, 2, "Inode size", "u16", None),
    (92, 4, "Compatible features", "hex", None),
    (96, 4, "Incompatible features", "hex", "a reader must understand every bit here"),
    (100, 4, "Read-only compat features", "hex", None),
    (104, 16, "Filesystem UUID", "guid", None),
    (120, 16, "Volume name", "ascii", None),
    (136, 64, "Last mounted on", "ascii", None),
]

APFS_NX = [
    (0, 8, "Checksum (Fletcher-64)", "hex", "over the rest of the block"),
    (8, 8, "Object ID", "u64", None),
    (16, 8, "Transaction ID", "u64", "the xid; the newest valid one wins"),
    (24, 2, "Object type", "hex", None),
    (26, 2, "Object subtype", "hex", None),
    (32, 4, "Magic", "ascii", "'NXSB'"),
    (36, 4, "Block size", "u32", "bytes"),
    (40, 8, "Block count", "u64", None),
    (48, 8, "Features", "hex", None),
    (56, 8, "Read-only compatible features", "hex", None),
    (64, 8, "Incompatible features", "hex", None),
    (72, 16, "Container UUID", "guid", None),
    (88, 8, "Next object ID", "u64", None),
    (96, 8, "Next transaction ID", "u64", None),
    (104, 4, "Checkpoint descriptor blocks", "u32", None),
    (108, 4, "Checkpoint data blocks", "u32", None),
    (112, 8, "Checkpoint descriptor base", "u64", None),
]

MFT_RECORD = [
    (0, 4, "Signature", "ascii", "'FILE', or 'BAAD' if the fixups failed"),
    (4, 2, "Update sequence offset", "u16", None),
    (6, 2, "Update sequence size", "u16", "in 2-byte entries, including the number itself"),
    (8, 8, "$LogFile sequence number", "u64", None),
    (16, 2, "Sequence number", "u16", "incremented each time the record is reused"),
    (18, 2, "Hard link count", "u16", None),
    (20, 2, "First attribute offset", "u16", None),
    (22, 2, "Flags", "hex", "bit 0 = in use, bit 1 = directory"),
    (24, 4, "Used size", "u32", "bytes of this record actually in use"),
    (28, 4, "Allocated size", "u32", "normally 1024"),
    (32, 8, "Base record reference", "u64", "non-zero on an extension record"),
    (40, 2, "Next attribute id", "u16", None),
]

def _label(fields, field_name, fn):
    for f in fields:
        if f["name"] == field_name:
            try:
                f["meaning"] = fn(f["value"])
            except (TypeError, ValueError):
                pass
    return fields

def _mbr(source):
    data = source.read_at(0, SECTOR)
    if len(data) < SECTOR or data[510:512] != b"\x55\xaa":
        return []
    out = [{
        "name": "Master Boot Record", "offset": 0, "size": SECTOR,
        "kind": "mbr", "fields": apply(MBR, data, 0),
    }]
    for i in range(4):
        off = 446 + i * 16
        if not any(data[off:off + 16]):
            continue
        fields = _label(apply(MBR_ENTRY, data, 0, off), "Partition type",
                        lambda v: MBR_TYPES.get(int(str(v), 16), "Unknown type"))
        out.append({
            "name": "MBR partition entry %d" % (i + 1),
            "offset": off, "size": 16, "kind": "mbr_entry", "fields": fields,
        })
    return out

def _gpt(source):
    hdr = source.read_at(SECTOR, SECTOR)
    if hdr[:8] != b"EFI PART":
        return []
    out = [{
        "name": "GPT header", "offset": SECTOR, "size": 92,
        "kind": "gpt_header", "fields": apply(GPT_HEADER, hdr, SECTOR),
    }]
    entry_lba, = struct.unpack("<Q", hdr[72:80])
    n_entries, = struct.unpack("<I", hdr[80:84])
    entry_size, = struct.unpack("<I", hdr[84:88])
    if not (0 < entry_size <= 4096) or not (0 < n_entries <= 4096):
        return out
    base = entry_lba * SECTOR
    blob = source.read_at(base, min(n_entries * entry_size, 1 << 20))
    for i in range(n_entries):
        off = i * entry_size
        chunk = blob[off:off + entry_size]
        if len(chunk) < 128 or not any(chunk[:16]):
            continue
        fields = _label(apply(GPT_ENTRY, blob, base, off), "Type GUID",
                        lambda v: GPT_GUIDS.get(str(v).lower(), "Unknown GUID"))
        out.append({
            "name": "GPT partition entry %d" % (i + 1),
            "offset": base + off, "size": entry_size,
            "kind": "gpt_entry", "fields": fields,
        })
    return out

def _volume_boot(source, part):
    base = part["offset"]
    kind = (part.get("detected") or "").upper()
    head = source.read_at(base, SECTOR)
    if len(head) < SECTOR:
        return []

    if kind.startswith("NTFS"):
        return [{"name": "NTFS $Boot", "offset": base, "size": SECTOR,
                 "kind": "ntfs_boot", "fields": apply(NTFS_BOOT, head, base)}]
    if kind.startswith("EXFAT"):
        return [{"name": "exFAT boot sector", "offset": base, "size": SECTOR,
                 "kind": "exfat_boot", "fields": apply(EXFAT_BOOT, head, base)}]
    if kind.startswith("FAT"):
        fields = apply(FAT_BOOT, head, base)
        ext = FAT32_EXT if kind.startswith("FAT32") else FAT16_EXT
        fields += apply(ext, head, base)
        fields.sort(key=lambda f: f["offset"])
        return [{"name": "%s boot sector" % (kind or "FAT"), "offset": base,
                 "size": SECTOR, "kind": "fat_boot", "fields": fields}]
    if kind.startswith("APFS"):
        blk = source.read_at(base, 4096)
        return [{"name": "APFS container superblock", "offset": base,
                 "size": 120, "kind": "apfs_nx",
                 "fields": apply(APFS_NX, blk, base)}]
    if kind.startswith("EXT"):
        sb = source.read_at(base + 1024, 1024)
        if sb[56:58] == b"\x53\xef":
            return [{"name": "%s superblock" % kind, "offset": base + 1024,
                     "size": 200, "kind": "ext_sb",
                     "fields": apply(EXT4_SB, sb, base + 1024)}]
    return []

def map_image(source, volumes):
    out = []
    out += _mbr(source)
    out += _gpt(source)
    for p in (volumes or {}).get("partitions", []):
        if p.get("allocated") is False:
            continue
        try:
            out += _volume_boot(source, p)
        except Exception:
            continue
    out.sort(key=lambda s: s["offset"])
    return out

def mft_record(source, offset):
    data = source.read_at(offset, 1024)
    if data[:4] not in (b"FILE", b"BAAD"):
        return None
    return {"name": "MFT record", "offset": offset, "size": 1024,
            "kind": "mft_record", "fields": apply(MFT_RECORD, data, offset)}
