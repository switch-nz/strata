import binascii
import struct
import uuid
from . import entropy as entropy_mod

MBR_TYPES = {
    0x00: "Empty", 0x01: "FAT12", 0x04: "FAT16 <32M", 0x05: "Extended",
    0x06: "FAT16", 0x07: "NTFS / exFAT / HPFS", 0x0B: "FAT32 CHS",
    0x0C: "FAT32 LBA", 0x0E: "FAT16 LBA", 0x0F: "Extended LBA",
    0x11: "Hidden FAT12", 0x82: "Linux swap", 0x83: "Linux",
    0x8E: "Linux LVM", 0xA5: "FreeBSD", 0xA8: "Apple UFS",
    0xAF: "Apple HFS/HFS+", 0xEE: "GPT protective", 0xEF: "EFI System",
    0xFD: "Linux RAID",
}

GPT_GUIDS = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft Basic Data",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows Recovery",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
    "53746f72-6167-11aa-aa11-00306543ecac": "Apple Core Storage",
    "21686148-6449-6e6f-744e-656564454649": "BIOS boot",
}

GENERIC_TYPES = {
    "Microsoft Basic Data", "Linux filesystem", "Apple HFS/HFS+",
    "Unknown GUID", "Empty",
}

VBR_SIGS = [
    (3, b"NTFS    ", "NTFS"),
    (3, b"EXFAT   ", "exFAT"),
    (3, b"-FVE-FS-", "BitLocker"),
    (0, b"LUKS\xba\xbe", "LUKS"),
    (32, b"NXSB", "APFS"),
    (54, b"FAT12   ", "FAT12"),
    (54, b"FAT16   ", "FAT16"),
    (82, b"FAT32   ", "FAT32"),
    (3, b"MSDOS5.0", "FAT (unspecified width)"),
]

def _guid_le(b):
    return str(uuid.UUID(bytes_le=b))

BOOTABLE_UNKNOWN = "Unknown (bootable)"

def _clean_label(text):
    if not text:
        return None
    text = text.replace("\x00", "").strip()
    if not text or text.upper() in ("NO NAME", "NONAME"):
        return None
    if any(ord(c) < 32 for c in text):
        return None
    return text

def _ntfs_label(source, offset):
    boot = source.read_at(offset, 512)
    if len(boot) < 512 or boot[3:7] != b"NTFS":
        return None
    bps = struct.unpack("<H", boot[0x0B:0x0D])[0]
    spc = boot[0x0D]
    if not bps or not spc:
        return None
    cluster = bps * spc
    mft_lcn = struct.unpack("<Q", boot[0x30:0x38])[0]
    raw = struct.unpack("<b", boot[0x40:0x41])[0]
    rec_size = raw * cluster if raw > 0 else 1 << -raw
    if not (0 < rec_size <= (1 << 20)):
        return None

    rec = source.read_at(offset + mft_lcn * cluster + 3 * rec_size, rec_size)
    if len(rec) < 56 or rec[:4] != b"FILE":
        return None

    rec = bytearray(rec)
    usa_off, usa_count = struct.unpack("<HH", rec[4:8])
    if usa_off and usa_count:
        usa = rec[usa_off:usa_off + usa_count * 2]
        for i in range(1, usa_count):
            end = i * bps
            if end > len(rec) or (i * 2 + 2) > len(usa):
                break
            rec[end - 2:end] = usa[i * 2:i * 2 + 2]

    pos = struct.unpack("<H", rec[0x14:0x16])[0]
    while 0 < pos < len(rec) - 8:
        type_id, length = struct.unpack("<II", rec[pos:pos + 8])
        if type_id == 0xFFFFFFFF or length == 0:
            break
        if type_id == 0x60 and rec[pos + 8] == 0:
            clen, coff = struct.unpack("<IH", rec[pos + 0x10:pos + 0x16])
            body = bytes(rec[pos + coff:pos + coff + clen])
            return _clean_label(body.decode("utf-16-le", "replace"))
        pos += length
    return None

def _ext_label(source, offset):
    sb = source.read_at(offset + 1024, 256)
    if len(sb) < 136 or sb[56:58] != b"\x53\xEF":
        return None
    return _clean_label(sb[120:136].decode("utf-8", "replace"))

def _exfat_label(source, offset):
    boot = source.read_at(offset, 512)
    if len(boot) < 512 or boot[3:11] != b"EXFAT   ":
        return None
    heap_start = struct.unpack("<I", boot[0x58:0x5C])[0]
    root_cluster = struct.unpack("<I", boot[0x60:0x64])[0]
    bps_shift, spc_shift = boot[0x6C], boot[0x6D]
    if bps_shift > 12 or spc_shift > 25 or root_cluster < 2:
        return None
    bps = 1 << bps_shift
    cluster = bps << spc_shift
    root = offset + heap_start * bps + (root_cluster - 2) * cluster
    data = source.read_at(root, min(cluster, 1 << 16))
    for i in range(0, len(data) - 32, 32):
        e = data[i:i + 32]
        if e[0] == 0x00:
            break
        if e[0] == 0x83:
            n = min(e[1], 11)
            return _clean_label(e[2:2 + n * 2].decode("utf-16-le", "replace"))
        if e[0] == 0x03:
            return None
    return None

def _fat_label(source, offset):
    boot = source.read_at(offset, 512)
    if len(boot) < 512:
        return None
    if boot[0x52:0x5A] == b"FAT32   ":
        return _clean_label(boot[0x47:0x52].decode("latin-1"))
    if boot[0x36:0x3B] in (b"FAT12", b"FAT16", b"FAT  "):
        return _clean_label(boot[0x2B:0x36].decode("latin-1"))
    return None

def volume_label(source, offset, detected):
    if not detected:
        return None
    fs = detected.upper()
    try:
        if fs.startswith("NTFS"):
            return _ntfs_label(source, offset)
        if fs.startswith("EXT"):
            return _ext_label(source, offset)
        if fs.startswith("EXFAT"):
            return _exfat_label(source, offset)
        if fs.startswith("FAT"):
            return _fat_label(source, offset)
    except Exception:
        return None
    return None

def identify_fs(source, offset):
    got = probe_vbr(source, offset)
    return None if got == BOOTABLE_UNKNOWN else got

def probe_vbr(source, offset):
    d = source.read_at(offset, 512)
    if len(d) < 512:
        return None
    for at, sig, name in VBR_SIGS:
        if d[at:at + len(sig)] == sig:
            return name
    if d[0x438:0x43A] == b"\x53\xEF" or source.read_at(offset + 1024 + 56, 2) == b"\x53\xEF":
        sb = source.read_at(offset + 1024, 1024)
        if len(sb) >= 100:
            incompat = struct.unpack("<I", sb[96:100])[0]
            compat = struct.unpack("<I", sb[92:96])[0]
            if incompat & 0x40:
                return "ext4"
            return "ext3" if compat & 0x04 else "ext2"
        return "ext2/3/4"
    if source.read_at(offset + 32, 4) == b"NXSB":
        return "APFS"
    hfs = source.read_at(offset + 1024, 2)
    if hfs == b"H+":
        return "HFS+"
    if hfs == b"HX":
        return "HFSX"
    if d[510:512] == b"\x55\xAA":
        return BOOTABLE_UNKNOWN
    return None

def _absent_fs_note(source, part):
    try:
        head = source.read_at(part["offset"], 65536)
    except Exception:
        return None
    if not head:
        return None
    if not any(head):
        return ("The table declares %s but the region is entirely zeroed — "
                "wiped, or allocated and never written." % part["type"])
    ent = entropy_mod.of(head)
    if ent > 7.5:
        return ("The table declares %s but no filesystem is present and the "
                "content is statistically random (%.2f bits/byte). That is "
                "what encryption or a secure wipe looks like; it is not an "
                "unreadable filesystem." % (part["type"], ent))
    return ("The table declares %s but no recognised filesystem starts here. "
            "The declared type may be stale, or the volume header damaged."
            % part["type"])

def parse_mbr(source, sector_size=512):
    d = source.read_at(0, 512)
    if len(d) < 512 or d[510:512] != b"\x55\xAA":
        return None, []
    parts = []
    protective = False
    for i in range(4):
        e = d[446 + i * 16: 446 + (i + 1) * 16]
        ptype = e[4]
        start = struct.unpack("<I", e[8:12])[0]
        count = struct.unpack("<I", e[12:16])[0]
        if ptype == 0xEE:
            protective = True
        if ptype == 0 or count == 0:
            continue
        if start * sector_size >= source.size or \
                (start + count) * sector_size > source.size * 2:
            continue
        parts.append({
            "scheme": "MBR", "index": i, "slot": "MBR %d" % (i + 1),
            "type_id": "0x%02X" % ptype,
            "type": MBR_TYPES.get(ptype, "Unknown (0x%02X)" % ptype),
            "bootable": bool(e[0] & 0x80),
            "start_sector": start, "sector_count": count,
            "offset": start * sector_size, "size": count * sector_size,
        })
    return ("GPT protective" if protective else "MBR"), parts

def _gpt_header(source, lba, sector_size):
    findings = []
    hdr = source.read_at(lba * sector_size, 512)
    if len(hdr) < 92 or hdr[0:8] != b"EFI PART":
        return None, findings

    size, = struct.unpack_from("<I", hdr, 12)
    if not 92 <= size <= 512:
        findings.append("The GPT header at LBA %d declares a size of %d "
                        "bytes, which is outside the specification."
                        % (lba, size))
        return None, findings

    stored = struct.unpack_from("<I", hdr, 16)[0]
    check = bytearray(hdr[:size])
    check[16:20] = bytes(4)
    actual = binascii.crc32(bytes(check)) & 0xFFFFFFFF
    if stored != actual:
        findings.append(
            "The GPT header at LBA %d fails its own checksum (stored "
            "0x%08X, computed 0x%08X), so it has been altered or damaged."
            % (lba, stored, actual))
        return None, findings

    f = {
        "lba": lba,
        "this_lba": struct.unpack_from("<Q", hdr, 24)[0],
        "alt_lba": struct.unpack_from("<Q", hdr, 32)[0],
        "disk_guid": _guid_le(hdr[56:72]),
        "entry_lba": struct.unpack_from("<Q", hdr, 72)[0],
        "n_entries": struct.unpack_from("<I", hdr, 80)[0],
        "entry_size": struct.unpack_from("<I", hdr, 84)[0],
        "array_crc": struct.unpack_from("<I", hdr, 88)[0],
    }
    if f["n_entries"] > 512 or not 128 <= f["entry_size"] <= 1024:
        findings.append(
            "The GPT header at LBA %d describes %d entries of %d bytes, "
            "which is not a layout this reads."
            % (lba, f["n_entries"], f["entry_size"]))
        return None, findings
    return f, findings

def _gpt_entries(source, f, sector_size):
    findings = []
    span = f["n_entries"] * f["entry_size"]
    blob = source.read_at(f["entry_lba"] * sector_size, span)
    if len(blob) < span:
        findings.append(
            "The partition array at LBA %d runs past the end of the image; "
            "%d of %d bytes are present."
            % (f["entry_lba"], len(blob), span))
        return None, findings
    actual = binascii.crc32(blob) & 0xFFFFFFFF
    if actual != f["array_crc"]:
        findings.append(
            "The partition array referenced by the header at LBA %d fails "
            "its checksum (stored 0x%08X, computed 0x%08X). Entries read "
            "from it cannot be relied on: one altered byte changes a name, "
            "a type or an offset with nothing else to show for it."
            % (f["lba"], f["array_crc"], actual))
        return None, findings
    return blob, findings

def _gpt_partitions(blob, f, sector_size):
    parts = []
    for i in range(f["n_entries"]):
        e = blob[i * f["entry_size"]:(i + 1) * f["entry_size"]]
        if len(e) < 128 or not any(e[0:16]):
            continue
        tguid = _guid_le(e[0:16])
        first, last = struct.unpack("<QQ", e[32:48])
        name = e[56:128].decode("utf-16-le", "replace").split("\x00")[0]
        parts.append({
            "scheme": "GPT", "index": i, "slot": "GPT %d" % (i + 1),
            "type_id": tguid, "type": GPT_GUIDS.get(tguid, "Unknown GUID"),
            "name": name, "guid": _guid_le(e[16:32]),
            "start_sector": first, "sector_count": last - first + 1,
            "offset": first * sector_size,
            "size": (last - first + 1) * sector_size,
        })
    return parts

def parse_gpt(source, sector_size=512):
    findings = []
    used = None
    blob = None

    primary, notes = _gpt_header(source, 1, sector_size)
    findings.extend(notes)
    if primary is not None:
        blob, notes = _gpt_entries(source, primary, sector_size)
        findings.extend(notes)
        if blob is not None:
            used = primary

    if used is None:
        alt = primary["alt_lba"] if primary else (
            (getattr(source, "size", 0) // sector_size) - 1)
        if alt > 1:
            backup, notes = _gpt_header(source, alt, sector_size)
            findings.extend(notes)
            if backup is not None:
                blob, notes = _gpt_entries(source, backup, sector_size)
                findings.extend(notes)
                if blob is not None:
                    used = backup
                    findings.append(
                        "The primary GPT could not be used, so the layout "
                        "was recovered from the backup table at LBA %d. The "
                        "backup is as authoritative as the primary — a GPT "
                        "disk carries it for exactly this reason — but the "
                        "damage at the front of the disk is itself a "
                        "finding." % alt)

    if used is None or blob is None:
        if findings:
            findings.append(
                "Neither the primary nor the backup GPT could be read, so no "
                "partition layout was recovered from either.")
        return None, [], findings

    parts = _gpt_partitions(blob, used, sector_size)

    if used is primary:
        alt = primary["alt_lba"]
        if alt > 1:
            backup, _n = _gpt_header(source, alt, sector_size)
            if backup is None:
                findings.append(
                    "The primary GPT is sound but the backup table at LBA %d "
                    "is missing or damaged. The layout is reliable; the state "
                    "of the backup is not." % alt)
            elif backup["array_crc"] != primary["array_crc"]:
                findings.append(
                    "The primary and backup GPTs describe different partition "
                    "arrays. One was updated and the other was not, so the "
                    "layout changed after the copy that was left behind.")
    return "GPT", parts, findings

def scan(source):
    ss = getattr(source, "bytes_per_sector", 512) or 512

    if getattr(source, "logical", False):
        kind = getattr(source, "kind", "folder")
        return {
            "scheme": "None (logical evidence)",
            "findings": list(getattr(source, "findings", [])),
            "partitions": [{
                "scheme": "-", "slot": "Logical evidence",
                "type": {"folder": "Folder", "zip": "Zip archive",
                         "file": "Single file"}.get(kind, "Collection"),
                "detected": "Logical", "type_id": "-",
                "label": getattr(getattr(source, "tree", None), "label", None),
                "start_sector": 0, "sector_count": 0,
                "offset": 0, "size": source.size, "allocated": True,
                "logical": True,
            }],
        }

    if source.read_at(0, 16) == b"ADSEGMENTEDFILE\x00":
        return {
            "scheme": "None (logical image)",
            "findings": [
                "A logical image: a selection of files and their metadata, "
                "not a copy of media. There is no partition table, no "
                "unallocated space and no slack, so nothing here is carved "
                "and no file's position on the original disk is recoverable."
            ],
            "partitions": [{
                "scheme": "-", "slot": "Logical image", "type": "AD1",
                "detected": "AD1", "type_id": "-", "label": None,
                "start_sector": 0, "sector_count": source.size // ss,
                "offset": 0, "size": source.size, "allocated": True,
                "logical": True,
            }],
        }
    scheme, parts, gpt_findings = parse_gpt(source, ss)

    if not parts:
        at_zero = identify_fs(source, 0)
        if at_zero:
            return {"scheme": "None (unpartitioned)",
                    "findings": gpt_findings,
                    "partitions": [{
                        "scheme": "-", "slot": "Whole image", "type": at_zero,
                        "detected": at_zero, "type_id": "-",
                        "start_sector": 0, "sector_count": source.size // ss,
                        "offset": 0, "size": source.size, "allocated": True,
                        "label": volume_label(source, 0, at_zero),
                    }]}
        scheme, parts = parse_mbr(source, ss)
        if scheme == "GPT protective":
            gpt_findings.append(
                "This disk carries a protective MBR, which means it was "
                "written as a GPT disk, but no readable GPT was found at "
                "either the front or the back of the image. The single entry "
                "below is that placeholder — it exists so older tools do not "
                "treat the disk as empty — and is not the layout. The real "
                "layout has been destroyed or is outside this image.")

    if not parts:
        return {"scheme": "None (unpartitioned)",
                "findings": gpt_findings,
                "partitions": [{
                    "label": None,
                    "scheme": "-", "slot": "Whole image", "type":
                    probe_vbr(source, 0) or "Unknown", "type_id": "-",
                    "start_sector": 0, "sector_count": source.size // ss,
                    "offset": 0, "size": source.size, "allocated": True,
                }]}

    for p in parts:
        detected = identify_fs(source, p["offset"])
        p["detected"] = detected
        p["allocated"] = True
        p["label"] = volume_label(source, p["offset"], detected)
        if detected and detected not in p["type"] \
                and p["type"] not in GENERIC_TYPES:
            p["note"] = ("Boot record says %s; the partition table says %s. "
                         "The table is the easier of the two to falsify."
                         % (detected, p["type"]))
        elif not detected and p["type"] not in GENERIC_TYPES:
            p["note"] = _absent_fs_note(source, p)

    regions = sorted(parts, key=lambda p: p["offset"])
    out = []
    cursor = ss
    for p in regions:
        if p["offset"] > cursor + ss:
            out.append({
                "scheme": "-", "slot": "Gap", "type": "Unpartitioned",
                "label": None,
                "type_id": "-", "start_sector": cursor // ss,
                "sector_count": (p["offset"] - cursor) // ss,
                "offset": cursor, "size": p["offset"] - cursor,
                "allocated": False,
            })
        out.append(p)
        cursor = max(cursor, p["offset"] + p["size"])
    if source.size - cursor > ss:
        out.append({
            "scheme": "-", "slot": "Gap", "type": "Unpartitioned (trailing)",
            "label": None,
            "type_id": "-", "start_sector": cursor // ss,
            "sector_count": (source.size - cursor) // ss,
            "offset": cursor, "size": source.size - cursor, "allocated": False,
        })
    return {"scheme": scheme, "partitions": out,
            "findings": gpt_findings}


def identities(source, layout=None):
    """Volume identities for each detected filesystem in an image.

    Returns [{"part": <partition offset>, "key": "<scheme>:<id>"}] for every
    partition whose filesystem exposes a stable volume identifier.  Partitions
    without one (FAT, HFS+, logical folders) are omitted.
    """
    # Imported here rather than at module level: ewf and fs.ntfs are heavier
    # modules and volume.py is imported on nearly every code path.
    from .ewf import OffsetReader
    from .fs import ntfs

    layout = layout or scan(source)
    found = []
    for p in layout["partitions"]:
        if not p.get("detected"):
            continue
        if p.get("logical") and p.get("detected") == "Logical":
            continue
        try:
            src = OffsetReader(source, p["offset"], p["size"], p["slot"])
            info = ntfs.open_fs(src).info()
        except Exception:
            # Encrypted volumes, unsupported filesystems, damaged boot
            # records: identity extraction must never fail an acquire.
            continue
        kind = info.get("type")
        if kind == "NTFS":
            value = info.get("serial")
            key = "ntfs:" + value if value else None
        elif kind == "exFAT":
            value = info.get("serial")
            key = "exfat:" + value if value else None
        elif kind == "ext4":
            value = info.get("uuid")
            key = "ext4:" + value if value else None
        elif kind == "APFS":
            value = info.get("uuid")
            key = "apfs:" + value if value else None
        elif kind == "AD1":
            value = info.get("volume_serial")
            key = "ad1:" + value if value else None
        else:
            key = None
        if not key:
            continue
        found.append({"part": p["offset"], "key": key})
    return found
