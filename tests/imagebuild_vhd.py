"""Build synthetic VHD files (fixed, dynamic, differencing) in memory.

Layouts follow the Virtual Hard Disk Image Format Specification: a
512-byte footer at the end (and, for dynamic and differencing disks, a
copy at the start), a 1024-byte "cxsparse" header, a block allocation
table of big-endian sector offsets, and blocks each preceded by a sector
bitmap (most significant bit first; a set bit means the sector is held in
this file)."""

import struct
import uuid

FIXED, DYNAMIC, DIFFERENCING = 2, 3, 4
SECTOR = 512
UNUSED = 0xFFFFFFFF


def _checksum(buf, skip_at):
    total = sum(buf[:skip_at]) + sum(buf[skip_at + 4:])
    return (~total) & 0xFFFFFFFF


def footer(disk_type, size, unique_id, data_offset=0xFFFFFFFFFFFFFFFF):
    f = bytearray(512)
    f[0:8] = b"conectix"
    struct.pack_into(">II", f, 8, 2, 0x00010000)
    struct.pack_into(">Q", f, 16, data_offset)
    f[28:32] = b"stra"
    struct.pack_into(">I", f, 32, 0x00010000)
    f[36:40] = b"Wi2k"
    struct.pack_into(">QQ", f, 40, size, size)
    struct.pack_into(">I", f, 60, disk_type)
    f[68:84] = unique_id
    struct.pack_into(">I", f, 64, _checksum(f, 64))
    return bytes(f)


def sparse(size, blocks, block_size=4096, parent=None, locators=(),
           parent_name="", unique_id=None, corrupt_header=False,
           table_entries=None):
    """A dynamic VHD, or a differencing one when `parent` (the parent's
    unique id bytes) is given.

    blocks: {block index: (data, present_sectors or None)}. data is the
    block's content (block_size bytes); present_sectors is the set of
    sector indices within the block whose bitmap bit is set (None = all).
    locators: [(code, bytes)] parent locator entries.
    Returns (file bytes, unique id bytes)."""
    unique_id = unique_id or uuid.uuid4().bytes
    n = (size + block_size - 1) // block_size
    if table_entries is not None:
        n = table_entries          # what the header declares, however many
    header_at = 512
    table_at = header_at + 1024
    table_len = (4 * n + 511) // 512 * 512
    pos = table_at + table_len
    loc_blobs = []
    for code, blob in locators:
        space = (len(blob) + 511) // 512 * 512
        loc_blobs.append((code, blob, pos, space))
        pos += space
    bitmap_size = ((block_size // 512 + 7) // 8 + 511) // 512 * 512
    bat = [UNUSED] * n
    body = bytearray()
    blocks = {i: b for i, b in blocks.items() if i < n}
    for idx in sorted(blocks):
        data, present = blocks[idx]
        bat[idx] = (pos + len(body)) // SECTOR
        bm = bytearray(bitmap_size)
        for s in range(block_size // SECTOR):
            if present is None or s in present:
                bm[s >> 3] |= 0x80 >> (s & 7)
        body += bm + data
    disk_type = DIFFERENCING if parent is not None else DYNAMIC

    hdr = bytearray(1024)
    hdr[0:8] = b"cxsparse"
    struct.pack_into(">QQ", hdr, 8, 0xFFFFFFFFFFFFFFFF, table_at)
    struct.pack_into(">III", hdr, 24, 0x00010000, n, block_size)
    if parent is not None:
        hdr[40:56] = parent
        name = parent_name.encode("utf-16-be")[:510]
        hdr[64:64 + len(name)] = name
    for i, (code, blob, at, space) in enumerate(loc_blobs):
        struct.pack_into(">4sIIIQ", hdr, 576 + 24 * i, code, space,
                         len(blob), 0, at)
    struct.pack_into(">I", hdr, 36, _checksum(hdr, 36))
    if corrupt_header:
        hdr[100] ^= 0xFF

    foot = footer(disk_type, size, unique_id, data_offset=header_at)
    out = bytearray(foot)
    out += hdr
    out += struct.pack(">%dI" % n, *bat) + bytes(table_len - 4 * n)
    for code, blob, at, space in loc_blobs:
        out += blob + bytes(space - len(blob))
    out += body
    out += foot
    return bytes(out), unique_id
