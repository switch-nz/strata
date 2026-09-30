"""Build synthetic VirtualBox VDI files (version 1.1) in memory.

Layout follows VirtualBox's own: a 64-byte text banner, a signature and
version, a 400-byte header, a block map of little-endian 32-bit entries
and blocks stored back to back from the data offset."""

import struct
import uuid

FREE = 0xFFFFFFFF
ZERO = 0xFFFFFFFE
DYNAMIC, FIXED, UNDO, DIFF = 1, 2, 3, 4
BANNER = b"<<< Oracle VM VirtualBox Disk Image >>>\n"


def build(size, blocks, block_size=4096, kind=DYNAMIC, zero=(),
          map_entries=None, allocated=None, extra=0, version=0x00010001,
          sector_size=512, comment=b"strata test", parent=bytes(16)):
    """blocks: {block index: block bytes}; zero: block indices written as
    ZERO in the map. Returns (file bytes, unique id bytes)."""
    n = (size + block_size - 1) // block_size
    if map_entries is not None:
        n = map_entries                  # what the header declares
    off_blocks = 512
    off_data = off_blocks + (4 * n + 511) // 512 * 512
    table = [FREE] * n
    body = bytearray()
    slot = 0
    for idx in sorted(blocks):
        if idx >= n:
            continue
        table[idx] = slot
        body += blocks[idx].ljust(block_size + extra, b"\x00")
        slot += 1
    for idx in zero:
        if idx < n:
            table[idx] = ZERO
    if kind == FIXED:
        # A fixed disk maps every block to itself, in order.
        table = list(range(n))
        body = bytearray()
        for idx in range(n):
            body += blocks.get(idx, b"").ljust(block_size, b"\x00")
    hdr = bytearray(512)
    hdr[0:len(BANNER)] = BANNER
    struct.pack_into("<II", hdr, 0x40, 0xBEDA107F, version)
    struct.pack_into("<III", hdr, 0x48, 0x190, kind, 0)
    hdr[0x54:0x54 + len(comment)] = comment
    struct.pack_into("<II", hdr, 0x154, off_blocks, off_data)
    struct.pack_into("<IIII", hdr, 0x15C, 0, 0, 0, sector_size)
    struct.pack_into("<Q", hdr, 0x170, size)
    got = sum(1 for e in table if e not in (FREE, ZERO))
    struct.pack_into("<IIII", hdr, 0x178, block_size, extra, n,
                     got if allocated is None else allocated)
    uid = uuid.uuid4().bytes_le
    hdr[0x188:0x198] = uid
    hdr[0x1B8:0x1C8] = parent
    out = bytearray(hdr)
    out += struct.pack("<%dI" % n, *table) + bytes(off_data - off_blocks
                                                    - 4 * n)
    out += body
    return bytes(out), uid
