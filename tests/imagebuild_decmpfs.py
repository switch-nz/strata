"""Build decmpfs attribute values and resource forks (see engine.decmpfs).

The zlib resource fork is a 0x100-byte header (big-endian: the offset of the
block table, then the offset of a footer), a block table at that offset (four
bytes, then a little-endian block count, then a little-endian offset and size
for each block, offsets counted from the count), the blocks, and a footer. The
LZVN resource fork is a table of little-endian block offsets followed by the
blocks. Each block covers 64 KiB of the file."""

import struct
import zlib

BLOCK = 0x10000


def header(kind, size):
    return b"fpmc" + struct.pack("<IQ", kind, size)


def zlib_block(data, stored=False):
    if stored:
        return b"\xff" + data
    return zlib.compress(data, 6)


def lzvn_literals(data):
    """A valid LZVN stream that only holds literals: 'small literal'
    instructions (0xE1..0xEF, 1..15 bytes) or 'large literal' ones
    (0xE0 and a length byte, 16..271 bytes), then the end-of-stream marker."""
    out = bytearray()
    for i in range(0, len(data), 271):
        piece = data[i:i + 271]
        if len(piece) < 16:
            out += bytes([0xE0 + len(piece)])
        else:
            out += bytes([0xE0, len(piece) - 16])
        out += piece
    return bytes(out) + b"\x06" + bytes(7)


def lzvn_stored(data):
    return b"\x06" + data


def inline_value(kind, size, payload):
    """The com.apple.decmpfs value for a type that keeps its data there."""
    return header(kind, size) + payload


def zlib_fork(blocks):
    """The resource fork holding zlib `blocks` (already compressed)."""
    table_at = 0x100
    count = len(blocks)
    base = table_at + 4                  # offsets are counted from here
    data_at = base + 4 + 8 * count
    descs, body, pos = [], bytearray(), data_at
    for b in blocks:
        descs.append(struct.pack("<II", pos - base, len(b)))
        body += b
        pos += len(b)
    footer_at = pos
    fork = bytearray(struct.pack(">II", 0x100, footer_at))
    fork += bytes(0x100 - len(fork))
    fork += struct.pack(">I", footer_at - 0x100)          # data size
    fork += struct.pack("<I", count) + b"".join(descs) + body
    fork += bytes(50)                                    # the footer
    return bytes(fork)


def lzvn_fork(blocks):
    """The resource fork holding LZVN `blocks` (already encoded)."""
    n = len(blocks)
    pos = 4 * n
    offs = []
    for b in blocks:
        offs.append(pos)
        pos += len(b)
    return struct.pack("<%dI" % n, *offs) + b"".join(blocks)


def split(data):
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)] or [b""]
