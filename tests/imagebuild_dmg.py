"""Build synthetic Apple disk images (UDIF) in memory.

The layout follows the published description of the format: the data fork
holds each chunk's payload one after another; an XML property list holds a
"blkx" entry per partition, each a "mish" table of chunks; a 512-byte "koly"
trailer, big-endian throughout, ends the file and points at the plist.
Compressed chunks come from the standard library (zlib, bz2, lzma) except
LZFSE, for which a stream of one LZVN block is written (valid LZFSE) unless
real encoder output is supplied."""

import bz2
import lzma
import plistlib
import struct
import zlib

import imagebuild_decmpfs as dc

SECTOR = 512
ZERO, RAW, IGNORE, ADC, ZLIB, BZIP2, LZFSE, LZMA = (
    0, 1, 2, 0x80000004, 0x80000005, 0x80000006, 0x80000007, 0x80000008)


def lzfse_stream(data):
    """A valid LZFSE stream holding `data` as one LZVN block."""
    payload = dc.lzvn_literals(data)
    return (b"bvxn" + struct.pack("<II", len(data), len(payload)) + payload
            + b"bvx$")


def pack(kind, data):
    if kind == RAW:
        return data
    if kind in (ZERO, IGNORE):
        return b""
    if kind == ZLIB:
        return zlib.compress(data)
    if kind == BZIP2:
        return bz2.compress(data)
    if kind == LZMA:
        return lzma.compress(data)
    if kind == LZFSE:
        return lzfse_stream(data)
    return b"\x00" * 8                      # ADC and anything else: junk


def mish(first, sectors, chunks, base=0):
    """The block table; `chunks` are (type, sector, sectors, offset, length)
    with the sector counted from `first`."""
    head = b"mish" + struct.pack(">IQQQII", 1, first, sectors, base, 2056,
                                 len(chunks) + 1)
    head += bytes(24) + struct.pack(">II", 2, 32) + bytes(128)
    head += struct.pack(">I", len(chunks) + 1)
    body = b"".join(struct.pack(">IIQQQQ", k, 0, s, n, o, l)
                    for k, s, n, o, l in chunks)
    body += struct.pack(">IIQQQQ", 0xFFFFFFFF, 0, sectors, 0, 0, 0)
    return head + body


def build(parts, chunk_sectors=8, kinds=(ZLIB, BZIP2, LZMA, RAW, LZFSE),
          total_sectors=None, trailer_fixups=None, plist_fixups=None,
          prefix=b"", segments=1):
    """The image bytes. `parts` is [(name, first sector, data)]; each becomes
    one blkx table of chunks of `chunk_sectors`, cycling through `kinds`
    (an all-zero chunk is stored as a zero-fill chunk)."""
    fork = bytearray(prefix)
    entries = []
    end = 0
    n = 0
    for name, first, data in parts:
        assert len(data) % SECTOR == 0
        chunks = []
        step = chunk_sectors * SECTOR
        for i in range(0, len(data), step):
            piece = data[i:i + step]
            sectors = len(piece) // SECTOR
            kind = ZERO if not any(piece) else kinds[n % len(kinds)]
            n += 1
            payload = pack(kind, piece)
            chunks.append((kind, i // SECTOR, sectors, len(fork),
                           len(payload)))
            fork += payload
        end = max(end, first + len(data) // SECTOR)
        entries.append({"Attributes": "0x0050", "CFName": name,
                        "Data": mish(first, len(data) // SECTOR, chunks),
                        "ID": str(len(entries) - 1), "Name": name})
    plist = {"resource-fork": {"blkx": entries, "plst": []}}
    if plist_fixups:
        plist_fixups(plist)
    xml = plistlib.dumps(plist)
    trailer = bytearray(512)
    trailer[:4] = b"koly"
    struct.pack_into(">II", trailer, 4, 4, 512)
    struct.pack_into(">IQQQQQII", trailer, 12, 1, 0, len(prefix),
                     len(fork) - len(prefix), 0, 0, 1, segments)
    struct.pack_into(">QQ", trailer, 216, len(fork), len(xml))
    struct.pack_into(">IQ", trailer, 488, 1, total_sectors or end)
    if trailer_fixups:
        trailer_fixups(trailer)
    return bytes(fork) + xml + bytes(trailer)
