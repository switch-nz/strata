"""Build synthetic QCOW2 files (version 2 and 3) in memory.

Layout follows the QEMU specification: a header in the first cluster, an L1
table, L2 tables and data clusters, all big-endian. Cluster 0 is the header,
cluster 1 the L1 table; the rest are appended as needed."""

import struct
import zlib

COPIED = 1 << 63
COMPRESSED = 1 << 62
ZERO_FLAG = 1


def build(size, clusters, cluster_bits=12, version=2, backing=None, crypt=0,
          incompatible=0, compression=0, snapshots=0, l1_entries=None,
          l1_offset=None, pack=False):
    """clusters: {virtual cluster index: data (cluster-size bytes) | "zero"
    (the version 3 zero flag, no data cluster) | ("zero+", data) (zero flag on
    a cluster that still has data behind it) | ("z", data) (stored
    compressed; with `pack` the streams are packed one after another at
    byte offsets, as QEMU writes them, rather than sector-aligned)}.
    Returns the file bytes."""
    cs = 1 << cluster_bits
    per_l2 = cs // 8
    needed = -(-size // (cs * per_l2)) or 1
    l1_n = needed if l1_entries is None else l1_entries
    l1_cl = -(-(l1_n * 8) // cs) or 1
    out = bytearray(cs * (1 + l1_cl))          # header + L1, filled below
    l1 = [0] * max(l1_n, needed)
    l2s = {}
    for vidx in sorted(clusters):
        l2s.setdefault(vidx // per_l2, {})[vidx % per_l2] = clusters[vidx]
    for l1i in sorted(l2s):
        table = [0] * per_l2
        for i, val in l2s[l1i].items():
            if val == "zero":
                table[i] = COPIED | ZERO_FLAG
            elif isinstance(val, tuple) and val[0] == "zero+":
                out += bytes((-len(out)) % cs)
                table[i] = COPIED | len(out) | ZERO_FLAG
                out += val[1].ljust(cs, b"\x00")
            elif isinstance(val, tuple):
                raw = zlib.compressobj(9, zlib.DEFLATED, -15)
                blob = raw.compress(val[1]) + raw.flush()
                if not pack:
                    out += bytes((-len(out)) % 512)
                host = len(out)
                sectors = (host + len(blob) - 1) // 512 - host // 512 + 1
                out += blob if pack else blob.ljust(sectors * 512, b"\x00")
                shift = 62 - (cluster_bits - 8)
                table[i] = COMPRESSED | ((sectors - 1) << shift) | host
            else:
                out += bytes((-len(out)) % cs)
                table[i] = COPIED | len(out)
                out += val.ljust(cs, b"\x00")
        out += bytes((-len(out)) % cs)
        if l1i < len(l1):
            l1[l1i] = COPIED | len(out)
        out += struct.pack(">%dQ" % per_l2, *table)
    l1_at = cs if l1_offset is None else l1_offset
    out[l1_at:l1_at + 8 * l1_n] = struct.pack(">%dQ" % l1_n, *l1[:l1_n])
    name_at = 0
    if backing is not None:
        out += bytes((-len(out)) % cs)
        name_at = len(out)
        out += backing
    hdr = bytearray(112)
    hdr[0:4] = b"QFI\xfb"
    struct.pack_into(">I", hdr, 4, version)
    struct.pack_into(">QI", hdr, 8, name_at, len(backing or b""))
    struct.pack_into(">I", hdr, 20, cluster_bits)
    struct.pack_into(">Q", hdr, 24, size)
    struct.pack_into(">IIQ", hdr, 32, crypt, l1_n, l1_at)
    struct.pack_into(">QIIQ", hdr, 48, 0, 0, snapshots, 0)
    if version == 3:
        struct.pack_into(">QQQII", hdr, 72, incompatible, 0, 0, 4, 112)
        hdr[104] = compression
    out[0:len(hdr)] = hdr
    return bytes(out)
