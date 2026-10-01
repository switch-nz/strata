"""Synthetic AFF4 volumes for testing engine.aff4, built field by field from
the published AFF4 Standard v1.0a (github.com/aff4/Standard) and from bytes
observed in real files written by pyaff4 (the reference implementation),
not from engine.aff4 itself -- see that module's own docstring for the two
points where the standard's prose turned out not to match real output
(the ImageStream bevy index layout, and the compression method URI).

A plain, non-Zip64 local/central/EOCD layout is used by default since that
already exercises every code path except the Zip64 fallback, which
build_zip64() exists to exercise on its own.
"""

import struct
import zlib

CHUNK_SIZE = 1024
CHUNKS_PER_SEGMENT = 4


def _local_header(name, data, method):
    nb = name.encode("utf-8")
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, method, 0, 0,
                       crc, len(data), len(data), len(nb), 0) + nb


def _central_header(name, data, method, offset):
    nb = name.encode("utf-8")
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, 0, method,
                       0, 0, crc, len(data), len(data), len(nb), 0, 0, 0, 0,
                       0, offset) + nb


class ZipBuilder:
    """A minimal, plain (non-Zip64) Zip writer -- just enough to build an
    AFF4 volume: stored members, in the order added, with a comment
    carrying the volume URI (AFF4 Standard v1.0a section 5.4)."""

    def __init__(self):
        self._parts = []
        self._central = []
        self._offset = 0

    def add(self, name, data):
        self._parts.append(_local_header(name, data, 0) + data)
        self._central.append(_central_header(name, data, 0, self._offset))
        self._offset += len(self._parts[-1])

    def finish(self, comment=b""):
        body = b"".join(self._parts)
        cd = b"".join(self._central)
        cd_off = len(body)
        eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(self._central),
                           len(self._central), len(cd), cd_off, len(comment))
        return body + cd + eocd + comment


def build_zip64(members, comment=b""):
    """A Zip64 volume (EOCD64 + locator + 64-bit central-directory extra
    fields), all members stored, to exercise engine.aff4's Zip64 path
    specifically. `members`: [(name, data), ...]."""
    parts, central = [], []
    offset = 0
    for name, data in members:
        nb = name.encode("utf-8")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        parts.append(_local_header(name, data, 0) + data)
        central.append(struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014b50, 45, 45, 0, 0, 0, 0, crc,
            len(data), len(data), len(nb), 0, 0, 0, 0, 0, offset) + nb)
        offset += len(parts[-1])
    body = b"".join(parts)
    cd = b"".join(central)
    cd_off = len(body)
    eocd64 = struct.pack(
        "<IQHHIIQQQQ", 0x06064b50, 44, 45, 45, 0, 0, len(central),
        len(central), len(cd), cd_off)
    eocd64_loc = struct.pack("<IIQI", 0x07064b50, 0, len(body) + len(cd), 1)
    eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, 0xFFFF, 0xFFFF,
                       0xFFFFFFFF, 0xFFFFFFFF, len(comment))
    return body + cd + eocd64 + eocd64_loc + eocd + comment


def _turtle(triples):
    """triples: [(subject, [(pred, [obj, ...]), ...]), ...]; obj is a
    pre-formatted Turtle term (<uri>, "lit", or a bare number)."""
    lines = ["@prefix aff4: <http://aff4.org/Schema#> .",
            "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .", ""]
    for subj, preds in triples:
        parts = []
        for pred, objs in preds:
            parts.append("%s %s" % (pred, ", ".join(objs)))
        lines.append("<%s> %s ." % (subj, " ;\n    ".join(parts)))
        lines.append("")
    return "\n".join(lines).encode("utf-8")


def _bevy(chunks, chunk_size, compress):
    """(bevy_bytes, index_bytes) for one bevy -- the real, empirically-
    verified 12-byte-per-chunk index record (offset, reserved, stored
    length), not the struct the standard's prose describes. A chunk is
    stored compressed only when doing so saves at least 16 bytes
    (AFF4 Standard v1.0a section 3.2); otherwise it is padded to
    chunk_size and stored as-is."""
    body = bytearray()
    index = bytearray()
    for chunk in chunks:
        chunk = chunk[:chunk_size].ljust(chunk_size, b"\x00")
        compressed = zlib.compress(chunk) if compress else None
        if compressed is not None and len(compressed) < chunk_size - 16:
            stored = compressed
        else:
            stored = chunk
        index += struct.pack("<III", len(body), 0, len(stored))
        body += stored
    return bytes(body), bytes(index)


def build_bare_image_stream(data, chunk_size=CHUNK_SIZE,
                            chunks_per_segment=CHUNKS_PER_SEGMENT,
                            compress=True, volume_name="image.dd"):
    """A volume whose only image object is a bare ImageStream (no Map, no
    DiskImage wrapper) -- the simplest valid AFF4 image."""
    volume_urn = "aff4://11111111-1111-1111-1111-111111111111"
    stream_urn = "%s/%s" % (volume_urn, volume_name)
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)] \
        or [b""]
    zb = ZipBuilder()
    for seg, start in enumerate(range(0, len(chunks), chunks_per_segment)):
        bevy_chunks = chunks[start:start + chunks_per_segment]
        bevy, index = _bevy(bevy_chunks, chunk_size, compress)
        name = "%s/%08d" % (volume_name, seg)
        zb.add(name, bevy)
        zb.add(name + ".index", index)
    triples = [("a", ["aff4:ImageStream"]),
              ("aff4:chunkSize", [str(chunk_size)]),
              ("aff4:chunksInSegment", [str(chunks_per_segment)]),
              ("aff4:size", [str(len(data))])]
    if compress:
        triples.append(("aff4:compressionMethod",
                        ["<https://www.ietf.org/rfc/rfc1950.txt>"]))
    turtle = _turtle([(stream_urn, triples)])
    zb.add("information.turtle", turtle)
    return zb.finish(comment=volume_urn.encode("ascii"))


def build_disk_image(ranges, stream_size=None, chunk_size=CHUNK_SIZE,
                     chunks_per_segment=CHUNKS_PER_SEGMENT, compress=True,
                     gap_fill="aff4:Zero", hash_md5=None, hash_sha1=None):
    """A volume with a DiskImage -> Map -> ImageStream chain, the shape a
    real disk-imaging tool produces. `ranges`: a list of
    (map_offset, data_bytes) tuples, each written to its own place in one
    backing ImageStream at a matching target_offset (so the fixture, unlike
    pyaff4's own AFF4Map.WriteStream(), does not reproduce pyaff4's
    target_offset bug -- see engine/aff4.py's module docstring). Gaps
    between ranges, and before/after them up to `stream_size`, read as
    `gap_fill`."""
    volume_urn = "aff4://22222222-2222-2222-2222-222222222222"
    disk_urn = "%s/disk0" % volume_urn
    map_urn = "%s/map0" % volume_urn
    stream_urn = "%s/data0" % volume_urn

    backing = bytearray()
    target_offsets = []
    for _map_off, data in ranges:
        target_offsets.append(len(backing))
        backing += data
    size = stream_size if stream_size is not None else (
        max((o + len(d) for o, d in ranges), default=0))

    chunks = [bytes(backing)[i:i + chunk_size]
             for i in range(0, len(backing), chunk_size)] or [b""]
    zb = ZipBuilder()
    for seg, start in enumerate(range(0, len(chunks), chunks_per_segment)):
        bevy_chunks = chunks[start:start + chunks_per_segment]
        bevy, index = _bevy(bevy_chunks, chunk_size, compress)
        name = "data0/%08d" % seg
        zb.add(name, bevy)
        zb.add(name + ".index", index)

    map_entries = bytearray()
    for (map_off, data), target_off in zip(ranges, target_offsets):
        map_entries += struct.pack("<QQQI", map_off, len(data), target_off, 0)
    zb.add("map0/map", bytes(map_entries))
    zb.add("map0/idx", stream_urn.encode("utf-8"))

    stream_triples = [("a", ["aff4:ImageStream"]),
                      ("aff4:chunkSize", [str(chunk_size)]),
                      ("aff4:chunksInSegment", [str(chunks_per_segment)]),
                      ("aff4:size", [str(len(backing))])]
    if compress:
        stream_triples.append(
            ("aff4:compressionMethod", ["<https://www.ietf.org/rfc/rfc1950.txt>"]))

    disk_triples = [("a", ["aff4:DiskImage", "aff4:ContiguousImage", "aff4:Image"]),
                    ("aff4:dataStream", ["<%s>" % map_urn]),
                    ("aff4:size", [str(size)])]
    hashes = []
    if hash_md5:
        hashes.append('"%s"^^aff4:MD5' % hash_md5)
    if hash_sha1:
        hashes.append('"%s"^^aff4:SHA1' % hash_sha1)
    if hashes:
        disk_triples.append(("aff4:hash", hashes))

    map_triples = [("a", ["aff4:Map"]),
                  ("aff4:size", [str(size)]),
                  ("aff4:dependentStream", ["<%s>" % stream_urn])]
    if gap_fill and gap_fill != "aff4:Zero":
        map_triples.append(("aff4:mapGapDefaultStream", ["<%s>" % gap_fill]))

    turtle = _turtle([
        (disk_urn, disk_triples),
        (map_urn, map_triples),
        (stream_urn, stream_triples),
    ])
    zb.add("information.turtle", turtle)
    return zb.finish(comment=volume_urn.encode("ascii"))
