"""A synthetic EWF2 (Ex01) image for testing engine.ewf2, built field by
field from libyal's "EWF 2 specification" (documentation/Expert Witness
Compression Format 2 (EWF2).asciidoc) and cross-checked against libewf's
own C source for the one detail the prose alone doesn't pin down -- see
engine/ewf2.py's module docstring. Not derived from engine.ewf2 itself, so
a misreading in the parser cannot be repeated here.

Sections are written in the same order a real writer would produce them
(file header, device info, case data, sector data, sector table, hashes,
done), with each section's descriptor computed from the position of the
one written just before it -- which is exactly the back-to-front chain
engine.ewf2 walks in the opposite direction when reading.
"""

import struct
import uuid
import zlib

EVF2_SIG = b"EVF2\x0d\x0a\x81\x00"
FILE_HEADER_SIZE = 32
SECTION_DESC_SIZE = 64

COMPRESSION_NONE = 0
COMPRESSION_LZ = 1
COMPRESSION_BZIP2 = 2

SECTION_DEVICE = 1
SECTION_CASE = 2
SECTION_SECTORS = 3
SECTION_TABLE = 4
SECTION_ERROR = 5
SECTION_MD5 = 8
SECTION_SHA1 = 9
SECTION_CRYPT = 11
SECTION_NEXT = 13
SECTION_DONE = 15

DATA_FLAG_ENCRYPTED = 0x00000002

CHUNK_COMPRESSED = 0x00000001
CHUNK_HAS_CHECKSUM = 0x00000002
CHUNK_PATTERN_FILL = 0x00000004

SECTOR = 512
SECTORS_PER_CHUNK = 4
CHUNK_SIZE = SECTOR * SECTORS_PER_CHUNK


def _escape(value):
    return (value.replace("\t", "\x03").replace("\r", "\x02")
                 .replace("\n", "\x01"))


def object_string(tags):
    """A serialized object string: object count, "main", tab-separated
    tags, tab-separated (escaped) values, blank line (EWF2 specification,
    "Serialized (file) object data")."""
    keys = "\t".join(tags.keys())
    values = "\t".join(_escape(str(v)) for v in tags.values())
    text = "1\nmain\n%s\n%s\n\n" % (keys, values)
    return b"\xff\xfe" + text.encode("utf-16-le")


class SegmentBuilder:

    def __init__(self, segment_number=1, segment_set_id=None,
                compression_method=COMPRESSION_LZ):
        self.compression_method = compression_method
        header = (EVF2_SIG + bytes([2, 1])
                 + struct.pack("<H", compression_method)
                 + struct.pack("<I", segment_number)
                 + (segment_set_id or uuid.uuid4().bytes_le))
        assert len(header) == FILE_HEADER_SIZE
        self.parts = [header]
        self.length = FILE_HEADER_SIZE
        self.last_desc_pos = None

    def add_section(self, type_num, data, data_flags=0):
        previous_offset = self.last_desc_pos or 0
        desc_pos = self.length + len(data)
        body = struct.pack("<IIQQII", type_num, data_flags, previous_offset,
                           len(data), SECTION_DESC_SIZE, 0)
        body += bytes(16)          # data integrity hash (unset)
        body += bytes(12)          # padding
        checksum = zlib.adler32(body) & 0xFFFFFFFF
        body += struct.pack("<I", checksum)
        assert len(body) == SECTION_DESC_SIZE
        self.parts.append(data)
        self.parts.append(body)
        self.length = desc_pos + SECTION_DESC_SIZE
        self.last_desc_pos = desc_pos

    def add_object_section(self, type_num, tags):
        blob = object_string(tags)
        if self.compression_method == COMPRESSION_LZ:
            blob = zlib.compress(blob)
        self.add_section(type_num, blob)

    def add_table(self, first_chunk, entries):
        """entries: [(offset, size, flags), ...] already resolved (pattern
        fill entries pass their 8-byte pattern as `offset`)."""
        header = struct.pack("<QII", first_chunk, len(entries), 0)
        header += struct.pack("<I", zlib.adler32(header) & 0xFFFFFFFF)
        header += bytes(12)        # alignment padding
        body = b"".join(struct.pack("<QII", off, size, flags)
                        for off, size, flags in entries)
        footer = struct.pack("<I", zlib.adler32(body) & 0xFFFFFFFF)
        footer += bytes(12)
        self.add_section(SECTION_TABLE, header + body + footer)

    def add_hash(self, md5=None, sha1=None):
        if md5 is not None:
            data = md5 + struct.pack("<I", zlib.adler32(md5) & 0xFFFFFFFF)
            data += bytes(12)
            self.add_section(SECTION_MD5, data)
        if sha1 is not None:
            data = sha1 + struct.pack("<I", zlib.adler32(sha1) & 0xFFFFFFFF)
            data += bytes(8)
            self.add_section(SECTION_SHA1, data)

    def finish(self, last=True):
        self.add_section(SECTION_DONE if last else SECTION_NEXT, b"")
        return b"".join(self.parts)


def chunk_entry(data, compress, force_stored=False):
    """(stored_bytes, flags) for one chunk: compressed if that is shorter
    than storing it raw (EWF2 specification, "Sector data" -- same
    compress-or-store rule as EWF1), unless force_stored."""
    if compress and not force_stored:
        compressed = zlib.compress(data)
        if len(compressed) < len(data):
            return compressed, CHUNK_COMPRESSED
    return data + struct.pack("<I", zlib.adler32(data) & 0xFFFFFFFF), \
        CHUNK_HAS_CHECKSUM


def build_ex01(data, chunk_size=CHUNK_SIZE, compress=True,
              compression_method=COMPRESSION_LZ, md5=None, sha1=None,
              device_tags=None, case_tags=None, sector_count=None,
              pattern_fill_chunks=()):
    """One-segment EWF2-Ex01 image holding `data`. `pattern_fill_chunks`:
    a set of chunk indices to store as pattern-fill (8-byte repeating
    pattern, no sector data) instead of real content -- the caller is
    responsible for `data` at those chunks actually being that pattern,
    since this fixture does not silently rewrite content.
    """
    seg = SegmentBuilder(compression_method=compression_method)

    device = {"bp": SECTOR, "ts": sector_count if sector_count is not None
             else len(data) // SECTOR}
    device.update(device_tags or {})
    seg.add_object_section(SECTION_DEVICE, device)

    case = {"sb": chunk_size // SECTOR, "tb": -(-len(data) // chunk_size),
            "cp": compression_method}
    case.update(case_tags or {})
    seg.add_object_section(SECTION_CASE, case)

    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)] \
        or [b""]
    sectors_blob = bytearray()
    entries = []
    for i, chunk in enumerate(chunks):
        if i in pattern_fill_chunks:
            entries.append((struct.unpack("<Q", (chunk * 2)[:8])[0], 8,
                            CHUNK_COMPRESSED | CHUNK_PATTERN_FILL))
            continue
        stored, flags = chunk_entry(chunk, compress)
        entries.append((len(sectors_blob), len(stored), flags))
        sectors_blob += stored
    seg.add_section(SECTION_SECTORS, bytes(sectors_blob))

    # Sector table entries for pattern-fill chunks don't reference the
    # sectors blob at all; their "offset" is already the raw pattern, set
    # above -- only non-pattern entries need the sectors-section base.
    base = seg.length - len(sectors_blob) - SECTION_DESC_SIZE
    resolved = []
    for off, size, flags in entries:
        if flags & CHUNK_PATTERN_FILL:
            resolved.append((off, size, flags))
        else:
            resolved.append((base + off, size, flags))
    seg.add_table(0, resolved)

    seg.add_hash(md5=md5, sha1=sha1)
    return seg.finish()


def build_encrypted_ex01():
    """A minimal EWF2 image whose sector data section has the ENCRYPTED
    data flag set, for testing refusal."""
    seg = SegmentBuilder()
    seg.add_object_section(SECTION_DEVICE, {"bp": SECTOR, "ts": 4})
    seg.add_object_section(SECTION_CASE, {"sb": 4, "tb": 1})
    seg.add_section(SECTION_SECTORS, bytes(CHUNK_SIZE), data_flags=DATA_FLAG_ENCRYPTED)
    seg.add_table(0, [(seg.length - CHUNK_SIZE - SECTION_DESC_SIZE,
                      CHUNK_SIZE, CHUNK_HAS_CHECKSUM)])
    return seg.finish()


def build_bzip2_ex01():
    """A minimal EWF2 image declaring bzip2 compression, for testing
    refusal (EWF2 specification: EnCase 7 has never offered this as an
    option, and strips the standard bzip2 container framing in a way
    this reader -- using stdlib bz2 -- cannot parse)."""
    seg = SegmentBuilder(compression_method=COMPRESSION_BZIP2)
    return seg.finish()
