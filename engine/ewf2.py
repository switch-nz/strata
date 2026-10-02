import os
import struct
import threading
import zlib
from collections import OrderedDict

from .inflate import DAMAGED, STOPPED, inflate_capped, inflate_ended
from .text import t as _t

# EWF2 (EnCase Evidence File Format Version 2, "Ex01"), introduced in
# EnCase 7. Despite the name this is not EWF1 with wider fields: sections
# are read back-to-front (each section's 64-byte descriptor sits at its own
# *end* and points to the *previous* section's descriptor, not the next
# one), metadata is a different key/value text format, and the chunk table
# carries each chunk's exact size and flags explicitly rather than
# computing size from the next entry's offset.
#
# Written from libyal's "EWF 2 specification" (Joachim Metz,
# github.com/libyal/libewf, documentation/Expert Witness Compression
# Format 2 (EWF2).asciidoc) and cross-checked line-for-line against
# libewf's own C source (libewf_section_descriptor.c,
# libewf_table_section.c, libewf_chunk_group.c) for the one detail the
# prose doesn't fully pin down: what the "previous section offset" field
# actually encodes. It is not the previous section's start offset (as a
# literal reading suggests) -- it is that section's *descriptor* position,
# i.e. (this section's start - 64); reading it as "the previous
# descriptor's file offset" is what makes the back-to-front walk work.
# This fixture/reader pair was also cross-validated against pyewf (the
# real libewf reference implementation's Python bindings), which reads
# this module's own synthetic test files correctly.

EVF2_SIG = b"EVF2\x0d\x0a\x81\x00"
FILE_HEADER_SIZE = 32
SECTION_DESC_SIZE = 64

COMPRESSION_NONE = 0
COMPRESSION_LZ = 1
COMPRESSION_BZIP2 = 2

DATA_FLAG_MD5HASHED = 0x00000001
DATA_FLAG_ENCRYPTED = 0x00000002

CHUNK_COMPRESSED = 0x00000001
CHUNK_HAS_CHECKSUM = 0x00000002
CHUNK_PATTERN_FILL = 0x00000004

SECTION_TYPES = {
    1: "device", 2: "case", 3: "sectors", 4: "table", 5: "error",
    6: "session", 7: "increment", 8: "md5", 9: "sha1", 10: "restart",
    11: "crypt", 12: "memextents", 13: "next", 14: "final", 15: "done",
    16: "analytical", 0x20: "ls_data", 0x21: "ls_table1",
    0x22: "ls_md5_table", 0x23: "ls_table2",
}

# Every size below comes from the segment file itself, so each read is
# bounded by what the format can legitimately hold rather than by what a
# damaged or hostile descriptor claims -- same discipline as engine/ewf.py.
MAX_OBJECT_STRING = 4 << 20
MAX_CHUNK_SIZE = 64 << 20
MAX_TABLE_ENTRIES = 1 << 20
SECTOR_SIZES = (512, 1024, 2048, 4096)


class Ewf2Error(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice


def looks_like_ewf2(head):
    return head[:8] == EVF2_SIG


# --- the serialized object string (device info / case data / etc.) -------

_ESCAPES = {"\x01": "\n", "\x02": "\r", "\x03": "\t"}


def _unescape(field):
    for esc, real in _ESCAPES.items():
        if esc in field:
            field = field.replace(esc, real)
    return field


def parse_object_string(text):
    """{tag: value} from a decompressed, decoded serialized object string:
    a line holding the object count, then per object a name line, a
    tab-separated tag line and a tab-separated value line (EWF2
    specification, "Serialized (file) object data"). Only the first
    ("main") object's tags are returned; nested sub-objects (used by
    restart data, not device/case/analytical data) are not parsed."""
    lines = text.lstrip("﻿").split("\n")
    out = {}
    for i, line in enumerate(lines):
        if line.strip() == "main" and i + 2 < len(lines):
            tags = lines[i + 1].split("\t")
            values = lines[i + 2].split("\t")
            for tag, value in zip(tags, values):
                if value:
                    out[tag] = _unescape(value)
            break
    return out


def _decode_object_string(blob):
    """UTF-16 with byte-order-mark, little-endian unless the BOM says
    otherwise (EWF2 specification, section 'Serialized (file) object
    data')."""
    if blob[:2] == b"\xff\xfe":
        return blob.decode("utf-16-le", "replace")
    if blob[:2] == b"\xfe\xff":
        return blob.decode("utf-16-be", "replace")
    return blob.decode("utf-16-le", "replace")


class Chunk2:
    __slots__ = ("seg", "offset", "size", "flags")

    def __init__(self, seg, offset, size, flags):
        self.seg = seg
        self.offset = offset
        self.size = size
        self.flags = flags


class Ewf2Image:
    """An EWF2-Ex01 image. EWF2-Lx01 (logical evidence: files and folders,
    not a disk image) is a different, adjacent format and is not read
    here. Encrypted images are refused outright -- EWF2 encryption is not
    disclosed by Guidance Software and not documented even by libewf; bzip2
    chunk compression is refused too, since EnCase 7 itself has never
    offered it as an option and EnCase's variant of the format strips the
    standard bzip2 container framing in a way stdlib's bz2 module cannot
    parse."""

    def __init__(self, path):
        self.path = path
        self.segment_paths = None
        self._handles = {}
        self._seg_sizes = {}
        self.findings = []
        self.chunks = []
        self.chunk_size = 0
        self.sectors_per_chunk = 0
        self.bytes_per_sector = 512
        self.sector_count = 0
        self.compression_method = None
        self.header = {}
        self.stored_md5 = None
        self.stored_sha1 = None
        self.error_ranges = []
        self._cache = OrderedDict()
        self._cache_max = 64
        self._io_lock = threading.Lock()
        self._pos = 0
        try:
            from . import ewf as ewf_mod
            self.segment_paths = ewf_mod.discover_segments(path)
            self._parse()
        except BaseException:
            self.close()
            raise

    def _fh(self, seg):
        h = self._handles.get(seg)
        if h is None:
            h = open(self.segment_paths[seg], "rb")
            self._handles[seg] = h
        return h

    def _seg_size(self, seg):
        size = self._seg_sizes.get(seg)
        if size is None:
            size = os.fstat(self._fh(seg).fileno()).st_size
            self._seg_sizes[seg] = size
        return size

    def _read_bounded(self, seg, offset, size, cap):
        end = self._seg_size(seg)
        if offset < 0 or offset >= end:
            return b"", size > 0
        want = min(size, end - offset, cap)
        fh = self._fh(seg)
        fh.seek(offset)
        return fh.read(want), want < size

    def close(self):
        for h in self._handles.values():
            h.close()
        self._handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --- parsing ----------------------------------------------------------

    def _parse(self):
        chunk_by_index = {}
        for seg_index in range(len(self.segment_paths)):
            self._parse_segment(seg_index, chunk_by_index)

        if not chunk_by_index:
            raise Ewf2Error(_t("ewf2.chunk_table_found_evidence"))

        last = max(chunk_by_index)
        missing = 0
        self.chunks = []
        for i in range(last + 1):
            c = chunk_by_index.get(i)   # None stands for a missing chunk
            if c is None:
                missing += 1
            self.chunks.append(c)
        if missing:
            self.findings.append(
                _t("ewf2.chunk_table_has_gaps") % missing)

        if self.sector_count and self.bytes_per_sector:
            self.size = self.sector_count * self.bytes_per_sector
        else:
            self.size = len(self.chunks) * (self.chunk_size or 32768)

    def _parse_segment(self, seg_index, chunk_by_index):
        head, _ = self._read_bounded(seg_index, 0, FILE_HEADER_SIZE,
                                     FILE_HEADER_SIZE)
        if len(head) < FILE_HEADER_SIZE or head[:8] != EVF2_SIG:
            raise Ewf2Error(
                _t("ewf2.ewf2_segment_file") % self.segment_paths[seg_index])
        compression_method = struct.unpack_from("<H", head, 10)[0]
        if self.compression_method is None:
            self.compression_method = compression_method
        if compression_method == COMPRESSION_BZIP2:
            raise Ewf2Error(_t("ewf2.bzip2_compression_not_supported"))
        elif compression_method not in (COMPRESSION_NONE, COMPRESSION_LZ):
            raise Ewf2Error(
                _t("ewf2.compression_method_unknown") % compression_method)

        size = self._seg_size(seg_index)
        desc_pos = size - SECTION_DESC_SIZE
        seen = set()
        guard = 0
        while desc_pos >= FILE_HEADER_SIZE:
            guard += 1
            if guard > 200000:
                self.findings.append(
                    _t("ewf2.section_chain_exceeded") % seg_index)
                break
            if desc_pos in seen:
                self.findings.append(
                    _t("ewf2.section_chain_cyclic") % (seg_index, desc_pos))
                break
            seen.add(desc_pos)

            sec = self._read_section_descriptor(seg_index, desc_pos)
            if sec is None:
                break
            if sec["data_flags"] & DATA_FLAG_ENCRYPTED:
                raise Ewf2Error(_t("ewf2.encrypted_not_supported"))

            self._dispatch_section(seg_index, sec, chunk_by_index)

            if sec["previous_offset"] == 0:
                break
            if sec["previous_offset"] >= desc_pos:
                self.findings.append(
                    _t("ewf2.section_chain_non_receding")
                    % (seg_index, desc_pos))
                break
            desc_pos = sec["previous_offset"]

    def _read_section_descriptor(self, seg, desc_pos):
        raw, _ = self._read_bounded(seg, desc_pos, SECTION_DESC_SIZE,
                                    SECTION_DESC_SIZE)
        if len(raw) < SECTION_DESC_SIZE:
            self.findings.append(
                _t("ewf2.section_descriptor_truncated") % (seg, desc_pos))
            return None
        type_num, data_flags, previous_offset, data_size = \
            struct.unpack_from("<IIQQ", raw, 0)
        stored = struct.unpack_from("<I", raw, 60)[0]
        if zlib.adler32(raw[:60]) & 0xFFFFFFFF != stored:
            self.findings.append(
                _t("ewf2.section_descriptor_checksum_mismatch")
                % (seg, desc_pos))
        start_offset = (FILE_HEADER_SIZE if previous_offset == 0
                        else previous_offset + SECTION_DESC_SIZE)
        if data_size > (desc_pos - start_offset):
            self.findings.append(
                _t("ewf2.section_data_size_implausible")
                % (seg, desc_pos))
            data_size = max(0, desc_pos - start_offset)
        return {
            "type": type_num,
            "name": SECTION_TYPES.get(type_num),
            "data_flags": data_flags,
            "previous_offset": previous_offset,
            "data_start": start_offset,
            "data_size": data_size,
        }

    def _dispatch_section(self, seg, sec, chunk_by_index):
        name = sec["name"]
        if name == "device":
            self._parse_device(seg, sec)
        elif name == "case":
            self._parse_case(seg, sec)
        elif name == "table":
            self._parse_table(seg, sec, chunk_by_index)
        elif name == "md5":
            self._parse_md5(seg, sec)
        elif name == "sha1":
            self._parse_sha1(seg, sec)
        elif name == "error":
            self._parse_error_table(seg, sec)
        # "sectors", "session", "increment", "restart", "memextents",
        # "next", "final", "done", "analytical" carry nothing this reader
        # needs to resolve chunk data, and the ls_* (0x20-0x23) sections
        # belong to EWF2-Lx01 (logical evidence), not Ex01.

    def _section_object(self, seg, sec):
        blob, clipped = self._read_bounded(seg, sec["data_start"],
                                           sec["data_size"], MAX_OBJECT_STRING)
        if clipped:
            self.findings.append(
                _t("ewf2.object_section_truncated") % sec["data_start"])
        if self.compression_method == COMPRESSION_LZ:
            text, over = inflate_capped(blob, MAX_OBJECT_STRING)
            if over:
                self.findings.append(
                    _t("ewf2.object_section_inflates_past") % sec["data_start"])
            if not text:
                self.findings.append(
                    _t("ewf2.object_section_decompress_failed")
                    % sec["data_start"])
                return {}
        else:
            text = blob
        try:
            return parse_object_string(_decode_object_string(text))
        except (UnicodeDecodeError, IndexError):
            self.findings.append(
                _t("ewf2.object_section_unparseable") % sec["data_start"])
            return {}

    def _parse_device(self, seg, sec):
        tags = self._section_object(seg, sec)
        self.header.update({
            "drive_serial_number": tags.get("sn"),
            "drive_model": tags.get("md"),
            "drive_label": tags.get("lb"),
        })
        if "bp" in tags:
            try:
                bp = int(tags["bp"])
                if bp in SECTOR_SIZES:
                    self.bytes_per_sector = bp
            except ValueError:
                pass
        if "ts" in tags:
            try:
                self.sector_count = int(tags["ts"])
            except ValueError:
                pass

    def _parse_case(self, seg, sec):
        tags = self._section_object(seg, sec)
        self.header.update({
            "description": tags.get("nm"), "case_number": tags.get("cn"),
            "evidence_number": tags.get("en"), "examiner": tags.get("ex"),
            "notes": tags.get("nt"), "acquiry_software": tags.get("av"),
            "acquiry_os": tags.get("os"),
        })
        if "sb" in tags:
            try:
                sb = int(tags["sb"])
                if 0 < sb * self.bytes_per_sector <= MAX_CHUNK_SIZE:
                    self.sectors_per_chunk = sb
                    self.chunk_size = sb * self.bytes_per_sector
            except ValueError:
                pass

    def _parse_table(self, seg, sec, chunk_by_index):
        head, _ = self._read_bounded(seg, sec["data_start"], 20, 20)
        if len(head) < 20:
            self.findings.append(_t("ewf2.table_header_truncated") % sec["data_start"])
            return
        first_chunk, entry_count = struct.unpack_from("<QI", head, 0)
        stored = struct.unpack_from("<I", head, 16)[0]
        if zlib.adler32(head[:16]) & 0xFFFFFFFF != stored:
            self.findings.append(
                _t("ewf2.table_header_checksum_mismatch") % sec["data_start"])
        if entry_count == 0 or entry_count > MAX_TABLE_ENTRIES:
            self.findings.append(
                _t("ewf2.table_entry_count_implausible") % entry_count)
            return

        entries_start = sec["data_start"] + 20 + 12  # 12-byte alignment pad
        raw, _ = self._read_bounded(seg, entries_start, entry_count * 16,
                                    entry_count * 16)
        if len(raw) < entry_count * 16:
            self.findings.append(
                _t("ewf2.table_entries_truncated") % sec["data_start"])
            entry_count = len(raw) // 16

        for i in range(entry_count):
            offset, data_size, flags = struct.unpack_from("<QII", raw, i * 16)
            chunk_by_index[first_chunk + i] = Chunk2(seg, offset, data_size, flags)

    def _parse_md5(self, seg, sec):
        d, _ = self._read_bounded(seg, sec["data_start"], 16, 16)
        if len(d) >= 16 and any(d):
            self.stored_md5 = d.hex()

    def _parse_sha1(self, seg, sec):
        d, _ = self._read_bounded(seg, sec["data_start"], 20, 20)
        if len(d) >= 20 and any(d):
            self.stored_sha1 = d.hex()

    def _parse_error_table(self, seg, sec):
        head, _ = self._read_bounded(seg, sec["data_start"], 20, 20)
        if len(head) < 20:
            return
        count = struct.unpack_from("<I", head, 0)[0]
        if count == 0 or count > MAX_TABLE_ENTRIES:
            return
        raw, _ = self._read_bounded(seg, sec["data_start"] + 20 + 12,
                                    count * 16, count * 16)
        for i in range(len(raw) // 16):
            start_sector, num_sectors = struct.unpack_from("<QI", raw, i * 16)
            self.error_ranges.append((start_sector, num_sectors))

    # --- chunk data ---------------------------------------------------------

    def _chunk(self, index):
        hit = self._cache.get(index)
        if hit is not None:
            self._cache.move_to_end(index)
            return hit
        if index < 0 or index >= len(self.chunks):
            return b""
        c = self.chunks[index]
        want = max(0, min(self.chunk_size, self.size - index * self.chunk_size))

        if c is None:
            # A chunk the table never named (see _parse()'s gap finding).
            data = bytes(want)
            self._cache[index] = data
            if len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)
            return data

        # PATTERNFILL is only meaningful alongside COMPRESSED; libewf
        # itself ignores it otherwise (EWF2 specification, "Chunk data
        # flags").
        if c.flags & CHUNK_PATTERN_FILL and c.flags & CHUNK_COMPRESSED:
            pattern = struct.pack("<Q", c.offset)
            reps = want // 8 + 2
            data = (pattern * reps)[:want]
            self._cache[index] = data
            if len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)
            return data

        cap = self.chunk_size + self.chunk_size // 64 + 64
        with self._io_lock:
            raw, _ = self._read_bounded(c.seg, c.offset, c.size, cap)
        if len(raw) < c.size:
            self.findings.append(
                _t("ewf2.chunk_declares_bytes_only_read")
                % (index, c.size, c.offset, c.seg, len(raw)))

        if c.flags & CHUNK_COMPRESSED:
            data, over, status = inflate_ended(raw, self.chunk_size)
            if over:
                self.findings.append(
                    _t("ewf2.chunk_inflates_past_chunk_size")
                    % (index, self.chunk_size))
            elif not data or status == DAMAGED:
                self.findings.append(
                    _t("ewf2.chunk_failed_to_decompress") % index)
                data = bytes(self.chunk_size)
            elif len(data) < want:
                self.findings.append(
                    _t("ewf2.chunk_incomplete")
                    % (index, "ends early" if status == STOPPED
                       else "decompressed short", len(data), want))
                data = data + bytes(want - len(data))
            elif status == STOPPED:
                self.findings.append(
                    _t("ewf2.chunk_ends_before_checksum") % index)
        elif c.flags & CHUNK_HAS_CHECKSUM:
            if len(raw) >= 4:
                payload, crc = raw[:-4], struct.unpack("<I", raw[-4:])[0]
                if zlib.adler32(payload) & 0xFFFFFFFF != crc:
                    self.findings.append(
                        _t("ewf2.chunk_failed_adler32") % index)
                data = payload
            else:
                data = raw
        else:
            data = raw

        self._cache[index] = data
        if len(self._cache) > self._cache_max:
            self._cache.popitem(last=False)
        return data

    def read_at(self, offset, length):
        if offset < 0:
            raise ValueError(_t("ewf2.negative_offset"))
        if offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        pos = offset
        remaining = length
        while remaining > 0:
            idx = pos // self.chunk_size
            within = pos % self.chunk_size
            data = self._chunk(idx)
            if not data:
                break
            take = data[within:within + remaining]
            if not take:
                break
            out += take
            pos += len(take)
            remaining -= len(take)
        return bytes(out)

    def read(self, n=-1):
        if n < 0:
            n = self.size - self._pos
        d = self.read_at(self._pos, n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            self._pos = off
        elif whence == os.SEEK_CUR:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos

    def verify(self, progress=None):
        import hashlib
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        step = max(1, len(self.chunks) // 100)
        for i in range(len(self.chunks)):
            d = self._chunk(i)
            md5.update(d)
            sha1.update(d)
            if progress and i % step == 0:
                progress(i / max(1, len(self.chunks)))
        result = {
            "computed_md5": md5.hexdigest(),
            "computed_sha1": sha1.hexdigest(),
            "stored_md5": self.stored_md5,
            "stored_sha1": self.stored_sha1,
        }
        result["md5_match"] = (self.stored_md5 is not None
                               and self.stored_md5 == result["computed_md5"])
        result["sha1_match"] = (self.stored_sha1 is not None
                                and self.stored_sha1 == result["computed_sha1"])
        return result

    def info(self):
        return {
            "format": "EWF v2 (Ex01)",
            "segments": [os.path.basename(p) for p in self.segment_paths],
            "size": self.size,
            "sector_count": self.sector_count,
            "bytes_per_sector": self.bytes_per_sector,
            "chunk_size": self.chunk_size,
            "compression": {COMPRESSION_NONE: "none", COMPRESSION_LZ: "zlib"}
                .get(self.compression_method, "unknown"),
            "acquisition": self.header,
            "error_ranges": [{"start_sector": s, "sector_count": n}
                             for s, n in self.error_ranges],
            "findings": self.findings,
        }
