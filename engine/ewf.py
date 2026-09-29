import bisect
import io
import os
import re
import struct
import threading

from . import vhdx as vhdx_mod
from . import vhd as vhd_mod
from . import ad1 as ad1_mod
from . import vmdk as vmdk_mod
from .inflate import DAMAGED, STOPPED, inflate_capped, inflate_ended
import zlib
from collections import OrderedDict

from .text import t as _t

EVF_SIG = b"EVF\x09\x0d\x0a\xff\x00"
LVF_SIG = b"LVF\x09\x0d\x0a\xff\x00"
EVF2_SIG = b"EVF2\x0d\x0a\x81\x00"

SECTION_DESC = 76
FILE_HEADER = 13

# Every size below comes from the segment file itself, so each read is bounded
# by what the format can legitimately hold rather than by what a damaged or
# hostile descriptor claims.  Real metadata sections are a few KB; EnCase's
# largest chunk is 32768 sectors.
MAX_METADATA_SECTION = 1 << 20
MAX_HEADER_SECTION = 16 << 20
MAX_CHUNK_SIZE = 64 << 20
MAX_TABLE_ENTRIES = 1 << 20
SECTOR_SIZES = (512, 1024, 2048, 4096)

class EwfError(Exception):
    pass

class Section:
    __slots__ = ("type", "start", "next_offset", "size", "data_start", "data_size")

    def __init__(self, type_, start, next_offset, size):
        self.type = type_
        self.start = start
        self.next_offset = next_offset
        self.size = size
        self.data_start = start + SECTION_DESC
        self.data_size = max(0, size - SECTION_DESC)

    def __repr__(self):
        return "<Section %s @%d size=%d>" % (self.type, self.start, self.size)

class Chunk:
    __slots__ = ("seg", "offset", "length", "compressed")

    def __init__(self, seg, offset, length, compressed):
        self.seg = seg
        self.offset = offset
        self.length = length
        self.compressed = compressed

def _has_ewf_signature(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(8) in (EVF_SIG, LVF_SIG, EVF2_SIG)
    except OSError:
        return False

def discover_segments(path):
    base, ext = os.path.splitext(path)
    if len(ext) != 4:
        return [path]
    stem = ext[1]
    directory = os.path.dirname(os.path.abspath(path)) or "."
    prefix = os.path.basename(base)
    pattern = re.compile(
        r"^" + re.escape(prefix) + r"\.(" + re.escape(stem) + r"[0-9]{2}|"
        + re.escape(stem.upper()) + r"[A-Z]{2}|[A-Z]{3})$",
        re.IGNORECASE,
    )
    found = []
    for name in os.listdir(directory):
        if pattern.match(name):
            found.append(os.path.join(directory, name))

    # Past .E99 segments are lettered (.EAA ... .ZZZ), which a sidecar such
    # as notes.txt also matches. Lettered names only count once .E99 exists,
    # and only when they carry the EWF signature.
    numbered = [p for p in found if os.path.splitext(p)[1][2:].isdigit()]
    if any(os.path.splitext(p)[1][2:] == "99" for p in numbered):
        found = numbered + [p for p in found
                            if p not in numbered and _has_ewf_signature(p)]
    else:
        found = numbered

    def order(p):
        e = os.path.splitext(p)[1][1:].upper()
        if e[1:].isdigit():
            return (0, int(e[1:]))
        return (1, e)

    return sorted(found, key=order) if found else [path]

class EwfImage:

    def __init__(self, path, cache_chunks=64):
        self.path = path
        self.segment_paths = discover_segments(path)
        self._handles = {}
        self.header = {}
        self.chunks = []
        self.chunk_size = 32768
        self.sectors_per_chunk = 64
        self.bytes_per_sector = 512
        self.sector_count = 0
        self.media_type = None
        self.compression_level = 0
        self.stored_md5 = None
        self.stored_sha1 = None
        self.sections = []
        self.findings = []
        self._cache = OrderedDict()
        self._cache_max = cache_chunks
        self._io_lock = threading.Lock()
        self._pos = 0
        self._seg_sizes = {}
        try:
            self._parse()
        except BaseException:
            # Otherwise a failed open leaves the evidence files held open,
            # which on Windows keeps them locked.
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
        """Read `size` bytes at `offset`, but never past the end of the
        segment and never more than `cap`.  Returns (data, clipped)."""
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

    def _parse(self):
        for seg_index, seg_path in enumerate(self.segment_paths):
            fh = self._fh(seg_index)
            sig = fh.read(8)
            if sig == EVF2_SIG:
                raise EwfError(
                    _t("ewf.ewf_v2_ex01_detected")
                )
            if sig not in (EVF_SIG, LVF_SIG):
                raise EwfError(_t("ewf.ewf_segment_file") % seg_path)
            fh.read(5)

            offset = FILE_HEADER
            pending_table = None
            sectors_extent = None
            guard = 0
            while True:
                guard += 1
                if guard > 200000:
                    self.findings.append("Section chain in segment %d exceeded "
                                         "sane length; stopped." % seg_index)
                    break
                sec = self._read_section(seg_index, offset)
                if sec is None:
                    break
                self.sections.append((seg_index, sec))

                if sec.type == "sectors":
                    sectors_extent = (sec.data_start, sec.start + sec.size)
                elif sec.type in ("volume", "disk"):
                    self._parse_volume(seg_index, sec)
                elif sec.type == "header2":
                    self._parse_header(seg_index, sec, utf16=True)
                elif sec.type == "header":
                    if not self.header:
                        self._parse_header(seg_index, sec, utf16=False)
                elif sec.type == "table":
                    pending_table = sec
                    self._parse_table(sec, seg_index, sectors_extent)
                elif sec.type == "digest":
                    self._parse_digest(seg_index, sec)
                elif sec.type == "hash":
                    self._parse_hash(seg_index, sec)

                if sec.type in ("next", "done"):
                    break
                if sec.next_offset <= sec.start:
                    self.findings.append(
                        "Section '%s' at %d has a non-advancing next pointer "
                        "(possible cyclic chain)." % (sec.type, sec.start))
                    break
                offset = sec.next_offset
            del pending_table

        if not self.chunks:
            raise EwfError(_t("ewf.chunk_table_found_evidence"))

        self.size = self.sector_count * self.bytes_per_sector
        if self.size == 0:
            self.size = len(self.chunks) * self.chunk_size

    def _read_section(self, seg, offset):
        raw, _ = self._read_bounded(seg, offset, SECTION_DESC, SECTION_DESC)
        if len(raw) < SECTION_DESC:
            if offset >= self._seg_size(seg):
                self.findings.append(
                    "Section pointer %d is past the end of segment %d; "
                    "stopped." % (offset, seg))
            return None
        type_ = raw[0:16].split(b"\x00")[0].decode("ascii", "replace")
        next_offset, size = struct.unpack("<QQ", raw[16:32])
        stored = struct.unpack("<I", raw[72:76])[0]
        if zlib.adler32(raw[:72]) & 0xFFFFFFFF != stored:
            self.findings.append(
                "Section descriptor checksum mismatch at offset %d (type '%s')."
                % (offset, type_))
        if not type_:
            return None
        return Section(type_, offset, next_offset, size)

    def _section_data(self, seg, sec, cap):
        data, clipped = self._read_bounded(seg, sec.data_start, sec.data_size,
                                           cap)
        if clipped:
            self.findings.append(
                "Section '%s' at %d declares %d bytes; only %d were read."
                % (sec.type, sec.start, sec.data_size, len(data)))
        return data

    def _parse_volume(self, seg, sec):
        data = self._section_data(seg, sec, MAX_METADATA_SECTION)
        if len(data) < 52:
            self.findings.append("Volume section too short to parse.")
            return
        self.media_type = data[0]
        chunk_count = struct.unpack("<I", data[4:8])[0]
        self.sectors_per_chunk = struct.unpack("<I", data[8:12])[0] or 64
        self.bytes_per_sector = struct.unpack("<I", data[12:16])[0] or 512
        self.sector_count = struct.unpack("<Q", data[16:24])[0]
        self.media_flags = data[36]
        self.compression_level = data[52] if len(data) > 52 else 0
        if self.bytes_per_sector not in SECTOR_SIZES:
            self.findings.append(
                "Volume section declares %d bytes per sector; using 512."
                % self.bytes_per_sector)
            self.bytes_per_sector = 512
        if self.sectors_per_chunk * self.bytes_per_sector > MAX_CHUNK_SIZE:
            self.findings.append(
                "Volume section declares %d sectors per chunk; using 64."
                % self.sectors_per_chunk)
            self.sectors_per_chunk = 64
        self.chunk_size = self.sectors_per_chunk * self.bytes_per_sector
        self._declared_chunks = chunk_count

    def _parse_header(self, seg, sec, utf16):
        blob = self._section_data(seg, sec, MAX_HEADER_SECTION)
        text, over = inflate_capped(blob, 1 << 20)
        if over:
            self.findings.append("Header section inflates to more than 1 MB; "
                                 "only that much was read.")
        if not text:
            self.findings.append("Header section failed to decompress.")
            return
        try:
            text = text.decode("utf-16-le" if utf16 else "latin-1")
        except UnicodeDecodeError:
            text = text.decode("latin-1")
        lines = [ln for ln in text.replace("\r\n", "\n").split("\n") if ln.strip()]
        for i, line in enumerate(lines):
            if line.startswith("main") and i + 2 < len(lines):
                keys = lines[i + 1].split("\t")
                vals = lines[i + 2].split("\t")
                names = {
                    "a": "description", "c": "case_number", "n": "evidence_number",
                    "e": "examiner", "t": "notes", "av": "acquiry_software",
                    "ov": "acquiry_os", "m": "acquisition_date",
                    "u": "system_date", "p": "password_hash", "dc": "unknown_dc",
                    "pid": "process_id", "r": "compression",
                }
                for k, v in zip(keys, vals):
                    if v:
                        self.header[names.get(k, k)] = v
                break

    def _parse_table(self, sec, seg_index, sectors_extent):
        head, _ = self._read_bounded(seg_index, sec.data_start, 24, 24)
        if len(head) < 24:
            self.findings.append("Table section header truncated.")
            return
        entry_count = struct.unpack("<I", head[0:4])[0]
        base_offset = struct.unpack("<Q", head[8:16])[0]
        stored = struct.unpack("<I", head[20:24])[0]
        if zlib.adler32(head[:20]) & 0xFFFFFFFF != stored:
            self.findings.append("Table header checksum mismatch at %d." % sec.start)
        if entry_count == 0 or entry_count > MAX_TABLE_ENTRIES:
            self.findings.append("Table entry count %d is implausible." % entry_count)
            return

        raw, _ = self._read_bounded(seg_index, sec.data_start + 24,
                                    entry_count * 4, entry_count * 4)
        if len(raw) < entry_count * 4:
            self.findings.append("Table entries truncated at %d." % sec.start)
            entry_count = len(raw) // 4
        entries = struct.unpack("<%dI" % entry_count, raw[: entry_count * 4])

        limit = sectors_extent[1] if sectors_extent else None
        for i, e in enumerate(entries):
            compressed = bool(e & 0x80000000)
            off = base_offset + (e & 0x7FFFFFFF)
            if i + 1 < entry_count:
                nxt = base_offset + (entries[i + 1] & 0x7FFFFFFF)
                length = nxt - off
            elif limit is not None:
                length = limit - off
            else:
                length = self.chunk_size + 4
            if length <= 0:
                self.findings.append(
                    "Chunk %d in segment %d has non-positive length; "
                    "falling back to nominal size." % (i, seg_index))
                length = self.chunk_size + 4
            self.chunks.append(Chunk(seg_index, off, length, compressed))

    def _parse_digest(self, seg, sec):
        d = self._section_data(seg, sec, MAX_METADATA_SECTION)
        if len(d) >= 36:
            md5, sha1 = d[0:16], d[16:36]
            if any(md5):
                self.stored_md5 = md5.hex()
            if any(sha1):
                self.stored_sha1 = sha1.hex()

    def _parse_hash(self, seg, sec):
        d = self._section_data(seg, sec, MAX_METADATA_SECTION)
        if len(d) >= 16 and any(d[0:16]) and not self.stored_md5:
            self.stored_md5 = d[0:16].hex()

    def _chunk(self, index):
        hit = self._cache.get(index)
        if hit is not None:
            self._cache.move_to_end(index)
            return hit
        if index < 0 or index >= len(self.chunks):
            return b""
        c = self.chunks[index]
        # A stored chunk is at most the chunk plus its checksum; a compressed
        # one can exceed that only by zlib's small worst-case expansion.
        cap = self.chunk_size + self.chunk_size // 64 + 64
        with self._io_lock:
            raw, _ = self._read_bounded(c.seg, c.offset, c.length, cap)
        # Running into the end of the segment is not itself remarkable (a
        # final chunk sized from the nominal chunk size does); a length past
        # what any chunk can be, or an offset outside the file, is.
        if c.length > cap or c.offset >= self._seg_size(c.seg):
            self.findings.append(
                "Chunk %d declares %d bytes at offset %d in segment %d; "
                "only %d could be read." % (index, c.length, c.offset, c.seg,
                                            len(raw)))
        if c.compressed:
            data, over, status = inflate_ended(raw, self.chunk_size)
            want = max(0, min(self.chunk_size,
                              self.size - index * self.chunk_size))
            if over:
                self.findings.append(
                    "Chunk %d inflates past the %d-byte chunk size this "
                    "image declares; it was cut off there."
                    % (index, self.chunk_size))
            elif not data or status == DAMAGED:
                # Output before zlib rejected the stream is not trustworthy:
                # the checksum that would vouch for it comes at the end.
                self.findings.append("Chunk %d failed to decompress; "
                                     "zero-filled." % index)
                data = b"\x00" * self.chunk_size
            elif len(data) < want:
                # A stream that stops early still yields a plausible prefix.
                # Returned short, it would also end every read at this chunk.
                self.findings.append(
                    "Chunk %d is incomplete: its compressed data %s and gave "
                    "%d of %d bytes; the rest reads as zeros."
                    % (index, "ends early" if status == STOPPED
                       else "decompressed short", len(data), want))
                data = data + b"\x00" * (want - len(data))
            elif status == STOPPED:
                self.findings.append(
                    "Chunk %d's compressed data ends before its checksum, so "
                    "the chunk could not be verified." % index)
        else:
            if len(raw) >= 4:
                payload, crc = raw[:-4], struct.unpack("<I", raw[-4:])[0]
                if zlib.adler32(payload) & 0xFFFFFFFF != crc:
                    self.findings.append("Chunk %d failed its Adler-32 "
                                         "integrity check." % index)
                data = payload
            else:
                data = raw
        self._cache[index] = data
        if len(self._cache) > self._cache_max:
            self._cache.popitem(last=False)
        return data

    def read_at(self, offset, length):
        if offset < 0:
            raise ValueError(_t("ewf.negative_offset"))
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

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = off
        elif whence == io.SEEK_CUR:
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
            "format": "EWF v1 (E01)",
            "segments": [os.path.basename(p) for p in self.segment_paths],
            "size": self.size,
            "sector_count": self.sector_count,
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_chunk": self.sectors_per_chunk,
            "chunk_size": self.chunk_size,
            "chunk_count": len(self.chunks),
            "compression_level": self.compression_level,
            "compressed_chunks": sum(1 for c in self.chunks if c.compressed),
            "media_type": self.media_type,
            "media_flags": getattr(self, "media_flags", 0),
            "stored_md5": self.stored_md5,
            "stored_sha1": self.stored_sha1,
            "acquisition": dict(self.header),
            "findings": list(self.findings),
        }

# Split raw sets are named by the acquisition tool, and every tool names them
# differently: FTK Imager writes .001, Guymager .000 with as many digits as the
# disk needs, and `split` writes .aa or, with -d, .00.  Matching only three
# digits meant a wider set opened as its first piece alone, silently.
SPLIT_NUMERIC = re.compile(r"^(.+)\.([0-9]{2,5})$")
SPLIT_ALPHA = re.compile(r"^(.+)\.([a-z]{2,4})$")


def _split_piece(name):
    """(prefix, index, style, width) for a split-raw piece name, or None.
    style is "n" for numeric pieces and "a" for `split`'s alphabetic ones."""
    m = SPLIT_NUMERIC.match(name)
    if m:
        return m.group(1), int(m.group(2)), "n", len(m.group(2))
    m = SPLIT_ALPHA.match(name)
    if m:
        index = 0
        for ch in m.group(2):
            index = index * 26 + (ord(ch) - 97)
        return m.group(1), index, "a", len(m.group(2))
    return None


def _piece_name(prefix, index, style, width):
    """The name a piece would carry in this set's own numbering."""
    if style == "n":
        return "%s.%0*d" % (prefix, width, index)
    letters = []
    for _ in range(width):
        letters.append(chr(97 + index % 26))
        index //= 26
    return "%s.%s" % (prefix, "".join(reversed(letters)))


def discover_raw_segments(path):
    """The pieces of a split raw set (name.001, name.0000, name.aa, ...) that
    `path` belongs to, in order, and findings about the set. A lone file, or
    one without a piece-shaped extension, is its own set."""
    directory, name = os.path.split(os.path.abspath(path))
    piece = _split_piece(name)
    if not piece:
        return [path], []
    prefix, opened, style, opened_width = piece
    widths = {}
    for sib in os.listdir(directory):
        s = _split_piece(sib)
        if s and s[0] == prefix and s[2] == style and \
                os.path.isfile(os.path.join(directory, sib)):
            widths[s[1]] = s[3]
    if style == "a":
        # `split`'s default suffixes always begin at aa; without that rule any
        # two files differing in their extension would look like one disk.
        if 0 not in widths:
            return [path], []
        first = 0
    else:
        first = 0 if 0 in widths else 1
    run = []
    while first + len(run) in widths:
        run.append(first + len(run))
    # first itself can be absent from widths (e.g. numeric style opened at
    # piece 2 with neither 0 nor 1 present) -- fall back to the opened
    # piece's own width so the "missing piece" finding below can still name
    # it, rather than skipping the finding entirely.
    width = widths.get(first, opened_width)
    findings = []
    if style == "n":
        odd = [n for n in run if widths[n] != width]
        if odd:
            findings.append(
                "Split raw set mixes %d- and %d-digit numbering (%s and %s); "
                "the pieces were joined in numeric order."
                % (width, widths[odd[0]],
                   _piece_name(prefix, first, style, width),
                   _piece_name(prefix, odd[0], style, widths[odd[0]])))
    missing = _piece_name(prefix, first + len(run), style, width)
    beyond = sorted(n for n in widths if n > first + len(run))
    if opened not in run and len(widths) == 1:
        # Nothing beside it is named as another piece, so there is no set to
        # say is incomplete: capture.2024 is as likely a year as a piece.
        return [path], [
            "%s is named like piece %d of a split raw set, but no other "
            "piece is beside it, so it is read as a single image. If it was "
            "part of a set, it starts partway through the disk."
            % (name, opened)]
    if opened not in run:
        return [path], [
            "%s is read on its own: its split raw set is missing %s, so "
            "this piece starts partway through the disk." % (name, missing)]
    if beyond:
        findings.append(
            "Split raw set is missing %s; %s after it %s not read."
            % (missing, ", ".join(
                _piece_name(prefix, n, style, widths[n]) for n in beyond),
               "is" if len(beyond) == 1 else "are"))
    if len(run) == 1:
        return [path], findings
    return [os.path.join(directory, _piece_name(prefix, n, style, widths[n]))
            for n in run], findings


class RawImage:

    MAX_OPEN = 16

    def __init__(self, path):
        self.path = path
        self.segment_paths, self.findings = discover_raw_segments(path)
        self._starts, self._sizes = [], []
        total = 0
        for p in self.segment_paths:
            self._starts.append(total)
            self._sizes.append(os.path.getsize(p))
            total += self._sizes[-1]
        self.size = total
        # Every piece but the last is cut to the same size; a piece that is
        # not has lost or gained data, and every offset after it is suspect.
        for p, n in zip(self.segment_paths[1:-1], self._sizes[1:-1]):
            if n != self._sizes[0]:
                self.findings.append(
                    "%s is %d bytes where %s is %d; data after it may be at "
                    "the wrong offset." % (os.path.basename(p), n,
                                           os.path.basename(
                                               self.segment_paths[0]),
                                           self._sizes[0]))
        if len(self.segment_paths) > 1 and self._sizes[-1] > self._sizes[0]:
            self.findings.append(
                "%s is larger than the pieces before it; the set may be "
                "damaged." % os.path.basename(self.segment_paths[-1]))
        self._handles = OrderedDict()
        self._fh_for(0)
        self.bytes_per_sector = 512
        self.header = {}
        self.stored_md5 = None
        self.stored_sha1 = None
        self._pos = 0
        self._io_lock = threading.Lock()

    def _fh_for(self, index):
        fh = self._handles.get(index)
        if fh is None:
            fh = open(self.segment_paths[index], "rb")
            self._handles[index] = fh
            while len(self._handles) > self.MAX_OPEN:
                self._handles.popitem(last=False)[1].close()
        else:
            self._handles.move_to_end(index)
        return fh

    def read_at(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        with self._io_lock:
            index = bisect.bisect_right(self._starts, offset) - 1
            while length > 0 and index < len(self.segment_paths):
                within = offset - self._starts[index]
                take = min(length, self._sizes[index] - within)
                if take > 0:
                    fh = self._fh_for(index)
                    fh.seek(within)
                    piece = fh.read(take)
                    out += piece
                    if len(piece) < take:
                        break
                    offset += take
                    length -= take
                index += 1
        return bytes(out)

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = off
        elif whence == io.SEEK_CUR:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos

    def close(self):
        while self._handles:
            self._handles.popitem()[1].close()

    def verify(self, progress=None):
        import hashlib
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        pos = 0
        while pos < self.size:
            d = self.read_at(pos, 1 << 20)
            if not d:
                break
            md5.update(d); sha1.update(d)
            pos += len(d)
            if progress:
                progress(pos / self.size)
        return {"computed_md5": md5.hexdigest(), "computed_sha1": sha1.hexdigest(),
                "stored_md5": None, "stored_sha1": None,
                "md5_match": None, "sha1_match": None}

    def info(self):
        return {"format": "Raw / dd",
                "segments": [os.path.basename(p) for p in self.segment_paths],
                "size": self.size, "bytes_per_sector": 512,
                "chunk_size": 1 << 20, "acquisition": {},
                "findings": list(self.findings)}

UNSUPPORTED = (
    (b"AFF\x00", "Advanced Forensic Format (AFF)",
     "Not implemented. Convert to E01 or raw first."),
    (b"EVF2\x0d\x0a\x81\x00", "EWF2 / Ex01",
     "The version 2 container format is not implemented; version 1 (E01) is. "
     "Convert, or re-acquire as E01."),
    (b"COWD", "VMware COW disk",
     "An older VMware container with its own indirection. Convert it first."),
    (b"conectix", "Virtual PC / Hyper-V disk (VHD)",
     "The file starts with a VHD footer, but no valid footer was found at "
     "its end, where the format keeps the authoritative one. It is most "
     "likely a truncated copy of a dynamic or differencing VHD, or damaged "
     "at the end, so the disk cannot be read. Obtain a complete copy."),
    (b"QFI\xfb", "QEMU copy-on-write (QCOW/QCOW2)",
     "QCOW stores data through an indirection table. Convert with qemu-img."),
    (b"<<< Oracle VM VirtualBox Disk Image >>>", "VirtualBox disk (VDI)",
     "VDI has its own block map. Convert with VBoxManage or qemu-img."),
    (b"SQLite format 3\x00", "SQLite database",
     "This is a database, not a disk image. Open it from within a "
     "filesystem, where the SQLite viewer will read it."),
    (b"Rar!\x1a\x07", "RAR archive",
     "An archive is not a disk image. Extract it first."),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive",
     "An archive is not a disk image. Extract it first."),
)

class UnsupportedContainer(Exception):

    def __init__(self, fmt, advice):
        super().__init__("%s. %s" % (fmt, advice))
        self.format = fmt
        self.advice = advice

def identify_unsupported(head):
    for magic, fmt, advice in UNSUPPORTED:
        if head.startswith(magic):
            return fmt, advice
    return None

def open_image(path):
    with open(path, "rb") as fh:
        head = fh.read(64)
    sig = head[:8]
    if sig in (EVF_SIG, LVF_SIG) or sig == EVF2_SIG:
        return EwfImage(path)
    if vmdk_mod.looks_like_vmdk(head):
        try:
            return vmdk_mod.VmdkImage(path)
        except vmdk_mod.VmdkError as exc:
            raise UnsupportedContainer(_t("ewf.vmware_vmdk") % exc.message,
                                       exc.advice)
    if ad1_mod.looks_like_ad1(head):
        try:
            return ad1_mod.Ad1Image(path)
        except ad1_mod.Ad1Error as exc:
            raise UnsupportedContainer(_t("ewf.accessdata_ad1") % exc.message,
                                       exc.advice)
    if sig == vhdx_mod.SIGNATURE:
        try:
            return vhdx_mod.VhdxImage(path)
        except vhdx_mod.VhdxError as exc:
            raise UnsupportedContainer(_t("ewf.hyper_v_vhdx") % exc.message,
                                       exc.advice)
    if vhd_mod.looks_like_vhd(path):
        try:
            return vhd_mod.VhdImage(path)
        except vhd_mod.VhdError as exc:
            raise UnsupportedContainer(_t("ewf.virtual_pc_vhd") % exc.message,
                                       exc.advice)
    known = identify_unsupported(head)
    if known:
        raise UnsupportedContainer(*known)
    return RawImage(path)

class OffsetReader:

    def __init__(self, source, offset, size, label=""):
        self.source = source
        self.offset = offset
        self.size = size
        self.label = label
        self.bytes_per_sector = getattr(source, "bytes_per_sector", 512)
        self._pos = 0

    def read_at(self, offset, length):
        # A negative offset is still a positive offset in the image once
        # self.offset is added, so without this it would quietly return bytes
        # from whatever lies before this region and present them as ours.
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        return self.source.read_at(self.offset + offset,
                                   min(length, self.size - offset))

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
        self._pos += len(d)
        return d

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = off
        elif whence == io.SEEK_CUR:
            self._pos += off
        else:
            self._pos = self.size + off
        return self._pos
