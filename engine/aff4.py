import os
import re
import struct
import threading
import zlib

from .text import t as _t

# Advanced Forensic Format 4 (AFF4): a ZIP64 container whose image content is
# either a Map (a virtual address space over one or more ImageStreams) or a
# bare ImageStream read directly. Written from the published AFF4 Standard
# v1.0a (github.com/aff4/Standard), cross-checked byte-for-byte against
# pyaff4 (the reference implementation) -- which was necessary: the standard
# text's own description of the ImageStream bevy index (an 8+4-byte "bevy
# offset / chunk size" struct) does not match what pyaff4 actually reads and
# writes, confirmed by building real AFF4 files with pyaff4 and inspecting
# the bytes directly. The real, empirically-verified layout is a 12-byte
# (offset, reserved, stored length) record per chunk -- see _read_chunk().
#
# Only the common case is read: a single ZIP64 volume (not a striped or
# segmented multi-volume set), with a DiskImage/Image whose dataStream is a
# Map or a bare ImageStream, zlib/deflate-compressed or stored chunks.
# Encrypted streams, multi-volume containers, and metadata this reader's
# small Turtle parser cannot make sense of are refused with the reason, not
# guessed at.

EOCD_SIG = b"PK\x05\x06"
EOCD64_SIG = b"PK\x06\x06"
EOCD64_LOC_SIG = b"PK\x06\x07"
CENTRAL_SIG = b"PK\x01\x02"
LOCAL_SIG = b"PK\x03\x04"

RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
AFF4 = "http://aff4.org/Schema#"
T_IMAGE = AFF4 + "Image"
T_CONTIGUOUS_IMAGE = AFF4 + "ContiguousImage"
T_DISK_IMAGE = AFF4 + "DiskImage"
T_MAP = AFF4 + "Map"
T_IMAGE_STREAM = AFF4 + "ImageStream"
P_DATA_STREAM = AFF4 + "dataStream"
P_DEPENDENT_STREAM = AFF4 + "dependentStream"
P_SIZE = AFF4 + "size"
P_CHUNK_SIZE = AFF4 + "chunkSize"
P_CHUNKS_IN_SEGMENT = AFF4 + "chunksInSegment"
P_COMPRESSION = AFF4 + "compressionMethod"
P_MAP_GAP_DEFAULT = AFF4 + "mapGapDefaultStream"
P_HASH = AFF4 + "hash"

# The AFF4 Standard v1.0a lists RFC1951 (raw DEFLATE) for this URI, but every
# real producer observed (pyaff4, and the files it writes) uses zlib-wrapped
# DEFLATE (RFC1950) in practice -- confirmed by inspecting real compressed
# chunk bytes (a 0x78 0x9c zlib header). Both RFC1950 and RFC1951 resource
# URIs are accepted and read the same way (Python's zlib.decompress()
# handles the zlib wrapper; see _read_chunk()).
DEFLATE_URIS = (
    "https://tools.ietf.org/html/rfc1951",
    "http://tools.ietf.org/html/rfc1951",
    "https://www.ietf.org/rfc/rfc1950.txt",
    "http://www.ietf.org/rfc/rfc1950.txt",
    "https://tools.ietf.org/html/rfc1950",
)

DEFAULT_CHUNK_SIZE = 32 * 1024
DEFAULT_CHUNKS_IN_SEGMENT = 1024
BEVY_CACHE = 4


class Aff4Error(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice


def looks_like_aff4(path):
    """AFF4 is a ZIP64 container with no reserved signature of its own, so
    it is deliberately not matched by magic bytes -- that would misdetect
    (and then refuse) every ordinary ZIP archive. Detection is by extension
    first; Aff4Image's own parsing then requires the interior AFF4 markers
    (the volume URI in the Zip comment, and information.turtle) before
    accepting the file, so a plain .aff4-named ZIP is refused with a clear
    reason rather than misread as a disk image."""
    return path.lower().endswith(".aff4")


# --- a minimal Turtle parser -------------------------------------------

_STOP = set(" \t\r\n.;,#<\"")


def _tokenize(text):
    toks = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "@":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "-"):
                j += 1
            toks.append(("at", text[i + 1:j]))
            i = j
            continue
        if c == "<":
            j = text.find(">", i + 1)
            if j < 0:
                raise Aff4Error(_t("aff4.turtle_unterminated_uri"))
            toks.append(("uri", text[i + 1:j]))
            i = j + 1
            continue
        if c == '"':
            j = i + 1
            buf = []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                else:
                    buf.append(text[j])
                    j += 1
            if j >= n:
                raise Aff4Error(_t("aff4.turtle_unterminated_string"))
            value = "".join(buf)
            j += 1
            dtype = None
            if text[j:j + 2] == "^^":
                j += 2
                if j < n and text[j] == "<":
                    k = text.find(">", j + 1)
                    if k < 0:
                        raise Aff4Error(_t("aff4.turtle_unterminated_uri"))
                    dtype = text[j + 1:k]
                    j = k + 1
                else:
                    k = j
                    while k < n and (text[k].isalnum() or text[k] in ":_-"):
                        k += 1
                    dtype = text[j:k]
                    j = k
            toks.append(("lit", value, dtype))
            i = j
            continue
        if c in ".;,":
            toks.append(("punct", c))
            i += 1
            continue
        j = i
        while j < n and text[j] not in _STOP:
            j += 1
        if j == i:
            raise Aff4Error(_t("aff4.turtle_unexpected_character") % c)
        toks.append(("bare", text[i:j]))
        i = j
    return toks


def _parse_turtle(text):
    """{subject_uri: {predicate_uri: [('uri', value) | ('lit', value, dtype)]}}
    for exactly the Turtle subset real AFF4 producers use: @prefix lines,
    and `subject pred obj (, obj)* (; pred obj (, obj)*)* .` statements.
    Not a general RDF/Turtle parser -- anything outside this raises
    Aff4Error rather than being silently misread."""
    toks = _tokenize(text)
    prefixes = {}
    graph = {}
    i, n = 0, len(toks)

    def resolve(tok):
        kind = tok[0]
        if kind == "uri":
            return ("uri", tok[1])
        if kind == "lit":
            dtype = tok[2]
            if dtype and ":" in dtype and not dtype.startswith("http"):
                p, local = dtype.split(":", 1)
                if p not in prefixes:
                    raise Aff4Error(_t("aff4.turtle_undeclared_prefix") % p)
                dtype = prefixes[p] + local
            return ("lit", tok[1], dtype)
        if kind == "bare":
            w = tok[1]
            if w == "a":
                return ("uri", RDF_TYPE)
            if ":" in w:
                p, local = w.split(":", 1)
                if p not in prefixes:
                    raise Aff4Error(_t("aff4.turtle_undeclared_prefix") % p)
                return ("uri", prefixes[p] + local)
            return ("lit", w, None)
        raise Aff4Error(_t("aff4.turtle_unexpected_token"))

    while i < n:
        if toks[i][0] == "at":
            if toks[i][1] != "prefix" or i + 3 >= n or \
                    toks[i + 1][0] != "bare" or not toks[i + 1][1].endswith(":") \
                    or toks[i + 2][0] != "uri" or toks[i + 3] != ("punct", "."):
                raise Aff4Error(_t("aff4.turtle_bad_prefix_line"))
            prefixes[toks[i + 1][1][:-1]] = toks[i + 2][1]
            i += 4
            continue
        subj = resolve(toks[i])
        if subj[0] != "uri":
            raise Aff4Error(_t("aff4.turtle_subject_not_a_uri"))
        i += 1
        preds = graph.setdefault(subj[1], {})
        while True:
            if i >= n:
                raise Aff4Error(_t("aff4.turtle_truncated_statement"))
            pred = resolve(toks[i])
            i += 1
            if pred[0] != "uri":
                raise Aff4Error(_t("aff4.turtle_predicate_not_a_uri"))
            values = preds.setdefault(pred[1], [])
            while True:
                if i >= n:
                    raise Aff4Error(_t("aff4.turtle_truncated_statement"))
                values.append(resolve(toks[i]))
                i += 1
                if i < n and toks[i] == ("punct", ","):
                    i += 1
                    continue
                break
            if i < n and toks[i] == ("punct", ";"):
                i += 1
                continue
            break
        if i >= n or toks[i] != ("punct", "."):
            raise Aff4Error(_t("aff4.turtle_statement_not_terminated"))
        i += 1
    return graph


def _types(graph, subject):
    return {v[1] for v in graph.get(subject, {}).get(RDF_TYPE, ())
            if v[0] == "uri"}


def _first(graph, subject, pred):
    vals = graph.get(subject, {}).get(pred, ())
    return vals[0] if vals else None


def _uri(value):
    return value[1] if value and value[0] == "uri" else None


def _int(value):
    if not value or value[0] != "lit":
        return None
    try:
        return int(value[1])
    except ValueError:
        return None


def _str(value):
    return value[1] if value and value[0] == "lit" else None


_IMAGE_TYPES = (T_DISK_IMAGE, T_CONTIGUOUS_IMAGE, T_IMAGE)


def _find_image(graph):
    candidates = [s for s, preds in graph.items() if P_DATA_STREAM in preds]
    if not candidates:
        return None
    for want in _IMAGE_TYPES:
        for s in candidates:
            if want in _types(graph, s):
                return s
    return candidates[0]


_SYMBOLIC_SINGLE = re.compile(r"^SymbolicStream([0-9A-Fa-f]{2})$")


def _symbolic_pattern(target_uri):
    """The repeated-byte pattern a symbolic stream URI names, or None if
    `target_uri` does not look like one (AFF4 Standard v1.0a section 4.4)."""
    tail = re.split(r"[#:/]", target_uri)[-1]
    if tail in ("Zero", "SymbolicStream00"):
        return b"\x00"
    m = _SYMBOLIC_SINGLE.match(tail)
    if m:
        return bytes([int(m.group(1), 16)])
    if tail == "UnknownData":
        return b"UNKNOWN"
    if tail == "UnreadableData":
        return b"UNREADABLEDATA"
    return None


def _repeated_stream(pattern, offset, length):
    """Bytes [offset, offset+length) of the infinite stream formed by tiling
    `pattern` across contiguous 1MiB-aligned chunks, each restarting the
    pattern at its own start (AFF4 Standard v1.0a section 4.4)."""
    mib = 1 << 20
    out = bytearray()
    pos, remaining = offset, length
    while remaining > 0:
        within = pos % mib
        take = min(remaining, mib - within)
        reps = within // len(pattern) + take // len(pattern) + 2
        out += (pattern * reps)[within:within + take]
        pos += take
        remaining -= take
    return bytes(out)


# --- the ZIP64 container layer ------------------------------------------

class _ZipEntry:
    __slots__ = ("name", "method", "compressed", "size", "local_offset",
                 "data_offset")


class _Zip:
    """A lazy, seek-based ZIP64 central-directory reader: only the central
    directory (always small) is read into memory, never the member data,
    so a multi-gigabyte AFF4 image is never loaded whole. Field layout
    follows the same ZIP spec as engine/archive.py's in-memory reader;
    this one is separate because archive.py's `Zip` requires the entire
    file as a `bytes` object up front, which a forensic disk image cannot
    afford to be."""

    def __init__(self, fh, file_size):
        self._fh = fh
        self._lock = threading.Lock()
        self.file_size = file_size
        self.comment = b""
        self.entries = {}
        self._parse()

    def _read(self, offset, length):
        with self._lock:
            self._fh.seek(offset)
            return self._fh.read(length)

    def _parse(self):
        tail_len = min(self.file_size, 65536 + 22)
        tail = self._read(self.file_size - tail_len, tail_len)
        i = tail.rfind(EOCD_SIG)
        if i < 0:
            raise Aff4Error(_t("aff4.no_end_of_central_directory"))
        eocd = self.file_size - tail_len + i
        (_, _disk, _cd_disk, _here, total, cd_size, cd_off, clen) = \
            struct.unpack_from("<IHHHHIIH", tail, i)
        if clen:
            self.comment = tail[i + 22:i + 22 + clen]

        if cd_off == 0xFFFFFFFF or total == 0xFFFF or \
                cd_size == 0xFFFFFFFF:
            locator = self._read(max(0, eocd - 20), 20)
            if locator[:4] != EOCD64_LOC_SIG:
                raise Aff4Error(_t("aff4.zip64_locator_missing"))
            rel = struct.unpack_from("<Q", locator, 8)[0]
            rec = self._read(rel, 56)
            if rec[:4] != EOCD64_SIG:
                raise Aff4Error(_t("aff4.zip64_record_missing"))
            total, cd_size, cd_off = struct.unpack_from("<QQQ", rec, 32)[0], \
                struct.unpack_from("<Q", rec, 40)[0], \
                struct.unpack_from("<Q", rec, 48)[0]

        if not (0 <= cd_off < self.file_size):
            raise Aff4Error(_t("aff4.central_directory_offset_invalid"))
        central = self._read(cd_off, min(cd_size, self.file_size - cd_off))
        pos = 0
        seen = 0
        while pos + 46 <= len(central) and central[pos:pos + 4] == CENTRAL_SIG:
            (_, _ver, _need, flags, method, _mtime, _mdate, _crc, csize,
             usize, nlen, elen, clen2, _d, _ia, _ea, loff) = \
                struct.unpack_from("<IHHHHHHIIIHHHHHII", central, pos)
            name = central[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
            extra = central[pos + 46 + nlen:pos + 46 + nlen + elen]
            e = _ZipEntry()
            e.name = name
            e.method = method
            e.compressed = csize
            e.size = usize
            e.local_offset = loff
            e.data_offset = None
            if usize == 0xFFFFFFFF or csize == 0xFFFFFFFF or \
                    loff == 0xFFFFFFFF:
                self._zip64_extra(e, extra)
            self.entries[name] = e
            pos += 46 + nlen + elen + clen2
            seen += 1
            if seen > 2_000_000:
                break
        if not self.entries:
            raise Aff4Error(_t("aff4.central_directory_empty"))

    @staticmethod
    def _zip64_extra(e, extra):
        pos = 0
        while pos + 4 <= len(extra):
            hid, hlen = struct.unpack_from("<HH", extra, pos)
            body = extra[pos + 4:pos + 4 + hlen]
            if hid == 0x0001:
                off = 0
                for attr in ("size", "compressed", "local_offset"):
                    if getattr(e, attr) == 0xFFFFFFFF and off + 8 <= len(body):
                        setattr(e, attr, struct.unpack_from("<Q", body, off)[0])
                        off += 8
            pos += 4 + hlen

    def _resolve_data_offset(self, e):
        if e.data_offset is None:
            head = self._read(e.local_offset, 30)
            if len(head) < 30 or head[:4] != LOCAL_SIG:
                raise Aff4Error(
                    _t("aff4.local_header_missing") % e.name)
            nlen, elen = struct.unpack_from("<HH", head, 26)
            e.data_offset = e.local_offset + 30 + nlen + elen
        return e.data_offset

    def read_member(self, name, max_bytes=None):
        e = self.entries.get(name)
        if e is None:
            raise Aff4Error(_t("aff4.member_not_found") % name)
        data_offset = self._resolve_data_offset(e)
        want = e.compressed if max_bytes is None else min(e.compressed, max_bytes)
        raw = self._read(data_offset, want)
        if e.method == 0:
            return raw
        if e.method == 8:
            try:
                return zlib.decompress(raw, -15)
            except zlib.error:
                raise Aff4Error(_t("aff4.member_decompress_failed") % name)
        raise Aff4Error(_t("aff4.member_compression_unsupported") % e.method)


def _volume_relative(volume_urn, urn):
    """The Zip-member path for `urn`, relative to the volume root (AFF4
    Standard v1.0a section 5.1): only the portion of a URI after the
    volume's own GUID is used as a path inside the volume. A URI outside
    the volume (another AFF4 object entirely, as in a striped or segmented
    multi-volume set) is out of scope for this reader."""
    prefix = volume_urn + "/"
    if not urn.startswith(prefix):
        raise Aff4Error(_t("aff4.map_target_not_in_volume") % urn)
    return urn[len(prefix):]


# --- the ImageStream (bevy/chunk) layer ----------------------------------

class _ImageStream:
    """One AFF4 ImageStream: chunked, optionally-compressed data under
    `<urn>/%08d` (bevy) and `<urn>/%08d.index` (bevy index) members."""

    def __init__(self, zf, urn, graph, volume_urn, findings):
        self.zf = zf
        self.urn = urn
        self.rel = _volume_relative(volume_urn, urn)
        self.findings = findings
        self.size = _int(_first(graph, urn, P_SIZE)) or 0
        self.chunk_size = _int(_first(graph, urn, P_CHUNK_SIZE)) \
            or DEFAULT_CHUNK_SIZE
        self.chunks_per_segment = _int(
            _first(graph, urn, P_CHUNKS_IN_SEGMENT)) or DEFAULT_CHUNKS_IN_SEGMENT
        compression = _uri(_first(graph, urn, P_COMPRESSION))
        if compression is not None and compression not in DEFLATE_URIS:
            raise Aff4Error(_t("aff4.compression_method_unsupported") % compression)
        self._bevy_cache = []  # [(bevy_id, [(off, length), ...] or None, bevy_bytes)]
        self._lock = threading.Lock()

    def _bevy_name(self, bevy_id):
        return "%s/%08d" % (self.rel, bevy_id)

    def _load_bevy(self, bevy_id):
        """(index, bevy_bytes) for `bevy_id`, or (None, b"") if its index is
        damaged -- a malformed index affects only this bevy's worth of
        chunks (each read as zero, with a finding), not the whole image,
        the same resilience EWF's chunk decoder applies to one bad chunk."""
        with self._lock:
            for entry in self._bevy_cache:
                if entry[0] == bevy_id:
                    return entry[1], entry[2]
            name = self._bevy_name(bevy_id)
            index_raw = self.zf.read_member(name + ".index")
            if len(index_raw) % 12:
                self.findings.append(
                    _t("aff4.bevy_index_malformed") % name)
                index = None
                bevy_bytes = b""
            else:
                n = len(index_raw) // 12
                fields = struct.unpack("<" + "III" * n, index_raw)
                index = [(fields[i * 3], fields[i * 3 + 2]) for i in range(n)]
                bevy_bytes = self.zf.read_member(name)
            entry = (bevy_id, index, bevy_bytes)
            self._bevy_cache.append(entry)
            if len(self._bevy_cache) > BEVY_CACHE:
                self._bevy_cache.pop(0)
            return index, bevy_bytes

    def _read_chunk(self, chunk_id):
        bevy_id, local = divmod(chunk_id, self.chunks_per_segment)
        index, bevy_bytes = self._load_bevy(bevy_id)
        if index is None:
            return bytes(self.chunk_size)
        if local >= len(index):
            self.findings.append(
                _t("aff4.bevy_chunk_missing") % (local, bevy_id))
            return bytes(self.chunk_size)
        off, length = index[local]
        raw = bevy_bytes[off:off + length]
        if length == self.chunk_size:
            return raw
        try:
            return zlib.decompress(raw)
        except zlib.error:
            self.findings.append(
                _t("aff4.chunk_decompress_failed") % (chunk_id, self.urn))
            return bytes(self.chunk_size)

    def read_at(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        remaining = length
        pos = offset
        while remaining > 0:
            chunk_id, within = divmod(pos, self.chunk_size)
            chunk = self._read_chunk(chunk_id)
            take = min(remaining, self.chunk_size - within)
            out += chunk[within:within + take]
            pos += take
            remaining -= take
        return bytes(out)


# --- the Map layer --------------------------------------------------------

class _MapRange:
    __slots__ = ("map_offset", "length", "target_offset", "target_id")


class _Map:
    """One AFF4 Map: a virtual address space over one or more dependent
    streams (ImageStreams, or symbolic streams like aff4:Zero), described
    by the `<urn>/map` (binary ranges) and `<urn>/idx` (target URNs)
    segments."""

    def __init__(self, zf, urn, graph, streams, volume_urn):
        self.zf = zf
        self.urn = urn
        self.rel = _volume_relative(volume_urn, urn)
        self.graph = graph
        self.streams = streams
        self.size = _int(_first(graph, urn, P_SIZE)) or 0
        gap = _uri(_first(graph, urn, P_MAP_GAP_DEFAULT))
        self.gap_pattern = _symbolic_pattern(gap) if gap else b"\x00"

        idx_raw = zf.read_member("%s/idx" % self.rel)
        self.targets = idx_raw.decode("utf-8", "replace").split("\n") \
            if idx_raw else []
        self.targets = [t for t in self.targets if t]

        map_raw = zf.read_member("%s/map" % self.rel)
        if len(map_raw) % 28:
            raise Aff4Error(_t("aff4.map_entries_malformed") % urn)
        self.ranges = []
        for i in range(0, len(map_raw), 28):
            mo, ln, to, tid = struct.unpack_from("<QQQI", map_raw, i)
            r = _MapRange()
            r.map_offset, r.length, r.target_offset, r.target_id = mo, ln, to, tid
            self.ranges.append(r)
        self.ranges.sort(key=lambda r: r.map_offset)

        # A target this volume does not have means a striped or segmented
        # multi-volume AFF4 set (section 7) -- refused up front, like DMG's
        # and QCOW2's segmented/backing-file images, rather than reading
        # part of the disk and silently zero-filling the rest.
        for r in self.ranges:
            target = self._target_stream(r.target_id)
            if _symbolic_pattern(target) is None and target not in self.streams:
                raise Aff4Error(_t("aff4.map_target_not_in_volume") % target)

    def _target_stream(self, target_id):
        if not (0 <= target_id < len(self.targets)):
            raise Aff4Error(_t("aff4.map_target_id_out_of_range") % target_id)
        return self.targets[target_id]

    def read_at(self, offset, length):
        if offset < 0 or length <= 0 or (self.size and offset >= self.size):
            return b""
        if self.size:
            length = min(length, self.size - offset)
        out = bytearray()
        pos = offset
        end = offset + length
        for r in self.ranges:
            if r.map_offset + r.length <= pos:
                continue
            if r.map_offset >= end:
                break
            if r.map_offset > pos:
                out += _repeated_stream(self.gap_pattern, pos, r.map_offset - pos)
                pos = r.map_offset
            read_from = pos - r.map_offset
            take = min(end, r.map_offset + r.length) - pos
            out += self._read_target(r.target_id, r.target_offset + read_from, take)
            pos += take
        if pos < end:
            out += _repeated_stream(self.gap_pattern, pos, end - pos)
        return bytes(out)

    def _read_target(self, target_id, offset, length):
        target = self._target_stream(target_id)
        pattern = _symbolic_pattern(target)
        if pattern is not None:
            return _repeated_stream(pattern, offset, length)
        stream = self.streams.get(target)
        if stream is None:
            raise Aff4Error(_t("aff4.map_target_not_in_volume") % target)
        return stream.read_at(offset, length)


# --- the volume ------------------------------------------------------------

class Aff4Image:
    """An AFF4 volume holding one disk image. Only the common case is read:
    a single ZIP64 volume (not a striped or segmented set) with one
    DiskImage/Image whose dataStream is a Map or a bare ImageStream."""

    def __init__(self, path, fh):
        self.path = path
        self.segment_paths = [path]
        self.findings = []
        self._pos = 0
        self._fh = fh
        try:
            self._open()
        except BaseException:
            self.close()
            raise

    def _open(self):
        file_size = os.fstat(self._fh.fileno()).st_size
        self.zf = _Zip(self._fh, file_size)
        self._file_size = file_size

        volume_urn = None
        if self.zf.comment.startswith(b"aff4://"):
            volume_urn = self.zf.comment.decode("utf-8", "replace").strip()
        elif "container.description" in self.zf.entries:
            volume_urn = self.zf.read_member(
                "container.description").decode("utf-8", "replace").strip()
        if not volume_urn:
            raise Aff4Error(_t("aff4.volume_uri_not_found"))
        self.volume_urn = volume_urn

        if "information.turtle" not in self.zf.entries:
            raise Aff4Error(_t("aff4.no_information_turtle"))
        turtle = self.zf.read_member("information.turtle").decode(
            "utf-8", "replace")
        self.graph = _parse_turtle(turtle)

        image_urn = _find_image(self.graph)
        if image_urn is not None:
            data_stream_urn = _uri(_first(self.graph, image_urn, P_DATA_STREAM))
            if not data_stream_urn:
                raise Aff4Error(_t("aff4.image_has_no_data_stream"))
        else:
            # No wrapping Image/DiskImage object -- a bare ImageStream is
            # itself a complete, valid image (AFF4 Standard v1.0a section
            # 3.3 requires only the ImageStream object, not a wrapper), and
            # real producers do write exactly this shape.
            streams = [s for s in self.graph if T_IMAGE_STREAM in _types(self.graph, s)]
            if len(streams) != 1:
                raise Aff4Error(_t("aff4.no_image_found"))
            data_stream_urn = image_urn = streams[0]
        self.image_urn = image_urn

        self.streams = {}
        root_types = _types(self.graph, data_stream_urn)
        if T_IMAGE_STREAM in root_types:
            root = _ImageStream(self.zf, data_stream_urn, self.graph,
                                self.volume_urn, self.findings)
            self.streams[data_stream_urn] = root
            self._root = root
        elif T_MAP in root_types:
            # aff4:dependentStream is how the standard says a Map names its
            # backing ImageStream(s), but real output (pyaff4) does not
            # always set it -- confirmed by inspecting a real file's own
            # information.turtle. Falling back to every ImageStream the
            # graph declares is harmless: a Map's own idx file is what
            # actually selects which targets it uses.
            candidates = {_uri(d) for d in self.graph.get(
                data_stream_urn, {}).get(P_DEPENDENT_STREAM, ())}
            candidates.discard(None)
            candidates |= {s for s in self.graph
                          if T_IMAGE_STREAM in _types(self.graph, s)}
            for dep_urn in candidates:
                self.streams[dep_urn] = _ImageStream(
                    self.zf, dep_urn, self.graph, self.volume_urn, self.findings)
            self._root = _Map(self.zf, data_stream_urn, self.graph,
                              self.streams, self.volume_urn)
            if not self._root.size:
                self._root.size = _int(_first(
                    self.graph, image_urn, P_SIZE)) or 0
        else:
            raise Aff4Error(_t("aff4.data_stream_not_map_or_image_stream"))

        self.size = self._root.size
        if not self.size:
            raise Aff4Error(_t("aff4.image_size_unknown"))

        self.stored_md5 = None
        self.stored_sha1 = None
        for v in self.graph.get(image_urn, {}).get(P_HASH, ()):
            if v[0] != "lit" or not v[2]:
                continue
            if v[2].endswith("#MD5") or v[2] == "MD5":
                self.stored_md5 = v[1].lower()
            elif v[2].endswith("#SHA1") or v[2] == "SHA1":
                self.stored_sha1 = v[1].lower()

    def read_at(self, offset, length):
        return self._root.read_at(offset, length)

    def read(self, n=-1):
        d = self.read_at(self._pos, self.size - self._pos if n < 0 else n)
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

    def close(self):
        fh = getattr(self, "_fh", None)
        if fh is not None:
            fh.close()

    def verify(self, progress=None):
        import hashlib
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        pos = 0
        while pos < self.size:
            d = self.read_at(pos, 1 << 20)
            if not d:
                break
            md5.update(d)
            sha1.update(d)
            pos += len(d)
            if progress:
                progress(pos / self.size)
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
        kind = "Map over %d stream(s)" % len(self.streams) \
            if isinstance(self._root, _Map) else "bare ImageStream"
        return {
            "format": "AFF4",
            "segments": [os.path.basename(self.path)],
            "size": self.size,
            "bytes_per_sector": 512,
            "acquisition": {
                "container size on disk": self._file_size,
                "volume URI": self.volume_urn,
                "image URI": self.image_urn,
                "data stream": kind,
            },
            "findings": list(self.findings),
        }
