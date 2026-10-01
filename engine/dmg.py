import bisect
import bz2
import hashlib
import io
import lzma
import os
import plistlib
import struct
import threading
import zlib

from . import lzfse
from .text import t as _t

# Apple's UDIF disk image. A 512-byte "koly" trailer at the end of the file
# points at an XML property list; its "blkx" entries are tables of chunks, each
# a run of 512-byte sectors that is stored raw, as zeros, or compressed.
# Everything in the trailer and tables is big-endian.
SIGNATURE = b"koly"
TRAILER = 512
SECTOR = 512

# Chunk types in a block table.
ZERO, RAW, IGNORE = 0x00000000, 0x00000001, 0x00000002
ADC, ZLIB, BZIP2, LZFSE, LZMA = (0x80000004, 0x80000005, 0x80000006,
                                 0x80000007, 0x80000008)
COMMENT, TERMINATOR = 0x7FFFFFFE, 0xFFFFFFFF
_NAMES = {ZERO: "zero fill", RAW: "raw", IGNORE: "unused", ADC: "ADC",
          ZLIB: "zlib", BZIP2: "bzip2", LZFSE: "LZFSE", LZMA: "LZMA"}
_COMPRESSED = (ZLIB, BZIP2, LZFSE, LZMA)

MAX_XML = 1 << 26
MAX_CHUNKS = 1 << 22
MAX_CHUNK_BYTES = 1 << 26        # what one compressed chunk may decompress to
_CACHE_BYTES = 1 << 26
ENCRYPTED_HEADERS = (b"encrcdsa", b"cdsaencr")


class DmgError(Exception):

    def __init__(self, message, advice=""):
        Exception.__init__(self, message)
        self.message = message
        self.advice = advice


def looks_like_dmg(tail):
    """Whether the last 512 bytes of a file are a UDIF trailer: the signature,
    version 4 and a header size of 512. Checked together because the
    signature is only four bytes and sits at the end of the file."""
    if len(tail) < TRAILER or tail[:4] != SIGNATURE:
        return False
    version, size = struct.unpack_from(">II", tail, 4)
    return version == 4 and size == TRAILER


def parse_trailer(raw):
    """The fields Strata uses from a UDIF trailer, or DmgError."""
    if not looks_like_dmg(raw):
        raise DmgError(_t("dmg.not_a_dmg"))
    (flags, running, data_off, data_len, rsrc_off, rsrc_len, seg_no,
     seg_count) = struct.unpack_from(">IQQQQQII", raw, 12)
    xml_off, xml_len = struct.unpack_from(">QQ", raw, 216)
    variant, sectors = struct.unpack_from(">IQ", raw, 488)
    return {"flags": flags, "data_off": data_off, "data_len": data_len,
            "rsrc_off": rsrc_off, "rsrc_len": rsrc_len, "segment": seg_no,
            "segments": seg_count, "xml_off": xml_off, "xml_len": xml_len,
            "variant": variant, "sectors": sectors}


def parse_block_table(blob):
    """(first sector, sector count, data offset, [chunk]) from one "mish"
    table; a chunk is (type, sector, sectors, offset, length), with the
    sector counted from the table's first sector."""
    if len(blob) < 204 or blob[:4] != b"mish":
        raise DmgError(_t("dmg.table_damaged"))
    first, count, base = struct.unpack_from(">QQQ", blob, 8)
    n = struct.unpack_from(">I", blob, 200)[0]
    if n > MAX_CHUNKS or 204 + 40 * n > len(blob):
        raise DmgError(_t("dmg.table_damaged"))
    chunks = []
    for i in range(n):
        kind, _comment, sector, sectors, off, length = struct.unpack_from(
            ">IIQQQQ", blob, 204 + 40 * i)
        if kind == TERMINATOR:
            break
        if kind == COMMENT:
            continue
        chunks.append((kind, sector, sectors, off, length))
    return first, count, base, chunks


class DmgImage:
    """An Apple disk image (UDIF). Chunks are decompressed as they are read;
    ranges the tables do not cover read as zeros and are reported. Images
    that are encrypted, split over several files, or that use a compression
    Strata does not read are refused whole, so a partly zero disk is never
    shown as the disk. The koly trailer, plist and tables are container
    metadata and are not exposed."""

    def __init__(self, path, fh):
        # The caller opens the file once, and this reader takes over the
        # handle (closing it in close()); `path` is only its name.
        self.path = path
        self.segment_paths = [path]
        self.findings = []
        self._pos = 0
        self._io_lock = threading.Lock()
        self._fh = fh
        self._cache = {}
        self._cache_bytes = 0
        self._noted = set()
        try:
            self._open()
        except BaseException:
            self.close()
            raise

    def _file_read(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self._file_size:
            return b""
        length = min(length, self._file_size - offset)
        with self._io_lock:
            self._fh.seek(offset)
            return self._fh.read(length)

    def _note_once(self, key, text):
        if key not in self._noted:
            self._noted.add(key)
            self.findings.append(text)

    def _open(self):
        self._file_size = size = os.fstat(self._fh.fileno()).st_size
        if size < TRAILER:
            raise DmgError(_t("dmg.not_a_dmg"))
        info = parse_trailer(self._file_read(size - TRAILER, TRAILER))
        self.trailer = info
        if self._file_read(0, 8) in ENCRYPTED_HEADERS:
            raise DmgError(
                _t("dmg.encrypted"),
                "The image is encrypted. Decrypt it with hdiutil (or "
                "convert it to an unencrypted image) first.")
        if info["segments"] > 1:
            raise DmgError(
                _t("dmg.segmented") % info["segments"],
                "Only single-file images are read. Join the segments with "
                "hdiutil convert first.")
        if not 0 < info["xml_len"] <= MAX_XML \
                or info["xml_off"] + info["xml_len"] > size - TRAILER:
            raise DmgError(_t("dmg.plist_unreadable"))
        try:
            plist = plistlib.loads(self._file_read(info["xml_off"],
                                                   info["xml_len"]))
            tables = plist["resource-fork"]["blkx"]
        except Exception:
            raise DmgError(_t("dmg.plist_unreadable"))
        self.size = info["sectors"] * SECTOR
        self._data_off = info["data_off"]
        runs = []
        self._table_names = []
        for entry in tables:
            try:
                blob = bytes(entry["Data"])
                first, _count, base, chunks = parse_block_table(blob)
            except DmgError:
                raise
            except Exception:
                raise DmgError(_t("dmg.table_damaged"))
            self._table_names.append(str(entry.get("Name", "")))
            for kind, sector, sectors, off, length in chunks:
                runs.append((first + sector, sectors, kind, base + off, length))
        if len(runs) > MAX_CHUNKS:
            raise DmgError(_t("dmg.table_damaged"))
        runs.sort()
        bad = sorted({kind for _s, _n, kind, _o, _l in runs
                      if kind not in (ZERO, RAW, IGNORE) + _COMPRESSED})
        if bad:
            raise DmgError(
                _t("dmg.chunk_type_unsupported") % ", ".join(
                    _NAMES.get(k, "0x%08X" % k) for k in bad),
                "Convert the image with hdiutil convert -format UDRW "
                "first.")
        end = 0
        for start, sectors, kind, off, length in runs:
            if start < end:
                raise DmgError(_t("dmg.chunks_overlap"))
            end = start + sectors
            if kind in (RAW, *_COMPRESSED):
                if sectors * SECTOR > MAX_CHUNK_BYTES and kind != RAW:
                    raise DmgError(_t("dmg.chunk_too_large") % (
                        sectors * SECTOR))
                if self._data_off + off + length > size - TRAILER:
                    raise DmgError(_t("dmg.chunk_outside_file"))
                if kind == RAW and length < sectors * SECTOR:
                    raise DmgError(_t("dmg.chunk_outside_file"))
        if end * SECTOR > self.size:
            self.findings.append(_t("dmg.tables_longer") % (
                end * SECTOR, self.size))
        self._runs = runs
        self._starts = [r[0] for r in runs]
        covered = sum(r[1] for r in runs)
        if covered < info["sectors"]:
            self.findings.append(_t("dmg.tables_shorter") % (
                covered * SECTOR, self.size))
        self.bytes_per_sector = SECTOR

    # -- reading -------------------------------------------------------------

    def _chunk(self, index):
        """The decompressed content of run `index`, or None for a zero run."""
        start, sectors, kind, off, length = self._runs[index]
        if kind in (ZERO, IGNORE):
            return None
        want = sectors * SECTOR
        if kind == RAW:
            return self._file_read(self._data_off + off, want)
        got = self._cache.get(index)
        if got is not None:
            return got
        blob = self._file_read(self._data_off + off, length)
        try:
            data = self._decompress(kind, blob, want)
        except (zlib.error, OSError, EOFError, ValueError,
                lzma.LZMAError) as exc:
            self._note_once(("bad", index), _t("dmg.chunk_failed") % (
                start * SECTOR, exc))
            data = b""
        if len(data) != want:
            if data:
                self._note_once(("short", index), _t("dmg.chunk_short") % (
                    start * SECTOR, len(data), want))
            data = data[:want] + bytes(max(0, want - len(data)))
        if self._cache_bytes + want > _CACHE_BYTES:
            self._cache.clear()
            self._cache_bytes = 0
        self._cache[index] = data
        self._cache_bytes += want
        return data

    @staticmethod
    def _decompress(kind, blob, want):
        if kind == ZLIB:
            return zlib.decompressobj().decompress(blob, want)
        if kind == BZIP2:
            return bz2.BZ2Decompressor().decompress(blob, want)
        if kind == LZMA:
            return lzma.LZMADecompressor().decompress(blob, want)
        try:
            return lzfse.decode(blob, max_size=want)
        except lzfse.LzfseError as exc:
            raise ValueError(str(exc))

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        out = bytearray()
        while length > 0:
            sector, within = divmod(offset, SECTOR)
            i = bisect.bisect_right(self._starts, sector) - 1
            if i >= 0 and sector < self._runs[i][0] + self._runs[i][1]:
                start, sectors, kind, _o, _l = self._runs[i]
                span = (start + sectors) * SECTOR - offset
                n = min(length, span)
                data = self._chunk(i)
                if data is None:
                    out += bytes(n)
                else:
                    at = offset - start * SECTOR
                    piece = data[at:at + n]
                    out += piece + bytes(n - len(piece))
            else:
                # a gap between runs: zeros, up to the next run
                nxt = self._starts[i + 1] * SECTOR if i + 1 < len(
                    self._starts) else self.size
                n = min(length, max(1, nxt - offset))
                out += bytes(n)
            offset += n
            length -= n
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
        fh = getattr(self, "_fh", None)
        if fh is not None:
            fh.close()

    def verify(self, progress=None):
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
        return {"computed_md5": md5.hexdigest(),
                "computed_sha1": sha1.hexdigest(),
                "stored_md5": None, "stored_sha1": None,
                "md5_match": None, "sha1_match": None,
                "note": _t("dmg.dmg_stores_acquisition_hash")}

    def info(self):
        kinds = {}
        for _s, _n, kind, _o, _l in self._runs:
            name = _NAMES.get(kind, "0x%08X" % kind)
            kinds[name] = kinds.get(name, 0) + 1
        acquisition = {
            "container size on disk": self._file_size,
            "block tables": len(self._table_names),
            "chunks": len(self._runs),
            "chunk types": ", ".join("%s: %d" % kv
                                     for kv in sorted(kinds.items())),
        }
        return {
            "format": "Apple disk image (DMG)",
            "segments": [os.path.basename(self.path)],
            "size": self.size,
            "bytes_per_sector": self.bytes_per_sector,
            "chunk_size": 1 << 20,
            "acquisition": acquisition,
            "findings": list(self.findings),
        }
