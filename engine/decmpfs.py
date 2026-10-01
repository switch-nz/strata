"""Apple's transparent file compression (decmpfs), as found on HFS+ and APFS.

A compressed file has the BSD flag UF_COMPRESSED and an extended attribute
`com.apple.decmpfs` whose value starts with a 16-byte header:

    "fpmc"  (magic)      4 bytes
    type                 uint32, little-endian
    uncompressed size    uint64, little-endian

followed, for the "attribute" types, by the compressed data itself. For the
"resource fork" types the data is in the file's resource fork instead, cut
into blocks of 64 KiB of uncompressed data each:

  type  codec          where
   3    zlib           attribute
   4    zlib           resource fork
   7    LZVN           attribute
   8    LZVN           resource fork
   9/10 stored raw     (attribute / resource fork; not read here)
  11/12 LZFSE          (attribute / resource fork)

The numbering and the block tables follow libfshfs and Apple's published
LZFSE sources; zlib, LZVN and LZFSE are decoded. A block that is stored
uncompressed starts with a marker byte (0xFF for zlib and LZFSE, 0x06 for
LZVN) and carries the data after it."""

import struct
import zlib

from .text import t as _t

MAGIC = b"fpmc"
HEADER_SIZE = 16
BLOCK_SIZE = 0x10000
MAX_INLINE_SIZE = 1 << 28        # what an attribute-held file may inflate to
MAX_BLOCKS = 1 << 22
_BLOCK_CACHE = 16

CODEC_ZLIB, CODEC_LZVN, CODEC_RAW, CODEC_LZFSE = "zlib", "LZVN", "raw", "LZFSE"

# type -> (codec, held in the resource fork?)
TYPES = {
    3: (CODEC_ZLIB, False), 4: (CODEC_ZLIB, True),
    7: (CODEC_LZVN, False), 8: (CODEC_LZVN, True),
    9: (CODEC_RAW, False), 10: (CODEC_RAW, True),
    11: (CODEC_LZFSE, False), 12: (CODEC_LZFSE, True),
}
SUPPORTED = (CODEC_ZLIB, CODEC_LZVN, CODEC_LZFSE)


class DecmpfsError(ValueError):
    pass


def parse_header(value):
    """The decmpfs header held in an attribute value, or None if the value is
    not one. `supported` says whether the codec is one this module decodes."""
    if value is None or len(value) < HEADER_SIZE or value[:4] != MAGIC:
        return None
    kind, size = struct.unpack_from("<IQ", value, 4)
    codec, in_fork = TYPES.get(kind, (None, False))
    return {"type": kind, "size": size, "codec": codec,
            "in_resource_fork": in_fork,
            "supported": codec in SUPPORTED,
            "payload": bytes(value[HEADER_SIZE:])}


def describe(header):
    """A short phrase for an examiner: what this file is compressed with."""
    if header["codec"]:
        return "%s (type %d, %s)" % (
            header["codec"], header["type"],
            "resource fork" if header["in_resource_fork"] else "attribute")
    return "unknown (type %d)" % header["type"]


# -- LZVN ----------------------------------------------------------------------
# The opcode classes are those of Apple's lzvn_decode_base.c.

_EOS, _NOP, _UDEF = "eos", "nop", "udef"
_SML_D, _MED_D, _LRG_D, _PRE_D = "sml_d", "med_d", "lrg_d", "pre_d"
_SML_M, _LRG_M, _SML_L, _LRG_L = "sml_m", "lrg_m", "sml_l", "lrg_l"


def _classify(op):
    if op == 0x06:
        return _EOS
    if op in (0x0E, 0x16):
        return _NOP
    if op in (0x1E, 0x26, 0x2E, 0x36, 0x3E) or 0x70 <= op <= 0x7F \
            or 0xD0 <= op <= 0xDF:
        return _UDEF
    if 0xA0 <= op <= 0xBF:
        return _MED_D
    if op == 0xE0:
        return _LRG_L
    if 0xE1 <= op <= 0xEF:
        return _SML_L
    if op == 0xF0:
        return _LRG_M
    if op >= 0xF1:
        return _SML_M
    if op & 7 == 7:
        return _LRG_D
    if op & 7 == 6:
        return _PRE_D
    return _SML_D


_OPCODES = [_classify(i) for i in range(256)]


def lzvn_decode(src, out_size):
    """Decode an LZVN stream to `out_size` bytes (or to its end-of-stream
    marker, whichever comes first). Raises DecmpfsError for an opcode LZVN
    does not define, a match that reaches before the start of the output, or
    a stream that stops in the middle of an instruction."""
    out = bytearray()
    n = len(src)
    i = 0
    dist = 0
    while len(out) < out_size:
        if i >= n:
            raise DecmpfsError(_t("decmpfs.lzvn_truncated"))
        op = src[i]
        kind = _OPCODES[op]
        lit = match = 0
        if kind == _EOS:
            break
        if kind == _NOP:
            i += 1
            continue
        if kind == _UDEF:
            raise DecmpfsError(_t("decmpfs.lzvn_opcode") % op)
        if kind == _SML_D:
            if i + 2 > n:
                raise DecmpfsError(_t("decmpfs.lzvn_truncated"))
            lit = op >> 6
            match = ((op >> 3) & 7) + 3
            dist = ((op & 7) << 8) | src[i + 1]
            i += 2
        elif kind == _MED_D:
            if i + 3 > n:
                raise DecmpfsError(_t("decmpfs.lzvn_truncated"))
            lit = (op >> 3) & 3
            low = src[i + 1] | (src[i + 2] << 8)
            match = (((op & 7) << 2) | (low & 3)) + 3
            dist = low >> 2
            i += 3
        elif kind == _LRG_D:
            if i + 3 > n:
                raise DecmpfsError(_t("decmpfs.lzvn_truncated"))
            lit = op >> 6
            match = ((op >> 3) & 7) + 3
            dist = src[i + 1] | (src[i + 2] << 8)
            i += 3
        elif kind == _PRE_D:
            lit = op >> 6
            match = ((op >> 3) & 7) + 3
            i += 1
        elif kind == _SML_M:
            match = op & 0xF
            i += 1
        elif kind == _LRG_M:
            if i + 2 > n:
                raise DecmpfsError(_t("decmpfs.lzvn_truncated"))
            match = src[i + 1] + 16
            i += 2
        elif kind == _SML_L:
            lit = op & 0xF
            i += 1
        else:                                   # _LRG_L
            if i + 2 > n:
                raise DecmpfsError(_t("decmpfs.lzvn_truncated"))
            lit = src[i + 1] + 16
            i += 2
        if lit:
            if i + lit > n:
                raise DecmpfsError(_t("decmpfs.lzvn_truncated"))
            out += src[i:i + lit]
            i += lit
        if match:
            if dist == 0 or dist > len(out):
                raise DecmpfsError(_t("decmpfs.lzvn_distance"))
            start = len(out) - dist
            if dist >= match:
                out += out[start:start + match]
            else:
                # The window overlaps what it is copying: a repeating
                # pattern, as byte-by-byte copying makes it.
                pattern = bytes(out[start:])
                reps = -(-match // dist)
                out += (pattern * reps)[:match]
    return bytes(out[:out_size])


# -- one block -------------------------------------------------------------------

def _zlib_block(data, expected):
    if data[:1] and data[0] & 0x0F == 0x0F:     # stored: 0xFF, then the data
        return bytes(data[1:1 + expected])
    d = zlib.decompressobj()
    try:
        return d.decompress(bytes(data), expected)
    except zlib.error as exc:
        raise DecmpfsError(_t("decmpfs.zlib_damaged") % exc)


def _lzvn_block(data, expected):
    if data[:1] == b"\x06":                     # stored: 0x06, then the data
        return bytes(data[1:1 + expected])
    return lzvn_decode(data, expected)


def _lzfse_block(data, expected):
    if data[:1] == b"\xff":                     # stored: 0xFF, then the data
        return bytes(data[1:1 + expected])
    from . import lzfse                         # (it uses this module's LZVN)
    try:
        return lzfse.decode(data, max_size=max(expected, 1))[:expected]
    except lzfse.LzfseError as exc:
        raise DecmpfsError(str(exc))


_BLOCK_DECODERS = {CODEC_ZLIB: _zlib_block, CODEC_LZVN: _lzvn_block,
                   CODEC_LZFSE: _lzfse_block}


class Compressed:
    """The decompressed contents of a file, read by offset. `resource` is a
    callable read(offset, length) over the file's resource fork (for the types
    that keep their data there) and `resource_size` its length. What could not
    be decoded reads as zeros, and `findings` says so."""

    def __init__(self, header, resource=None, resource_size=0):
        if not header["supported"]:
            raise DecmpfsError(_t("decmpfs.unsupported") % describe(header))
        self.header = header
        self.size = header["size"]
        self.findings = []
        self._decode = _BLOCK_DECODERS[header["codec"]]
        self._resource = resource
        self._rsize = resource_size
        self._cache = {}
        self._noted = set()
        self._inline = None
        self._table = None
        if header["in_resource_fork"]:
            if resource is None:
                raise DecmpfsError(_t("decmpfs.no_resource_fork"))
            self._table = self._block_table()
        elif self.size > MAX_INLINE_SIZE:
            raise DecmpfsError(_t("decmpfs.too_large") % self.size)

    def _note(self, key, text):
        if key not in self._noted:
            self._noted.add(key)
            self.findings.append(text)

    def _read_fork(self, off, n):
        if off < 0 or n < 0 or off + n > self._rsize:
            raise DecmpfsError(_t("decmpfs.table_bounds"))
        got = self._resource(off, n)
        if len(got) < n:
            raise DecmpfsError(_t("decmpfs.table_bounds"))
        return got

    def _block_table(self):
        """[(offset, length)] of each compressed block in the resource fork."""
        want = -(-self.size // BLOCK_SIZE)
        if self.header["codec"] == CODEC_ZLIB:
            head = self._read_fork(0, 8)
            base = struct.unpack_from(">I", head, 0)[0]
            if base != 0x100:
                raise DecmpfsError(_t("decmpfs.table_layout"))
            count_at = base + 4
            count = struct.unpack_from("<I", self._read_fork(count_at, 4))[0]
            if count == 0 or count > MAX_BLOCKS:
                raise DecmpfsError(_t("decmpfs.table_layout"))
            raw = self._read_fork(count_at + 4, count * 8)
            table = []
            for k in range(count):
                off, length = struct.unpack_from("<II", raw, k * 8)
                table.append((count_at + off, length))
        else:
            first = struct.unpack_from("<I", self._read_fork(0, 4))[0]
            count = first // 4
            if first % 4 or count == 0 or count > MAX_BLOCKS:
                raise DecmpfsError(_t("decmpfs.table_layout"))
            raw = self._read_fork(0, first)
            offs = list(struct.unpack("<%dI" % count, raw))
            offs.append(self._rsize)
            table = [(offs[k], offs[k + 1] - offs[k]) for k in range(count)]
            if any(length < 0 for _o, length in table):
                raise DecmpfsError(_t("decmpfs.table_layout"))
        if len(table) != want:
            self._note("blocks", _t("decmpfs.block_count") % (
                len(table), want))
        return table

    def _block(self, index):
        got = self._cache.get(index)
        if got is not None:
            return got
        expected = min(BLOCK_SIZE, self.size - index * BLOCK_SIZE)
        data = b""
        try:
            if self._table is None:
                # The whole file is in the attribute; it is one "block".
                data = self._decode(self.header["payload"], self.size)
                expected = self.size
            elif index < len(self._table):
                off, length = self._table[index]
                data = self._decode(self._read_fork(off, length), expected)
            else:
                raise DecmpfsError(_t("decmpfs.block_missing") % index)
        except DecmpfsError as exc:
            self._note(("bad", index), _t("decmpfs.block_failed") % (
                index, exc))
        if len(data) < expected:
            if data:
                self._note(("short", index), _t("decmpfs.block_short") % (
                    index, len(data), expected))
            data = data + bytes(expected - len(data))
        if len(self._cache) >= _BLOCK_CACHE:
            self._cache.clear()
        self._cache[index] = data
        return data

    def read_at(self, offset, length):
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, self.size - offset)
        if self._table is None:
            return self._block(0)[offset:offset + length]
        out = bytearray()
        while length > 0:
            index, within = divmod(offset, BLOCK_SIZE)
            piece = self._block(index)[within:within + length]
            if not piece:
                break
            out += piece
            offset += len(piece)
            length -= len(piece)
        return bytes(out)
