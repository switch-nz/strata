"""LZFSE decompression, as used by Apple for compressed files (decmpfs types
11 and 12) and for disk images (DMG "ULFO").

An LZFSE stream is a series of blocks, each starting with a four-byte magic:

    bvx$  end of the stream
    bvx-  raw bytes follow (a 32-bit count, then the bytes)
    bvxn  LZVN-compressed bytes (raw size, payload size, then the payload)
    bvx1  LZFSE block, frequency tables stored in full
    bvx2  LZFSE block, frequency tables packed

An LZFSE block holds literals, coded four at a time with finite state
entropy (FSE), and a list of (literal length, match length, distance)
triplets, coded with three more FSE streams. Both are read backwards from the
end of their payload. A match may reach back into any earlier block.

The layouts and tables follow Apple's published reference implementation
(github.com/lzfse/lzfse); the decoder here was checked against its output.
Output is capped (`max_size`) so a damaged or hostile stream cannot grow
without bound."""

import struct

from . import decmpfs
from .text import t as _t

MAGIC_END = b"bvx$"
MAGIC_RAW = b"bvx-"
MAGIC_V1 = b"bvx1"
MAGIC_V2 = b"bvx2"
MAGIC_LZVN = b"bvxn"

L_SYMBOLS, M_SYMBOLS, D_SYMBOLS, LIT_SYMBOLS = 20, 20, 64, 256
L_STATES, M_STATES, D_STATES, LIT_STATES = 64, 64, 256, 1024
MATCHES_PER_BLOCK = 10000
LITERALS_PER_BLOCK = 4 * MATCHES_PER_BLOCK
V1_HEADER = 770
V2_FIXED = 32

L_EXTRA = (0,) * 16 + (2, 3, 5, 8)
L_BASE = tuple(range(16)) + (16, 20, 28, 60)
M_EXTRA = (0,) * 16 + (3, 5, 8, 11)
M_BASE = tuple(range(16)) + (16, 24, 56, 312)
D_EXTRA = tuple(b for b in range(16) for _ in range(4))
D_BASE = (
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108,
    124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276,
    1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236,
    12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148, 57340,
    65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372)

_FREQ_BITS = (2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
              2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14)
_FREQ_VALUE = (0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
               0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1)


class LzfseError(ValueError):
    pass


def _bad(key, *args):
    return LzfseError(_t(key) % args if args else _t(key))


# -- header ---------------------------------------------------------------------

def _freq_value(bits):
    """(value, bits consumed) for one packed frequency."""
    low = bits & 31
    n = _FREQ_BITS[low]
    if n == 8:
        return 8 + ((bits >> 4) & 0xF), n
    if n == 14:
        return 24 + ((bits >> 4) & 0x3FF), n
    return _FREQ_VALUE[low], n


def _unpack_v2(data, at):
    """The fields of a v2 header at `at`, as a dict like the v1 header, and
    the header's size."""
    if at + V2_FIXED > len(data):
        raise _bad("lzfse.truncated")
    n_raw = struct.unpack_from("<I", data, at + 4)[0]
    v0, v1, v2 = struct.unpack_from("<QQQ", data, at + 8)
    size = v2 & 0xFFFFFFFF
    if size < V2_FIXED or at + size > len(data):
        raise _bad("lzfse.truncated")
    h = {
        "n_raw": n_raw,
        "n_literals": v0 & 0xFFFFF,
        "n_literal_payload": (v0 >> 20) & 0xFFFFF,
        "n_matches": (v0 >> 40) & 0xFFFFF,
        "literal_bits": ((v0 >> 60) & 7) - 7,
        "literal_state": [(v1 >> s) & 0x3FF for s in (0, 10, 20, 30)],
        "n_lmd_payload": (v1 >> 40) & 0xFFFFF,
        "lmd_bits": ((v1 >> 60) & 7) - 7,
        "l_state": (v2 >> 32) & 0x3FF,
        "m_state": (v2 >> 42) & 0x3FF,
        "d_state": (v2 >> 52) & 0x3FF,
    }
    total = L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LIT_SYMBOLS
    freq = [0] * total
    src, end = at + V2_FIXED, at + size
    if src != end:
        accum = nbits_in = 0
        for i in range(total):
            while src < end and nbits_in + 8 <= 32:
                accum |= data[src] << nbits_in
                nbits_in += 8
                src += 1
            value, used = _freq_value(accum)
            if used > nbits_in:
                raise _bad("lzfse.header_damaged")
            freq[i] = value
            accum >>= used
            nbits_in -= used
        if nbits_in >= 8 or src != end:
            raise _bad("lzfse.header_damaged")
    _split_freq(h, freq)
    return h, size


def _split_freq(h, freq):
    a, b, c = L_SYMBOLS, L_SYMBOLS + M_SYMBOLS, L_SYMBOLS + M_SYMBOLS + D_SYMBOLS
    h["l_freq"], h["m_freq"] = freq[:a], freq[a:b]
    h["d_freq"], h["literal_freq"] = freq[b:c], freq[c:]


def _unpack_v1(data, at):
    if at + V1_HEADER > len(data):
        raise _bad("lzfse.truncated")
    (n_raw, _n_payload, n_literals, n_matches, n_lit_payload, n_lmd_payload,
     literal_bits) = struct.unpack_from("<IIIIIIi", data, at + 4)
    lit_state = list(struct.unpack_from("<4H", data, at + 32))
    lmd_bits, l_state, m_state, d_state = struct.unpack_from("<iHHH", data,
                                                             at + 40)
    freq = list(struct.unpack_from("<%dH" % (L_SYMBOLS + M_SYMBOLS + D_SYMBOLS
                                             + LIT_SYMBOLS), data, at + 50))
    h = {"n_raw": n_raw, "n_literals": n_literals, "n_matches": n_matches,
         "n_literal_payload": n_lit_payload, "n_lmd_payload": n_lmd_payload,
         "literal_bits": literal_bits, "literal_state": lit_state,
         "lmd_bits": lmd_bits, "l_state": l_state, "m_state": m_state,
         "d_state": d_state}
    _split_freq(h, freq)
    return h, V1_HEADER


def _check_header(h):
    if h["n_literals"] > LITERALS_PER_BLOCK or h["n_matches"] > MATCHES_PER_BLOCK:
        raise _bad("lzfse.header_damaged")
    if any(s >= LIT_STATES for s in h["literal_state"]) \
            or h["l_state"] >= L_STATES or h["m_state"] >= M_STATES \
            or h["d_state"] >= D_STATES:
        raise _bad("lzfse.header_damaged")
    for key, states in (("l_freq", L_STATES), ("m_freq", M_STATES),
                        ("d_freq", D_STATES), ("literal_freq", LIT_STATES)):
        if sum(h[key]) > states:
            raise _bad("lzfse.header_damaged")
    if h["n_literals"] % 4:
        raise _bad("lzfse.header_damaged")


# -- finite state entropy --------------------------------------------------------

def _decoder_table(nstates, freq):
    """[(bits to read, symbol, delta)] per state."""
    n_clz = 32 - nstates.bit_length()
    table = []
    for sym, f in enumerate(freq):
        if not f:
            continue
        k = (32 - f.bit_length()) - n_clz
        j0 = ((2 * nstates) >> k) - f
        for j in range(f):
            if j < j0:
                table.append((k, sym, ((f + j) << k) - nstates))
            else:
                table.append((k - 1, sym, (j - j0) << (k - 1)))
    table.extend([(0, 0, 0)] * (nstates - len(table)))
    return table


def _value_table(nstates, freq, vbits, vbase):
    """[(total bits, value bits, delta, base)] per state."""
    n_clz = 32 - nstates.bit_length()
    table = []
    for sym, f in enumerate(freq):
        if not f:
            continue
        k = (32 - f.bit_length()) - n_clz
        j0 = ((2 * nstates) >> k) - f
        for j in range(f):
            if j < j0:
                table.append((k + vbits[sym], vbits[sym],
                              ((f + j) << k) - nstates, vbase[sym]))
            else:
                table.append((k - 1 + vbits[sym], vbits[sym],
                              (j - j0) << (k - 1), vbase[sym]))
    table.extend([(0, 0, 0, 0)] * (nstates - len(table)))
    return table


class _Reader:
    """Bits taken from the end of data[start:end], going backwards."""

    def __init__(self, data, end, start, bits):
        self.data, self.pos, self.start = data, end, start
        if bits:
            if self.pos < start + 4:
                raise _bad("lzfse.truncated")
            self.pos -= 4
            self.accum = int.from_bytes(data[self.pos:self.pos + 4], "little")
            self.nbits = bits + 32
        else:
            if self.pos < start + 3:
                raise _bad("lzfse.truncated")
            self.pos -= 3
            self.accum = int.from_bytes(data[self.pos:self.pos + 3], "little")
            self.nbits = 24
        if self.nbits < 24 or self.nbits >= 32 or self.accum >> self.nbits:
            raise _bad("lzfse.header_damaged")

    def flush(self):
        take = (63 - self.nbits) & -8
        if not take:
            return
        pos = self.pos - (take >> 3)
        if pos < self.start:
            raise _bad("lzfse.truncated")
        self.pos = pos
        incoming = int.from_bytes(self.data[pos:pos + (take >> 3)], "little")
        self.accum = (self.accum << take) | incoming
        self.nbits += take

    def pull(self, n):
        self.nbits -= n
        value = self.accum >> self.nbits
        self.accum &= (1 << self.nbits) - 1
        return value


def _literals(data, at, h, start):
    """The block's literals, decoded from the payload at data[at:...]."""
    table = _decoder_table(LIT_STATES, h["literal_freq"])
    end = at + h["n_literal_payload"]
    if end > len(data):
        raise _bad("lzfse.truncated")
    rd = _Reader(data, end, start, h["literal_bits"])
    states = list(h["literal_state"])
    out = bytearray(h["n_literals"])
    for i in range(0, h["n_literals"], 4):
        rd.flush()
        for j in range(4):
            k, sym, delta = table[states[j]]
            states[j] = delta + rd.pull(k)
            if states[j] >= LIT_STATES:
                raise _bad("lzfse.stream_damaged")
            out[i + j] = sym
    return bytes(out)


def _block(data, at, h, header_size, out, limit):
    """Decode one LZFSE block into `out`; returns the offset after it."""
    _check_header(h)
    lit_at = at + header_size
    lmd_at = lit_at + h["n_literal_payload"]
    end = lmd_at + h["n_lmd_payload"]
    if end > len(data):
        raise _bad("lzfse.truncated")
    literals = _literals(data, lit_at, h, 0)
    l_t = _value_table(L_STATES, h["l_freq"], L_EXTRA, L_BASE)
    m_t = _value_table(M_STATES, h["m_freq"], M_EXTRA, M_BASE)
    d_t = _value_table(D_STATES, h["d_freq"], D_EXTRA, D_BASE)
    rd = _Reader(data, end, lmd_at, h["lmd_bits"])
    ls, ms, ds = h["l_state"], h["m_state"], h["d_state"]
    lit = 0
    d_prev = -1
    block_start = len(out)
    for _ in range(h["n_matches"]):
        rd.flush()
        tb, vb, delta, base = l_t[ls]
        sv = rd.pull(tb)
        ls = delta + (sv >> vb)
        length = base + (sv & ((1 << vb) - 1))
        tb, vb, delta, base = m_t[ms]
        sv = rd.pull(tb)
        ms = delta + (sv >> vb)
        match = base + (sv & ((1 << vb) - 1))
        tb, vb, delta, base = d_t[ds]
        sv = rd.pull(tb)
        ds = delta + (sv >> vb)
        dist = base + (sv & ((1 << vb) - 1))
        if dist:
            d_prev = dist
        if ls >= L_STATES or ms >= M_STATES or ds >= D_STATES:
            raise _bad("lzfse.stream_damaged")
        if lit + length > len(literals):
            raise _bad("lzfse.stream_damaged")
        out += literals[lit:lit + length]
        lit += length
        if match:
            if d_prev <= 0 or d_prev > len(out):
                raise _bad("lzfse.stream_damaged")
            start = len(out) - d_prev
            if d_prev >= match:
                out += out[start:start + match]
            else:
                pattern = bytes(out[start:])
                out += (pattern * -(-match // d_prev))[:match]
        if len(out) > limit or len(out) - block_start > h["n_raw"]:
            raise _bad("lzfse.too_large")
    if len(out) - block_start != h["n_raw"]:
        raise _bad("lzfse.stream_damaged")
    return end


def decode(data, max_size=1 << 30):
    """The bytes an LZFSE stream decodes to. Raises LzfseError for a stream
    that is damaged, truncated, lacks its end marker or would decode to more
    than `max_size` bytes."""
    data = bytes(data)
    out = bytearray()
    at = 0
    while True:
        if at + 4 > len(data):
            raise _bad("lzfse.truncated")
        magic = data[at:at + 4]
        if magic == MAGIC_END:
            return bytes(out)
        if magic == MAGIC_RAW:
            if at + 8 > len(data):
                raise _bad("lzfse.truncated")
            n = struct.unpack_from("<I", data, at + 4)[0]
            if at + 8 + n > len(data):
                raise _bad("lzfse.truncated")
            if len(out) + n > max_size:
                raise _bad("lzfse.too_large")
            out += data[at + 8:at + 8 + n]
            at += 8 + n
        elif magic == MAGIC_LZVN:
            if at + 12 > len(data):
                raise _bad("lzfse.truncated")
            n_raw, n_payload = struct.unpack_from("<II", data, at + 4)
            if at + 12 + n_payload > len(data):
                raise _bad("lzfse.truncated")
            if len(out) + n_raw > max_size:
                raise _bad("lzfse.too_large")
            try:
                got = decmpfs.lzvn_decode(data[at + 12:at + 12 + n_payload],
                                          n_raw)
            except decmpfs.DecmpfsError as exc:
                raise LzfseError(str(exc))
            if len(got) != n_raw:
                raise _bad("lzfse.stream_damaged")
            out += got
            at += 12 + n_payload
        elif magic in (MAGIC_V1, MAGIC_V2):
            if magic == MAGIC_V1:
                h, size = _unpack_v1(data, at)
            else:
                h, size = _unpack_v2(data, at)
            if len(out) + h["n_raw"] > max_size:
                raise _bad("lzfse.too_large")
            at = _block(data, at, h, size, out, max_size)
        else:
            raise _bad("lzfse.bad_magic")
