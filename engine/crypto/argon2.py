"""Argon2 (RFC 9106) key derivation, Python standard library only.

Implements Argon2d (y=0), Argon2i (y=1) and Argon2id (y=2), version 0x13
(1.3; 0x10 accepted) on top of hashlib.blake2b alone.  Every 1024-byte
block is one flat run of 128 u64 words; the whole matrix is a single
array("Q") of m' * 128 words, lane-major: block B[lane][col] occupies
words (lane * q + col) * 128 .. +128.

Byte conversions at the module boundary always go through struct with an
explicit "<" prefix, so results are identical on either endianness; the
array itself only carries internal integer state.

derive() takes an optional progress callback, invoked with a fraction in
0.0..1.0 at every slice boundary as ((pass * 4) + slice) / (4 * t).
"""

import hashlib
import struct
from array import array

from .. import native

VERSION = 0x13
LEGACY_VERSION = 0x10
KIND_CODE = {"argon2d": 0, "argon2i": 1, "argon2id": 2}
SLOTS_PER_BLOCK = 128            # u64 words per 1024-byte block
WORDS_PER_REGISTER = 2           # one 16-byte register = two u64 words
SYNC_ROUNDS = 4                  # SL: vertical slices per pass
ADDRESSES_IN_BLOCK = 128         # u64 address values per address block

_MASK64 = (1 << 64) - 1
_ZERO_BLOCK = [0] * SLOTS_PER_BLOCK


class OutOfMemory(MemoryError):
    """The memory requested for a derive call could not be allocated."""


def _h(data, out_len):
    """BLAKE2b hash H with digest_size=out_len (RFC 9106 section 2)."""
    return hashlib.blake2b(data, digest_size=out_len).digest()


def _h_prime(data, out_len):
    """Variable-length hash H' (RFC 9106 section 3.3)."""
    if out_len <= 64:
        return _h(struct.pack("<I", out_len) + data, out_len)
    r = (out_len + 31) // 32 - 2
    parts = []
    v = _h(struct.pack("<I", out_len) + data, 64)
    parts.append(v[:32])
    for _ in range(r - 1):
        v = _h(v, 64)
        parts.append(v[:32])
    parts.append(_h(v, out_len - 32 * len(parts)))
    return b"".join(parts)


def _gb(v, ia, ib, ic, id_):
    """One BLAKE2b-round step with the Argon2 multiplication (fig. 19),
    in place on the 16-word register list v."""
    a = v[ia]
    b = v[ib]
    c = v[ic]
    d = v[id_]

    a = (a + b + 2 * ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF))) & _MASK64
    d ^= a
    d = ((d >> 32) | (d << 32)) & _MASK64
    c = (c + d + 2 * ((c & 0xFFFFFFFF) * (d & 0xFFFFFFFF))) & _MASK64
    b ^= c
    b = ((b >> 24) | (b << 40)) & _MASK64

    a = (a + b + 2 * ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF))) & _MASK64
    d ^= a
    d = ((d >> 16) | (d << 48)) & _MASK64
    c = (c + d + 2 * ((c & 0xFFFFFFFF) * (d & 0xFFFFFFFF))) & _MASK64
    b ^= c
    b = ((b >> 63) | (b << 1)) & _MASK64

    v[ia] = a
    v[ib] = b
    v[ic] = c
    v[id_] = d


def _p(w):
    """Permutation P over eight 16-byte registers (fig. 18); w holds the
    16 u64 words of one row or column group."""
    v = list(w)
    _gb(v, 0, 4, 8, 12)
    _gb(v, 1, 5, 9, 13)
    _gb(v, 2, 6, 10, 14)
    _gb(v, 3, 7, 11, 15)
    _gb(v, 0, 5, 10, 15)
    _gb(v, 1, 6, 11, 12)
    _gb(v, 2, 7, 8, 13)
    _gb(v, 3, 4, 9, 14)
    return v


def _compress(prev, ref, old=None):
    """Compression function G on two 128-word blocks (fig. 15/16).

    R = ref XOR prev, P rowwise then columnwise, output Z XOR R; when old
    is given the further-pass XOR (fig. 6) folds it in.
    """
    r = [a ^ b for a, b in zip(ref, prev)]
    tmp = list(r)
    if old is not None:
        for k in range(128):
            tmp[k] ^= old[k]
    for row in range(8):
        off = 16 * row
        r[off:off + 16] = _p(r[off:off + 16])
    for col in range(8):
        idx = [2 * col + 16 * j + d for j in range(8) for d in (0, 1)]
        vals = _p([r[j] for j in idx])
        for pos, j in enumerate(idx):
            r[j] = vals[pos]
    return [tmp[k] ^ r[k] for k in range(128)]


def _next_addresses(zero, inp):
    """Advance the Argon2i/Argon2id address generator by one block
    (ref.c next_addresses): inp word 6 is the counter."""
    inp[6] += 1
    t = _compress(zero, inp)
    return _compress(zero, t)


def _ref_index(pass_no, slice_no, index, pseudo, same_lane, seg, q):
    """Reference column for a pseudo-random value (fig. 12/13; ref.c
    index_alpha)."""
    if pass_no == 0:
        if slice_no == 0:
            ras = index - 1
        elif same_lane:
            ras = slice_no * seg + index - 1
        else:
            ras = slice_no * seg + (-1 if index == 0 else 0)
    elif same_lane:
        ras = q - seg + index - 1
    else:
        ras = q - seg + (-1 if index == 0 else 0)
    ras &= 0xFFFFFFFF
    rp = (pseudo * pseudo) >> 32
    rel = (ras - 1 - ((ras * rp) >> 32)) & 0xFFFFFFFF
    start = 0 if pass_no == 0 or slice_no == SYNC_ROUNDS - 1 \
        else (slice_no + 1) * seg
    return (start + rel) % q


def _fill_segment(mem, pass_no, lane, slice_no, lanes, q, seg, m_prime,
                  passes, y, version):
    """Compute one (pass, slice, lane) segment into the flat matrix."""
    indep = y == 1 or (y == 2 and pass_no == 0 and slice_no < 2)
    inp = None
    addr = None
    if indep:
        inp = [0] * 128
        inp[0] = pass_no
        inp[1] = lane
        inp[2] = slice_no
        inp[3] = m_prime
        inp[4] = passes
        inp[5] = y
    start = 2 if (pass_no == 0 and slice_no == 0) else 0
    if indep and start:
        addr = _next_addresses(_ZERO_BLOCK, inp)
    curr = lane * q + slice_no * seg + start
    prev = curr - 1 if curr % q else curr + q - 1
    for i in range(start, seg):
        if curr % q == 1:
            prev = curr - 1
        if indep:
            if i % ADDRESSES_IN_BLOCK == 0:
                addr = _next_addresses(_ZERO_BLOCK, inp)
            pseudo = addr[i % ADDRESSES_IN_BLOCK]
        else:
            pseudo = mem[prev * 128]
        ref_lane = (pseudo >> 32) % lanes
        if pass_no == 0 and slice_no == 0:
            ref_lane = lane
        col = _ref_index(pass_no, slice_no, i, pseudo & 0xFFFFFFFF,
                         ref_lane == lane, seg, q)
        base_p = prev * 128
        base_r = (ref_lane * q + col) * 128
        base_c = curr * 128
        old = mem[base_c:base_c + 128] if pass_no and version == VERSION \
            else None
        out = _compress(mem[base_p:base_p + 128], mem[base_r:base_r + 128],
                        old)
        mem[base_c:base_c + 128] = array("Q", out)
        curr += 1
        prev += 1


def _derive_native(password, salt, t, m_kib, p, out_len, kind, version,
                   secret, associated):
    """Run Argon2 in the native sidecar; None when it must not be used."""
    if not native.available():
        return None
    # The sidecar handles both versions (0x13, 0x10) and all three kinds
    # with secret/associated data.  Guard only against lengths the C ABI
    # cannot express; on any native error fall back to pure Python, which
    # is the oracle.
    if max(len(password), len(salt), len(secret),
           len(associated)) >= (1 << 31):
        return None
    try:
        return native.argon2_derive(
            password, salt, t=t, m_kib=m_kib, p=p, out_len=out_len,
            kind=KIND_CODE[kind], version=version, secret=secret,
            associated=associated)
    except native.NativeError:
        return None


def derive(password, salt, *, t, m_kib, p, out_len, kind="argon2id",
           version=VERSION, secret=b"", associated=b"", progress=None):
    """Derive out_len bytes with Argon2 (RFC 9106, version 0x13).

    password, salt, secret, associated: bytes.  t: passes; m_kib: memory
    parameter in KiB (the LUKS2 "memory" field); p: lanes; kind: one of
    "argon2d", "argon2i", "argon2id".  progress: called with a 0.0..1.0
    fraction at every slice boundary.  Raises ValueError on out-of-range
    parameters and OutOfMemory when the matrix cannot be allocated.
    """
    if kind not in KIND_CODE:
        raise ValueError("unknown Argon2 kind: %r" % (kind,))
    if version not in (LEGACY_VERSION, VERSION):
        raise ValueError("unsupported Argon2 version: %#x" % (version,))
    if t < 1:
        raise ValueError("pass count must be at least 1")
    if p < 1:
        raise ValueError("lane count must be at least 1")
    if m_kib < 8 * p:
        raise ValueError("memory %d KiB too small for %d lanes"
                         % (m_kib, p))
    if m_kib > 0xFFFFFFFF:
        raise OutOfMemory("cannot allocate %d KiB for Argon2" % (m_kib,))
    if out_len < 4:
        raise ValueError("tag length %d too short" % (out_len,))
    if len(salt) < 8:
        raise ValueError("salt %d bytes too short" % (len(salt),))
    password = bytes(password)
    salt = bytes(salt)
    secret = bytes(secret)
    associated = bytes(associated)

    y = KIND_CODE[kind]
    m_prime = 4 * p * (m_kib // (4 * p))
    q = m_prime // p
    seg = q // SYNC_ROUNDS

    if progress is None:
        got = _derive_native(password, salt, t, m_kib, p, out_len, kind,
                             version, secret, associated)
        if got is not None:
            return got

    h0 = _h(
        struct.pack("<7I", p, out_len, m_kib, t, version, y, len(password))
        + password
        + struct.pack("<I", len(salt)) + salt
        + struct.pack("<I", len(secret)) + secret
        + struct.pack("<I", len(associated)) + associated,
        64)

    try:
        mem = array("Q", [0]) * (m_prime * 128)
    except MemoryError as exc:
        raise OutOfMemory("cannot allocate %d KiB for Argon2"
                          % (m_kib,)) from exc

    unpack = struct.unpack
    for lane in range(p):
        base = lane * q * 128
        for j in (0, 1):
            block = _h_prime(h0 + struct.pack("<II", j, lane), 1024)
            mem[base + 128 * j:base + 128 * (j + 1)] = \
                array("Q", unpack("<128Q", block))

    for pass_no in range(t):
        for slice_no in range(SYNC_ROUNDS):
            if progress is not None:
                progress(((pass_no * 4) + slice_no) / (4 * t))
            for lane in range(p):
                _fill_segment(mem, pass_no, lane, slice_no, p, q, seg,
                              m_prime, t, y, version)

    c = [0] * 128
    for lane in range(p):
        base = (lane * q + q - 1) * 128
        for k in range(128):
            c[k] ^= mem[base + k]
    return _h_prime(struct.pack("<128Q", *c), out_len)