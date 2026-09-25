import struct

from .. import native

SBOX = bytes((
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
))

INV_SBOX = bytearray(256)
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
INV_SBOX = bytes(INV_SBOX)

RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D)

def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a

def _mul(a, b):
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        b >>= 1
        a = _xtime(a)
    return out

def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

Te0 = [0] * 256
Td0 = [0] * 256
for _i in range(256):
    _s = SBOX[_i]
    Te0[_i] = (_mul(_s, 2) << 24) | (_s << 16) | (_s << 8) | _mul(_s, 3)
    _d = INV_SBOX[_i]
    Td0[_i] = ((_mul(_d, 14) << 24) | (_mul(_d, 9) << 16)
               | (_mul(_d, 13) << 8) | _mul(_d, 11))
Te1 = [_rotl32(x, 24) for x in Te0]
Te2 = [_rotl32(x, 16) for x in Te0]
Te3 = [_rotl32(x, 8) for x in Te0]
Td1 = [_rotl32(x, 24) for x in Td0]
Td2 = [_rotl32(x, 16) for x in Td0]
Td3 = [_rotl32(x, 8) for x in Td0]

MASK = 0xFFFFFFFF

class AES:

    __slots__ = ("rounds", "ek", "dk", "key_size", "_raw")

    def __init__(self, key):
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes, got %d"
                             % len(key))
        self._raw = key
        self.key_size = len(key)
        nk = len(key) // 4
        self.rounds = nk + 6
        self.ek = self._expand(key, nk)
        self.dk = self._invert(self.ek)

    def _raw_key(self):
        return self._raw

    def _expand(self, key, nk):
        w = list(struct.unpack(">%dI" % nk, key))
        total = 4 * (self.rounds + 1)
        for i in range(nk, total):
            t = w[i - 1]
            if i % nk == 0:
                t = _rotl32(t, 8)
                t = ((SBOX[(t >> 24) & 0xFF] << 24)
                     | (SBOX[(t >> 16) & 0xFF] << 16)
                     | (SBOX[(t >> 8) & 0xFF] << 8)
                     | SBOX[t & 0xFF])
                t ^= RCON[i // nk - 1] << 24
            elif nk > 6 and i % nk == 4:
                t = ((SBOX[(t >> 24) & 0xFF] << 24)
                     | (SBOX[(t >> 16) & 0xFF] << 16)
                     | (SBOX[(t >> 8) & 0xFF] << 8)
                     | SBOX[t & 0xFF])
            w.append((w[i - nk] ^ t) & MASK)
        return w

    def _invert(self, ek):
        dk = list(ek)
        for i in range(4, 4 * self.rounds):
            x = dk[i]
            dk[i] = (Td0[SBOX[(x >> 24) & 0xFF]]
                     ^ Td1[SBOX[(x >> 16) & 0xFF]]
                     ^ Td2[SBOX[(x >> 8) & 0xFF]]
                     ^ Td3[SBOX[x & 0xFF]])
        return dk

    def encrypt_block(self, block):
        ek = self.ek
        s0, s1, s2, s3 = struct.unpack(">4I", block)
        s0 ^= ek[0]
        s1 ^= ek[1]
        s2 ^= ek[2]
        s3 ^= ek[3]
        k = 4
        for _ in range(self.rounds - 1):
            t0 = (Te0[(s0 >> 24) & 0xFF] ^ Te1[(s1 >> 16) & 0xFF]
                  ^ Te2[(s2 >> 8) & 0xFF] ^ Te3[s3 & 0xFF] ^ ek[k])
            t1 = (Te0[(s1 >> 24) & 0xFF] ^ Te1[(s2 >> 16) & 0xFF]
                  ^ Te2[(s3 >> 8) & 0xFF] ^ Te3[s0 & 0xFF] ^ ek[k + 1])
            t2 = (Te0[(s2 >> 24) & 0xFF] ^ Te1[(s3 >> 16) & 0xFF]
                  ^ Te2[(s0 >> 8) & 0xFF] ^ Te3[s1 & 0xFF] ^ ek[k + 2])
            t3 = (Te0[(s3 >> 24) & 0xFF] ^ Te1[(s0 >> 16) & 0xFF]
                  ^ Te2[(s1 >> 8) & 0xFF] ^ Te3[s2 & 0xFF] ^ ek[k + 3])
            s0, s1, s2, s3 = t0, t1, t2, t3
            k += 4
        return struct.pack(
            ">4I",
            ((SBOX[(s0 >> 24) & 0xFF] << 24) | (SBOX[(s1 >> 16) & 0xFF] << 16)
             | (SBOX[(s2 >> 8) & 0xFF] << 8) | SBOX[s3 & 0xFF]) ^ ek[k],
            ((SBOX[(s1 >> 24) & 0xFF] << 24) | (SBOX[(s2 >> 16) & 0xFF] << 16)
             | (SBOX[(s3 >> 8) & 0xFF] << 8) | SBOX[s0 & 0xFF]) ^ ek[k + 1],
            ((SBOX[(s2 >> 24) & 0xFF] << 24) | (SBOX[(s3 >> 16) & 0xFF] << 16)
             | (SBOX[(s0 >> 8) & 0xFF] << 8) | SBOX[s1 & 0xFF]) ^ ek[k + 2],
            ((SBOX[(s3 >> 24) & 0xFF] << 24) | (SBOX[(s0 >> 16) & 0xFF] << 16)
             | (SBOX[(s1 >> 8) & 0xFF] << 8) | SBOX[s2 & 0xFF]) ^ ek[k + 3])

    def decrypt_block(self, block):
        dk = self.dk
        s0, s1, s2, s3 = struct.unpack(">4I", block)
        n = 4 * self.rounds
        s0 ^= dk[n]
        s1 ^= dk[n + 1]
        s2 ^= dk[n + 2]
        s3 ^= dk[n + 3]
        k = n - 4
        for _ in range(self.rounds - 1):
            t0 = (Td0[(s0 >> 24) & 0xFF] ^ Td1[(s3 >> 16) & 0xFF]
                  ^ Td2[(s2 >> 8) & 0xFF] ^ Td3[s1 & 0xFF] ^ dk[k])
            t1 = (Td0[(s1 >> 24) & 0xFF] ^ Td1[(s0 >> 16) & 0xFF]
                  ^ Td2[(s3 >> 8) & 0xFF] ^ Td3[s2 & 0xFF] ^ dk[k + 1])
            t2 = (Td0[(s2 >> 24) & 0xFF] ^ Td1[(s1 >> 16) & 0xFF]
                  ^ Td2[(s0 >> 8) & 0xFF] ^ Td3[s3 & 0xFF] ^ dk[k + 2])
            t3 = (Td0[(s3 >> 24) & 0xFF] ^ Td1[(s2 >> 16) & 0xFF]
                  ^ Td2[(s1 >> 8) & 0xFF] ^ Td3[s0 & 0xFF] ^ dk[k + 3])
            s0, s1, s2, s3 = t0, t1, t2, t3
            k -= 4
        return struct.pack(
            ">4I",
            ((INV_SBOX[(s0 >> 24) & 0xFF] << 24)
             | (INV_SBOX[(s3 >> 16) & 0xFF] << 16)
             | (INV_SBOX[(s2 >> 8) & 0xFF] << 8)
             | INV_SBOX[s1 & 0xFF]) ^ dk[0],
            ((INV_SBOX[(s1 >> 24) & 0xFF] << 24)
             | (INV_SBOX[(s0 >> 16) & 0xFF] << 16)
             | (INV_SBOX[(s3 >> 8) & 0xFF] << 8)
             | INV_SBOX[s2 & 0xFF]) ^ dk[1],
            ((INV_SBOX[(s2 >> 24) & 0xFF] << 24)
             | (INV_SBOX[(s1 >> 16) & 0xFF] << 16)
             | (INV_SBOX[(s0 >> 8) & 0xFF] << 8)
             | INV_SBOX[s3 & 0xFF]) ^ dk[2],
            ((INV_SBOX[(s3 >> 24) & 0xFF] << 24)
             | (INV_SBOX[(s2 >> 16) & 0xFF] << 16)
             | (INV_SBOX[(s1 >> 8) & 0xFF] << 8)
             | INV_SBOX[s0 & 0xFF]) ^ dk[3])

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def _cbc_decrypt_py(key, iv, data):
    a = key if isinstance(key, AES) else AES(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += _xor(a.decrypt_block(block), prev)
        prev = block
    return bytes(out)


def cbc_decrypt(key, iv, data):
    raw = key.key_size if isinstance(key, AES) else len(key)
    kb = key if not isinstance(key, AES) else _key_bytes(key)
    if native.available() and raw in (16, 24, 32) and len(iv) == 16 \
            and len(data) and len(data) % 16 == 0:
        try:
            return native.aes_cbc_decrypt(kb, iv, data)
        except native.NativeError:
            pass
    return _cbc_decrypt_py(key, iv, data)

def _gf_mul_alpha(t):
    lo, hi = struct.unpack("<QQ", t)
    carry = hi >> 63
    hi = ((hi << 1) | (lo >> 63)) & 0xFFFFFFFFFFFFFFFF
    lo = (lo << 1) & 0xFFFFFFFFFFFFFFFF
    if carry:
        lo ^= 0x87
    return struct.pack("<QQ", lo, hi)

def _xts_tweak(c2, sector):
    return c2.encrypt_block(struct.pack("<Q", sector) + b"\x00" * 8)

def _xts_decrypt_py(key1, key2, sector, data):
    c1 = key1 if isinstance(key1, AES) else AES(key1)
    c2 = key2 if isinstance(key2, AES) else AES(key2)
    tweak = _xts_tweak(c2, sector)
    n = len(data)
    if n < 16:
        raise ValueError("XTS needs at least one full block")
    q, rem = divmod(n, 16)

    out = bytearray()
    last_full = q if rem == 0 else q - 1
    for i in range(last_full):
        blk = data[i * 16:(i + 1) * 16]
        out += _xor(c1.decrypt_block(_xor(blk, tweak)), tweak)
        tweak = _gf_mul_alpha(tweak)

    if rem:
        next_tweak = _gf_mul_alpha(tweak)
        cm1 = data[last_full * 16:(last_full + 1) * 16]
        cm = data[(last_full + 1) * 16:]
        pp = _xor(c1.decrypt_block(_xor(cm1, next_tweak)), next_tweak)
        tail = pp[:rem]
        stolen = pp[rem:]
        full = bytes(cm) + stolen
        out += _xor(c1.decrypt_block(_xor(full, tweak)), tweak)
        out += tail
    return bytes(out)


def _key_bytes(key):
    """Raw key bytes of an AES instance (kept for the native bridge)."""
    return key._raw_key()


def xts_decrypt(key1, key2, sector, data, sector_size=None):
    if native.available() and len(data) >= 16:
        k1 = _key_bytes(key1) if isinstance(key1, AES) else bytes(key1)
        k2 = _key_bytes(key2) if isinstance(key2, AES) else bytes(key2)
        if len(k1) == len(k2) and len(k1) in (16, 24, 32):
            try:
                return native.aes_xts_decrypt(k1, k2, sector, data,
                                              sector_size=sector_size)
            except native.NativeError:
                pass
    return _xts_decrypt_py(key1, key2, sector, data)


