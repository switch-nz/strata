"""A synthetic BitLocker (FVE) volume for engine.bitlocker, built field by
field from the on-disk structures documented in libyal's "BitLocker Drive
Encryption (BDE) format" specification -- every offset and value type used
here was checked against that spec (and, for the protector-type numeric
values, cross-checked against bitlocker2john.c) while implementing this
module, not assumed from the pre-existing code.

Layout of the synthetic image:
  offset 0        -- the FVE volume header (signature, GUID, metadata offsets)
  offset META_OFF  -- one FVE metadata block (four protectors + the FVEK)
  offset VH_OFF    -- the "real" first volume sector, relocated here the way
                      BitLocker relocates it while a volume is live, holding
                      an XTS-encrypted, minimally-valid NTFS boot sector so
                      unlock()'s own verify() step has something to check.
"""

import hashlib
import struct
import uuid

from engine import bitlocker as bitlocker_mod
from engine.crypto import aes as aes_mod
from engine.crypto import ccm as ccm_mod
from engine.crypto.aes import AES

SECTOR_SIZE = 512
META_OFF = 0x4000
VH_OFF = 0x10000
IMAGE_SIZE = 0x20000

ENCRYPTION_METHOD = 0x8005  # AES-XTS 256, per ENCRYPTION_METHODS in bitlocker.py
KEY_BYTES = 32

VOLUME_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
VMK = b"\x42" * 32          # the one "real" VMK every protector wraps
FVEK = b"\x24" * (KEY_BYTES * 2)
CLEAR_RAW_KEY = b"\x99" * 32

PASSWORD = "correct horse battery staple"
RECOVERY_KEY = "-".join(["001100"] * 8)   # each group a multiple of 11
BEK_KEY = b"\x77" * 32

# Real BitLocker stretches ~1,000,000 rounds per attempt, deliberately slow
# to guess. These tests are checking the byte-format and unwrap logic, not
# timing the KDF, so the round count is turned down for the module's
# lifetime -- mirrors imagebuild_luks.py baking a low PBKDF2 iteration count
# into its own fixtures, just via the module constant since FVE's stretch
# count isn't itself stored on disk.
bitlocker_mod.STRETCH_ROUNDS = 200


def _entry(entry_type, value_type, data, version=1):
    return struct.pack("<HHHH", 8 + len(data), entry_type, value_type,
                        version) + data


def _ccm_encrypt(key, nonce, plain):
    """The exact inverse of engine.crypto.ccm.decrypt, reusing its own
    private helpers so the fixture is anchored to the same CCM math the
    code under test uses -- not a second, possibly-diverging one."""
    cipher = key if isinstance(key, AES) else AES(key)
    L = 15 - len(nonce)
    out = bytearray()
    for i in range(0, len(plain), 16):
        ks = cipher.encrypt_block(ccm_mod._ctr_block(nonce, (i >> 4) + 1, L))
        out += ccm_mod._xor(plain[i:i + 16], ks)
    ciphertext = bytes(out)

    mac_len = 16
    flags = ((mac_len - 2) // 2) << 3 | (L - 1)
    b0 = bytes([flags]) + nonce + len(plain).to_bytes(L, "big")
    y = ccm_mod._cbc_mac(cipher, b0, plain)
    s0 = cipher.encrypt_block(ccm_mod._ctr_block(nonce, 0, L))
    mac = ccm_mod._xor(y[:mac_len], s0[:mac_len])
    return nonce + mac + ciphertext


def _wrapped(key, nonce, method, key_data):
    """One "FVE AES-CCM encrypted key" entry's on-disk bytes: CCM-wrap the
    spec's "unencrypted data" framing (size + version + unknown + method,
    then the real key bytes) around key_data."""
    unencrypted = struct.pack("<IHHI", 12 + len(key_data), 1, 0,
                              method) + key_data
    return _ccm_encrypt(key, nonce, unencrypted)


def _vmk_entry(guid, ptype, properties):
    body = guid.bytes_le + struct.pack("<Q", 0) + struct.pack("<HH", 0, ptype)
    return _entry(bitlocker_mod.ENTRY_VMK, bitlocker_mod.VALUE_VMK,
                  body + properties)


def _clear_key_protector(guid, nonce):
    key_entry = _entry(0, bitlocker_mod.VALUE_KEY,
                        struct.pack("<I", 0) + CLEAR_RAW_KEY)
    ccm_entry = _entry(0, bitlocker_mod.VALUE_AES_CCM,
                        _wrapped(CLEAR_RAW_KEY, nonce, 0x2000, VMK))
    return _vmk_entry(guid, 0x0000, key_entry + ccm_entry)


def _stretched_protector(guid, ptype, initial, salt, nonce):
    wrapped = _wrapped(bitlocker_mod._stretch(initial, salt), nonce, 0x2000, VMK)
    nested_ccm = _entry(0, bitlocker_mod.VALUE_AES_CCM, wrapped)
    stretch_body = struct.pack("<I", 0x1000) + salt + nested_ccm
    stretch_entry = _entry(0, bitlocker_mod.VALUE_STRETCH_KEY, stretch_body)
    return _vmk_entry(guid, ptype, stretch_entry)


def _password_initial(secret):
    return hashlib.sha256(
        hashlib.sha256(secret.encode("utf-16-le")).digest()).digest()


def _recovery_initial(recovery_key):
    digits = bitlocker_mod._recovery_digits(recovery_key)
    return hashlib.sha256(digits).digest()


def _external_key_entry(key_id, raw_key):
    key_entry = _entry(0, bitlocker_mod.VALUE_KEY,
                        struct.pack("<I", 0) + raw_key)
    body = key_id.bytes_le + struct.pack("<Q", 0) + key_entry
    return _entry(0, bitlocker_mod.VALUE_EXTERNAL_KEY, body)


def build_bek_file(key_id, raw_key):
    entries = _external_key_entry(key_id, raw_key)
    meta_size = 48 + len(entries)
    header = struct.pack("<4I", meta_size, 1, 48, meta_size) \
        + key_id.bytes_le + struct.pack("<II", 0, 0) + struct.pack("<Q", 0)
    return header + entries


def _xts_encrypt_sector(key1, key2, sector, data):
    c1 = key1 if isinstance(key1, AES) else AES(key1)
    c2 = key2 if isinstance(key2, AES) else AES(key2)
    tweak = aes_mod._xts_tweak(c2, sector)
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += aes_mod._xor(c1.encrypt_block(aes_mod._xor(blk, tweak)), tweak)
        tweak = aes_mod._gf_mul_alpha(tweak)
    return bytes(out)


DIFFUSER_METHOD = 0x8000  # AES-CBC 128 with Elephant diffuser
DIFFUSER_KEY_BYTES = 16
# Each component sits in its own fixed 256-bit (32-byte) slot regardless of
# the actual AES key size -- see bitlocker.py's _keys(), verified against
# dislocker's dis_crypt_set_fvekey(). Bytes past the first
# DIFFUSER_KEY_BYTES of each slot are unused padding.
DIFFUSER_FVEK = (b"\x11" * DIFFUSER_KEY_BYTES + b"\x00" * (32 - DIFFUSER_KEY_BYTES) +
                 b"\x22" * DIFFUSER_KEY_BYTES + b"\x00" * (32 - DIFFUSER_KEY_BYTES))


def _cbc_encrypt(key, iv, data):
    """The exact inverse of engine.crypto.aes._cbc_decrypt_py."""
    a = key if isinstance(key, AES) else AES(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        enc = a.encrypt_block(aes_mod._xor(data[i:i + 16], prev))
        out += enc
        prev = enc
    return bytes(out)


def _diffuser_encrypt_pass(d, n, cycles, rot, near, far):
    """The exact inverse of bitlocker_mod._diffuser_pass -- reverse
    iteration order, subtract instead of add (whitepaper section 4.4)."""
    for _ in range(cycles):
        for i in range(n - 1, -1, -1):
            d[i] = (d[i] - (d[(i + near) % n]
                    ^ bitlocker_mod._rotl32(d[(i + far) % n], rot[i % 4]))) & 0xFFFFFFFF
    return d


def _diffuser_encrypt_sector(k1, ksec, offset, sector_size, plain):
    """Mirrors bitlocker.diffuser_decrypt: XOR sector key -> A diffuser ->
    B diffuser -> AES-CBC encrypt (whitepaper figure 1, reversed for
    decryption)."""
    n = sector_size // 4
    ks = struct.unpack("<%dI" % n,
                        bitlocker_mod._sector_key(ksec, offset, sector_size))
    d = [x ^ k for x, k in zip(struct.unpack("<%dI" % n, plain), ks)]
    d = _diffuser_encrypt_pass(d, n, bitlocker_mod._DIFFUSER_A_CYCLES,
                                bitlocker_mod._DIFFUSER_A_ROT, -2, -5)
    d = _diffuser_encrypt_pass(d, n, bitlocker_mod._DIFFUSER_B_CYCLES,
                                bitlocker_mod._DIFFUSER_B_ROT, 2, 5)
    diffused = struct.pack("<%dI" % n, *d)
    iv = k1.encrypt_block(struct.pack("<Q", offset) + b"\x00" * 8)
    return _cbc_encrypt(k1, iv, diffused)


def build_diffuser_volume():
    """A minimal single-protector (password) BitLocker volume using
    AES-128-CBC with the Elephant diffuser (method 0x8000), so unlock()'s
    own verify() step exercises a real encrypt/decrypt round trip through
    diffuser_decrypt."""
    guid_password = uuid.UUID("00000000-0000-0000-0000-000000000005")

    protectors = _stretched_protector(guid_password, 0x2000,
                                       _password_initial(PASSWORD),
                                       b"\x06" * 16, b"\x06" * 12)
    fvek_entry = _entry(bitlocker_mod.ENTRY_FVEK, bitlocker_mod.VALUE_AES_CCM,
                         _wrapped(VMK, b"\x07" * 12, DIFFUSER_METHOD, DIFFUSER_FVEK))
    volume_header_entry = _entry(
        bitlocker_mod.ENTRY_VOLUME_HEADER, bitlocker_mod.VALUE_OFFSET_SIZE,
        struct.pack("<QQ", VH_OFF, SECTOR_SIZE))

    entries = protectors + fvek_entry + volume_header_entry
    meta_size = 48 + len(entries)
    metadata_header = struct.pack("<4I", meta_size, 1, 48, meta_size) \
        + VOLUME_ID.bytes_le + struct.pack("<I", 0) \
        + struct.pack("<I", DIFFUSER_METHOD) + struct.pack("<Q", 0)
    block_header = bitlocker_mod.SIGNATURE + struct.pack("<HH", 0, 1) \
        + b"\x00" * 52
    metadata_block = block_header + metadata_header + entries
    assert len(metadata_block) <= 4096

    image = bytearray(IMAGE_SIZE)
    header = bytearray(SECTOR_SIZE)
    header[3:11] = bitlocker_mod.SIGNATURE
    struct.pack_into("<H", header, 0x0B, SECTOR_SIZE)
    header[0xA0:0xB0] = bitlocker_mod.GUID_WIN7.bytes_le
    struct.pack_into("<3Q", header, 0xB0, META_OFF, META_OFF, META_OFF)
    header[510:512] = b"\x55\xAA"
    image[0:SECTOR_SIZE] = header
    image[META_OFF:META_OFF + len(metadata_block)] = metadata_block

    ntfs_sector = bytearray(SECTOR_SIZE)
    ntfs_sector[3:11] = b"NTFS    "
    ntfs_sector[510:512] = b"\x55\xAA"
    k1 = AES(DIFFUSER_FVEK[:DIFFUSER_KEY_BYTES])
    ksec = AES(DIFFUSER_FVEK[0x20:0x20 + DIFFUSER_KEY_BYTES])
    ciphertext = _diffuser_encrypt_sector(k1, ksec, VH_OFF, SECTOR_SIZE,
                                          bytes(ntfs_sector))
    image[VH_OFF:VH_OFF + SECTOR_SIZE] = ciphertext

    return bytes(image)


def build_bitlocker_volume(include_clear=True):
    """(image_bytes, bek_file_bytes) for a volume with four key protectors
    (clear key, startup key, recovery password, password) all wrapping the
    same VMK, and an FVEK that decrypts a relocated, minimally-valid NTFS
    boot sector -- so a successful unlock() also verifies. include_clear
    controls only the clear-key protector: since a clear-key protector
    unlocks unconditionally, leave it out to exercise the other three
    protectors' own rejection of a wrong secret without it masking the
    result."""
    guid_clear = uuid.UUID("00000000-0000-0000-0000-000000000001")
    guid_keyfile = uuid.UUID("00000000-0000-0000-0000-000000000002")
    guid_recovery = uuid.UUID("00000000-0000-0000-0000-000000000003")
    guid_password = uuid.UUID("00000000-0000-0000-0000-000000000004")
    bek_key_id = uuid.UUID("00000000-0000-0000-0000-0000000000bb")

    protectors = b"".join(filter(None, [
        _clear_key_protector(guid_clear, b"\x01" * 12) if include_clear else b"",
        _stretched_protector(guid_keyfile, 0x0200, BEK_KEY, b"\x02" * 16,
                              b"\x02" * 12),
        _stretched_protector(guid_recovery, 0x0800, _recovery_initial(RECOVERY_KEY),
                              b"\x03" * 16, b"\x03" * 12),
        _stretched_protector(guid_password, 0x2000, _password_initial(PASSWORD),
                              b"\x04" * 16, b"\x04" * 12),
    ]))
    fvek_entry = _entry(bitlocker_mod.ENTRY_FVEK, bitlocker_mod.VALUE_AES_CCM,
                         _wrapped(VMK, b"\x05" * 12, ENCRYPTION_METHOD, FVEK))
    volume_header_entry = _entry(
        bitlocker_mod.ENTRY_VOLUME_HEADER, bitlocker_mod.VALUE_OFFSET_SIZE,
        struct.pack("<QQ", VH_OFF, SECTOR_SIZE))

    entries = protectors + fvek_entry + volume_header_entry
    meta_size = 48 + len(entries)
    metadata_header = struct.pack("<4I", meta_size, 1, 48, meta_size) \
        + VOLUME_ID.bytes_le + struct.pack("<I", 0) \
        + struct.pack("<I", ENCRYPTION_METHOD) + struct.pack("<Q", 0)
    block_header = bitlocker_mod.SIGNATURE + struct.pack("<HH", 0, 1) \
        + b"\x00" * 52
    metadata_block = block_header + metadata_header + entries
    assert len(metadata_block) <= 4096

    image = bytearray(IMAGE_SIZE)
    header = bytearray(SECTOR_SIZE)
    header[3:11] = bitlocker_mod.SIGNATURE
    struct.pack_into("<H", header, 0x0B, SECTOR_SIZE)
    header[0xA0:0xB0] = bitlocker_mod.GUID_WIN7.bytes_le
    struct.pack_into("<3Q", header, 0xB0, META_OFF, META_OFF, META_OFF)
    header[510:512] = b"\x55\xAA"
    image[0:SECTOR_SIZE] = header
    image[META_OFF:META_OFF + len(metadata_block)] = metadata_block

    ntfs_sector = bytearray(SECTOR_SIZE)
    ntfs_sector[3:11] = b"NTFS    "
    ntfs_sector[510:512] = b"\x55\xAA"
    k1, k2 = AES(FVEK[:KEY_BYTES]), AES(FVEK[KEY_BYTES:KEY_BYTES * 2])
    ciphertext = _xts_encrypt_sector(k1, k2, VH_OFF // SECTOR_SIZE,
                                     bytes(ntfs_sector))
    image[VH_OFF:VH_OFF + SECTOR_SIZE] = ciphertext

    bek_file = build_bek_file(bek_key_id, BEK_KEY)
    return bytes(image), bek_file
