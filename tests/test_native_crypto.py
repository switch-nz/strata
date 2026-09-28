"""Tests for the optional native crypto sidecar (engine.native).

Runs everywhere: when the sidecar is absent these tests prove the fallback
contract (pure-Python results unchanged with native forced unavailable);
when present they add RFC-vector and differential gates against the
pure-Python oracle.  Standard library only, like the rest of the suite.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.crypto import aes, argon2                     # noqa: E402
from engine.crypto.argon2 import derive, OutOfMemory      # noqa: E402
from engine import native, reglog                          # noqa: E402
from engine.native import NativeError                     # noqa: E402

NATIVE = native.available()


class RfcVectorsNative(unittest.TestCase):
    """RFC 9106 section 5 tags through derive() with native loaded."""

    @unittest.skipUnless(NATIVE, "native sidecar not available")
    def test_rfc_9106_section_5_matches_python_oracle(self):
        # The published vectors themselves are pinned in tests.test_luks
        # (pure path).  Here: native must reproduce the pure oracle, which
        # those vectors already validate.
        for kind, version, secret, ad in (
            ("argon2d", 0x13, b"\x03" * 8, b"\x04" * 12),
            ("argon2i", 0x13, b"\x03" * 8, b"\x04" * 12),
            ("argon2id", 0x13, b"\x03" * 8, b"\x04" * 12),
            ("argon2id", 0x10, b"", b""),
        ):
            with self.subTest(kind=kind, version=version):
                want = derive(b"\x01" * 32, b"\x02" * 16, t=3, m_kib=32,
                              p=4, out_len=32, kind=kind, version=version,
                              secret=secret, associated=ad)
                got = native.argon2_derive(
                    b"\x01" * 32, b"\x02" * 16, t=3, m_kib=32, p=4,
                    out_len=32, kind=argon2.KIND_CODE[kind],
                    version=version, secret=secret, associated=ad)
                self.assertEqual(got, want)


class Differential(unittest.TestCase):
    """Native vs pure-Python byte identity on seeded random inputs."""

    @unittest.skipUnless(NATIVE, "native sidecar not available")
    def test_xts_differential_seeded(self):
        rng = random.Random(0x5EED)
        cases = []
        # sector sizes 512 and 4096, plus the 15..17-byte tail shapes the
        # CTS branch in _xts_decrypt_py handles (odd lengths are rejected
        # by the native gate on purpose: it never sees them, callers slice
        # per sector; exercise the boundary the engine actually uses).
        for sector_size in (512, 4096):
            for _ in range(40):
                key_len = rng.choice((16, 32))
                k1 = bytes(rng.randrange(256) for _ in range(key_len))
                k2 = bytes(rng.randrange(256) for _ in range(key_len))
                sector = rng.randrange(1 << 40)
                data = bytes(rng.randrange(256) for _ in range(sector_size))
                cases.append((k1, k2, sector, (sector_size, data)))
        for k1, k2, sector, (sector_size, data) in cases:
            with self.subTest(k=len(k1), sector=sector):
                got = native.aes_xts_decrypt(k1, k2, sector, data,
                                             sector_size=sector_size)
                want = aes._xts_decrypt_py(k1, k2, sector, data)
                self.assertEqual(got, want)

    @unittest.skipUnless(NATIVE, "native sidecar not available")
    def test_cbc_differential_seeded(self):
        rng = random.Random(0xC0DE)
        for _ in range(100):
            key_len = rng.choice((16, 24, 32))
            key = bytes(rng.randrange(256) for _ in range(key_len))
            iv = bytes(rng.randrange(256) for _ in range(16))
            n = rng.randrange(1, 40) * 16
            data = bytes(rng.randrange(256) for _ in range(n))
            with self.subTest(k=key_len, n=n):
                got = native.aes_cbc_decrypt(key, iv, data)
                want = aes._cbc_decrypt_py(key, iv, data)
                self.assertEqual(got, want)

    @unittest.skipUnless(NATIVE, "native sidecar not available")
    def test_marvin32_differential_seeded(self):
        rng = random.Random(0x4A12)
        # Exhaustive small sizes (covers every tail-byte-count branch) plus
        # randomized larger ones up to a size worth mixing many words, and
        # a handful of seeds (including the module's own default one, used
        # for hive/log checksums).
        seeds = (reglog.MARVIN_SEED, 0, 1, 0xFFFFFFFFFFFFFFFF,
                 0x004FB61A001BDBCC)
        lengths = list(range(0, 20)) + [rng.randrange(20, 5000)
                                        for _ in range(30)]
        for seed in seeds:
            for n in lengths:
                data = bytes(rng.randrange(256) for _ in range(n))
                with self.subTest(seed=seed, n=n):
                    self.assertEqual(native.marvin32(data, seed),
                                     reglog._marvin32_py(data, seed))

    @unittest.skipUnless(NATIVE, "native sidecar not available")
    def test_selftest_export_returns_zero(self):
        self.assertEqual(_raw_selftest(), 0)

    @unittest.skipUnless(NATIVE, "native sidecar not available")
    def test_error_paths_raise_native_error_not_crash(self):
        # m_kib above the crate's u32 ceiling is refused pre-alloc.
        with self.assertRaises(NativeError):
            native.argon2_derive(b"\x01" * 32, b"\x02" * 16, t=3,
                                 m_kib=1 << 40, p=4, out_len=32, kind=2,
                                 version=0x13, secret=b"", associated=b"")
        # bad params: salt too short
        with self.assertRaises(NativeError):
            native.argon2_derive(b"\x01" * 32, b"\x02" * 4, t=3, m_kib=32,
                                 p=4, out_len=32, kind=2, version=0x13,
                                 secret=b"", associated=b"")


def _raw_selftest():
    """Call the exported selftest directly through the loaded handle."""
    import ctypes
    lib = native._State.lib
    lib.strata_selftest.argtypes = []
    lib.strata_selftest.restype = ctypes.c_int32
    return lib.strata_selftest()


class PublishedAesVectors(unittest.TestCase):
    """Published known answers for the pure implementation -- the oracle
    every differential test here trusts -- and, when the sidecar is loaded,
    for the sidecar too. The same vectors are compiled into the sidecar's
    load-time self-test (native/src/lib.rs, strata_selftest)."""

    # IEEE 1619-2007 XTS-AES-128, vectors 1 and 2.
    XTS = (
        (bytes(16), bytes(16), 0, bytes(32),
         "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"),
        (b"\x11" * 16, b"\x22" * 16, 0x3333333333, b"\x44" * 32,
         "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0"),
    )
    # NIST SP 800-38A F.2.2, CBC-AES128.Decrypt, block 1.
    CBC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    CBC_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    CBC_CT = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    CBC_PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    def test_pure_xts_matches_ieee_1619_vectors(self):
        for k1, k2, sector, plain, ct in self.XTS:
            self.assertEqual(
                aes._xts_decrypt_py(k1, k2, sector, bytes.fromhex(ct)), plain)

    def test_pure_cbc_matches_nist_800_38a(self):
        self.assertEqual(
            aes._cbc_decrypt_py(self.CBC_KEY, self.CBC_IV, self.CBC_CT),
            self.CBC_PT)

    @unittest.skipUnless(NATIVE, "native sidecar not available")
    def test_native_xts_matches_ieee_1619_vectors(self):
        for k1, k2, sector, plain, ct in self.XTS:
            self.assertEqual(
                native.aes_xts_decrypt(k1, k2, sector, bytes.fromhex(ct)),
                plain)

    @unittest.skipUnless(NATIVE, "native sidecar not available")
    def test_native_cbc_matches_nist_800_38a(self):
        self.assertEqual(
            native.aes_cbc_decrypt(self.CBC_KEY, self.CBC_IV, self.CBC_CT),
            self.CBC_PT)


class PublishedMarvin32Vectors(unittest.TestCase):
    """The .NET runtime's own Marvin32 test vectors (seed
    0x004FB61A001BDBCC), the same ones tests.test_registry.Marvin32 checks
    the pure implementation against, here for the native one too. One is
    compiled into the sidecar's load-time self-test."""

    SEED = 0x004FB61A001BDBCC
    VECTORS = (
        (b"\xaf", 0x48E73FC77D75DDC1),
        (b"\xe7\x0f", 0xB5F6E1FC485DBFF8),
        (b"\x37\xf4\x95", 0xF0B07C789B8CF7E8),
        (b"\x15\x3f\xb7\x98\x26", 0xE6C08C6DA2AFA997),
        (b"\x09\x32\xe6\x24\x6c\x47", 0x6F04BF1A5EA24060),
        (b"\xab\x42\x7e\xa8\xd1\x0f\xc7", 0xE11847E4F0678C41),
    )

    @unittest.skipUnless(NATIVE, "native sidecar not available")
    def test_native_matches_dotnet_vectors(self):
        for data, want in self.VECTORS:
            self.assertEqual(native.marvin32(data, self.SEED), want, data)


class FallbackContract(unittest.TestCase):
    """Runs everywhere: with native forced unavailable, behavior is
    exactly the pure-Python one."""

    def test_derive_matches_rfc_vectors_with_native_disabled(self):
        saved = dict(native._State.__dict__)
        try:
            native._State.failed = True
            native._State.loaded = False
            native._State.lib = None
            for kind, want in {
                "argon2d": "512b391b6f1162975371d30919734294"
                           "f868e3be3984f3c1a13a4db9fabe4acb",
                "argon2i": "c814d9d1dc7f37aa13f0d77f2494bda1"
                           "c8de6b016dd388d29952a4c4672b6ce8",
                "argon2id": "0d640df58d78766c08c037a34a8b53c9"
                            "d01ef0452d75b65eb52520e96b01e659",
            }.items():
                with self.subTest(kind=kind):
                    got = derive(b"\x01" * 32, b"\x02" * 16, t=3, m_kib=32,
                                 p=4, out_len=32, kind=kind, version=0x13,
                                 secret=b"\x03" * 8, associated=b"\x04" * 12)
                    self.assertEqual(got.hex(), want)
        finally:
            native._State.failed = saved["failed"]
            native._State.loaded = saved["loaded"]
            native._State.lib = saved["lib"]

    def test_reglog_marvin32_falls_back_when_native_unavailable(self):
        saved = dict(native._State.__dict__)
        try:
            native._State.failed = True
            native._State.loaded = False
            native._State.lib = None
            rng = random.Random(0x9001)
            for n in (0, 1, 7, 4000):
                data = bytes(rng.randrange(256) for _ in range(n))
                self.assertEqual(reglog.marvin32(data),
                                 reglog._marvin32_py(data))
        finally:
            native._State.failed = saved["failed"]
            native._State.loaded = saved["loaded"]
            native._State.lib = saved["lib"]

    def test_native_entries_refuse_when_unavailable(self):
        saved = dict(native._State.__dict__)
        try:
            native._State.failed = True
            native._State.loaded = False
            native._State.lib = None
            with self.assertRaises(NativeError):
                native.aes_xts_decrypt(b"\x00" * 16, b"\x11" * 16, 0,
                                       b"\x00" * 512)
            with self.assertRaises(NativeError):
                native.aes_cbc_decrypt(b"\x00" * 16, b"\x00" * 16,
                                       b"\x00" * 16)
            with self.assertRaises(NativeError):
                native.argon2_derive(b"\x01" * 32, b"\x02" * 16, t=3,
                                     m_kib=32, p=4, out_len=32, kind=2,
                                     version=0x13, secret=b"",
                                     associated=b"")
            with self.assertRaises(NativeError):
                native.marvin32(b"\x00" * 16, 0)
        finally:
            native._State.failed = saved["failed"]
            native._State.loaded = saved["loaded"]
            native._State.lib = saved["lib"]


class ErrorIdentity(unittest.TestCase):
    """OOM mapping keeps the public exception contract."""

    def test_oom_from_derive_is_out_of_memory_subclass(self):
        # Via the public derive() with an absurd (but validated) m_kib on
        # the pure path, the caller sees OutOfMemory, same as before this
        # change; the native path maps any refusal to a fallback, so the
        # exception type can never regress.
        with self.assertRaises(OutOfMemory):
            derive(b"\x01" * 32, b"\x02" * 16, t=3, m_kib=(1 << 40), p=4,
                   out_len=32, kind="argon2id")


if __name__ == "__main__":
    unittest.main()