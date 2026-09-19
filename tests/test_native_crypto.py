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
from engine import native                                 # noqa: E402
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