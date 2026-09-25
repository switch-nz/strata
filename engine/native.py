"""ctypes loader for the optional native crypto sidecar.

Strata is pure Python by contract, but AES-XTS sector decrypts and Argon2
unlocks dominate encrypted-volume work.  This module loads a small Rust
``cdylib`` (source in ``native/``, prebuilt binaries vendored under
``engine/native/<target-triple>/``) and re-exports the exact operations the
pure-Python modules implement, so ``engine.crypto.aes`` and
``engine.crypto.argon2`` can swap implementations behind their existing
signatures.

Contract (mirrors the plan's "API parity rule"):

* ``available()`` is True only when a library was found, loaded, and its
  built-in self-test passed.  All failure modes degrade to False, never to a
  raised exception: callers treat native as a pure optimization.
* Every entry point re-raises ``NativeError`` on a nonzero status from the
  library.  The wired-in wrappers in ``engine/crypto/*`` translate that into
  the same exception objects the pure-Python code raises, so caller-visible
  error behavior is identical on both paths.
* ``STRATA_FORCE_PURE=1`` disables the loader entirely — the escape hatch CI
  and tests use to prove the fallback contract.

The library ABI and the error codes below are a mirror of ``native/src/lib.rs``
in the repo; change them together.
"""

import ctypes
import os
import platform
import struct

__all__ = ["available", "NativeError", "argon2_derive", "aes_xts_decrypt",
           "aes_cbc_decrypt"]

_LIBRARY_NAME = {
    "Linux": "libstrata_native.so",
    "Windows": "strata_native.dll",
    "Darwin": "libstrata_native.dylib",
}

# platform.machine() -> Rust target triple directory name.  Keep in sync
# with native/build.sh, which fills engine/native/<triple>/.
_MACHINE_DIR = {
    "x86_64": "x86_64-unknown-linux-gnu",
    "amd64": "x86_64-unknown-linux-gnu",
    "aarch64": "aarch64-unknown-linux-gnu",
    "arm64": "aarch64-unknown-linux-gnu",
}

_DIRNAME_OVERRIDES = {
    ("Windows", "x86_64"): "x86_64-pc-windows-msvc",
    ("Windows", "amd64"): "x86_64-pc-windows-msvc",
    ("Darwin", "x86_64"): "x86_64-apple-darwin",
    ("Darwin", "amd64"): "x86_64-apple-darwin",
    ("Darwin", "arm64"): "aarch64-apple-darwin",
}

# Error codes returned by the exported functions.  Mirror of
# native/src/lib.rs STRATA_ERR_*.
_OK = 0
_ERR_OOM = 1
_ERR_PARAMS = 2
_ERR_SELFTEST = 3
_ERR_GENERIC = 4

_PARAM_CODES = {_ERR_PARAMS, _ERR_SELFTEST}


class NativeError(Exception):
    """The native sidecar reported an error for one call."""


class _State(object):
    loaded = False
    failed = False
    lib = None


def _candidate_paths():
    system = platform.system()
    name = _LIBRARY_NAME.get(system)
    if not name:
        return
    machine = platform.machine().lower()
    dirname = _DIRNAME_OVERRIDES.get((system, machine)) or \
        _MACHINE_DIR.get(machine)
    if not dirname:
        return
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "native", dirname)
    # The vendored binary lives in engine/native/<triple>/ next to this
    # module (engine/native.py -> engine/native/<triple>/...); a build run
    # from the repo root may also have left it in <repo>/native/target.
    yield os.path.join(base, name)


def _bind(lib):
    """Attach prototypes; raises on signature mismatch."""
    u64 = ctypes.c_uint64
    usize = ctypes.c_size_t
    i32 = ctypes.c_int32

    lib.strata_selftest.argtypes = []
    lib.strata_selftest.restype = i32

    lib.strata_argon2_derive.argtypes = [
        ctypes.c_char_p,           # password
        usize,                     # password_len
        ctypes.c_char_p,           # salt
        usize,                     # salt_len
        u64,                       # passes t
        u64,                       # m_kib
        u64,                       # lanes p
        u64,                       # out_len
        i32,                       # kind code (0=d,1=i,2=id)
        i32,                       # version (0x13 / 0x10)
        ctypes.c_char_p,           # secret
        usize,                     # secret_len
        ctypes.c_char_p,           # associated
        usize,                     # associated_len
        ctypes.c_char_p,           # out buffer
    ]
    lib.strata_argon2_derive.restype = i32

    lib.strata_xts_decrypt.argtypes = [
        ctypes.c_char_p,           # key1 (data key)
        ctypes.c_char_p,           # key2 (tweak key)
        usize,                     # key_len (16/24/32 each half)
        u64,                       # start sector
        usize,                     # sector_size
        ctypes.c_char_p,           # data
        usize,                     # data_len
        ctypes.c_char_p,           # out buffer
    ]
    lib.strata_xts_decrypt.restype = i32

    lib.strata_cbc_decrypt.argtypes = [
        ctypes.c_char_p,           # key
        usize,                     # key_len
        ctypes.c_char_p,           # iv (16 bytes)
        ctypes.c_char_p,           # data
        usize,                     # data_len (multiple of 16)
        ctypes.c_char_p,           # out buffer
    ]
    lib.strata_cbc_decrypt.restype = i32
    return lib


def _load():
    if _State.loaded or _State.failed:
        return
    if os.environ.get("STRATA_FORCE_PURE"):
        _State.failed = True
        return
    try:
        for path in _candidate_paths():
            if not os.path.exists(path):
                continue
            lib = _bind(ctypes.CDLL(path))
            if lib.strata_selftest() != _OK:
                continue
            _State.lib = lib
            break
    except Exception:
        _State.lib = None
    if _State.lib is None:
        _State.failed = True
    else:
        _State.loaded = True


def available():
    """True when the native sidecar is loaded and self-tested."""
    _load()
    return _State.loaded


def _require():
    if not available():
        raise NativeError("native crypto sidecar not available")
    return _State.lib


def argon2_derive(password, salt, *, t, m_kib, p, out_len, kind, version,
                  secret, associated):
    """Argon2 via the sidecar; raises NativeError on failure.

    ``kind`` is the code from ``argon2.KIND_CODE``.  The wrapper in
    ``engine.crypto.argon2`` maps error codes to its own exception types.
    """
    lib = _require()
    out = ctypes.create_string_buffer(int(out_len))
    rc = lib.strata_argon2_derive(
        password, len(password), salt, len(salt),
        t, m_kib, p, out_len, kind, version,
        secret, len(secret), associated, len(associated),
        out)
    if rc != _OK:
        raise NativeError(_code_name(rc))
    return out.raw


def aes_xts_decrypt(key1, key2, start_sector, data, sector_size=None):
    """XTS-decrypt full sectors via the sidecar; raises NativeError."""
    lib = _require()
    if len(key1) != len(key2):
        raise NativeError("XTS key halves must match")
    if sector_size is None:
        sector_size = len(data)
    out = ctypes.create_string_buffer(len(data))
    rc = lib.strata_xts_decrypt(
        key1, key2, len(key1), start_sector, sector_size, data, len(data),
        out)
    if rc != _OK:
        raise NativeError(_code_name(rc))
    return out.raw


def aes_cbc_decrypt(key, iv, data):
    """CBC-decrypt via the sidecar; raises NativeError."""
    lib = _require()
    if len(iv) != 16:
        raise NativeError("CBC IV must be 16 bytes")
    out = ctypes.create_string_buffer(len(data))
    rc = lib.strata_cbc_decrypt(key, len(key), iv, data, len(data), out)
    if rc != _OK:
        raise NativeError(_code_name(rc))
    return out.raw


def _code_name(rc):
    if rc == _ERR_OOM:
        return "out of memory"
    if rc == _ERR_PARAMS:
        return "bad parameters"
    if rc == _ERR_SELFTEST:
        return "self-test failed"
    return "generic failure (code %d)" % (rc,)


def _pack_u64(n):
    return struct.pack("<Q", n)