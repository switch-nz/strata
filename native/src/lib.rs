//! Native crypto sidecar for Strata.
//!
//! Exposes six operations plus a self-test over a C ABI consumed by
//! `engine/native.py` (ctypes).  Error codes are a mirror of the table in
//! that file — change them together.
//!
//! All buffers are caller-allocated; no global state.  The only allocation
//! is the Argon2 matrix (inherent to the algorithm) plus a small tag buffer.
//! `panic = "abort"` is set, so every length is validated up front and
//! `STRATA_ERR_PARAMS` is returned instead of panicking on
//! attacker-controlled input.
//!
//! AES-XTS is hand-rolled over the `aes` crate's block primitive so the
//! ciphertext-stealing tail can match `engine/crypto/aes.py` exactly (the
//! plan's contingency); the differential test in tests/test_native_crypto.py
//! is the referee.  CBC and Argon2 use the crates directly.

use aes::cipher::consts::U16;
use aes::cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit};
use aes::Block;
use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

// Mirror of engine/native.py.  Keep both tables identical.
pub const STRATA_OK: i32 = 0;
pub const STRATA_ERR_OOM: i32 = 1;
pub const STRATA_ERR_PARAMS: i32 = 2;
pub const STRATA_ERR_SELFTEST: i32 = 3;
pub const STRATA_ERR_GENERIC: i32 = 4;

/// Argon2 with the exact parameter envelope of engine/crypto/argon2.py.
///
/// `kind`: 0 = argon2d, 1 = argon2i, 2 = argon2id (mirror of KIND_CODE).
/// `version`: 0x13 (1.3) or 0x10 (1.0).  `m_kib` in KiB.  Fills `out`
/// (out_len bytes) on success; returns nonzero error code otherwise.
#[no_mangle]
pub extern "C" fn strata_argon2_derive(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    t: u64,
    m_kib: u64,
    p: u64,
    out_len: u64,
    kind: i32,
    version: i32,
    secret: *const u8,
    secret_len: usize,
    associated: *const u8,
    associated_len: usize,
    out: *mut u8,
) -> i32 {
    if password.is_null() || salt.is_null() || out.is_null() {
        return STRATA_ERR_PARAMS;
    }
    // The Python side enforces the semantic ranges; re-check cheap
    // invariants so no slice can exceed isize or panic here.
    if password_len > i32::MAX as usize
        || salt_len > i32::MAX as usize
        || secret_len > i32::MAX as usize
        || associated_len > i32::MAX as usize
        || out_len > i32::MAX as u64
        || out_len < 4
        || salt_len < 8
        || t == 0
        || t > u32::MAX as u64
        || p == 0
        || p > u32::MAX as u64
        || m_kib < 8 * p
        || m_kib > (1 << 32)
    {
        return STRATA_ERR_PARAMS;
    }
    let algorithm = match kind {
        0 => Algorithm::Argon2d,
        1 => Algorithm::Argon2i,
        2 => Algorithm::Argon2id,
        _ => return STRATA_ERR_PARAMS,
    };
    let ver = match version {
        0x13 => Version::V0x13,
        0x10 => Version::V0x10,
        _ => return STRATA_ERR_PARAMS,
    };

    let password = unsafe { std::slice::from_raw_parts(password, password_len) };
    let salt = unsafe { std::slice::from_raw_parts(salt, salt_len) };
    // The crate carries the secret (key) on the context and associated
    // data on Params.  Associated data is capped at 32 bytes by the
    // crate; the engine never sends more (refuse rather than drop).
    if associated_len > 32 {
        return STRATA_ERR_PARAMS;
    }
    let secret: &[u8] = if secret_len > 0 {
        if secret.is_null() {
            return STRATA_ERR_PARAMS;
        }
        unsafe { std::slice::from_raw_parts(secret, secret_len) }
    } else {
        &[]
    };
    let associated: &[u8] = if associated_len > 0 {
        if associated.is_null() {
            return STRATA_ERR_PARAMS;
        }
        unsafe { std::slice::from_raw_parts(associated, associated_len) }
    } else {
        &[]
    };

    let mut builder = ParamsBuilder::new();
    builder.m_cost(m_kib as u32);
    builder.t_cost(t as u32);
    builder.p_cost(p as u32);
    builder.output_len(out_len as usize);
    if !associated.is_empty() {
        let ad = match AssociatedData::new(associated) {
            Ok(x) => x,
            Err(_) => return STRATA_ERR_PARAMS,
        };
        builder.data(ad);
    }
    let params = match builder.build() {
        Ok(x) => x,
        Err(_) => return STRATA_ERR_PARAMS,
    };
    let ctx = if secret.is_empty() {
        Argon2::new(algorithm, ver, params)
    } else {
        match Argon2::new_with_secret(secret, algorithm, ver, params) {
            Ok(x) => x,
            Err(_) => return STRATA_ERR_PARAMS,
        }
    };
    let mut tag = vec![0u8; out_len as usize];
    if ctx.hash_password_into(password, salt, &mut tag).is_err() {
        return STRATA_ERR_OOM;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(tag.as_ptr(), out, out_len as usize);
    }
    STRATA_OK
}

/// XTS-decrypt one data unit: `data_len` bytes (multiple of 16, not more
/// than `sector_size`) with data key `key1` / tweak key `key2` (equal
/// length, 16/24/32).  Tweak = E_k2(little-endian u64 `sector` || zeros),
/// advanced by GF(2^128) multiply per 16-byte block.  Full data units only;
/// the engine slices per sector before calling, matching its CTS tail case
/// being unreachable through these call sites.
#[no_mangle]
pub extern "C" fn strata_xts_decrypt(
    key1: *const u8,
    key2: *const u8,
    key_len: usize,
    sector: u64,
    sector_size: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) -> i32 {
    if key1.is_null() || key2.is_null() || data.is_null() || out.is_null() {
        return STRATA_ERR_PARAMS;
    }
    if !matches!(key_len, 16 | 24 | 32) {
        return STRATA_ERR_PARAMS;
    }
    if data_len == 0 || data_len % 16 != 0 || sector_size % 16 != 0
        || data_len > sector_size
    {
        return STRATA_ERR_PARAMS;
    }
    let k1 = unsafe { std::slice::from_raw_parts(key1, key_len) };
    let k2 = unsafe { std::slice::from_raw_parts(key2, key_len) };
    let data = unsafe { std::slice::from_raw_parts(data, data_len) };
    match key_len {
        16 => xts_decrypt_inner::<aes::Aes128>(k1, k2, sector, data, out),
        24 => xts_decrypt_inner::<aes::Aes192>(k1, k2, sector, data, out),
        32 => xts_decrypt_inner::<aes::Aes256>(k1, k2, sector, data, out),
        _ => unreachable!("key_len validated above"),
    }
}

fn xts_decrypt_inner<A: BlockDecrypt + BlockEncrypt + KeyInit + BlockSizeUser<BlockSize = U16>>(
    k1: &[u8],
    k2: &[u8],
    sector: u64,
    data: &[u8],
    mut out: *mut u8,
) -> i32 {
    let data_cipher = match A::new_from_slice(k1) {
        Ok(c) => c,
        Err(_) => return STRATA_ERR_PARAMS,
    };
    let tweak_cipher = match A::new_from_slice(k2) {
        Ok(c) => c,
        Err(_) => return STRATA_ERR_PARAMS,
    };

    // Tweak = E_k2(sector as LE u64 padded to 16 zero bytes).
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector.to_le_bytes());
    let mut tblock = Block::clone_from_slice(&tweak);
    tweak_cipher.encrypt_block(&mut tblock);

    let mut block = Block::default();
    for chunk in data.chunks_exact(16) {
        block.copy_from_slice(chunk);
        for j in 0..16 {
            block[j] ^= tblock[j];
        }
        data_cipher.decrypt_block(&mut block);
        for j in 0..16 {
            block[j] ^= tblock[j];
        }
        unsafe {
            std::ptr::copy_nonoverlapping(block.as_ptr(), out, 16);
            out = out.add(16);
        }
        tblock = gf_mul_alpha(&tblock);
    }
    STRATA_OK
}

/// xts * alpha in GF(2^128), polynomial x^128 + x^7 + x^2 + x + 1, bit
/// order matching engine/crypto/aes.py `_gf_mul_alpha` (little-endian u64
/// pair; carry out of the top bit folds 0x87 into the low word).
fn gf_mul_alpha(t: &Block) -> Block {
    let lo = u64::from_le_bytes(t[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(t[8..16].try_into().unwrap());
    let carry = hi >> 63;
    let hi = (hi << 1) | (lo >> 63);
    let lo = (lo << 1) ^ (carry * 0x87);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&lo.to_le_bytes());
    out[8..16].copy_from_slice(&hi.to_le_bytes());
    out.into()
}

/// CBC-decrypt `data_len` bytes (multiple of 16) with a 16-byte `iv`.
#[no_mangle]
pub extern "C" fn strata_cbc_decrypt(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) -> i32 {
    if key.is_null() || iv.is_null() || data.is_null() || out.is_null() {
        return STRATA_ERR_PARAMS;
    }
    if !matches!(key_len, 16 | 24 | 32) || data_len == 0 || data_len % 16 != 0 {
        return STRATA_ERR_PARAMS;
    }
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    let iv = unsafe { std::slice::from_raw_parts(iv, 16) };
    let data = unsafe { std::slice::from_raw_parts(data, data_len) };
    match key_len {
        16 => cbc_decrypt_inner::<aes::Aes128>(key, iv, data, out),
        24 => cbc_decrypt_inner::<aes::Aes192>(key, iv, data, out),
        32 => cbc_decrypt_inner::<aes::Aes256>(key, iv, data, out),
        _ => unreachable!("key_len validated above"),
    }
}

fn cbc_decrypt_inner<A: BlockDecrypt + KeyInit + BlockSizeUser<BlockSize = U16>>(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    mut out: *mut u8,
) -> i32 {
    let cipher = match A::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return STRATA_ERR_PARAMS,
    };
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    let mut block = Block::default();
    for chunk in data.chunks_exact(16) {
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for j in 0..16 {
            block[j] ^= prev[j];
        }
        unsafe {
            std::ptr::copy_nonoverlapping(block.as_ptr(), out, 16);
            out = out.add(16);
        }
        prev.copy_from_slice(chunk);
    }
    STRATA_OK
}

/// Marvin32, the hash Windows uses for registry hive and transaction-log
/// checksums (`engine/reglog.py` decides whether a dirty hive's log is
/// trustworthy from it). Same algorithm as that module's pure-Python
/// `marvin32`/`_mix`/`_rotl` — kept as the correctness reference and the
/// fallback when this sidecar is unavailable, since a large dirty log
/// (tens of megabytes, one Python-level operation per 4 input bytes) is
/// what made replaying it slow enough to be worth this.
#[inline]
fn marvin32_mix(lo: &mut u32, hi: &mut u32, val: u32) {
    *lo = lo.wrapping_add(val);
    *hi ^= *lo;
    *lo = lo.rotate_left(20).wrapping_add(*hi);
    *hi = hi.rotate_left(9) ^ *lo;
    *lo = lo.rotate_left(27).wrapping_add(*hi);
    *hi = hi.rotate_left(19);
}

fn marvin32(data: &[u8], seed: u64) -> u64 {
    let mut lo = (seed & 0xFFFF_FFFF) as u32;
    let mut hi = (seed >> 32) as u32;
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        marvin32_mix(&mut lo, &mut hi, u32::from_le_bytes(chunk.try_into().unwrap()));
    }
    let rest = chunks.remainder();
    let final_word: u32 = match rest.len() {
        0 => 0x80,
        1 => 0x8000 | rest[0] as u32,
        2 => 0x80_0000 | u16::from_le_bytes([rest[0], rest[1]]) as u32,
        3 => {
            0x8000_0000
                | ((rest[2] as u32) << 16)
                | u16::from_le_bytes([rest[0], rest[1]]) as u32
        }
        _ => unreachable!("chunks_exact(4)'s remainder is under 4 bytes"),
    };
    marvin32_mix(&mut lo, &mut hi, final_word);
    marvin32_mix(&mut lo, &mut hi, 0);
    ((hi as u64) << 32) | lo as u64
}

/// `data` (`data_len` bytes, may be empty) hashed with Marvin32, seeded
/// with `seed`; writes the 64-bit result through `out`.
#[no_mangle]
pub extern "C" fn strata_marvin32(
    data: *const u8,
    data_len: usize,
    seed: u64,
    out: *mut u64,
) -> i32 {
    if out.is_null() || (data.is_null() && data_len > 0) {
        return STRATA_ERR_PARAMS;
    }
    let slice: &[u8] = if data_len > 0 {
        unsafe { std::slice::from_raw_parts(data, data_len) }
    } else {
        &[]
    };
    let result = marvin32(slice, seed);
    unsafe {
        *out = result;
    }
    STRATA_OK
}

/// Context-triggered piecewise hashing (the ssdeep-compatible fuzzy hash),
/// mirroring `engine/fuzzyhash.py` control-flow for control-flow -- that
/// module is the correctness reference (it is itself checked against a
/// third-party pure-Python ssdeep implementation, ppdeep, in
/// tests/test_fuzzyhash.py) and the fallback when this sidecar is
/// unavailable. It runs over every byte of every file in a bulk hashing
/// job, which is what made a native port worth doing.
const FUZZY_F_TABLE: [u8; 64] = [
    0x00, 0x13, 0x26, 0x39, 0x0c, 0x1f, 0x32, 0x05, 0x18, 0x2b, 0x3e, 0x11,
    0x24, 0x37, 0x0a, 0x1d, 0x30, 0x03, 0x16, 0x29, 0x3c, 0x0f, 0x22, 0x35,
    0x08, 0x1b, 0x2e, 0x01, 0x14, 0x27, 0x3a, 0x0d, 0x20, 0x33, 0x06, 0x19,
    0x2c, 0x3f, 0x12, 0x25, 0x38, 0x0b, 0x1e, 0x31, 0x04, 0x17, 0x2a, 0x3d,
    0x10, 0x23, 0x36, 0x09, 0x1c, 0x2f, 0x02, 0x15, 0x28, 0x3b, 0x0e, 0x21,
    0x34, 0x07, 0x1a, 0x2d,
];
const FUZZY_B64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const FUZZY_MIN_BLOCK_SIZE: u64 = 3;
const FUZZY_SPAMSUM_LENGTH: usize = 64;
const FUZZY_ROLL_WINDOW: usize = 7;
const FUZZY_HASH_INIT: u8 = 0x27;

/// Mirrors `_RollingHash` -- a 7-byte rolling checksum used only to pick
/// trigger points. `h1`/`h2` are Python's unbounded ints (they stay tiny,
/// bounded by 7 byte values, so i64 never risks overflow); `h3` is masked
/// to 32 bits every step in Python, which a plain `u32` shift already does.
struct FuzzyRoll {
    window: [i64; FUZZY_ROLL_WINDOW],
    h1: i64,
    h2: i64,
    h3: u32,
    pos: u64,
}

impl FuzzyRoll {
    fn new() -> Self {
        FuzzyRoll { window: [0; FUZZY_ROLL_WINDOW], h1: 0, h2: 0, h3: 0, pos: 0 }
    }

    fn update(&mut self, b: u8) -> u32 {
        let bv = b as i64;
        let slot = (self.pos % FUZZY_ROLL_WINDOW as u64) as usize;
        self.h2 = self.h2 - self.h1 + (FUZZY_ROLL_WINDOW as i64) * bv;
        self.h1 = self.h1 + bv - self.window[slot];
        self.window[slot] = bv;
        self.pos += 1;
        self.h3 = (self.h3 << 5) ^ (bv as u32);
        // (h1 + h2 + h3) & 0xFFFFFFFF, matching Python's mask on a value
        // that can be transiently negative before masking.
        let combined = self.h1.wrapping_add(self.h2).wrapping_add(self.h3 as i64);
        (combined as u64 & 0xFFFF_FFFF) as u32
    }
}

fn fuzzy_block_hash_next(h: u8, b: u8) -> u8 {
    FUZZY_F_TABLE[h as usize] ^ (b & 0x3F)
}

fn fuzzy_initial_block_size(length: usize) -> u64 {
    let mut bs = FUZZY_MIN_BLOCK_SIZE;
    while bs * (FUZZY_SPAMSUM_LENGTH as u64) < (length as u64) {
        bs *= 2;
    }
    bs
}

/// Mirrors `_piecewise_pass` exactly. `last1`/`last2` are Python's ""
/// (`None` here) versus a real trailing character (`Some(b64 index)`).
fn fuzzy_piecewise_pass(
    data: &[u8],
    block_size: u64,
) -> (Vec<u8>, Vec<u8>, Option<u8>, Option<u8>) {
    let mut roll = FuzzyRoll::new();
    let mut h1 = FUZZY_HASH_INIT;
    let mut h2 = FUZZY_HASH_INIT;
    let mut sig1 = Vec::<u8>::new();
    let mut sig2 = Vec::<u8>::new();
    let mut last1: Option<u8> = None;
    let mut last2: Option<u8> = None;
    let mut rh: u32 = 0;
    for &b in data {
        h1 = fuzzy_block_hash_next(h1, b);
        h2 = fuzzy_block_hash_next(h2, b);
        rh = roll.update(b);
        if (rh as u64) % block_size == block_size - 1 {
            last1 = Some(h1);
            if sig1.len() < FUZZY_SPAMSUM_LENGTH - 1 {
                sig1.push(h1);
                h1 = FUZZY_HASH_INIT;
                last1 = None;
            }
            if (rh as u64) % (block_size * 2) == block_size * 2 - 1 {
                last2 = Some(h2);
                if sig2.len() < FUZZY_SPAMSUM_LENGTH / 2 - 1 {
                    sig2.push(h2);
                    h2 = FUZZY_HASH_INIT;
                    last2 = None;
                }
            }
        }
    }
    let tail1 = if rh != 0 { Some(h1) } else { last1 };
    let tail2 = if rh != 0 { Some(h2) } else { last2 };
    (sig1, sig2, tail1, tail2)
}

/// Mirrors `hash_bytes`: retries with a halved block size, rescanning from
/// the start, until the first signature is long enough or the block size
/// bottoms out. Returns the "blocksize:sig1:sig2" string.
fn fuzzy_hash(data: &[u8]) -> String {
    let mut block_size = fuzzy_initial_block_size(data.len());
    loop {
        let (sig1, sig2, tail1, tail2) = fuzzy_piecewise_pass(data, block_size);
        if block_size > FUZZY_MIN_BLOCK_SIZE && sig1.len() < FUZZY_SPAMSUM_LENGTH / 2 {
            block_size /= 2;
            continue;
        }
        let mut out = block_size.to_string();
        out.push(':');
        for i in sig1 {
            out.push(FUZZY_B64[i as usize] as char);
        }
        if let Some(i) = tail1 {
            out.push(FUZZY_B64[i as usize] as char);
        }
        out.push(':');
        for i in sig2 {
            out.push(FUZZY_B64[i as usize] as char);
        }
        if let Some(i) = tail2 {
            out.push(FUZZY_B64[i as usize] as char);
        }
        return out;
    }
}

/// The fuzzy hash of `data` (`data_len` bytes, may be empty) as an ASCII
/// "blocksize:sig1:sig2" string, written into `out` (`out_cap` bytes,
/// never more than ~110 in practice); `out_len` gets the string's length.
/// `STRATA_ERR_PARAMS` if `out_cap` is too small.
#[no_mangle]
pub extern "C" fn strata_fuzzy_hash(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() || (data.is_null() && data_len > 0) {
        return STRATA_ERR_PARAMS;
    }
    let slice: &[u8] = if data_len > 0 {
        unsafe { std::slice::from_raw_parts(data, data_len) }
    } else {
        &[]
    };
    let result = fuzzy_hash(slice);
    let bytes = result.as_bytes();
    if bytes.len() > out_cap {
        return STRATA_ERR_PARAMS;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *out_len = bytes.len();
    }
    STRATA_OK
}

/// Load-time self-test: known-answer vectors, not consistency checks.
///
/// Each primitive is checked against a published answer, so a build that
/// links, loads and runs but computes the wrong thing (a compiler or
/// platform problem, or a later refactor of the hand-rolled XTS loop) is
/// refused and the loader stays on pure Python:
///
/// * Argon2id -- RFC 9106 section 5.3 (secret and associated data included),
///   through the same `strata_argon2_derive` the engine calls.
/// * AES-CBC -- NIST SP 800-38A F.2.2 (CBC-AES128.Decrypt, first block).
/// * AES-XTS -- IEEE 1619-2007 vectors 1 and 2 (AES-128), through
///   `strata_xts_decrypt`. Vector 2 uses a nonzero sector, which exercises
///   the tweak encoding.
/// * Marvin32 -- one of the .NET runtime's own Marvin test vectors (seed
///   0x004FB61A001BDBCC), the same one `tests/test_registry.py` checks the
///   pure-Python implementation against.
/// * Fuzzy hash -- one ppdeep-verified vector, the same one
///   `tests/test_fuzzyhash.py` checks the pure-Python implementation
///   against.
///
/// Broader agreement with the pure-Python implementation (key sizes, sector
/// sizes, ciphertext stealing being refused) is checked by
/// tests/test_native_crypto.py, not at load time.
#[no_mangle]
pub extern "C" fn strata_selftest() -> i32 {
    // RFC 9106 5.3, Argon2id: pwd 32x01, salt 16x02, secret 8x03, ad 12x04,
    // t=3, m=32 KiB, p=4, 32-byte tag.
    const ARGON2ID_TAG: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37,
        0xa3, 0x4a, 0x8b, 0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75,
        0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
    ];
    let (pwd, salt, secret, ad) = ([0x01u8; 32], [0x02u8; 16], [0x03u8; 8], [0x04u8; 12]);
    let mut tag = [0u8; 32];
    if strata_argon2_derive(
        pwd.as_ptr(), pwd.len(),
        salt.as_ptr(), salt.len(),
        3, 32, 4, 32,
        2, 0x13,
        secret.as_ptr(), secret.len(),
        ad.as_ptr(), ad.len(),
        tag.as_mut_ptr(),
    ) != STRATA_OK
        || tag != ARGON2ID_TAG
    {
        return STRATA_ERR_SELFTEST;
    }

    // NIST SP 800-38A F.2.2, CBC-AES128.Decrypt, block 1.
    let cbc_key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    let cbc_iv: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let cbc_ct: [u8; 16] = [
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    ];
    let cbc_pt: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    ];
    let mut dec = [0u8; 16];
    if strata_cbc_decrypt(
        cbc_key.as_ptr(), cbc_key.len(),
        cbc_iv.as_ptr(),
        cbc_ct.as_ptr(), cbc_ct.len(),
        dec.as_mut_ptr(),
    ) != STRATA_OK
        || dec != cbc_pt
    {
        return STRATA_ERR_SELFTEST;
    }

    // IEEE 1619-2007 XTS-AES-128 vector 1: key1 = key2 = 0, data unit 0,
    // 32 zero bytes of plaintext.
    let zero_key = [0u8; 16];
    let xts1_ct: [u8; 32] = [
        0x91, 0x7c, 0xf6, 0x9e, 0xbd, 0x68, 0xb2, 0xec,
        0x9b, 0x9f, 0xe9, 0xa3, 0xea, 0xdd, 0xa6, 0x92,
        0xcd, 0x43, 0xd2, 0xf5, 0x95, 0x98, 0xed, 0x85,
        0x8c, 0x02, 0xc2, 0x65, 0x2f, 0xbf, 0x92, 0x2e,
    ];
    let mut xts_out = [0xffu8; 32];
    if strata_xts_decrypt(
        zero_key.as_ptr(), zero_key.as_ptr(), zero_key.len(),
        0, xts1_ct.len(),
        xts1_ct.as_ptr(), xts1_ct.len(),
        xts_out.as_mut_ptr(),
    ) != STRATA_OK
        || xts_out != [0u8; 32]
    {
        return STRATA_ERR_SELFTEST;
    }

    // Vector 2: key1 = 16x11, key2 = 16x22, data unit 0x3333333333,
    // plaintext 32x44.
    let (k1, k2) = ([0x11u8; 16], [0x22u8; 16]);
    let xts2_ct: [u8; 32] = [
        0xc4, 0x54, 0x18, 0x5e, 0x6a, 0x16, 0x93, 0x6e,
        0x39, 0x33, 0x40, 0x38, 0xac, 0xef, 0x83, 0x8b,
        0xfb, 0x18, 0x6f, 0xff, 0x74, 0x80, 0xad, 0xc4,
        0x28, 0x93, 0x82, 0xec, 0xd6, 0xd3, 0x94, 0xf0,
    ];
    let mut xts_out = [0u8; 32];
    if strata_xts_decrypt(
        k1.as_ptr(), k2.as_ptr(), k1.len(),
        0x3333333333, xts2_ct.len(),
        xts2_ct.as_ptr(), xts2_ct.len(),
        xts_out.as_mut_ptr(),
    ) != STRATA_OK
        || xts_out != [0x44u8; 32]
    {
        return STRATA_ERR_SELFTEST;
    }

    // .NET runtime Marvin tests, seed 0x004FB61A001BDBCC: 7-byte input.
    const MARVIN_SEED: u64 = 0x004F_B61A_001B_DBCC;
    let marvin_input: [u8; 7] = [0xab, 0x42, 0x7e, 0xa8, 0xd1, 0x0f, 0xc7];
    let mut marvin_out: u64 = 0;
    if strata_marvin32(
        marvin_input.as_ptr(), marvin_input.len(),
        MARVIN_SEED, &mut marvin_out,
    ) != STRATA_OK
        || marvin_out != 0xE118_47E4_F067_8C41
    {
        return STRATA_ERR_SELFTEST;
    }

    // Fuzzy hash of b"hello world", checked against a third-party
    // pure-Python ssdeep implementation (ppdeep) in tests/test_fuzzyhash.py
    // -- the same vector engine.fuzzyhash's own pure implementation is
    // checked against.
    let fuzzy_input = b"hello world";
    let want_fuzzy = b"3:iKFSMPn:rJPn";
    let mut fuzzy_out = [0u8; 32];
    let mut fuzzy_len: usize = 0;
    if strata_fuzzy_hash(
        fuzzy_input.as_ptr(), fuzzy_input.len(),
        fuzzy_out.as_mut_ptr(), fuzzy_out.len(), &mut fuzzy_len,
    ) != STRATA_OK
        || &fuzzy_out[..fuzzy_len] != want_fuzzy
    {
        return STRATA_ERR_SELFTEST;
    }
    STRATA_OK
}
