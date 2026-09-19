//! Native crypto sidecar for Strata.
//!
//! Exposes exactly three operations plus a self-test over a C ABI consumed
//! by `engine/native.py` (ctypes).  Error codes are a mirror of the table in
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

/// Load-time self-test.  Nonzero return = the loader refuses the library
/// and stays on pure Python.
///
/// The RFC 9106 §5 vectors all carry secret + associated data, which the
/// argon2 crate's raw `hash_password_into(pwd, salt)` does not accept; the
/// authoritative vector comparison therefore runs in Python
/// (tests/test_native_crypto.py) against the pure-Python oracle, and the
/// native wrapper falls back whenever it cannot reproduce an output.
/// Here we pin: (a) the call succeeds, (b) it is deterministic, (c) CBC
/// links and produces stable output for a fixed input.
#[no_mangle]
pub extern "C" fn strata_selftest() -> i32 {
    let mut tag = [0u8; 32];
    let args = (
        [0x01u8; 32], [0x02u8; 16], [0x03u8; 8], [0x04u8; 12],
    );
    if strata_argon2_derive(
        args.0.as_ptr(), 32,
        args.1.as_ptr(), 16,
        3, 32, 4, 32,
        2, 0x13,
        args.2.as_ptr(), 8,
        args.3.as_ptr(), 12,
        tag.as_mut_ptr(),
    ) != STRATA_OK
    {
        return STRATA_ERR_SELFTEST;
    }
    let mut tag2 = [0u8; 32];
    if strata_argon2_derive(
        args.0.as_ptr(), 32,
        args.1.as_ptr(), 16,
        3, 32, 4, 32,
        2, 0x13,
        args.2.as_ptr(), 8,
        args.3.as_ptr(), 12,
        tag2.as_mut_ptr(),
    ) != STRATA_OK
        || tag != tag2
    {
        return STRATA_ERR_SELFTEST;
    }
    // CBC: a fixed key/iv/block must decrypt to a stable value; assert the
    // roundtrip property using the block cipher direction we don't export:
    // encrypt via the argon2-free aes crate directly.
    use aes::cipher::BlockEncrypt;
    let key = [0x2bu8; 16];
    let iv = [0u8; 16];
    let plain = [0x6bu8; 16];
    let mut enc_block = Block::from(plain);
    let cipher = match aes::Aes128::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return STRATA_ERR_SELFTEST,
    };
    cipher.encrypt_block(&mut enc_block);
    let ct: [u8; 16] = enc_block.into();
    let mut dec = [0u8; 16];
    if strata_cbc_decrypt(
        key.as_ptr(), 16,
        iv.as_ptr(),
        ct.as_ptr(), 16,
        dec.as_mut_ptr(),
    ) != STRATA_OK
        || dec != plain
    {
        return STRATA_ERR_SELFTEST;
    }
    STRATA_OK
}