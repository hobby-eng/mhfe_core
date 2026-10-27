//! The vendored Argon2id engine through the public trait, at MHFE's parameters, against RustCrypto
//! `argon2`, an independent implementation, at small costs. The binding itself (RFC 9106 with a
//! secret and associated data, both copies of the core, the thread count, the wiped work area) is
//! tested in the crate, `engine/ffi.rs`.

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute, alone, or by #[test].
#![cfg(test)]
// WebAssembly has no native engine.
#![cfg(not(target_arch = "wasm32"))]

use argon2::{Algorithm, Argon2, Block, Params, Version};
use mhfe_core::{Argon2Engine, NativeArgon2};

/// Argon2id lanes, as the specification fixes them.
const LANES: u32 = 4;
/// The smallest memory for four lanes: two blocks per slice and four slices per lane, in KiB.
const LEAST_KIB: u32 = 8 * LANES;

/// The tag of RustCrypto's Argon2id with MHFE's parameters.
fn rustcrypto_tag(password: &[u8], salt: &[u8; 16], memory_kib: u32, passes: u32) -> [u8; 32] {
    let params = Params::new(memory_kib, passes, LANES, Some(32)).unwrap();
    let mut blocks = vec![Block::default(); params.block_count()];
    let mut tag = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, &mut tag, &mut blocks)
        .unwrap();
    tag
}

/// One engine for every call, which reserves the most memory once: passwords of 1 to 1,024 bytes,
/// the lengths of `P_enc`, and a deterministic spread of salts, memory and passes. The inputs are
/// counters, not secrets.
#[test]
fn the_native_engine_matches_rustcrypto_at_small_costs() {
    let most_kib = LEAST_KIB + 8 * 15;
    let mut engine = NativeArgon2::new(most_kib).unwrap();
    for case in 0u32..160 {
        let length = [1, 20, 64, 333, 1024][case as usize % 5];
        let password: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(case as u8))
            .collect();
        let salt: [u8; 16] = std::array::from_fn(|index| (index as u8) ^ (case as u8));
        let memory_kib = LEAST_KIB + 8 * (case % 16);
        let passes = 1 + case % 3;
        let mut key = [0u8; 32];
        engine
            .argon2id(&password, &salt, memory_kib, passes, &mut key)
            .unwrap();
        assert_eq!(
            key,
            rustcrypto_tag(&password, &salt, memory_kib, passes),
            "case {case}"
        );
    }
}
