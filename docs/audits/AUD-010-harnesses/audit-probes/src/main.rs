//! Standalone audit probes for `AUD-010`:
//!
//! 1. Reproduces `AUD-010-ARC001` directly against `xtask/src/code_rules.rs`.
//! 2. Exercises the `slice_as_blocks` cast of `src/engine/native.rs` and `reed-solomon-core` 0.2.0's
//!    `CyclicWords` over `GF(2^11)` under Miri without `secret-protection-core`'s signal-mask FFI.

#[cfg(not(miri))]
#[path = "../../../../../xtask/src/code_rules.rs"]
mod code_rules;

use std::fmt;
#[cfg(all(test, not(miri)))]
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use reed_solomon_core::{CyclicWords, Field};

/// Repository root expected by `xtask/src/code_rules.rs`'s unit tests.
#[cfg(all(test, not(miri)))]
pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..")
}

/// Error wrapper expected by `xtask/src/code_rules.rs`.
#[cfg(not(miri))]
#[derive(Debug)]
pub(crate) struct Failure(pub(crate) String);

#[cfg(not(miri))]
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(not(miri))]
impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

/// Deliberate copy of `slice_as_blocks` from `src/engine/native.rs:146-159`, isolated from
/// `secret-protection-core` so Miri can check its size, alignment and pointer provenance rules.
fn slice_as_blocks(bytes: &mut [u8]) -> Option<&mut [Block]> {
    let block_size = size_of::<Block>();
    if !bytes.len().is_multiple_of(block_size) {
        return None;
    }
    let pointer = bytes.as_mut_ptr();
    if pointer.align_offset(align_of::<Block>()) != 0 {
        return None;
    }
    let blocks = bytes.len() / block_size;
    #[expect(
        unsafe_code,
        reason = "audits the exact raw-slice cast of src/engine/native.rs under Miri"
    )]
    // SAFETY: `Block` is `[u64; 128]` (`#[repr(align(64))]`), every bit pattern is valid, the
    // alignment and exact byte multiple were checked above, and the returned slice borrows `bytes`
    // exclusively for the same lifetime.
    Some(unsafe { std::slice::from_raw_parts_mut(pointer.cast::<Block>(), blocks) })
}

/// Over-aligned byte backing for `slice_as_blocks` probes.
#[repr(C, align(64))]
struct AlignedArena<const N: usize>([u8; N]);

/// Checks aligned, misaligned, non-multiple and zero-length inputs to `slice_as_blocks`, then
/// runs `argon2` 0.6.0's `hash_password_into_with_memory` over the cast slice.
fn probe_slice_as_blocks() -> Result<(), &'static str> {
    const BLOCK_BYTES: usize = size_of::<Block>();
    const MEMORY_BLOCKS: usize = 8;
    let mut arena = AlignedArena([0xA5_u8; BLOCK_BYTES * MEMORY_BLOCKS + 64]);

    if slice_as_blocks(&mut arena.0[..0]).is_none_or(|blocks| !blocks.is_empty()) {
        return Err("empty aligned slice was not accepted as zero blocks");
    }
    if slice_as_blocks(&mut arena.0[..BLOCK_BYTES + 1]).is_some() {
        return Err("non-multiple byte length was accepted");
    }
    if slice_as_blocks(&mut arena.0[1..1 + BLOCK_BYTES]).is_some() {
        return Err("misaligned slice was accepted");
    }

    let Some(blocks) = slice_as_blocks(&mut arena.0[..BLOCK_BYTES * MEMORY_BLOCKS]) else {
        return Err("aligned eight-block slice was rejected");
    };
    if blocks.len() != MEMORY_BLOCKS {
        return Err("block count mismatch");
    }
    let Ok(params) = Params::new(8, 1, 1, Some(32)) else {
        return Err("8 KiB Argon2id parameters were rejected");
    };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_with_blocks = [0_u8; 32];
    let mut key_reference = [0_u8; 32];
    let mut reference_blocks = [Block::default(); MEMORY_BLOCKS];
    if argon2
        .hash_password_into_with_memory(
            b"probe-password",
            b"0123456789abcdef",
            &mut key_with_blocks,
            blocks,
        )
        .is_err()
    {
        return Err("hash_password_into_with_memory failed on cast Block slice");
    }
    if argon2
        .hash_password_into_with_memory(
            b"probe-password",
            b"0123456789abcdef",
            &mut key_reference,
            &mut reference_blocks,
        )
        .is_err()
    {
        return Err("reference hash_password_into_with_memory failed");
    }
    if key_with_blocks != key_reference {
        return Err("Argon2id digest over cast Block slice disagreed with reference");
    }
    Ok(())
}

/// Checks `reed-solomon-core` 0.2.0's `CyclicWords` over `GF(2^11)` across MHFE card shapes.
fn probe_reed_solomon_cyclic_words() -> Result<(), &'static str> {
    const MAX_DATA: usize = 24;
    const MAX_PARITY: usize = 8;
    const MAX_SYMBOLS: usize = MAX_DATA + MAX_PARITY;
    const ROOM: usize = CyclicWords::room(MAX_PARITY);

    for data in [12_usize, 15, 18, 21, 24] {
        for parity in [2_usize, 4, 6, 8] {
            let mut generator = [0_u16; MAX_PARITY + 1];
            let Ok(code) =
                CyclicWords::new(Field::Gf2048, data, parity, 1, 1, &mut generator[..=parity])
            else {
                return Err("valid MHFE card shape rejected by CyclicWords::new");
            };

            let mut original = [0_u16; MAX_SYMBOLS];
            let mut source_bytes = [[0_u8; 2]; MAX_DATA];
            for idx in 0..data {
                let word = ((idx * 137 + parity * 29 + data * 7) % 2048) as u16;
                original[idx] = word;
                source_bytes[idx] = word.to_be_bytes();
            }
            let mut parity_bytes = [[0_u8; 2]; MAX_PARITY];
            let mut remainder = [0_u16; MAX_PARITY];
            let source_slices = source_bytes.each_ref().map(|bytes| bytes.as_slice());
            let mut parity_slices = parity_bytes.each_mut().map(|bytes| bytes.as_mut_slice());
            if code
                .encode(
                    &source_slices[..data],
                    &mut parity_slices[..parity],
                    &mut remainder[..parity],
                )
                .is_err()
            {
                return Err("CyclicWords::encode failed on valid GF(2^11) words");
            }
            for idx in 0..parity {
                original[data + idx] = u16::from_be_bytes(parity_bytes[idx]);
            }

            // Repair max erasures (`parity` erased symbols in strictly rising order).
            let mut erased_words = original;
            let mut erasures = [0_usize; MAX_PARITY];
            for (slot, pos) in erasures[..parity].iter_mut().enumerate() {
                let target = slot * 2;
                erased_words[target] = 0;
                *pos = target;
            }
            let mut room = [0_u16; ROOM];
            let Ok(Some(changed)) = code.correct_word(
                &mut erased_words[..data + parity],
                &erasures[..parity],
                &mut room,
            ) else {
                return Err("erasure repair failed within parity budget");
            };
            if changed > parity || erased_words[..data + parity] != original[..data + parity] {
                return Err("erasure repair did not restore original codeword");
            }

            // Repair unknown symbol errors (`parity / 2` corrupted symbols).
            let max_errors = parity / 2;
            let mut corrupted = original;
            for err_idx in 0..max_errors {
                corrupted[err_idx * 2] ^= 0x0555;
            }
            let mut room = [0_u16; ROOM];
            let Ok(Some(found)) =
                code.correct_word(&mut corrupted[..data + parity], &[], &mut room)
            else {
                return Err("unknown-error repair failed within floor(parity / 2) budget");
            };
            if found != max_errors || corrupted[..data + parity] != original[..data + parity] {
                return Err("unknown-error repair did not restore original codeword");
            }
        }
    }
    Ok(())
}

/// Reproduces `AUD-010-ARC001`: `code_rules::run` misses TOML dependency sub-tables, commented
/// dependency headers, and multi-line inline tables while catching a plain single-line wildcard.
#[cfg(not(miri))]
fn probe_aud_010_arc001() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("aud010-code-rules-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tools")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("Cargo.lock"), "# lockfile\n").map_err(|e| e.to_string())?;

    let bypass_manifest = "\
[package]
name = \"synthetic-tool\"
version = \"0.0.0\"
edition = \"2024\"

[dependencies.subtable-wildcard]
version = \"*\"

[dependencies] # inline comment hides section from ends_with(\"dependencies]\")
commented-wildcard = \"*\"

[dev-dependencies]
multiline-wildcard = {
  version = \"*\"
}

[lints.rust]
unsafe_code = \"forbid\"

[lints.clippy]
all = \"deny\"
";
    std::fs::write(dir.join("tools/Cargo.toml"), bypass_manifest).map_err(|e| e.to_string())?;
    let bypass_result = code_rules::run(&dir);

    let caught_manifest = "\
[package]
name = \"synthetic-tool\"
version = \"0.0.0\"
edition = \"2024\"

[dependencies]
plain-wildcard = \"*\"

[lints.rust]
unsafe_code = \"forbid\"

[lints.clippy]
all = \"deny\"
";
    std::fs::write(dir.join("tools/Cargo.toml"), caught_manifest).map_err(|e| e.to_string())?;
    let caught_result = code_rules::run(&dir);
    let _ = std::fs::remove_dir_all(&dir);

    if let Err(unexpected) = bypass_result {
        return Err(format!(
            "expected bypass manifest to pass unflagged, got: {}",
            unexpected.0
        ));
    }
    match caught_result {
        Err(refused) if refused.0.contains("CORE-25") => Ok(()),
        other => Err(format!(
            "expected plain wildcard manifest to fail CORE-25, got: {other:?}"
        )),
    }
}

fn main() -> ExitCode {
    if let Err(reason) = probe_slice_as_blocks() {
        eprintln!("slice_as_blocks probe failed: {reason}");
        return ExitCode::FAILURE;
    }
    println!("ok: slice_as_blocks alignment, length and provenance probe");

    if let Err(reason) = probe_reed_solomon_cyclic_words() {
        eprintln!("CyclicWords probe failed: {reason}");
        return ExitCode::FAILURE;
    }
    println!("ok: reed-solomon-core 0.2.0 CyclicWords GF(2^11) probe");

    #[cfg(not(miri))]
    {
        if let Err(reason) = probe_aud_010_arc001() {
            eprintln!("AUD-010-ARC001 reproduction failed: {reason}");
            return ExitCode::FAILURE;
        }
        println!("ok: AUD-010-ARC001 reproduced against xtask/src/code_rules.rs");
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_as_blocks_enforces_size_alignment_and_round_trips_blocks() {
        assert_eq!(probe_slice_as_blocks(), Ok(()));
    }

    #[test]
    fn cyclic_words_repairs_erasures_and_unknown_errors_across_mhfe_card_shapes() {
        assert_eq!(probe_reed_solomon_cyclic_words(), Ok(()));
    }

    #[cfg(not(miri))]
    #[test]
    fn xtask_code_rules_misses_subtable_commented_header_and_multiline_wildcards() {
        assert_eq!(probe_aud_010_arc001(), Ok(()));
    }
}
