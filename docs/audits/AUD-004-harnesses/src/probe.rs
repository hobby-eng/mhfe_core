//! Bounded probes of actual public APIs with independently checked public data.

use mhfe_core::{Argon2Engine, NativeArgon2, Phrase, wallet_check::Seed};
use sha2::{Digest, Sha256};

use crate::Result;

pub(crate) fn wallet_boundary() -> Result<()> {
    for trial in 0u32..4096 {
        let mut entropy = [0u8; 32];
        entropy[28..].copy_from_slice(&trial.to_be_bytes());
        let phrase = Phrase::from_entropy(&entropy)?;
        let seed = Seed::derive(&phrase, "AUD-004 public boundary fixture");
        let digest = Sha256::new()
            .chain_update(b"MHFE-WALLET-CHECK-SEED-1")
            .chain_update(256u32.to_be_bytes())
            .chain_update(seed.as_bytes())
            .finalize();
        if digest[0] == 0 && digest[1] != 0 {
            if seed.passes() != Some(false) {
                return Err("the 16-bit check accepted an 8-bit-only fixture".into());
            }
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            println!("16-bit boundary passes: trial={trial}, public digest={hex}");
            return Ok(());
        }
    }
    Err("no discriminating fixture in the bounded public trial set".into())
}

pub(crate) fn small_stack() -> Result<()> {
    let thread = std::thread::Builder::new()
        .stack_size(32 * 1024)
        .spawn(|| {
            let mut engine = NativeArgon2::new(1024)?;
            let mut tag = [0u8; 32];
            engine.argon2id(
                b"public test password",
                b"0123456789abcdef",
                1024,
                1,
                &mut tag,
            )?;
            Ok::<_, mhfe_core::Error>(tag)
        })?;
    let tag = thread.join().map_err(|_| "small-stack caller panicked")??;
    let actual: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
    if actual != "e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2" {
        return Err("small-stack native tag differs from independent OpenSSL fixture".into());
    }
    println!("32 KiB caller, four explicit worker stacks: tag={actual}");
    Ok(())
}
