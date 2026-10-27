//! Exits 1 when NativeArgon2::argon2id gives a password of 2^32 bytes the tag of the empty
//! password (its length cut to 32 bits), 0 when it refuses it or gives another tag, and 2 when the
//! control fails or a call it needs is refused. A control first checks that a 2,000-byte password
//! is not cut to its first byte.

use std::process::ExitCode;

use mhfe_core::{Argon2Engine, NativeArgon2};

/// The exit code of a run in which the length is cut.
const CUT: u8 = 1;
/// The exit code of a run that proves nothing.
const BROKEN: u8 = 2;
/// The smallest Argon2id cost, 32 KiB and one pass: the check is about the password, not the work.
const MEMORY_KIB: u32 = 32;
const PASSES: u32 = 1;
/// A control password longer than one byte and far below 2^32.
const CONTROL_BYTES: usize = 2000;
/// The first length a 32-bit length cuts to 0.
const LONG_BYTES: usize = 1 << 32;

/// The message of a call the check needs that the engine refused.
fn refused(what: &'static str) -> impl Fn(mhfe_core::Error) -> String {
    move |error| format!("{what}: {error}")
}

/// Whether the long password's length is cut to 32 bits.
fn run() -> Result<bool, String> {
    let mut engine = NativeArgon2::new(MEMORY_KIB).map_err(refused("engine"))?;
    let salt = [7u8; 16];
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let control = vec![0u8; CONTROL_BYTES];
    engine
        .argon2id(&control, &salt, MEMORY_KIB, PASSES, &mut a)
        .map_err(refused("control"))?;
    engine
        .argon2id(&control[..1], &salt, MEMORY_KIB, PASSES, &mut b)
        .map_err(refused("control's first byte"))?;
    if a == b {
        return Err("control: a 2,000-byte password shares the 1-byte tag".to_owned());
    }
    let long = vec![0u8; LONG_BYTES];
    let long_result = engine.argon2id(&long, &salt, MEMORY_KIB, PASSES, &mut a);
    engine
        .argon2id(&[], &salt, MEMORY_KIB, PASSES, &mut b)
        .map_err(refused("the empty password"))?;
    let cut = long_result.is_ok() && a == b;
    println!(
        "password of {} bytes: {:?}; its tag equals that of the empty password: {cut}",
        long.len(),
        long_result
    );
    Ok(cut)
}

fn main() -> ExitCode {
    match run() {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(CUT),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(BROKEN)
        }
    }
}
