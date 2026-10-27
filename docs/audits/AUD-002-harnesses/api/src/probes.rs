//! The probes of the api review: the length of an Argon2id password (CHECK-API-001), the stack a
//! public function needs (CHECK-API-003) and the cost of a run of combining marks (CHECK-API-001).

use std::ops::ControlFlow;
use std::process::Command;
use std::time::Instant;

use mhfe_core::password_check::Check;
use mhfe_core::wallet_check::{self, Seed};
use mhfe_core::{Argon2Engine, NativeArgon2, Password, Phrase};

use crate::Outcome;

/// The BIP39 phrase of 32 zero bytes, a public test phrase.
const ZERO_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon art";

/// The smallest Argon2id cost, 32 KiB and one pass: the probe is about the password, not the work.
const MEMORY_KIB: u32 = 32;
const PASSES: u32 = 1;
/// One byte more than a 32-bit length can hold, so that a length cut to 32 bits reads 1.
const LONG_PASSWORD: usize = (1 << 32) + 1;

/// The stack sizes tried, in KiB, smallest first.
const SIZES_KIB: [usize; 8] = [64, 96, 128, 136, 144, 160, 192, 256];
/// The default thread stack of musl's pthread_create, which a C host may give a caller.
const MUSL_DEFAULT_KIB: usize = 128;
/// The public functions that handle a secret, by the names `call` knows them by.
const FUNCTIONS: [&str; 6] = [
    "Phrase::read_word",
    "Phrase::read",
    "Password::new",
    "Check::of",
    "Seed::derive",
    "draw",
];

/// The lengths of the run of U+0301, each double the one before.
const MARKS: [usize; 4] = [10_000, 20_000, 40_000, 80_000];
/// The most a doubling may multiply the time by: a pass linear up to a log factor about doubles
/// it, a quadratic one quadruples it.
const MAX_GROWTH: f64 = 3.0;

/// The contract of `Argon2Engine::argon2id`: the tag of `password`, or an error. A password of
/// 2^32 + 1 zero bytes must not give the tag of the one-byte password [0].
pub(crate) fn truncation() -> Outcome {
    let mut engine = NativeArgon2::new(MEMORY_KIB).map_err(|error| format!("engine: {error}"))?;
    let salt = [7u8; 16];
    // Zero pages from the allocator: only the first page is ever touched when the length is cut
    // to 1.
    let long = vec![0u8; LONG_PASSWORD];
    let mut long_key = [0u8; 32];
    let long_result = engine.argon2id(&long, &salt, MEMORY_KIB, PASSES, &mut long_key);
    let mut short_key = [0u8; 32];
    engine
        .argon2id(&long[..1], &salt, MEMORY_KIB, PASSES, &mut short_key)
        .map_err(|error| format!("the 1-byte password: {error}"))?;
    let same = long_result.is_ok() && long_key == short_key;
    println!(
        "password of {} bytes: {:?}; its tag equals that of the 1-byte password: {same}",
        long.len(),
        long_result
    );
    Ok(!same)
}

/// For each function, the smallest of `SIZES_KIB` whose thread completes the call, each call in
/// a child process, since an overflow ends the process. The check: every function runs on a
/// thread of `MUSL_DEFAULT_KIB`.
pub(crate) fn stack_floor() -> Outcome {
    let me = std::env::current_exe().map_err(|error| format!("this program's path: {error}"))?;
    let mut held = true;
    for name in FUNCTIONS {
        let mut floor = None;
        for kib in SIZES_KIB {
            let child = Command::new(&me)
                .args(["stack", &kib.to_string(), name])
                .output()
                .map_err(|error| format!("child for {name} on {kib} KiB: {error}"))?;
            // A signal is the overflow (SIGSEGV, or SIGABRT from Rust's guard page handler); an
            // exit code other than 0 is a call that went wrong, which says nothing of the stack.
            match child.status.code() {
                Some(0) => {
                    floor = Some(kib);
                    break;
                }
                None => {}
                Some(code) => {
                    let said = String::from_utf8_lossy(&child.stderr);
                    return Err(format!(
                        "{name} on {kib} KiB exited {code}: {}",
                        said.trim()
                    ));
                }
            }
        }
        println!("{name}: smallest thread stack that completes the call: {floor:?} KiB");
        held &= floor.is_some_and(|kib| kib <= MUSL_DEFAULT_KIB);
    }
    Ok(held)
}

/// One call of the function `name` on a new thread of `kib` KiB.
pub(crate) fn stack(kib: &str, name: &str) -> Outcome {
    let kib: usize = kib
        .parse()
        .map_err(|_| format!("not a size in KiB: {kib}"))?;
    let name = name.to_owned();
    std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || call(&name))
        .map_err(|error| format!("thread of {kib} KiB: {error}"))?
        .join()
        .map_err(|_| "the thread panicked".to_owned())??;
    Ok(true)
}

/// One public function that handles a secret, by name, with an input it accepts.
fn call(name: &str) -> Result<(), String> {
    let answered = match name {
        "Phrase::read" => Phrase::read(ZERO_24).is_ok(),
        "Phrase::read_word" => Phrase::read_word("aban") == Some("abandon"),
        "Password::new" => Password::new("public test password").is_ok(),
        "Check::of" => Check::of("a b") == Check::NotApplicable,
        "Seed::derive" => Phrase::read(ZERO_24)
            .map(|phrase| Seed::derive(&phrase, ""))
            .is_ok(),
        "draw" => {
            let mut once = false;
            // Its answer does not matter: the probe measures the stack of the call, which runs
            // one trial and is then cancelled.
            let _ = wallet_check::draw("", &mut |_| {
                if once {
                    ControlFlow::Break(())
                } else {
                    once = true;
                    ControlFlow::Continue(())
                }
            });
            true
        }
        other => return Err(format!("unknown function {other}")),
    };
    if answered {
        Ok(())
    } else {
        Err(format!("{name} refused or misread its public test input"))
    }
}

/// Seed::derive with a passphrase of `MARKS` U+0301 after one letter, a single run of
/// non-starters: the time of each doubling. The check: the last doubling stays within
/// `MAX_GROWTH`.
pub(crate) fn nfkd() -> Outcome {
    let phrase = Phrase::read(ZERO_24).map_err(|error| format!("the test phrase: {error}"))?;
    let mut times = Vec::new();
    for marks in MARKS {
        let passphrase = format!("a{}", "\u{301}".repeat(marks));
        let started = Instant::now();
        let seed = Seed::derive(&phrase, &passphrase);
        let seconds = started.elapsed().as_secs_f64();
        drop(seed);
        println!(
            "{marks} combining marks ({} bytes): {seconds:.3} s",
            passphrase.len()
        );
        times.push(seconds);
    }
    let ratios: Vec<f64> = times.windows(2).map(|pair| pair[1] / pair[0]).collect();
    println!("time ratio per doubling: {ratios:.2?}");
    Ok(ratios.last().is_some_and(|&ratio| ratio <= MAX_GROWTH))
}
