//! AUD-002 verification of the fix to the NFKD passphrase cost finding, AUD-002-SEC001 (release
//! build, public inputs only). For passphrases of 16 to 128 KiB, median of 3, it times
//! `Seed::derive` on:
//! - checked, must grow at most 3 times per doubling: one run of U+0301 (one class, in order); one
//!   run of U+0316 then U+0301 (two classes, in order); ASCII;
//! - reported only, as the audit's fix left them quadratic and documented them: U+0301 U+0316
//!   repeated (classes alternate); one U+0301 followed by U+0316 repeated (one mark above a long
//!   run of a lower class).
//!
//! For every shape it also checks, at 16 KiB, that the crate's seed equals BIP39's seed of the
//! passphrase normalized by unicode-normalization's own iterator, so that the expected value never
//! goes through the crate's NFKD writer (CORE-28). Exit 0 when every checked item passes, 1 when
//! one fails, 2 when the harness cannot run.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use mhfe_core::Phrase;
use mhfe_core::wallet_check::Seed;
use unicode_normalization::UnicodeNormalization;

/// The largest growth per doubling that still reads as linear: a linear cost grows about 2 times,
/// a quadratic one about 4.
const MAX_GROWTH: f64 = 3.0;
/// The shortest time a growth divides by, in seconds, so that runs below the clock's resolution
/// read as no growth.
const SHORTEST_TIME: f64 = 1e-3;
/// The passphrase lengths in bytes: 16, 32, 64 and 128 KiB.
const SIZES: [usize; 4] = [16 << 10, 32 << 10, 64 << 10, 128 << 10];
/// The entropy of BIP39's first 24-word test vector (23 times "abandon", then "art"): public.
const ENTROPY: [u8; 32] = [0; 32];

/// A passphrase shape: its name, what makes one of a length in bytes, and whether its growth is
/// checked.
type Shape = (&'static str, fn(usize) -> String, bool);

fn median_of_3(mut run: impl FnMut()) -> Duration {
    let mut times: Vec<Duration> = (0..3)
        .map(|_| {
            let start = Instant::now();
            run();
            start.elapsed()
        })
        .collect();
    times.sort();
    times[1]
}

fn one_class(bytes: usize) -> String {
    format!("a{}", "\u{301}".repeat(bytes / 2))
}

fn two_classes_in_order(bytes: usize) -> String {
    format!(
        "a{}{}",
        "\u{316}".repeat(bytes / 4),
        "\u{301}".repeat(bytes / 4)
    )
}

fn ascii(bytes: usize) -> String {
    "a".repeat(bytes)
}

fn alternating(bytes: usize) -> String {
    format!("a{}", "\u{301}\u{316}".repeat(bytes / 4))
}

fn one_above_a_run(bytes: usize) -> String {
    format!("a\u{301}{}", "\u{316}".repeat(bytes / 2))
}

/// Prints a line per check and returns how many checks failed.
fn run() -> Result<usize, String> {
    let phrase = Phrase::from_entropy(&ENTROPY).map_err(|error| format!("mhfe-core: {error}"))?;
    let mnemonic =
        bip39::Mnemonic::from_entropy(&ENTROPY).map_err(|error| format!("bip39: {error}"))?;
    let shapes: [Shape; 5] = [
        ("one class in order", one_class, true),
        ("two classes in order", two_classes_in_order, true),
        ("ASCII", ascii, true),
        ("classes alternating (residual)", alternating, false),
        (
            "one mark above a run of a lower class (residual)",
            one_above_a_run,
            false,
        ),
    ];
    let mut failed = 0;
    for (name, make, checked) in shapes {
        let text = make(SIZES[0]);
        let reference: String = text.nfkd().collect();
        let same =
            Seed::derive(&phrase, &text).as_bytes() == &mnemonic.to_seed_normalized(&reference);
        let verdict = if same { "PASS" } else { "FAIL" };
        println!("{verdict} {name}: seed equals BIP39's seed of the reference NFKD");
        failed += usize::from(!same);

        let times: Vec<f64> = SIZES
            .iter()
            .map(|&size| {
                let input = make(size);
                median_of_3(|| drop(Seed::derive(&phrase, &input))).as_secs_f64()
            })
            .collect();
        let worst = times
            .windows(2)
            .map(|pair| pair[1] / pair[0].max(SHORTEST_TIME))
            .fold(0.0, f64::max);
        let detail: Vec<String> = SIZES
            .iter()
            .zip(&times)
            .map(|(size, time)| format!("{} KiB {time:.4} s", size >> 10))
            .collect();
        let verdict = if !checked {
            "INFO"
        } else if worst <= MAX_GROWTH {
            "PASS"
        } else {
            failed += 1;
            "FAIL"
        };
        println!(
            "{verdict} {name}: {}; worst growth per doubling {worst:.2}",
            detail.join(", ")
        );
    }
    println!("{failed} failed");
    Ok(failed)
}

fn main() -> ExitCode {
    match run() {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(error) => {
            eprintln!("ERROR {error}");
            ExitCode::from(2)
        }
    }
}
