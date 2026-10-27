//! AUD-002 skeptic harness for the FUN finding "NFKD writer is quadratic in a run of combining
//! marks". Public API of mhfe-core only, public inputs only. Release build.
//!
//! Checks (exit 1 when any fails):
//! - every timed seed equals bip39's seed of the passphrase normalized by unicode-normalization's
//!   own `nfkd()` (so a timing is of a correct result);
//! - for one run of U+0301, one run of U+0316 U+0301 and ASCII, `Seed::derive` grows by at most
//!   x3 per doubling once it takes more than 100 ms (n log n would give about x2);
//! - `wallet_check::draw` with a fill that cancels at once (so only its NFKD runs) grows the same;
//! - the same length made of stream-safe runs (a starter and 30 marks, repeated) grows at most x3.
//!
//! Each timing is the minimum of 3 runs.

use std::ops::ControlFlow;
use std::time::Instant;

use mhfe_core::Phrase;
use mhfe_core::wallet_check::{Seed, draw};
use unicode_normalization::UnicodeNormalization;

/// Any public entropy: the phrase only gives PBKDF2 its password.
const ENTROPY: [u8; 32] = [0x5a; 32];
/// The most a doubling may multiply the time by: n log n gives about 2, quadratic work 4.
const MAX_GROWTH: f64 = 3.0;
/// Below this many seconds the fixed cost of PBKDF2 and the timer's noise dominate the ratio, so a
/// ratio counts only when the larger time is above it.
const NOISE_FLOOR_S: f64 = 0.1;
/// The smallest earlier time a ratio divides by, in seconds, against a division by zero.
const MIN_DIVISOR_S: f64 = 1e-6;
/// The exit code of a run that could not measure: the phrase refused, or a draw not cancelled.
const BROKEN: i32 = 2;

/// The test phrase and its seed computed without the crate, or exit 2.
fn phrases() -> (Phrase, bip39::Mnemonic) {
    let phrase = Phrase::from_entropy(&ENTROPY);
    let reference = phrase
        .as_ref()
        .ok()
        .and_then(|phrase| bip39::Mnemonic::parse_normalized(phrase.as_str()).ok());
    let (Ok(phrase), Some(reference)) = (phrase, reference) else {
        eprintln!("the test phrase was refused");
        std::process::exit(BROKEN);
    };
    (phrase, reference)
}

fn min_of_3(mut run: impl FnMut()) -> f64 {
    (0..3)
        .map(|_| {
            let start = Instant::now();
            run();
            start.elapsed().as_secs_f64()
        })
        .fold(f64::INFINITY, f64::min)
}

/// Times `Seed::derive` on each passphrase and checks its seed against the reference.
fn derive_series(name: &str, passphrases: &[String], failures: &mut u32) {
    let (phrase, reference) = phrases();
    let mut times = Vec::new();
    for passphrase in passphrases {
        let expected = reference.to_seed_normalized(&passphrase.nfkd().collect::<String>());
        let seed = Seed::derive(&phrase, passphrase);
        if seed.as_bytes() != &expected {
            println!(
                "FAIL {name}: seed differs from the reference at {} bytes",
                passphrase.len()
            );
            *failures += 1;
        }
        times.push(min_of_3(|| {
            std::hint::black_box(Seed::derive(&phrase, passphrase));
        }));
    }
    report(name, passphrases, &times, failures);
}

fn report(name: &str, passphrases: &[String], times: &[f64], failures: &mut u32) {
    let mut worst: f64 = 0.0;
    for pair in times.windows(2) {
        if pair[1] > NOISE_FLOOR_S {
            worst = worst.max(pair[1] / pair[0].max(MIN_DIVISOR_S));
        }
    }
    let verdict = if worst > MAX_GROWTH { "FAIL" } else { "PASS" };
    if worst > MAX_GROWTH {
        *failures += 1;
    }
    let cells: Vec<String> = passphrases
        .iter()
        .zip(times)
        .map(|(p, t)| format!("{} B {:.4} s", p.len(), t))
        .collect();
    println!(
        "{verdict} {name}: {}; worst growth per doubling above 100 ms x{worst:.2}",
        cells.join(", ")
    );
}

fn main() {
    let mut failures = 0;
    let marks = [10_000usize, 20_000, 40_000, 80_000];
    let one_class: Vec<String> = marks.iter().map(|&n| "\u{301}".repeat(n)).collect();
    let two_classes: Vec<String> = marks
        .iter()
        .map(|&n| "\u{316}\u{301}".repeat(n / 2))
        .collect();
    let ascii: Vec<String> = marks.iter().map(|&n| "a".repeat(2 * n)).collect();
    // A starter and 30 marks: the longest run the stream-safe text format allows, 61 bytes.
    let stream_safe: Vec<String> = marks
        .iter()
        .map(|&n| format!("a{}", "\u{316}\u{301}".repeat(15)).repeat(n / 30))
        .collect();
    derive_series("Seed::derive, ASCII", &ascii, &mut failures);
    derive_series("Seed::derive, one run of U+0301", &one_class, &mut failures);
    derive_series(
        "Seed::derive, one run of U+0316 U+0301",
        &two_classes,
        &mut failures,
    );
    derive_series(
        "Seed::derive, stream-safe runs of 30 marks",
        &stream_safe,
        &mut failures,
    );

    // draw: the fill cancels before the first trial, after the passphrase has been normalized.
    let times: Vec<f64> = one_class
        .iter()
        .map(|passphrase| {
            min_of_3(|| {
                let result = draw(passphrase, &mut |_| ControlFlow::Break(()));
                if result.is_ok() {
                    eprintln!("draw was not cancelled at its first trial");
                    std::process::exit(BROKEN);
                }
            })
        })
        .collect();
    report(
        "wallet_check::draw (cancelled at once), one run of U+0301",
        &one_class,
        &times,
        &mut failures,
    );

    // Ordinary lengths: a 1,024-byte run of marks, the size limit of an MHFE password.
    let (phrase, _) = phrases();
    let short = "\u{316}\u{301}".repeat(256);
    let t = min_of_3(|| {
        std::hint::black_box(Seed::derive(&phrase, &short));
    });
    println!(
        "INFO Seed::derive, one run of 512 marks ({} B): {:.6} s",
        short.len(),
        t
    );

    if failures > 0 {
        println!("{failures} failed");
        std::process::exit(1);
    }
    println!("all passed");
}
