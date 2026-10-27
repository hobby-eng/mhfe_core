//! AUD-002 (mhfe-core dec9c81), skeptic review of the finding that a passphrase holding a long run
//! of combining marks makes `Seed::derive` take quadratic time. Release build, public inputs only.
//!
//! For passphrases of 16 to 128 KiB it times, median of 3:
//! - `Seed::derive` with ASCII (baseline: PBKDF2 and the copy are linear);
//! - `Seed::derive` with `a` and U+0301 repeated (a run already in canonical order);
//! - `Seed::derive` with `a` and U+0301 U+0316 repeated (classes 230, 220: out of order);
//! - unicode-normalization's own `nfkd()` iterator on the in-order input (reference cost);
//!
//! and checks that each grows by at most 3.0 per doubling (linear doubles, quadratic quadruples).
//! It also checks that the seed equals bip39's seed of the passphrase normalized by the reference
//! NFKD, computed without the crate, so the timing is of a correct result. Exit 1 when any check
//! fails, 0 when all pass, 2 when the test phrase is refused.

use std::time::{Duration, Instant};

use mhfe_core::Phrase;
use mhfe_core::wallet_check::Seed;
use unicode_normalization::UnicodeNormalization;

/// The most a doubling may multiply the time by: linear work doubles it, quadratic quadruples it.
const MAX_GROWTH: f64 = 3.0;
/// The passphrase sizes in bytes, 16 to 128 KiB, each double the one before.
const SIZES: [usize; 4] = [16 << 10, 32 << 10, 64 << 10, 128 << 10];
/// The smallest earlier time a ratio divides by, in seconds, against a division by zero.
const MIN_DIVISOR_S: f64 = 1e-9;
/// The exit code of a run that could not measure.
const BROKEN: i32 = 2;

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

fn growth(failed: &mut usize, name: &str, make: impl Fn(usize) -> String, run: impl Fn(&str)) {
    let times: Vec<f64> = SIZES
        .iter()
        .map(|&size| {
            let input = make(size);
            median_of_3(|| run(&input)).as_secs_f64()
        })
        .collect();
    let worst = times
        .windows(2)
        .map(|pair| pair[1] / pair[0].max(MIN_DIVISOR_S))
        .fold(0.0, f64::max);
    let ok = worst <= MAX_GROWTH;
    let detail: Vec<String> = SIZES
        .iter()
        .zip(&times)
        .map(|(size, time)| format!("{} KiB {time:.4} s", size >> 10))
        .collect();
    println!(
        "{} {name}: {}; worst growth per doubling {worst:.2}",
        if ok { "PASS" } else { "FAIL" },
        detail.join(", ")
    );
    if !ok {
        *failed += 1;
    }
}

fn in_order(bytes: usize) -> String {
    format!("a{}", "\u{301}".repeat(bytes / 2))
}

fn out_of_order(bytes: usize) -> String {
    format!("a{}", "\u{301}\u{316}".repeat(bytes / 4))
}

fn main() {
    let mut failed = 0;
    let phrase = Phrase::from_entropy(&[0; 32]);
    let expected = phrase
        .as_ref()
        .ok()
        .and_then(|phrase| bip39::Mnemonic::parse_normalized(phrase.as_str()).ok());
    let (Ok(phrase), Some(expected)) = (phrase, expected) else {
        eprintln!("the test phrase of 32 zero bytes was refused");
        std::process::exit(BROKEN);
    };

    // Correctness at the smallest size: the seed from mhfe-core equals bip39's seed of the
    // passphrase normalized by the reference iterator, so that neither side is the crate's own
    // NFKD (an in-order run is already in NFKD, so the crate on the reference would be the crate
    // on the same text).
    for make in [in_order as fn(usize) -> String, out_of_order] {
        let text = make(SIZES[0]);
        let reference: String = text.nfkd().collect();
        let same =
            Seed::derive(&phrase, &text).as_bytes() == &expected.to_seed_normalized(&reference);
        println!(
            "{} seed equals the seed of the reference NFKD",
            if same { "PASS" } else { "FAIL" }
        );
        failed += usize::from(!same);
    }

    growth(
        &mut failed,
        "Seed::derive, ASCII",
        |bytes| "a".repeat(bytes),
        |text| drop(Seed::derive(&phrase, text)),
    );
    growth(
        &mut failed,
        "unicode-normalization nfkd(), in-order marks",
        in_order,
        |text| drop(std::hint::black_box(text.nfkd().collect::<String>())),
    );
    growth(
        &mut failed,
        "Seed::derive, in-order marks",
        in_order,
        |text| drop(Seed::derive(&phrase, text)),
    );
    growth(
        &mut failed,
        "Seed::derive, out-of-order marks",
        out_of_order,
        |text| drop(Seed::derive(&phrase, text)),
    );

    println!("{failed} failed");
    std::process::exit(i32::from(failed > 0));
}
