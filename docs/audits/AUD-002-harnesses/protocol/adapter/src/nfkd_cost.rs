//! The time `Seed::derive` takes as a BIP39 passphrase grows, for ASCII and for runs of combining
//! marks (non-starters). NFKD needs O(n log n) at most; the check fails when doubling a passphrase
//! more than triples the time, the quadratic growth that the protocol review of AUD-002 reports.
//! Rewritten from the archived `nfkd_cost.py`, whose lines it prints.

use std::time::Instant;

use mhfe_core::Phrase;
use mhfe_core::wallet_check::Seed;

/// How many times each unit is repeated, each count double the one before.
const COUNTS: [usize; 4] = [10_000, 20_000, 40_000, 80_000];
/// Each unit with its name: ASCII, which NFKD keeps; U+0301 (class 230), a run in canonical order;
/// and U+0316 U+0301 (classes 220 and 230), a run out of canonical order.
const UNITS: [(&str, &str); 3] = [
    ("ascii a", "a"),
    ("U+0301 (one class)", "\u{301}"),
    ("U+0316 U+0301 (two classes)", "\u{316}\u{301}"),
];
/// The most a doubling may multiply the time by: n log n about doubles it, quadratic work
/// quadruples it.
const MAX_GROWTH: f64 = 3.0;
/// Below this many milliseconds the fixed cost of PBKDF2 and the timer's noise dominate the
/// ratio, so a ratio counts only when the larger time is above it.
const NOISE_FLOOR_MS: f64 = 100.0;
/// The smallest earlier time a ratio divides by, in milliseconds, against a division by zero.
const MIN_DIVISOR_MS: f64 = 0.001;
/// Any public entropy: the phrase only gives PBKDF2 its password.
const ENTROPY: [u8; 32] = [0x5a; 32];

/// Times every unit at every count; true when no unit grows too fast.
pub(crate) fn run() -> Result<bool, String> {
    let phrase =
        Phrase::from_entropy(&ENTROPY).map_err(|error| format!("the test phrase: {error}"))?;
    let mut failed = false;
    for (name, unit) in UNITS {
        let mut cells = Vec::new();
        let mut times = Vec::new();
        for count in COUNTS {
            let passphrase = unit.repeat(count);
            let started = Instant::now();
            let seed = Seed::derive(&phrase, &passphrase);
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            drop(seed);
            cells.push(format!("{} bytes {ms:.1} ms", passphrase.len()));
            times.push(ms);
        }
        let (last, before) = match times.as_slice() {
            [.., before, last] => (*last, *before),
            _ => return Err("fewer than two counts".to_owned()),
        };
        let ratio = last / before.max(MIN_DIVISOR_MS);
        println!("{name}: {}; last doubling x{ratio:.1}", cells.join(", "));
        failed |= last > NOISE_FLOOR_MS && ratio > MAX_GROWTH;
    }
    if failed {
        println!("FAILED: Seed::derive grows faster than n log n with the passphrase length");
    } else {
        println!("Seed::derive grows at most n log n.");
    }
    Ok(!failed)
}
