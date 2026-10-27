//! AUD-002 skeptic: does a run of combining marks in a BIP39 passphrase make `Seed::derive` and
//! `wallet_check::draw` quadratic, and does the cost come from the run rather than the length?
//!
//! Each case is timed at 10,000, 20,000, 40,000 and 80,000 marks (median of 3). A case passes when
//! the last doubling at most triples the time. Expected on dec9c81: the control (the same marks,
//! each after its own letter, so every run has length 1) passes; the single-run cases of
//! `Seed::derive` and `draw` fail with a growth of about 4; exit 1. The 4,096-mark line (the size
//! of an 8 KiB typed line) is informational.

use std::ops::ControlFlow;
use std::time::Instant;

use mhfe_core::Phrase;
use mhfe_core::wallet_check::{Seed, draw};

/// The exit code of a run in which a case grew too fast; 0 is a run in which every case passed.
const FAILED: i32 = 1;
/// The exit code of a run that could not measure: the phrase refused, or a draw not cancelled.
const BROKEN: i32 = 2;
/// The lengths of the runs of marks, each double the one before.
const MARKS: [usize; 4] = [10_000, 20_000, 40_000, 80_000];
/// The most the last doubling may multiply the time by: n log n about doubles it, quadratic work
/// quadruples it.
const MAX_GROWTH: f64 = 3.0;
/// The smallest earlier time a ratio divides by, in seconds, against a division by zero.
const MIN_DIVISOR_S: f64 = 1e-6;
/// The marks of an 8 KiB typed line, for information.
const TYPED_LINE_MARKS: usize = 4_096;

const ZERO_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon art";

fn median(mut run: impl FnMut() -> f64) -> f64 {
    let mut times = [run(), run(), run()];
    times.sort_by(f64::total_cmp);
    times[1]
}

fn derive(phrase: &Phrase, passphrase: &str) -> f64 {
    median(|| {
        let started = Instant::now();
        drop(Seed::derive(phrase, passphrase));
        started.elapsed().as_secs_f64()
    })
}

/// `draw` normalizes the passphrase, then asks for the first trial; `Break` stops it there.
fn draw_only_normalizing(passphrase: &str) -> f64 {
    median(|| {
        let started = Instant::now();
        let result = draw(passphrase, &mut |_| ControlFlow::Break(()));
        let seconds = started.elapsed().as_secs_f64();
        if result.is_ok() {
            eprintln!("draw was not cancelled at its first trial");
            std::process::exit(BROKEN);
        }
        seconds
    })
}

fn case(name: &str, make: fn(usize) -> String, time: &dyn Fn(&str) -> f64) -> bool {
    let mut times = Vec::new();
    let mut line = String::new();
    for marks in MARKS {
        let passphrase = make(marks);
        let seconds = time(&passphrase);
        line += &format!(" {marks} marks ({} B) {seconds:.4} s;", passphrase.len());
        times.push(seconds);
    }
    let growth = times
        .windows(2)
        .map(|pair| pair[1] / pair[0].max(MIN_DIVISOR_S))
        .collect::<Vec<_>>();
    let pass = growth.last().is_some_and(|&last| last <= MAX_GROWTH);
    println!(
        "{} {name}:{line} growth per doubling {growth:.2?}",
        if pass { "PASS" } else { "FAIL" }
    );
    pass
}

fn one_run(marks: usize) -> String {
    format!("a{}", "\u{301}".repeat(marks))
}

fn runs_of_one(marks: usize) -> String {
    "a\u{301}".repeat(marks)
}

fn main() {
    let Ok(phrase) = Phrase::read(ZERO_24) else {
        eprintln!("the test phrase was refused");
        std::process::exit(BROKEN);
    };
    let mut ok = true;
    ok &= case(
        "Seed::derive, control (runs of one mark)",
        runs_of_one,
        &|text| derive(&phrase, text),
    );
    ok &= case("Seed::derive, one run of marks", one_run, &|text| {
        derive(&phrase, text)
    });
    ok &= case(
        "draw (normalization only), one run of marks",
        one_run,
        &|text| draw_only_normalizing(text),
    );
    let typed_line = one_run(TYPED_LINE_MARKS);
    println!(
        "INFO Seed::derive, one run of 4,096 marks ({} B, an 8 KiB typed line): {:.4} s",
        typed_line.len(),
        derive(&phrase, &typed_line)
    );
    if !ok {
        eprintln!("quadratic growth in a run of combining marks");
        std::process::exit(FAILED);
    }
}
