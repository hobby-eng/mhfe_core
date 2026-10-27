//! AUD-002 (mhfe-core dec9c81), CHECK-SEC-007: how the cost of each public entry point that takes
//! text grows with that text, measured in a release build with public inputs only. Each check
//! doubles the input and asks that the time grow by at most `MAX_GROWTH` per doubling (linear
//! work doubles, quadratic work quadruples), or that a refusal of an oversized input come within
//! `REFUSAL_LIMIT`. Prints PASS or FAIL per check with its timings and exits 1 when any check
//! fails. Run it with `--release` on an otherwise idle machine; the times are medians of 3 runs.

use std::time::{Duration, Instant};

use mhfe_core::repair::Repaired;
use mhfe_core::wallet_check::Seed;
use mhfe_core::{Password, Phrase};

/// The most a doubling of the input may multiply the time by.
const MAX_GROWTH: f64 = 3.0;
/// The longest a refusal of an oversized input may take.
const REFUSAL_LIMIT: Duration = Duration::from_secs(1);

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

struct Checks {
    failed: usize,
}

impl Checks {
    fn check(&mut self, name: &str, ok: bool, detail: impl std::fmt::Display) {
        println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            self.failed += 1;
        }
    }

    /// Times `run` on the inputs `make(n)` for each `n` and checks the growth per doubling.
    fn growth(
        &mut self,
        name: &str,
        sizes: &[usize],
        make: impl Fn(usize) -> String,
        run: impl Fn(&str),
    ) {
        let times: Vec<Duration> = sizes
            .iter()
            .map(|&size| {
                let input = make(size);
                median_of_3(|| run(&input))
            })
            .collect();
        let growth: Vec<f64> = times
            .windows(2)
            .map(|pair| pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-9))
            .collect();
        let worst = growth.iter().copied().fold(0.0, f64::max);
        let detail = sizes
            .iter()
            .zip(&times)
            .map(|(size, time)| format!("{size} B: {:.3} s", time.as_secs_f64()))
            .collect::<Vec<_>>()
            .join(", ");
        self.check(
            name,
            worst <= MAX_GROWTH,
            format!("{detail}; worst growth per doubling {worst:.2}"),
        );
    }
}

fn main() {
    let mut checks = Checks { failed: 0 };
    let Ok(phrase) = Phrase::from_entropy(&[0; 32]) else {
        eprintln!("the test phrase of 32 zero bytes was refused");
        std::process::exit(2);
    };
    let sizes = [16 << 10, 32 << 10, 64 << 10, 128 << 10];

    // The BIP39 passphrase has no length limit (specification: the password's limits do not apply
    // to Q). A baseline of ASCII, which NFKD keeps, against a starter followed by combining acute
    // accents (U+0301, class 230, two bytes each), which NFKD also keeps unchanged.
    checks.growth(
        "Seed::derive, ASCII passphrase",
        &sizes,
        |bytes| "a".repeat(bytes),
        |passphrase| drop(Seed::derive(&phrase, passphrase)),
    );
    checks.growth(
        "Seed::derive, passphrase of one starter and combining marks",
        &sizes,
        |bytes| format!("a{}", "\u{301}".repeat(bytes / 2)),
        |passphrase| drop(Seed::derive(&phrase, passphrase)),
    );
    checks.growth(
        "wallet_check::draw, passphrase of one starter and combining marks, first trial",
        &sizes,
        |bytes| format!("a{}", "\u{301}".repeat(bytes / 2)),
        |passphrase| {
            // Cancelled at its first trial, so that only the passphrase's NFKD is timed.
            let _ =
                mhfe_core::wallet_check::draw(
                    passphrase,
                    &mut |_| std::ops::ControlFlow::Break(()),
                );
        },
    );

    // Oversized inputs are refused without work that grows with them.
    let large = 64 << 20;
    let marks = format!("a{}", "\u{301}".repeat(large / 2));
    let mut refused = true;
    let time = median_of_3(|| refused &= Password::new(&marks).is_err());
    checks.check(
        "Password::new refuses 64 MiB of combining marks",
        refused && time <= REFUSAL_LIMIT,
        format!("{:.3} s, refused {refused}", time.as_secs_f64()),
    );
    let spaces = format!("{}abandon", " ".repeat(large));
    let mut refused = true;
    let time = median_of_3(|| refused &= Phrase::read(&spaces).is_err());
    checks.check(
        "Phrase::read refuses 64 MiB of spaces",
        refused && time <= REFUSAL_LIMIT,
        format!("{:.3} s, refused {refused}", time.as_secs_f64()),
    );

    // The repair's search: 24 words and 8 card words that no repair within the bound fixes, so
    // every set of up to four wrong places is tried.
    let written = ["zoo"; 24].join(" ");
    let card = ["abandon"; 8].join(" ");
    // Its answer does not matter: the check is the time of the search, whatever it finds.
    let time = median_of_3(|| {
        let _ = Repaired::of(&written, &card);
    });
    checks.check(
        "Repaired::of, worst search",
        time <= REFUSAL_LIMIT,
        format!("{:.3} s", time.as_secs_f64()),
    );

    println!("{} failed", checks.failed);
    std::process::exit(i32::from(checks.failed > 0));
}
