//! The corpora at full cost: every transcript of both suites through `Mhfe` on the vendored
//! Argon2id engine at its recorded settings, 2 or 3 GiB per call, with each salt and key compared
//! with the recorded ones, then every recovery case on the same engine.
//!
//! Expensive, hours for both suites: run at a release or on request with
//! `cargo test --locked --release --test full_cost -- --ignored --nocapture`, shared among
//! processes with `MHFE_VECTOR_SHARE=k/n` (tests/vector_share/share.rs).

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute, alone, or by #[test].
#![cfg(test)]
// WebAssembly has no native engine.
#![cfg(not(target_arch = "wasm32"))]

#[path = "support/corpus.rs"]
mod corpus;
// In a folder, so that Cargo does not build it as a test of its own; named by its path, since
// there are no mod.rs files (RUST-03).
#[path = "vector_share/share.rs"]
mod vector_share;

use corpus::{RecordedKeys, text};
use mhfe_core::{Argon2Engine, Error, NativeArgon2, Suite};

const SUITES: [(&str, Suite); 2] = [
    ("spec/vectors/suite3", Suite::TwentyFourWords),
    ("spec/vectors/suite4", Suite::SameLength),
];

/// The vendored engine, whose every key must be the one the transcript records for its salt.
struct Compared {
    native: NativeArgon2,
    recorded: RecordedKeys,
}

impl Argon2Engine for Compared {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; 16],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8; 32],
    ) -> Result<(), Error> {
        self.native
            .argon2id(password, salt, memory_kib, passes, key)?;
        assert_eq!(
            key[..],
            *self.recorded.key(password, salt, memory_kib, passes)
        );
        Ok(())
    }
}

/// The engine for the settings of a transcript's inputs or of a recovery case.
fn native(record: &serde_json::Value) -> NativeArgon2 {
    NativeArgon2::new(corpus::work_of(record).memory_kib()).unwrap()
}

#[test]
#[ignore = "full-size Argon2id: hours for both suites"]
fn every_transcript_and_recovery_case_is_reproduced_at_full_cost() {
    // The transcripts, then the recovery cases, in one count, of which this process takes its
    // share.
    let mut item = 0;
    for (folder, suite) in SUITES {
        for transcript in corpus::transcripts(folder) {
            if vector_share::mine(item) {
                let engine = Compared {
                    native: native(&transcript["inputs"]),
                    recorded: RecordedKeys::of(&transcript),
                };
                corpus::replay(&transcript, suite, engine);
                println!("{}: reproduced", text(&transcript, "name"));
            }
            item += 1;
        }
    }
    for (folder, _) in SUITES {
        for case in corpus::recovery_cases(folder) {
            if vector_share::mine(item) {
                corpus::recover(&case, native(&case));
                println!("{}: reproduced", text(&case, "name"));
            }
            item += 1;
        }
    }
}
