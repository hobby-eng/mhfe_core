//! The suite 3 corpus, `tests/spec/vectors/suite3/`, through the public API: its files are checked
//! against its `SHA256SUMS`, its 17 transcripts are created and recovered with their recorded
//! Argon2id keys, the recovery cases those keys reach give their recorded readings, and its fast
//! cases of settings, phrases and containers give their recorded outcomes before any Argon2id work.
//! The password cases are in tests/passwords.rs; the length detection and verifier cases compare
//! values the API hides and run in the crate (`packing.rs`). The other recovery cases need Argon2id
//! at full cost (tests/full_cost.rs). The specification whose vectors every test reads, the
//! submodule `tests/spec`, is checked here to be the version this crate implements.

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute or by #[test].
#![cfg(test)]

#[path = "support/corpus.rs"]
mod corpus;

use corpus::{NoArgon2Calls, RecordedKeys, every_round, number, text};
use mhfe_core::{Error, Mhfe, Phrase, Suite, WorkFactor};
use serde_json::Value;

const FOLDER: &str = "spec/vectors/suite3";

/// The submodule pins a commit of the specification; the crate's texts name the specification by
/// its version, and this test checks that the pinned commit's header names that version.
#[test]
fn the_vectors_are_those_of_specification_0_7_0() {
    assert_eq!(corpus::specification_version(), "0.7.0");
}

#[test]
fn every_transcript_is_created_and_recovered_as_recorded() {
    let transcripts = corpus::transcripts(FOLDER);
    for transcript in &transcripts {
        corpus::replay(
            transcript,
            Suite::TwentyFourWords,
            RecordedKeys::of(transcript),
        );
    }
    assert_eq!(transcripts.len(), 17);
}

/// `stated-24-words` and `selected-24-words`: the password and settings of `zero-12`, 24 words
/// stated.
#[test]
fn the_recovery_cases_of_recorded_keys_give_their_readings() {
    assert_eq!(corpus::recover_with_recorded_keys(FOLDER), 2);
}

#[test]
fn settings_are_accepted_or_refused_as_recorded() {
    let cases = corpus::read(FOLDER, "validation-cases.json");
    let cases = cases["settings"].as_array().unwrap();
    for case in cases {
        let id = text(case, "id");
        let (pim, level) = (number(case, "pim"), number(case, "memory_level"));
        let result = WorkFactor::new(pim, level);
        match case.get("expected_error").and_then(Value::as_str) {
            None => {
                let work = result.unwrap();
                assert_eq!(
                    work.memory_kib(),
                    number(case, "expected_memory_kib"),
                    "{id}"
                );
                assert_eq!(work.passes(), number(case, "expected_passes"), "{id}");
            }
            Some("INVALID_PIM") => assert_eq!(result, Err(Error::InvalidPim { pim }), "{id}"),
            Some("INVALID_MEMORY_LEVEL") => {
                assert_eq!(result, Err(Error::InvalidMemoryLevel { level }), "{id}");
            }
            Some(other) => panic!("{id}: unknown code {other}"),
        }
    }
    assert_eq!(cases.len(), 5);
}

/// An original that is no phrase is refused when it is read; a container that is none, or is not
/// of suite 3, and a stated length that no phrase has are refused before any Argon2id work:
/// [`NoArgon2Calls`] fails the test if a case reaches it.
#[test]
fn phrases_and_containers_are_refused_as_recorded() {
    let password = corpus::password();
    let mut cipher = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
    let cases = corpus::read(FOLDER, "validation-cases.json");
    let cases = cases["phrases"].as_array().unwrap();
    for case in cases {
        let id = text(case, "id");
        let refusal = match text(case, "operation") {
            "encrypt" => Phrase::read(text(case, "phrase"))
                .err()
                .map(|_| "INVALID_PHRASE"),
            "decrypt" => {
                let stated = case.get("words").map(|_| number(case, "words") as usize);
                match Phrase::read(text(case, "container")) {
                    Err(_) => Some("INVALID_CONTAINER"),
                    Ok(container) => match cipher
                        .decrypt(
                            &container,
                            &password,
                            stated,
                            Some(Suite::TwentyFourWords),
                            &mut every_round,
                        )
                        .err()
                    {
                        Some(Error::SuiteNotAdmitted { .. }) => Some("INVALID_CONTAINER"),
                        Some(Error::InvalidWordCount { words }) if stated == Some(words) => {
                            Some("INVALID_WORD_COUNT")
                        }
                        other => panic!("{id}: {other:?}"),
                    },
                }
            }
            other => panic!("{id}: unknown operation {other}"),
        };
        assert_eq!(refusal, Some(text(case, "expected_error")), "{id}");
    }
    assert_eq!(cases.len(), 6);
}
