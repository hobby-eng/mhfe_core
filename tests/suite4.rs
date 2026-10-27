//! The suite 4 corpus, `tests/spec/vectors/suite4/`, through the public API: its files are checked
//! against its `SHA256SUMS`, its 10 transcripts are created and recovered with their recorded
//! Argon2id keys, the recovery case those keys reach is refused as recorded, and the 63 refusals of
//! its fast cases come before any Argon2id work. The four `ENT`-separation cases compare round
//! messages the API hides and run in the crate (`feistel.rs`). The other recovery cases need
//! Argon2id at full cost (tests/full_cost.rs).

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute or by #[test].
#![cfg(test)]

#[path = "support/corpus.rs"]
mod corpus;

use corpus::{NoArgon2Calls, RecordedKeys, every_round, number, text};
use mhfe_core::{Error, Mhfe, Phrase, Suite, WorkFactor};

const FOLDER: &str = "spec/vectors/suite4";

#[test]
fn every_transcript_is_created_and_recovered_as_recorded() {
    let transcripts = corpus::transcripts(FOLDER);
    for transcript in &transcripts {
        corpus::replay(transcript, Suite::SameLength, RecordedKeys::of(transcript));
    }
    assert_eq!(transcripts.len(), 10);
}

/// `same-length-other-length-chosen`: 15 words stated with a 12-word container.
#[test]
fn the_recovery_case_of_recorded_keys_is_refused_as_recorded() {
    assert_eq!(corpus::recover_with_recorded_keys(FOLDER), 1);
}

/// The encryption of a 24-word original, and every combination of supplied suite, supplied length
/// and container length that the recovery table does not admit, each refused before any Argon2id
/// work: [`NoArgon2Calls`] fails the test if a case reaches it.
#[test]
fn every_refusal_comes_before_argon2() {
    let password = corpus::password();
    let mut cipher = Mhfe::with_engine(WorkFactor::default(), NoArgon2Calls);
    let cases = corpus::read(FOLDER, "validation-cases.json");
    let cases = cases["refusals"].as_array().unwrap();
    for case in cases {
        let id = text(case, "id");
        assert_eq!(text(case, "expected"), "rejected", "{id}");
        let phrase = Phrase::read(text(case, "text")).unwrap();
        match text(case, "operation") {
            "encrypt-same-length" => {
                let error = cipher
                    .encrypt(
                        &phrase,
                        &password,
                        Suite::SameLength,
                        &mut every_round,
                        &mut |_| panic!("{id}: a container was made"),
                    )
                    .unwrap_err();
                assert_eq!(error, Error::SameLengthNeedsShortPhrase, "{id}");
            }
            "decrypt" => {
                let stated = case.get("words").map(|_| number(case, "words") as usize);
                let suite = case.get("suite").map(|_| match number(case, "suite") {
                    3 => Suite::TwentyFourWords,
                    4 => Suite::SameLength,
                    other => panic!("{id}: unknown suite {other}"),
                });
                let error = cipher
                    .decrypt(&phrase, &password, stated, suite, &mut every_round)
                    .err();
                assert!(
                    matches!(
                        error,
                        Some(
                            Error::LengthNotAdmitted { container_words }
                                | Error::SuiteNotAdmitted { container_words }
                        ) if container_words == phrase.words()
                    ),
                    "{id}: {error:?}"
                );
            }
            other => panic!("{id}: unknown operation {other}"),
        }
    }
    assert_eq!(cases.len(), 63);
    // A stated length that no phrase has is refused before the rounds too.
    let container = Phrase::read(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         about",
    )
    .unwrap();
    assert_eq!(
        cipher
            .decrypt(&container, &password, Some(13), None, &mut every_round)
            .err(),
        Some(Error::InvalidWordCount { words: 13 })
    );
}
