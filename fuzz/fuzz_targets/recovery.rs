//! A phrase of any length encrypted and decrypted with a stand-in for Argon2id, in the suite the
//! input chooses, and its recovered state read with any stated length: the answer is the one the
//! specification's length rules give, written here apart from the crate's own code; each reading
//! reads back as itself and is verified exactly when its length's verifier matched, and the
//! original comes back whenever its length is among the readings.
#![no_main]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its unwraps and assertions are its checks"
)]

use std::ops::ControlFlow;

use libfuzzer_sys::fuzz_target;
use mhfe_core::{Argon2Engine, Error, Mhfe, Password, Phrase, Suite, WorkFactor};
use mhfe_core_fuzz::phrase_of;

/// The phrase lengths of BIP39.
const WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// A cheap stand-in for Argon2id: a tag that depends on the salt and the password alone.
struct Stand;

impl Argon2Engine for Stand {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; 16],
        _memory_kib: u32,
        _passes: u32,
        key: &mut [u8; 32],
    ) -> Result<(), Error> {
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = salt[index % 16] ^ password[index % password.len()] ^ index as u8;
        }
        Ok(())
    }
}

/// The readings' lengths that the specification gives a container of `container` words for
/// `stated`, when `detected` are the short lengths whose verifier matched.
fn expected(
    container: usize,
    stated: Option<usize>,
    detected: &[usize],
) -> Result<Vec<usize>, &'static str> {
    if let Some(words) = stated {
        if !WORD_COUNTS.contains(&words) {
            return Err("word count");
        }
        if container != 24 && words != container {
            return Err("not admitted");
        }
    }
    if container != 24 {
        return Ok(vec![container]);
    }
    Ok(match stated {
        Some(words) if detected.contains(&words) => vec![words],
        None | Some(24) if detected.is_empty() => vec![24],
        Some(_) if detected.is_empty() => return Err("verifier"),
        None => match detected {
            [words] => vec![*words],
            _ => detected.iter().copied().chain([24]).collect(),
        },
        Some(words) if words != 24 && detected.len() == 1 => detected.to_vec(),
        Some(_) => detected.iter().copied().chain([24]).collect(),
    })
}

fn refusal(error: &Error) -> &'static str {
    match error {
        Error::InvalidWordCount { .. } => "word count",
        Error::LengthNotAdmitted { .. } => "not admitted",
        Error::VerifierMismatch => "verifier",
        other => panic!("not a refusal of the length rules: {other:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    let [shape, suite, stated, rest @ ..] = data else {
        return;
    };
    let Some((original, _)) = phrase_of(*shape, rest) else {
        return;
    };
    let suite = if suite & 1 == 0 {
        Suite::TwentyFourWords
    } else {
        Suite::SameLength
    };
    let password = Password::new("fuzzing").unwrap();
    let mut cipher = Mhfe::with_engine(WorkFactor::default(), Stand);
    let go = &mut |_, _| ControlFlow::Continue(());
    let Ok(ControlFlow::Continue(container)) =
        cipher.encrypt(&original, &password, suite, go, &mut |_| {
            ControlFlow::Continue(())
        })
    else {
        // A 24-word phrase has no same-length container.
        assert!(suite == Suite::SameLength && original.words() == 24);
        return;
    };
    let Ok(ControlFlow::Continue(recovery)) = cipher.decrypt(&container, &password, None, None, go)
    else {
        panic!("a container decrypts with its own password");
    };
    // 0 states no length; 1 to 30 state one, valid or not.
    let stated = (*stated % 31 != 0).then_some(usize::from(*stated % 31));
    let detected = recovery.detected_lengths();
    match (
        recovery.readings(stated),
        expected(container.words(), stated, detected),
    ) {
        (Ok(readings), Ok(lengths)) => {
            let words: Vec<usize> = readings
                .iter()
                .map(|reading| reading.phrase().words())
                .collect();
            assert_eq!(words, lengths);
            for reading in &readings {
                let phrase = reading.phrase();
                assert_eq!(
                    Phrase::read(phrase.as_str()).unwrap().as_str(),
                    phrase.as_str()
                );
                assert_eq!(reading.is_verified(), detected.contains(&phrase.words()));
                if phrase.words() == original.words() {
                    assert_eq!(phrase.as_str(), original.as_str());
                }
            }
        }
        (Err(error), Err(rule)) => assert_eq!(refusal(&error), rule),
        (got, rule) => panic!(
            "readings {:?} against the rules' {rule:?}",
            got.map(|r| r.len())
        ),
    }
});
