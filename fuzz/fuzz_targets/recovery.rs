//! A container of any length decrypted with a stand-in for Argon2id, and its recovered state read
//! with any stated length: each reading reads back as the phrase it holds, and is verified exactly
//! when its length is one whose verifier matched.
#![no_main]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its unwraps and assertions are its checks"
)]

use std::ops::ControlFlow;

use libfuzzer_sys::fuzz_target;
use mhfe_core::{Argon2Engine, Error, Mhfe, Password, Phrase, WorkFactor};

/// The entropy lengths of the containers of 12 to 24 words.
const ENTROPY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

/// A cheap stand-in for Argon2id: a tag that depends on the salt and the password alone, so that
/// every round differs and the fuzzer's container decides the recovered state.
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

fuzz_target!(|data: &[u8]| {
    let [shape, stated, rest @ ..] = data else {
        return;
    };
    let entropy_bytes = ENTROPY_BYTES[usize::from(*shape) % ENTROPY_BYTES.len()];
    let Some(entropy) = rest.get(..entropy_bytes) else {
        return;
    };
    let container = Phrase::from_entropy(entropy).unwrap();
    let password = Password::new("fuzzing").unwrap();
    // 0 states no length; 1 to 30 state one, valid or not.
    let stated = (*stated % 31 != 0).then_some(usize::from(*stated % 31));
    let mut cipher = Mhfe::with_engine(WorkFactor::default(), Stand);
    let Ok(answer) = cipher.decrypt(&container, &password, stated, None, &mut |_, _| {
        ControlFlow::Continue(())
    }) else {
        return;
    };
    let ControlFlow::Continue(recovery) = answer else {
        panic!("no callback stops the rounds");
    };
    for words in [stated, None] {
        let Ok(readings) = recovery.readings(words) else {
            continue;
        };
        assert!(!readings.is_empty());
        for reading in &readings {
            let phrase = reading.phrase();
            assert_eq!(
                Phrase::read(phrase.as_str()).unwrap().as_str(),
                phrase.as_str()
            );
            let detected = recovery.detected_lengths().contains(&phrase.words());
            assert_eq!(reading.is_verified(), detected);
        }
    }
});
