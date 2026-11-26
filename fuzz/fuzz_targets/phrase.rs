//! Any text read as a phrase, as a person writes one down: a phrase that is read gives a canonical
//! text that reads back as the same phrase, with as many words as it says, and a token read as a
//! word reads as that word again.
#![no_main]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its unwraps and assertions are its checks"
)]

use libfuzzer_sys::fuzz_target;
use mhfe_core::Phrase;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for token in text.split_whitespace() {
        if let Some(word) = Phrase::read_word(token) {
            assert_eq!(Phrase::read_word(word), Some(word));
        }
    }
    if let Ok(phrase) = Phrase::read(text) {
        assert_eq!(
            Phrase::read(phrase.as_str()).unwrap().as_str(),
            phrase.as_str()
        );
        assert_eq!(phrase.as_str().split(' ').count(), phrase.words());
        assert!(!phrase.other_detected_lengths().contains(&phrase.words()));
    }
});
