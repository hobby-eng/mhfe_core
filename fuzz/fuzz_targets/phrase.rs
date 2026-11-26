//! Any text read as a phrase, as a person writes one down: a phrase that is read gives a canonical
//! text that reads back as the same phrase, with as many words as it says, and a token read as a
//! word reads as that word again. Input with its first byte at 0x80 or more is a phrase instead,
//! written as a person may write it: each word in upper or lower case, cut to its first four letters
//! or more, between runs of spaces, tabs and line breaks; it reads as the phrase itself.
#![no_main]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its unwraps and assertions are its checks"
)]

use libfuzzer_sys::fuzz_target;
use mhfe_core::Phrase;
use mhfe_core_fuzz::phrase_of;

/// What may stand between two words.
const SPACES: [&str; 4] = [" ", "  ", "\t", "\r\n"];

/// A phrase from `data` written as a person may write it: it must read as itself.
fn written(shape: u8, data: &[u8]) {
    let Some((phrase, styles)) = phrase_of(shape, data) else {
        return;
    };
    let mut text = String::new();
    for (index, word) in phrase.as_str().split(' ').enumerate() {
        let style = styles.get(index).copied().unwrap_or(0);
        let kept = (4 + usize::from(style & 3)).min(word.len());
        let word = &word[..kept];
        if style & 4 == 0 {
            text.push_str(word);
        } else {
            text.push_str(&word.to_uppercase());
        }
        text.push_str(SPACES[usize::from(style >> 3) % SPACES.len()]);
    }
    assert_eq!(Phrase::read(&text).unwrap().as_str(), phrase.as_str());
}

fuzz_target!(|data: &[u8]| {
    if let Some((&shape, rest)) = data.split_first()
        && shape >= 0x80
    {
        return written(shape, rest);
    }
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
