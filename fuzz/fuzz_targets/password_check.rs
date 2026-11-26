//! Any text read under the password-check profile, and six words made to fit from five indexes the
//! input gives: six that fit are read as fitting; with one erased, the word restored is the one
//! that was there; with one replaced by another word, the candidate at that place is the one that
//! was there; and the word any check offers makes six that fit.
#![no_main]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its unwraps and assertions are its checks"
)]

use libfuzzer_sys::fuzz_target;
use mhfe_core::password_check::{Check, EFF_WORDS, check_word};

/// The six tokens of `text` with `word` at `position`, from 1.
fn with_word(text: &str, position: usize, word: &str) -> String {
    let mut tokens: Vec<&str> = text.split(' ').collect();
    tokens[position - 1] = word;
    tokens.join(" ")
}

/// Six words that fit, from the first ten bytes of `data`, and two more bytes: a place and a
/// word to put there.
fn made(data: &[u8]) {
    let [a, b, c, d, e, f, g, h, i, j, place, other, ..] = *data else {
        return;
    };
    let index = |high: u8, low: u8| u16::from_be_bytes([high, low]) % 7776;
    let drawn = [
        index(a, b),
        index(c, d),
        index(e, f),
        index(g, h),
        index(i, j),
    ];
    let check = check_word(&drawn).unwrap();
    let indexes: Vec<u16> = drawn.into_iter().chain([check]).collect();
    let words: Vec<&str> = indexes
        .iter()
        .map(|&index| EFF_WORDS[usize::from(index)])
        .collect();
    let text = words.join(" ");
    assert!(Check::of(&text) == Check::Fits);
    let position = usize::from(place) % 6 + 1;
    let was = words[position - 1];
    assert!(
        Check::of(&with_word(&text, position, "?"))
            == Check::OneErased {
                position,
                word: was
            }
    );
    let replaced = EFF_WORDS[usize::from(other) * 31 % 7776];
    if replaced != was {
        let Check::Mismatch { candidates } = Check::of(&with_word(&text, position, replaced))
        else {
            panic!("one wrong word is a mismatch");
        };
        assert_eq!(candidates[position - 1], was);
    }
}

fuzz_target!(|data: &[u8]| {
    made(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match Check::of(text) {
        Check::OneErased { position, word } => {
            assert!(Check::of(&with_word(text, position, word)) == Check::Fits);
        }
        Check::Mismatch { candidates } => {
            for (index, word) in candidates.iter().enumerate() {
                assert!(Check::of(&with_word(text, index + 1, word)) == Check::Fits);
            }
        }
        _ => {}
    }
});
