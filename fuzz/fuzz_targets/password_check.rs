//! Any text read under the password-check profile: the word it offers for an erased place makes six
//! words that fit, and each candidate of a mismatch, put in its place, makes six that fit too.
#![no_main]
#![allow(
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its assertions are its checks"
)]

use libfuzzer_sys::fuzz_target;
use mhfe_core::password_check::Check;

/// The six tokens of `text` with `word` at `position`, from 1.
fn with_word(text: &str, position: usize, word: &str) -> String {
    let mut tokens: Vec<&str> = text.split(' ').collect();
    tokens[position - 1] = word;
    tokens.join(" ")
}

fuzz_target!(|data: &[u8]| {
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
