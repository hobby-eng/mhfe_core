//! Any text encoded as a password: one that is accepted is encoded as its NFKD, as
//! unicode-normalization gives it, in 1 to `Password::MAX_BYTES` bytes.
#![no_main]
#![allow(
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its assertions are its checks"
)]

use libfuzzer_sys::fuzz_target;
use mhfe_core::Password;
use unicode_normalization::UnicodeNormalization;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(password) = Password::new(text) {
        let expected: String = text.nfkd().collect();
        assert_eq!(password.as_bytes(), expected.as_bytes());
        assert!((1..=Password::MAX_BYTES).contains(&password.as_bytes().len()));
    }
});
