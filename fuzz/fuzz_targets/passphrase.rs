//! Any text as a BIP39 passphrase with a phrase of any length: the wallet check's seed is bip39's
//! seed of the phrase with the passphrase's NFKD, as unicode-normalization gives it.
#![no_main]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its unwraps and assertions are its checks"
)]

use bip39::{Language, Mnemonic};
use libfuzzer_sys::fuzz_target;
use mhfe_core::wallet_check::Seed;
use mhfe_core_fuzz::phrase_of;
use unicode_normalization::UnicodeNormalization;

fuzz_target!(|data: &[u8]| {
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    let Some((phrase, passphrase)) = phrase_of(shape, rest) else {
        return;
    };
    let Ok(passphrase) = std::str::from_utf8(passphrase) else {
        return;
    };
    let seed = Seed::derive(&phrase, passphrase).unwrap();
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase.as_str()).unwrap();
    let normalized: String = passphrase.nfkd().collect();
    assert_eq!(seed.as_bytes(), &mnemonic.to_seed_normalized(&normalized));
    assert_eq!(seed.passes().is_some(), phrase.words() == 24);
});
