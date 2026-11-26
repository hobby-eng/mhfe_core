//! The profiles of mhfe-core built for `wasm32-unknown-unknown`, the target of a browser, checked
//! on the specification's published vectors, which are built into the module. `checks` returns how
//! many checks passed; a check that fails stops the module with a trap. The module imports
//! nothing, as a browser gives it nothing; CI calls it with `wasmtime run --invoke checks`.
//! Argon2id needs a host engine there, so the suites are left to the WASI tests.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a check answers by stopping the module: its unwraps and assertions are its checks"
)]

use mhfe_core::Phrase;
use mhfe_core::password_check::{Check, EFF_WORDS, check_word};
use mhfe_core::repair::{Card, Repaired};
use mhfe_core::wallet_check::Seed;
use serde_json::Value;

const REPAIR: &str = include_str!("../../tests/spec/vectors/profiles/repair-words.json");
const CHECK_WORD: &str = include_str!("../../tests/spec/vectors/profiles/password-check-word.json");
const WALLET_CHECK: &str = include_str!("../../tests/spec/vectors/profiles/wallet-check.json");

fn list(json: &str, key: &str) -> Vec<Value> {
    let value: Value = serde_json::from_str(json).unwrap();
    value[key].as_array().unwrap().clone()
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

/// Every card of every case, and every published repair.
fn repair(passed: &mut u32) {
    let cases = list(REPAIR, "cases");
    for case in &cases {
        let container = Phrase::read(text(case, "container")).unwrap();
        for words in Card::SIZES {
            let card = Card::new(&container, words).unwrap();
            assert_eq!(
                card.as_str(),
                text(&case["repair_words"], &words.to_string())
            );
            *passed += 1;
        }
    }
    for repair in &list(REPAIR, "repairs") {
        let case = cases
            .iter()
            .find(|case| case["id"] == repair["case"])
            .unwrap();
        let container = text(case, "container");
        let mut written: Vec<&str> = container.split(' ').collect();
        for position in repair["unreadable"].as_array().unwrap() {
            written[usize::try_from(position.as_u64().unwrap()).unwrap() - 1] = "?";
        }
        for (position, typed) in repair["replaced"].as_object().unwrap() {
            written[position.parse::<usize>().unwrap() - 1] = typed.as_str().unwrap();
        }
        let card = text(&case["repair_words"], &repair["k"].to_string());
        let repaired = Repaired::of(&written.join(" "), card).unwrap();
        assert_eq!(repaired.container().as_str(), container);
        assert_eq!(
            repaired.changes().count(),
            repair["restored"].as_object().unwrap().len()
        );
        *passed += 1;
    }
}

/// Every published check word and erasure.
fn password_check(passed: &mut u32) {
    for case in &list(CHECK_WORD, "cases") {
        let rolls = case["dice"].as_array().unwrap();
        let drawn: [u16; 5] = std::array::from_fn(|word| {
            rolls[word]
                .as_str()
                .unwrap()
                .bytes()
                .fold(0, |index, digit| index * 6 + u16::from(digit - b'1'))
        });
        let check = check_word(drawn).unwrap();
        assert_eq!(u64::from(check), case["check_index"].as_u64().unwrap());
        let words: Vec<&str> = drawn
            .iter()
            .chain([&check])
            .map(|&index| EFF_WORDS[usize::from(index)])
            .collect();
        assert_eq!(words.join(" "), text(case, "password"));
        assert!(Check::of(text(case, "password")) == Check::Fits);
        *passed += 1;
    }
    for erasure in &list(CHECK_WORD, "erasures") {
        let position = usize::try_from(erasure["position"].as_u64().unwrap()).unwrap();
        let word = text(erasure, "recovered");
        let Check::OneErased {
            position: found,
            word: restored,
        } = Check::of(text(erasure, "input"))
        else {
            panic!("one erased word is restored");
        };
        assert!(found == position && restored == word);
        *passed += 1;
    }
}

/// Every published wallet-check case.
fn wallet_check(passed: &mut u32) {
    for case in &list(WALLET_CHECK, "cases") {
        let phrase = Phrase::read(text(case, "mnemonic")).unwrap();
        let seed = Seed::derive(&phrase, text(case, "bip39_passphrase")).unwrap();
        assert_eq!(seed.passes(), case["passes"].as_bool());
        *passed += 1;
    }
}

/// Runs every check and returns how many passed.
#[allow(
    unsafe_code,
    reason = "no_mangle exports the function under its own name, which the engine calls"
)]
#[unsafe(no_mangle)]
pub extern "C" fn checks() -> u32 {
    let mut passed = 0;
    repair(&mut passed);
    password_check(&mut passed);
    wallet_check(&mut passed);
    passed
}
