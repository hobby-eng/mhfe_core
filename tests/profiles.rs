//! The public vectors of the three optional profiles through the public API: the JSON files of the
//! specification's `vectors/profiles/`, checked against their `SHA256SUMS`, and the containers of
//! its corpus that the repair vectors name, read from its repository, the submodule `tests/spec`.

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute or by #[test].
#![cfg(test)]

#[path = "support/corpus.rs"]
mod corpus;

use std::ops::ControlFlow;

use corpus::{WALLET_CHECK_VECTORS, hex, number, profile_vectors, text};
use mhfe_core::Phrase;
use mhfe_core::password_check::{self, Check, EFF_WORDS};
use mhfe_core::repair::{Card, Repaired};
use mhfe_core::wallet_check::{self, Seed};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The profile vectors of MHFE-PASSWORD-CHECK-1.
const CHECK_WORD_VECTORS: &str = "password-check-word.json";
/// The profile vectors of MHFE-REPAIR-1.
const REPAIR_VECTORS: &str = "repair-words.json";

/// The entropy of a wallet-check case: 192 zero bits, then its counter as a 64-bit big-endian
/// number.
fn counted(case: &Value) -> [u8; 32] {
    let mut entropy = [0u8; 32];
    entropy[24..].copy_from_slice(&case["counter"].as_u64().unwrap().to_be_bytes());
    entropy
}

/// Each case's counter gives its recorded entropy and phrase, and the phrase with its passphrase
/// passes or fails as recorded: two cases pass, and the counter of each with the passphrase of the
/// other fails.
#[test]
fn the_wallet_check_cases_pass_and_fail_as_published() {
    let cases = profile_vectors(WALLET_CHECK_VECTORS, "cases");
    for case in &cases {
        let id = text(case, "id");
        let entropy = counted(case);
        assert_eq!(entropy[..], hex(text(case, "entropy_hex")), "{id}");
        let phrase = Phrase::from_entropy(&entropy).unwrap();
        assert_eq!(phrase.as_str(), text(case, "mnemonic"), "{id}");
        let seed = Seed::derive(&phrase, text(case, "bip39_passphrase"));
        assert_eq!(seed.passes(), case["passes"].as_bool(), "{id}");
    }
    assert_eq!(cases.len(), 4);
    // The check is defined for 24 words only.
    let twelve = Phrase::from_entropy(&[0; 16]).unwrap();
    assert_eq!(Seed::derive(&twelve, "TREZOR").passes(), None);
}

/// The trials run in order and the first that passes is the phrase: with the first case's
/// passphrase, the second case's counter fails and the first case's passes.
#[test]
fn a_draw_returns_the_first_trial_that_passes() {
    let cases = profile_vectors(WALLET_CHECK_VECTORS, "cases");
    let passphrase = text(&cases[0], "bip39_passphrase");
    let passing = counted(&cases[0]);
    let mut entropies = [counted(&cases[1]), passing].into_iter();
    let mut trials = 0;
    let drawn = wallet_check::draw(passphrase, &mut |entropy| {
        trials += 1;
        match entropies.next() {
            Some(next) => {
                *entropy = next;
                ControlFlow::Continue(())
            }
            None => ControlFlow::Break(()),
        }
    })
    .unwrap()
    .continue_value()
    .unwrap();
    assert_eq!(trials, 2);
    let expected = Phrase::from_entropy(&passing).unwrap();
    assert_eq!(drawn.as_str(), expected.as_str());
    let stopped = wallet_check::draw(passphrase, &mut |_| ControlFlow::Break(()));
    assert!(stopped.unwrap().is_break());
    // A host's limit: the trials end at it, without a phrase.
    let failing = counted(&cases[1]);
    let mut left = 3;
    let bounded = wallet_check::draw(passphrase, &mut |entropy| {
        if left == 0 {
            return ControlFlow::Break(());
        }
        left -= 1;
        *entropy = failing;
        ControlFlow::Continue(())
    });
    assert!(bounded.unwrap().is_break());
    assert_eq!(left, 0);
}

/// Each case's card of every size is the published one, and a case that names its transcript holds
/// that transcript's container.
#[test]
fn the_cards_are_the_published_repair_words() {
    let cases = profile_vectors(REPAIR_VECTORS, "cases");
    for case in &cases {
        if let Some(path) = case["container_vector"].as_str() {
            let transcript = corpus::read("spec", path);
            assert_eq!(transcript["container"], case["container"], "{path}");
        }
        let container = Phrase::read(text(case, "container")).unwrap();
        let cards = &case["repair_words"];
        assert_eq!(cards.as_object().unwrap().len(), Card::SIZES.len());
        for words in Card::SIZES {
            let card = Card::new(&container, words).unwrap();
            assert_eq!(card.as_str(), text(cards, &words.to_string()));
        }
    }
    assert_eq!(cases.len(), 4);
}

/// The specification's three repairs of a case's container with its card of `k` words: each
/// restores the container and names every repaired word in the order of the places, with its place
/// and what was read there.
#[test]
fn the_published_repairs_restore_the_container_and_name_every_word() {
    let cases = profile_vectors(REPAIR_VECTORS, "cases");
    let repairs = profile_vectors(REPAIR_VECTORS, "repairs");
    for repair in &repairs {
        let case = cases
            .iter()
            .find(|case| case["id"] == repair["case"])
            .unwrap();
        let container = text(case, "container");
        let mut written: Vec<&str> = container.split(' ').collect();
        for position in repair["unreadable"].as_array().unwrap() {
            written[position.as_u64().unwrap() as usize - 1] = "?";
        }
        let replaced = &repair["replaced"];
        for (position, typed) in replaced.as_object().unwrap() {
            written[position.parse::<usize>().unwrap() - 1] = typed.as_str().unwrap();
        }
        let mut expected: Vec<(usize, Option<&str>, &str)> = repair["restored"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(position, word)| {
                let place = position.parse().unwrap();
                (place, replaced[position].as_str(), word.as_str().unwrap())
            })
            .collect();
        expected.sort_unstable();
        let written = written.join(" ");
        let card = text(&case["repair_words"], &repair["k"].to_string());
        let repaired = Repaired::of(&written, card).unwrap();
        assert_eq!(repaired.container().as_str(), container);
        let changes: Vec<_> = repaired
            .changes()
            .map(|change| {
                assert!(!change.on_card());
                (change.position(), change.read(), change.word())
            })
            .collect();
        assert_eq!(changes, expected, "{written}");
    }
    assert_eq!(repairs.len(), 3);
}

/// The list file rebuilt from the words, each index's five dice digits from 1 in base 6, a tab,
/// the word and a line feed, is the published file; its order is byte order.
#[test]
fn the_words_rebuild_the_published_list() {
    let mut file = Sha256::new();
    for (index, word) in EFF_WORDS.iter().enumerate() {
        let dice: String = (0..5u32)
            .rev()
            .map(|place| char::from(b'1' + (index / 6usize.pow(place) % 6) as u8))
            .collect();
        file.update(format!("{dice}\t{word}\n"));
    }
    let digest: String = file
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    // EFF's file, as vendor/eff-large-wordlist.md records it.
    assert_eq!(
        digest,
        "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
    );
    assert!(EFF_WORDS.is_sorted());
}

/// Each case's check word and password, and the specification's erased word, which is recovered.
#[test]
fn the_check_words_are_the_published_ones() {
    let cases = profile_vectors(CHECK_WORD_VECTORS, "cases");
    for case in &cases {
        let rolls = case["dice"].as_array().unwrap();
        let check = u16::try_from(number(case, "check_index")).unwrap();
        let password = text(case, "password");
        // The index five dice digits select: base 6, each digit less one.
        let drawn: [u16; 5] = std::array::from_fn(|word| {
            rolls[word]
                .as_str()
                .unwrap()
                .bytes()
                .fold(0, |index, digit| index * 6 + u16::from(digit - b'1'))
        });
        assert_eq!(password_check::check_word(drawn), Some(check), "{password}");
        let words: Vec<&str> = drawn
            .iter()
            .chain([&check])
            .map(|&index| EFF_WORDS[usize::from(index)])
            .collect();
        assert_eq!(words.join(" "), password);
        assert_eq!(Check::of(password), Check::Fits);
    }
    assert_eq!(cases.len(), 4);
    let erasures = profile_vectors(CHECK_WORD_VECTORS, "erasures");
    for erasure in &erasures {
        let Check::OneErased { position, word } = Check::of(text(erasure, "input")) else {
            panic!("an erased word is recovered");
        };
        assert_eq!(position, number(erasure, "position") as usize);
        assert_eq!(word, text(erasure, "recovered"));
    }
    assert_eq!(erasures.len(), 1);
    assert_eq!(password_check::check_word([0, 0, 7776, 0, 0]), None);
}

#[test]
fn one_missing_word_is_restored_at_any_place() {
    for case in profile_vectors(CHECK_WORD_VECTORS, "cases") {
        let password = text(&case, "password");
        for position in 0..6 {
            let mut words: Vec<&str> = password.split(' ').collect();
            let missing = std::mem::replace(&mut words[position], "unreadable");
            let Check::OneErased { position: at, word } = Check::of(&words.join(" ")) else {
                panic!("{password}, {position}: not recovered");
            };
            assert_eq!((at, word), (position + 1, missing), "{password}");
        }
    }
}

#[test]
fn one_wrong_word_leaves_six_repairs_with_the_right_one_among_them() {
    let cases = profile_vectors(CHECK_WORD_VECTORS, "cases");
    let password = text(&cases[0], "password");
    // The fourth word replaced by another word of the list.
    let mut typed: Vec<&str> = password.split(' ').collect();
    typed[3] = "zoom";
    let typed = typed.join(" ");
    let Check::Mismatch { candidates } = Check::of(&typed) else {
        panic!("a wrong word is a mismatch");
    };
    let mut right = Vec::new();
    for (position, candidate) in candidates.into_iter().enumerate() {
        let mut words: Vec<&str> = typed.split(' ').collect();
        words[position] = candidate;
        let repaired = words.join(" ");
        // Every one of the six makes the words fit.
        assert_eq!(Check::of(&repaired), Check::Fits, "{repaired}");
        if repaired == password {
            right.push(position + 1);
        }
    }
    assert_eq!(right, [4]);
}
