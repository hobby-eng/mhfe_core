//! The public vectors of the three optional profiles through the public API: the tables of the
//! specification's `vectors/profiles/README.md` and the containers of its corpus that the repair
//! vectors name, read from its repository, the submodule `tests/spec`. Where the specification
//! states a case in words only, the test writes the inputs those words give and takes every
//! expected value from the tables and the corpus.

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute or by #[test].
#![cfg(test)]

#[path = "support/corpus.rs"]
mod corpus;

use std::ops::ControlFlow;

use corpus::{literal, profile_table, wallet_check_rows};
use mhfe_core::password_check::{self, Check, EFF_WORDS};
use mhfe_core::repair::{Card, Repaired};
use mhfe_core::wallet_check::{self, Seed};
use mhfe_core::{Error, Phrase};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The rows of MHFE-PASSWORD-CHECK-1: five dice rolls, the index of their check word and the
/// password.
fn check_word_rows() -> Vec<(String, u16, String)> {
    profile_table("MHFE-PASSWORD-CHECK-1")
        .iter()
        .map(|row| {
            (
                literal(&row[0]).to_owned(),
                row[1].parse().unwrap(),
                literal(&row[2]).to_owned(),
            )
        })
        .collect()
}

/// The rows of MHFE-REPAIR-1: a container and its repair words for each card size, in the order
/// of `Card::SIZES`.
fn repair_rows() -> Vec<(Phrase, Vec<String>)> {
    profile_table("MHFE-REPAIR-1")
        .iter()
        .map(|row| {
            let cards = row[1].split(" / ").map(|card| literal(card).to_owned());
            (repair_container(&row[0]), cards.collect())
        })
        .collect()
}

/// The container of a repair row: that of the transcript whose path the row gives, or the phrase
/// the one other row describes in words, "abandon" 23 times, then "art".
fn repair_container(cell: &str) -> Phrase {
    if cell.ends_with(".json`") {
        container(&corpus::read("spec", literal(cell)))
    } else {
        // The cell describes the phrase, such as "`abandon` 23 times, then `art`": a word written
        // the stated number of times, then the last word.
        let words: Vec<&str> = cell.split('`').skip(1).step_by(2).collect();
        let times: usize = cell
            .split_whitespace()
            .find_map(|token| token.parse().ok())
            .unwrap();
        let [repeated, last] = words[..] else {
            panic!("{cell}");
        };
        Phrase::read(&format!("{}{last}", format!("{repeated} ").repeat(times))).unwrap()
    }
}

/// The container of a transcript of the corpus.
fn container(transcript: &Value) -> Phrase {
    Phrase::read(corpus::text(transcript, "container")).unwrap()
}

/// The entropy of a wallet-check row: 192 zero bits, then `counter` as a 64-bit big-endian number.
fn counted(counter: u64) -> [u8; 32] {
    let mut entropy = [0u8; 32];
    entropy[24..].copy_from_slice(&counter.to_be_bytes());
    entropy
}

/// Both rows pass, and each row's counter with the other row's passphrase fails.
#[test]
fn the_wallet_check_rows_pass_and_fail_as_published() {
    let rows = wallet_check_rows();
    for (counter, own, _) in &rows {
        let phrase = Phrase::from_entropy(&counted(*counter)).unwrap();
        for (_, passphrase, _) in &rows {
            let seed = Seed::derive(&phrase, passphrase);
            let passes = passphrase == own;
            assert_eq!(seed.passes(), Some(passes), "{counter} {passphrase:?}");
        }
    }
    assert_eq!(rows.len(), 2);
    // The check is defined for 24 words only.
    let twelve = Phrase::from_entropy(&[0; 16]).unwrap();
    assert_eq!(Seed::derive(&twelve, "TREZOR").passes(), None);
}

/// The trials run in order and the first that passes is the phrase: with the first row's
/// passphrase, the second row's counter fails and the first row's passes.
#[test]
fn a_draw_returns_the_first_trial_that_passes() {
    let rows = wallet_check_rows();
    let (passing, passphrase, _) = &rows[0];
    let mut counters = [rows[1].0, *passing].into_iter();
    let mut trials = 0;
    let drawn = wallet_check::draw(passphrase, &mut |entropy| {
        trials += 1;
        match counters.next() {
            Some(counter) => {
                *entropy = counted(counter);
                ControlFlow::Continue(())
            }
            None => ControlFlow::Break(()),
        }
    })
    .unwrap();
    assert_eq!(trials, 2);
    let expected = Phrase::from_entropy(&counted(*passing)).unwrap();
    assert_eq!(drawn.as_str(), expected.as_str());
    let stopped = wallet_check::draw(passphrase, &mut |_| ControlFlow::Break(()));
    assert_eq!(stopped.unwrap_err(), Error::Cancelled);
}

#[test]
fn the_cards_are_the_published_repair_words() {
    let rows = repair_rows();
    for (container, cards) in &rows {
        assert_eq!(cards.len(), Card::SIZES.len());
        for (words, card) in Card::SIZES.into_iter().zip(cards) {
            assert_eq!(Card::new(container, words).unwrap().as_str(), card);
        }
    }
    assert_eq!(rows.len(), 4);
}

/// The specification's three repairs of the container of the first repair row,
/// `vectors/suite3/zero-12.json`, with its four repair words: words 3 and 17 unreadable; word 10
/// replaced by "zoo" and word 5 unreadable; and, at the bound `2e + s = k`, words 3 and 17
/// replaced by "zoo" and "abandon". Each restores the container and names every repaired word in
/// the order of the places, with its place and what was read there.
#[test]
fn the_published_repairs_restore_the_container_and_name_every_word() {
    let rows = repair_rows();
    let (container, cards) = &rows[0];
    // The second card size, four words.
    let card = &cards[1];
    let words: Vec<&str> = container.as_str().split(' ').collect();
    let cases: [&[(usize, &str)]; 3] = [
        &[(3, "?"), (17, "?")],
        &[(10, "zoo"), (5, "?")],
        &[(3, "zoo"), (17, "abandon")],
    ];
    for damage in cases {
        let mut written = words.clone();
        let mut expected = Vec::new();
        for &(position, typed) in damage {
            written[position - 1] = typed;
            let read = (typed != "?").then_some(typed);
            expected.push((position, read, words[position - 1]));
        }
        expected.sort_unstable();
        let written = written.join(" ");
        let repaired = Repaired::of(&written, card).unwrap();
        assert_eq!(repaired.container().as_str(), container.as_str());
        let changes: Vec<_> = repaired
            .changes()
            .map(|change| {
                assert!(!change.on_card());
                (change.position(), change.read(), change.word())
            })
            .collect();
        assert_eq!(changes, expected, "{written}");
    }
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

/// Each row's check word and password, and the specification's case of the third row with its
/// third word erased, which is recovered.
#[test]
fn the_check_words_are_the_published_ones() {
    let rows = check_word_rows();
    for (rolls, check, password) in &rows {
        // The index five dice digits select: base 6, each digit less one.
        let drawn: [u16; 5] = std::array::from_fn(|word| {
            rolls
                .split(' ')
                .nth(word)
                .unwrap()
                .bytes()
                .fold(0, |index, digit| index * 6 + u16::from(digit - b'1'))
        });
        assert_eq!(password_check::check_word(drawn), Some(*check), "{rolls}");
        let words: Vec<&str> = drawn
            .iter()
            .chain([check])
            .map(|&index| EFF_WORDS[usize::from(index)])
            .collect();
        assert_eq!(&words.join(" "), password);
        assert_eq!(Check::of(password), Check::Fits);
    }
    assert_eq!(rows.len(), 4);
    let mut third: Vec<&str> = rows[2].2.split(' ').collect();
    let erased = std::mem::replace(&mut third[2], "?");
    let Check::OneErased { position, word } = Check::of(&third.join(" ")) else {
        panic!("an erased word is recovered");
    };
    assert_eq!((position, word), (3, erased));
    assert_eq!(password_check::check_word([0, 0, 7776, 0, 0]), None);
}

#[test]
fn one_missing_word_is_restored_at_any_place() {
    for (_, _, password) in check_word_rows() {
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
    let rows = check_word_rows();
    let password = &rows[0].2;
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
        if repaired == *password {
            right.push(position + 1);
        }
    }
    assert_eq!(right, [4]);
}
