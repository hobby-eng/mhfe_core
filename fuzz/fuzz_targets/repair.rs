//! Containers of every length with cards of every size, damaged at places the input chooses: within
//! 2e + s <= k the repair gives the container back and names exactly the damaged places, and beyond
//! it a repair still gives a container that reads as a phrase. Input with its first byte at 0x80 or
//! more is any text instead, a container phrase and, after a line break, a card.
#![no_main]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: its unwraps and assertions are its checks"
)]

use libfuzzer_sys::fuzz_target;
use mhfe_core::Phrase;
use mhfe_core::repair::{Card, Repaired};

/// The entropy lengths of the containers of 12 to 24 words.
const ENTROPY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

/// Any text as a container phrase and a card: a repair is a container, and what it names lies on
/// the phrase or the card, at most one change for each repair word.
fn any_text(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (written, card) = text.split_once('\n').unwrap_or((text, ""));
    let Ok(repaired) = Repaired::of(written, card) else {
        return;
    };
    Phrase::read(repaired.container().as_str()).unwrap();
    let (words, card_words) = (
        written.split_whitespace().count(),
        card.split_whitespace().count(),
    );
    assert!(repaired.changes().count() <= card_words);
    for change in repaired.changes() {
        let on = if change.on_card() { card_words } else { words };
        assert!((1..=on).contains(&change.position()));
        assert_ne!(change.read(), Some(change.word()));
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    if shape >= 0x80 {
        return any_text(rest);
    }
    let entropy_bytes = ENTROPY_BYTES[usize::from(shape) % ENTROPY_BYTES.len()];
    let k = Card::SIZES[usize::from(shape) / ENTROPY_BYTES.len() % Card::SIZES.len()];
    let Some((entropy, damage)) = rest.split_at_checked(entropy_bytes) else {
        return;
    };
    let container = Phrase::from_entropy(entropy).unwrap();
    let card = Card::new(&container, k).unwrap();
    let original: Vec<&str> = container
        .as_str()
        .split(' ')
        .chain(card.as_str().split(' '))
        .collect();
    // Each two bytes damage one place: the first chooses it, the second makes it unreadable or puts
    // another word of the same container phrase or card there, which may be the same word.
    let mut read: Vec<&str> = original.clone();
    for &[place, word] in damage.as_chunks::<2>().0 {
        let place = usize::from(place) % read.len();
        read[place] = match word {
            0 => "?",
            other => original[usize::from(other) % original.len()],
        };
    }
    let (written, card_read) = read.split_at(container.words());
    let answer = Repaired::of(&written.join(" "), &card_read.join(" "));
    let erased = read.iter().filter(|word| **word == "?").count();
    let wrong = read
        .iter()
        .zip(&original)
        .filter(|(r, o)| **r != "?" && r != o)
        .count();
    if 2 * wrong + erased > k {
        if let Ok(repaired) = answer {
            Phrase::read(repaired.container().as_str()).unwrap();
        }
        return;
    }
    let repaired = answer.unwrap();
    assert_eq!(repaired.container().as_str(), container.as_str());
    let damaged: Vec<(bool, usize)> = read
        .iter()
        .zip(&original)
        .enumerate()
        .filter(|(_, (r, o))| r != o)
        .map(|(index, _)| {
            let on_card = index >= container.words();
            (
                on_card,
                if on_card {
                    index - container.words()
                } else {
                    index
                } + 1,
            )
        })
        .collect();
    let named: Vec<(bool, usize)> = repaired
        .changes()
        .map(|c| (c.on_card(), c.position()))
        .collect();
    assert_eq!(named, damaged);
});
