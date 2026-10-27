//! Repair words for a finished container: the optional profile MHFE-REPAIR-1 (specification:
//! "Optional repair words"), which changes neither suite.
//!
//! A written container phrase can fade, rust, be scratched or be copied with a wrong word. A few
//! extra English BIP39 words on a card of their own, [`Card`], let a host repair it without the
//! password and without Argon2id, [`Repaired::of`]. They are the parity of a Reed–Solomon code over
//! the container's words: the BIP39 list has 2,048 words, exactly the elements of GF(2^11), so
//! each word is a field element and each repair word is a word of the same list.
//!
//! The code, byte for byte:
//!
//! - the field GF(2^11) with the primitive polynomial x^11 + x^2 + 1, and alpha = x;
//! - the data: the container's word numbers d_0 to d_(n-1) in the list, the first word first, as
//!   the coefficients of m(x) from x^(n-1) down to x^0;
//! - k repair words, 2, 4, 6 or 8: the remainder r(x) of m(x) * x^k divided by
//!   g(x) = (x + alpha) (x + alpha^2) ... (x + alpha^k), its coefficients from x^(k-1) down to x^0.
//!
//! The container's words followed by the repair words are then a codeword. Any `e` wrong words at
//! unknown places and `s` unreadable words with 2e + s <= k are repaired, words of the card
//! included. A host releases a card only after the container's creation check passed: it makes
//! the card inside the `on_unchecked` of [`crate::Mhfe::encrypt`] and gives it out once `encrypt`
//! returns `Ok`.
//!
//! A card adds nothing for someone who holds the whole container phrase, but it completes a
//! damaged or partial copy for whoever has both, as it does for the owner: it is kept apart from
//! the container phrase and guarded like it. On its own it leaves about 2^(11(n - k) - n/3)
//! candidate containers: 2^168 for 24 words and 8 repair words, only 2^40 for 12 words.

mod field;

use std::fmt;

use crate::phrase::{self, WORD_COUNTS};
use crate::protect::Secret;
use crate::{Phrase, stack};
use field::{Field, MAX_PARITY, MAX_SYMBOLS};

/// Stands, in what a [`Repaired`] records as read, for a token that is no word: no word number
/// reaches it.
const UNREADABLE: u16 = u16::MAX;
/// The bytes a [`Repaired`] records for each word: the number read and the number of the word it
/// is, two big-endian bytes each.
const RECORD_BYTES: usize = 4;

/// The repair words of a container, written out as a person copies them onto a card.
pub struct Card {
    text: Secret,
}

impl Card {
    /// The numbers of repair words a card can have: each repairs one unreadable word, and two
    /// repair one wrong word.
    pub const SIZES: [usize; 4] = [2, 4, 6, 8];

    /// The `words` repair words of `container`, a container of 12 to 24 words. Errors:
    /// [`Error::CardWordCount`] unless `words` is one of [`Card::SIZES`].
    pub fn new(container: &Phrase, words: usize) -> Result<Self, Error> {
        stack::cleared(|| {
            if !Self::SIZES.contains(&words) {
                return Err(Error::CardWordCount { words });
            }
            let mut data = [0u16; MAX_SYMBOLS];
            for (symbol, number) in data.iter_mut().zip(container.mnemonic().word_indices()) {
                // A word number, below 2,048.
                *symbol = number as u16;
            }
            let mut parity = [0u16; MAX_PARITY];
            let parity = &mut parity[..words];
            Field::new().parity(&data[..container.words()], parity);
            let list = parity.iter().map(|&number| phrase::word(number));
            Ok(Self {
                text: phrase::text_of(words, list),
            })
        })
    }

    /// The repair words in their order, lower case, one space apart. The card should also carry
    /// the profile's name and number its words, such as `1/4` to `4/4`, which a host leaves out
    /// again before [`Repaired::of`].
    #[expect(
        clippy::expect_used,
        reason = "the text holds words of the English list, which are ASCII"
    )]
    pub fn as_str(&self) -> &str {
        self.text
            .as_str()
            .expect("a card's text holds English BIP39 words")
    }
}

impl fmt::Debug for Card {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Card(hidden)")
    }
}

/// A container repaired with its card, and what was repaired.
pub struct Repaired {
    container: Phrase,
    /// For each word of the container phrase and then of the card, [`RECORD_BYTES`]: the number
    /// read there, or [`UNREADABLE`], and the number of the word it is.
    record: Secret,
}

impl Repaired {
    /// Repairs a container from `written`, its words as read from the container phrase, and
    /// `card`, its repair words as read from the card. Each token is read as
    /// [`Phrase::read_word`] reads it; a token that is no word, such as `?` for a word that cannot
    /// be read, is unreadable at its place. A word left out without a mark moves the words after
    /// it to other places, which the code does not guarantee to repair.
    ///
    /// Errors, in this order: [`Error::ContainerWordCount`], [`Error::CardWordCount`],
    /// [`Error::NotPossible`] when no repair within 2e + s <= k gives a container that passes its
    /// BIP39 checksum. Beyond that bound, or with the card of another container phrase, a repair
    /// can also give another container that passes the checksum: a repair does not show that the
    /// container is the original, which only a rehearsal of the recovery does.
    pub fn of(written: &str, card: &str) -> Result<Self, Error> {
        stack::cleared(|| {
            let words = written.split_whitespace().count();
            if !WORD_COUNTS.contains(&words) {
                return Err(Error::ContainerWordCount { words });
            }
            let card_words = card.split_whitespace().count();
            if !Card::SIZES.contains(&card_words) {
                return Err(Error::CardWordCount { words: card_words });
            }
            let tokens = written.split_whitespace().chain(card.split_whitespace());
            let mut received = [0u16; MAX_SYMBOLS];
            let mut unreadable = [0usize; MAX_SYMBOLS];
            let mut erased = 0;
            for (position, token) in tokens.enumerate() {
                match phrase::number_of(token) {
                    Some(number) => received[position] = number,
                    None => {
                        unreadable[erased] = position;
                        erased += 1;
                    }
                }
            }
            let symbols = words + card_words;
            let (received, unreadable) = (&received[..symbols], &unreadable[..erased]);
            let mut corrected = [0u16; MAX_SYMBOLS];
            let corrected = &mut corrected[..symbols];
            if !Field::new().repair(received, unreadable, card_words, corrected) {
                return Err(Error::NotPossible);
            }
            // Damage beyond the code's bound can end in another codeword; the container's BIP39
            // checksum still catches most of those.
            let container =
                Phrase::of_numbers(&corrected[..words]).map_err(|_| Error::NotPossible)?;
            let mut record = Secret::zeroed(RECORD_BYTES * symbols);
            let (slots, _) = record.as_mut_bytes().as_chunks_mut::<RECORD_BYTES>();
            for (position, slot) in slots.iter_mut().enumerate() {
                let read = if unreadable.contains(&position) {
                    UNREADABLE
                } else {
                    received[position]
                };
                slot[..2].copy_from_slice(&read.to_be_bytes());
                slot[2..].copy_from_slice(&corrected[position].to_be_bytes());
            }
            Ok(Self { container, record })
        })
    }

    /// The repaired container, which has a valid checksum.
    pub fn container(&self) -> &Phrase {
        &self.container
    }

    /// Every repaired word, those of the container phrase first, then those of the card, each in
    /// its order. A host shows each with its place and what was read there before any recovery:
    /// a repair is never silent.
    pub fn changes(&self) -> impl Iterator<Item = Change> + '_ {
        let words = self.container.words();
        let (record, _) = self.record.as_bytes().as_chunks::<RECORD_BYTES>();
        record.iter().enumerate().filter_map(move |(index, slot)| {
            let read = u16::from_be_bytes([slot[0], slot[1]]);
            let word = u16::from_be_bytes([slot[2], slot[3]]);
            let on_card = index >= words;
            (read != word).then(|| Change {
                on_card,
                position: if on_card { index - words } else { index } + 1,
                read: (read != UNREADABLE).then(|| phrase::word(read)),
                word: phrase::word(word),
            })
        })
    }
}

impl fmt::Debug for Repaired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Repaired(hidden)")
    }
}

/// One repaired word.
#[derive(Clone, Copy)]
pub struct Change {
    on_card: bool,
    position: usize,
    read: Option<&'static str>,
    word: &'static str,
}

impl Change {
    /// Whether the word is one of the card rather than of the container phrase.
    pub fn on_card(self) -> bool {
        self.on_card
    }

    /// Its place on the container phrase or on the card, from 1.
    pub fn position(self) -> usize {
        self.position
    }

    /// The word read there, or `None` when the token was no word.
    pub fn read(self) -> Option<&'static str> {
        self.read
    }

    /// The word it is now.
    pub fn word(self) -> &'static str {
        self.word
    }
}

impl fmt::Debug for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Change(hidden)")
    }
}

/// Why a card or a repair was refused.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The container phrase as written has another number of words than 12, 15, 18, 21 or 24.
    ContainerWordCount {
        /// The number of words.
        words: usize,
    },
    /// A card of another number of words than [`Card::SIZES`].
    CardWordCount {
        /// The number of words.
        words: usize,
    },
    /// No repair within the code's bound gives a container that passes its BIP39 checksum.
    NotPossible,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContainerWordCount { words } => {
                write!(f, "{words} words is not the length of a container")
            }
            Self::CardWordCount { words } => {
                write!(f, "{words} words is not the length of a card")
            }
            Self::NotPossible => f.write_str("the card cannot repair the container phrase"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    // Unit tests through the public items: the container of the corpus's zero-12.json is only an
    // input here, and tests/profiles.rs replays the published cards and repairs.

    use super::*;
    use crate::test_support::{fixture, text};

    /// The container of `vectors/suite3/zero-12.json`.
    fn zero_12_container() -> Phrase {
        let transcript = fixture(include_str!("../tests/spec/vectors/suite3/zero-12.json"));
        Phrase::read(text(&transcript, "container")).unwrap()
    }

    /// What `changes` reports, in its order.
    fn changes(repaired: &Repaired) -> Vec<(bool, usize, Option<&str>, &str)> {
        repaired
            .changes()
            .map(|change| {
                (
                    change.on_card(),
                    change.position(),
                    change.read(),
                    change.word(),
                )
            })
            .collect()
    }

    /// Tokens are read as BIP39 words are: any case and four letters or more; a token longer than
    /// any word is unreadable, never cut to the word it begins with. The changes on the card come
    /// after those on the container phrase, at their places on the card.
    #[test]
    fn tokens_are_read_as_reading_words() {
        let container = zero_12_container();
        let card = Card::new(&container, 4).unwrap();
        let typed: Vec<String> = container
            .as_str()
            .split(' ')
            .map(|word| word[..word.len().min(4)].to_uppercase())
            .collect();
        let repaired = Repaired::of(&typed.join("  "), &card.as_str().to_uppercase()).unwrap();
        assert_eq!(repaired.container().as_str(), container.as_str());
        assert!(changes(&repaired).is_empty());
        // The first word with six letters more, longer than any word of the list, and the second
        // repair word unreadable.
        let first = container.as_str().split(' ').next().unwrap();
        let long = container
            .as_str()
            .replacen(first, &format!("{first}ations"), 1);
        let mut card_words: Vec<&str> = card.as_str().split(' ').collect();
        let erased = std::mem::replace(&mut card_words[1], "?");
        let repaired = Repaired::of(&long, &card_words.join(" ")).unwrap();
        assert_eq!(
            changes(&repaired),
            [(false, 1, None, first), (true, 2, None, erased)]
        );
    }

    #[test]
    fn too_much_damage_or_a_wrong_card_is_refused() {
        let container = zero_12_container();
        let card = Card::new(&container, 2).unwrap();
        let mut words: Vec<&str> = container.as_str().split(' ').collect();
        words[..3].fill("?");
        assert_eq!(
            Repaired::of(&words.join(" "), card.as_str()).unwrap_err(),
            Error::NotPossible
        );
        assert_eq!(
            Repaired::of(container.as_str(), "abandon abandon abandon").unwrap_err(),
            Error::CardWordCount { words: 3 }
        );
        assert_eq!(
            Card::new(&container, 3).unwrap_err(),
            Error::CardWordCount { words: 3 }
        );
        assert_eq!(
            Repaired::of(&words[1..].join(" "), card.as_str()).unwrap_err(),
            Error::ContainerWordCount { words: 23 }
        );
    }

    /// A card of another container phrase is not always refused. The container phrases of the
    /// zero entropy and of entropy 00…01 differ in their last word only; with the other container
    /// phrase's two repair words, that word is "repaired" into a container that passes its
    /// checksum but is not the container phrase's. A repair never proves the container; a
    /// rehearsal of the recovery does.
    #[test]
    fn a_card_of_another_container_phrase_can_give_another_valid_container() {
        let written = [vec!["abandon"; 23], vec!["art"]].concat().join(" ");
        let other = [vec!["abandon"; 23], vec!["diesel"]].concat().join(" ");
        let card = Card::new(&Phrase::read(&other).unwrap(), 2).unwrap();
        let repaired = Repaired::of(&written, card.as_str()).unwrap();
        assert_eq!(repaired.container().as_str(), other);
        assert_eq!(changes(&repaired), [(false, 24, Some("art"), "diesel")]);
    }

    #[test]
    fn debug_output_hides_the_words() {
        let container = zero_12_container();
        let card = Card::new(&container, 2).unwrap();
        let repaired = Repaired::of(container.as_str(), card.as_str()).unwrap();
        assert_eq!(
            format!("{card:?} {repaired:?}"),
            "Card(hidden) Repaired(hidden)"
        );
    }
}
