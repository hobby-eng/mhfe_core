//! The optional password check word, the profile MHFE-PASSWORD-CHECK-1 (specification: "Optional
//! password check word"). Five words drawn independently and uniformly from the EFF large
//! wordlist, [`EFF_WORDS`], get a sixth, [`check_word`], and the six words are the MHFE password.
//! The check word lets a host notice and repair a typing error before any Argon2id work: one word
//! erased at a known place, the check word included, is restored uniquely; one wrong word is
//! noticed, but not where it is ([`Check::of`]).
//!
//! The profile's canonical form, which a host composes in a [`crate::protect::Secret`]: the five
//! drawn words and then the check word, in lower case as the list writes them, with one U+0020
//! space between words and nothing else.
//!
//! The five drawn words carry about 64.6 bits; the check word adds none and is as secret as the
//! rest. A check word that fits shows only that the six words belong together, never that the
//! password opens a given container.

use std::fmt;

use crate::protect::Secret;
use crate::stack;

/// The EFF large wordlist (`vendor/eff-large-wordlist/`, SHA-256 `addd3553…`), the words as
/// written, hyphens included, in the order of its lines and so in byte order. The index of a word
/// is its line number minus one: five dice rolls `r1` to `r5` select
/// `(r1 - 1) * 6^4 + (r2 - 1) * 6^3 + (r3 - 1) * 6^2 + (r4 - 1) * 6 + (r5 - 1)`.
pub static EFF_WORDS: [&str; LIST_SIZE] = include!(concat!(env!("OUT_DIR"), "/eff_words.rs"));

/// Words in the list: 6^5, one for every roll of five dice.
const LIST_SIZE: usize = 7776;
/// The words drawn at random, before the check word.
const DRAWN_WORDS: usize = 5;
/// The words of a password under the profile, the check word last.
const WORDS: usize = DRAWN_WORDS + 1;
/// The weights of the five drawn words, each coprime to 7,776, which is what makes one erased word
/// recoverable and one wrong word noticeable.
const WEIGHTS: [usize; DRAWN_WORDS] = [1, 5, 7, 11, 13];
/// Stands, among the indexes of a password's tokens, for a token not on the list: no index
/// reaches it.
const ERASED: u16 = u16::MAX;

/// The index of the check word for the indexes of the five drawn words,
/// `(d1 + 5 d2 + 7 d3 + 11 d4 + 13 d5) mod 7776`; `None` when an index is 7,776 or more.
pub fn check_word(drawn: [u16; DRAWN_WORDS]) -> Option<u16> {
    stack::cleared(|| {
        drawn
            .iter()
            .all(|&index| usize::from(index) < LIST_SIZE)
            .then(|| check_index(&drawn))
    })
}

/// What six words are under the profile.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// Six words of the list whose check word fits.
    Fits,
    /// One token is not on the list, such as `?` for a word that cannot be read; the five others
    /// give the only word that fits there.
    OneErased {
        /// Its place, from 1; 6 is the check word.
        position: usize,
        /// The word that fits.
        word: &'static str,
    },
    /// Six words of the list that do not fit: at least one is wrong, at a place that cannot be
    /// told. Each place admits exactly one repair, so there are six candidates.
    Mismatch {
        /// The word that would fit at each place, the first place first, with the five others as
        /// given.
        candidates: [&'static str; WORDS],
    },
    /// Not six tokens, or two or more of them off the list: the profile gives no repair.
    NotApplicable,
}

impl Check {
    /// Reads `password` under the profile: split at each U+0020 space, every token compared with
    /// the list exactly as written, hyphens included. The rules of reading BIP39 words do not
    /// apply, since the list holds both `yo-yo` and `yoyo`, and an extra space makes an empty
    /// token. A host shows any repair and asks before using it, and a password that does not fit
    /// is still a valid MHFE password as typed.
    pub fn of(password: &str) -> Self {
        stack::cleared(|| {
            let tokens = password.split(' ');
            if tokens.clone().count() != WORDS {
                return Self::NotApplicable;
            }
            // The indexes reveal the password.
            let mut indexes = Secret::zeroed(2 * WORDS);
            let (slots, _) = indexes.as_mut_bytes().as_chunks_mut();
            for (slot, token) in slots.iter_mut().zip(tokens) {
                *slot = index_of(token).unwrap_or(ERASED).to_be_bytes();
            }
            Self::of_indexes(indexes.as_bytes().as_chunks().0)
        })
    }

    /// The outcome for the six `indexes`, big-endian.
    fn of_indexes(indexes: &[[u8; 2]]) -> Self {
        let at = |position: usize| u16::from_be_bytes(indexes[position]);
        let restored = |position: usize| EFF_WORDS[restored_index(at, position)];
        let mut erased = (0..WORDS).filter(|&position| at(position) == ERASED);
        match (erased.next(), erased.next()) {
            (None, _) if restored_index(at, DRAWN_WORDS) == usize::from(at(DRAWN_WORDS)) => {
                Self::Fits
            }
            (None, _) => Self::Mismatch {
                candidates: std::array::from_fn(restored),
            },
            (Some(position), None) => Self::OneErased {
                position: position + 1,
                word: restored(position),
            },
            (Some(_), Some(_)) => Self::NotApplicable,
        }
    }
}

impl fmt::Debug for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Check(hidden)")
    }
}

/// [`check_word`] for five indexes below 7,776.
fn check_index(drawn: &[u16; DRAWN_WORDS]) -> u16 {
    let sum = drawn
        .iter()
        .zip(WEIGHTS)
        .map(|(&index, weight)| usize::from(index) * weight % LIST_SIZE)
        .sum::<usize>();
    // Below 7,776.
    (sum % LIST_SIZE) as u16
}

/// The index that makes the six fit at `position`, the five others as `at` gives them.
fn restored_index(at: impl Fn(usize) -> u16, position: usize) -> usize {
    let drawn = std::array::from_fn(|place| if place == position { 0 } else { at(place) });
    let check = usize::from(check_index(&drawn));
    if position == DRAWN_WORDS {
        return check;
    }
    // weight * d = check - (the weighted sum of the others): d is that times the weight's inverse.
    let wanted = (usize::from(at(DRAWN_WORDS)) + LIST_SIZE - check) % LIST_SIZE;
    wanted * inverse(WEIGHTS[position]) % LIST_SIZE
}

/// The inverse of `weight` modulo 7,776, which exists because the weight is coprime to it.
#[expect(
    clippy::expect_used,
    reason = "every weight is coprime to 7,776, so its inverse exists"
)]
fn inverse(weight: usize) -> usize {
    (1..LIST_SIZE)
        .find(|&candidate| weight * candidate % LIST_SIZE == 1)
        .expect("every weight is coprime to 7,776")
}

/// The index of `token` in the list, compared exactly as written.
fn index_of(token: &str) -> Option<u16> {
    // Below 7,776.
    EFF_WORDS
        .binary_search(&token)
        .ok()
        .map(|index| index as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The password of the five words at `drawn`, with their check word.
    fn password(drawn: [u16; DRAWN_WORDS]) -> String {
        let check = check_word(drawn).unwrap();
        let indexes = drawn.into_iter().chain([check]);
        let words: Vec<&str> = indexes.map(|index| EFF_WORDS[usize::from(index)]).collect();
        words.join(" ")
    }

    /// Only six tokens with at most one off the list have a repair, and tokens count only as
    /// written: an extra space makes an empty token, and `yoyo` is another word than `yo-yo`.
    #[test]
    fn other_passwords_are_not_applicable() {
        let fits = password([0, 1, 2, 3, 4]);
        let words: Vec<&str> = fits.split(' ').collect();
        for typed in [
            "correct horse battery staple".to_owned(),
            words[..DRAWN_WORDS].join(" "),
            format!("{} ? ? {}", words[0], words[3..].join(" ")),
            format!(" {fits}"),
            format!("{fits} extra"),
        ] {
            assert_eq!(Check::of(&typed), Check::NotApplicable, "{typed}");
        }
        let yo_yo = index_of("yo-yo").unwrap();
        let hyphenated = password([0, 1, 2, yo_yo, 4]);
        assert!(matches!(
            Check::of(&hyphenated.replace("yo-yo", "yoyo")),
            Check::Mismatch { .. }
        ));
        let erased = Check::of(&format!("{} ? {}", words[0], words[2..].join(" ")));
        assert_eq!(format!("{erased:?}"), "Check(hidden)");
    }
}
