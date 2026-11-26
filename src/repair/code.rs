//! The code of the profile: the shortened Reed–Solomon code of reed-solomon-core over GF(2^11),
//! whose 2,048 elements are the word numbers of the BIP39 list, with the first root alpha and a
//! step of 1, so that g(x) = (x + alpha)(x + alpha^2)...(x + alpha^k).
//!
//! The word numbers, and every value computed from them, are held in fixed arrays on the stack,
//! never on the heap, each wiped when it goes out of use, as in WebAssembly nothing clears the
//! stack. In a native build the profile's public functions but `Repaired::changes` also clear the
//! stack after them (`stack::cleared`), and the calls of reed-solomon-core clear it too, through the
//! same secret-protection-core, and wipe their working room.

use reed_solomon_core::{CyclicWords, Field};
use zeroize::Zeroizing;

use super::Card;
use crate::packing::STATE_WORDS;

/// The most repair words a card has.
pub(super) const MAX_PARITY: usize = Card::SIZES[Card::SIZES.len() - 1];
/// The most symbols of a codeword: a 24-word container and the most repair words.
pub(super) const MAX_SYMBOLS: usize = STATE_WORDS + MAX_PARITY;
/// The working room of a repair with the most repair words.
const ROOM: usize = CyclicWords::room(MAX_PARITY);
/// The power of alpha that is the first root of g(x).
const FIRST_ROOT: u32 = 1;
/// The step between the powers of alpha that are the roots of g(x).
const ROOT_STEP: u32 = 1;

/// Runs `work` with the code of `data` container words and `parity` repair words.
#[expect(
    clippy::expect_used,
    reason = "12 to 24 words and 2 to 8 repair words make at most 32 symbols, a code over GF(2^11)"
)]
fn with_code<T>(data: usize, parity: usize, work: impl FnOnce(&CyclicWords<'_>) -> T) -> T {
    let mut generator = [0u16; MAX_PARITY + 1];
    let code = CyclicWords::new(
        Field::Gf2048,
        data,
        parity,
        FIRST_ROOT,
        ROOT_STEP,
        &mut generator[..=parity],
    )
    .expect("the shape of a card is a code");
    work(&code)
}

/// Writes the k = `parity.len()` parity symbols of `data` into `parity`: the remainder of
/// m(x) * x^k by g(x), highest degree first.
#[expect(
    clippy::expect_used,
    reason = "word numbers are below 2,048, elements of GF(2^11), and the counts are the code's"
)]
pub(super) fn parity(data: &[u16], parity: &mut [u16]) {
    let mut sources = Zeroizing::new([[0u8; 2]; MAX_SYMBOLS]);
    for (bytes, symbol) in sources.iter_mut().zip(data) {
        *bytes = symbol.to_be_bytes();
    }
    let mut outputs = Zeroizing::new([[0u8; 2]; MAX_PARITY]);
    let mut remainder = [0u16; MAX_PARITY];
    let k = parity.len();
    with_code(data.len(), k, |code| {
        let sources = sources.each_ref().map(|bytes| bytes.as_slice());
        let mut outputs = outputs.each_mut().map(|bytes| bytes.as_mut_slice());
        code.encode(
            &sources[..data.len()],
            &mut outputs[..k],
            &mut remainder[..k],
        )
    })
    .expect("a card's data is a word of the code");
    for (symbol, bytes) in parity.iter_mut().zip(outputs.iter()) {
        *symbol = u16::from_be_bytes(*bytes);
    }
}

/// Writes into `corrected` the repair of `received`, whose `unreadable` positions, in rising
/// order, are known: the codeword within 2e + s <= k, the only one there, as the code's minimum
/// distance is k + 1. False when there is none.
#[expect(
    clippy::expect_used,
    reason = "the marks rise and lie in the word, and every word read is below 2,048"
)]
pub(super) fn repair(
    received: &[u16],
    unreadable: &[usize],
    k: usize,
    corrected: &mut [u16],
) -> bool {
    corrected.copy_from_slice(received);
    let mut room = [0u16; ROOM];
    with_code(received.len() - k, k, |code| {
        code.correct_word(corrected, unreadable, &mut room)
    })
    .expect("a word read from a card and its container is a word to correct")
    .is_some()
}

#[cfg(test)]
mod tests {
    // The code is tested here, not in tests/ (RUST-08): the public API hides the generator
    // polynomials and the decoding of codewords of every length.

    use super::*;
    use crate::phrase::WORD_COUNTS;

    /// Elements of GF(2^11): 2,048, as many as the words of the BIP39 list.
    const FIELD_SIZE: usize = 2048;

    #[test]
    fn the_generator_polynomials_are_the_specification_s() {
        let generator = |k| with_code(12, k, |code| code.generator().to_vec());
        assert_eq!(generator(2), [1, 6, 8]);
        assert_eq!(generator(4), [1, 30, 216, 960, 1024]);
        assert_eq!(generator(6), [1, 126, 1181, 1719, 2029, 1077, 1034]);
        assert_eq!(
            generator(8),
            [1, 510, 1509, 1770, 1837, 850, 1339, 600, 680]
        );
    }

    /// Every pattern of damage within 2e + s <= k, at random places of random codewords of every
    /// length and card size, card words included, is repaired; the places are drawn by a fixed
    /// generator, so the test is the same every run.
    #[test]
    fn damage_within_the_bound_is_repaired() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        for words in WORD_COUNTS {
            for count in Card::SIZES {
                for _ in 0..300 {
                    let mut codeword = vec![0u16; words + count];
                    let (data, check) = codeword.split_at_mut(words);
                    data.iter_mut()
                        .for_each(|symbol| *symbol = next(FIELD_SIZE) as u16);
                    parity(data, check);
                    let unreadable_count = next(count + 1);
                    let wrong_count = next((count - unreadable_count) / 2 + 1);
                    let mut received = codeword.clone();
                    let mut damaged = Vec::new();
                    while damaged.len() < unreadable_count + wrong_count {
                        let position = next(codeword.len());
                        if !damaged.contains(&position) {
                            damaged.push(position);
                        }
                    }
                    let mut unreadable = damaged[..unreadable_count].to_vec();
                    unreadable.sort_unstable();
                    for &position in &unreadable {
                        received[position] = 0;
                    }
                    for &position in &damaged[unreadable_count..] {
                        // A different word, never the right one.
                        received[position] ^= 1 + next(FIELD_SIZE - 1) as u16;
                    }
                    let mut repaired = vec![0u16; codeword.len()];
                    assert!(repair(&received, &unreadable, count, &mut repaired));
                    assert_eq!(repaired, codeword);
                }
            }
        }
    }
}
