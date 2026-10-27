//! The code of the profile: a shortened Reed–Solomon code over GF(2^11), whose 2,048 elements are
//! the word numbers of the BIP39 list.
//!
//! The word numbers, and every value computed from them, are held in fixed arrays on the stack,
//! never on the heap, and the profile's public functions but `Repaired::changes` clear the stack
//! after them (`stack::cleared`). Only the tables of the field and the generator polynomials,
//! which are the same for every container, are on the heap.

use super::Card;
use crate::packing::STATE_WORDS;

/// Elements of GF(2^11): 2,048, as many as the words of the BIP39 list.
const FIELD_SIZE: usize = 2048;
/// The order of the multiplicative group, 2^11 - 1.
const ORDER: usize = FIELD_SIZE - 1;
/// x^11 + x^2 + 1, a primitive polynomial of degree 11.
const POLYNOMIAL: usize = 0x805;
/// The most repair words a card has.
pub(super) const MAX_PARITY: usize = Card::SIZES[Card::SIZES.len() - 1];
/// The most symbols of a codeword: a 24-word container and the most repair words.
pub(super) const MAX_SYMBOLS: usize = STATE_WORDS + MAX_PARITY;

/// GF(2^11) by its tables of powers and logarithms of alpha = x.
pub(super) struct Field {
    /// alpha^i for i from 0 to 2 * ORDER - 1, so that a sum of two logarithms needs no reduction.
    exp: Vec<u16>,
    /// The logarithm of each nonzero element; log[0] is unused.
    log: Vec<u16>,
}

impl Field {
    pub(super) fn new() -> Self {
        let mut exp = vec![0u16; 2 * ORDER];
        let mut log = vec![0u16; FIELD_SIZE];
        let mut value = 1usize;
        let (powers, repeated) = exp.split_at_mut(ORDER);
        for (power, slot) in powers.iter_mut().enumerate() {
            *slot = value as u16;
            log[value] = power as u16;
            value <<= 1;
            if value & FIELD_SIZE != 0 {
                value ^= POLYNOMIAL;
            }
        }
        repeated.copy_from_slice(powers);
        Self { exp, log }
    }

    fn mul(&self, a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            return 0;
        }
        self.exp[usize::from(self.log[usize::from(a)]) + usize::from(self.log[usize::from(b)])]
    }

    /// `a / b`, for a nonzero `b`.
    fn div(&self, a: u16, b: u16) -> u16 {
        if a == 0 {
            return 0;
        }
        let power =
            usize::from(self.log[usize::from(a)]) + ORDER - usize::from(self.log[usize::from(b)]);
        self.exp[power]
    }

    /// alpha^power.
    fn alpha(&self, power: usize) -> u16 {
        self.exp[power % ORDER]
    }

    /// The value at `x` of the polynomial with `coefficients`, the highest degree first.
    fn eval(&self, coefficients: &[u16], x: u16) -> u16 {
        coefficients
            .iter()
            .fold(0, |sum, &coefficient| self.mul(sum, x) ^ coefficient)
    }

    /// g(x) = (x + alpha)(x + alpha^2)...(x + alpha^k), the highest degree first.
    fn generator(&self, k: usize) -> Vec<u16> {
        let mut g = vec![1u16];
        for power in 1..=k {
            let root = self.alpha(power);
            let mut next = vec![0u16; g.len() + 1];
            for (i, &coefficient) in g.iter().enumerate() {
                next[i] ^= coefficient;
                next[i + 1] ^= self.mul(coefficient, root);
            }
            g = next;
        }
        g
    }

    /// Writes the k = `parity.len()` parity symbols of `data` into `parity`: the remainder of
    /// m(x) * x^k by g(x), highest degree first.
    pub(super) fn parity(&self, data: &[u16], parity: &mut [u16]) {
        let k = parity.len();
        let g = self.generator(k);
        parity.fill(0);
        for &symbol in data {
            let feedback = symbol ^ parity[0];
            for i in 0..k - 1 {
                parity[i] = parity[i + 1] ^ self.mul(feedback, g[i + 1]);
            }
            parity[k - 1] = self.mul(feedback, g[k]);
        }
    }

    /// S_j = c(alpha^j) for j from 1 to k, then zeros; all zero for a codeword.
    fn syndromes(&self, codeword: &[u16], k: usize) -> [u16; MAX_PARITY] {
        let mut syndromes = [0; MAX_PARITY];
        for (power, syndrome) in (1..=k).zip(&mut syndromes) {
            *syndrome = self.eval(codeword, self.alpha(power));
        }
        syndromes
    }

    /// Writes into `corrected` the codeword that differs from `received` at most at `positions`,
    /// k or fewer (erasure decoding, Forney's formula); false when there is none.
    fn correct_at(
        &self,
        received: &[u16],
        positions: &[usize],
        k: usize,
        corrected: &mut [u16],
    ) -> bool {
        let n = received.len();
        let syndromes = self.syndromes(received, k);
        corrected.copy_from_slice(received);
        if syndromes.iter().all(|&syndrome| syndrome == 0) {
            return true;
        }
        // The locator of a position: alpha to the power of the degree of its term.
        let mut locators = [0u16; MAX_PARITY];
        for (locator, &position) in locators.iter_mut().zip(positions) {
            *locator = self.alpha(n - 1 - position);
        }
        // Gamma(x) = prod (1 + X_i x), and Omega(x) = S(x) Gamma(x) mod x^k with
        // S(x) = S_1 + S_2 x + ... + S_k x^(k-1); both lowest degree first.
        let mut gamma = [0u16; MAX_PARITY + 1];
        gamma[0] = 1;
        for (degree, &locator) in locators[..positions.len()].iter().enumerate() {
            // Times (1 + X_i x), in place from the highest coefficient down.
            for i in (0..=degree).rev() {
                gamma[i + 1] ^= self.mul(gamma[i], locator);
            }
        }
        let mut omega = [0u16; MAX_PARITY];
        for (i, &syndrome) in syndromes[..k].iter().enumerate() {
            for (j, &coefficient) in gamma.iter().enumerate() {
                if i + j < k {
                    omega[i + j] ^= self.mul(syndrome, coefficient);
                }
            }
        }
        let low_first = |coefficients: &[u16], x: u16| {
            coefficients
                .iter()
                .rev()
                .fold(0, |sum, &coefficient| self.mul(sum, x) ^ coefficient)
        };
        // Gamma'(x): in characteristic 2 only the odd powers survive the derivative.
        let mut derivative = [0u16; MAX_PARITY];
        for (i, coefficient) in derivative.iter_mut().enumerate().step_by(2) {
            *coefficient = gamma[i + 1];
        }
        for (&position, &locator) in positions.iter().zip(&locators) {
            let inverse = self.div(1, locator);
            let denominator = low_first(&derivative, inverse);
            if denominator == 0 {
                return false;
            }
            // Forney with the first root alpha^1: e = Omega(X^-1) / Gamma'(X^-1).
            corrected[position] ^= self.div(low_first(&omega, inverse), denominator);
        }
        self.syndromes(corrected, k)
            .iter()
            .all(|&syndrome| syndrome == 0)
    }

    /// Writes into `corrected` the repair of `received`, whose `unreadable` positions are known,
    /// by trying every set of e wrong positions with 2e + s <= k, fewest first; false when none
    /// gives a codeword. The first codeword found is the only one within that distance, as the
    /// code's minimum distance is k + 1. A codeword has at most 32 symbols and k is at most 8, so
    /// trying the sets takes milliseconds.
    pub(super) fn repair(
        &self,
        received: &[u16],
        unreadable: &[usize],
        k: usize,
        corrected: &mut [u16],
    ) -> bool {
        if unreadable.len() > k {
            return false;
        }
        let mut readable = [0usize; MAX_SYMBOLS];
        let mut count = 0;
        for position in 0..received.len() {
            if !unreadable.contains(&position) {
                readable[count] = position;
                count += 1;
            }
        }
        let mut positions = [0usize; MAX_PARITY];
        positions[..unreadable.len()].copy_from_slice(unreadable);
        for wrong in 0..=(k - unreadable.len()) / 2 {
            let damaged = unreadable.len() + wrong;
            let mut found = false;
            for_each_subset(&readable[..count], wrong, &mut |chosen| {
                if !found {
                    positions[unreadable.len()..damaged].copy_from_slice(chosen);
                    found = self.correct_at(received, &positions[..damaged], k, corrected);
                }
            });
            if found {
                return true;
            }
        }
        false
    }
}

/// Calls `visit` with every subset of `items` that has `size` elements, at most [`MAX_PARITY`].
fn for_each_subset(items: &[usize], size: usize, visit: &mut dyn FnMut(&[usize])) {
    fn walk(
        items: &[usize],
        chosen: &mut [usize],
        filled: usize,
        start: usize,
        visit: &mut dyn FnMut(&[usize]),
    ) {
        if filled == chosen.len() {
            visit(chosen);
            return;
        }
        for i in start..items.len() {
            chosen[filled] = items[i];
            walk(items, chosen, filled + 1, i + 1, visit);
        }
    }
    let mut chosen = [0; MAX_PARITY];
    walk(items, &mut chosen[..size], 0, 0, visit);
}

#[cfg(test)]
mod tests {
    // The code is tested here, not in tests/ (RUST-08): the public API hides the generator
    // polynomials and the decoding of codewords of every length.

    use super::*;
    use crate::phrase::WORD_COUNTS;

    #[test]
    fn the_generator_polynomials_are_the_specification_s() {
        let field = Field::new();
        assert_eq!(field.generator(2), [1, 6, 8]);
        assert_eq!(field.generator(4), [1, 30, 216, 960, 1024]);
        assert_eq!(field.generator(6), [1, 126, 1181, 1719, 2029, 1077, 1034]);
        assert_eq!(
            field.generator(8),
            [1, 510, 1509, 1770, 1837, 850, 1339, 600, 680]
        );
    }

    /// Every pattern of damage within 2e + s <= k, at random places of random codewords of every
    /// length and card size, card words included, is repaired; the places are drawn by a fixed
    /// generator, so the test is the same every run.
    #[test]
    fn damage_within_the_bound_is_repaired() {
        let field = Field::new();
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
                    let (data, parity) = codeword.split_at_mut(words);
                    data.iter_mut()
                        .for_each(|symbol| *symbol = next(FIELD_SIZE) as u16);
                    field.parity(data, parity);
                    let unreadable_count = next(count + 1);
                    let wrong_count = next((count - unreadable_count) / 2 + 1);
                    let mut received = codeword.clone();
                    let mut unreadable = Vec::new();
                    let mut damaged = Vec::new();
                    while damaged.len() < unreadable_count + wrong_count {
                        let position = next(codeword.len());
                        if !damaged.contains(&position) {
                            damaged.push(position);
                        }
                    }
                    for (i, &position) in damaged.iter().enumerate() {
                        if i < unreadable_count {
                            received[position] = 0;
                            unreadable.push(position);
                        } else {
                            // A different word, never the right one.
                            received[position] ^= 1 + next(FIELD_SIZE - 1) as u16;
                        }
                    }
                    let mut repaired = vec![0u16; codeword.len()];
                    assert!(field.repair(&received, &unreadable, count, &mut repaired));
                    assert_eq!(repaired, codeword);
                }
            }
        }
    }
}
