//! What the fuzz targets share: a BIP39 phrase of any of the five lengths, made from the input.

use mhfe_core::Phrase;

/// The entropy lengths of the phrases of 12, 15, 18, 21 and 24 words.
pub const ENTROPY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

/// A phrase whose length `shape` chooses and whose entropy comes first in `rest`, and what is left
/// of `rest`; `None` when `rest` is too short.
pub fn phrase_of(shape: u8, rest: &[u8]) -> Option<(Phrase, &[u8])> {
    let bytes = ENTROPY_BYTES[usize::from(shape) % ENTROPY_BYTES.len()];
    let (entropy, left) = rest.split_at_checked(bytes)?;
    Phrase::from_entropy(entropy)
        .ok()
        .map(|phrase| (phrase, left))
}
