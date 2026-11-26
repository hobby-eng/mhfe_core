//! What the fuzz targets share: a BIP39 phrase of any of the five lengths, made from the input.

use mhfe_core::Phrase;

/// The entropy lengths of the phrases of 12, 15, 18, 21 and 24 words.
pub const ENTROPY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

/// A phrase whose length `shape` chooses and whose entropy comes first in `rest`, and what is left
/// of `rest`; `None` when `rest` is too short. Entropy of a phrase's length that is refused stops
/// the run, as every such entropy makes a phrase.
#[allow(
    clippy::panic,
    reason = "a fuzz target answers by stopping the run: a refusal here is a finding, not a skip"
)]
pub fn phrase_of(shape: u8, rest: &[u8]) -> Option<(Phrase, &[u8])> {
    let bytes = ENTROPY_BYTES[usize::from(shape) % ENTROPY_BYTES.len()];
    let (entropy, left) = rest.split_at_checked(bytes)?;
    match Phrase::from_entropy(entropy) {
        Ok(phrase) => Some((phrase, left)),
        Err(error) => panic!("{bytes} bytes of entropy refused: {error}"),
    }
}
