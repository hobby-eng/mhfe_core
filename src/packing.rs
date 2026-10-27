//! The 256-bit state `X` of suite 3 (specification: "Packing" and step 3 of "Recovering a
//! mnemonic").
//!
//! `X = E || Trunc_r(SHA-256(E))` with `r = 256 - ENT`. For a short phrase the free bits hold a
//! verifier: an internal consistency check that screens out wrong passwords and most corruption
//! and reveals the length, but does not authenticate the password (a wrong one passes with
//! probability about 2^-r for each length). A 24-word phrase fills `X` alone and has no verifier.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::Error;
use crate::protect::Secret;

pub(crate) const STATE_BYTES: usize = 32;
/// The words of a phrase that fills the whole state: a suite 3 container, and the longest
/// original, which leaves no room for a verifier.
pub(crate) const STATE_WORDS: usize = words_of_entropy(STATE_BYTES);
/// The short phrase lengths, in the order detection tests them.
pub(crate) const SHORT_WORD_COUNTS: [usize; 4] = [12, 15, 18, 21];

/// The words of a BIP39 phrase of `bytes` bytes of entropy: BIP39 adds one checksum bit to every
/// 32 bits of entropy, and each word carries 11 bits, so three words for every four bytes.
pub(crate) const fn words_of_entropy(bytes: usize) -> usize {
    bytes / 4 * 3
}

/// The entropy bytes of a BIP39 phrase of `words` words, the inverse of [`words_of_entropy`].
pub(crate) const fn entropy_of_words(words: usize) -> usize {
    words / 3 * 4
}

/// Packs the entropy `E` of a phrase into `X`, which is the phrase in all but form.
pub(crate) fn pack(entropy: &[u8]) -> Secret {
    let mut state = Secret::zeroed(STATE_BYTES);
    let (source, verifier) = state.as_mut_bytes().split_at_mut(entropy.len());
    source.copy_from_slice(entropy);
    if !verifier.is_empty() {
        let mut digest = Sha256::digest(entropy);
        verifier.copy_from_slice(&digest[..verifier.len()]);
        digest.as_mut_slice().zeroize();
    }
    state
}

/// Reads `X` as the entropy of a phrase of `words` words: its first `ENT / 8` bytes, read in place,
/// since a copy would lie outside the buffer that holds `X`. For a short phrase all `r` verifier
/// bits must match, else [`Error::VerifierMismatch`].
pub(crate) fn unpack(state: &[u8], words: usize) -> Result<&[u8], Error> {
    let (entropy, verifier) = state.split_at(entropy_of_words(words));
    if !verifier.is_empty() {
        let mut digest = Sha256::digest(entropy);
        let matches = *verifier == digest[..verifier.len()];
        digest.as_mut_slice().zeroize();
        if !matches {
            return Err(Error::VerifierMismatch);
        }
    }
    Ok(entropy)
}

/// The 12- to 21-word lengths whose verifier `X` passes, ascending: one for a short original, none
/// for a 24-word one or a wrong password, and more than one only by accident, about once in 2^32.
pub(crate) fn detected_lengths(state: &[u8]) -> Vec<usize> {
    SHORT_WORD_COUNTS
        .into_iter()
        .filter(|&words| unpack(state, words).is_ok())
        .collect()
}

#[cfg(test)]
mod tests {
    // The verifier and length-detection cases are replayed here, not in tests/ (RUST-08): they
    // are compared with the packed state `X`, which the public API hides.

    use bip39::Mnemonic;

    use super::*;
    use crate::test_support::{SUITE_3_VALIDATION, fixture, hex, text};

    /// Public test entropy of `length` bytes, every byte different.
    fn entropy(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
            .collect()
    }

    /// The first `ENT/32` bits of the verifier are the phrase's BIP39 checksum.
    fn assert_verifier_starts_with_the_checksum(source: &[u8], state: &[u8]) {
        let checksum = Mnemonic::from_entropy(source).unwrap().checksum();
        let bits = source.len() / 4;
        assert_eq!(state[source.len()] >> (8 - bits), checksum);
    }

    #[test]
    fn short_phrases_get_a_sha256_verifier() {
        let zero = [0u8; 16];
        let state = pack(&zero);
        let digest = Sha256::digest(zero);
        assert_eq!(state.as_bytes()[..16], zero);
        assert_eq!(state.as_bytes()[16..], digest[..16]);
        assert_eq!(unpack(state.as_bytes(), 12).unwrap(), zero);
    }

    /// The 21-word verifier of 00 01 .. 1b is the first four bytes of their SHA-256 in digest
    /// order, never an integer read in host byte order, and begins with the checksum.
    #[test]
    fn the_verifier_keeps_digest_order_and_begins_with_the_checksum() {
        let case = &fixture(SUITE_3_VALIDATION)["verifier_serialization"];
        let source = hex(text(case, "entropy_hex"));
        let state = pack(&source);
        assert_eq!(state.as_bytes(), hex(text(case, "state_hex")));
        assert_eq!(state.as_bytes()[28..], hex(text(case, "sha256_hex"))[..4]);
        assert_eq!(state.as_bytes()[28..], hex(text(case, "verifier_hex")));
        assert_verifier_starts_with_the_checksum(&source, state.as_bytes());
    }

    #[test]
    fn detection_finds_the_lengths_of_the_shared_cases() {
        let cases = fixture(SUITE_3_VALIDATION);
        for case in cases["length_detection"].as_array().unwrap() {
            let state = hex(text(case, "state_hex"));
            let expected: Vec<usize> = case["matching_short_lengths"]
                .as_array()
                .unwrap()
                .iter()
                .map(|words| words.as_u64().unwrap() as usize)
                .collect();
            assert_eq!(detected_lengths(&state), expected, "{}", text(case, "id"));
            if let Some(source) = case.get("entropy_hex") {
                let source = hex(source.as_str().unwrap());
                assert_eq!(pack(&source).as_bytes(), state);
                if source.len() < STATE_BYTES {
                    assert_verifier_starts_with_the_checksum(&source, &state);
                }
            }
        }
    }

    /// `X` is the phrase in all but form: it is packed into a secret, and a reading of it is no copy
    /// but the start of the same buffer.
    #[test]
    fn the_state_is_packed_into_a_secret_and_read_in_place() {
        let state = pack(&entropy(20));
        assert_eq!(state.is_locked(), cfg!(any(unix, windows)));
        let reading = unpack(state.as_bytes(), 15).unwrap();
        assert_eq!(
            reading.as_ptr(),
            state.as_bytes().as_ptr(),
            "the reading is a copy"
        );
        assert_eq!(reading, entropy(20));
    }

    #[test]
    fn a_24_word_phrase_fills_the_state_alone() {
        let source = entropy(32);
        let state = pack(&source);
        assert_eq!(state.as_bytes(), source);
        assert_eq!(unpack(state.as_bytes(), 24).unwrap(), source);
        assert!(detected_lengths(state.as_bytes()).is_empty());
    }

    #[test]
    fn any_changed_verifier_bit_is_rejected() {
        let state = pack(&entropy(28));
        for byte in 28..32 {
            for bit in 0..8 {
                let mut corrupted = state.as_bytes().to_vec();
                corrupted[byte] ^= 1 << bit;
                assert_eq!(unpack(&corrupted, 21), Err(Error::VerifierMismatch));
            }
        }
    }
}
