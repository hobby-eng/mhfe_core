//! The optional source profile MHFE-WALLET-CHECK-SEED-1 (specification: "Optional source profile:
//! a recovery check for new 24-word phrases"): a new 24-word phrase is drawn until its BIP39 seed
//! passes a check, [`draw`], and every recovery evaluates the check for its 24-word readings,
//! [`Seed::passes`]. It changes nothing in suite 3.
//!
//! The check, byte for byte: `T` is the SHA-256 digest of
//!
//! - the ASCII tag `MHFE-WALLET-CHECK-SEED-1`, 24 bytes, with no terminating NUL;
//! - `BE32(256)`, the bits of the entropy as a 4-byte big-endian number, `00 00 01 00`;
//! - the 64-byte BIP39 seed: PBKDF2-HMAC-SHA512 with 2,048 iterations of the phrase, its words in
//!   lower case one space apart, with the salt `mnemonic` followed by the BIP39 passphrase `Q` in
//!   NFKD, Unicode 18.0.0;
//!
//! and the phrase passes when the first 16 bits of `T` are zero.
//!
//! A pass is statistical evidence, not proof. A random phrase passes with a given passphrase once
//! in about 65,536, so a wrong MHFE password or passphrase passes at that rate, and a passphrase
//! that passes with a given phrase is found by anyone who searches about 65,536 of them. A drawn
//! phrase keeps about 240 of its 256 bits of entropy for a given passphrase. A pass never
//! identifies the wallet: only a reference such as an address does. Without a passphrase the seed
//! is a function of the phrase alone, so anyone who sees the phrase can test the check.

use std::fmt;
use std::ops::ControlFlow;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::nfkd::Nfkd;
use crate::packing::{STATE_BYTES, STATE_WORDS};
use crate::protect::Secret;
use crate::{Error, Phrase, stack};

/// The domain tag, which keeps the check apart from every other hash of the seed.
const DOMAIN: &[u8] = b"MHFE-WALLET-CHECK-SEED-1";
/// `ENT` of a 24-word phrase, which `T` holds as `BE32(256)`.
const ENTROPY_BITS: u32 = 8 * STATE_BYTES as u32;
/// The leading bits of `T` that must be zero: a wrong phrase passes once in 2^16.
const CHECK_BITS: usize = 16;
/// The length of a BIP39 seed.
const SEED_BYTES: usize = 64;

/// The BIP39 seed of a phrase and a passphrase, and the profile's check on it.
pub struct Seed {
    bytes: Secret,
    /// Whether the phrase has 24 words, the only length the check is defined for.
    twenty_four_words: bool,
}

impl Seed {
    /// The BIP39 seed of `phrase` with `passphrase`, which is used in Unicode 18.0.0 NFKD: any
    /// passphrase, the empty one included, without the limits of an MHFE password. Its NFKD takes
    /// time and memory linear in its length, so a host bounds a passphrase it reads from a file or
    /// the clipboard.
    pub fn derive(phrase: &Phrase, passphrase: &str) -> Self {
        stack::cleared(|| Self::of(phrase, &Nfkd::of(passphrase).write()))
    }

    /// The 64 bytes of the seed.
    #[expect(
        clippy::expect_used,
        reason = "Seed::of writes a seed of 64 bytes, never another length"
    )]
    pub fn as_bytes(&self) -> &[u8; SEED_BYTES] {
        self.bytes
            .as_bytes()
            .try_into()
            .expect("a seed has 64 bytes")
    }

    /// Whether the seed passes the check, `Trunc_16(T) = 0`; `None` unless the phrase has 24
    /// words. A pass does not confirm the wallet, so a 24-word reading stays not verified.
    pub fn passes(&self) -> Option<bool> {
        stack::cleared(|| {
            self.twenty_four_words
                .then(|| seed_passes(self.bytes.as_bytes()))
        })
    }

    /// The seed of `phrase` with `normalized`, the passphrase in NFKD.
    #[expect(
        clippy::expect_used,
        reason = "the NFKD of text, which Nfkd writes, is UTF-8"
    )]
    fn of(phrase: &Phrase, normalized: &Secret) -> Self {
        let passphrase = normalized.as_str().expect("the NFKD of text is UTF-8");
        let mut seed = phrase.mnemonic().to_seed_normalized(passphrase);
        let mut bytes = Secret::zeroed(SEED_BYTES);
        bytes.as_mut_bytes().copy_from_slice(&seed);
        seed.zeroize();
        Self {
            bytes,
            twenty_four_words: phrase.words() == STATE_WORDS,
        }
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(hidden)")
    }
}

/// The profile's generation: with `passphrase` held fixed, each trial `fill` writes 32 bytes from
/// the host's cryptographic generator, and the first trial whose 24-word phrase passes the check
/// is the phrase, about 65,536 trials on average. The trials run one after another, in order, so
/// the phrase depends only on their outcomes. `Break` from `fill` stops with [`Error::Cancelled`].
/// The phrase then becomes a suite 3 container as any other, with its creation check. The NFKD of
/// `passphrase`, before the first trial, takes time and memory linear in its length, so a host
/// bounds a passphrase it reads from a file or the clipboard.
#[expect(
    clippy::expect_used,
    reason = "the trial buffer is made with exactly 32 bytes"
)]
pub fn draw(
    passphrase: &str,
    fill: &mut dyn FnMut(&mut [u8; STATE_BYTES]) -> ControlFlow<()>,
) -> Result<Phrase, Error> {
    stack::cleared(|| {
        let normalized = Nfkd::of(passphrase).write();
        let mut entropy = Secret::zeroed(STATE_BYTES);
        loop {
            let trial = entropy
                .as_mut_bytes()
                .try_into()
                .expect("a trial has 32 bytes");
            if fill(trial).is_break() {
                return Err(Error::Cancelled);
            }
            let phrase = Phrase::encode(entropy.as_bytes())?;
            if seed_passes(Seed::of(&phrase, &normalized).bytes.as_bytes()) {
                return Ok(phrase);
            }
        }
    })
}

/// `T = SHA-256(DOMAIN || BE32(256) || seed)`.
fn digest(seed: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(ENTROPY_BITS.to_be_bytes())
        .chain_update(seed)
        .finalize()
        .into()
}

/// Whether `seed` passes: `T` starts with [`CHECK_BITS`] zero bits. `T`, derived from the seed,
/// is wiped.
fn seed_passes(seed: &[u8]) -> bool {
    let mut digest = digest(seed);
    let passes = digest[..CHECK_BITS / 8].iter().all(|&byte| byte == 0);
    digest.zeroize();
    passes
}

#[cfg(test)]
mod tests {
    // The profile's digests are replayed here, not in tests/ (RUST-08): the public API gives only
    // whether `T` passes, not `T` itself.

    use super::*;
    use crate::test_support::{hex, wallet_check_prefixes, wallet_check_rows};

    /// The phrase of a vector: 192 zero bits, then `counter` as a 64-bit big-endian number.
    fn phrase(counter: u64) -> Phrase {
        let mut entropy = [0u8; STATE_BYTES];
        entropy[STATE_BYTES - 8..].copy_from_slice(&counter.to_be_bytes());
        Phrase::from_entropy(&entropy).unwrap()
    }

    /// Whether `T` fails the check: its first 16 bits are not all zero.
    fn fails(digest: &[u8]) -> bool {
        digest[..CHECK_BITS / 8] != [0; CHECK_BITS / 8]
    }

    /// vectors/profiles/README.md: the whole `T` of each row, and the first bytes of the failing
    /// digests its text gives: each row's counter with the other row's passphrase, and the first
    /// row with `BE32(256)` left out.
    #[test]
    fn the_digests_are_the_profile_vectors() {
        let rows = wallet_check_rows();
        for (counter, passphrase, expected) in &rows {
            let seed = Seed::derive(&phrase(*counter), passphrase);
            assert_eq!(digest(seed.as_bytes())[..], hex(expected), "{counter}");
        }
        let [(first, first_passphrase, _), (second, second_passphrase, _)] = &rows[..] else {
            panic!("two rows");
        };
        let prefixes = wallet_check_prefixes();
        let crossed = [(first, second_passphrase), (second, first_passphrase)];
        for ((counter, passphrase), prefix) in crossed.into_iter().zip(&prefixes) {
            let seed = Seed::derive(&phrase(*counter), passphrase);
            let digest = digest(seed.as_bytes());
            assert_eq!(digest[..4], hex(prefix), "{counter}");
            assert!(fails(&digest), "{counter}");
        }
        let seed = Seed::derive(&phrase(*first), first_passphrase);
        let without_length = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(seed.as_bytes())
            .finalize();
        assert_eq!(without_length[..4], hex(&prefixes[2]));
        assert!(fails(&without_length));
        assert_eq!(format!("{seed:?}"), "Seed(hidden)");
    }
}
