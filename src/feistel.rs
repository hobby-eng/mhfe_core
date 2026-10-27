//! The 12-round balanced Feistel permutation (specification: "Permutation", and "Suite 4" for
//! the same-length containers).
//!
//! ```text
//! Suite 3, 128-bit halves:
//! S_i = Trunc_128(BLAKE2b-256(DS_SALT || BE32(MEM) || BE32(PIM) || BE32(i) || R))
//! K_i = Argon2id(P_enc, S_i)
//! M_i = Trunc_128(HMAC-SHA-256(K_i, DS_MASK || BE32(MEM) || BE32(PIM) || BE32(i) || R))
//!
//! Suite 4, h = ENT/2-bit halves, with its own domain strings and BE32(ENT) in both messages:
//! S_i = Trunc_128(BLAKE2b-256(DS_SALT || BE32(MEM) || BE32(PIM) || BE32(ENT) || BE32(i) || R))
//! M_i = Trunc_h(HMAC-SHA-256(K_i, DS_MASK || BE32(MEM) || BE32(PIM) || BE32(ENT) || BE32(i) || R))
//! ```
//!
//! Every value of a permutation lives in one [`Secret`], its workspace: both halves, and the
//! message, salt, key and mask of the round, the message holding `R` through the Argon2id call.

use std::ops::ControlFlow;

use blake2::Blake2b;
use blake2::digest::consts::U32;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::engine::{Argon2Engine, KEY_BYTES, SALT_BYTES};
use crate::packing::{STATE_BYTES, entropy_of_words};
use crate::protect::Secret;
use crate::suite::{ROUNDS, SUITE_3_DS_MASK, SUITE_3_DS_SALT, SUITE_4_DS_MASK, SUITE_4_DS_SALT};
use crate::{Error, Password, Suite, WorkFactor, stack};

type Blake2b256 = Blake2b<U32>;
type HmacSha256 = Hmac<Sha256>;

/// The block of SHA-256, which is the size of an HMAC-SHA-256 key.
const HMAC_KEY_BYTES: usize = 64;
/// One `BE32` value of a round message.
const BE32_BYTES: usize = 4;

/// The shape of one suite's permutation: its domain strings, the size of its halves and whether
/// its round message carries the entropy size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Geometry {
    ds_salt: &'static [u8],
    ds_mask: &'static [u8],
    half_bytes: usize,
    /// `ENT` of suite 4, written as `BE32(ENT)` after the settings; suite 3 has none.
    entropy_bits: Option<u32>,
}

impl Geometry {
    /// The permutation of `suite` for a phrase of `words` words: suite 3 works on the packed
    /// 256-bit state whatever the length, suite 4 on the entropy of a 12- to 21-word phrase.
    pub(crate) fn of(suite: Suite, words: usize) -> Self {
        match suite {
            Suite::TwentyFourWords => Self {
                ds_salt: SUITE_3_DS_SALT,
                ds_mask: SUITE_3_DS_MASK,
                half_bytes: STATE_BYTES / 2,
                entropy_bits: None,
            },
            Suite::SameLength => {
                let bytes = entropy_of_words(words);
                Self {
                    ds_salt: SUITE_4_DS_SALT,
                    ds_mask: SUITE_4_DS_MASK,
                    half_bytes: bytes / 2,
                    entropy_bits: Some(8 * bytes as u32),
                }
            }
        }
    }

    /// `BE32(MEM) || BE32(PIM) || [BE32(ENT)] || BE32(i) || R`.
    fn message_bytes(self) -> usize {
        let settings = if self.entropy_bits.is_some() { 4 } else { 3 };
        settings * BE32_BYTES + self.half_bytes
    }
}

/// The permutation for one password, one work factor and one suite's geometry.
pub(crate) struct Permutation<'a> {
    pub(crate) engine: &'a mut dyn Argon2Engine,
    pub(crate) password: &'a Password,
    pub(crate) work: WorkFactor,
    pub(crate) geometry: Geometry,
}

impl Permutation<'_> {
    /// `Y = Perm(X)`: rounds 0 to 11. `on_round` gets 1 to 12 before each round; `Break` stops
    /// before that round with [`Error::Cancelled`].
    pub(crate) fn forward(
        &mut self,
        x: &[u8],
        on_round: &mut dyn FnMut(u32) -> ControlFlow<()>,
    ) -> Result<Secret, Error> {
        let mut space = Workspace::new(self.geometry, x);
        for round in 0..ROUNDS {
            if on_round(round + 1).is_break() {
                return Err(Error::Cancelled);
            }
            // L_{i+1} = R_i and R_{i+1} = L_i XOR M_i: the left half takes the mask.
            self.round(&mut space, round, Side::Left)?;
        }
        Ok(space.into_state())
    }

    /// `X = Perm^-1(Y)`: rounds 11 down to 0, while `on_round` still counts from 1 to 12.
    pub(crate) fn inverse(
        &mut self,
        y: &[u8],
        on_round: &mut dyn FnMut(u32) -> ControlFlow<()>,
    ) -> Result<Secret, Error> {
        let mut space = Workspace::new(self.geometry, y);
        for (step, round) in (1..).zip((0..ROUNDS).rev()) {
            if on_round(step).is_break() {
                return Err(Error::Cancelled);
            }
            // R_i = L_{i+1}, so the mask comes from the left half; then L_i = R_{i+1} XOR M_i: the
            // right half takes the mask.
            self.round(&mut space, round, Side::Right)?;
        }
        Ok(space.into_state())
    }

    /// One round in place, in either direction: the `masked` half takes `RoundMask(i, R)` of the
    /// other half, then the two trade places.
    fn round(&mut self, space: &mut Workspace, round: u32, masked: Side) -> Result<(), Error> {
        stack::cleared(|| {
            let geometry = space.geometry;
            let Parts {
                left,
                right,
                message,
                salt,
                key,
                mask,
            } = space.parts();
            let (target, source) = match masked {
                Side::Left => (left, right),
                Side::Right => (right, left),
            };
            write_message(message, geometry, self.work, round, source);
            round_salt(geometry, message, salt);
            self.engine.argon2id(
                self.password.as_bytes(),
                salt,
                self.work.memory_kib(),
                self.work.passes(),
                key,
            )?;
            round_mask(geometry, key, message, mask);
            for (byte, mask_byte) in target.iter_mut().zip(mask.iter()) {
                *byte ^= mask_byte;
            }
            target.swap_with_slice(source);
            Ok(())
        })
    }
}

/// The half of the state that takes a round's mask: the left one going forward, the right one
/// going back.
#[derive(Clone, Copy)]
enum Side {
    Left,
    Right,
}

/// The secret memory of one permutation: both halves, then the message, salt, key and mask of the
/// round.
struct Workspace {
    secret: Secret,
    geometry: Geometry,
}

/// The parts of a [`Workspace`].
struct Parts<'a> {
    left: &'a mut [u8],
    right: &'a mut [u8],
    message: &'a mut [u8],
    salt: &'a mut [u8; SALT_BYTES],
    key: &'a mut [u8; KEY_BYTES],
    mask: &'a mut [u8],
}

impl Workspace {
    /// A workspace whose halves are `L_0 || R_0 = state`.
    fn new(geometry: Geometry, state: &[u8]) -> Self {
        let halves = 2 * geometry.half_bytes;
        let mut secret = Secret::zeroed(
            halves + geometry.message_bytes() + SALT_BYTES + KEY_BYTES + geometry.half_bytes,
        );
        secret.as_mut_bytes()[..halves].copy_from_slice(state);
        Self { secret, geometry }
    }

    #[expect(
        clippy::expect_used,
        reason = "`new` sized the workspace for every part"
    )]
    fn parts(&mut self) -> Parts<'_> {
        let half = self.geometry.half_bytes;
        let (left, rest) = self.secret.as_mut_bytes().split_at_mut(half);
        let (right, rest) = rest.split_at_mut(half);
        let (message, rest) = rest.split_at_mut(self.geometry.message_bytes());
        let (salt, rest) = rest.split_first_chunk_mut().expect("room for the salt");
        let (key, mask) = rest.split_first_chunk_mut().expect("room for the key");
        Parts {
            left,
            right,
            message,
            salt,
            key,
            mask,
        }
    }

    /// The state `L || R` alone, in the same secret: the rest is wiped.
    fn into_state(mut self) -> Secret {
        self.secret.truncate(2 * self.geometry.half_bytes);
        self.secret
    }
}

/// Writes `BE32(MEM) || BE32(PIM) || [BE32(ENT)] || BE32(i) || R`, the message that follows the
/// salt domain in `D_i` and the mask domain in `D'_i`.
fn write_message(
    message: &mut [u8],
    geometry: Geometry,
    work: WorkFactor,
    round: u32,
    right: &[u8],
) {
    let settings = [
        Some(work.memory_level()),
        Some(work.pim()),
        geometry.entropy_bits,
        Some(round),
    ];
    let mut at = 0;
    for value in settings.into_iter().flatten() {
        message[at..at + BE32_BYTES].copy_from_slice(&value.to_be_bytes());
        at += BE32_BYTES;
    }
    message[at..].copy_from_slice(right);
}

/// `S_i = Trunc_128(BLAKE2b-256(DS_SALT || message))`.
fn round_salt(geometry: Geometry, message: &[u8], salt: &mut [u8; SALT_BYTES]) {
    let mut digest = Blake2b256::new()
        .chain_update(geometry.ds_salt)
        .chain_update(message)
        .finalize();
    salt.copy_from_slice(&digest[..SALT_BYTES]);
    digest.as_mut_slice().zeroize();
}

/// `M_i = Trunc_h(HMAC-SHA-256(K_i, DS_MASK || message))`, as long as one half.
fn round_mask(geometry: Geometry, key: &[u8; KEY_BYTES], message: &[u8], mask: &mut [u8]) {
    // HMAC pads a key shorter than the block with zeros, so `K_i` padded to the block is the same
    // key, and of the fixed size that needs no fallible constructor.
    let mut block = [0u8; HMAC_KEY_BYTES];
    block[..KEY_BYTES].copy_from_slice(key);
    let mut mac = <HmacSha256 as KeyInit>::new((&block).into());
    block.zeroize();
    mac.update(geometry.ds_mask);
    mac.update(message);
    let mut digest = mac.finalize().into_bytes();
    mask.copy_from_slice(&digest[..mask.len()]);
    digest.as_mut_slice().zeroize();
}

#[cfg(test)]
mod tests {
    // The transcripts and the ENT-separation cases are replayed here, not in tests/ (RUST-08):
    // each round is compared with values the public API hides, its message, salt, key, mask and
    // halves.

    use super::*;
    use crate::test_support::{
        HashEngine, RecordedKeys, SUITE_4_VALIDATION, TRANSCRIPTS, every_permutation_round,
        fixture, hex, number, password, text,
    };

    fn permutation<'a>(engine: &'a mut HashEngine, password: &'a Password) -> Permutation<'a> {
        Permutation {
            engine,
            password,
            work: WorkFactor::default(),
            geometry: Geometry::of(Suite::TwentyFourWords, 12),
        }
    }

    #[test]
    fn inverse_undoes_forward() {
        let password = password();
        let mut engine = HashEngine;
        let mut permutation = permutation(&mut engine, &password);
        let x: [u8; STATE_BYTES] = std::array::from_fn(|index| index as u8);
        let y = permutation
            .forward(&x, &mut every_permutation_round)
            .unwrap();
        assert_ne!(y.as_bytes(), x);
        let back = permutation
            .inverse(y.as_bytes(), &mut every_permutation_round)
            .unwrap();
        assert_eq!(back.as_bytes(), x);
    }

    /// Both halves, the message of each round, which holds R through its Argon2id call, and the
    /// result are held in one secret: until the rounds have mixed it, the state is the phrase in
    /// all but form.
    #[test]
    fn the_state_and_the_round_values_are_held_in_secret_memory() {
        let password = password();
        let mut engine = HashEngine;
        let mut permutation = permutation(&mut engine, &password);
        let x = [7u8; STATE_BYTES];
        let mut space = Workspace::new(permutation.geometry, &x);
        assert_eq!(space.secret.is_locked(), cfg!(any(unix, windows)));
        permutation.round(&mut space, 0, Side::Left).unwrap();
        let state = space.into_state();
        assert_eq!(state.as_bytes()[..16], x[16..], "the halves traded places");
        let y = permutation
            .forward(&x, &mut every_permutation_round)
            .unwrap();
        assert_eq!(y.is_locked(), cfg!(any(unix, windows)));
    }

    #[test]
    fn the_callback_counts_rounds_and_can_stop_before_one() {
        let password = password();
        let mut engine = HashEngine;
        for forward in [true, false] {
            let mut seen = Vec::new();
            let mut on_round = |round| {
                seen.push(round);
                if round == 4 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            };
            let mut permutation = permutation(&mut engine, &password);
            let result = if forward {
                permutation.forward(&[7u8; STATE_BYTES], &mut on_round)
            } else {
                permutation.inverse(&[7u8; STATE_BYTES], &mut on_round)
            };
            assert_eq!(result.unwrap_err(), Error::Cancelled);
            assert_eq!(seen, [1, 2, 3, 4]);
        }
    }

    #[test]
    fn salt_and_mask_messages_bind_both_settings_and_the_round() {
        let geometry = Geometry::of(Suite::TwentyFourWords, 12);
        let right = [9u8; STATE_BYTES / 2];
        let key = [5u8; KEY_BYTES];
        let message = |work, round| {
            let mut message = vec![0; geometry.message_bytes()];
            write_message(&mut message, geometry, work, round, &right);
            message
        };
        let salt = |work, round| {
            let mut salt = [0; SALT_BYTES];
            round_salt(geometry, &message(work, round), &mut salt);
            salt
        };
        let mask = |work, round| {
            let mut mask = [0; STATE_BYTES / 2];
            round_mask(geometry, &key, &message(work, round), &mut mask);
            mask
        };
        let default = WorkFactor::default();
        let other_pim = WorkFactor::new(1, 0).unwrap();
        let other_memory = WorkFactor::new(0, 1).unwrap();
        for work in [other_pim, other_memory] {
            assert_ne!(salt(work, 0), salt(default, 0));
            assert_ne!(mask(work, 0), mask(default, 0));
        }
        assert_ne!(salt(default, 1), salt(default, 0));

        let written = message(WorkFactor::new(0x0102, 3).unwrap(), 0x0a);
        assert_eq!(written[..12], [0, 0, 0, 3, 0, 0, 1, 2, 0, 0, 0, 0x0a]);
        assert_eq!(written[12..], right);
    }

    #[test]
    fn same_length_rounds_carry_the_entropy_size_and_their_own_domain() {
        let work = WorkFactor::new(0x0102, 3).unwrap();
        for (words, half) in [(12, 8), (15, 10), (18, 12), (21, 14)] {
            let geometry = Geometry::of(Suite::SameLength, words);
            assert_eq!(geometry.half_bytes, half);
            let right = vec![9u8; half];
            let mut message = vec![0; geometry.message_bytes()];
            write_message(&mut message, geometry, work, 0x0a, &right);
            let bits = (8 * entropy_of_words(words) as u32).to_be_bytes();
            assert_eq!(message[..8], [0, 0, 0, 3, 0, 0, 1, 2]);
            assert_eq!(message[8..12], bits);
            assert_eq!(message[12..16], [0, 0, 0, 0x0a]);
            assert_eq!(message[16..], right[..]);
        }
        // Another suite gives another salt for the same half.
        let right = [9u8; 8];
        let salt_of = |geometry: Geometry| {
            let mut message = vec![0; geometry.message_bytes()];
            write_message(&mut message, geometry, work, 0, &right);
            let mut salt = [0; SALT_BYTES];
            round_salt(geometry, &message, &mut salt);
            salt
        };
        assert_ne!(
            salt_of(Geometry::of(Suite::SameLength, 12)),
            salt_of(Geometry {
                half_bytes: 8,
                ..Geometry::of(Suite::TwentyFourWords, 12)
            })
        );
    }

    #[test]
    fn same_length_inverse_undoes_forward_for_every_length() {
        let password = password();
        for words in [12, 15, 18, 21] {
            let mut engine = HashEngine;
            let mut permutation = Permutation {
                engine: &mut engine,
                password: &password,
                work: WorkFactor::default(),
                geometry: Geometry::of(Suite::SameLength, words),
            };
            let x: Vec<u8> = (0..entropy_of_words(words))
                .map(|index| index as u8)
                .collect();
            let y = permutation
                .forward(&x, &mut every_permutation_round)
                .unwrap();
            assert_eq!(y.as_bytes().len(), x.len());
            assert_ne!(y.as_bytes(), x);
            let back = permutation
                .inverse(y.as_bytes(), &mut every_permutation_round)
                .unwrap();
            assert_eq!(back.as_bytes(), x);
        }
    }

    /// `BE32(ENT)` follows the settings in every suite 4 round message of the shared cases, so the
    /// same settings, round and leading half bytes give another salt and mask for each entropy
    /// size.
    #[test]
    fn suite_4_round_messages_carry_the_entropy_size() {
        let cases = fixture(SUITE_4_VALIDATION);
        assert_eq!(text(&cases, "suite_id"), Suite::SameLength.id());
        for case in cases["ent_separation"].as_array().unwrap() {
            let id = text(case, "id");
            let words = number(case, "words") as usize;
            let geometry = Geometry::of(Suite::SameLength, words);
            assert_eq!(
                geometry.entropy_bits,
                Some(number(case, "entropy_bits")),
                "{id}"
            );
            let work = WorkFactor::new(number(case, "pim"), number(case, "memory_level")).unwrap();
            let half = hex(text(case, "half_hex"));
            let mut message = vec![0; geometry.message_bytes()];
            write_message(&mut message, geometry, work, number(case, "round"), &half);
            let salt_input = [geometry.ds_salt, &message].concat();
            assert_eq!(salt_input, hex(text(case, "salt_input_hex")), "{id}");
            let mut salt = [0; SALT_BYTES];
            round_salt(geometry, &message, &mut salt);
            assert_eq!(salt[..], hex(text(case, "salt_hex")), "{id}");
            let key: [u8; KEY_BYTES] = hex(text(case, "key_hex")).try_into().unwrap();
            let mask_input = [geometry.ds_mask, &message].concat();
            assert_eq!(mask_input, hex(text(case, "mask_input_hex")), "{id}");
            let mut mask = vec![0; geometry.half_bytes];
            round_mask(geometry, &key, &message, &mut mask);
            assert_eq!(mask, hex(text(case, "mask_hex")), "{id}");
        }
    }

    /// Every round of every transcript of both suites, in both directions, against its recorded
    /// message, salt, key, mask and halves, with an engine that answers each recorded salt with its
    /// recorded key; then each whole direction against its recorded result.
    #[test]
    fn every_round_of_every_transcript_replays_in_both_directions() {
        for json in TRANSCRIPTS {
            let transcript = fixture(json);
            let name = text(&transcript, "name");
            let inputs = &transcript["inputs"];
            let password = Password::new(text(inputs, "password")).unwrap();
            let encoded = hex(text(inputs, "password_nfkd_utf8_hex"));
            assert_eq!(password.as_bytes(), encoded, "{name}");
            let work = WorkFactor::new(number(inputs, "pim"), number(inputs, "memory_level"));
            let (suite, layout) = if text(&transcript, "suite_id") == Suite::SameLength.id() {
                (Suite::SameLength, "state")
            } else {
                (Suite::TwentyFourWords, "packing")
            };
            let words = number(&transcript[layout], "words") as usize;
            let mut engine = RecordedKeys::of(&transcript);
            let mut permutation = Permutation {
                engine: &mut engine,
                password: &password,
                work: work.unwrap(),
                geometry: Geometry::of(suite, words),
            };
            for (direction, masked) in [("encryption", Side::Left), ("decryption", Side::Right)] {
                let record = &transcript[direction];
                for round in record["rounds"].as_array().unwrap() {
                    replay_round(&mut permutation, round, masked, name);
                }
                let input = hex(text(record, "input_state_hex"));
                let output = match masked {
                    Side::Left => permutation.forward(&input, &mut every_permutation_round),
                    Side::Right => permutation.inverse(&input, &mut every_permutation_round),
                };
                let expected = hex(text(record, "output_state_hex"));
                assert_eq!(output.unwrap().as_bytes(), expected, "{name} {direction}");
            }
        }
    }

    fn replay_round(
        permutation: &mut Permutation<'_>,
        round: &serde_json::Value,
        masked: Side,
        name: &str,
    ) {
        let index = number(round, "round");
        let before = [
            hex(text(round, "left_before_hex")),
            hex(text(round, "right_before_hex")),
        ]
        .concat();
        let geometry = permutation.geometry;
        let mut space = Workspace::new(geometry, &before);
        permutation.round(&mut space, index, masked).unwrap();
        let parts = space.parts();
        let recorded = |field| hex(text(round, field));
        let context = format!("{name} round {index}");
        let salt_input = [geometry.ds_salt, parts.message].concat();
        assert_eq!(salt_input, recorded("salt_input_hex"), "{context}");
        let mask_input = [geometry.ds_mask, parts.message].concat();
        assert_eq!(mask_input, recorded("mask_input_hex"), "{context}");
        assert_eq!(parts.salt[..], recorded("salt_hex"), "{context}");
        assert_eq!(parts.key[..], recorded("argon2_key_hex"), "{context}");
        assert_eq!(parts.mask, recorded("mask_hex"), "{context}");
        assert_eq!(parts.left, recorded("left_after_hex"), "{context}");
        assert_eq!(parts.right, recorded("right_after_hex"), "{context}");
    }
}
