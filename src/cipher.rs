//! Creating a container and recovering its state (specification: "Creating a container",
//! "Recovering a mnemonic" and their suite 4 forms).

use std::ops::ControlFlow;

use crate::engine::Argon2Engine;
#[cfg(not(target_arch = "wasm32"))]
use crate::engine::NativeArgon2;
use crate::feistel::{Geometry, Permutation};
use crate::packing::{self, STATE_WORDS};
use crate::recovery::{self, Recovery};
use crate::suite::ROUNDS;
use crate::{Error, Password, Phrase, Suite, WorkFactor, stack};

/// MHFE at one work factor, with the Argon2id engine that computes its rounds.
pub struct Mhfe<E: Argon2Engine> {
    work: WorkFactor,
    engine: E,
}

#[cfg(not(target_arch = "wasm32"))]
impl Mhfe<NativeArgon2> {
    /// `Mhfe::with_engine(work, NativeArgon2::new(work.memory_kib())?)`: reserves the memory of
    /// `work` once, for every round. Encode the password and check free memory first, as for
    /// [`NativeArgon2::new`]. Errors: [`Error::OutOfMemory`].
    pub fn new(work: WorkFactor) -> Result<Self, Error> {
        Ok(Self::with_engine(
            work,
            NativeArgon2::new(work.memory_kib())?,
        ))
    }
}

impl<E: Argon2Engine> Mhfe<E> {
    /// MHFE at `work` on `engine`, which gets the memory and passes of `work` with every call:
    /// the constructor where the crate has no engine of its own, as in WebAssembly.
    pub fn with_engine(work: WorkFactor, engine: E) -> Self {
        Self { work, engine }
    }

    /// The engine, such as a host's, whose own checks the host runs again after an operation.
    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// The PIM and memory level every round runs at.
    pub fn work_factor(&self) -> WorkFactor {
        self.work
    }

    /// Creation from the packing of step 2 to step 6: [`Suite::TwentyFourWords`] turns an
    /// original of 12 to 24 words into a 24-word container, [`Suite::SameLength`], which only the
    /// user's own choice selects, a 12- to 21-word original into a container of its own length.
    /// Asking for the password twice (step 1), the check of other lengths (step 2,
    /// [`Phrase::other_detected_lengths`]) and showing [`Suite::id`] are the host's.
    ///
    /// `on_round(round, 24)` comes before each of rounds 1 to 24, the last twelve those of the
    /// check of step 6. `on_unchecked(container)` comes once, after step 5 and before round 13, so
    /// that a person can write the container down, marked as not yet verified, during the check.
    /// `Break` from either stops with [`Error::Cancelled`]. Only `Ok` returns the container, after
    /// the check passed.
    ///
    /// Errors: [`Error::SameLengthNeedsShortPhrase`] before any Argon2id work, those of the engine,
    /// [`Error::FixedPoint`], [`Error::CreationCheckFailed`], [`Error::Cancelled`].
    pub fn encrypt(
        &mut self,
        original: &Phrase,
        password: &Password,
        suite: Suite,
        on_round: &mut dyn FnMut(u32, u32) -> ControlFlow<()>,
        on_unchecked: &mut dyn FnMut(&Phrase) -> ControlFlow<()>,
    ) -> Result<Phrase, Error> {
        stack::cleared(|| {
            let words = original.words();
            if suite == Suite::SameLength && words == STATE_WORDS {
                return Err(Error::SameLengthNeedsShortPhrase);
            }
            let entropy = original.entropy();
            let x = match suite {
                Suite::TwentyFourWords => packing::pack(entropy.as_bytes()),
                // Suite 4 encrypts the entropy itself: there is no room for a verifier.
                Suite::SameLength => entropy,
            };
            let y = self
                .permutation(password, suite, words)
                .forward(x.as_bytes(), &mut |round| on_round(round, 2 * ROUNDS))?;
            reject_fixed_point(x.as_bytes(), y.as_bytes())?;
            let container = Phrase::encode(y.as_bytes())?;
            if on_unchecked(&container).is_break() {
                return Err(Error::Cancelled);
            }
            // Step 6 starts from the words, decoded again, which checks their encoding as well as
            // the rounds.
            let decoded = Phrase::read_text(container.as_str())
                .ok()
                .filter(|decoded| decoded.words() == container.words())
                .ok_or(Error::CreationCheckFailed)?;
            let back = self
                .permutation(password, suite, words)
                .inverse(decoded.entropy().as_bytes(), &mut |round| {
                    on_round(ROUNDS + round, 2 * ROUNDS)
                })?;
            if back.as_bytes() == x.as_bytes() {
                Ok(container)
            } else {
                Err(Error::CreationCheckFailed)
            }
        })
    }

    /// Recovery steps 1 and 2, twelve rounds: the state `X` of `container`, whose word count
    /// selects the suite, for [`Recovery::readings`]. `stated_words` and `suite`, as the user
    /// supplied them with the container, are checked against it before any Argon2id work (the
    /// specification's admission table), so a container is never recovered under another suite.
    /// `on_round(round, 12)` comes before each round; `Break` stops with [`Error::Cancelled`].
    ///
    /// Errors, before any Argon2id work: [`Error::SuiteNotAdmitted`], then those of
    /// [`Recovery::readings`] for `stated_words`, [`Error::InvalidWordCount`] and
    /// [`Error::LengthNotAdmitted`]; then those of the engine and [`Error::Cancelled`].
    #[expect(
        clippy::expect_used,
        reason = "every word count of a phrase selects a suite"
    )]
    pub fn decrypt(
        &mut self,
        container: &Phrase,
        password: &Password,
        stated_words: Option<usize>,
        suite: Option<Suite>,
        on_round: &mut dyn FnMut(u32, u32) -> ControlFlow<()>,
    ) -> Result<Recovery, Error> {
        stack::cleared(|| {
            let words = container.words();
            let selected = Suite::of_container(words).expect("a phrase has 12 to 24 words");
            if suite.is_some_and(|suite| suite != selected) {
                return Err(Error::SuiteNotAdmitted {
                    container_words: words,
                });
            }
            recovery::admit(words, stated_words)?;
            let x = self
                .permutation(password, selected, words)
                .inverse(container.entropy().as_bytes(), &mut |round| {
                    on_round(round, ROUNDS)
                })?;
            Ok(Recovery::new(selected, x))
        })
    }

    fn permutation<'a>(
        &'a mut self,
        password: &'a Password,
        suite: Suite,
        words: usize,
    ) -> Permutation<'a> {
        Permutation {
            engine: &mut self.engine,
            password,
            work: self.work,
            geometry: Geometry::of(suite, words),
        }
    }
}

/// Creation step 4: refuses `Y = X`, which a working permutation meets with probability 2^-256
/// (2^-ENT in suite 4). It stops a broken engine that returns its input from exposing the
/// original.
fn reject_fixed_point(x: &[u8], y: &[u8]) -> Result<(), Error> {
    if x == y {
        Err(Error::FixedPoint)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::test_support::{HashEngine, ZERO_12, every_round, password};

    fn zero_12() -> Phrase {
        Phrase::read(ZERO_12).unwrap()
    }

    fn unchecked(_: &Phrase) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }

    /// A phrase of `words` words whose entropy bytes all differ, another for every length.
    fn varied(words: usize) -> Phrase {
        let entropy: Vec<u8> = (0..packing::entropy_of_words(words))
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(words as u8))
            .collect();
        Phrase::from_entropy(&entropy).unwrap()
    }

    #[test]
    fn every_length_of_both_suites_recovers_its_original() {
        let password = password();
        let mut cipher = Mhfe::with_engine(WorkFactor::default(), HashEngine);
        let cases = [12, 15, 18, 21, 24]
            .map(|words| (Suite::TwentyFourWords, words))
            .into_iter()
            .chain([12, 15, 18, 21].map(|words| (Suite::SameLength, words)));
        for (suite, words) in cases {
            let original = varied(words);
            let container = cipher
                .encrypt(
                    &original,
                    &password,
                    suite,
                    &mut every_round,
                    &mut unchecked,
                )
                .unwrap();
            let expected_words = if suite == Suite::SameLength {
                words
            } else {
                24
            };
            assert_eq!(container.words(), expected_words, "{suite:?} {words}");
            assert_ne!(container.as_str(), original.as_str());
            let recovery = cipher
                .decrypt(
                    &container,
                    &password,
                    Some(words),
                    Some(suite),
                    &mut every_round,
                )
                .unwrap();
            assert_eq!(recovery.suite(), suite);
            let readings = recovery.readings(Some(words)).unwrap();
            assert_eq!(readings.len(), 1, "{suite:?} {words}");
            assert_eq!(readings[0].phrase().as_str(), original.as_str());
            // Only a short original of suite 3 carries a verifier.
            let verified = suite == Suite::TwentyFourWords && words < 24;
            assert_eq!(readings[0].is_verified(), verified, "{suite:?} {words}");
        }
    }

    /// Rounds 1 to 24, and the unchecked container between rounds 12 and 13: the one `encrypt`
    /// then returns.
    #[test]
    fn encryption_shows_its_container_between_the_two_halves_of_its_24_rounds() {
        let password = password();
        let mut cipher = Mhfe::with_engine(WorkFactor::default(), HashEngine);
        let mut rounds = Vec::new();
        let last_round = Cell::new(0);
        let mut shown = Vec::new();
        let container = cipher
            .encrypt(
                &zero_12(),
                &password,
                Suite::TwentyFourWords,
                &mut |round, of| {
                    rounds.push((round, of));
                    last_round.set(round);
                    ControlFlow::Continue(())
                },
                &mut |container| {
                    shown.push((last_round.get(), container.as_str().to_owned()));
                    ControlFlow::Continue(())
                },
            )
            .unwrap();
        let expected: Vec<(u32, u32)> = (1..=24).map(|round| (round, 24)).collect();
        assert_eq!(rounds, expected);
        assert_eq!(shown, [(12, container.as_str().to_owned())]);
    }

    #[test]
    fn refuses_a_container_equal_to_the_original() {
        let state = [7u8; packing::STATE_BYTES];
        assert_eq!(reject_fixed_point(&state, &state), Err(Error::FixedPoint));
        let mut different = state;
        different[31] ^= 1;
        assert_eq!(reject_fixed_point(&state, &different), Ok(()));
    }

    #[test]
    fn a_fault_during_encryption_is_caught_by_the_check() {
        // Fault: an engine that gives a different key on every call, as a memory error would:
        // the container then does not turn back into the original and is not returned.
        struct FlakyEngine(u8);
        impl Argon2Engine for FlakyEngine {
            fn argon2id(
                &mut self,
                password: &[u8],
                salt: &[u8; 16],
                memory_kib: u32,
                passes: u32,
                key: &mut [u8; 32],
            ) -> Result<(), Error> {
                HashEngine.argon2id(password, salt, memory_kib, passes, key)?;
                self.0 = self.0.wrapping_add(1);
                key[0] ^= self.0;
                Ok(())
            }
        }
        let password = password();
        let mut cipher = Mhfe::with_engine(WorkFactor::default(), FlakyEngine(0));
        for suite in [Suite::TwentyFourWords, Suite::SameLength] {
            let mut shown = 0;
            let result =
                cipher.encrypt(&zero_12(), &password, suite, &mut every_round, &mut |_| {
                    shown += 1;
                    ControlFlow::Continue(())
                });
            assert_eq!(result.unwrap_err(), Error::CreationCheckFailed, "{suite:?}");
            assert_eq!(shown, 1, "shown, marked as unchecked, but never released");
        }
    }

    #[test]
    fn either_callback_cancels_the_operation() {
        let password = password();
        let mut cipher = Mhfe::with_engine(WorkFactor::default(), HashEngine);
        let mut shown = false;
        let stopped_at_round_2 = cipher.encrypt(
            &zero_12(),
            &password,
            Suite::TwentyFourWords,
            &mut |round, _| {
                if round == 2 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            },
            &mut |_| {
                shown = true;
                ControlFlow::Continue(())
            },
        );
        assert_eq!(stopped_at_round_2.unwrap_err(), Error::Cancelled);
        assert!(!shown);

        let mut last_round = 0;
        let stopped_when_shown = cipher.encrypt(
            &zero_12(),
            &password,
            Suite::TwentyFourWords,
            &mut |round, _| {
                last_round = round;
                ControlFlow::Continue(())
            },
            &mut |_| ControlFlow::Break(()),
        );
        assert_eq!(stopped_when_shown.unwrap_err(), Error::Cancelled);
        assert_eq!(last_round, 12, "the check never started");

        let container = cipher
            .encrypt(
                &zero_12(),
                &password,
                Suite::TwentyFourWords,
                &mut every_round,
                &mut unchecked,
            )
            .unwrap();
        let recovery = cipher.decrypt(&container, &password, None, None, &mut |round, _| {
            if round == 5 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert_eq!(recovery.err(), Some(Error::Cancelled));
    }
}
