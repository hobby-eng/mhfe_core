//! What a recovery gives (specification: "Recovering a mnemonic", its length rules, and the
//! recovery of suite 4).

use std::fmt;

use crate::packing::{self, STATE_WORDS};
use crate::phrase::WORD_COUNTS;
use crate::protect::Secret;
use crate::{Error, Phrase, Suite, stack};

/// The recovered state `X` of a container, which [`Recovery::readings`] reads under the length
/// rules as often as needed without new rounds, as a rehearsal or a re-encryption does.
pub struct Recovery {
    suite: Suite,
    container_words: usize,
    state: Secret,
    /// The 12- to 21-word lengths whose verifier `X` passes, ascending.
    detected: Vec<usize>,
}

impl Recovery {
    /// The recovery of a container of `suite` whose state is `state`.
    pub(crate) fn new(suite: Suite, state: Secret) -> Self {
        let (container_words, detected) = match suite {
            Suite::TwentyFourWords => (STATE_WORDS, packing::detected_lengths(state.as_bytes())),
            // Suite 3's packing and its length detection do not apply to suite 4.
            Suite::SameLength => (
                packing::words_of_entropy(state.as_bytes().len()),
                Vec::new(),
            ),
        };
        Self {
            suite,
            container_words,
            state,
            detected,
        }
    }

    /// The suite of the container, which its word count selected.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The 12- to 21-word lengths whose verifier matched, ascending; empty in suite 4. When a
    /// stated length is among several, its reading comes alone and these name the others.
    pub fn detected_lengths(&self) -> &[usize] {
        &self.detected
    }

    /// The readings of the length rules for `stated_words`, in their order, without new rounds.
    /// A suite 4 container gives one, of its own length. In suite 3, without a stated length: the
    /// one length that matches, else each length that matches and then the 24-word reading. A
    /// stated length that matches gives its reading alone; a short one that does not is set aside
    /// when others match, and 24 stated words add the 24-word reading after the short ones.
    /// Errors: [`Error::InvalidWordCount`] and [`Error::LengthNotAdmitted`] for `stated_words`
    /// against the container, [`Error::VerifierMismatch`] for a short length stated when nothing
    /// matches: no reading.
    pub fn readings(&self, stated_words: Option<usize>) -> Result<Vec<Reading>, Error> {
        stack::cleared(|| {
            admit(self.container_words, stated_words)?;
            let lengths = match self.suite {
                Suite::TwentyFourWords => lengths(stated_words, &self.detected)?,
                Suite::SameLength => vec![self.container_words],
            };
            lengths
                .into_iter()
                .map(|words| {
                    Ok(Reading {
                        // In suite 4 the state is the entropy whole, with no verifier to compare.
                        phrase: Phrase::encode(packing::unpack(self.state.as_bytes(), words)?)?,
                        verified: self.detected.contains(&words),
                    })
                })
                .collect()
        })
    }
}

impl fmt::Debug for Recovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Recovery(hidden)")
    }
}

/// One reading of a recovery: a phrase and whether its verifier matched. Every 24-word reading
/// must also go through the wallet check, [`crate::wallet_check::Seed`], with the BIP39 passphrase
/// the user gives or the empty one: the container does not show whether the phrase was drawn to
/// pass it.
pub struct Reading {
    phrase: Phrase,
    verified: bool,
}

impl Reading {
    /// The phrase, with its BIP39 checksum and word count.
    pub fn phrase(&self) -> &Phrase {
        &self.phrase
    }

    /// The phrase alone, for a host that keeps it.
    pub fn into_phrase(self) -> Phrase {
        self.phrase
    }

    /// Whether the verifier of its length matched: never for 24 words or suite 4, which have none.
    /// A match is never a confirmation of the wallet: only a reference the user supplies, such as
    /// a receiving address, identifies it.
    pub fn is_verified(&self) -> bool {
        self.verified
    }
}

impl fmt::Debug for Reading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Reading(hidden)")
    }
}

/// Whether a length stated with a container of `container_words` words admits it: a 24-word
/// container admits every phrase length, a suite 4 container its own only. Errors:
/// [`Error::InvalidWordCount`], [`Error::LengthNotAdmitted`].
pub(crate) fn admit(container_words: usize, stated: Option<usize>) -> Result<(), Error> {
    match stated {
        Some(words) if !WORD_COUNTS.contains(&words) => Err(Error::InvalidWordCount { words }),
        Some(words) if container_words != STATE_WORDS && words != container_words => {
            Err(Error::LengthNotAdmitted { container_words })
        }
        _ => Ok(()),
    }
}

/// The length rules of suite 3: the word counts of the readings for `stated`, when `detected` are
/// the lengths that match, in their order.
fn lengths(stated: Option<usize>, detected: &[usize]) -> Result<Vec<usize>, Error> {
    match (stated, detected) {
        // A stated length that matches is the result, also among others that match by chance.
        (Some(words), _) if detected.contains(&words) => Ok(vec![words]),
        // Nothing matches: the 24-word reading, unless a short length was stated, whose verifier
        // then fails: a wrong password or setting, or a 24-word phrase.
        (None | Some(STATE_WORDS), []) => Ok(vec![STATE_WORDS]),
        (Some(_), []) => Err(Error::VerifierMismatch),
        // One length matches, with none stated or another short one stated.
        (None, [words]) => Ok(vec![*words]),
        (Some(stated), [words]) if stated != STATE_WORDS => Ok(vec![*words]),
        // Several match, or one beside 24 stated words, which pass a short verifier by chance
        // about once in 2^32: every reading, the matching ones first and the 24-word one last.
        _ => Ok(detected.iter().copied().chain([STATE_WORDS]).collect()),
    }
}

#[cfg(test)]
mod tests {
    // The corpus's ambiguous states are replayed here, not in tests/ (RUST-08): each is made the
    // state `X` of a container through the permutation, which the public API hides.

    use super::*;
    use crate::feistel::{Geometry, Permutation};
    use crate::test_support::{
        HashEngine, SUITE_3_VALIDATION, every_permutation_round, every_round, fixture, hex,
        password, text,
    };
    use crate::{Mhfe, WorkFactor};

    /// The recovery of a 24-word container whose state is `x`, made and recovered under a hash
    /// engine: `x` need not be the packing of a phrase.
    fn recovery_of(x: &[u8]) -> Recovery {
        let password = password();
        let y = Permutation {
            engine: &mut HashEngine,
            password: &password,
            work: WorkFactor::default(),
            geometry: Geometry::of(Suite::TwentyFourWords, STATE_WORDS),
        }
        .forward(x, &mut every_permutation_round)
        .unwrap();
        let container = Phrase::from_entropy(y.as_bytes()).unwrap();
        Mhfe::with_engine(WorkFactor::default(), HashEngine)
            .decrypt(&container, &password, None, None, &mut every_round)
            .unwrap()
    }

    /// The words and the verifier match of each reading, which must be the reading of `x` at its
    /// length.
    fn shape(readings: &[Reading], x: &[u8]) -> Vec<(usize, bool)> {
        readings
            .iter()
            .map(|reading| {
                let words = reading.phrase().words();
                let entropy = &x[..packing::entropy_of_words(words)];
                assert_eq!(
                    reading.phrase().as_str(),
                    Phrase::from_entropy(entropy).unwrap().as_str()
                );
                (words, reading.is_verified())
            })
            .collect()
    }

    /// A short original's state: its own length matches.
    fn short_state() -> Vec<u8> {
        packing::pack(&[0x5a; 16]).as_bytes().to_vec()
    }

    /// A 24-word original's state: no short length matches.
    fn full_state() -> Vec<u8> {
        vec![0x7f; packing::STATE_BYTES]
    }

    /// The shared states whose verifier two short lengths pass, with those lengths.
    fn ambiguous_states() -> Vec<(Vec<u8>, [usize; 2])> {
        let cases = fixture(SUITE_3_VALIDATION);
        let states: Vec<_> = cases["length_detection"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| text(case, "id").starts_with("ambiguous"))
            .map(|case| {
                let lengths = &case["matching_short_lengths"];
                let length = |at: usize| lengths[at].as_u64().unwrap() as usize;
                (hex(text(case, "state_hex")), [length(0), length(1)])
            })
            .collect();
        assert_eq!(states.len(), 3);
        states
    }

    #[test]
    fn without_a_stated_length_the_one_match_is_the_reading() {
        let x = short_state();
        let recovery = recovery_of(&x);
        assert_eq!(recovery.detected_lengths(), [12]);
        assert_eq!(shape(&recovery.readings(None).unwrap(), &x), [(12, true)]);
    }

    #[test]
    fn without_a_stated_length_several_matches_give_each_reading_and_then_the_24_word_one() {
        for (x, [short, long]) in ambiguous_states() {
            let recovery = recovery_of(&x);
            assert_eq!(recovery.detected_lengths(), [short, long]);
            let readings = recovery.readings(None).unwrap();
            assert_eq!(
                shape(&readings, &x),
                [(short, true), (long, true), (24, false)]
            );
        }
    }

    #[test]
    fn without_a_stated_length_and_no_match_the_24_word_reading_is_unverified() {
        let x = full_state();
        let recovery = recovery_of(&x);
        assert!(recovery.detected_lengths().is_empty());
        assert_eq!(shape(&recovery.readings(None).unwrap(), &x), [(24, false)]);
    }

    #[test]
    fn a_stated_length_among_several_matches_gives_its_reading_and_names_the_others() {
        for (x, [short, long]) in ambiguous_states() {
            let recovery = recovery_of(&x);
            for (stated, other) in [(short, long), (long, short)] {
                let readings = recovery.readings(Some(stated)).unwrap();
                assert_eq!(shape(&readings, &x), [(stated, true)]);
                assert!(recovery.detected_lengths().contains(&other));
            }
        }
    }

    #[test]
    fn a_short_length_stated_that_fails_beside_one_match_gives_that_reading() {
        let x = short_state();
        let recovery = recovery_of(&x);
        for stated in [15, 18, 21] {
            let readings = recovery.readings(Some(stated)).unwrap();
            assert_eq!(shape(&readings, &x), [(12, true)], "{stated}");
        }
    }

    #[test]
    fn a_short_length_stated_that_fails_beside_several_matches_gives_every_reading() {
        for (x, [short, long]) in ambiguous_states() {
            let recovery = recovery_of(&x);
            let stated = [12, 15, 18, 21]
                .into_iter()
                .find(|words| ![short, long].contains(words))
                .unwrap();
            let readings = recovery.readings(Some(stated)).unwrap();
            assert_eq!(
                shape(&readings, &x),
                [(short, true), (long, true), (24, false)]
            );
        }
    }

    #[test]
    fn a_short_length_stated_with_no_match_gives_no_reading() {
        let recovery = recovery_of(&full_state());
        for stated in [12, 15, 18, 21] {
            assert_eq!(
                recovery.readings(Some(stated)).err(),
                Some(Error::VerifierMismatch)
            );
        }
    }

    #[test]
    fn stated_24_words_beside_a_match_give_the_short_readings_first() {
        let x = short_state();
        let readings = recovery_of(&x).readings(Some(24)).unwrap();
        assert_eq!(shape(&readings, &x), [(12, true), (24, false)]);
        for (x, [short, long]) in ambiguous_states() {
            let readings = recovery_of(&x).readings(Some(24)).unwrap();
            assert_eq!(
                shape(&readings, &x),
                [(short, true), (long, true), (24, false)]
            );
        }
    }

    #[test]
    fn stated_24_words_with_no_match_give_the_24_word_reading_alone() {
        let x = full_state();
        let readings = recovery_of(&x).readings(Some(24)).unwrap();
        assert_eq!(shape(&readings, &x), [(24, false)]);
    }

    /// A suite 4 container gives one unverified reading of its own length, which is the only
    /// length it admits.
    #[test]
    fn a_suite_4_recovery_gives_its_own_length_alone_and_unverified() {
        for words in [12, 15, 18, 21] {
            let x: Vec<u8> = (0..packing::entropy_of_words(words))
                .map(|at| at as u8)
                .collect();
            let recovery = Recovery::new(
                Suite::SameLength,
                Phrase::from_entropy(&x).unwrap().entropy(),
            );
            assert_eq!(recovery.suite(), Suite::SameLength);
            assert!(recovery.detected_lengths().is_empty());
            for stated in [None, Some(words)] {
                let readings = recovery.readings(stated).unwrap();
                assert_eq!(shape(&readings, &x), [(words, false)]);
            }
            for stated in [12, 15, 18, 21, 24]
                .into_iter()
                .filter(|&other| other != words)
            {
                assert_eq!(
                    recovery.readings(Some(stated)).err(),
                    Some(Error::LengthNotAdmitted {
                        container_words: words
                    })
                );
            }
        }
    }

    #[test]
    fn a_24_word_container_admits_every_phrase_length_and_nothing_else() {
        assert_eq!(
            admit(24, Some(13)),
            Err(Error::InvalidWordCount { words: 13 })
        );
        assert_eq!(
            admit(12, Some(0)),
            Err(Error::InvalidWordCount { words: 0 })
        );
        for words in [12, 15, 18, 21, 24] {
            assert_eq!(admit(24, Some(words)), Ok(()));
        }
        assert_eq!(admit(15, None), Ok(()));
    }

    #[test]
    fn debug_output_hides_the_recovery() {
        let recovery = recovery_of(&short_state());
        assert_eq!(format!("{recovery:?}"), "Recovery(hidden)");
        let reading = recovery.readings(None).unwrap().pop().unwrap();
        assert_eq!(format!("{reading:?}"), "Reading(hidden)");
    }
}
