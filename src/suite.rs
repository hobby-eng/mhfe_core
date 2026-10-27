//! The two suites and their two settings (specification: "Suite parameters", "Suite 4" and "Work
//! factor").

use crate::Error;
use crate::packing::{SHORT_WORD_COUNTS, STATE_WORDS};

const SUITE_3_ID: &str = "MHFE-BIP39-256-EXPERIMENTAL-3";
const SUITE_4_ID: &str = "MHFE-BIP39-LP-EXPERIMENTAL-4";
// The domain strings of the round salt and mask: the identifier, then `/ROUND-SALT` or
// `/ROUND-MASK`, without a terminating NUL.
pub(crate) const SUITE_3_DS_SALT: &[u8] = b"MHFE-BIP39-256-EXPERIMENTAL-3/ROUND-SALT";
pub(crate) const SUITE_3_DS_MASK: &[u8] = b"MHFE-BIP39-256-EXPERIMENTAL-3/ROUND-MASK";
pub(crate) const SUITE_4_DS_SALT: &[u8] = b"MHFE-BIP39-LP-EXPERIMENTAL-4/ROUND-SALT";
pub(crate) const SUITE_4_DS_MASK: &[u8] = b"MHFE-BIP39-LP-EXPERIMENTAL-4/ROUND-MASK";

/// Feistel rounds of one direction, each with one Argon2id call.
pub(crate) const ROUNDS: u32 = 12;
/// Argon2id passes at PIM 0.
const BASE_PASSES: u32 = 12;

/// The suite of a container. Suite 3 is the default for every original; suite 4 is used only when
/// the user chooses it ("Choosing the suite").
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Suite {
    /// Suite 3: every original of 12 to 24 words becomes a 24-word container. A 12- to 21-word
    /// original carries a verifier, so a wrong password is detected, and every container looks the
    /// same.
    #[default]
    TwentyFourWords,
    /// Suite 4: a 12-, 15-, 18- or 21-word original becomes a container of its own length. Nothing
    /// detects a wrong password, the container shows the original's length, and a word copied
    /// wrongly passes the shorter checksum more often.
    SameLength,
}

impl Suite {
    /// The identifier, which an application shows when it creates a container.
    pub const fn id(self) -> &'static str {
        match self {
            Self::TwentyFourWords => SUITE_3_ID,
            Self::SameLength => SUITE_4_ID,
        }
    }

    /// The suite of a container of `words` words inside the MHFE recovery workflow: 24 words are
    /// suite 3, 12 to 21 words suite 4, any other count none. The word count does not show that a
    /// phrase is a container, nor tell suite 3 from another 24-word suite.
    pub const fn of_container(words: usize) -> Option<Self> {
        if words == STATE_WORDS {
            return Some(Self::TwentyFourWords);
        }
        let mut short = 0;
        while short < SHORT_WORD_COUNTS.len() {
            if SHORT_WORD_COUNTS[short] == words {
                return Some(Self::SameLength);
            }
            short += 1;
        }
        None
    }
}

/// The two settings a user may choose: the PIM multiplies the Argon2id passes and the memory level
/// sets the Argon2id memory. Both default to 0: 12 passes and 2 GiB.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkFactor {
    pim: u32,
    memory_level: u32,
}

impl WorkFactor {
    /// The highest PIM. A factor of 1,024 already adds only ten bits while it turns a one- to
    /// two-minute recovery into roughly 17 to 34 hours.
    pub const MAX_PIM: u32 = 1023;
    /// The highest memory level. Level 22 would need 2^32 KiB, one more than Argon2 accepts.
    pub const MAX_MEMORY_LEVEL: u32 = 21;

    /// Accepts a PIM up to [`WorkFactor::MAX_PIM`] and a memory level up to
    /// [`WorkFactor::MAX_MEMORY_LEVEL`]. Errors: [`Error::InvalidPim`], then
    /// [`Error::InvalidMemoryLevel`]. Nothing is reserved: that is the engine's work.
    pub fn new(pim: u32, memory_level: u32) -> Result<Self, Error> {
        if pim > Self::MAX_PIM {
            return Err(Error::InvalidPim { pim });
        }
        if memory_level > Self::MAX_MEMORY_LEVEL {
            return Err(Error::InvalidMemoryLevel {
                level: memory_level,
            });
        }
        Ok(Self { pim, memory_level })
    }

    /// The PIM.
    pub const fn pim(self) -> u32 {
        self.pim
    }

    /// The memory level.
    pub const fn memory_level(self) -> u32 {
        self.memory_level
    }

    /// The Argon2id passes `t(PIM) = 12 * (PIM + 1)`.
    pub const fn passes(self) -> u32 {
        BASE_PASSES * (self.pim + 1)
    }

    /// The Argon2id memory `m(MEM) = (2 + MEM mod 2) * 2^(20 + floor(MEM / 2))` in KiB: 2, 3, 4,
    /// 6, 8, 12 GiB and so on, up to 3 TiB at level 21. Integers only, as the specification
    /// requires; level 21 gives 3 * 2^30, which fits a `u32`.
    pub const fn memory_kib(self) -> u32 {
        (2 + self.memory_level % 2) << (20 + self.memory_level / 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB_IN_KIB: u64 = 1 << 20;

    /// The identifiers and domain strings as the specification writes them.
    #[test]
    fn identifiers_and_domain_strings_are_the_specification_s() {
        assert_eq!(Suite::TwentyFourWords.id(), "MHFE-BIP39-256-EXPERIMENTAL-3");
        assert_eq!(Suite::SameLength.id(), "MHFE-BIP39-LP-EXPERIMENTAL-4");
        assert_eq!(SUITE_3_DS_SALT, b"MHFE-BIP39-256-EXPERIMENTAL-3/ROUND-SALT");
        assert_eq!(SUITE_3_DS_MASK, b"MHFE-BIP39-256-EXPERIMENTAL-3/ROUND-MASK");
        assert_eq!(SUITE_4_DS_SALT, b"MHFE-BIP39-LP-EXPERIMENTAL-4/ROUND-SALT");
        assert_eq!(SUITE_4_DS_MASK, b"MHFE-BIP39-LP-EXPERIMENTAL-4/ROUND-MASK");
    }

    #[test]
    fn recovery_selects_the_suite_by_word_count() {
        assert_eq!(Suite::of_container(24), Some(Suite::TwentyFourWords));
        for words in [12, 15, 18, 21] {
            assert_eq!(Suite::of_container(words), Some(Suite::SameLength));
        }
        for words in [0, 11, 13, 23, 25] {
            assert_eq!(Suite::of_container(words), None);
        }
        assert_eq!(Suite::default(), Suite::TwentyFourWords);
    }

    #[test]
    fn memory_levels_follow_the_specified_series() {
        let expected_gib = [2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64];
        for (level, gib) in (0..).zip(expected_gib) {
            let work = WorkFactor::new(0, level).unwrap();
            assert_eq!(
                u64::from(work.memory_kib()),
                gib * GIB_IN_KIB,
                "level {level}"
            );
        }
        let highest = WorkFactor::new(0, WorkFactor::MAX_MEMORY_LEVEL).unwrap();
        assert_eq!(
            u64::from(highest.memory_kib()),
            3 * (1 << 30),
            "3 TiB at level 21"
        );
    }

    #[test]
    fn passes_grow_with_the_pim() {
        assert_eq!(WorkFactor::default().passes(), 12);
        assert_eq!(WorkFactor::new(1, 0).unwrap().passes(), 24);
        assert_eq!(
            WorkFactor::new(WorkFactor::MAX_PIM, 0).unwrap().passes(),
            12 * 1024
        );
    }

    #[test]
    fn out_of_range_settings_are_rejected() {
        assert_eq!(
            WorkFactor::new(1024, 0),
            Err(Error::InvalidPim { pim: 1024 })
        );
        assert_eq!(
            WorkFactor::new(0, 22),
            Err(Error::InvalidMemoryLevel { level: 22 })
        );
        assert_eq!(
            WorkFactor::new(u32::MAX, u32::MAX),
            Err(Error::InvalidPim { pim: u32::MAX })
        );
    }
}
