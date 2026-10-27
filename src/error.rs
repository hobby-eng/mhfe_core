//! The refusals of the suites, of their settings and of a [`crate::protect::Secret`], and
//! cancellation.

use std::fmt;

use crate::{Password, WorkFactor};

/// Why an operation of the suites stopped. A variant carries counts, positions, settings and return
/// codes only, never text that was passed in.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The password is empty.
    EmptyPassword,
    /// The password is longer than [`Password::MAX_BYTES`] after NFKD normalization.
    PasswordTooLong {
        /// Its length in bytes after normalization.
        bytes: usize,
    },
    /// The password contains a control character (General_Category Cc), U+2028 or U+2029.
    ForbiddenCharacter,
    /// The password contains a code point that Unicode 18.0.0 does not assign, a noncharacter
    /// included.
    UnassignedCharacter,
    /// The PIM is above [`WorkFactor::MAX_PIM`].
    InvalidPim {
        /// The PIM given.
        pim: u32,
    },
    /// The memory level is above [`WorkFactor::MAX_MEMORY_LEVEL`].
    InvalidMemoryLevel {
        /// The level given.
        level: u32,
    },
    /// A phrase or a stated length of another number of words than 12, 15, 18, 21 or 24.
    InvalidWordCount {
        /// The number of words.
        words: usize,
    },
    /// A token is neither a word of the English list nor the beginning, four letters or more, of
    /// exactly one.
    UnknownWord {
        /// Its place in the phrase, from 1.
        position: usize,
    },
    /// The words do not carry their BIP39 checksum.
    InvalidChecksum,
    /// Entropy of another length than 16 to 32 bytes in steps of 4.
    InvalidEntropyLength {
        /// The length given.
        bytes: usize,
    },
    /// Suite 4 was asked for a 24-word phrase; it takes 12 to 21 words.
    SameLengthNeedsShortPhrase,
    /// The length stated with a container does not admit its word count.
    LengthNotAdmitted {
        /// The words of the container.
        container_words: usize,
    },
    /// The suite stated with a container does not admit its word count.
    SuiteNotAdmitted {
        /// The words of the container.
        container_words: usize,
    },
    /// The stated short length does not pass its verifier, and no other length does.
    VerifierMismatch,
    /// The container would equal the original (`Y = X`).
    FixedPoint,
    /// The new container did not decrypt to the original: nothing was released.
    CreationCheckFailed,
    /// The memory for Argon2id could not be reserved.
    OutOfMemory,
    /// The Argon2id engine failed.
    Argon2Failed {
        /// The return value of the reference implementation, or the host engine's own code.
        code: i32,
    },
    /// A callback stopped the operation.
    Cancelled,
    /// A [`crate::protect::Secret`] has no room for the bytes pushed; nothing was written.
    SecretFull {
        /// Its capacity in bytes.
        capacity: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPassword => f.write_str("the password is empty"),
            Self::PasswordTooLong { bytes } => write!(
                f,
                "the password has {bytes} bytes after NFKD, more than {}",
                Password::MAX_BYTES
            ),
            Self::ForbiddenCharacter => {
                f.write_str("the password contains a control character, U+2028 or U+2029")
            }
            Self::UnassignedCharacter => {
                f.write_str("the password contains a code point Unicode 18.0.0 does not assign")
            }
            Self::InvalidPim { pim } => {
                write!(f, "PIM {pim} is above {}", WorkFactor::MAX_PIM)
            }
            Self::InvalidMemoryLevel { level } => write!(
                f,
                "memory level {level} is above {}",
                WorkFactor::MAX_MEMORY_LEVEL
            ),
            Self::InvalidWordCount { words } => {
                write!(f, "{words} words is not a BIP39 phrase length")
            }
            Self::UnknownWord { position } => {
                write!(f, "word {position} is not in the English BIP39 list")
            }
            Self::InvalidChecksum => f.write_str("the BIP39 checksum does not match"),
            Self::InvalidEntropyLength { bytes } => {
                write!(f, "{bytes} bytes is not a BIP39 entropy length")
            }
            Self::SameLengthNeedsShortPhrase => {
                f.write_str("suite 4 has no container for a 24-word phrase")
            }
            Self::LengthNotAdmitted { container_words } => write!(
                f,
                "the stated length does not admit a container of {container_words} words"
            ),
            Self::SuiteNotAdmitted { container_words } => write!(
                f,
                "the stated suite does not admit a container of {container_words} words"
            ),
            Self::VerifierMismatch => {
                f.write_str("no verifier passes at the stated length or any other")
            }
            Self::FixedPoint => f.write_str("the container would equal the original"),
            Self::CreationCheckFailed => {
                f.write_str("the new container did not decrypt to the original")
            }
            Self::OutOfMemory => f.write_str("the memory for Argon2id could not be reserved"),
            Self::Argon2Failed { code } => write!(f, "Argon2id failed with code {code}"),
            Self::Cancelled => f.write_str("the operation was cancelled"),
            Self::SecretFull { capacity } => {
                write!(f, "a secret buffer of {capacity} bytes is full")
            }
        }
    }
}

impl std::error::Error for Error {}
