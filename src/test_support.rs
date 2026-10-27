//! What the unit tests share: the corpora, the JSON files of the specification's `vectors/` read
//! from its repository (the submodule `tests/spec`) and Unicode's `NormalizationTest.txt`, a
//! phrase, callbacks and stand-ins for Argon2id, and the corpus helpers of the integration tests,
//! included rather than copied.

use std::ops::ControlFlow;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::Error;
use crate::engine::{Argon2Engine, KEY_BYTES, SALT_BYTES};

#[path = "../tests/support/corpus.rs"]
mod corpus;
pub(crate) use corpus::{
    RecordedKeys, every_round, hex, number, password, text, wallet_check_prefixes,
    wallet_check_rows,
};

/// Passwords, settings, phrases, length detection and the verifier's byte order of suite 3.
pub(crate) const SUITE_3_VALIDATION: &str =
    include_str!("../tests/spec/vectors/suite3/validation-cases.json");
/// The round messages of suite 4 for each entropy size, and its refusals before Argon2id.
pub(crate) const SUITE_4_VALIDATION: &str =
    include_str!("../tests/spec/vectors/suite4/validation-cases.json");
/// Unicode 18.0.0's normalization test suite.
pub(crate) const NORMALIZATION_TEST: &str =
    include_str!("../tests/fixtures/unicode18-ucd/NormalizationTest.txt");

/// Every transcript of both suites: each round of an encryption and of its recovery.
pub(crate) const TRANSCRIPTS: [&str; 27] = [
    include_str!("../tests/spec/vectors/suite3/ambiguous-12-21.json"),
    include_str!("../tests/spec/vectors/suite3/nonzero-12.json"),
    include_str!("../tests/spec/vectors/suite3/nonzero-15.json"),
    include_str!("../tests/spec/vectors/suite3/nonzero-18.json"),
    include_str!("../tests/spec/vectors/suite3/nonzero-21.json"),
    include_str!("../tests/spec/vectors/suite3/nonzero-24.json"),
    include_str!("../tests/spec/vectors/suite3/spaces-password.json"),
    include_str!("../tests/spec/vectors/suite3/unicode-password.json"),
    include_str!("../tests/spec/vectors/suite3/zero-12.json"),
    include_str!("../tests/spec/vectors/suite3/zero-12-memory-level-1.json"),
    include_str!("../tests/spec/vectors/suite3/zero-12-pim-1.json"),
    include_str!("../tests/spec/vectors/suite3/zero-12-pim-1-memory-level-1.json"),
    include_str!("../tests/spec/vectors/suite3/zero-15.json"),
    include_str!("../tests/spec/vectors/suite3/zero-18.json"),
    include_str!("../tests/spec/vectors/suite3/zero-21.json"),
    include_str!("../tests/spec/vectors/suite3/zero-24.json"),
    include_str!("../tests/spec/vectors/suite3/zero-24-pim-1-memory-level-1.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-nonzero-12.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-nonzero-21.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-unicode-password.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-zero-12.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-zero-12-memory-level-1.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-zero-12-pim-1.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-zero-12-pim-1-memory-level-1.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-zero-15.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-zero-18.json"),
    include_str!("../tests/spec/vectors/suite4/same-length-zero-21.json"),
];

/// The 12-word phrase of zero entropy.
pub(crate) const ZERO_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                  abandon abandon abandon about";

/// An `on_round` of the permutation alone, which lets every round run.
pub(crate) fn every_permutation_round(_: u32) -> ControlFlow<()> {
    ControlFlow::Continue(())
}

pub(crate) fn fixture(json: &str) -> Value {
    serde_json::from_str(json).unwrap()
}

/// A stand-in for Argon2id in structural tests: a key that depends on the password and the salt.
pub(crate) struct HashEngine;

impl Argon2Engine for HashEngine {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        _: u32,
        _: u32,
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), Error> {
        key.copy_from_slice(&Sha256::digest([password, &salt[..]].concat()));
        Ok(())
    }
}
