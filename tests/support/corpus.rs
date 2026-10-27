//! What the corpus tests share: the corpora, the specification's vectors read from its repository
//! (the submodule `tests/spec`, the specification of the version this crate implements) and
//! Unicode's `NormalizationTest.txt` in `tests/fixtures/`, the Argon2id of a transcript, the
//! replay of a transcript and of a recovery case through the public API, and the rows of the
//! profile vectors' tables.
//!
//! The crate's unit tests include this file too (`src/test_support.rs`), for the field readers,
//! `hex`, `password`, `every_round`, `RecordedKeys` and the wallet-check rows.
#![allow(dead_code, reason = "each test file uses its own part")]

use std::fs;
use std::ops::ControlFlow;

use mhfe_core::{Argon2Engine, Error, Mhfe, Password, Phrase, Reading, Suite, WorkFactor};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The tests' folder: the folders the functions below take are paths from it, such as
/// `spec/vectors/suite3` for the specification's and `fixtures/unicode18-ucd` for Unicode's.
const TESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests");
/// The recovery cases beside the transcripts of a suite.
const RECOVERY_CASES: &str = "negative-cases.json";
/// The specification publishes the profile vectors only as the Markdown tables of this file.
const PROFILE_VECTORS: &str = "spec/vectors/profiles/README.md";

/// The files that the `SHA256SUMS` of `folder` lists, each checked against its SHA-256 first.
pub(crate) fn checked_files(folder: &str) -> Vec<String> {
    let sums = fs::read_to_string(format!("{TESTS}/{folder}/SHA256SUMS")).unwrap();
    sums.lines()
        .map(|line| {
            let (digest, name) = line.split_once("  ").expect("a sha256sum line");
            let bytes = fs::read(format!("{TESTS}/{folder}/{name}")).unwrap();
            assert_eq!(Sha256::digest(&bytes)[..], hex(digest), "{folder}/{name}");
            name.to_owned()
        })
        .collect()
}

/// The JSON file `name` of `folder`.
pub(crate) fn read(folder: &str, name: &str) -> Value {
    let path = format!("{TESTS}/{folder}/{name}");
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

/// The version the specification's header names in its line `Version: x.y.z`.
pub(crate) fn specification_version() -> String {
    let readme = fs::read_to_string(format!("{TESTS}/spec/README.md")).unwrap();
    readme
        .lines()
        .find_map(|line| line.trim().strip_prefix("Version: "))
        .expect("a version line in the specification's header")
        .to_owned()
}

/// The rows of the table in the section of the profile vectors whose heading ends with `profile`,
/// such as `MHFE-REPAIR-1`: each row's cells, trimmed, without the header row and its rule.
pub(crate) fn profile_table(profile: &str) -> Vec<Vec<String>> {
    let readme = fs::read_to_string(format!("{TESTS}/{PROFILE_VECTORS}")).unwrap();
    let rows: Vec<Vec<String>> = readme
        .lines()
        .skip_while(|line| !(line.starts_with("## ") && line.ends_with(profile)))
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        // The header row and the rule under it.
        .skip(2)
        .map(|row| {
            row.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_owned())
                .collect()
        })
        .collect();
    assert!(!rows.is_empty(), "no table for {profile}");
    rows
}

/// A cell's literal value, which the tables write as code: its text between the backticks.
pub(crate) fn literal(cell: &str) -> &str {
    cell.strip_prefix('`')
        .and_then(|inner| inner.strip_suffix('`'))
        .unwrap_or_else(|| panic!("{cell} is not a literal"))
}

/// The rows of MHFE-WALLET-CHECK-SEED-1: the counter, the BIP39 passphrase, which the table writes
/// as words when it is empty, and the digest `T` in hex.
pub(crate) fn wallet_check_rows() -> Vec<(u64, String, String)> {
    profile_table("MHFE-WALLET-CHECK-SEED-1")
        .iter()
        .map(|row| {
            let passphrase = match row[1].as_str() {
                "empty string" => "",
                cell => literal(cell),
            };
            (
                row[0].parse().unwrap(),
                passphrase.to_owned(),
                literal(&row[2]).to_owned(),
            )
        })
        .collect()
}

/// The digest prefixes that the text under the MHFE-WALLET-CHECK-SEED-1 table gives, in order: the
/// first row's counter with the empty passphrase, the second row's counter with `TREZOR`, and the
/// first row with `BE32(256)` left out. The text writes each as eight hex digits in backticks.
pub(crate) fn wallet_check_prefixes() -> Vec<String> {
    let readme = fs::read_to_string(format!("{TESTS}/{PROFILE_VECTORS}")).unwrap();
    let prefixes: Vec<String> = readme
        .lines()
        .skip_while(|line| !(line.starts_with("## ") && line.ends_with("MHFE-WALLET-CHECK-SEED-1")))
        .skip(1)
        .skip_while(|line| !line.starts_with('|'))
        .skip_while(|line| line.starts_with('|'))
        .take_while(|line| !line.starts_with("## "))
        .flat_map(|line| line.split('`').skip(1).step_by(2))
        .filter(|code| code.len() == 8 && code.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_owned)
        .collect();
    assert_eq!(prefixes.len(), 3, "{prefixes:?}");
    prefixes
}

/// The transcripts of `folder`: every file its `SHA256SUMS` lists, checked against it, but the
/// recovery cases.
pub(crate) fn transcripts(folder: &str) -> Vec<Value> {
    checked_files(folder)
        .iter()
        .filter(|name| *name != RECOVERY_CASES)
        .map(|name| read(folder, name))
        .collect()
}

/// The recovery cases of `folder`.
pub(crate) fn recovery_cases(folder: &str) -> Vec<Value> {
    match read(folder, RECOVERY_CASES) {
        Value::Array(cases) => cases,
        other => panic!("{folder}/{RECOVERY_CASES} is not a list: {other}"),
    }
}

pub(crate) fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("no text {field}"))
}

pub(crate) fn number(value: &Value, field: &str) -> u32 {
    u32::try_from(value[field].as_u64().unwrap()).unwrap()
}

pub(crate) fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "{text}");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// A public password, for the cases whose outcome does not depend on it.
pub(crate) fn password() -> Password {
    Password::new("public test password").unwrap()
}

/// The PIM and memory level of a transcript's inputs or of a recovery case.
pub(crate) fn work_of(record: &Value) -> WorkFactor {
    WorkFactor::new(number(record, "pim"), number(record, "memory_level")).unwrap()
}

/// An `on_round` that lets every round run.
pub(crate) fn every_round(_: u32, _: u32) -> ControlFlow<()> {
    ControlFlow::Continue(())
}

/// The password of a transcript's inputs or of a recovery case, which encodes to its recorded
/// `P_enc`.
fn password_of(record: &Value) -> Password {
    let password = Password::new(text(record, "password")).unwrap();
    assert_eq!(
        password.as_bytes(),
        hex(text(record, "password_nfkd_utf8_hex"))
    );
    password
}

/// Readings in the form the corpora record them.
fn as_recorded(readings: &[Reading]) -> Vec<Value> {
    readings
        .iter()
        .map(|reading| {
            json!({
                "words": reading.phrase().words(),
                "verified": reading.is_verified(),
                "phrase": reading.phrase().as_str(),
            })
        })
        .collect()
}

/// The Argon2id of a transcript: each recorded salt gives its recorded key, for the transcript's
/// `P_enc` and cost only.
pub(crate) struct RecordedKeys {
    password: Vec<u8>,
    memory_kib: u32,
    passes: u32,
    keys: Vec<(Vec<u8>, Vec<u8>)>,
}

impl RecordedKeys {
    pub(crate) fn of(transcript: &Value) -> Self {
        let rounds = ["encryption", "decryption"]
            .into_iter()
            .flat_map(|direction| transcript[direction]["rounds"].as_array().unwrap());
        Self {
            password: hex(text(&transcript["inputs"], "password_nfkd_utf8_hex")),
            memory_kib: number(&transcript["argon2"], "memory_kib"),
            passes: number(&transcript["argon2"], "passes"),
            keys: rounds
                .map(|round| {
                    let key = hex(text(round, "argon2_key_hex"));
                    (hex(text(round, "salt_hex")), key)
                })
                .collect(),
        }
    }

    /// The recorded key of a call, which must be one the transcript records.
    pub(crate) fn key(&self, password: &[u8], salt: &[u8], memory_kib: u32, passes: u32) -> &[u8] {
        assert_eq!(password, self.password, "P_enc");
        assert_eq!((memory_kib, passes), (self.memory_kib, self.passes), "cost");
        let (_, key) = self
            .keys
            .iter()
            .find(|(recorded, _)| recorded == salt)
            .expect("a salt of the transcript");
        key
    }
}

impl Argon2Engine for RecordedKeys {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; 16],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8; 32],
    ) -> Result<(), Error> {
        key.copy_from_slice(self.key(password, salt, memory_kib, passes));
        Ok(())
    }
}

/// An engine that must never run: a refusal must come before any Argon2id work.
pub(crate) struct NoArgon2Calls;

impl Argon2Engine for NoArgon2Calls {
    fn argon2id(
        &mut self,
        _: &[u8],
        _: &[u8; 16],
        _: u32,
        _: u32,
        _: &mut [u8; 32],
    ) -> Result<(), Error> {
        panic!("Argon2id ran where a refusal should have come first");
    }
}

/// Creates the container of `transcript` with `suite` on `engine` and recovers it: the
/// container, shown once before its check and returned after it, the suite its word count
/// selects and the readings without a stated length must be the recorded ones.
pub(crate) fn replay(transcript: &Value, suite: Suite, engine: impl Argon2Engine) {
    let name = text(transcript, "name");
    let inputs = &transcript["inputs"];
    let original = Phrase::read(text(inputs, "phrase")).unwrap();
    let password = password_of(inputs);
    let mut cipher = Mhfe::with_engine(work_of(inputs), engine);
    let mut shown = Vec::new();
    let container = cipher
        .encrypt(
            &original,
            &password,
            suite,
            &mut every_round,
            &mut |unchecked| {
                shown.push(unchecked.as_str().to_owned());
                ControlFlow::Continue(())
            },
        )
        .unwrap();
    assert_eq!(container.as_str(), text(transcript, "container"), "{name}");
    assert_eq!(shown, [container.as_str()], "{name}");

    let recovery = cipher
        .decrypt(&container, &password, None, None, &mut every_round)
        .unwrap();
    assert_eq!(recovery.suite(), suite, "{name}");
    // Suite 4 records its one reading alone, suite 3 the list the length rules give.
    let recorded = match &transcript["recovery"] {
        Value::Array(readings) => readings.clone(),
        reading => vec![reading.clone()],
    };
    let readings = as_recorded(&recovery.readings(None).unwrap());
    assert_eq!(readings, recorded, "{name}");
    let verified: Vec<usize> = recorded
        .iter()
        .filter(|reading| reading["verified"] == true)
        .map(|reading| number(reading, "words") as usize)
        .collect();
    assert_eq!(recovery.detected_lengths(), verified, "{name}");
}

/// Recovers the container of a recovery case with its password, settings and stated length on
/// `engine`: the readings, or the refusal, must be the recorded ones.
pub(crate) fn recover(case: &Value, engine: impl Argon2Engine) {
    let name = text(case, "name");
    let container = Phrase::read(text(case, "container")).unwrap();
    let password = password_of(case);
    // Zero words: no length was stated.
    let stated = Some(number(case, "words") as usize).filter(|&words| words != 0);
    let mut cipher = Mhfe::with_engine(work_of(case), engine);
    let result = cipher
        .decrypt(&container, &password, stated, None, &mut every_round)
        .and_then(|recovery| recovery.readings(stated));
    let recorded = case["recovery"].as_array().unwrap();
    let Some(code) = case["error_code"].as_str() else {
        let readings = as_recorded(&result.unwrap());
        // This case keeps the one reading of a manual mode that the length rules removed; they
        // give it last, after the 12-word reading (vectors/suite3/README.md, "Current recovery
        // expectations").
        let current = if name == "selected-24-words" {
            &readings[1..]
        } else {
            &readings[..]
        };
        assert_eq!(current, recorded, "{name}");
        return;
    };
    let expected = match code {
        "VERIFIER_MISMATCH" => Error::VerifierMismatch,
        "LENGTH_CHOICE_NOT_APPLICABLE" => Error::LengthNotAdmitted {
            container_words: container.words(),
        },
        other => panic!("{name}: unknown code {other}"),
    };
    assert_eq!(result.err(), Some(expected), "{name}");
    assert!(recorded.is_empty(), "{name}");
}

/// Recovers each case of `folder` whose keys a transcript records, with that transcript's keys:
/// the case of a transcript's container with the transcript's password and settings. The other
/// cases need Argon2id at full cost (tests/full_cost.rs). Returns how many were recovered.
pub(crate) fn recover_with_recorded_keys(folder: &str) -> usize {
    let transcripts = transcripts(folder);
    let mut recovered = 0;
    for case in recovery_cases(folder) {
        let same_inputs = |transcript: &&Value| {
            let inputs = &transcript["inputs"];
            transcript["container"] == case["container"]
                && ["password", "pim", "memory_level"]
                    .into_iter()
                    .all(|field| inputs[field] == case[field])
        };
        if let Some(transcript) = transcripts.iter().find(same_inputs) {
            recover(&case, RecordedKeys::of(transcript));
            recovered += 1;
        }
    }
    recovered
}
