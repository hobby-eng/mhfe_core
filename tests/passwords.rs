//! The password encoding through [`Password::new`]: the 30 password cases of the suite 3 corpus
//! that are text and the eight cases of the Unicode 18 corpus, `tests/spec/vectors/suite3/` and
//! `tests/spec/vectors/unicode18/`. The three cases of invalid UTF-8 are a host's: it converts its
//! bytes strictly before it calls `Password::new`. The passwords of the transcripts, the
//! non-ASCII ones among them, keep their recorded bytes in tests/suite3.rs and tests/suite4.rs.

// The whole file is test code. Saying so lets it unwrap and panic as tests do (clippy.toml), since
// clippy recognises test code by this attribute or by #[test].
#![cfg(test)]

#[path = "support/corpus.rs"]
mod corpus;

use corpus::{hex, text};
use mhfe_core::{Error, Password};
use serde_json::Value;

/// The password cases of `file` in `folder`.
fn cases(folder: &str, file: &str) -> Vec<Value> {
    corpus::read(folder, file)["passwords"]
        .as_array()
        .unwrap()
        .clone()
}

/// The bytes of a case's input.
fn input(case: &Value) -> Vec<u8> {
    match case.get("repeat_utf8_hex") {
        Some(_) => {
            hex(text(case, "repeat_utf8_hex")).repeat(corpus::number(case, "count") as usize)
        }
        None => hex(text(case, "input_utf8_hex")),
    }
}

/// Encodes `password`, the input of `case`, and compares the outcome with the recorded one: the
/// exact bytes or their length after NFKD, or the refusal.
fn encodes_as_recorded(case: &Value, password: &str) {
    let id = text(case, "id");
    let result = Password::new(password);
    let bytes = case
        .get("expected_nfkd_bytes")
        .map(|_| corpus::number(case, "expected_nfkd_bytes") as usize);
    let Some(code) = case.get("expected_error") else {
        let password = result.unwrap();
        if case.get("expected_nfkd_utf8_hex").is_some() {
            assert_eq!(
                password.as_bytes(),
                hex(text(case, "expected_nfkd_utf8_hex")),
                "{id}"
            );
        }
        if let Some(bytes) = bytes {
            assert_eq!(password.as_bytes().len(), bytes, "{id}");
        }
        return;
    };
    let expected = match code.as_str().unwrap() {
        "CONTROL_CHARACTER_IN_PASSWORD" => Error::ForbiddenCharacter,
        "UNASSIGNED_CHARACTER" => Error::UnassignedCharacter,
        "EMPTY_PASSWORD" => Error::EmptyPassword,
        "PASSWORD_TOO_LONG" => Error::PasswordTooLong {
            bytes: bytes.unwrap(),
        },
        other => panic!("{id}: unknown code {other}"),
    };
    assert_eq!(result.err(), Some(expected), "{id}");
}

#[test]
fn the_suite_3_passwords_encode_or_are_refused_as_recorded() {
    let cases = cases("spec/vectors/suite3", "validation-cases.json");
    let mut not_text = 0;
    for case in &cases {
        match String::from_utf8(input(case)) {
            Ok(password) => encodes_as_recorded(case, &password),
            Err(_) => {
                assert_eq!(text(case, "expected_error"), "INVALID_PASSWORD_UTF8");
                not_text += 1;
            }
        }
    }
    assert_eq!((cases.len(), not_text), (33, 3));
}

#[test]
fn the_unicode_18_passwords_encode_or_are_refused_as_recorded() {
    let cases = cases("spec/vectors/unicode18", "password-encoding.json");
    for case in &cases {
        encodes_as_recorded(case, &String::from_utf8(input(case)).unwrap());
    }
    assert_eq!(cases.len(), 8);
}

/// The Unicode 18 cases above, and the Unicode 18.0.0 normalization test suite that the crate's
/// NFKD tests replay.
#[test]
fn the_unicode_corpora_are_the_recorded_files() {
    assert_eq!(
        corpus::checked_files("spec/vectors/unicode18"),
        ["password-encoding.json"]
    );
    assert_eq!(
        corpus::checked_files("fixtures/unicode18-ucd"),
        ["NormalizationTest.txt"]
    );
}
