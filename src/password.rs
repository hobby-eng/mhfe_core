//! The MHFE password, encoded as the specification requires ("Password encoding"):
//! `P_enc = UTF8(NFKD(P))`, by the Normalization Process for Stabilized Strings with the Unicode
//! 18.0.0 character database, 1 to 1024 bytes, without control characters or the line and
//! paragraph separators.

use std::fmt;

use unicode_normalization::UNICODE_VERSION;
use unicode_normalization::char::is_public_assigned;

use crate::nfkd::Nfkd;
use crate::protect::Secret;
use crate::{Error, stack};

// The specification pins the character database; the dependency's requirement keeps it, and this
// stops a build that would resolve another one.
const _: () = assert!(
    UNICODE_VERSION.0 == 18 && UNICODE_VERSION.1 == 0 && UNICODE_VERSION.2 == 0,
    "passwords need the Unicode 18.0.0 tables"
);

/// The encoded password `P_enc`, as every Argon2id call of an operation receives it.
pub struct Password {
    encoded: Secret,
}

impl Password {
    /// The longest `P_enc`, in bytes.
    pub const MAX_BYTES: usize = 1024;

    /// Encodes `text`, the password as typed, without case folding, trimming or any other change.
    /// Errors, in this order: [`Error::ForbiddenCharacter`], [`Error::UnassignedCharacter`],
    /// [`Error::EmptyPassword`], [`Error::PasswordTooLong`]; a password is never truncated, and one
    /// that is too long is refused before it is written.
    ///
    /// A host whose input is UTF-16 or bytes converts it strictly, an unpaired surrogate or
    /// invalid UTF-8 refused rather than replaced by U+FFFD or `?`, into a
    /// [`crate::protect::Secret`] and passes its `as_str()`: a lossy conversion gives another
    /// password.
    pub fn new(text: &str) -> Result<Self, Error> {
        stack::cleared(|| Self::encode(text))
    }

    /// `P_enc`.
    pub fn as_bytes(&self) -> &[u8] {
        self.encoded.as_bytes()
    }

    fn encode(text: &str) -> Result<Self, Error> {
        // A password is ordinary single-line text: invisible characters such as NUL or TAB, and
        // line breaks, which systems write differently, could not be typed or pasted the same way
        // everywhere. NFKD makes none of them from another character (a test checks every code
        // point), so checking the input is enough.
        if text.chars().any(is_forbidden_in_password) {
            return Err(Error::ForbiddenCharacter);
        }
        // The stabilization rule: a string with an unassigned code point is not normalized at
        // all, so that a later Unicode version cannot change what the password means.
        if !text.chars().all(is_assigned_in_unicode_18) {
            return Err(Error::UnassignedCharacter);
        }
        let nfkd = Nfkd::of(text);
        match nfkd.bytes() {
            0 => Err(Error::EmptyPassword),
            bytes if bytes > Self::MAX_BYTES => Err(Error::PasswordTooLong { bytes }),
            _ => Ok(Self {
                encoded: nfkd.write(),
            }),
        }
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(hidden)")
    }
}

/// Characters no password may contain: every control character (General_Category Cc, 65 code
/// points such as NUL, TAB, LF, CR and U+0085), U+2028 LINE SEPARATOR and U+2029 PARAGRAPH
/// SEPARATOR. `char::is_control` is exactly the Cc category.
fn is_forbidden_in_password(character: char) -> bool {
    character.is_control() || character == '\u{2028}' || character == '\u{2029}'
}

/// Whether Unicode 18.0.0 assigns `character`. `is_public_assigned` answers this except that it
/// also rejects Private Use characters, which are assigned and therefore allowed.
fn is_assigned_in_unicode_18(character: char) -> bool {
    is_public_assigned(character) || is_private_use(character)
}

/// The three Private Use areas: the one in the Basic Multilingual Plane and planes 15 and 16
/// without their last two code points, which are noncharacters.
fn is_private_use(character: char) -> bool {
    matches!(
        character,
        '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(text: &str) -> Vec<u8> {
        Password::new(text).unwrap().as_bytes().to_vec()
    }

    #[test]
    fn control_characters_and_separators_are_refused_anywhere() {
        for text in [
            "pass\nword",
            "pass\rword",
            "password\r\n",
            "\npassword",
            "a\tb",
            "a\u{0}b",
            "a\u{7f}b",
            "a\u{85}b",
            "a\u{9f}b",
            "a\u{2028}b",
            "a\u{2029}b",
        ] {
            assert_eq!(
                Password::new(text).unwrap_err(),
                Error::ForbiddenCharacter,
                "{text:?}"
            );
        }
        // Visible separators and spaces stay part of the password.
        assert_eq!(encoded("  a b\u{a0}"), "  a b ".as_bytes());
    }

    /// The refused set is General_Category Cc, 65 code points in Unicode 18, plus U+2028 and
    /// U+2029: 67 in all.
    #[test]
    fn the_refused_set_has_67_code_points() {
        let refused = (0..=0x10FFFF)
            .filter_map(char::from_u32)
            .filter(|&character| is_forbidden_in_password(character))
            .count();
        assert_eq!(refused, 67);
    }

    /// The specification checks the refused characters before normalization and relies on NFKD
    /// never producing one from another character. This checks that claim for every Unicode 18
    /// scalar value.
    #[test]
    fn normalization_never_creates_a_refused_character() {
        use unicode_normalization::UnicodeNormalization;
        for character in (0..=0x10FFFF).filter_map(char::from_u32) {
            if is_forbidden_in_password(character) {
                continue;
            }
            let decomposed: String = std::iter::once(character).nfkd().collect();
            assert!(
                !decomposed.chars().any(is_forbidden_in_password),
                "U+{:04X} decomposes to a refused character",
                u32::from(character)
            );
        }
    }

    #[test]
    fn ascii_passes_through_unchanged_with_case_and_spaces() {
        assert_eq!(encoded("public test password"), b"public test password");
        assert_eq!(encoded("  Case Matters "), b"  Case Matters ");
        assert_ne!(encoded("Password"), encoded("password"));
    }

    #[test]
    fn applies_compatibility_decomposition() {
        // Each pair: input and its NFKD form.
        let cases = [
            ("\u{FB01}", "fi"),                       // ligature fi
            ("\u{E9}", "e\u{301}"),                   // é becomes e + combining acute
            ("\u{212B}", "A\u{30A}"),                 // Angstrom sign
            ("\u{FF30}", "P"),                        // fullwidth P
            ("\u{2460}", "1"),                        // circled digit one
            ("\u{B2}", "2"),                          // superscript two
            ("\u{439}", "\u{438}\u{306}"),            // Cyrillic й
            ("\u{D55C}", "\u{1112}\u{1161}\u{11AB}"), // Hangul syllable han
            ("\u{1F510}", "\u{1F510}"),               // emoji, no decomposition
        ];
        for (input, expected) in cases {
            assert_eq!(encoded(input), expected.as_bytes(), "{input:?}");
        }
    }

    #[test]
    fn accepts_private_use_characters_unchanged() {
        for character in [
            '\u{E000}',
            '\u{F8FF}',
            '\u{F0000}',
            '\u{FFFFD}',
            '\u{100000}',
            '\u{10FFFD}',
        ] {
            let text = character.to_string();
            assert_eq!(encoded(&text), text.as_bytes(), "{character:?}");
        }
    }

    #[test]
    fn rejects_unassigned_code_points_and_noncharacters() {
        let unassigned = ['\u{378}', '\u{E0080}', '\u{50000}'];
        let noncharacters = [
            '\u{FDD0}',
            '\u{FDEF}',
            '\u{FFFE}',
            '\u{FFFF}',
            '\u{1FFFF}',
            '\u{10FFFF}',
        ];
        for character in unassigned.into_iter().chain(noncharacters) {
            let text = format!("valid{character}");
            assert_eq!(
                Password::new(&text).unwrap_err(),
                Error::UnassignedCharacter,
                "{character:?}"
            );
        }
    }

    #[test]
    fn length_limit_applies_after_normalization() {
        assert_eq!(Password::new("").unwrap_err(), Error::EmptyPassword);
        assert_eq!(encoded(&"a".repeat(1024)).len(), 1024);
        assert_eq!(
            Password::new(&"a".repeat(1025)).unwrap_err(),
            Error::PasswordTooLong { bytes: 1025 }
        );
        assert_eq!(
            Password::new(&"\u{44F}".repeat(513)).unwrap_err(), // я, two bytes each
            Error::PasswordTooLong { bytes: 1026 }
        );

        // U+FDFA expands to 18 characters, 33 UTF-8 bytes: 31 copies fit, 32 do not.
        let expanding = "\u{FDFA}";
        assert_eq!(encoded(expanding).len(), 33);
        assert_eq!(encoded(&expanding.repeat(31)).len(), 1023);
        assert_eq!(
            Password::new(&expanding.repeat(32)).unwrap_err(),
            Error::PasswordTooLong { bytes: 1056 }
        );

        // The ligature fi shrinks from three bytes to two: 1,536 input bytes are accepted.
        assert_eq!(encoded(&"\u{FB01}".repeat(512)).len(), 1024);
    }

    #[test]
    fn refusals_come_in_their_documented_order() {
        let too_long = "a".repeat(2000);
        let cases = [
            (format!("{too_long}\u{378}\n"), Error::ForbiddenCharacter),
            (format!("{too_long}\u{378}"), Error::UnassignedCharacter),
            (too_long, Error::PasswordTooLong { bytes: 2000 }),
        ];
        for (text, refusal) in cases {
            assert_eq!(Password::new(&text).unwrap_err(), refusal);
        }
    }

    #[test]
    fn the_password_is_held_in_a_secret_of_its_own_size() {
        let password = Password::new("public test password").unwrap();
        assert_eq!(password.encoded.capacity(), 20);
        assert_eq!(password.encoded.is_locked(), cfg!(any(unix, windows)));
    }

    #[test]
    fn debug_output_hides_the_password() {
        let password = Password::new("public test password").unwrap();
        assert_eq!(format!("{password:?}"), "Password(hidden)");
    }
}
