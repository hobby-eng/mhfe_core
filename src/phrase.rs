//! English BIP39 phrases, read the way people write them down (specification: "Reading words").

use std::fmt;

use bip39::{Language, Mnemonic};
use zeroize::Zeroize;

use crate::packing::{self, SHORT_WORD_COUNTS, STATE_WORDS};
use crate::protect::Secret;
use crate::{Error, stack};

/// The word counts of a BIP39 phrase.
pub(crate) const WORD_COUNTS: [usize; 5] = [
    SHORT_WORD_COUNTS[0],
    SHORT_WORD_COUNTS[1],
    SHORT_WORD_COUNTS[2],
    SHORT_WORD_COUNTS[3],
    STATE_WORDS,
];
/// The longest English BIP39 word has eight letters.
const LONGEST_WORD: usize = 8;
/// The shortest typed beginning that is completed: the English list is unique in its first four
/// letters.
const PREFIX_LETTERS: usize = 4;

/// An English BIP39 phrase of 12 to 24 words with a valid checksum: every phrase that goes into or
/// comes out of an operation. Its canonical text, every word written out in lower case and one
/// space apart, lives in a [`Secret`].
pub struct Phrase {
    text: Secret,
    words: usize,
}

impl Phrase {
    /// Reads `text` as a person writes a phrase down: any whitespace between words, any letter case
    /// and words cut to four letters or more, each token as [`Phrase::read_word`] reads it. Errors,
    /// in this order: [`Error::InvalidWordCount`], [`Error::UnknownWord`] with the first token that
    /// is no word, [`Error::InvalidChecksum`].
    pub fn read(text: &str) -> Result<Self, Error> {
        stack::cleared(|| Self::read_text(text))
    }

    /// One token, ASCII letters in any case: the word of the English list it equals, else the only
    /// word it begins with four letters or more. A token longer than 8 bytes or with a byte outside
    /// ASCII is `None`: it is never copied or truncated, so `abstracts` is not `abstract`.
    pub fn read_word(token: &str) -> Option<&'static str> {
        stack::cleared(|| word_of(token))
    }

    /// The phrase of `entropy`, 16 to 32 bytes in steps of 4. Errors:
    /// [`Error::InvalidEntropyLength`].
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Error> {
        stack::cleared(|| Self::encode(entropy))
    }

    /// The canonical text: lower-case words, one space apart.
    #[expect(
        clippy::expect_used,
        reason = "the text holds words of the English list, which are ASCII"
    )]
    pub fn as_str(&self) -> &str {
        self.text
            .as_str()
            .expect("a phrase's text holds English BIP39 words")
    }

    /// The number of words.
    pub fn words(&self) -> usize {
        self.words
    }

    /// Creation step 2: the other 12- to 21-word lengths whose verifier this phrase's suite 3 state
    /// passes, ascending, which a recovery without a stated length would also give. Empty for
    /// almost every phrase, which meets it with probability about 2^-32; otherwise the owner
    /// should record the word count.
    pub fn other_detected_lengths(&self) -> Vec<usize> {
        stack::cleared(|| {
            let state = packing::pack(self.entropy().as_bytes());
            packing::detected_lengths(state.as_bytes())
                .into_iter()
                .filter(|&words| words != self.words)
                .collect()
        })
    }

    /// The entropy `E`, read from the array bip39 fills on the stack, which is wiped here.
    pub(crate) fn entropy(&self) -> Secret {
        let (mut array, bytes) = self.mnemonic().to_entropy_array();
        let mut entropy = Secret::zeroed(bytes);
        entropy.as_mut_bytes().copy_from_slice(&array[..bytes]);
        array.zeroize();
        entropy
    }

    /// The phrase as bip39 holds it, its word numbers, which bip39 wipes when it is dropped.
    #[expect(
        clippy::expect_used,
        reason = "the text is a valid phrase: Phrase::read checked it, or bip39 wrote it"
    )]
    pub(crate) fn mnemonic(&self) -> Mnemonic {
        Mnemonic::parse_in_normalized(Language::English, self.as_str())
            .expect("a phrase's text is a valid BIP39 phrase")
    }

    /// [`Phrase::from_entropy`] without its stack clear, for a public function that clears it.
    pub(crate) fn encode(entropy: &[u8]) -> Result<Self, Error> {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy).map_err(|_| {
            Error::InvalidEntropyLength {
                bytes: entropy.len(),
            }
        })?;
        Ok(Self::of_words(mnemonic.word_count(), mnemonic.words()))
    }

    /// [`Phrase::read`] without its stack clear, for a public function that clears it.
    pub(crate) fn read_text(text: &str) -> Result<Self, Error> {
        let words = text.split_whitespace().count();
        if !WORD_COUNTS.contains(&words) {
            return Err(Error::InvalidWordCount { words });
        }
        let unknown = text
            .split_whitespace()
            .position(|token| word_of(token).is_none());
        if let Some(index) = unknown {
            return Err(Error::UnknownWord {
                position: index + 1,
            });
        }
        // The count and the words are right, so the checksum is the only refusal left.
        Self::of_words(words, text.split_whitespace().filter_map(word_of)).checked()
    }

    /// The phrase of `numbers`, word numbers of the English list. Errors:
    /// [`Error::InvalidChecksum`].
    pub(crate) fn of_numbers(numbers: &[u16]) -> Result<Self, Error> {
        Self::of_words(numbers.len(), numbers.iter().map(|&number| word(number))).checked()
    }

    /// The phrase of `words` words of the list, one space apart, written into a secret of its own.
    fn of_words(words: usize, list: impl Iterator<Item = &'static str>) -> Self {
        Self {
            text: text_of(words, list),
            words,
        }
    }

    /// The phrase, if its words carry their BIP39 checksum. Errors: [`Error::InvalidChecksum`].
    fn checked(self) -> Result<Self, Error> {
        Mnemonic::parse_in_normalized(Language::English, self.as_str())
            .map_err(|_| Error::InvalidChecksum)?;
        Ok(self)
    }
}

impl fmt::Debug for Phrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Phrase(hidden)")
    }
}

/// `words` words of the English list, one space apart, written into a secret of their own.
pub(crate) fn text_of(words: usize, list: impl Iterator<Item = &'static str>) -> Secret {
    let mut text = Secret::zeroed(words * (LONGEST_WORD + 1));
    let mut end = 0;
    for word in list {
        let bytes = text.as_mut_bytes();
        if end > 0 {
            bytes[end] = b' ';
            end += 1;
        }
        bytes[end..end + word.len()].copy_from_slice(word.as_bytes());
        end += word.len();
    }
    text.truncate(end);
    text
}

/// The word of the English list with `number`, below 2,048.
pub(crate) fn word(number: u16) -> &'static str {
    Language::English.word_list()[usize::from(number)]
}

/// The number in the English list of the word that `token` is read as, by
/// [`Phrase::read_word`]'s rule.
pub(crate) fn number_of(token: &str) -> Option<u16> {
    word_of(token).and_then(|word| Language::English.find_word(word))
}

/// [`Phrase::read_word`]. The token is folded to lower case in an array on the stack, which is
/// wiped: no word of the list is longer, so a longer token begins none.
fn word_of(token: &str) -> Option<&'static str> {
    if token.len() > LONGEST_WORD || !token.is_ascii() {
        return None;
    }
    let mut folded = [0u8; LONGEST_WORD];
    let typed = &mut folded[..token.len()];
    typed.copy_from_slice(token.as_bytes());
    typed.make_ascii_lowercase();
    let word = std::str::from_utf8(typed).ok().and_then(complete);
    folded.zeroize();
    word
}

/// The word of the English list that `typed` equals, else the only one it begins, when it has
/// four letters or more. An exact word comes first: some three-letter words, such as `act`, begin
/// longer ones.
fn complete(typed: &str) -> Option<&'static str> {
    let english = Language::English;
    if let Some(number) = english.find_word(typed) {
        return Some(word(number));
    }
    if typed.len() < PREFIX_LETTERS {
        return None;
    }
    let mut candidates = english.words_by_prefix_iter(typed);
    match (candidates.next(), candidates.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    // The corpus's ambiguous states are replayed here, not in tests/ (RUST-08): they are cut into
    // phrases at the packing's sizes, which the public API hides.

    use super::*;
    use crate::test_support::{SUITE_3_VALIDATION, ZERO_12, fixture, hex, text};

    #[test]
    fn accepts_spacing_case_and_four_letter_prefixes() {
        let typed = "  ABANDON aban\tAband abandon abandon abandon abandon abandon abandon abandon \
                     abandon abou ";
        let phrase = Phrase::read(typed).unwrap();
        assert_eq!(phrase.as_str(), ZERO_12);
        assert_eq!(phrase.words(), 12);
        assert_eq!(Phrase::read_word("ABANDON"), Some("abandon"));
        assert_eq!(Phrase::read_word("Aban"), Some("abandon"));
    }

    /// A phrase's text is bip39's words for every length, in a secret of its own.
    #[test]
    fn the_text_of_a_phrase_is_its_words_for_every_length() {
        for words in WORD_COUNTS {
            // Varied public entropy, so that the phrases include words of every length.
            for seed in 0u8..64 {
                let entropy: Vec<u8> = (0..packing::entropy_of_words(words))
                    .map(|index| {
                        (index as u8)
                            .wrapping_mul(97)
                            .wrapping_add(seed.wrapping_mul(53))
                    })
                    .collect();
                let phrase = Phrase::from_entropy(&entropy).unwrap();
                let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
                assert_eq!(phrase.as_str(), mnemonic.to_string());
                assert_eq!(phrase.words(), words);
                assert_eq!(phrase.entropy().as_bytes(), entropy);
                assert_eq!(
                    Phrase::read(phrase.as_str()).unwrap().as_str(),
                    phrase.as_str()
                );
            }
        }
        // The BIP39 vector 7f…7f.
        let legal = Phrase::from_entropy(&[0x7f; 32]).unwrap();
        assert!(legal.as_str().starts_with("legal winner thank year"));
        assert_eq!(legal.text.is_locked(), cfg!(any(unix, windows)));
        for bytes in [0, 15, 17, 33] {
            assert_eq!(
                Phrase::from_entropy(&vec![0; bytes]).unwrap_err(),
                Error::InvalidEntropyLength { bytes }
            );
        }
    }

    #[test]
    fn an_exact_word_comes_before_a_prefix() {
        // "act" is a word and also begins action, actor, actress and actual.
        assert_eq!(Phrase::read_word("act"), Some("act"));
        assert_eq!(Phrase::read_word("acti"), Some("action"));
        assert_eq!(Phrase::read_word("acto"), Some("actor"));
        assert_eq!(Phrase::read_word("actr"), Some("actress"));
        assert_eq!(Phrase::read_word("actu"), Some("actual"));
        assert_eq!(Phrase::read_word("ac"), None);
    }

    #[test]
    fn four_letters_identify_every_word_and_only_three_letter_words_begin_others() {
        let words = Language::English.word_list();
        let mut first_four: Vec<&str> = words
            .iter()
            .map(|word| &word[..4.min(word.len())])
            .collect();
        first_four.sort_unstable();
        first_four.dedup();
        assert_eq!(first_four.len(), words.len());

        let prefixes: Vec<&str> = words
            .iter()
            .copied()
            .filter(|word| {
                words
                    .iter()
                    .any(|other| other != word && other.starts_with(word))
            })
            .collect();
        assert_eq!(prefixes.len(), 49);
        assert!(prefixes.iter().all(|word| word.len() == 3));
        for word in prefixes {
            assert_eq!(Phrase::read_word(word), Some(word));
        }
        assert!(words.iter().all(|word| word.len() <= LONGEST_WORD));
    }

    /// A token longer than any word, or with a byte outside ASCII, is never cut to a word.
    #[test]
    fn long_or_non_ascii_tokens_are_unknown_words() {
        // Each of the first three begins with a word of the list; the last two have eight bytes or
        // fewer, one of them outside ASCII.
        for token in [
            "abstracts",
            "accidents",
            "announced",
            "abandön",
            "ABOU\u{301}",
        ] {
            assert_eq!(Phrase::read_word(token), None, "{token}");
            assert_eq!(
                Phrase::read(&ZERO_12.replacen("abandon", token, 1)).unwrap_err(),
                Error::UnknownWord { position: 1 },
                "{token}"
            );
        }
    }

    #[test]
    fn rejects_short_or_ambiguous_prefixes_and_unknown_words() {
        let with_short_prefix = ZERO_12.replacen("abandon", "aba", 1);
        assert_eq!(
            Phrase::read(&with_short_prefix).unwrap_err(),
            Error::UnknownWord { position: 1 }
        );
        let with_unknown_word = ZERO_12.replacen("about", "aboutx", 1);
        assert_eq!(
            Phrase::read(&with_unknown_word).unwrap_err(),
            Error::UnknownWord { position: 12 }
        );
    }

    #[test]
    fn reports_word_count_and_checksum_problems() {
        assert_eq!(
            Phrase::read("abandon abandon").unwrap_err(),
            Error::InvalidWordCount { words: 2 }
        );
        assert_eq!(
            Phrase::read("").unwrap_err(),
            Error::InvalidWordCount { words: 0 }
        );
        let bad_checksum = ZERO_12.replace("about", "abandon");
        assert_eq!(
            Phrase::read(&bad_checksum).unwrap_err(),
            Error::InvalidChecksum
        );
        // The word count comes before the words.
        assert_eq!(
            Phrase::read("xyz xyz").unwrap_err(),
            Error::InvalidWordCount { words: 2 }
        );
    }

    /// Creation step 2 over the shared ambiguous states: a short original whose state also passes
    /// the 21-word verifier, and a 24-word original equal to the whole state, which passes both.
    #[test]
    fn creation_names_the_other_lengths_detection_would_accept() {
        assert!(
            Phrase::read(ZERO_12)
                .unwrap()
                .other_detected_lengths()
                .is_empty()
        );
        let legal_24 = Phrase::from_entropy(&[0x7f; 32]).unwrap();
        assert!(legal_24.other_detected_lengths().is_empty());
        let cases = fixture(SUITE_3_VALIDATION);
        let ambiguous = cases["length_detection"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| text(case, "id").starts_with("ambiguous"));
        let mut checked = 0;
        for case in ambiguous {
            let state = hex(text(case, "state_hex"));
            let lengths = &case["matching_short_lengths"];
            let short = lengths[0].as_u64().unwrap() as usize;
            let long = lengths[1].as_u64().unwrap() as usize;
            let original = Phrase::from_entropy(&state[..packing::entropy_of_words(short)]);
            assert_eq!(original.unwrap().other_detected_lengths(), [long]);
            let whole = Phrase::from_entropy(&state).unwrap();
            assert_eq!(whole.other_detected_lengths(), [short, long]);
            checked += 1;
        }
        assert_eq!(checked, 3);
    }

    #[test]
    fn debug_output_hides_the_phrase() {
        let phrase = Phrase::read(ZERO_12).unwrap();
        assert_eq!(format!("{phrase:?}"), "Phrase(hidden)");
    }
}
