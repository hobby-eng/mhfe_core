//! `UTF8(NFKD(text))` written straight into a [`Secret`]: the password `P_enc` and the BIP39
//! passphrase `Q` never pass through a buffer of their own (`unicode-normalization`'s iterator keeps
//! pending combining marks in a heap vector from the fifth on, which nothing wipes).
//!
//! A counting pass sizes the result, so that a caller can refuse it before anything is written.
//! The writing pass appends each character's full compatibility decomposition; a starter that
//! decomposes into non-starters, such as U+0F73 or U+0F75, joins the run before it. A run of
//! non-starters that came out of canonical order is put in that order when a starter or the end of
//! the text closes it, by a stable counting sort on the canonical combining class through a second
//! [`Secret`], so that the time stays linear in the length of the text whatever its order.

use unicode_normalization::char::{canonical_combining_class, decompose_compatible};

use crate::protect::Secret;

/// The NFKD of one text: counted first, written on request.
pub(crate) struct Nfkd<'a> {
    text: &'a str,
    bytes: usize,
}

impl<'a> Nfkd<'a> {
    /// Counts the UTF-8 bytes of the NFKD of `text` without writing them.
    pub(crate) fn of(text: &'a str) -> Self {
        let mut bytes = 0;
        for character in text.chars() {
            decompose_compatible(character, |part| bytes += part.len_utf8());
        }
        Self { text, bytes }
    }

    /// The length of the NFKD in UTF-8 bytes.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// The NFKD in a [`Secret`] of exactly its length.
    pub(crate) fn write(self) -> Secret {
        let mut written = Secret::zeroed(self.bytes);
        let out = written.as_mut_bytes();
        // Made at the first run out of order: a run never outgrows the whole text.
        let mut spare: Option<Secret> = None;
        let mut end = 0;
        // Where the run of non-starters that ends at `end` begins, the class of its last
        // character, and whether a character came after one of a higher class.
        let mut run = 0;
        let mut last = 0;
        let mut unordered = false;
        for character in self.text.chars() {
            decompose_compatible(character, |part| {
                let class = canonical_combining_class(part);
                if class == 0 && unordered {
                    order(&mut out[run..end], &mut spare, self.bytes);
                    unordered = false;
                } else if class != 0 && class < last {
                    unordered = true;
                }
                last = class;
                let width = part.len_utf8();
                part.encode_utf8(&mut out[end..end + width]);
                end += width;
                if class == 0 {
                    run = end;
                }
            });
        }
        if unordered {
            order(&mut out[run..end], &mut spare, self.bytes);
        }
        written
    }
}

/// Puts `run`, non-starters out of canonical order, in that order: a stable counting sort on the
/// canonical combining class, which keeps equal classes in their order, through `spare`, a
/// [`Secret`] of `bytes`, the whole text's length, made on the first call.
#[expect(
    clippy::expect_used,
    reason = "the run holds whole characters that the writing pass wrote"
)]
fn order(run: &mut [u8], spare: &mut Option<Secret>, bytes: usize) {
    let copy = &mut spare
        .get_or_insert_with(|| Secret::zeroed(bytes))
        .as_mut_bytes()[..run.len()];
    copy.copy_from_slice(run);
    let copy = std::str::from_utf8(copy).expect("the run is UTF-8 that the writing pass wrote");
    // One slot per class, a u8: first the bytes of that class, then where they go.
    let mut at = [0; 256];
    for character in copy.chars() {
        at[usize::from(canonical_combining_class(character))] += character.len_utf8();
    }
    let mut start = 0;
    for slot in &mut at {
        let bytes = *slot;
        *slot = start;
        start += bytes;
    }
    for character in copy.chars() {
        let slot = &mut at[usize::from(canonical_combining_class(character))];
        character.encode_utf8(&mut run[*slot..]);
        *slot += character.len_utf8();
    }
}

#[cfg(test)]
mod tests {
    // NormalizationTest.txt is replayed here, not in tests/ (RUST-08): it runs the NFKD writer
    // and its counting pass, which the public API reaches only through a password's refusals and
    // byte limit.

    use super::*;
    use unicode_normalization::UnicodeNormalization;

    fn nfkd(text: &str) -> Vec<u8> {
        let counted = Nfkd::of(text);
        let bytes = counted.bytes();
        let written = counted.write();
        assert_eq!(written.as_bytes().len(), bytes, "{text:?}");
        written.as_bytes().to_vec()
    }

    /// U+0F73 decomposes into U+0F71 (class 129) and U+0F72 (class 130), which join the run of
    /// the U+0F72 before it and are ordered with it.
    #[test]
    fn non_starters_are_ordered_across_input_characters() {
        assert_eq!(nfkd("a\u{F72}\u{F73}"), "a\u{F71}\u{F72}\u{F72}".as_bytes());
        // U+0344 gives U+0308 U+0301, both of class 230, after the U+0316 of class 220.
        assert_eq!(nfkd("\u{344}\u{316}"), "\u{316}\u{308}\u{301}".as_bytes());
        // A starter ends the run; equal classes keep their order.
        assert_eq!(
            nfkd("\u{301}\u{316}e\u{301}\u{300}"),
            "\u{316}\u{301}e\u{301}\u{300}".as_bytes()
        );
        assert_eq!(nfkd(""), b"");
    }

    /// Unicode 18.0.0's NormalizationTest.txt: for every line, c5 is the NFKD of each of c1 to c5.
    #[test]
    fn every_line_of_the_unicode_normalization_test_holds() {
        let lines = crate::test_support::NORMALIZATION_TEST
            .lines()
            .filter(|line| !line.starts_with(['#', '@']) && !line.is_empty());
        let mut checked = 0;
        for line in lines {
            let columns: Vec<String> = line
                .split(';')
                .take(5)
                .map(|column| {
                    column
                        .split(' ')
                        .map(|hex| char::from_u32(u32::from_str_radix(hex, 16).unwrap()).unwrap())
                        .collect()
                })
                .collect();
            for column in &columns {
                assert_eq!(nfkd(column), columns[4].as_bytes(), "{line}");
            }
            checked += 1;
        }
        assert!(checked > 20_000, "{checked} lines");
    }

    /// Each code point alone, between starters that end every run, as the crate's own iterator
    /// normalizes it.
    #[test]
    fn every_code_point_alone_matches_the_crate_iterator() {
        let scalars: Vec<char> = (0..=0x10FFFF).filter_map(char::from_u32).collect();
        for block in scalars.chunks(4096) {
            let text: String = block
                .iter()
                .flat_map(|&character| [character, '|'])
                .collect();
            assert_eq!(nfkd(&text), text.nfkd().collect::<String>().as_bytes());
        }
    }

    /// Random sequences of decomposing starters, non-starters of different classes and ASCII,
    /// against the crate's own iterator; the generator is a fixed xorshift, so the run repeats.
    #[test]
    fn random_sequences_match_the_crate_iterator() {
        const POOL: [char; 18] = [
            'a', 'Z', ' ', '\u{F73}', '\u{F72}', '\u{F71}', '\u{344}', '\u{D55C}', '\u{AC00}',
            '\u{FDFA}', '\u{301}', '\u{316}', '\u{327}', '\u{334}', '\u{94D}', '\u{345}',
            '\u{1E0A}', '\u{FB01}',
        ];
        let mut state: u64 = 0x4d48_4645_2d4e_464b;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let length = next() % 24;
            let text: String = (0..length)
                .map(|_| POOL[(next() % POOL.len() as u64) as usize])
                .collect();
            assert_eq!(
                nfkd(&text),
                text.nfkd().collect::<String>().as_bytes(),
                "{text:?}"
            );
        }
    }

    /// Long runs out of canonical order, closed by a starter and by the end of the text, are
    /// ordered as the crate's own iterator orders them.
    #[test]
    fn long_runs_out_of_order_match_the_crate_iterator() {
        for text in [
            format!("a{}", "\u{316}\u{301}".repeat(20_000)),
            format!("a\u{301}{}", "\u{316}".repeat(40_000)),
            format!(
                "{}b{}",
                "\u{344}\u{327}".repeat(9_000),
                "\u{F73}\u{F71}".repeat(9_000)
            ),
        ] {
            assert_eq!(nfkd(&text), text.nfkd().collect::<String>().as_bytes());
        }
    }

    /// A run out of canonical order costs time linear in its length: an insertion on each mark,
    /// which this writer replaced, took about half a minute on these 320 KB in a release build.
    #[test]
    fn a_long_run_out_of_order_is_written_in_linear_time() {
        let text = format!("a{}", "\u{316}\u{301}".repeat(80_000));
        let start = std::time::Instant::now();
        let written = Nfkd::of(&text).write();
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        assert_eq!(written.as_bytes().len(), text.len());
    }
}
