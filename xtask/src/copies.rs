//! The `copies` gate (CORE-10): finds code copied from one place to another, the same run of at
//! least MIN_TOKENS tokens in two places of the library (src/) or of the repository's tools
//! (xtask/src/), whatever the white space, the line breaks and the comments. It reads the code
//! with a small tokenizer of its own (`copies/tokens.rs`), so that it needs no crate.
//!
//! A copy is reported as "file A:lines = file B:lines": the code belongs in one function that both
//! call. A deliberate copy, such as a fast path or a test program that cannot import, says so in a
//! comment that contains "deliberate copy" inside the copied lines or the three lines above them,
//! with its reason; it is then not reported.
//!
//! It finds copies, not the same rule written in other words, nor a constant written in many
//! places: those still need the search before writing and a review. `use` lists at the start of a
//! statement, `pub use` and `pub(crate) use` included, are left out: two files that use the same
//! modules share no code. A `use` inside a type, as in `impl Trait + use<'a>`, is code and is read.
//!
//! The same rule as mhfe's scripts/verify-no-copies.mjs and MnemoCode's: a change of the rule goes
//! to all three.
//!
//! Usage: `cargo xtask copies [--tokens N]`, N a whole number from 2, 50 by default. The controls
//! that the checker must decide right are its unit tests.

mod tokens;

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::Path;

use crate::Failure;
use tokens::Tokens;

/// The shortest run of tokens that counts as a copy, about four to six lines of code: jscpd's
/// default, below which the same few lines of ordinary code meet by chance.
const MIN_TOKENS: usize = 50;
/// The smallest threshold `--tokens` takes: with one token, every word used twice is a copy.
const FEWEST_TOKENS: usize = 2;
/// The folders read, from the root.
const SOURCES: [&str; 2] = ["src", "xtask/src"];
/// The ending of the files read in them.
const SOURCE_ENDING: &str = ".rs";
/// Lines above a copy in which its marker may stand.
const MARKER_LINES_ABOVE: usize = 3;
/// The usage, said with a refused command line.
const USAGE: &str = "usage: cargo xtask copies [--tokens N]";

/// A source file: its path from the root, with `/` between its names, and its text.
struct Source {
    path: String,
    text: String,
}

/// The lines of a file that a copy spans.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Place<'a> {
    path: &'a str,
    first: usize,
    last: usize,
}

impl<'a> Place<'a> {
    /// The place of the tokens `from` to `to` of `file`, which is at `path`.
    fn of(path: &'a str, file: &Tokens, from: usize, to: usize) -> Self {
        Self {
            path,
            first: file.tokens[from].line,
            last: file.tokens[to].line,
        }
    }

    /// Whether a comment on the place, or on the few lines above it, marks a deliberate copy.
    fn deliberate(&self, file: &Tokens) -> bool {
        let first = self.first.saturating_sub(MARKER_LINES_ABOVE);
        (first..=self.last).any(|line| file.marked_lines.contains(&line))
    }
}

impl fmt::Display for Place<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}-{}", self.path, self.first, self.last)
    }
}

/// A copy: a place, the place that repeats it, and the number of tokens they share.
struct Copied<'a> {
    place: Place<'a>,
    other: Place<'a>,
    tokens: usize,
}

/// Runs the gate with its command line.
pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), Failure> {
    let min_tokens = min_tokens(arguments)?;
    let mut sources = Vec::new();
    for folder in SOURCES {
        read_sources(root, folder, &mut sources)?;
    }
    println!("{}", verdict(&sources, min_tokens)?);
    Ok(())
}

/// The threshold of the command line: `--tokens N` with N a whole number from 2, or nothing.
/// Anything else is refused, so that a mistyped threshold never passes a check that looked at
/// nothing.
fn min_tokens(arguments: &[String]) -> Result<usize, Failure> {
    let refused = || Failure(format!("{USAGE}: N is a whole number from {FEWEST_TOKENS}"));
    match arguments {
        [] => Ok(MIN_TOKENS),
        // Digits only: Rust's own parsing also takes a leading `+`.
        [option, number] if option == "--tokens" && number.bytes().all(|b| b.is_ascii_digit()) => {
            number
                .parse()
                .ok()
                .filter(|&tokens| tokens >= FEWEST_TOKENS)
                .ok_or_else(refused)
        }
        _ => Err(refused()),
    }
}

/// Adds every source file under `folder` to `sources`, in the order of their names, so that the
/// report is the same on every system.
fn read_sources(root: &Path, folder: &str, sources: &mut Vec<Source>) -> Result<(), Failure> {
    let failed = |error: std::io::Error| Failure(format!("{folder}: {error}"));
    let mut entries = fs::read_dir(root.join(folder))
        .and_then(|entries| entries.collect::<Result<Vec<_>, _>>())
        .map_err(failed)?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = format!("{folder}/{}", entry.file_name().to_string_lossy());
        if entry.file_type().map_err(failed)?.is_dir() {
            read_sources(root, &path, sources)?;
        } else if path.ends_with(SOURCE_ENDING) {
            let text = fs::read_to_string(entry.path())
                .map_err(|error| Failure(format!("{path}: {error}")))?;
            sources.push(Source { path, text });
        }
    }
    Ok(())
}

/// The summary of a check that finds no copy among `sources`, or a failure that lists the copies
/// it finds and says what to do with them.
fn verdict(sources: &[Source], min_tokens: usize) -> Result<String, Failure> {
    let copies = find_copies(sources, min_tokens);
    if copies.is_empty() {
        let (files, folders) = (sources.len(), SOURCES.map(|folder| format!("{folder}/")));
        let folders = folders.join(" and ");
        return Ok(format!(
            "No copies of {min_tokens} tokens or more in {files} files of {folders}."
        ));
    }
    let list: String = copies
        .iter()
        .map(|copy| format!("{} = {} ({} tokens)\n", copy.place, copy.other, copy.tokens))
        .collect();
    Err(Failure(format!(
        "{list}{} copies of {min_tokens} tokens or more: move each into one function that both \
         places call, or mark a deliberate one (see the top of {}).",
        copies.len(),
        file!(),
    )))
}

/// The copies of `min_tokens` tokens or more among `sources`, the longest first, with the
/// deliberate ones left out.
fn find_copies(sources: &[Source], min_tokens: usize) -> Vec<Copied<'_>> {
    let files: Vec<Tokens> = sources
        .iter()
        .map(|source| tokens::read(&source.text))
        .collect();
    let mut copies = Vec::new();
    for ((a, b), mut starts) in runs(&files, min_tokens) {
        starts.sort_unstable();
        // Consecutive windows that match at the same distance are one copy.
        for run in starts.chunk_by(|start, next| next.0 == start.0 + 1) {
            let (from, other_from) = run[0];
            let (last, other_last) = run[run.len() - 1];
            let (to, other_to) = (last + min_tokens - 1, other_last + min_tokens - 1);
            let place = Place::of(&sources[a].path, &files[a], from, to);
            let other = Place::of(&sources[b].path, &files[b], other_from, other_to);
            if !place.deliberate(&files[a]) && !other.deliberate(&files[b]) {
                copies.push(Copied {
                    place,
                    other,
                    tokens: to - from + 1,
                });
            }
        }
    }
    // A place copied several times is named once, against the first place it copies: three equal
    // blocks are two copies, not three.
    copies.sort_by_key(|copy| (copy.place.path, copy.place.first));
    let mut named = HashSet::new();
    copies.retain(|copy| named.insert(copy.other));
    copies.sort_by_key(|copy| Reverse(copy.tokens));
    copies
}

/// The places of the same text on one diagonal: the two files, and the pairs of places at the same
/// distance from the first file to the second, each as the first token of both places.
type Run = ((usize, usize), Vec<(usize, usize)>);

/// Every pair of places of the same window of `min_tokens` tokens, by diagonal, in the order in
/// which the windows and then the diagonals are first met: that order decides which place a place
/// copied several times is named against. Every pair, not each place against the first, so that a
/// first place marked as deliberate does not hide copies among the others.
fn runs(files: &[Tokens], min_tokens: usize) -> Vec<Run> {
    let keys = numbered(files);
    let mut windows: Vec<_> = windows(&keys, min_tokens).into_values().collect();
    windows.sort_unstable_by_key(|places| places.first().copied());
    let mut diagonals: HashMap<(usize, usize, isize), usize> = HashMap::new();
    let mut runs: Vec<Run> = Vec::new();
    for places in &windows {
        for (index, &(file, start)) in places.iter().enumerate() {
            for &(other_file, other_start) in &places[index + 1..] {
                // Overlapping windows of one file are one run of repeated tokens, not a copy.
                if file == other_file && other_start - start < min_tokens {
                    continue;
                }
                let distance = other_start as isize - start as isize;
                let run = *diagonals
                    .entry((file, other_file, distance))
                    .or_insert_with(|| {
                        runs.push(((file, other_file), Vec::new()));
                        runs.len() - 1
                    });
                runs[run].1.push((start, other_start));
            }
        }
    }
    runs
}

/// The tokens of `files` as the numbers of their texts, so that a window is a slice of numbers.
fn numbered(files: &[Tokens]) -> Vec<Vec<usize>> {
    let mut numbers: HashMap<&str, usize> = HashMap::new();
    let mut numbered = Vec::with_capacity(files.len());
    for file in files {
        let mut keys = Vec::with_capacity(file.tokens.len());
        for token in &file.tokens {
            let next = numbers.len();
            keys.push(*numbers.entry(token.key.as_str()).or_insert(next));
        }
        numbered.push(keys);
    }
    numbered
}

/// Where every window of `min_tokens` tokens occurs, by its text: as (file, first token), in the
/// order of the files and of their tokens.
fn windows(keys: &[Vec<usize>], min_tokens: usize) -> HashMap<&[usize], Vec<(usize, usize)>> {
    let mut windows: HashMap<&[usize], Vec<_>> = HashMap::new();
    for (file, keys) in keys.iter().enumerate() {
        for (start, window) in keys.windows(min_tokens).enumerate() {
            windows.entry(window).or_default().push((file, start));
        }
    }
    windows
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `count` statements, long enough together to be a copy, different for every `seed`.
    fn long_body(seed: usize, count: usize) -> String {
        let lines: Vec<String> = (0..count)
            .map(|index| format!("    total = total * {seed} + from + {index};"))
            .collect();
        lines.join("\n")
    }

    /// A function named `name` around `count` statements.
    fn function_of(name: &str, count: usize) -> String {
        let body = long_body(7, count);
        format!("fn {name}(from: u64) -> u64 {{\n    let mut total = 0;\n{body}\n    total\n}}")
    }

    /// A function long enough to be a copy.
    fn function(name: &str) -> String {
        function_of(name, 12)
    }

    /// The same function, under a comment that marks it as a deliberate copy.
    fn marked(name: &str) -> String {
        format!("// A deliberate copy: its reason.\n{}", function(name))
    }

    fn sources(files: &[(&str, String)]) -> Vec<Source> {
        let source = |(path, text): &(&str, String)| Source {
            path: (*path).to_owned(),
            text: text.clone(),
        };
        files.iter().map(source).collect()
    }

    fn found(files: &[(&str, String)]) -> bool {
        !find_copies(&sources(files), MIN_TOKENS).is_empty()
    }

    fn arguments(list: &[&str]) -> Vec<String> {
        list.iter().map(|&argument| argument.to_owned()).collect()
    }

    #[test]
    fn an_ordinary_copy_is_found() {
        assert!(found(&[
            ("src/a.rs", function("a")),
            ("src/b.rs", function("b"))
        ]));
    }

    #[test]
    fn a_copy_in_public_items_is_found() {
        let a = format!("pub {}", function("sample"));
        let b = format!(
            "pub(crate) struct Other;\nimpl Other {{\n    pub(crate) {}\n}}",
            function("sample")
        );
        assert!(found(&[("src/a.rs", a), ("src/b.rs", b)]));
    }

    #[test]
    fn a_copy_beside_raw_strings_and_lifetimes_is_found() {
        let lines: Vec<String> = (0..12)
            .map(|i| format!("    total = total * 7 + r#\"a\"b\"# .len() + {i};"))
            .collect();
        let body = lines.join("\n");
        let text = |name: &str, lifetime: &str, char: &str| {
            format!(
                "fn {name}<'{lifetime}>(x: &'{lifetime} str) -> usize {{\n    let c = '{char}';\n    \
                 let mut total = 0;\n{body}\n    total\n}}"
            )
        };
        assert!(found(&[
            ("src/a.rs", text("a", "a", "x")),
            ("src/b.rs", text("b", "b", "y"))
        ]));
    }

    #[test]
    fn use_lists_are_not_found() {
        let names: Vec<String> = (0..40).map(|i| format!("name{i}")).collect();
        let list = format!("crate::{{{}}};", names.join(", "));
        let text =
            format!("use {list}\npub use {list}\npub(crate) use {list}\n#[cfg(test)]\nuse {list}");
        assert!(!found(&[("src/a.rs", text.clone()), ("src/b.rs", text)]));
    }

    #[test]
    fn a_copy_right_after_use_lists_is_found() {
        let a = format!(
            "use std::fmt;\n#[cfg(test)]\nuse std::io;\n{}",
            function("a")
        );
        let b = format!(
            "pub use crate::x;\npub(crate) use crate::y::{{self, z}};\n{}",
            function("b")
        );
        assert!(found(&[("src/a.rs", a), ("src/b.rs", b)]));
    }

    #[test]
    fn a_copy_after_use_in_a_type_is_found() {
        let lines: Vec<String> = (0..12)
            .map(|i| format!("    total = total * 7 + x.len() + {i};"))
            .collect();
        let body = lines.join("\n");
        let text = |name: &str| {
            format!(
                "fn {name}<'a>(x: &'a str) -> impl Sized + use<'a> {{\n    let mut total = 0;\n\
                 {body}\n    x\n}}"
            )
        };
        assert!(found(&[("src/a.rs", text("a")), ("src/b.rs", text("b"))]));
    }

    #[test]
    fn a_deliberate_copy_is_not_found() {
        let a = format!(
            "// A deliberate copy: a test program cannot import.\n{}",
            function("a")
        );
        assert!(!found(&[("src/a.rs", a), ("src/b.rs", function("b"))]));
    }

    #[test]
    fn a_short_repeat_is_not_found() {
        assert!(!found(&[
            ("src/a.rs", function_of("a", 2)),
            ("src/b.rs", function_of("b", 2))
        ]));
    }

    #[test]
    fn a_copy_beside_strings_that_say_deliberate_copy_is_found() {
        let a = format!("const WHY: &str = \"deliberate copy\";\n{}", function("a"));
        let b = format!(
            "const WHY: &str = r#\"deliberate copy\"#;\n{}",
            function("b")
        );
        assert!(found(&[("src/a.rs", a), ("src/b.rs", b)]));
    }

    #[test]
    fn a_copy_under_a_block_comment_that_marks_it_is_not_found() {
        let comment = "/*\n * A deliberate copy: a test program\n * cannot import.\n */";
        let a = format!("{comment}\n{}", function("a"));
        assert!(!found(&[("src/a.rs", a), ("src/b.rs", function("b"))]));
    }

    #[test]
    fn two_unmarked_copies_beside_a_marked_one_are_found_wherever_it_stands() {
        for marked_at in 0..3 {
            let files: Vec<(&str, String)> = ["src/0.rs", "src/1.rs", "src/2.rs"]
                .into_iter()
                .zip(["a", "b", "c"])
                .enumerate()
                .map(|(index, (path, name))| {
                    (
                        path,
                        if index == marked_at {
                            marked(name)
                        } else {
                            function(name)
                        },
                    )
                })
                .collect();
            assert!(found(&files), "the marked one at {marked_at}");
        }
    }

    #[test]
    fn two_unmarked_copies_in_one_file_beside_a_marked_one_are_found() {
        let text = format!("{}\n{}\n{}", marked("a"), function("b"), function("c"));
        assert!(found(&[("src/one.rs", text)]));
    }

    #[test]
    fn one_copy_of_a_marked_place_is_not_found() {
        assert!(!found(&[
            ("src/a.rs", marked("a")),
            ("src/b.rs", function("b"))
        ]));
    }

    #[test]
    fn three_equal_places_give_two_copies() {
        let files = [
            ("src/a.rs", function("a")),
            ("src/b.rs", function("b")),
            ("src/c.rs", function("c")),
        ];
        assert_eq!(find_copies(&sources(&files), MIN_TOKENS).len(), 2);
    }

    #[test]
    fn a_copy_is_reported_with_its_places_and_what_to_do() {
        let files = sources(&[("src/a.rs", function("a")), ("src/b.rs", function("b"))]);
        let Err(Failure(message)) = verdict(&files, MIN_TOKENS) else {
            panic!("the copy is not found");
        };
        assert_eq!(
            message,
            "src/a.rs:1-16 = src/b.rs:1-16 (137 tokens)\n1 copies of 50 tokens or more: move each \
             into one function that both places call, or mark a deliberate one (see the top of \
             xtask/src/copies.rs)."
        );
    }

    #[test]
    fn no_copy_is_reported_with_the_number_of_files_read() {
        let files = sources(&[
            ("src/a.rs", function("a")),
            ("xtask/src/b.rs", long_body(3, 12)),
        ]);
        assert_eq!(
            verdict(&files, MIN_TOKENS).ok().as_deref(),
            Some("No copies of 50 tokens or more in 2 files of src/ and xtask/src/.")
        );
    }

    #[test]
    fn the_threshold_is_50_by_default_or_any_whole_number_from_2() {
        assert_eq!(min_tokens(&[]).ok(), Some(50));
        assert_eq!(min_tokens(&arguments(&["--tokens", "2"])).ok(), Some(2));
        assert_eq!(min_tokens(&arguments(&["--tokens", "120"])).ok(), Some(120));
    }

    #[test]
    fn a_bad_threshold_or_another_argument_is_refused() {
        for list in [
            &["--tokens", "NaN"][..],
            &["--tokens", "Infinity"],
            &["--tokens", "0"],
            &["--tokens", "1"],
            &["--tokens", "-5"],
            &["--tokens", "+5"],
            &["--tokens", "1.5"],
            &["--tokens", ""],
            &["--tokens"],
            // Past the largest whole number the threshold can hold.
            &["--tokens", "99999999999999999999999999"],
            &["--tokens", "50", "--tokens", "50"],
            // The script's self-test, now the unit tests.
            &["--self-test"],
            &["--other"],
        ] {
            let Err(Failure(message)) = min_tokens(&arguments(list)) else {
                panic!("{} is accepted", list.join(" "));
            };
            assert_eq!(
                message,
                "usage: cargo xtask copies [--tokens N]: N is a whole number from 2"
            );
        }
    }
}
