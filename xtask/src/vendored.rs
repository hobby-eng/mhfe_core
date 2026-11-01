//! The vendored tree holds exactly the file its document records, byte for byte:
//! vendor/eff-large-wordlist/ its one file, whose SHA-256 the table of vendor/eff-large-wordlist.md
//! gives. A file changed, added or missing fails.
//!
//! Run as `cargo xtask vendored`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::Failure;

/// The folder of the vendored trees, each beside its document, `vendor/<tree>.md`.
const VENDOR: &str = "vendor";
const TREES: &[(&str, &str)] = &[("eff-large-wordlist", "eff_large_wordlist.txt")];
/// The digits of a SHA-256 in hexadecimal: 32 bytes of two digits each.
const DIGEST_DIGITS: usize = 64;
/// The start of the row of a document's table that gives the SHA-256 of the tree's one file,
/// ``| SHA-256   | `<digest>`   |``.
const SHA256_ROW: &str = "| SHA-256 ";

pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    let mut problems = Vec::new();
    let mut checked = 0;
    for (tree, file) in TREES {
        let mut digests = BTreeMap::new();
        digests_of(&root.join(VENDOR).join(tree), "", &mut digests)?;
        let document = read(&root.join(VENDOR).join(format!("{tree}.md")))?;
        let recorded = recorded_digests(&String::from_utf8_lossy(&document), file);
        problems.extend(differences(tree, &digests, &recorded));
        checked += digests
            .iter()
            .filter(|(path, digest)| recorded.get(*path) == Some(*digest))
            .count();
    }
    if problems.is_empty() {
        println!("The {checked} vendored files are the recorded ones.");
        return Ok(());
    }
    Err(Failure(format!(
        "{}\n{} vendored files differ from {VENDOR}/*.md.",
        problems.join("\n"),
        problems.len()
    )))
}

/// The SHA-256 that `document` records for `file`, the one file of its tree: the SHA-256 row of its
/// table.
fn recorded_digests(document: &str, file: &str) -> BTreeMap<String, String> {
    document
        .split('\n')
        .find_map(table_row)
        .map(|digest| BTreeMap::from([(file.to_owned(), digest.to_owned())]))
        .unwrap_or_default()
}

/// The digest of the table row ``| SHA-256   | `<digest>`   |``, its cells padded with spaces.
fn table_row(line: &str) -> Option<&str> {
    let cell = line
        .strip_prefix(SHA256_ROW)?
        .trim_start_matches(' ')
        .strip_prefix("| `")?;
    let (digest, end) = cell.split_once('`')?;
    let closed = end.starts_with(' ') && end.trim_start_matches(' ') == "|";
    (is_digest(digest) && closed).then_some(digest)
}

/// Whether `text` is a SHA-256 in lowercase hexadecimal, as `sha256sum` writes it.
fn is_digest(text: &str) -> bool {
    text.len() == DIGEST_DIGITS
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// What differs between the SHA-256 of a tree's files and those its document records.
fn differences(
    tree: &str,
    digests: &BTreeMap<String, String>,
    recorded: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut problems = Vec::new();
    for (path, digest) in digests {
        match recorded.get(path) {
            None => problems.push(format!("{VENDOR}/{tree}/{path} is not recorded")),
            Some(listed) if listed != digest => {
                problems.push(format!("{VENDOR}/{tree}/{path} changed"));
            }
            Some(_) => {}
        }
    }
    for path in recorded.keys().filter(|path| !digests.contains_key(*path)) {
        problems.push(format!("{VENDOR}/{tree}/{path} is missing"));
    }
    problems
}

/// The SHA-256 of every file under `directory`, by its path from it; `prefix` is the folder
/// being read, from `directory`.
fn digests_of(
    directory: &Path,
    prefix: &str,
    digests: &mut BTreeMap<String, String>,
) -> Result<(), Failure> {
    let folder = directory.join(prefix);
    let entries =
        fs::read_dir(&folder).map_err(|error| Failure(format!("{}: {error}", folder.display())))?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type()?.is_dir() {
            digests_of(directory, &path, digests)?;
        } else {
            digests.insert(path, sha256_hex(&read(&entry.path())?));
        }
    }
    Ok(())
}

/// The SHA-256 of `bytes` in lowercase hexadecimal.
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The bytes of the file at `path`.
fn read(path: &Path) -> Result<Vec<u8>, Failure> {
    fs::read(path).map_err(|error| Failure(format!("{}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SHA-256 of "abc", FIPS 180-2's first example.
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    /// The SHA-256 of "", FIPS 180-2's empty message as `sha256sum` prints it.
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Paths with their digests.
    fn digests(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(path, digest)| ((*path).to_owned(), (*digest).to_owned()))
            .collect()
    }

    #[test]
    fn the_sha256_of_abc_is_the_published_one() {
        assert_eq!(sha256_hex(b"abc"), ABC);
        assert_eq!(sha256_hex(b""), EMPTY);
    }

    #[test]
    fn the_table_row_gives_the_digest_of_the_one_file() {
        let document = format!("| Field     | Value |\n| SHA-256   | `{ABC}`   |\n");
        let one = digests(&[("words.txt", ABC)]);
        assert_eq!(recorded_digests(&document, "words.txt"), one);
        let unpadded = format!("| SHA-256 | `{ABC}`|\n");
        assert_eq!(recorded_digests(&unpadded, "words.txt"), BTreeMap::new());
    }

    #[test]
    fn the_recorded_files_pass() {
        let files = digests(&[("LICENSE", ABC), ("words.txt", EMPTY)]);
        assert_eq!(differences("list", &files, &files), Vec::<String>::new());
    }

    #[test]
    fn a_file_changed_added_or_missing_is_refused() {
        let files = digests(&[("LICENSE", EMPTY), ("added.txt", ABC)]);
        let recorded = digests(&[("LICENSE", ABC), ("words.txt", EMPTY)]);
        assert_eq!(
            differences("list", &files, &recorded),
            [
                "vendor/list/LICENSE changed",
                "vendor/list/added.txt is not recorded",
                "vendor/list/words.txt is missing",
            ]
        );
    }
}
