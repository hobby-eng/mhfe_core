//! CHECK-BLD-003: the vendored trees and the Unicode test data against their upstream sources,
//! over the network:
//!   1. every file of `vendor/phc-winner-argon2/` has the Git blob ID of the same path in upstream
//!      commit f57e61e (GitHub's tree API, read through `gh api`), and the tree holds every file
//!      of upstream's `include/` and `src/` plus `LICENSE` and `README.md`;
//!   2. `vendor/eff-large-wordlist/eff_large_wordlist.txt` is byte-identical to EFF's download;
//!   3. `tests/fixtures/unicode18-ucd/NormalizationTest.txt` is byte-identical to unicode.org's.
//!
//! The downloads are only compared and hashed, never run.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

use serde_json::Value;

use crate::Error;
use crate::tools;

const USAGE: &str = "usage: vendored-upstream <repository> <download folder>";

/// The upstream commit the vendored Argon2 tree records (`vendor/phc-winner-argon2.md`).
const ARGON2_COMMIT: &str = "f57e61e19229e23c4445b85494dbf7c07de721cb";

/// The vendored Argon2 tree, relative to the repository.
const ARGON2_TREE: &str = "vendor/phc-winner-argon2";

/// The folders and files of upstream's tree that the vendored tree copies.
const ARGON2_FOLDERS: [&str; 2] = ["include/", "src/"];
const ARGON2_FILES: [&str; 2] = ["LICENSE", "README.md"];

/// Check number, upstream URL and local copy of each downloaded file.
const DOWNLOADS: [(u8, &str, &str); 2] = [
    (
        2,
        "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt",
        "vendor/eff-large-wordlist/eff_large_wordlist.txt",
    ),
    (
        3,
        "https://www.unicode.org/Public/18.0.0/ucd/NormalizationTest.txt",
        "tests/fixtures/unicode18-ucd/NormalizationTest.txt",
    ),
];

pub(crate) fn run(arguments: &[String]) -> Result<bool, Error> {
    let [repository, downloads] = arguments else {
        return Err(Error(USAGE.to_owned()));
    };
    let repository = Path::new(repository);
    let downloads = tools::work_folder(downloads)?;
    let mut passed = argon2_matches(repository, &downloads)?;
    for (number, url, local) in DOWNLOADS {
        let name = url.rsplit('/').next().unwrap_or(url);
        let body = tools::download(url)?;
        fs::write(downloads.join(name), &body)?;
        if body == fs::read(repository.join(local))? {
            println!(
                "{number}. {local} is byte-identical to {url} (SHA-256 {})",
                tools::sha256_hex(&body)
            );
        } else {
            println!("{number}. FAILED: {local} differs from {url}");
            passed = false;
        }
    }
    Ok(passed)
}

/// Check 1: the vendored Argon2 tree's blob IDs against upstream's tree.
fn argon2_matches(repository: &Path, downloads: &Path) -> Result<bool, Error> {
    let path = format!("repos/P-H-C/phc-winner-argon2/git/trees/{ARGON2_COMMIT}?recursive=1");
    let listing = tools::output(tools::tool("gh").args(["api", &path]))?;
    fs::write(downloads.join("argon2-tree.json"), &listing)?;
    let tree: Value = serde_json::from_slice(&listing)?;
    if tree["truncated"].as_bool() != Some(false) {
        return Err(Error(
            "the tree listing is truncated or has no `truncated` field".to_owned(),
        ));
    }
    let entries = tree["tree"]
        .as_array()
        .ok_or_else(|| Error("the tree listing has no tree".to_owned()))?;
    let mut upstream = BTreeSet::new();
    for entry in entries {
        let (Some(path), Some(kind), Some(sha)) = (
            entry["path"].as_str(),
            entry["type"].as_str(),
            entry["sha"].as_str(),
        ) else {
            return Err(Error("a tree entry without path, type or sha".to_owned()));
        };
        let copied = ARGON2_FOLDERS.iter().any(|folder| path.starts_with(folder))
            || ARGON2_FILES.contains(&path);
        if kind == "blob" && copied {
            upstream.insert(format!("{sha} {path}"));
        }
    }
    if upstream.is_empty() {
        return Err(Error(
            "upstream's tree lists none of the copied files".to_owned(),
        ));
    }

    let vendored = blob_ids(&repository.join(ARGON2_TREE))?;
    if upstream == vendored {
        println!(
            "1. the {} vendored Argon2 files are upstream's include/, src/, LICENSE and README.md at {ARGON2_COMMIT}",
            vendored.len()
        );
        return Ok(true);
    }
    for line in upstream.difference(&vendored) {
        println!("< {line}");
    }
    for line in vendored.difference(&upstream) {
        println!("> {line}");
    }
    println!("1. FAILED: the vendored Argon2 tree differs from upstream (< upstream, > vendored)");
    Ok(false)
}

/// `<blob ID> <path>` for every file under `folder`, as `git hash-object --no-filters` gives it.
fn blob_ids(folder: &Path) -> Result<BTreeSet<String>, Error> {
    let files = tools::files_under(folder)?;
    // Absolute paths: inside a repository git reads `--stdin-paths` from its top folder.
    let folder = fs::canonicalize(folder)?;
    let mut child = tools::tool("git")
        .args(["hash-object", "--no-filters", "--stdin-paths"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        for file in &files {
            writeln!(stdin, "{}", folder.join(file).display())?;
        }
    }
    let result = child.wait_with_output()?;
    if !result.status.success() {
        return Err(Error(format!(
            "git hash-object: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        )));
    }
    let ids = String::from_utf8_lossy(&result.stdout).into_owned();
    let ids: Vec<&str> = ids.lines().collect();
    if ids.len() != files.len() {
        return Err(Error(
            "git hash-object did not give one ID per file".to_owned(),
        ));
    }
    Ok(ids
        .iter()
        .zip(&files)
        .map(|(id, path)| format!("{id} {path}"))
        .collect())
}
