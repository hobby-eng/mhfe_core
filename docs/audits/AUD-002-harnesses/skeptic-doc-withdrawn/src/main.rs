//! AUD-002 skeptic check of the finding on the 0.1.0 notes of mhfe-core (see README.md beside this
//! crate). Two consumers written for the withdrawn mhfe-core 0.1.0, one with a feature it declared
//! and one with two items it exported, are built offline against the repository that holds this
//! harness. Exit 1 when such a consumer breaks and the CHANGELOG paragraph on the withdrawn package
//! does not say so; 2 when a consumer fails for another reason or the harness stops on an error: an
//! unknown state is never a pass (CORE-22).
//!
//!   aud002-skeptic-doc-withdrawn <scratch folder>

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// The documentation harness's reading of the paragraph, so that both read the same one (CORE-10).
#[path = "../../docs/src/notes.rs"]
mod notes;
use notes::withdrawn_notes;

/// A harness prints its errors and stops; it has no module errors to tell apart.
type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The exit code when the claim fails.
const FAILED: u8 = 1;
/// The exit code when a consumer failed for another reason or the harness stopped on an error.
const UNDECIDED: u8 = 2;
/// A feature that the withdrawn package declared (the `[features]` of its Cargo.toml, package
/// SHA-256 bc23d4d1...) and that this crate does not.
const OLD_FEATURE: &str = "browser-core";
/// Code using two items that the withdrawn package's src/lib.rs exported at its root and this
/// crate's does not.
const OLD_ITEMS: &str = "use mhfe_core::{Completion, ErrorCode};\n\n\
                         fn main() {\n    let _ = (None::<Completion>, None::<ErrorCode>);\n}\n";
/// rustc's error for an unresolved import, the way the second consumer breaks.
const UNRESOLVED_IMPORT: &str = "error[E0432]";

fn main() -> ExitCode {
    let Some(work) = std::env::args_os().nth(1) else {
        eprintln!("usage: aud002-skeptic-doc-withdrawn <scratch folder>");
        return ExitCode::from(UNDECIDED);
    };
    match run(Path::new(&work)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(FAILED),
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::from(UNDECIDED)
        }
    }
}

fn run(work: &Path) -> Result<bool> {
    let root = repository()?;
    // The consumers live outside the repository, so they take its toolchain explicitly.
    let toolchain = channel(&read(&root, "rust-toolchain.toml")?)?;
    let mut broken = Vec::new();

    let features = consumer(
        &root,
        &work.join("features"),
        "old-features",
        &format!(", features = [\"{OLD_FEATURE}\"]"),
        "fn main() {}\n",
    )?;
    // Resolving the dependency is enough to meet a missing feature.
    let resolve = ["metadata", "--offline", "--format-version", "1"];
    match breaks(&features, &toolchain, &resolve, OLD_FEATURE)? {
        None => println!("features: a dependency on feature {OLD_FEATURE} resolves"),
        Some(errors) => {
            println!("features: {}", error_lines(&errors, 1));
            broken.push("features");
        }
    }

    let api = consumer(&root, &work.join("api"), "old-api", "", OLD_ITEMS)?;
    let check = ["check", "--offline", "--quiet"];
    match breaks(&api, &toolchain, &check, UNRESOLVED_IMPORT)? {
        None => println!("api: code using Completion and ErrorCode builds"),
        Some(errors) => {
            println!("api: {}", error_lines(&errors, 2));
            broken.push("API");
        }
    }

    let notes = withdrawn_notes(&read(&root, "CHANGELOG.md")?).to_lowercase();
    let missing: Vec<&str> = broken
        .iter()
        .copied()
        .filter(|word| !notes.contains(&word.to_lowercase()))
        .collect();
    if missing.is_empty() {
        let breaks = if broken.is_empty() {
            "none".to_owned()
        } else {
            broken.join(" ")
        };
        println!("PASS: breaks: {breaks}; the 0.1.0 notes name them");
        return Ok(true);
    }
    println!(
        "FAIL: a consumer of the withdrawn 0.1.0 breaks on: {}; the 0.1.0 notes never name: {}",
        broken.join(" "),
        missing.join(" ")
    );
    Ok(false)
}

/// Writes a consumer crate of mhfe-core by path into `folder`, with the repository's lockfile, so
/// that it resolves offline to the versions the crate locks.
fn consumer(root: &Path, folder: &Path, name: &str, features: &str, main: &str) -> Result<PathBuf> {
    let path = root.to_str().ok_or("the repository's path is not UTF-8")?;
    // The empty workspace table keeps the consumer apart from any workspace above the folder.
    let manifest = format!(
        "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
         [dependencies]\nmhfe-core = {{ path = {path:?}{features} }}\n\n[workspace]\n"
    );
    let write = || -> std::io::Result<()> {
        fs::create_dir_all(folder.join("src"))?;
        fs::copy(root.join("Cargo.lock"), folder.join("Cargo.lock"))?;
        fs::write(folder.join("Cargo.toml"), manifest)?;
        fs::write(folder.join("src/main.rs"), main)
    };
    write().map_err(|error| format!("{}: {error}", folder.display()))?;
    Ok(folder.to_path_buf())
}

/// Runs cargo on a consumer: None when it succeeds, its error output when it fails the way a user
/// of the withdrawn package would meet, which names `sign`. A failure for another reason, such as
/// a dependency missing from the offline cache, says nothing about the notes and is an error.
fn breaks(
    folder: &Path,
    toolchain: &str,
    arguments: &[&str],
    sign: &str,
) -> Result<Option<String>> {
    let output = Command::new("cargo")
        .args(arguments)
        .current_dir(folder)
        .env("RUSTUP_TOOLCHAIN", toolchain)
        .output()
        .map_err(|error| format!("cargo: {error}"))?;
    if output.status.success() {
        return Ok(None);
    }
    let errors = String::from_utf8_lossy(&output.stderr).into_owned();
    if !errors.contains(sign) {
        let folder = folder.display();
        return Err(format!(
            "cargo {} in {folder} failed for another reason:\n{errors}",
            arguments.join(" ")
        )
        .into());
    }
    Ok(Some(errors))
}

/// The first `count` lines of cargo's output that start with "error", on one line.
fn error_lines(errors: &str, count: usize) -> String {
    errors
        .lines()
        .filter(|line| line.starts_with("error"))
        .take(count)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The channel of the repository's rust-toolchain.toml.
fn channel(toolchain: &str) -> Result<String> {
    toolchain
        .lines()
        .find_map(|line| line.strip_prefix("channel = \"")?.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(|| "rust-toolchain.toml names no channel".into())
}

fn read(root: &Path, path: &str) -> Result<String> {
    fs::read_to_string(root.join(path)).map_err(|error| format!("{path}: {error}").into())
}

/// The repository that holds this harness, four folders above this crate
/// (docs/audits/AUD-002-harnesses/skeptic-doc-withdrawn).
fn repository() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .map(Path::to_path_buf)
        .ok_or_else(|| "the harness is not inside a repository's docs/audits/".into())
}
