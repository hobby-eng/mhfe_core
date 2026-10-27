//! AUD-002-BLD001 and DOC001 as the release commit settles them. The owner kept version 0.1.0
//! and accepted both findings instead of the audit's fix (0.2.0), so this checks what the release
//! holds: one version, 0.1.0, in the manifest, the lockfile's root entry, the first CHANGELOG
//! section and `cargo pkgid`; a non-empty release-notes section, found as release.yml's notes step
//! finds it; and no `cargo update` advice anywhere in the CHANGELOG.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{Result, Verdicts};

/// The version the release keeps: the owner's decision on AUD-002-BLD001.
const VERSION: &str = "0.1.0";
/// The command of release.yml's step "Check the tag and write the release notes" that selects the
/// section; `notes` below does what it does.
const NOTES_STEP: &str =
    r#"awk -v version="$version" '/^## / { inside = ($2 == version); next } inside'"#;
/// The cleanup advice of dec9c81's CHANGELOG, which the release leaves out.
const ADVICE: &str = "cargo update";

/// The value of the first line `version = "..."` after the line `after`, or of the first one
/// when `after` is empty.
fn version_after<'a>(text: &'a str, after: &str) -> &'a str {
    text.lines()
        .skip_while(|line| !after.is_empty() && *line != after)
        .find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"'))
        .unwrap_or("none")
}

/// The lines release.yml's awk prints: those under a `## ` heading whose second field is `version`.
fn notes<'a>(changelog: &'a str, version: &str) -> Vec<&'a str> {
    let mut inside = false;
    let mut lines = Vec::new();
    for line in changelog.lines() {
        if line.starts_with("## ") {
            inside = line.split_whitespace().nth(1) == Some(version);
        } else if inside {
            lines.push(line);
        }
    }
    lines
}

pub(crate) fn run(checkout: &Path) -> Result<bool> {
    let read = |file: &str| fs::read_to_string(checkout.join(file));
    let changelog = read("CHANGELOG.md")?;
    let manifest = read("Cargo.toml")?;
    let lock = read("Cargo.lock")?;
    let output = Command::new("cargo")
        .args(["pkgid", "--locked", "--offline"])
        .current_dir(checkout)
        .output()?;
    if !output.status.success() {
        return Err(format!("cargo pkgid: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    let pkgid = String::from_utf8(output.stdout)?;
    // release.yml takes what follows the last `#` or `@`: `sed 's/.*[#@]//'`.
    let pkgid = pkgid.trim().rsplit(['#', '@']).next().unwrap_or("none");
    let first_section = changelog.lines().find(|line| line.starts_with("## "));
    let versions = [
        version_after(&manifest, ""),
        version_after(&lock, "name = \"mhfe-core\""),
        first_section
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("none"),
        pkgid,
    ];
    let [manifest, locked, heading, _] = versions;
    println!("manifest {manifest}, Cargo.lock {locked}, CHANGELOG {heading}, cargo pkgid {pkgid}");

    let mut verdicts = Verdicts::default();
    let one = versions.iter().all(|version| *version == VERSION);
    verdicts.check(one, "one-version", &format!("every place names {VERSION}"));

    let workflow = read(".github/workflows/release.yml")?;
    let section = notes(&changelog, pkgid);
    let found = workflow.contains(NOTES_STEP) && section.iter().any(|line| !line.trim().is_empty());
    let detail = format!("release.yml's notes step finds the section of {pkgid} and it has text");
    verdicts.check(found, "release-notes", &detail);
    let joined = section.join("\n");
    if let Some(paragraph) = joined.split("\n\n").find(|text| text.contains("withdrawn")) {
        println!(
            "withdrawn paragraph: {}",
            paragraph.split_whitespace().collect::<Vec<_>>().join(" ")
        );
    }

    // Collapsed whitespace finds the advice across a line break as well.
    let flat = changelog.split_whitespace().collect::<Vec<_>>().join(" ");
    let advised = flat.contains(ADVICE);
    verdicts.check(
        !advised,
        "no-cleanup-advice",
        &format!("the CHANGELOG has no `{ADVICE}`"),
    );
    Ok(!verdicts.failed)
}
