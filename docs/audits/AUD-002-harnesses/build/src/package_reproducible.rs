//! CHECK-BLD-004: builds the crate's package twice, from two clones of one commit, the second with
//! every file's time moved to 2001, and requires
//!   1. the two `.crate` files to be byte-identical;
//!   2. every packaged file but the three Cargo writes to be the commit's blob, the package's
//!      `Cargo.lock` the commit's (without the entries of other workspace members, which the
//!      release commit has), and `Cargo.toml.orig` the commit's `Cargo.toml`;
//!   3. the package's file list to be the include list's tracked files plus Cargo's four.

use std::collections::BTreeSet;
use std::fs::{self, File, FileTimes};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::Error;
use crate::tools;

const USAGE: &str = "usage: package-reproducible <repository> <commit> <work>";

/// 2001-01-01T00:00:00Z in seconds since the Unix epoch: a time no checkout has, so a package
/// that recorded file times would differ.
const OLD_TIME_SECONDS: u64 = 978_307_200;

/// The line that opens the manifest's include list; its `]` closes it at the start of a line.
const INCLUDE: &str = "\ninclude = [\n";

/// The files Cargo writes into every package.
const CARGO_FILES: [&str; 4] = [
    ".cargo_vcs_info.json",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
];

pub(crate) fn run(arguments: &[String]) -> Result<bool, Error> {
    let [repository, commit, work] = arguments else {
        return Err(Error(USAGE.to_owned()));
    };
    let repository = Path::new(repository);
    let work = tools::work_folder(work)?;
    let mut packages = Vec::new();
    for copy in ["one", "two"] {
        let clone = work.join(copy);
        tools::clone_at(repository, commit, &clone)?;
        if copy == "two" {
            let old = SystemTime::UNIX_EPOCH + Duration::from_secs(OLD_TIME_SECONDS);
            set_times(&clone, FileTimes::new().set_accessed(old).set_modified(old))?;
        }
        packages.push(package(&clone, &work.join(format!("{copy}-target")))?);
    }
    let [first, second] = packages.as_slice() else {
        return Err(Error("two packages expected".to_owned()));
    };
    let first_bytes = fs::read(first)?;
    let second_bytes = fs::read(second)?;
    let mut passed = true;
    if first_bytes == second_bytes {
        println!(
            "1. byte-identical packages: {}  {}",
            tools::sha256_hex(&first_bytes),
            first.file_name().unwrap_or_default().to_string_lossy()
        );
    } else {
        println!(
            "1. FAILED: the packages differ: {} {} {} {}",
            tools::sha256_hex(&first_bytes),
            first.display(),
            tools::sha256_hex(&second_bytes),
            second.display()
        );
        passed = false;
    }

    let root = extract(first, &work.join("extracted"))?;
    let packaged = tools::files_under(&root)?;
    passed &= blobs_match(repository, commit, &root, &packaged)?;
    passed &= list_matches(&work.join("one"), &packaged)?;
    let vcs_info = fs::read_to_string(root.join(".cargo_vcs_info.json"))?;
    println!("cargo_vcs_info: {}", vcs_info.replace(['\n', ' '], ""));
    Ok(passed)
}

/// Sets the times of every file and folder of a clone but its `.git`.
fn set_times(folder: &Path, times: FileTimes) -> Result<(), Error> {
    for entry in fs::read_dir(folder)? {
        let path = entry?.path();
        if path.file_name().is_some_and(|name| name == ".git") {
            continue;
        }
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_symlink() {
            return Err(Error(format!(
                "{}: a link, whose own time is not set",
                path.display()
            )));
        }
        if kind.is_dir() {
            set_times(&path, times)?;
        }
        File::open(&path)?.set_times(times)?;
    }
    Ok(File::open(folder)?.set_times(times)?)
}

/// Packages a clone offline and returns its one `.crate` file.
fn package(clone: &Path, target: &Path) -> Result<PathBuf, Error> {
    tools::remove_folder(target)?;
    let log = clone.with_extension("package.log");
    let packaged = tools::logged(
        tools::tool("cargo")
            .args([
                "package",
                "--locked",
                "--offline",
                "--no-verify",
                "--manifest-path",
            ])
            .arg(clone.join("Cargo.toml"))
            .env("CARGO_TARGET_DIR", target),
        &log,
    )?;
    if !packaged {
        return Err(Error(format!(
            "cargo package failed; see {}",
            log.display()
        )));
    }
    let crates: Vec<PathBuf> = fs::read_dir(target.join("package"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "crate")
        })
        .collect();
    match crates.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(Error(format!("no single .crate in {}", target.display()))),
    }
}

/// Extracts a package and returns its one top folder.
fn extract(package: &Path, into: &Path) -> Result<PathBuf, Error> {
    tools::remove_folder(into)?;
    fs::create_dir_all(into)?;
    tools::output(
        tools::tool("tar")
            .args(["--extract", "--gzip", "--file"])
            .arg(package)
            .arg("--directory")
            .arg(into),
    )?;
    let tops: Vec<PathBuf> = fs::read_dir(into)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()?;
    match tops.as_slice() {
        [top] if top.is_dir() => Ok(top.clone()),
        _ => Err(Error(format!("no single folder in {}", into.display()))),
    }
}

/// Check 2: every packaged file against the commit's blobs.
fn blobs_match(
    repository: &Path,
    commit: &str,
    root: &Path,
    packaged: &[String],
) -> Result<bool, Error> {
    let blob = |path: &str| {
        tools::output(
            tools::tool("git")
                .arg("-C")
                .arg(repository)
                .arg("show")
                .arg(format!("{commit}:{path}")),
        )
    };
    let manifest = String::from_utf8(blob("Cargo.toml")?).map_err(|e| Error(e.to_string()))?;
    let name = tools::manifest_value(&manifest, "name")
        .ok_or_else(|| Error("Cargo.toml has no name".to_owned()))?;
    let mut mismatches = 0;
    let mut other_members = Vec::new();
    for path in packaged {
        let expected = match path.as_str() {
            ".cargo_vcs_info.json" | "Cargo.toml" => continue,
            "Cargo.toml.orig" => manifest.clone().into_bytes(),
            "Cargo.lock" => {
                let lock = String::from_utf8(blob(path)?).map_err(|e| Error(e.to_string()))?;
                let (kept, removed) = without_other_members(&lock, name);
                other_members = removed;
                kept.into_bytes()
            }
            _ => blob(path)?,
        };
        if fs::read(root.join(path))? != expected {
            println!("   differs from {commit}:{path}");
            mismatches += 1;
        }
    }
    if !other_members.is_empty() {
        println!(
            "   Cargo.lock compared without the entries of the workspace's {}, which the package \
             does not build",
            other_members.join(", ")
        );
    }
    if mismatches == 0 {
        println!(
            "2. every packaged file equals the commit's blob (Cargo.lock and Cargo.toml.orig included)"
        );
        return Ok(true);
    }
    println!("2. FAILED: {mismatches} packaged files differ from the commit");
    Ok(false)
}

/// A lockfile without the `[[package]]` entries that have no source (the workspace's members)
/// other than `name`, and the names it removed: Cargo writes the package's lockfile that way.
fn without_other_members(lock: &str, name: &str) -> (String, Vec<String>) {
    const HEADING: &str = "[[package]]\n";
    let mut bodies = lock.split(HEADING);
    let mut kept = bodies.next().unwrap_or_default().to_owned();
    let mut removed = Vec::new();
    let mut last_removed = false;
    for body in bodies {
        let entry = tools::manifest_value(body, "name").unwrap_or_default();
        last_removed = !body.contains("\nsource = ") && entry != name;
        if last_removed {
            removed.push(entry.to_owned());
        } else {
            kept.push_str(HEADING);
            kept.push_str(body);
        }
    }
    // An entry removed at the end leaves behind the blank line that came before it.
    if last_removed && kept.ends_with("\n\n") {
        kept.pop();
    }
    (kept, removed)
}

/// The paths of the manifest's include list, one `"/path/",` per line, without the quotes, the
/// comma and the slashes, as `git ls-files` takes them; None when the manifest has none. The
/// release commit's list has `LICENSE-MIT` and `LICENSE-APACHE` where dec9c81's has `LICENSE`.
fn include_list(manifest: &str) -> Option<Vec<&str>> {
    let start = manifest.find(INCLUDE)? + INCLUDE.len();
    let end = start + manifest[start..].find("\n]")?;
    let paths: Vec<&str> = manifest[start..end]
        .lines()
        .filter_map(|line| {
            let quoted = line.trim().trim_end_matches(',');
            quoted.strip_prefix('"')?.strip_suffix('"')
        })
        .map(|path| path.trim_matches('/'))
        .collect();
    (!paths.is_empty()).then_some(paths)
}

/// Check 3: the package's files against the include list's tracked files and Cargo's four.
fn list_matches(clone: &Path, packaged: &[String]) -> Result<bool, Error> {
    let manifest = fs::read_to_string(clone.join("Cargo.toml"))?;
    let include = include_list(&manifest)
        .ok_or_else(|| Error("Cargo.toml has no include list".to_owned()))?;
    let tracked = tools::output(
        tools::tool("git")
            .arg("-C")
            .arg(clone)
            .arg("ls-files")
            .args(include),
    )?;
    let tracked = String::from_utf8(tracked).map_err(|e| Error(e.to_string()))?;
    let expected: BTreeSet<&str> = tracked.lines().chain(CARGO_FILES).collect();
    let actual: BTreeSet<&str> = packaged.iter().map(String::as_str).collect();
    if expected == actual {
        println!(
            "3. the package holds the {} files of the include list",
            actual.len()
        );
        return Ok(true);
    }
    println!("3. FAILED: the package's files are not those of the include list");
    for missing in expected.difference(&actual) {
        println!("   missing: {missing}");
    }
    for extra in actual.difference(&expected) {
        println!("   extra: {extra}");
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::{include_list, without_other_members};

    #[test]
    fn the_include_list_is_read_as_git_paths() {
        let manifest = "[package]\ninclude = [\n  \"/src/\",\n  \"/LICENSE-MIT\",\n]\n\n[lib]\n";
        assert_eq!(include_list(manifest), Some(vec!["src", "LICENSE-MIT"]));
        assert_eq!(include_list("[package]\nname = \"x\"\n"), None);
    }

    const ROOT: &str = "[[package]]\nname = \"mhfe-core\"\nversion = \"0.1.0\"\n";
    const SHA2: &str = "[[package]]\nname = \"sha2\"\nversion = \"0.11.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    const XTASK: &str =
        "[[package]]\nname = \"xtask\"\nversion = \"0.0.0\"\ndependencies = [\n \"sha2\",\n]\n";
    const HEADER: &str = "# This file is automatically @generated by Cargo.\nversion = 4\n";

    #[test]
    fn a_lockfile_without_other_members_is_unchanged() {
        let lock = format!("{HEADER}\n{ROOT}\n{SHA2}");
        assert_eq!(
            without_other_members(&lock, "mhfe-core"),
            (lock.clone(), Vec::new())
        );
    }

    #[test]
    fn a_member_between_entries_goes_with_its_blank_line() {
        let lock = format!("{HEADER}\n{ROOT}\n{XTASK}\n{SHA2}");
        let expected = format!("{HEADER}\n{ROOT}\n{SHA2}");
        assert_eq!(
            without_other_members(&lock, "mhfe-core"),
            (expected, vec!["xtask".to_owned()])
        );
    }

    #[test]
    fn a_member_at_the_end_goes_with_the_blank_line_before_it() {
        let lock = format!("{HEADER}\n{ROOT}\n{SHA2}\n{XTASK}");
        let expected = format!("{HEADER}\n{ROOT}\n{SHA2}");
        assert_eq!(
            without_other_members(&lock, "mhfe-core"),
            (expected, vec!["xtask".to_owned()])
        );
    }
}
