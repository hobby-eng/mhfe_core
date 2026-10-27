//! AUD-002 second verification round: checks that no file of the repository outside `.git`,
//! `docs/audits`, `target` and `node_modules` changed after a reference file, and that no file
//! outside `docs/audits/` is untracked, and prints the working-tree diff's SHA-256, which names the
//! tree checked. Exit 0 when the tree is unchanged, 1 when a file is newer or untracked, 2 when it
//! cannot run.
//!
//!   aud002-verify2-tree-unchanged <repository> <reference file>

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The folders left out, relative to the repository: Git's, the audits' and the build outputs.
const LEFT_OUT: [&str; 4] = [".git", "docs/audits", "target", "node_modules"];
const SECONDS_PER_DAY: u64 = 86_400;

/// Adds to `newer` every file under `folder` modified after `reference`, relative to `root`.
fn newer_files(
    root: &Path,
    folder: &Path,
    reference: SystemTime,
    newer: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root)?.to_path_buf();
        let kind = entry.file_type()?;
        if kind.is_dir()
            && !LEFT_OUT
                .iter()
                .any(|left_out| relative == Path::new(left_out))
        {
            newer_files(root, &path, reference, newer)?;
        } else if kind.is_file() && entry.metadata()?.modified()? > reference {
            newer.push(relative);
        }
    }
    Ok(())
}

fn git(repository: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {} failed: {}", arguments.join(" "), message.trim()).into());
    }
    Ok(output.stdout)
}

/// `time` in UTC as `YYYY-MM-DDTHH:MM:SSZ`, by the days-to-civil algorithm of Howard Hinnant's
/// "chrono-Compatible Low-Level Date Algorithms" (dates after 1970 only).
fn utc(time: SystemTime) -> Result<String> {
    let seconds = time.duration_since(UNIX_EPOCH)?.as_secs();
    let (days, second) = (seconds / SECONDS_PER_DAY, seconds % SECONDS_PER_DAY);
    // Days since 0000-03-01, in eras of 400 years of 146,097 days.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);
    let (hour, minute) = (second / 3_600, second / 60 % 60);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{:02}Z",
        second % 60
    ))
}

fn listed(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(" ")
    }
}

fn run(repository: &Path, reference: &Path) -> Result<bool> {
    let modified = fs::metadata(reference)?.modified()?;
    let mut newer = Vec::new();
    newer_files(repository, repository, modified, &mut newer)?;
    let newer: Vec<String> = newer
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let untracked = git(repository, &["ls-files", "--others", "--exclude-standard"])?;
    let untracked: Vec<String> = String::from_utf8(untracked)?
        .lines()
        .filter(|path| !path.starts_with("docs/audits/"))
        .map(str::to_owned)
        .collect();
    let changed = String::from_utf8(git(repository, &["diff", "--name-only"])?)?
        .lines()
        .count();
    let digest = Sha256::digest(git(repository, &["diff"])?);
    let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    println!("reference: {} ({})", reference.display(), utc(modified)?);
    println!("modified tracked files: {changed}");
    println!("working-tree diff SHA-256: {digest}");
    println!("files newer than the reference: {}", listed(&newer));
    println!("untracked outside docs/audits: {}", listed(&untracked));
    Ok(newer.is_empty() && untracked.is_empty())
}

fn main() -> ExitCode {
    let arguments: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let outcome = match arguments.as_slice() {
        [repository, reference] => run(repository, reference),
        _ => Err("usage: aud002-verify2-tree-unchanged <repository> <reference file>".into()),
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("ERROR {error}");
            ExitCode::from(2)
        }
    }
}
