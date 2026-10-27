//! AUD-002-BLD002, "No CI job runs Clippy on the macOS-only code". It checks that CI's ios job
//! (macos-latest, an aarch64-apple-darwin host) runs `cargo clippy --locked --all-targets -- -D
//! warnings`, and that this command, run here for aarch64-apple-darwin with a stand-in C compiler,
//! passes on the tree under check and refuses the two violations the finding planted in
//! `src/os/apple.rs`: an unwrap, and an unsafe block without its SAFETY comment.

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, ExitStatus};

use crate::{Result, Verdicts};

/// The host lint the fix adds to the ios job's Lint step.
const HOST_LINT: &str = "cargo clippy --locked --all-targets -- -D warnings";
/// The host of GitHub's macos-latest runner.
const TARGET: &str = "aarch64-apple-darwin";
/// The first planted violation: the line of `src/os/apple.rs` and its unwrapping copy.
const UNWRAP: [&str; 2] = [
    "let pid = libc::c_int::try_from(std::process::id()).ok()?;",
    "let pid = libc::c_int::try_from(std::process::id()).unwrap();",
];
/// The second planted violation: this comment of `src/os/apple.rs` is deleted.
const SAFETY: &str = "// SAFETY: frees the message sandbox_init allocated, once.";
/// The lints that must refuse the two violations.
const LINTS: [&str; 2] = ["unwrap_used", "undocumented_unsafe_blocks"];

/// The lines of the job `ios` of a workflow: from its key to the next job's key.
fn ios_job(workflow: &str) -> Vec<&str> {
    let job_key = |line: &&str| {
        line.strip_prefix("  ")
            .is_some_and(|key| key.starts_with(|c: char| c.is_ascii_lowercase()))
    };
    workflow
        .lines()
        .skip_while(|line| *line != "  ios:")
        .skip(1)
        .take_while(|line| !job_key(line))
        .collect()
}

/// Runs the host lint for aarch64-apple-darwin in `clone`, with its output in `log`.
fn clippy(clone: &Path, stand_in: &Path, log: &Path) -> Result<ExitStatus> {
    let output = File::create(log)?;
    Ok(Command::new("cargo")
        .args(["clippy", "--locked", "--all-targets", "--target", TARGET])
        .args(["--", "-D", "warnings"])
        .current_dir(clone)
        .env("CC_aarch64_apple_darwin", stand_in)
        .env("AR_aarch64_apple_darwin", "ar")
        .env("CARGO_NET_OFFLINE", "true")
        .stdout(output.try_clone()?)
        .stderr(output)
        .status()?)
}

/// Plants the two violations in `file`; false when one of their lines is missing.
fn plant(file: &Path) -> Result<bool> {
    let text = fs::read_to_string(file)?;
    if !text.contains(UNWRAP[0]) || !text.lines().any(|line| line.trim() == SAFETY) {
        return Ok(false);
    }
    let planted: String = text
        .replace(UNWRAP[0], UNWRAP[1])
        .lines()
        .filter(|line| line.trim() != SAFETY)
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(file, planted)?;
    Ok(true)
}

pub(crate) fn run(repository: &Path, stand_in: &Path, work: &Path) -> Result<bool> {
    let mut verdicts = Verdicts::default();
    let workflow = fs::read_to_string(repository.join(".github/workflows/ci.yml"))?;
    let job = ios_job(&workflow);
    let on_macos = job
        .iter()
        .any(|line| line.trim() == "runs-on: macos-latest");
    verdicts.check(
        on_macos,
        "ios job runs on macos-latest",
        "runs-on: macos-latest",
    );
    let lints_host = job.iter().any(|line| line.trim() == HOST_LINT);
    verdicts.check(lints_host, "ios job lints the host", HOST_LINT);

    // The C compiler runs in the build folders, so it needs a path that holds from anywhere.
    let stand_in = fs::canonicalize(stand_in)?;
    fs::create_dir_all(work)?;
    let clone = work.join("clone");
    crate::clone_with_changes(repository, &clone)?;
    crate::submodules_from(repository, &clone)?;
    let clean_log = work.join("clean.log");
    let clean = clippy(&clone, &stand_in, &clean_log)?.success();
    let name = format!("the tree passes the host lint for {TARGET}");
    verdicts.check(clean, &name, &clean_log.display().to_string());
    if !clean {
        let log = fs::read_to_string(&clean_log)?;
        let lines: Vec<&str> = log.lines().collect();
        println!("{}", lines[lines.len().saturating_sub(20)..].join("\n"));
    }

    if !plant(&clone.join("src/os/apple.rs"))? {
        verdicts.check(
            false,
            "the violations are planted",
            "a line to change is missing",
        );
        return Ok(false);
    }
    let planted_log = work.join("planted.log");
    if clippy(&clone, &stand_in, &planted_log)?.success() {
        verdicts.check(
            false,
            "the host lint refuses the planted violations",
            "it passes",
        );
    } else {
        let log = fs::read_to_string(&planted_log)?;
        for lint in LINTS {
            // Clippy writes a lint's name with underscores or with hyphens, by message.
            let named = log.contains(&format!("clippy::{lint}"))
                || log.contains(&format!("clippy::{}", lint.replace('_', "-")));
            verdicts.check(named, "the host lint refuses the planted violation", lint);
        }
    }
    Ok(!verdicts.failed)
}
