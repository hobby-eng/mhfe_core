//! AUD-002 skeptic check of the withdrawn report "lib.rs repeats the manifest's unsafe_code lint",
//! reviewed commit dec9c8115ff9ddbd32bb5fdd457ae9904043c966.
//!
//! In two exports of <commit>, each with one planted unsafe block in src/suite.rs and one with
//! src/lib.rs's `#![deny(unsafe_code)]` removed, runs `cargo check --locked --offline` four ways
//! and requires:
//!
//! - A, attribute kept, no RUSTFLAGS: refused, at the lint level of src/lib.rs;
//! - B, attribute removed, no RUSTFLAGS: refused, by the manifest's `-D unsafe-code`;
//! - C, attribute kept, RUSTFLAGS=-Aunsafe_code: refused, since the source attribute wins;
//! - D, attribute removed, RUSTFLAGS=-Aunsafe_code: accepted, since the command line overrides the
//!   manifest's [lints].
//!
//! C against D shows that the attribute is not redundant. Each run's output is written to
//! <work>/check-<case>.log. Exits 0 when all four hold, 1 when one differs, 2 when the check could
//! not run.
//!
//!   aud002-skeptic-arc-unsafe <repository> <commit> <work folder>

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

/// The planted function, appended to src/suite.rs as the shell version did. Its SAFETY comment is
/// there because real code needs one (RUST-07); `cargo check` runs no Clippy, so only the
/// `unsafe_code` lint can refuse it.
const PROBE: &str = "
// SAFETY: reads a live, aligned, initialised local through a shared reference.
pub(crate) fn skeptic_probe() -> u8 { unsafe { core::ptr::read(&1u8) } }
";
const ATTRIBUTE: &str = "#![deny(unsafe_code)]";
/// The manifest's lint, which Cargo passes to rustc as `-D unsafe-code`.
const MANIFEST_LINT: &str = "unsafe_code = \"deny\"";
/// Cargo's exit code when the compiler refuses the crate.
const REFUSED: i32 = 101;
/// rustc's error for the planted block, and where each refusal says its lint level comes from.
const UNSAFE_ERROR: &str = "error: usage of an `unsafe` block";
const LEVEL_IN_SOURCE: &str = "--> src/lib.rs:";
const LEVEL_FROM_MANIFEST: &str = "requested on the command line with `-D unsafe-code`";
/// Exit code when the check could not run, apart from 1, "a case differs".
const NOT_RUN: u8 = 2;

/// One `cargo check` run and the result it must give.
struct Case {
    name: &'static str,
    /// Whether src/lib.rs keeps its attribute.
    attribute: bool,
    rustflags: Option<&'static str>,
    exit: i32,
    /// Text the output must hold.
    says: &'static [&'static str],
}

const CASES: [Case; 4] = [
    Case {
        name: "A",
        attribute: true,
        rustflags: None,
        exit: REFUSED,
        says: &[UNSAFE_ERROR, LEVEL_IN_SOURCE],
    },
    Case {
        name: "B",
        attribute: false,
        rustflags: None,
        exit: REFUSED,
        says: &[UNSAFE_ERROR, LEVEL_FROM_MANIFEST],
    },
    Case {
        name: "C",
        attribute: true,
        rustflags: Some("-Aunsafe_code"),
        exit: REFUSED,
        says: &[UNSAFE_ERROR, LEVEL_IN_SOURCE],
    },
    Case {
        name: "D",
        attribute: false,
        rustflags: Some("-Aunsafe_code"),
        exit: 0,
        says: &[],
    },
];

/// Why the check could not run.
#[derive(Debug)]
struct Failure(String);

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Failure {}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

/// The export of <commit> for `attribute`: src-keep keeps it, src-drop has it removed.
fn tree(work: &Path, attribute: bool) -> PathBuf {
    work.join(if attribute { "src-keep" } else { "src-drop" })
}

/// Writes the files of `commit` into `folder` through `git archive | tar -x`.
fn export(repository: &Path, commit: &str, folder: &Path) -> Result<(), Failure> {
    if folder.exists() {
        fs::remove_dir_all(folder)?;
    }
    fs::create_dir_all(folder)?;
    let mut archive = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["archive", commit])
        .stdout(Stdio::piped())
        .spawn()?;
    let stream = archive
        .stdout
        .take()
        .ok_or_else(|| Failure("git archive gave no output stream".to_owned()))?;
    let unpacked = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(folder)
        .stdin(stream)
        .status()?;
    let archived = archive.wait()?;
    if !archived.success() || !unpacked.success() {
        return Err(Failure(format!("git archive {commit} | tar -x failed")));
    }
    Ok(())
}

/// Removes the attribute from the export's src/lib.rs, and checks that its manifest still denies
/// the lint, so that B tests the manifest alone.
fn remove_attribute(folder: &Path) -> Result<(), Failure> {
    let lib = folder.join("src/lib.rs");
    let text = fs::read_to_string(&lib)?;
    let kept: Vec<&str> = text.lines().filter(|line| *line != ATTRIBUTE).collect();
    if kept.len() == text.lines().count() {
        return Err(Failure(format!("src/lib.rs has no line {ATTRIBUTE}")));
    }
    let kept = kept.join("\n") + "\n";
    if kept.contains("deny(unsafe_code)") {
        return Err(Failure("src/lib.rs still denies unsafe_code".to_owned()));
    }
    fs::write(&lib, kept)?;
    let manifest = fs::read_to_string(folder.join("Cargo.toml"))?;
    if !manifest.lines().any(|line| line.starts_with(MANIFEST_LINT)) {
        return Err(Failure(format!("Cargo.toml has no {MANIFEST_LINT}")));
    }
    Ok(())
}

/// Runs one case and says whether it gave its result.
fn check(case: &Case, work: &Path) -> Result<bool, Failure> {
    let folder = tree(work, case.attribute);
    let mut cargo = Command::new("cargo");
    cargo
        .args(["check", "--locked", "--offline", "--manifest-path"])
        .arg(folder.join("Cargo.toml"))
        // The export's rust-toolchain.toml then picks the toolchain.
        .current_dir(&folder)
        // Cargo reads CARGO_ENCODED_RUSTFLAGS before RUSTFLAGS: neither may come from outside.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");
    // Separate target folders, so that a change of flags does not rebuild every dependency.
    if let Some(flags) = case.rustflags {
        cargo
            .env("RUSTFLAGS", flags)
            .env("CARGO_TARGET_DIR", work.join("target-flags"));
    } else {
        cargo.env("CARGO_TARGET_DIR", work.join("target-plain"));
    }
    let output = cargo.output()?;
    let mut log = fs::File::create(work.join(format!("check-{}.log", case.name)))?;
    log.write_all(&output.stdout)?;
    log.write_all(&output.stderr)?;
    let got = output
        .status
        .code()
        .ok_or_else(|| Failure(format!("{}: cargo check ended by a signal", case.name)))?;
    let text = String::from_utf8_lossy(&output.stderr);
    let missing: Vec<&str> = case
        .says
        .iter()
        .copied()
        .filter(|says| !text.contains(says))
        .collect();
    if got == case.exit && missing.is_empty() {
        println!("{}: ok (exit {got})", case.name);
        return Ok(true);
    }
    println!(
        "{}: FAIL (exit {got}, wanted {}; missing {missing:?})",
        case.name, case.exit
    );
    Ok(false)
}

fn run(arguments: &[String]) -> Result<bool, Failure> {
    let [repository, commit, work] = arguments else {
        return Err(Failure(
            "usage: aud002-skeptic-arc-unsafe <repository> <commit> <work folder>".to_owned(),
        ));
    };
    let (repository, work) = (Path::new(repository), Path::new(work));
    for attribute in [true, false] {
        let folder = tree(work, attribute);
        export(repository, commit, &folder)?;
        fs::OpenOptions::new()
            .append(true)
            .open(folder.join("src/suite.rs"))?
            .write_all(PROBE.as_bytes())?;
    }
    remove_attribute(&tree(work, false))?;
    let mut holds = true;
    for case in &CASES {
        holds &= check(case, work)?;
    }
    Ok(holds)
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(failure) => {
            eprintln!("error: {failure}");
            ExitCode::from(NOT_RUN)
        }
    }
}
