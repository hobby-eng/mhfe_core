//! The build harnesses of audit AUD-002 of mhfe-core, run from the repository root as
//! `aud002-build <harness> <arguments>`. Each one prints what it checked and exits 0 when every
//! check holds, 1 when one fails, and 2 when it cannot decide (a wrong argument, a tool that
//! failed, an input it does not recognise): an unknown result is never a pass (CORE-22).

mod lockfile_provenance;
mod macos_clippy_gap;
mod package_reproducible;
mod release_tag_step;
mod republished_version;
mod tools;
mod vendored_upstream;
mod windows_features_needed;

use std::fmt;
use std::process::ExitCode;

/// The exit code of a harness whose check failed.
const FAILED: u8 = 1;
/// The exit code of a harness that could not decide.
const UNDECIDED: u8 = 2;

const USAGE: &str = "usage: aud002-build <harness> <arguments>, the harness one of \
                     package-reproducible, release-tag-step, lockfile-provenance, \
                     vendored-upstream, windows-features-needed, macos-clippy-gap, \
                     republished-version";

/// Why a harness could not decide, as the message printed before exit code 2 (RUST-04's
/// exception for a program's own messages).
#[derive(Debug)]
struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self(format!("JSON: {error}"))
    }
}

/// Runs one harness: `Ok(true)` when every check holds, `Ok(false)` when one fails.
fn run(harness: &str, arguments: &[String]) -> Result<bool, Error> {
    match harness {
        "package-reproducible" => package_reproducible::run(arguments),
        "release-tag-step" => release_tag_step::run(arguments),
        "lockfile-provenance" => lockfile_provenance::run(arguments),
        "vendored-upstream" => vendored_upstream::run(arguments),
        "windows-features-needed" => windows_features_needed::run(arguments),
        "macos-clippy-gap" => macos_clippy_gap::run(arguments),
        "republished-version" => republished_version::run(arguments),
        _ => Err(Error(USAGE.to_owned())),
    }
}

fn main() -> ExitCode {
    let arguments: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect();
    let outcome = match arguments.as_deref() {
        Ok([harness, rest @ ..]) => run(harness, rest),
        Ok([]) => Err(Error(USAGE.to_owned())),
        Err(_) => Err(Error("an argument is not UTF-8".to_owned())),
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(FAILED),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(UNDECIDED)
        }
    }
}
