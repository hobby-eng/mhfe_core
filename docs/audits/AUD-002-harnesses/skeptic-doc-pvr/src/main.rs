//! AUD-002 skeptic check of the withdrawn report on SECURITY.md's reporting channel in mhfe-core
//! (see README.md beside this crate). Read-only `gh api` calls. It exits 1 when SECURITY.md at HEAD
//! names GitHub's security advisories while the public repository has private vulnerability
//! reporting off, and 2 when a call fails or answers what the check cannot read: an unknown state
//! is never a pass (CORE-22).
//!
//!   aud002-skeptic-doc-pvr [repository folder]   (default: the repository holding this harness)

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// A harness prints its errors and stops; it has no module errors to tell apart.
type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The exit code when the claim fails.
const FAILED: u8 = 1;
/// The exit code when the harness stopped on an error.
const UNDECIDED: u8 = 2;
/// The repository SECURITY.md sends reports to.
const REPOSITORY: &str = "hobby-eng/mhfe_core";
/// The repositories of the same protocol, printed for comparison.
const RELATED: [&str; 2] = ["hobby-eng/mhfe", "hobby-eng/mhfe-spec"];
/// The words of SECURITY.md's lines about reporting.
const REPORTING_WORDS: [&str; 4] = ["report", "advisor", "mail", "contact"];
/// An email address, for other contact routes in the tracked files (git grep -E).
const EMAIL: &str = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}";
/// Addresses that are no contact route: GitHub's no-reply addresses and examples.
const NOT_CONTACTS: [&str; 3] = ["noreply", "example.com", "example.org"];
/// The most addresses printed.
const MOST_ADDRESSES: usize = 20;
/// The reporting channel the withdrawn report was about.
const CHANNEL: &str = "security advisories";
/// A repository's facts as `gh api --jq` prints them: its visibility first.
const ABOUT: &str = concat!(
    r#".visibility + " archived=" + (.archived|tostring)"#,
    r#" + " has_issues=" + (.has_issues|tostring)"#
);
/// The visibilities GitHub gives a repository.
const VISIBILITIES: [&str; 3] = ["public", "private", "internal"];
/// GitHub's two answers on private vulnerability reporting.
const REPORTING_ON: &str = r#"{"enabled":true}"#;
const REPORTING_OFF: &str = r#"{"enabled":false}"#;

fn main() -> ExitCode {
    let repository = std::env::args_os().nth(1).map(PathBuf::from);
    match run(repository) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(FAILED),
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::from(UNDECIDED)
        }
    }
}

fn run(repository: Option<PathBuf>) -> Result<bool> {
    let repository = match repository {
        Some(folder) => folder,
        None => harness_repository()?,
    };
    let git = |arguments: &[&str]| -> Result<String> {
        output(
            Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(arguments),
        )
    };
    let head = git(&["rev-parse", "HEAD"])?;
    let security = git(&["show", "HEAD:SECURITY.md"])?;
    println!("== SECURITY.md reporting lines at {}", head.trim());
    for (index, line) in security.lines().enumerate() {
        let lower = line.to_lowercase();
        if REPORTING_WORDS.iter().any(|word| lower.contains(word)) {
            println!("{}:{line}", index + 1);
        }
    }
    println!("== other contact routes in tracked files (email addresses, security contact)");
    for line in contact_lines(&repository)?.iter().take(MOST_ADDRESSES) {
        println!("{line}");
    }
    let settings = Settings::of(REPOSITORY)?;
    // Printed for comparison only; an answer the check cannot read stops it all the same.
    for name in RELATED {
        Settings::of(name)?;
    }
    if refused(&security, &settings) {
        println!(
            "FAIL: SECURITY.md names GitHub security advisories; repository is {}; private \
             vulnerability reporting enabled={}",
            settings.visibility, settings.reporting
        );
        return Ok(false);
    }
    println!(
        "PASS: visibility={} pvr={}",
        settings.visibility, settings.reporting
    );
    Ok(true)
}

/// The withdrawn report's claim: SECURITY.md sends reports to GitHub's security advisories of a
/// public repository that does not accept them.
fn refused(security: &str, settings: &Settings) -> bool {
    security.to_lowercase().contains(CHANNEL)
        && settings.visibility == "public"
        && !settings.reporting
}

/// What GitHub says of a repository: its visibility, and whether private vulnerability reporting
/// is on.
struct Settings {
    visibility: String,
    reporting: bool,
}

impl Settings {
    /// Asks GitHub and prints the answers, as the original script did.
    fn of(name: &str) -> Result<Self> {
        let about =
            output(Command::new("gh").args(["api", &format!("repos/{name}"), "--jq", ABOUT]))?;
        let reporting = output(Command::new("gh").args([
            "api",
            &format!("repos/{name}/private-vulnerability-reporting"),
        ]))?;
        let (about, reporting) = (about.trim(), reporting.trim());
        println!("== {name}: {about} pvr={reporting}");
        let visibility = about.split(' ').next().unwrap_or_default();
        if !VISIBILITIES.contains(&visibility) {
            return Err(format!("{name}: unknown visibility in {about:?}").into());
        }
        let reporting = match reporting {
            REPORTING_ON => true,
            REPORTING_OFF => false,
            other => return Err(format!("{name}: unknown reporting answer {other:?}").into()),
        };
        Ok(Self {
            visibility: visibility.to_owned(),
            reporting,
        })
    }
}

/// The tracked lines of the working tree that hold an email address, the vendored trees and the
/// corpora left out.
fn contact_lines(repository: &Path) -> Result<Vec<String>> {
    let mut command = Command::new("git");
    command.arg("-C").arg(repository).args([
        "grep",
        "-n",
        "-I",
        "-E",
        EMAIL,
        "--",
        ":!vendor",
        ":!tests/fixtures",
    ]);
    let output = command
        .output()
        .map_err(|error| format!("{command:?}: {error}"))?;
    // git grep exits 1 when nothing matches, which is an answer, and above 1 on an error.
    if !matches!(output.status.code(), Some(0 | 1)) {
        let errors = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{command:?}: {}", errors.trim()).into());
    }
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter(|line| !NOT_CONTACTS.iter().any(|word| line.contains(word)))
        .map(str::to_owned)
        .collect())
}

/// The repository that holds this harness, four folders above this crate
/// (docs/audits/AUD-002-harnesses/skeptic-doc-pvr).
fn harness_repository() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .map(Path::to_path_buf)
        .ok_or_else(|| "the harness is not inside a repository's docs/audits/".into())
}

/// The standard output of a tool that must succeed.
fn output(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .map_err(|error| format!("{command:?}: {error}"))?;
    if !output.status.success() {
        let errors = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{command:?}: {}", errors.trim()).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_advisories_channel_is_refused_only_on_a_public_repository_without_private_reporting() {
        let text = "Report it privately through GitHub's Security Advisories.";
        let settings = |visibility: &str, reporting| Settings {
            visibility: visibility.to_owned(),
            reporting,
        };
        assert!(refused(text, &settings("public", false)));
        assert!(!refused(text, &settings("public", true)));
        assert!(!refused(text, &settings("private", false)));
        assert!(!refused("Report it by email.", &settings("public", false)));
    }
}
