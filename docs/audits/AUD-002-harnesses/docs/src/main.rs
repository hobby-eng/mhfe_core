//! AUD-002 documentation checks of mhfe-core (see README.md beside this crate), run on the
//! working tree of the repository that holds this harness. Each check prints PASS, FAIL or SKIP
//! with what it found. Exit 0 when every check passed, 1 when one failed, 2 when none failed but
//! one could not run or the harness stopped on an error: an unknown state is never a pass
//! (CORE-22).
//!
//!   aud002-doc-claims [mhfe-core-0.1.0.crate]

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use sha2::{Digest, Sha256};

mod notes;
use notes::withdrawn_notes;

/// A harness prints its errors and stops; it has no module errors to tell apart.
type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The exit code when a check failed.
const FAILED: u8 = 1;
/// The exit code when a check could not run or the harness stopped on an error.
const UNDECIDED: u8 = 2;
/// The SHA-256 of the withdrawn `mhfe-core-0.1.0.crate`, which crates.io served from 2026-10-25
/// until it was deleted (the publication record of that release).
const WITHDRAWN_SHA256: &str = "bc23d4d1dcdbdcef54100eb9a04cd6634ca37898ea1098e4385505724906269d";
/// The folder in which `cargo package` put the files of the withdrawn package.
const WITHDRAWN_FOLDER: &str = "mhfe-core-0.1.0";
/// The Windows read-back of `no_core_dumps` in src/os/windows.rs: the NOHEAP flag of error
/// reports, and nothing else.
const NOHEAP_READBACK: &str = "no_core_dumps: read && flags & WER_FAULT_REPORTING_FLAG_NOHEAP";
/// The opening of the field doc of `no_core_dumps` that the finding quotes (src/protect.rs:130 at
/// dec9c81).
const NO_DUMP_PROMISE: &str = "/// A crash writes no core dump";
/// What an error report on Windows still holds, which the documents must name.
const RESIDUE: &str = "stack";

fn main() -> ExitCode {
    let package = std::env::args_os().nth(1).map(PathBuf::from);
    match run(package.as_deref()) {
        Ok(report) => report.exit_code(),
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::from(UNDECIDED)
        }
    }
}

fn run(package: Option<&Path>) -> Result<Report> {
    let root = repository()?;
    let mut report = Report::default();
    audit_references(&root, &mut report)?;
    windows_wording(&root, &mut report)?;
    match package {
        Some(package) => withdrawn_release(&root, package, &mut report)?,
        None => report.skip("withdrawn-release", "no withdrawn package given"),
    }
    Ok(report)
}

/// DOC-003: no tracked file outside docs/audits/ names an audit record. The corpora, the
/// specification's repository (the submodule `tests/spec`, which git lists as one folder) and the
/// vendored trees are data, which the code-rules gate does not read either.
fn audit_references(root: &Path, report: &mut Report) -> Result<()> {
    let listing = output(Command::new("git").arg("-C").arg(root).args([
        "ls-files",
        "-z",
        "--",
        ".",
        ":!docs/audits",
        ":!tests/fixtures",
        ":!tests/spec",
        ":!vendor",
    ]))?;
    let mut found = Vec::new();
    for path in listing.split('\0').filter(|path| !path.is_empty()) {
        let bytes = match fs::read(root.join(path)) {
            Ok(bytes) => bytes,
            // A tracked file deleted from the working tree names nothing.
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("{path}: {error}").into()),
        };
        // grep -I's rule, which the original script followed: a file with a NUL byte is binary.
        if bytes.contains(&0) {
            continue;
        }
        for (index, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
            if names_audit(line) {
                found.push(format!("{path}:{}:{line}", index + 1));
            }
        }
    }
    report.check(
        "audit-references",
        found.is_empty(),
        "no tracked file names an audit record",
        &found.join("\n"),
    );
    Ok(())
}

/// The original script's pattern `AUD-[0-9]`: an audit identifier such as AUD-002.
fn names_audit(line: &str) -> bool {
    line.match_indices("AUD-")
        .any(|(at, _)| line.as_bytes().get(at + 4).is_some_and(u8::is_ascii_digit))
}

/// DOC-001: on Windows `no_core_dumps` reads back only the NOHEAP flag, so a crash still writes an
/// error report whose dump holds the threads' stacks. The field doc must not say that a crash
/// writes no core dump, and SECURITY.md's Windows section must name what the report keeps.
fn windows_wording(root: &Path, report: &mut Report) -> Result<()> {
    if !read(root, "src/os/windows.rs")?.contains(NOHEAP_READBACK) {
        report.skip(
            "no-core-dumps",
            "src/os/windows.rs no longer reads back the NOHEAP flag alone; re-read the finding",
        );
        return Ok(());
    }
    let promise = read(root, "src/protect.rs")?
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains(NO_DUMP_PROMISE))
        .map(|(index, line)| format!("src/protect.rs:{}:{line}", index + 1));
    report.check(
        "no-core-dumps-field",
        promise.is_none(),
        "the field doc does not promise no dump on Windows",
        promise.as_deref().unwrap_or_default(),
    );
    let security = read(root, "SECURITY.md")?;
    // The `### Windows` section, up to the next heading of its level or above.
    let windows: Vec<&str> = security
        .lines()
        .skip_while(|line| *line != "### Windows")
        .skip(1)
        .take_while(|line| !line.starts_with("### ") && !line.starts_with("## "))
        .collect();
    report.check(
        "windows-report-residue",
        windows.join("\n").to_lowercase().contains(RESIDUE),
        "SECURITY.md's Windows section names the stacks of an error report",
        "SECURITY.md's Windows section never names the threads' stacks that an error report keeps",
    );
    Ok(())
}

/// DOC-001: the 0.1.0 notes replace a withdrawn 0.1.0. Every difference a user of that package
/// meets (licence, features, public API) must be named in the CHANGELOG paragraph that says so.
fn withdrawn_release(root: &Path, package: &Path, report: &mut Report) -> Result<()> {
    let bytes = fs::read(package).map_err(|error| format!("{}: {error}", package.display()))?;
    let digest: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if digest != WITHDRAWN_SHA256 {
        return Err(format!(
            "{}: SHA-256 {digest}, not the withdrawn package's {WITHDRAWN_SHA256}",
            package.display()
        )
        .into());
    }
    let old = Surface::of(
        &package_file(package, "Cargo.toml")?,
        &package_file(package, "src/lib.rs")?,
    )?;
    let new = Surface::of(&read(root, "Cargo.toml")?, &read(root, "src/lib.rs")?)?;
    println!("withdrawn: {old}");
    println!("snapshot:  {new}");
    let notes = withdrawn_notes(&read(root, "CHANGELOG.md")?);
    let lower = notes.to_lowercase();
    let mut missing = Vec::new();
    if old.licence != new.licence && !lower.contains("licen") {
        missing.push("licence");
    }
    if old.features != new.features && !lower.contains("feature") {
        missing.push("features");
    }
    if old.modules != new.modules && !notes.contains("API") {
        missing.push("API");
    }
    report.check(
        "withdrawn-release",
        missing.is_empty(),
        "the 0.1.0 notes name every difference from the withdrawn package",
        &format!(
            "the 0.1.0 notes do not name these differences: {}",
            missing.join(" ")
        ),
    );
    Ok(())
}

/// What a user of a package meets: its licence, its features (`default` left out) and its public
/// modules.
struct Surface {
    licence: String,
    features: usize,
    modules: usize,
}

impl Surface {
    fn of(manifest: &str, lib: &str) -> Result<Self> {
        let licence = manifest
            .lines()
            .find_map(|line| line.strip_prefix("license = \"")?.strip_suffix('"'))
            .ok_or("a manifest without a licence line")?;
        let features = manifest
            .lines()
            .skip_while(|line| *line != "[features]")
            .skip(1)
            .take_while(|line| !line.starts_with('['))
            .filter(|line| line.contains(" = ") && !line.starts_with("default "))
            .count();
        let modules = lib
            .lines()
            .filter(|line| line.starts_with("pub mod "))
            .count();
        Ok(Self {
            licence: licence.to_owned(),
            features,
            modules,
        })
    }
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "licence \"{}\", ", self.licence)?;
        match self.features {
            0 => write!(f, "no features")?,
            count => write!(f, "{count} features")?,
        }
        write!(f, ", {} public modules", self.modules)
    }
}

/// The repository that holds this harness, four folders above this crate
/// (docs/audits/AUD-002-harnesses/docs).
fn repository() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .map(Path::to_path_buf)
        .ok_or_else(|| "the harness is not inside a repository's docs/audits/".into())
}

fn read(root: &Path, path: &str) -> Result<String> {
    fs::read_to_string(root.join(path)).map_err(|error| format!("{path}: {error}").into())
}

/// A file of the withdrawn package, read with `tar` from its gzip archive.
fn package_file(package: &Path, path: &str) -> Result<String> {
    output(
        Command::new("tar")
            .arg("-xzOf")
            .arg(package)
            .arg(format!("{WITHDRAWN_FOLDER}/{path}")),
    )
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

/// The verdicts printed so far.
#[derive(Default)]
struct Report {
    failed: bool,
    undecided: bool,
}

impl Report {
    fn check(&mut self, name: &str, passed: bool, pass: &str, fail: &str) {
        if passed {
            println!("PASS {name}: {pass}");
        } else {
            println!("FAIL {name}: {fail}");
            self.failed = true;
        }
    }

    fn skip(&mut self, name: &str, reason: &str) {
        println!("SKIP {name}: {reason}");
        self.undecided = true;
    }

    fn exit_code(&self) -> ExitCode {
        if self.failed {
            ExitCode::from(FAILED)
        } else if self.undecided {
            ExitCode::from(UNDECIDED)
        } else {
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_audit_identifier_is_found_and_a_bare_prefix_is_not() {
        assert!(names_audit(
            "    /// AUD-002-SEC001: long runs out of canonical order"
        ));
        assert!(!names_audit("AUD-x, and AUD- at the end: AUD-"));
    }
}
