//! AUD-002 verification harnesses of mhfe-core, one subcommand per check:
//!
//! - `gate-skip <repository> <scratch folder>`: AUD-002-BLD003, the code-rules gate and `docs/audits/`.
//! - `macos-lint <repository> <stand-in C compiler> <work folder>`: AUD-002-BLD002, Clippy on the
//!   macOS-only code.
//! - `version <checkout>`: AUD-002-BLD001 and DOC001, the version and the release notes.
//!
//! Each prints a PASS or FAIL line per check and exits 0 when every check passes, 1 when one
//! fails, and 2 when it cannot run.

mod gate_skip;
mod macos_lint;
mod version;

use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "usage: aud002-verify gate-skip <repository> <scratch folder>
       aud002-verify macos-lint <repository> <stand-in C compiler> <work folder>
       aud002-verify version <checkout>";

/// The verdicts of one harness: a PASS or FAIL line per check, and whether one failed.
#[derive(Default)]
struct Verdicts {
    failed: bool,
}

impl Verdicts {
    fn check(&mut self, ok: bool, name: &str, detail: &str) {
        println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
        self.failed |= !ok;
    }
}

/// Runs git with `arguments` in `directory`, feeding it `input`, and returns its output; a git
/// that fails is an error.
fn git(directory: &Path, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input)?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {} failed: {}", arguments.join(" "), message.trim()).into());
    }
    Ok(output.stdout)
}

/// Checks out each submodule of `clone` from `repository`'s own checkout of it, offline. Since the
/// release commit the tests read the specification's vectors from the submodule `tests/spec`, so
/// Clippy on the test targets needs it, as CI checks out with `submodules: true`. A tree without
/// submodules is left as it is.
fn submodules_from(repository: &Path, clone: &Path) -> Result<()> {
    if !clone.join(".gitmodules").is_file() {
        return Ok(());
    }
    let source = fs::canonicalize(repository)?;
    let regexp = r"^submodule\..*\.path$";
    let paths = git(
        clone,
        &["config", "--file", ".gitmodules", "--get-regexp", regexp],
        &[],
    )?;
    for line in String::from_utf8_lossy(&paths).lines() {
        let (name, path) = line
            .strip_prefix("submodule.")
            .and_then(|rest| rest.split_once(".path "))
            .ok_or_else(|| format!(".gitmodules: unexpected line `{line}`"))?;
        let url = source.join(path);
        let url = url.to_str().ok_or("the repository's path is not UTF-8")?;
        git(
            clone,
            &["config", &format!("submodule.{name}.url"), url],
            &[],
        )?;
    }
    let update = [
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "--quiet",
        "update",
        "--init",
    ];
    git(clone, &update, &[])?;
    Ok(())
}

/// Clones `repository` into `clone` and applies its working-tree changes outside `docs/audits/`,
/// so that the clone holds the tree under check: the uncommitted fix, or a commit as it is.
fn clone_with_changes(repository: &Path, clone: &Path) -> Result<()> {
    match fs::remove_dir_all(clone) {
        Err(error) if error.kind() != ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    // A clone of a detached HEAD, as at dec9c81, would print git's advice on detached HEADs.
    let mut arguments: Vec<OsString> = vec!["-c".into(), "advice.detachedHead=false".into()];
    arguments.extend(["clone".into(), "--quiet".into()]);
    arguments.extend([
        repository.as_os_str().to_owned(),
        clone.as_os_str().to_owned(),
    ]);
    let status = Command::new("git").args(&arguments).status()?;
    if !status.success() {
        return Err(format!("git clone {} failed", repository.display()).into());
    }
    let diff = git(repository, &["diff", "--", ".", ":!docs/audits"], &[])?;
    // A commit that holds the fix leaves no diff, and `git apply` refuses an empty one (AUD-002 H3).
    if !diff.is_empty() {
        git(clone, &["apply"], &diff)?;
    }
    Ok(())
}

/// Copies the files of the folder `from` into the folder `to`, which may exist already.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let paths: Vec<&Path> = arguments.iter().skip(1).map(Path::new).collect();
    let outcome = match (
        arguments.first().and_then(|name| name.to_str()),
        paths.as_slice(),
    ) {
        (Some("gate-skip"), [repository, scratch]) => gate_skip::run(repository, scratch),
        (Some("macos-lint"), [repository, stand_in, work]) => {
            macos_lint::run(repository, stand_in, work)
        }
        (Some("version"), [checkout]) => version::run(checkout),
        _ => Err(USAGE.into()),
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
