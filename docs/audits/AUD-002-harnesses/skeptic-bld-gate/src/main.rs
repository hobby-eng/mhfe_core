//! AUD-002 skeptic check of the finding AUD-002-BLD003, "the code-rules gate reads docs/audits/",
//! reviewed commit dec9c8115ff9ddbd32bb5fdd457ae9904043c966.
//!
//! Clones <repository> at its checked-out commit into <scratch>/clone and runs that commit's
//! code-rules gate, `cargo xtask code-rules`, in five states:
//!
//! 1. the clean commit passes;
//! 2. a synthetic harness docs/audits/AUD-999-harnesses/probe/probe.rs with a lint exception
//!    without reason fails, naming that file;
//! 3. with this audit's harness folder copied in as well, the gate fails;
//! 4. with "docs/audits" among the gate's skipped folders (the proposed fix, added when the gate's
//!    source does not name it yet) the gate passes with both;
//! 5. with the fix, the same probe under tests/ still fails, so the fix hides nothing else.
//!
//! Exits 0 when every result is the one the finding states, 1 when one differs (at a commit with
//! the fix, states 2 and 3 pass), 2 when the check could not run. At a commit whose gate is still
//! the Node.js script of dec9c81, which this repository no longer runs (TOOL-01), it exits 2 and
//! names the archived run of that commit.
//!
//!   aud002-skeptic-bld-gate <repository> <AUD-002 harness folder> <scratch folder>

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const PROBE: &str = "docs/audits/AUD-999-harnesses/probe/probe.rs";
const PROBE_TEXT: &str = "#![allow(unsafe_code)]\nfn main() {}\n";
const PROBE_REFUSED: &str =
    "docs/audits/AUD-999-harnesses/probe/probe.rs: #![allow(unsafe_code)] has no reason";
const TESTS_PROBE: &str = "tests/probe.rs";
const TESTS_PROBE_REFUSED: &str = "tests/probe.rs: #![allow(unsafe_code)] has no reason";
/// Where state 3 puts the harness folder, as the audit record lies in the repository.
const HARNESSES: &str = "docs/audits/AUD-002-harnesses";
/// The skipped-folder entry the fix adds after the anchor, as the finding words it.
const ANCHOR: &str = "\"tests/fixtures\",";
const FIX: &str = "\"docs/audits\",";
/// Exit code when the check could not run, apart from 1, "a result differs".
const NOT_RUN: u8 = 2;
/// The code-rules gate: `cargo` with these arguments, from the clone's root.
const GATE: [&str; 2] = ["xtask", "code-rules"];
/// The folder whose files hold the gate's skipped-folder list, which the fix edits.
const GATE_SOURCES: &str = "xtask/src";
/// The code-rules gate of dec9c81, a Node.js script.
const NODE_GATE: &str = "scripts/verify-code-rules.mjs";
/// The archived run of this check at dec9c81, made with `NODE_GATE` by the audit record.
const NODE_GATE_RECORD: &str = "docs/audits/AUD-002-evidence/record-gate-reads-audits.log";

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

/// Runs `command` and returns its standard output, or fails with its error output.
fn output_of(command: &mut Command) -> Result<String, Failure> {
    let output = command.output()?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(Failure(format!("{command:?}: {}", error.trim())));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Every file under `folder`, recursively.
fn files_under(folder: &Path) -> Result<Vec<PathBuf>, Failure> {
    let mut files = Vec::new();
    for entry in fs::read_dir(folder)? {
        let path = entry?.path();
        if path.is_dir() {
            files.extend(files_under(&path)?);
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

/// Refuses a clone whose code-rules gate is not the xtask task: dec9c81's Node.js script, which
/// this repository no longer runs (TOOL-01), or a tree with neither.
fn require_xtask_gate(clone: &Path) -> Result<(), Failure> {
    if clone.join("xtask/Cargo.toml").is_file() {
        Ok(())
    } else if clone.join(NODE_GATE).is_file() {
        Err(Failure(format!(
            "the reviewed commit's code-rules gate is the Node.js script {NODE_GATE}, which this \
             repository no longer runs (TOOL-01); the original run of this check is the archived \
             evidence {NODE_GATE_RECORD} (local)"
        )))
    } else {
        Err(Failure(format!(
            "the commit has neither xtask/ nor {NODE_GATE}"
        )))
    }
}

/// The clone under test, and whether a result so far differs from the finding.
struct Run {
    clone: PathBuf,
    differs: bool,
}

impl Run {
    /// Runs the gate, prints its output, and checks its exit code and, when given, a line it must
    /// print.
    fn expect(&mut self, exit: i32, line: Option<&str>) -> Result<(), Failure> {
        let output = Command::new("cargo")
            .args(GATE)
            .current_dir(&self.clone)
            // The xtask task builds from the cargo cache alone.
            .env("CARGO_NET_OFFLINE", "true")
            .output()?;
        let text = String::from_utf8_lossy(&[output.stdout, output.stderr].concat()).into_owned();
        print!("{text}");
        // A gate exits 0 or 1; anything else means it did not run, which is not a result.
        let got = output
            .status
            .code()
            .filter(|code| matches!(code, 0 | 1))
            .ok_or_else(|| Failure(format!("the gate did not run: {}", output.status)))?;
        if got != exit {
            println!("FAIL exit {got}, expected {exit}");
            self.differs = true;
        } else if let Some(line) = line
            && !text.lines().any(|printed| printed == line)
        {
            println!("FAIL missing line: {line}");
            self.differs = true;
        } else {
            println!("PASS exit {got}");
        }
        Ok(())
    }

    fn write(&self, path: &str, text: &str) -> Result<(), Failure> {
        let path = self.clone.join(path);
        if let Some(folder) = path.parent() {
            fs::create_dir_all(folder)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    /// Copies the files of `harnesses` into the clone's audit folder.
    fn copy_in(&self, harnesses: &Path) -> Result<(), Failure> {
        let target = self.clone.join(HARNESSES);
        for file in files_under(harnesses)? {
            let relative = file
                .strip_prefix(harnesses)
                .map_err(|error| Failure(error.to_string()))?;
            let copy = target.join(relative);
            if let Some(folder) = copy.parent() {
                fs::create_dir_all(folder)?;
            }
            fs::copy(&file, copy)?;
        }
        Ok(())
    }

    /// Puts the fix into the gate's source unless a source already names "docs/audits" there,
    /// and says which.
    fn apply_fix(&self) -> Result<String, Failure> {
        let sources = files_under(&self.clone.join(GATE_SOURCES))?;
        let shown = |path: &Path| {
            let relative = path.strip_prefix(&self.clone).unwrap_or(path);
            relative.display().to_string()
        };
        for path in &sources {
            if fs::read_to_string(path)?.contains("\"docs/audits") {
                return Ok(format!("already in {}", shown(path)));
            }
        }
        for path in &sources {
            let text = fs::read_to_string(path)?;
            let mut lines: Vec<&str> = text.split('\n').collect();
            let Some((at, anchor)) = lines
                .iter()
                .enumerate()
                .find(|(_, line)| line.trim() == ANCHOR)
                .map(|(at, line)| (at, *line))
            else {
                continue;
            };
            let indent = &anchor[..anchor.len() - anchor.trim_start().len()];
            let fix = format!("{indent}{FIX}");
            lines.insert(at + 1, &fix);
            fs::write(path, lines.join("\n"))?;
            return Ok(format!("added to {}", shown(path)));
        }
        Err(Failure(format!("no line {ANCHOR} in the gate's source")))
    }
}

fn run(arguments: &[String]) -> Result<bool, Failure> {
    let [repository, harnesses, scratch] = arguments else {
        return Err(Failure(
            "usage: aud002-skeptic-bld-gate <repository> <AUD-002 harness folder> <scratch folder>"
                .to_owned(),
        ));
    };
    // The program never changes its working folder, so relative arguments keep their meaning;
    // the shell version's `cd` broke a relative harness folder (AUD-002 H2).
    let harnesses = Path::new(harnesses);
    let commit = output_of(Command::new("git").args(["-C", repository]).args([
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
    ]))?;
    let commit = commit.trim();
    let clone = Path::new(scratch).join("clone");
    if clone.exists() {
        fs::remove_dir_all(&clone)?;
    }
    output_of(
        Command::new("git")
            .args(["clone", "--quiet", repository])
            .arg(&clone),
    )?;
    output_of(
        Command::new("git")
            .arg("-C")
            .arg(&clone)
            .args(["checkout", "--quiet", "--detach", commit]),
    )?;
    require_xtask_gate(&clone)?;
    let mut run = Run {
        clone,
        differs: false,
    };
    println!("gate: cargo {}", GATE.join(" "));

    println!("== 1. clean {commit}");
    run.expect(0, None)?;

    println!("== 2. synthetic harness with an allow without reason");
    run.write(PROBE, PROBE_TEXT)?;
    run.expect(1, Some(PROBE_REFUSED))?;

    // The probe of state 2 stays, as in the finding's run.
    println!("== 3. this audit's harnesses copied in");
    run.copy_in(harnesses)?;
    run.expect(1, None)?;

    println!("== 4. the proposed fix: docs/audits in the skipped folders");
    println!("fix {}", run.apply_fix()?);
    print!(
        "{}",
        output_of(Command::new("git").arg("-C").arg(&run.clone).arg("diff"))?
    );
    run.expect(0, None)?;

    println!("== 5. with the fix, the probe under tests/ still fails");
    run.write(TESTS_PROBE, PROBE_TEXT)?;
    run.expect(1, Some(TESTS_PROBE_REFUSED))?;

    if run.differs {
        println!("Some results differ from the finding.");
    } else {
        println!("Every result matches the finding.");
    }
    Ok(!run.differs)
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
