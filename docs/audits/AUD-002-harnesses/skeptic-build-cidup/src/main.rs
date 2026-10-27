//! AUD-002 skeptic check of the finding AUD-002-ARC001, "CI repeats two commands of the checks
//! job", reviewed commit dec9c8115ff9ddbd32bb5fdd457ae9904043c966.
//!
//! Exits 1 when <commit>'s ci.yml has another job run a command of the checks job's fast checks
//! again on the checks job's runner: the `cargo test` command of the native matrix, or the wasm
//! job's Lint line. The fast checks are the lines of scripts/check-fast.sh. At a commit where the
//! checks job runs `cargo xtask check` instead, its commands are Rust code that this program does
//! not read: a repeat that ci.yml offers is then unknown (exit 2), and no candidate means none.
//!
//! Given the log of a CI run (`gh run view <id> --log`), it also prints the runner images and the
//! sorted test lines of the checks job and of the native job on the same runner, for comparison;
//! they do not change the exit code.
//!
//! Exits 0 when no command repeats, 1 when one does, 2 when the check could not tell.
//!
//!   aud002-skeptic-build-cidup <repository> <commit> [<log of gh run view --log>]

use std::fmt;
use std::fs;
use std::process::{Command, ExitCode};

const WORKFLOW: &str = ".github/workflows/ci.yml";
const CHECK_FAST: &str = "scripts/check-fast.sh";
const XTASK_CHECK: &str = "xtask/src/check.rs";
/// The log's step names of the two test runs that the run log compares.
const CHECKS_STEP: &str = "Run the fast checks";
const NATIVE_STEP: &str = "Run the fast tests";
/// The last line check-fast.sh prints, which shows that every line before it ran.
const ALL_PASSED: &str = "All fast checks passed.";
/// Exit code when the check could not tell, apart from 1, "a command repeats".
const NOT_TOLD: u8 = 2;

/// Why the check could not tell.
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

/// The file at `path` in `commit`, or `None` when the commit has no such file.
fn show(repository: &str, commit: &str, path: &str) -> Result<Option<String>, Failure> {
    let object = format!("{commit}:{path}");
    let git = |arguments: &[&str]| {
        Command::new("git")
            .args(["-C", repository])
            .args(arguments)
            .output()
    };
    if !git(&["cat-file", "-e", &object])?.status.success() {
        return Ok(None);
    }
    let output = git(&["show", &object])?;
    if !output.status.success() {
        return Err(Failure(format!("git show {object} failed")));
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
}

/// The lines of a job of ci.yml, from its key at two spaces to the next key at that depth.
fn job<'a>(ci: &'a str, name: &str) -> Option<Vec<&'a str>> {
    let key = format!("  {name}:");
    let mut lines = ci.lines().skip_while(|line| *line != key);
    lines.next()?;
    let next_key = |line: &&str| {
        line.strip_prefix("  ")
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_lowercase()))
    };
    Some(lines.take_while(|line| !next_key(line)).collect())
}

/// The value of the first key `name` in `job`.
fn field<'a>(job: &[&'a str], name: &str) -> Option<&'a str> {
    let label = format!("{name}: ");
    job.iter()
        .find_map(|line| line.trim().strip_prefix(label.as_str()))
}

/// The fast checks of the checks job: the lines of check-fast.sh, or `None` when they are the
/// Rust code of `cargo xtask check`.
struct FastChecks(Option<String>);

impl FastChecks {
    fn read(repository: &str, commit: &str) -> Result<Self, Failure> {
        if let Some(script) = show(repository, commit, CHECK_FAST)? {
            println!("fast checks: {CHECK_FAST}");
            return Ok(Self(Some(script)));
        }
        if show(repository, commit, XTASK_CHECK)?.is_some() {
            println!("fast checks: cargo xtask check ({XTASK_CHECK}), whose lines are not read");
            return Ok(Self(None));
        }
        Err(Failure(format!(
            "{commit} has neither {CHECK_FAST} nor {XTASK_CHECK}"
        )))
    }

    /// The line number of `command` in check-fast.sh: `Some(None)` when it is not a line of it,
    /// `None` when the fast checks are Rust code.
    fn line_of(&self, command: &str) -> Option<Option<usize>> {
        let script = self.0.as_ref()?;
        Some(
            script
                .lines()
                .position(|line| line == command)
                .map(|at| at + 1),
        )
    }
}

/// The commands that another job runs on the checks job's runner, each with that job's name.
fn candidates(ci: &str, runner: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    if let Some(native) = job(ci, "native") {
        let systems = field(&native, "os").unwrap_or_default();
        let command = native
            .iter()
            .find_map(|line| {
                let command = line.trim().strip_prefix("run: ")?;
                command.starts_with("cargo test").then_some(command)
            })
            .unwrap_or_default();
        println!("native matrix: {systems}");
        println!("native command: {command}");
        let on_runner = systems
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .any(|system| system.trim() == runner);
        if on_runner && !command.is_empty() {
            found.push((command.to_owned(), format!("native ({runner})")));
        }
    }
    if let Some(wasm) = job(ci, "wasm") {
        let lint = wasm
            .iter()
            .position(|line| line.trim() == "- name: Lint")
            .and_then(|at| wasm.get(at + 1))
            .map(|line| {
                let line = line.trim();
                line.strip_prefix("run: ").unwrap_or(line)
            })
            .unwrap_or_default();
        println!("wasm Lint: {lint}");
        if field(&wasm, "runs-on") == Some(runner) && !lint.is_empty() {
            found.push((lint.to_owned(), "wasm".to_owned()));
        }
    }
    found
}

fn run(arguments: &[String]) -> Result<bool, Failure> {
    let (repository, commit, run_log) = match arguments {
        [repository, commit] => (repository, commit, None),
        [repository, commit, run_log] => (repository, commit, Some(run_log)),
        _ => {
            return Err(Failure(
                "usage: aud002-skeptic-build-cidup <repository> <commit> [<run log>]".to_owned(),
            ));
        }
    };
    let ci = show(repository, commit, WORKFLOW)?
        .ok_or_else(|| Failure(format!("{commit} has no {WORKFLOW}")))?;
    let fast = FastChecks::read(repository, commit)?;
    let runner = job(&ci, "checks")
        .and_then(|checks| field(&checks, "runs-on").map(str::to_owned))
        .ok_or_else(|| Failure("ci.yml has no checks job with runs-on".to_owned()))?;
    println!("checks runs-on: {runner}");
    let mut repeated = 0;
    let mut unknown = 0;
    for (command, job) in candidates(&ci, &runner) {
        match fast.line_of(&command) {
            Some(Some(line)) => {
                println!("REPEATED: '{command}' ({CHECK_FAST} line {line} and the {job} job)");
                repeated += 1;
            }
            Some(None) => println!("not a fast check: '{command}' ({job} job)"),
            None => {
                println!("UNKNOWN: whether cargo xtask check runs '{command}' ({job} job)");
                unknown += 1;
            }
        }
    }
    if let Some(run_log) = run_log {
        compare_runs(&fs::read_to_string(run_log)?, &runner);
    }
    println!("repeated commands: {repeated}");
    if unknown > 0 {
        return Err(Failure(format!(
            "{unknown} commands that may repeat cannot be told"
        )));
    }
    Ok(repeated == 0)
}

/// The step name `gh run view --log` writes when GitHub's log archive keeps a job's log as one
/// file, without one file per step, as it does for the runs of the published release.
const UNKNOWN_STEP: &str = "UNKNOWN STEP";

/// The text of each line of `job`'s `step` in a `gh run view --log` file, whose lines are
/// "job<TAB>step<TAB>timestamp text" and whose first line of a step may start with a byte-order
/// mark. In a log without step names, every line of the job counts.
fn step_lines<'a>(log: &'a str, job: &'a str, step: &'a str) -> impl Iterator<Item = &'a str> {
    log.lines().filter_map(move |line| {
        let mut fields = line.split('\t');
        if fields.next() != Some(job) {
            return None;
        }
        let named = fields.next()?;
        if named != step && named != UNKNOWN_STEP {
            return None;
        }
        let text = fields.next()?.trim_start_matches('\u{feff}');
        let stamp = |word: &str| {
            word.chars()
                .all(|c| c.is_ascii_digit() || "TZ:.-".contains(c))
        };
        Some(match text.split_once(' ') {
            Some((word, rest)) if !word.is_empty() && stamp(word) => rest,
            _ => text,
        })
    })
}

/// The runner image a job's set-up step names.
fn image<'a>(log: &'a str, job: &'a str) -> &'a str {
    step_lines(log, job, "Set up job")
        .find_map(|line| line.rsplit_once("Image Release: ").map(|(_, image)| image))
        .unwrap_or_default()
}

/// The test lines of one step, each with the test binary it belongs to, without the binary's
/// hash and the timing, and sorted: tests run on parallel threads, so their order varies.
fn tests(log: &str, job: &str, step: &str) -> Vec<(String, String)> {
    let mut binary = String::new();
    let mut lines: Vec<(String, String)> = step_lines(log, job, step)
        .filter(|line| {
            let trimmed = line.trim_start();
            line.starts_with("test ")
                || (line.starts_with(' ')
                    && (trimmed.starts_with("Running ") || trimmed.starts_with("Doc-tests")))
        })
        .map(|line| {
            let line = without_timing(&without_binary_path(line));
            if line.starts_with(' ') {
                binary.clone_from(&line);
            }
            (binary.clone(), line)
        })
        .collect();
    lines.sort();
    lines
}

/// `line` without " (target/debug/deps/<binary>)".
fn without_binary_path(line: &str) -> String {
    const START: &str = " (target/debug/deps/";
    match line.split_once(START) {
        Some((before, after)) => match after.split_once(')') {
            Some((_, rest)) => format!("{before}{rest}"),
            None => line.to_owned(),
        },
        None => line.to_owned(),
    }
}

/// `line` without "; finished in <seconds>s".
fn without_timing(line: &str) -> String {
    const START: &str = "; finished in ";
    let Some((before, after)) = line.split_once(START) else {
        return line.to_owned();
    };
    let seconds = after.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.');
    match seconds.strip_prefix('s') {
        Some(rest) if seconds.len() < after.len() => format!("{before}{rest}"),
        _ => line.to_owned(),
    }
}

/// Prints the runner images and test lines of the checks job and the native job on `runner`.
fn compare_runs(log: &str, runner: &str) {
    let native = format!("native ({runner})");
    let (checks_image, native_image) = (image(log, "checks"), image(log, &native));
    println!("image checks: {checks_image}");
    println!("image {native}: {native_image}");
    let checks_tests = tests(log, "checks", CHECKS_STEP);
    let native_tests = tests(log, &native, NATIVE_STEP);
    println!(
        "test lines: checks {}, {native} {}",
        checks_tests.len(),
        native_tests.len()
    );
    if !checks_tests.is_empty() && checks_tests == native_tests && checks_image == native_image {
        println!("SAME RESULTS: identical test lines on the identical runner image");
    } else {
        println!("DIFFERENT RESULTS or runner images");
    }
    if step_lines(log, "checks", CHECKS_STEP).any(|line| line == ALL_PASSED) {
        println!("checks job printed '{ALL_PASSED}'");
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(failure) => {
            eprintln!("error: {failure}");
            ExitCode::from(NOT_TOLD)
        }
    }
}
