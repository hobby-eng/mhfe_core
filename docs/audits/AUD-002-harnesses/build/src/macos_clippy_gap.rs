//! CHECK-BLD-002: whether some CI job lints the macOS-only code with Clippy. In a clone of the
//! commit it plants two Clippy violations in `mod macos` of `src/os/apple.rs`, which only a macOS
//! build compiles: an `unwrap()` (`clippy::unwrap_used`) and an unsafe block without its SAFETY
//! comment (`clippy::undocumented_unsafe_blocks`). It then runs, with a stand-in C compiler, the
//! commands of the CI jobs that could see that code:
//!   - checks: `cargo clippy --locked --all-targets -- -D warnings` on its Linux host;
//!   - ios: each `cargo clippy` line of the job's Lint step, read from the commit's `ci.yml`, for
//!     `$TARGET` or, without `--target`, for the job's macOS host;
//!   - native (macos-latest): `cargo test --locked` with `RUSTFLAGS=-D warnings`, of which the
//!     compile part, `cargo check --all-targets` for aarch64-apple-darwin, is run here;
//!
//! and, as the control, `cargo clippy --all-targets` for aarch64-apple-darwin, which must refuse
//! the violations. Passes when at least one CI command refuses them.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::Error;
use crate::tools;

const USAGE: &str = "usage: macos-clippy-gap <repository> <commit> <stand-in C compiler> <work>";

/// The file with `mod macos`, and the two plants in it.
const APPLE: &str = "src/os/apple.rs";
const CHECKED: &str = "let pid = libc::c_int::try_from(std::process::id()).ok()?;";
const UNWRAPPED: &str = "let pid = libc::c_int::try_from(std::process::id()).unwrap();";
const SAFETY_COMMENT: &str = "SAFETY: frees the message sandbox_init allocated, once.";

/// The host of GitHub's `macos-latest` runners, which are Apple silicon.
const MACOS_HOST: &str = "aarch64-apple-darwin";

/// The ios job's heading in `ci.yml`.
const IOS_JOB: &str = "  ios:";

pub(crate) fn run(arguments: &[String]) -> Result<bool, Error> {
    let [repository, commit, stand_in, work] = arguments else {
        return Err(Error(USAGE.to_owned()));
    };
    let stand_in = tools::existing_file(stand_in)?;
    let work = tools::work_folder(work)?;
    let clone = work.join("macos-clone");
    tools::clone_at(Path::new(repository), commit, &clone)?;
    tools::submodules_from(Path::new(repository), &clone)?;
    let file = clone.join(APPLE);
    let planted = plant(&fs::read_to_string(&file)?).ok_or_else(|| {
        Error(format!(
            "the violations could not be planted: {APPLE} changed"
        ))
    })?;
    fs::write(&file, planted)?;
    print!(
        "{}",
        String::from_utf8_lossy(&tools::output(
            tools::tool("git")
                .arg("-C")
                .arg(&clone)
                .args(["diff", "--stat"])
        )?)
    );

    let ios = ios_lint(&fs::read_to_string(clone.join(".github/workflows/ci.yml"))?)?;
    let cargo = |arguments: &[String]| {
        let mut command = tools::tool("cargo");
        command
            .args(arguments)
            .current_dir(&clone)
            .env("CARGO_TARGET_DIR", work.join("macos-target"))
            .env("CC_aarch64_apple_darwin", &stand_in)
            .env("AR_aarch64_apple_darwin", "ar")
            .env("CC_aarch64_apple_ios", &stand_in)
            .env("AR_aarch64_apple_ios", "ar")
            // No Apple SDK here: the cc crate must not look for one.
            .env("SDKROOT", "/nonexistent")
            .env("CRATE_CC_NO_DEFAULTS", "1")
            // The iOS version the ios job of ci.yml sets.
            .env("IPHONEOS_DEPLOYMENT_TARGET", "13.0")
            .env_remove("RUSTFLAGS");
        command
    };
    let words = |line: &str| {
        line.split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };

    let mut caught = false;
    caught |= !passes(
        &work,
        "checks",
        &mut cargo(&words(
            "clippy --locked --offline --all-targets -- -D warnings",
        )),
    )?;
    for (target, arguments) in &ios {
        caught |= !passes(&work, &format!("ios-{target}"), &mut cargo(arguments))?;
    }
    let native = words(&format!(
        "check --locked --offline --all-targets --target {MACOS_HOST}"
    ));
    caught |= !passes(
        &work,
        "native-macos",
        cargo(&native).env("RUSTFLAGS", "-D warnings"),
    )?;
    let control = words(&format!(
        "clippy --locked --offline --all-targets --target {MACOS_HOST} -- -D warnings"
    ));
    if passes(&work, "control-clippy-macos", &mut cargo(&control))? {
        return Err(Error(
            "the control did not refuse the planted violations".to_owned(),
        ));
    }
    if caught {
        println!("a CI command refuses Clippy violations in the macOS-only code");
    } else {
        println!("FAILED: no CI command refuses Clippy violations in the macOS-only code");
    }
    Ok(caught)
}

/// The file with both violations planted, or None when either place is gone.
fn plant(source: &str) -> Option<String> {
    let unwrapped = source
        .contains(CHECKED)
        .then(|| source.replacen(CHECKED, UNWRAPPED, 1))?;
    let kept: String = unwrapped
        .split_inclusive('\n')
        .filter(|line| !line.contains(SAFETY_COMMENT))
        .collect();
    (kept.len() < unwrapped.len()).then_some(kept)
}

/// The ios job's `cargo clippy` lines, each as its target and Cargo's arguments: `$TARGET` is
/// the job's target, a line without `--target` lints the macOS host, and every line runs offline.
fn ios_lint(ci: &str) -> Result<Vec<(String, Vec<String>)>, Error> {
    let job: Vec<&str> = ci
        .lines()
        .skip_while(|line| *line != IOS_JOB)
        .skip(1)
        .take_while(|line| !is_job_heading(line))
        .collect();
    let target = job
        .iter()
        .find_map(|line| line.trim().strip_prefix("TARGET: "))
        .ok_or_else(|| Error("ci.yml has no ios job with a TARGET".to_owned()))?;
    let mut commands = Vec::new();
    for line in &job {
        let line = line.trim();
        let Some(rest) = line
            .strip_prefix("run: ")
            .unwrap_or(line)
            .strip_prefix("cargo clippy ")
        else {
            continue;
        };
        let mut arguments: Vec<String> = vec!["clippy".to_owned(), "--offline".to_owned()];
        arguments.extend(
            rest.split_whitespace()
                .map(|word| word.replace("\"$TARGET\"", target)),
        );
        let lint_target = match arguments.iter().position(|word| word == "--target") {
            Some(index) => arguments.get(index + 1).cloned().unwrap_or_default(),
            None => {
                let end = arguments
                    .iter()
                    .position(|word| word == "--")
                    .unwrap_or(arguments.len());
                arguments.splice(end..end, ["--target".to_owned(), MACOS_HOST.to_owned()]);
                MACOS_HOST.to_owned()
            }
        };
        commands.push((lint_target, arguments));
    }
    Ok(commands)
}

/// A job's heading in a workflow: two spaces, a name and a colon.
fn is_job_heading(line: &str) -> bool {
    line.strip_prefix("  ")
        .is_some_and(|rest| !rest.starts_with([' ', '#']) && rest.ends_with(':'))
}

/// Runs one command and prints whether it passes or which Clippy lints refused it.
fn passes(work: &Path, name: &str, command: &mut Command) -> Result<bool, Error> {
    let log = work.join(format!("{name}.log"));
    if tools::logged(command, &log)? {
        println!("passes: {name}");
        return Ok(true);
    }
    let text = fs::read_to_string(&log)?;
    let mut lints: Vec<&str> = text
        .match_indices("clippy::")
        .map(|(start, _)| {
            let rest = &text[start..];
            let end = rest["clippy::".len()..]
                .find(|c: char| !(c.is_ascii_lowercase() || c == '_' || c == '-'))
                .map_or(rest.len(), |end| end + "clippy::".len());
            &rest[..end]
        })
        .collect();
    lints.sort_unstable();
    lints.dedup();
    // A command that fails without a Clippy lint failed for another reason than the plants, such
    // as a tree that does not build; counting it as a refusal would pass the harness wrongly.
    if lints.is_empty() {
        return Err(Error(format!(
            "{name} failed without a Clippy lint: {}",
            log.display()
        )));
    }
    println!("refuses: {name} ({})", lints.join(" "));
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::ios_lint;

    const JOBS: &str = "jobs:\n  ios:\n    runs-on: macos-latest\n    env:\n      TARGET: aarch64-apple-ios\n    steps:\n";
    const NEXT_JOB: &str =
        "  wasm:\n    steps:\n      - run: cargo clippy --locked --all-targets -- -D warnings\n";

    fn arguments(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn the_reviewed_lint_step_lints_the_ios_target_only() {
        let ci = format!(
            "{JOBS}      - name: Lint\n        run: cargo clippy --locked --all-targets --target \"$TARGET\" -- -D warnings\n{NEXT_JOB}"
        );
        let expected = arguments(
            "clippy --offline --locked --all-targets --target aarch64-apple-ios -- -D warnings",
        );
        assert_eq!(
            ios_lint(&ci).unwrap(),
            vec![("aarch64-apple-ios".to_owned(), expected)]
        );
    }

    #[test]
    fn a_lint_line_without_a_target_lints_the_macos_host() {
        let ci = format!(
            "{JOBS}      - name: Lint\n        run: |\n          cargo clippy --locked --all-targets --target \"$TARGET\" -- -D warnings\n          cargo clippy --locked --all-targets -- -D warnings\n{NEXT_JOB}"
        );
        let lints = ios_lint(&ci).unwrap();
        let host = arguments(
            "clippy --offline --locked --all-targets --target aarch64-apple-darwin -- -D warnings",
        );
        assert_eq!(lints.len(), 2);
        assert_eq!(lints[1], ("aarch64-apple-darwin".to_owned(), host));
    }
}
