//! The fast checks of the repository, which CI's `checks` job runs on every push (CORE-43), run as
//! `cargo xtask check`: the gates, every fast test (the isolation and secret-memory tests and the
//! unit tests of this crate's gates among them) and the stack check of the Argon2 C code, in that
//! order, stopping at the first failure. Needs the pinned Rust toolchain with its wasm32 target, a
//! C compiler and dprint, which formats the Markdown, JSON, TOML and YAML with the plugins that
//! dprint.json pins. No full-cost Argon2id runs here: vectors.yml runs tests/full_cost.rs.

use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::{Child, Command};

use crate::Failure;

pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    gate("vendored", || crate::vendored::run(root))?;
    gate("code-rules", || crate::code_rules::run(root))?;
    // The self-test of the copies gate is its unit tests, which `cargo test` runs below.
    gate("copies", || crate::copies::run(root, &[]))?;
    gate("public-api", || crate::public_api::run(root))?;
    step(Command::new("dprint").arg("check").current_dir(root))?;
    // Every crate of the workspace, this one included (RUST-02).
    step(cargo(root).args(["fmt", "--all", "--check"]))?;
    step(cargo(root).args([
        "clippy",
        "--locked",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]))?;
    // Only the library is built for WebAssembly; this crate is a tool of the host.
    step(cargo(root).args([
        "clippy",
        "--locked",
        "-p",
        "mhfe-core",
        "--all-targets",
        "--target",
        "wasm32-unknown-unknown",
        "--",
        "-D",
        "warnings",
    ]))?;
    step(
        cargo(root)
            .args(["doc", "--locked", "--no-deps", "-p", "mhfe-core"])
            .env("RUSTDOCFLAGS", "-D warnings"),
    )?;
    step(cargo(root).args(["test", "--locked", "--workspace"]))?;
    gate("argon2-stack", || crate::argon2_stack::run(root))?;
    println!("All fast checks passed.");
    Ok(())
}

/// Cargo in the repository's root: the one that `cargo run` started this tool with, which it names
/// in `CARGO`, so that every step uses the toolchain of rust-toolchain.toml; `cargo` otherwise.
pub(crate) fn cargo(root: &Path) -> Command {
    let mut command = Command::new(env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")));
    command.current_dir(root);
    command
}

/// Runs `command` and returns what it wrote to its standard output where the caller piped it; a
/// command that does not start, or does not exit 0, is a failure named by its command line.
pub(crate) fn run_tool(command: &mut Command) -> Result<Vec<u8>, Failure> {
    let description = describe(command);
    let output = command
        .spawn()
        .and_then(Child::wait_with_output)
        .map_err(|error| Failure(format!("{description} could not run: {error}")))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(Failure(format!("{description} failed ({})", output.status)))
    }
}

/// Runs the gate `task` in this process, under the command that runs it alone.
fn gate(task: &str, gate: impl FnOnce() -> Result<(), Failure>) -> Result<(), Failure> {
    header(&format!("cargo xtask {task}"));
    gate()
}

/// Runs `command` under its command line.
fn step(command: &mut Command) -> Result<(), Failure> {
    header(&describe(command));
    run_tool(command)?;
    Ok(())
}

fn header(command_line: &str) {
    println!("==> {command_line}");
}

/// The command line of `command` as a person types it: its environment, then the program by its
/// name alone, since `CARGO` is a long path into the toolchain, then its arguments.
fn describe(command: &Command) -> String {
    let environment = command.get_envs().filter_map(|(name, value)| {
        value.map(|value| format!("{}=\"{}\"", name.display(), value.display()))
    });
    let program = Path::new(command.get_program());
    let name = program.file_name().unwrap_or(program.as_os_str());
    let arguments = command
        .get_args()
        .map(|argument| argument.display().to_string());
    environment
        .chain([name.display().to_string()])
        .chain(arguments)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;

    use super::*;

    #[test]
    fn a_command_is_described_as_a_person_types_it() {
        let mut command = Command::new("/toolchain/bin/cargo");
        command
            .args(["doc", "--no-deps"])
            .env("RUSTDOCFLAGS", "-D warnings");
        assert_eq!(
            describe(&command),
            r#"RUSTDOCFLAGS="-D warnings" cargo doc --no-deps"#
        );
    }

    #[test]
    fn a_tool_that_exits_0_returns_what_it_wrote() {
        let output = run_tool(
            cargo(&crate::root())
                .arg("--version")
                .stdout(Stdio::piped()),
        );
        assert!(output.is_ok_and(|output| output.starts_with(b"cargo ")));
    }

    #[test]
    fn a_tool_that_exits_otherwise_fails() {
        let failure = run_tool(
            cargo(&crate::root())
                .arg("no-such-command")
                .stderr(Stdio::null()),
        )
        .err()
        .map(|failure| failure.0);
        assert_eq!(
            failure.as_deref(),
            Some("cargo no-such-command failed (exit status: 101)")
        );
    }

    #[test]
    fn a_tool_that_does_not_start_fails() {
        let failure = run_tool(&mut Command::new("no-such-tool-of-xtask"))
            .err()
            .map(|failure| failure.0);
        assert!(
            failure.is_some_and(|failure| failure.starts_with("no-such-tool-of-xtask could not run: "))
        );
    }
}
