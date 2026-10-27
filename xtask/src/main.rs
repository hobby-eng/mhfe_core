//! The tools of the mhfe-core repository (TOOL-01), run from anywhere in it as `cargo xtask
//! <task>`:
//!
//! - `check`: the fast checks that CI's `checks` job runs on every push (CORE-43): every gate
//!   below, dprint, rustfmt, Clippy, rustdoc, the tests and the Argon2 stack check.
//! - `code-rules`: the rules of the coding guide that the compiler, Clippy and the formatters
//!   cannot see.
//! - `copies [--tokens N]`: code copied from one place to another (CORE-10).
//! - `public-api`: the public items against `docs/public-api.txt`.
//! - `vendored`: the vendored trees against the files their documents record.
//! - `argon2-stack`: the stack the Argon2 C code leaves written, on Linux.
//!
//! A gate prints what it checked and exits 0, or prints what it refused and exits 1.

mod argon2_stack;
mod check;
mod code_rules;
mod copies;
mod public_api;
mod vendored;

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Why a task failed, as the message printed before exit code 1: a gate's refusals, a tool that
/// could not run, or a wrong argument (RUST-04's exception for a program's own messages).
#[derive(Debug)]
pub(crate) struct Failure(pub(crate) String);

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

const USAGE: &str = "usage: cargo xtask <check | code-rules | copies [--tokens N] | public-api | \
                     vendored | argon2-stack>";

/// The repository's root: the folder above this crate's.
pub(crate) fn root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap_or(manifest).to_path_buf()
}

/// Runs `task` with its arguments.
pub(crate) fn run(task: &str, arguments: &[String]) -> Result<(), Failure> {
    let root = root();
    match (task, arguments) {
        ("check", []) => check::run(&root),
        ("code-rules", []) => code_rules::run(&root),
        ("copies", arguments) => copies::run(&root, arguments),
        ("public-api", []) => public_api::run(&root),
        ("vendored", []) => vendored::run(&root),
        ("argon2-stack", []) => argon2_stack::run(&root),
        _ => Err(Failure(USAGE.to_owned())),
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some((task, rest)) = arguments.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    match run(task, rest) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("{failure}");
            ExitCode::FAILURE
        }
    }
}
