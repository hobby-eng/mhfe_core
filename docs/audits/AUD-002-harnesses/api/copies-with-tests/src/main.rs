//! AUD-002 api harness of mhfe-core (CHECK-ARC-002): the repository's copies gate (CORE-10) over
//! `src/` and `tests/` of a tree, the reviewed commit dec9c81's or the release commit's.
//!
//!   aud002-api-copies-with-tests <tree> <work>
//!
//! The gate is the release tree's `cargo xtask copies`: its source, `xtask/src/copies.rs` with its
//! tokenizer `xtask/src/copies/tokens.rs`, is compiled in unchanged, so this crate builds only in a
//! tree that has `xtask/`. dec9c81's own gate is a Node.js script, which this repository no longer
//! runs (TOOL-01). The gate reads `src/` and `xtask/src/` of a root; the root it gets is
//! `<work>/copies-with-tests`, replaced on every run, in which `src/` is the tree's `src/` with the
//! tree's `tests/` at `src/tests/`, and `xtask/src/` is empty.
//!
//! Exits 0 when the gate finds no copy, 1 when it names a copy, and 2 when it could not run (a
//! wrong argument, a file it cannot read), so that an unknown outcome never reads as either.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::process::ExitCode;

/// The copies gate of the release tree, compiled from its source. The path names the gate's
/// folder rather than its file, so that the gate's own `mod tokens;` finds `copies/tokens.rs`.
#[path = "../../../../../../xtask/src"]
mod xtask {
    pub(crate) mod copies;
}

/// Why the gate failed: the copies it names, or why it could not read a file. The gate takes this
/// type from the crate's root, as in the xtask crate.
#[derive(Debug)]
struct Failure(String);

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Failure {}

const USAGE: &str = "usage: aud002-api-copies-with-tests <tree> <work>";
/// The folder under `<work>` that holds the root the gate reads.
const ROOT: &str = "copies-with-tests";
/// The end of each line on which the gate names a copy: "a:1-9 = b:3-11 (53 tokens)".
const COPY_LINE_END: &str = " tokens)";
/// The exit code of a gate that named a copy; 0 is none.
const FOUND: u8 = 1;
/// The exit code of a check that could not run.
const BROKEN: u8 = 2;

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let [tree, work] = arguments.as_slice() else {
        eprintln!("{USAGE}");
        return ExitCode::from(BROKEN);
    };
    match check(Path::new(tree), Path::new(work)) {
        Ok(()) => ExitCode::SUCCESS,
        // The gate fails the same way when it names a copy and when it cannot read a file: only a
        // failure that names a copy is a verdict.
        Err(Failure(message)) if message.lines().any(|line| line.ends_with(COPY_LINE_END)) => {
            println!("{message}");
            ExitCode::from(FOUND)
        }
        Err(failure) => {
            eprintln!("{failure}");
            ExitCode::from(BROKEN)
        }
    }
}

/// Builds the gate's root under `work` from `src/` and `tests/` of `tree`, and runs the gate on
/// it, which prints its summary when it finds no copy.
fn check(tree: &Path, work: &Path) -> Result<(), Failure> {
    fs::create_dir_all(work).map_err(failed(work))?;
    let (tree_folder, work_folder) = (
        tree.canonicalize().map_err(failed(tree))?,
        work.canonicalize().map_err(failed(work))?,
    );
    // A root inside the tree would be copied into itself.
    if work_folder.starts_with(tree_folder) {
        return Err(Failure(format!(
            "<work> must lie outside {}",
            tree.display()
        )));
    }
    let root = work.join(ROOT);
    if root.exists() {
        fs::remove_dir_all(&root).map_err(failed(&root))?;
    }
    copy_tree(&tree.join("src"), &root.join("src"))?;
    let tests = copy_tree(&tree.join("tests"), &root.join("src/tests"))?;
    if tests == 0 {
        return Err(Failure("tests/ holds no Rust file".to_owned()));
    }
    println!("INFO the {tests} Rust files of tests/ are read as src/tests/");
    let tools = root.join("xtask/src");
    fs::create_dir_all(&tools).map_err(failed(&tools))?;
    xtask::copies::run(&root, &[])
}

/// Copies every file under `from` into `to`; returns how many of them are Rust files.
fn copy_tree(from: &Path, to: &Path) -> Result<usize, Failure> {
    fs::create_dir_all(to).map_err(failed(to))?;
    let mut rust_files = 0;
    for entry in fs::read_dir(from).map_err(failed(from))? {
        let entry = entry.map_err(failed(from))?;
        let (path, target) = (entry.path(), to.join(entry.file_name()));
        if entry.file_type().map_err(failed(&path))?.is_dir() {
            rust_files += copy_tree(&path, &target)?;
        } else {
            fs::copy(&path, &target).map_err(failed(&path))?;
            rust_files += usize::from(path.extension().is_some_and(|ending| ending == "rs"));
        }
    }
    Ok(rust_files)
}

/// The failure of a file operation on `path`.
fn failed(path: &Path) -> impl FnOnce(io::Error) -> Failure + '_ {
    move |error| Failure(format!("{}: {error}", path.display()))
}
