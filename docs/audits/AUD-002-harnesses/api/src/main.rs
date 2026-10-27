//! AUD-002 api harnesses of mhfe-core (audit of commit dec9c81), one subcommand each:
//!
//!   truncation              NativeArgon2::argon2id with a password of 2^32 + 1 bytes
//!   stack-floor             the smallest thread stack each public function runs on
//!   stack <KiB> <function>  one call on a thread of <KiB> KiB (a child of stack-floor)
//!   nfkd                    the time of Seed::derive as a run of combining marks doubles
//!   public-surface <rustdoc JSON> <docs/public-api.txt>
//!
//! The copies gate with tests/ read is a crate of its own, `copies-with-tests/` in this folder:
//! it builds only in a tree that has `xtask/`, and this one builds at dec9c81 too.
//!
//! Each prints what it found and exits 0 when its check holds and 1 when it fails. It exits 2 when
//! it could not run (a wrong argument, a file it cannot read, a tool that does not start), so that
//! an unknown outcome never reads as either.

mod probes;
mod public_surface;

use std::path::Path;
use std::process::ExitCode;

/// Whether a subcommand's check held, or why the subcommand could not run.
type Outcome = Result<bool, String>;

const USAGE: &str = "usage: aud002-api truncation | stack-floor | stack <KiB> <function> | nfkd | \
                     public-surface <rustdoc JSON> <public-api.txt>";

/// The exit code of a check that failed; 0 is a check that held.
const FAILED: u8 = 1;
/// The exit code of a subcommand that could not run.
const BROKEN: u8 = 2;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let outcome = match words.as_slice() {
        ["truncation"] => probes::truncation(),
        ["stack-floor"] => probes::stack_floor(),
        ["stack", kib, function] => probes::stack(kib, function),
        ["nfkd"] => probes::nfkd(),
        ["public-surface", json, list] => public_surface::run(Path::new(json), Path::new(list)),
        _ => Err(USAGE.to_owned()),
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(FAILED),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(BROKEN)
        }
    }
}
