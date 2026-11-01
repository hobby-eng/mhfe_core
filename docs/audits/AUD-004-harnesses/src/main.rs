//! Read-only AUD-004 orchestration. Commands and observations remain separate from product tests.

mod probe;
mod record;
mod registry;
mod runner;

use std::error::Error;
use std::process::ExitCode;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const EVIDENCE: &str = "docs/audits/AUD-004-evidence";

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("AUD-004: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("run") => runner::run(&arguments[1..]),
        Some("inventory") => record::inventory(),
        Some("provenance") => record::provenance(),
        Some("registry") => registry::check(),
        Some("validate") => record::validate(),
        Some("negative-controls") => record::negative_controls(),
        Some("wallet-boundary") => probe::wallet_boundary(),
        Some("small-stack") => probe::small_stack(),
        _ => Err("unknown mode; see AUD-004-harnesses/README.md".into()),
    }
}
