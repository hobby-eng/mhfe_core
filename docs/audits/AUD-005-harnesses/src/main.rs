//! Read-only AUD-005 orchestration. Audit probes stay outside product tests and release paths.

mod probe;
mod record;
mod runner;

use std::error::Error;
use std::process::ExitCode;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const EVIDENCE: &str = "docs/audits/AUD-005-evidence";
const REPORT_STEM: &str = "AUD-005-2026-11-02";

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("AUD-005: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("run") => runner::run(&arguments[1..]),
        Some("inventory") => record::inventory(),
        Some("source-findings") => probe::source_findings(),
        Some("validate") => record::validate(),
        Some("negative-controls") => record::negative_controls(),
        Some("record-negative-controls") => record::record_negative_controls(),
        _ => Err("unknown mode; see AUD-005-harnesses/README.md".into()),
    }
}
