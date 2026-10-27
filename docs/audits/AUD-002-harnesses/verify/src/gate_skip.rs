//! AUD-002-BLD003, "The code-rules gate reads audit records and harnesses under docs/audits/". In a
//! clone of the repository with its working-tree changes and its `docs/audits/` copied in, it runs
//! the tree's code-rules gate and checks that the gate passes with the audit folder present, that
//! a lint exception without a reason under `docs/audits/AUD-999-harnesses/` passes, and that the
//! same file under `tests/` and under `docs/` outside `docs/audits/` is refused. A tree whose gate
//! is still the Node.js script of dec9c81 is not checked (TOOL-01).

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{Result, Verdicts};

/// A lint exception without a reason, which the code-rules gate refuses everywhere but in
/// `docs/audits/`: the coding guide calls an exception without a reason a broken rule.
const PROBE: &str = "#![allow(unsafe_code)]\nfn main() {}\n";

/// The code-rules gate of dec9c81, a Node.js script, which this repository no longer runs
/// (TOOL-01).
const NODE_GATE: &str = "scripts/verify-code-rules.mjs";
/// The archived run of the audit record that reproduced AUD-002-BLD003 with `NODE_GATE` at dec9c81.
const NODE_GATE_RECORD: &str = "docs/audits/AUD-002-evidence/record-gate-reads-audits.log";

/// The code-rules gate of the tree in `clone`: the xtask task, which the release commit has. A
/// tree whose gate is still the Node.js script (dec9c81) is refused, naming the archived run.
fn gate(clone: &Path) -> Result<Command> {
    if !clone.join("xtask/Cargo.toml").is_file() {
        let why = if clone.join(NODE_GATE).is_file() {
            format!(
                "the reviewed commit's code-rules gate is the Node.js script {NODE_GATE}, which \
                 this repository no longer runs (TOOL-01); the original reproduction of \
                 AUD-002-BLD003 is the archived evidence {NODE_GATE_RECORD} (local)"
            )
        } else {
            format!("the tree has neither xtask/ nor {NODE_GATE}")
        };
        return Err(why.into());
    }
    let mut cargo = Command::new("cargo");
    cargo
        .args(["xtask", "code-rules"])
        .env("CARGO_NET_OFFLINE", "true")
        .current_dir(clone);
    Ok(cargo)
}

/// Runs the gate and checks its exit code and, for a refused probe, the line that names `refused`.
fn expect(
    verdicts: &mut Verdicts,
    clone: &Path,
    name: &str,
    want: i32,
    refused: Option<&str>,
) -> Result<()> {
    let output = gate(clone)?.output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for line in text.lines() {
        println!("    {line}");
    }
    let got = output.status.code();
    let exit = got.map_or_else(|| "none (a signal)".to_owned(), |code| code.to_string());
    let names = |path: &str| {
        text.lines().any(|line| {
            line.starts_with(&format!("{path}:"))
                && line.contains("#![allow(unsafe_code)]")
                && line.contains("no reason")
        })
    };
    if got != Some(want) {
        verdicts.check(false, name, &format!("exit {exit}, expected {want}"));
    } else if let Some(path) = refused.filter(|path| !names(path)) {
        verdicts.check(
            false,
            name,
            &format!("no line refuses {path} for its lint exception"),
        );
    } else {
        verdicts.check(true, name, &format!("exit {want}"));
    }
    Ok(())
}

pub(crate) fn run(repository: &Path, scratch: &Path) -> Result<bool> {
    fs::create_dir_all(scratch)?;
    let clone = scratch.join("gate-clone");
    crate::clone_with_changes(repository, &clone)?;
    crate::copy_tree(&repository.join("docs/audits"), &clone.join("docs/audits"))?;
    let mut verdicts = Verdicts::default();
    expect(
        &mut verdicts,
        &clone,
        "fixed tree with this audit's records and harnesses",
        0,
        None,
    )?;
    let probe = clone.join("docs/audits/AUD-999-harnesses/probe");
    fs::create_dir_all(&probe)?;
    fs::write(probe.join("probe.rs"), PROBE)?;
    expect(&mut verdicts, &clone, "probe under docs/audits", 0, None)?;
    fs::write(clone.join("tests/probe.rs"), PROBE)?;
    expect(
        &mut verdicts,
        &clone,
        "probe under tests",
        1,
        Some("tests/probe.rs"),
    )?;
    fs::remove_file(clone.join("tests/probe.rs"))?;
    fs::write(clone.join("docs/probe.rs"), PROBE)?;
    let name = "probe under docs outside docs/audits";
    expect(&mut verdicts, &clone, name, 1, Some("docs/probe.rs"))?;
    Ok(!verdicts.failed)
}
