//! Retains child failure and exact command provenance, including signal termination.

use std::env;
use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::json;

use crate::record::sha256;
use crate::{EVIDENCE, Result};

fn utc() -> Result<String> {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%S.%NZ"])
        .output()?;
    if !output.status.success() {
        return Err("UTC date failed".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub(crate) fn run(arguments: &[String]) -> Result<()> {
    let [label, program, tail @ ..] = arguments else {
        return Err("run needs a label and a command".into());
    };
    if label.is_empty()
        || !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("label must contain only ASCII letters, digits and hyphens".into());
    }
    let folder = Path::new(EVIDENCE);
    fs::create_dir_all(folder)?;
    let log_path = folder.join(format!("{label}.log"));
    if log_path.exists() {
        return Err(format!("refusing to overwrite {}", log_path.display()).into());
    }
    let log = File::create(&log_path)?;
    let started = utc()?;
    let result = Command::new(program)
        .args(tail)
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .status();
    let finished = utc()?;
    let (success, code, failure) = match &result {
        Ok(status) => (status.success(), status.code(), None),
        Err(error) => (false, None, Some(error.to_string())),
    };
    let keys = [
        "CARGO_HOME",
        "RUSTUP_HOME",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_JOBS",
        "CARGO_NET_OFFLINE",
        "RUST_TEST_THREADS",
        "RUST_MIN_STACK",
        "RAYON_NUM_THREADS",
        "DPRINT_CACHE_DIR",
        "PATH",
    ];
    let environment: serde_json::Map<String, serde_json::Value> = keys
        .into_iter()
        .filter_map(|key| {
            env::var(key)
                .ok()
                .map(|value| (key.to_owned(), json!(value)))
        })
        .collect();
    let receipt = json!({"argv": &arguments[1..], "cwd": env::current_dir()?,
        "environment": environment, "startedUtc": started, "finishedUtc": finished,
        "success": success, "exitCode": code, "spawnError": failure,
        "log": log_path, "logSha256": sha256(&fs::read(&log_path)?),
        "peakMemoryBytes": null});
    fs::write(
        folder.join(format!("{label}.command.json")),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!("{label}: success={success}, exit={code:?}");
    if success {
        Ok(())
    } else {
        Err(format!("child {label} failed: {result:?}").into())
    }
}
