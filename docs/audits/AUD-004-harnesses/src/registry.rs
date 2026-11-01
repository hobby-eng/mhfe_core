//! Reads the official sparse registry without updating Cargo's cache or any dependency version.

use std::fs;
use std::process::Command;

use serde_json::{Value, json};

use crate::record::sha256;
use crate::{EVIDENCE, Result};

pub(crate) fn check() -> Result<()> {
    let packages: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(format!("{EVIDENCE}/provenance.json"))?)?;
    let folder = std::path::Path::new(EVIDENCE).join("registry");
    fs::create_dir_all(&folder)?;
    let mut checked = Vec::new();
    for package in packages {
        let name = package["name"].as_str().ok_or("registry name missing")?;
        let version = package["version"]
            .as_str()
            .ok_or("registry version missing")?;
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("nonlocal registry name".into());
        }
        let path = match name.len() {
            1 => format!("1/{name}"),
            2 => format!("2/{name}"),
            3 => format!("3/{}/{name}", &name[..1]),
            _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
        };
        let url = format!("https://index.crates.io/{path}");
        let output = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "30",
                &url,
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "registry HTTP failed: {name}, {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        fs::write(folder.join(format!("{name}.jsonl")), &output.stdout)?;
        let records: Vec<Value> = std::str::from_utf8(&output.stdout)?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        let entry = records
            .iter()
            .find(|entry| entry["vers"] == version)
            .ok_or("resolved version absent from official index")?;
        if entry["cksum"] != package["checksum"] {
            return Err(format!("official registry checksum differs: {name}-{version}").into());
        }
        checked.push(
            json!({"name":name,"version":version,"checksum":entry["cksum"],
            "yanked":entry["yanked"],"url":url,"responseSha256":sha256(&output.stdout)}),
        );
    }
    let yanked = checked.iter().filter(|p| p["yanked"] == true).count();
    println!(
        "{} official registry checksums match; {yanked} resolved versions yanked",
        checked.len()
    );
    fs::write(
        format!("{EVIDENCE}/registry.json"),
        serde_json::to_vec_pretty(&checked)?,
    )?;
    Ok(())
}
