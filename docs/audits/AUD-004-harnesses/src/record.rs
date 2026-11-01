//! Baseline binding and checks of the new report; no historical record is rewritten.

use std::collections::BTreeSet;
use std::fs;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{EVIDENCE, Result};

#[path = "../../AUD-002-harnesses/record/src/schema.rs"]
mod schema;

pub(crate) fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn inventory() -> Result<()> {
    let paths = fs::read(format!("{EVIDENCE}/all-paths.nul"))?;
    let baseline = fs::read_to_string(format!("{EVIDENCE}/source-SHA256SUMS"))?;
    let expected: BTreeSet<&str> = baseline
        .lines()
        .map(|line| {
            line.split_once("  ")
                .map(|p| p.1)
                .ok_or("malformed baseline row")
        })
        .collect::<std::result::Result<_, _>>()?;
    let mut actual = BTreeSet::new();
    for path in paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        if !actual.insert(std::str::from_utf8(path)?) {
            return Err("duplicate inventory path".into());
        }
    }
    if actual != expected || expected.len() != baseline.lines().count() {
        return Err("inventory and baseline path sets differ".into());
    }
    let mut records = Vec::new();
    let mut aggregate = String::new();
    for path in actual {
        let bytes = fs::read(path)?;
        let hash = sha256(&bytes);
        if !baseline
            .lines()
            .any(|line| line == format!("{hash}  {path}"))
        {
            return Err(format!("baseline source mismatch: {path}").into());
        }
        aggregate.push_str(&format!("{hash}  {path}\n"));
        records.push(json!({"path":path,"sha256":hash,"bytes":bytes.len()}));
    }
    let value = json!({"fileCount":records.len(),"sourceFingerprint":sha256(aggregate.as_bytes()),
        "files":records});
    fs::write(
        format!("{EVIDENCE}/inventory.json"),
        serde_json::to_vec_pretty(&value)?,
    )?;
    println!(
        "inventory: {} files, SHA256 {}",
        value["fileCount"], value["sourceFingerprint"]
    );
    Ok(())
}

/// Checks the resolved archive against both Cargo's lock checksum and registry source metadata.
pub(crate) fn provenance() -> Result<()> {
    let metadata: Value =
        serde_json::from_str(&fs::read_to_string(format!("{EVIDENCE}/metadata.log"))?)?;
    let lock = fs::read_to_string("Cargo.lock")?;
    let mut checked = Vec::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or("metadata packages missing")?
    {
        if !package["source"]
            .as_str()
            .is_some_and(|s| s.starts_with("registry+"))
        {
            continue;
        }
        let name = package["name"].as_str().ok_or("package name missing")?;
        let version = package["version"]
            .as_str()
            .ok_or("package version missing")?;
        let manifest = std::path::Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or("package manifest missing")?,
        );
        let source = manifest.parent().ok_or("package parent missing")?;
        let registry = source
            .parent()
            .and_then(|p| p.file_name())
            .ok_or("registry ID missing")?;
        let archive = std::path::PathBuf::from(std::env::var("CARGO_HOME")?)
            .join("registry/cache")
            .join(registry)
            .join(format!("{name}-{version}.crate"));
        let checksum = sha256(&fs::read(&archive)?);
        let stanza = lock
            .split("[[package]]")
            .find(|part| {
                part.lines()
                    .any(|line| line == format!("name = \"{name}\""))
                    && part
                        .lines()
                        .any(|line| line == format!("version = \"{version}\""))
            })
            .ok_or("package absent from lock")?;
        if !stanza
            .lines()
            .any(|line| line == format!("checksum = \"{checksum}\""))
        {
            return Err(format!("archive differs from lock: {name}-{version}").into());
        }
        let files = archived_sources(&archive, source, &format!("{name}-{version}/"))?;
        checked.push(json!({"name":name,"version":version,"checksum":checksum,
            "sourceFilesChecked":files,"license":package["license"],"links":package["links"]}));
    }
    println!(
        "{} registry archives and extracted source trees match Cargo.lock",
        checked.len()
    );
    fs::write(
        format!("{EVIDENCE}/provenance.json"),
        serde_json::to_vec_pretty(&checked)?,
    )?;
    Ok(())
}

/// Streams archive entries without extracting a second project or modifying the registry cache.
fn archived_sources(
    archive: &std::path::Path,
    source: &std::path::Path,
    prefix: &str,
) -> Result<usize> {
    let output = std::process::Command::new("tar")
        .arg("-tf")
        .arg(archive)
        .output()?;
    if !output.status.success() {
        return Err("tar listing failed".into());
    }
    let mut count = 0;
    let mut names = BTreeSet::new();
    for name in std::str::from_utf8(&output.stdout)?
        .lines()
        .filter(|n| !n.ends_with('/'))
    {
        let relative = name.strip_prefix(prefix).ok_or("archive prefix differs")?;
        if !names.insert(relative.to_owned()) {
            return Err("duplicate archive path".into());
        }
        if std::path::Path::new(relative)
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("archive has a nonlocal path".into());
        }
        let output = std::process::Command::new("tar")
            .arg("-xOf")
            .arg(archive)
            .arg(name)
            .output()?;
        if !output.status.success() {
            return Err(format!("tar read failed: {name}").into());
        }
        if fs::read(source.join(relative))? != output.stdout {
            return Err(format!("registry source differs: {name}").into());
        }
        count += 1;
    }
    check_source_files(source, source, &names)?;
    Ok(count)
}

/// Refuses extra inputs Cargo could discover, including an unlisted `build.rs`.
fn check_source_files(
    folder: &std::path::Path,
    root: &std::path::Path,
    expected: &BTreeSet<String>,
) -> Result<()> {
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            check_source_files(&path, root, expected)?;
        } else {
            let name = path
                .strip_prefix(root)?
                .to_str()
                .ok_or("non-UTF8 cache path")?;
            // Cargo's own extraction marker is not a Rust or build input.
            if !kind.is_file() || (!expected.contains(name) && name != ".cargo-ok") {
                return Err(format!("unlisted registry source input: {name}").into());
            }
        }
    }
    Ok(())
}

pub(crate) fn validate() -> Result<()> {
    let json_text = fs::read_to_string("docs/audits/AUD-004-2026-11-01.json")?;
    let md = fs::read_to_string("docs/audits/AUD-004-2026-11-01.md")?;
    validate_text(&json_text, &md)?;
    println!("schema, literal keys, finding fields, 32 CHECK IDs and privacy: PASS");
    Ok(())
}

fn validate_text(json_text: &str, md: &str) -> Result<()> {
    let record: Value = serde_json::from_str(json_text)?;
    let canonical: Value = serde_json::from_str(&fs::read_to_string(
        "../multi-chain-wallet-tools/docs/audit-report.schema.json",
    )?)?;
    let mut errors = Vec::new();
    schema::errors(&canonical, &canonical, &record, "$", &mut errors);
    if !schema::duplicate_keys(json_text).is_empty() {
        errors.push("duplicate literal JSON keys".to_owned());
    }
    let mut seen = BTreeSet::new();
    for finding in record["findings"]
        .as_array()
        .ok_or("findings is not an array")?
    {
        let id = finding["id"].as_str().ok_or("finding ID is not text")?;
        if !seen.insert(id) {
            errors.push(format!("duplicate ID {id}"));
        }
        let start = md
            .find(&format!("#### {id} —"))
            .ok_or("finding missing in Markdown")?;
        let block = md[start..]
            .split("\n#### ")
            .next()
            .ok_or("missing finding block")?;
        let heading: Vec<&str> = block
            .lines()
            .next()
            .ok_or("empty heading")?
            .split(" — ")
            .collect();
        if heading.len() != 3
            || heading[1].to_ascii_lowercase() != finding["severity"]
            || heading[2] != finding["title"]
        {
            errors.push(format!("{id}: Markdown heading differs"));
        }
        for (label, field) in [
            ("Category", "category"),
            ("Severity", "severity"),
            ("Status", "status"),
        ] {
            let expected = format!(
                "- **{label}:** {}.",
                finding[field].as_str().ok_or("field not text")?
            );
            if !block.lines().any(|line| line == expected) {
                errors.push(format!("{id}: {label} differs"));
            }
        }
        let expected = format!("- **Release blocking:** {}.", finding["releaseBlocking"]);
        if !block.lines().any(|line| line == expected) {
            errors.push(format!("{id}: release flag differs"));
        }
    }
    let raw_ids: Vec<&str> = md
        .lines()
        .filter_map(|line| line.strip_prefix("#### "))
        .filter_map(|line| line.split_once(" — ").map(|p| p.0))
        .filter(|id| id.starts_with("AUD-004-"))
        .collect();
    let markdown_ids: BTreeSet<&str> = raw_ids.iter().copied().collect();
    if raw_ids.len() != markdown_ids.len() {
        errors.push("duplicate Markdown finding heading".to_owned());
    }
    if markdown_ids != seen {
        errors.push("Markdown and JSON finding ID sets differ".to_owned());
    }
    for key in ["observations", "remediation"] {
        for item in record[key].as_array().ok_or("record list missing")? {
            if item["id"].as_str().is_none() {
                errors.push(format!("{key} has no ID"));
            }
        }
    }
    let guide = fs::read_to_string("../multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md")?;
    let ids: BTreeSet<&str> = guide
        .lines()
        .filter_map(|line| {
            line.strip_prefix("### CHECK-")
                .and_then(|rest| rest.split_once(" —"))
                .map(|p| p.0)
        })
        .collect();
    if ids.len() != 32 {
        errors.push("procedure does not have 32 IDs".to_owned());
    }
    for id in ids {
        let id = format!("CHECK-{id}");
        if !md.contains(&id) || !json_text.contains(&id) {
            errors.push(format!("missing {id}"));
        }
    }
    for text in [md, json_text] {
        if text.contains("/home/sergio")
            || text.contains("Europe/")
            || text.chars().any(|c| ('\u{0400}'..='\u{04ff}').contains(&c))
        {
            errors.push("privacy or English-only check failed".to_owned());
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; ").into());
    }
    Ok(())
}

/// Fails if a deliberately inconsistent report or extra compiler input is accepted.
pub(crate) fn negative_controls() -> Result<()> {
    let json_text = fs::read_to_string("docs/audits/AUD-004-2026-11-01.json")?;
    let md = fs::read_to_string("docs/audits/AUD-004-2026-11-01.md")?;
    validate_text(&json_text, &md)?;
    let original: Value = serde_json::from_str(&json_text)?;
    for field in ["severity", "title", "status", "category"] {
        let mut changed = original.clone();
        changed["findings"][0][field] = match field {
            "severity" => json!("medium"),
            "status" => json!("fixed"),
            "category" => json!("SEC"),
            _ => json!("Changed title"),
        };
        if validate_text(&serde_json::to_string(&changed)?, &md).is_ok() {
            return Err(format!("record control accepted changed {field}").into());
        }
    }
    let heading = md
        .lines()
        .find(|line| line.starts_with("#### AUD-004-"))
        .ok_or("control needs a finding")?;
    if validate_text(&json_text, &format!("{md}\n{heading}\n")).is_ok() {
        return Err("record control accepted a duplicate heading".into());
    }
    let mut missing = original.clone();
    missing["findings"]
        .as_array_mut()
        .ok_or("findings missing")?
        .remove(0);
    if validate_text(&serde_json::to_string(&missing)?, &md).is_ok() {
        return Err("record control accepted an extra Markdown finding".into());
    }
    let fixture = std::path::Path::new(EVIDENCE).join("extra-source-control");
    fs::create_dir_all(&fixture)?;
    fs::write(
        fixture.join("build.rs"),
        b"// Public audit control, never compiled.\n",
    )?;
    if check_source_files(&fixture, &fixture, &BTreeSet::new()).is_ok() {
        return Err("source control accepted an unlisted build.rs".into());
    }
    let known = BTreeSet::from(["build.rs".to_owned()]);
    check_source_files(&fixture, &fixture, &known)?;
    println!(
        "six inconsistent report controls and an extra-build.rs control refused; valid controls pass"
    );
    Ok(())
}
