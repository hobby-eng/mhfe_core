//! Baseline identity and paired-record validation; no historical report is rewritten.

use std::collections::BTreeSet;
use std::fs;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{EVIDENCE, REPORT_STEM, Result};

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
                .map(|parts| parts.1)
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

fn report_paths() -> (String, String) {
    (
        format!("docs/audits/{REPORT_STEM}.json"),
        format!("docs/audits/{REPORT_STEM}.md"),
    )
}

pub(crate) fn validate() -> Result<()> {
    let (json_path, md_path) = report_paths();
    let json_text = fs::read_to_string(json_path)?;
    let md = fs::read_to_string(md_path)?;
    validate_text(&json_text, &md)?;
    println!("schema, keys, finding fields, 32 CHECK IDs, links and privacy: PASS");
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
        if finding["category"].as_str().is_none_or(|category| {
            id.strip_prefix("AUD-005-")
                .is_none_or(|suffix| !suffix.starts_with(category))
        }) {
            errors.push(format!("{id}: category and ID differ"));
        }
        let start = md
            .find(&format!("#### {id} —"))
            .ok_or("finding missing in Markdown")?;
        let block = md[start..]
            .split("\n#### ")
            .next()
            .ok_or("missing finding block")?;
        check_finding_block(id, finding, block, &mut errors)?;
    }
    let raw_ids: Vec<&str> = md
        .lines()
        .filter_map(|line| line.strip_prefix("#### "))
        .filter_map(|line| line.split_once(" — ").map(|parts| parts.0))
        .filter(|id| id.starts_with("AUD-005-"))
        .collect();
    let markdown_ids: BTreeSet<&str> = raw_ids.iter().copied().collect();
    if raw_ids.len() != markdown_ids.len() {
        errors.push("duplicate Markdown finding heading".to_owned());
    }
    if markdown_ids != seen {
        errors.push("Markdown and JSON finding ID sets differ".to_owned());
    }
    check_coverage(&record, md, json_text, &mut errors)?;
    check_privacy_and_links(&record, md, json_text, &mut errors)?;
    if !errors.is_empty() {
        return Err(errors.join("; ").into());
    }
    Ok(())
}

fn check_finding_block(
    id: &str,
    finding: &Value,
    block: &str,
    errors: &mut Vec<String>,
) -> Result<()> {
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
    for label in [
        "Affected files and builds",
        "Reproduction",
        "Expected behavior",
        "Observed behavior",
        "Impact",
        "Evidence",
        "Recommended fix",
        "Required verification",
    ] {
        if !block.contains(&format!("- **{label}:**")) {
            errors.push(format!("{id}: missing {label}"));
        }
    }
    Ok(())
}

fn check_coverage(
    record: &Value,
    md: &str,
    json_text: &str,
    errors: &mut Vec<String>,
) -> Result<()> {
    let guide = fs::read_to_string("../multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md")?;
    let ids: BTreeSet<&str> = guide
        .lines()
        .filter_map(|line| {
            line.strip_prefix("### CHECK-")
                .and_then(|rest| rest.split_once(" —"))
                .map(|parts| parts.0)
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
    if record["coverageLedger"].as_array().is_none_or(|rows| {
        rows.len() != 32
            || rows
                .iter()
                .filter_map(|row| row["checkId"].as_str())
                .collect::<BTreeSet<_>>()
                .len()
                != 32
    }) {
        errors.push("coverageLedger does not contain 32 unique rows".to_owned());
    }
    Ok(())
}

fn check_privacy_and_links(
    record: &Value,
    md: &str,
    json_text: &str,
    errors: &mut Vec<String>,
) -> Result<()> {
    let readme = fs::read_to_string("docs/audits/AUD-005-harnesses/README.md")?;
    for text in [md, json_text, &readme] {
        if text.contains("/home/sergio")
            || text.contains("Europe/")
            || text.to_ascii_lowercase().contains("the owner")
            || text.chars().any(|c| ('\u{0400}'..='\u{04ff}').contains(&c))
        {
            errors.push("privacy, wording or English-only check failed".to_owned());
        }
    }
    if record["reviewer"]["model"].is_string() || record["reviewer"]["reasoningEffort"].is_string()
    {
        errors.push("unverified model or effort metadata was guessed".to_owned());
    }
    let index = fs::read_to_string("docs/audits/README.md")?;
    for link in [
        format!("{REPORT_STEM}.md"),
        format!("{REPORT_STEM}.json"),
        "AUD-005-harnesses/README.md".to_owned(),
    ] {
        if !index.contains(&link) {
            errors.push(format!("audit index misses {link}"));
        }
    }
    Ok(())
}

pub(crate) fn negative_controls() -> Result<()> {
    let (json_path, md_path) = report_paths();
    let json_text = fs::read_to_string(json_path)?;
    let md = fs::read_to_string(md_path)?;
    validate_text(&json_text, &md)?;
    let original: Value = serde_json::from_str(&json_text)?;
    for field in ["severity", "title", "status", "category"] {
        let mut changed = original.clone();
        changed["findings"][0][field] = match field {
            "severity" => json!("high"),
            "status" => json!("fixed"),
            "category" => json!("API"),
            _ => json!("Changed title"),
        };
        if validate_text(&serde_json::to_string(&changed)?, &md).is_ok() {
            return Err(format!("record control accepted changed {field}").into());
        }
    }
    let heading = md
        .lines()
        .find(|line| line.starts_with("#### AUD-005-"))
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
    let mut wording = original.clone();
    wording["title"] = json!("contact the owner");
    if validate_text(&serde_json::to_string(&wording)?, &md).is_ok() {
        return Err("record control accepted prohibited wording".into());
    }
    crate::probe::negative_controls()?;
    println!("nine inconsistent record/source controls refused; valid record and sources pass");
    Ok(())
}
