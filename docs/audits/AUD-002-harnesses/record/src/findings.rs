//! The findings and the metadata in both records: the Markdown report's register, headings and
//! remediation table against the JSON record's findings and remediation.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::{Value, json};

use crate::{Audit, Check, Result, listed};

/// The fields a register row and a JSON finding share.
const FIELDS: [&str; 6] = [
    "category",
    "kind",
    "severity",
    "status",
    "releaseBlocking",
    "title",
];

/// The `id`s of the JSON record's array `key`, in order.
fn ids_of<'a>(record: &'a Value, key: &str) -> Vec<&'a str> {
    let items = record[key]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    items
        .iter()
        .map(|item| item["id"].as_str().unwrap_or_default())
        .collect()
}

/// The register's rows, as the JSON fields they state, by finding ID.
fn register(md: &str) -> Result<BTreeMap<&str, Value>> {
    let row = Regex::new(
        r"^\| (AUD-002-[A-Z]+\d{3}) \| (\w+) \| (\w+) \| (\w+) \| ([\w-]+) \| (yes|no) \| (.+) \|$",
    )?;
    let section = md
        .lines()
        .skip_while(|line| !line.starts_with("## Finding register"))
        .skip(1)
        .take_while(|line| !line.starts_with("## "));
    Ok(section
        .filter_map(|line| row.captures(line))
        .map(|captures| {
            let (_, [id, category, kind, severity, status, blocking, title]) = captures.extract();
            let fields = json!({
                "category": category, "kind": kind, "severity": severity, "status": status,
                "releaseBlocking": blocking == "yes", "title": title,
            });
            (id, fields)
        })
        .collect())
}

pub(crate) fn in_both_records(audit: &Audit) -> Result<Check> {
    let md = &audit.md;
    let register = register(md)?;
    let heading = Regex::new(r"(?m)^#### (AUD-002-[A-Z]+\d{3}) — (\w+) — (.+)$")?;
    let headings: BTreeMap<&str, (String, &str)> = heading
        .captures_iter(md)
        .map(|captures| {
            let (_, [id, severity, title]) = captures.extract();
            (id, (severity.to_lowercase(), title))
        })
        .collect();
    let findings = audit.record["findings"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let by_id: BTreeMap<&str, &Value> = findings
        .iter()
        .map(|finding| (finding["id"].as_str().unwrap_or_default(), finding))
        .collect();
    let ids = ids_of(&audit.record, "findings");
    let remediation_ids = ids_of(&audit.record, "remediation");
    let (_, remediation) = md
        .split_once("### Remediation and follow-up")
        .ok_or("the report has no section \"Remediation and follow-up\"")?;
    let remediation_row = Regex::new(r"(?m)^\| (AUD-002-[A-Z]+\d{3}) \| (\w+) \|")?;
    let md_remediation: Vec<(&str, &str)> = remediation_row
        .captures_iter(remediation)
        .map(|captures| {
            let (_, [id, status]) = captures.extract();
            (id, status)
        })
        .collect();

    let mut every: BTreeSet<&str> = ids.iter().chain(&remediation_ids).copied().collect();
    every.extend(register.keys().chain(headings.keys()).copied());
    every.extend(md_remediation.iter().map(|(id, _)| *id));
    let mut mismatch = Vec::new();
    for id in every {
        let found = (by_id.get(id), register.get(id), headings.get(id));
        let (Some(finding), Some(row), Some((severity, title))) = found else {
            mismatch.push(format!("{id}: missing in a record"));
            continue;
        };
        if !remediation_ids.contains(&id) {
            mismatch.push(format!("{id}: missing in the JSON remediation"));
            continue;
        }
        for field in FIELDS
            .iter()
            .filter(|field| row[**field] != finding[**field])
        {
            mismatch.push(format!("{id}: {field} differs"));
        }
        if Some(severity.as_str()) != finding["severity"].as_str()
            || Some(*title) != finding["title"].as_str()
        {
            mismatch.push(format!("{id}: heading differs"));
        }
        let number = id.strip_prefix("AUD-002-").unwrap_or(id);
        if !finding["category"]
            .as_str()
            .is_some_and(|category| number.starts_with(category))
        {
            mismatch.push(format!("{id}: ID does not carry its category"));
        }
    }
    for (id, status) in &md_remediation {
        if by_id.get(id).map(|finding| &finding["status"]) != Some(&Value::from(*status)) {
            mismatch.push(format!("{id}: remediation status differs"));
        }
    }
    let unique = ids.iter().collect::<BTreeSet<_>>().len() == ids.len();
    if !unique {
        mismatch.push("a finding ID appears twice in the JSON record".to_owned());
    }
    let detail = format!(
        "{} findings in JSON, {} in the register, {} headings, {} remediation rows; problems: {}",
        ids.len(),
        register.len(),
        headings.len(),
        md_remediation.len(),
        listed(&mismatch)
    );
    Ok(Check::new(
        "finding-ids-in-both-records",
        mismatch.is_empty(),
        detail,
    ))
}

pub(crate) fn numbering(audit: &Audit) -> Result<Check> {
    let pattern = Regex::new(r"^AUD-002-([A-Z]+)(\d{3})")?;
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    let mut out_of_order = Vec::new();
    for id in ids_of(&audit.record, "findings") {
        let Some(captures) = pattern.captures(id) else {
            out_of_order.push(id.to_owned());
            continue;
        };
        let (_, [category, number]) = captures.extract();
        let count = counts.entry(category).or_default();
        *count += 1;
        if number.parse() != Ok(*count) {
            out_of_order.push(id.to_owned());
        }
    }
    let detail = format!(
        "numbered per category in presentation order; out of order: {}",
        listed(&out_of_order)
    );
    Ok(Check::new(
        "finding-numbering",
        out_of_order.is_empty(),
        detail,
    ))
}

pub(crate) fn metadata(audit: &Audit) -> Check {
    let (md, record) = (&audit.md, &audit.record);
    let text = |pointer: &str| record.pointer(pointer).and_then(Value::as_str);
    let mut differences = Vec::new();
    if !text("/snapshot/commit").is_some_and(|commit| md.contains(&format!("`{commit}`"))) {
        differences.push("commit".to_owned());
    }
    if !text("/date").is_some_and(|date| md.contains(&format!("**Completed (UTC):** {date}"))) {
        differences.push("date".to_owned());
    }
    let heading = format!(
        "# {} — {}\n",
        text("/auditId").unwrap_or_default(),
        text("/title").unwrap_or_default()
    );
    if !md.starts_with(&heading) {
        differences.push("title".to_owned());
    }
    let model_named = text("/reviewer/model").is_some_and(|model| md.contains(model));
    if !model_named || !record["reviewer"]["reasoningEffort"].is_null() {
        differences.push("reviewer".to_owned());
    }
    Check::new(
        "metadata-agree",
        differences.is_empty(),
        format!("differences: {}", listed(&differences)),
    )
}
