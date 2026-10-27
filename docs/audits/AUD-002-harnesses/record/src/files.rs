//! The checks of the audit's files: links, references to the local evidence, cited logs, privacy
//! and language, and git's view of the evidence folder.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde_json::{Value, json};

use crate::{Audit, Check, EVIDENCE, JSON, Result, git, listed, sha256, without_fences};

/// The most unmarked references the detail lists.
const LISTED_REFERENCES: usize = 20;

/// Whether git ignores `path`, a path inside the repository.
fn ignored(root: &Path, path: &Path) -> Result<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["check-ignore", "-q"])
        .arg(path)
        .status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(format!("git check-ignore {} failed", path.display()).into()),
    }
}

pub(crate) fn links(audit: &Audit) -> Result<Check> {
    let link = Regex::new(r"\]\(([^)\s]+)\)")?;
    let scheme = Regex::new(r"^[a-z]+:")?;
    let evidence = audit.root.join(EVIDENCE);
    let (mut count, mut bad, mut external) = (0, Vec::new(), Vec::new());
    for path in &audit.committed {
        let text = without_fences(&fs::read_to_string(path)?)?;
        for captures in link.captures_iter(&text) {
            let (_, [target]) = captures.extract();
            count += 1;
            if scheme.is_match(target) {
                external.push(target.to_owned());
                continue;
            }
            let file = target.split('#').next().unwrap_or_default();
            let folder = path.parent().unwrap_or(&audit.root);
            let resolves = match fs::canonicalize(folder.join(file)) {
                Ok(resolved) => {
                    resolved.starts_with(&audit.root)
                        && !resolved.starts_with(&evidence)
                        && !ignored(&audit.root, &resolved)?
                }
                Err(_) => false,
            };
            if !resolves {
                bad.push(format!("{} -> {target}", audit.relative(path)));
            }
        }
    }
    let detail = format!(
        "{count} links in {} committed Markdown files; unresolved or ignored: {}; external: {}",
        audit.committed.len(),
        listed(&bad),
        listed(&external)
    );
    Ok(Check::new(
        "committed-links-resolve",
        bad.is_empty() && external.is_empty(),
        detail,
    ))
}

/// Whether `c` may stand next to an evidence file's name within a longer name.
fn in_name(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '.' | '-')
}

/// The text from `before` characters before the byte `start` to `after` characters after `end`.
fn window(text: &str, start: usize, end: usize, before: usize, after: usize) -> &str {
    let from = text[..start]
        .char_indices()
        .rev()
        .nth(before - 1)
        .map_or(0, |(index, _)| index);
    let to = text[end..]
        .char_indices()
        .nth(after)
        .map_or(text.len(), |(index, _)| end + index);
    &text[from..to]
}

/// Adds to `unmarked` every name of `names` in `text` not followed by "(local)", and every
/// mention of the evidence folder with no "local" near it.
fn scan_text(text: &str, place: &str, names: &BTreeSet<String>, unmarked: &mut Vec<String>) {
    for name in names {
        for (start, _) in text.match_indices(name.as_str()) {
            let end = start + name.len();
            let rest = &text[end..];
            if text[..start].chars().next_back().is_some_and(in_name)
                || rest.chars().next().is_some_and(in_name)
            {
                continue;
            }
            if !rest.starts_with("` (local)") && !rest.starts_with(" (local)") {
                unmarked.push(format!("{place}: {name}"));
            }
        }
    }
    for (start, found) in text.match_indices("AUD-002-evidence") {
        if !window(text, start, start + found.len(), 80, 40).contains("local") {
            unmarked.push(format!("{place}: the evidence folder at byte {start}"));
        }
    }
}

/// `scan_text` on every string of the JSON record but those an object marked `"local": true`
/// names as its file, and the command lines, which name their own logs and folders.
fn scan_json(
    value: &Value,
    place: &str,
    names: &BTreeSet<String>,
    command: &Regex,
    unmarked: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            let marked = object.get("local") == Some(&Value::Bool(true));
            for (key, item) in object {
                if !(marked && ["file", "log", "commandRecord"].contains(&key.as_str())) {
                    scan_json(item, &format!("{place}.{key}"), names, command, unmarked);
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                scan_json(item, &format!("{place}[{index}]"), names, command, unmarked);
            }
        }
        Value::String(text) if !command.is_match(place) => scan_text(text, place, names, unmarked),
        _ => {}
    }
}

pub(crate) fn local_evidence(audit: &Audit) -> Result<Check> {
    let mut names = BTreeSet::from(["report-validation.json".to_owned()]);
    for entry in fs::read_dir(audit.root.join(EVIDENCE))? {
        names.insert(entry?.file_name().to_string_lossy().into_owned());
    }
    // SHA256SUMS is also the name of the specification's and the fixtures' lists.
    names.remove("SHA256SUMS");
    let command = Regex::new(r"\.commands\[\d+\]\.(command|workingDirectory)$")?;
    let mut unmarked = Vec::new();
    for path in &audit.committed {
        let text = without_fences(&fs::read_to_string(path)?)?;
        scan_text(&text, &audit.relative(path), &names, &mut unmarked);
    }
    scan_json(&audit.record, "json", &names, &command, &mut unmarked);
    let shown = &unmarked[..unmarked.len().min(LISTED_REFERENCES)];
    let detail = format!("{} unmarked references: {}", unmarked.len(), listed(shown));
    Ok(Check::new(
        "local-evidence-marked",
        unmarked.is_empty(),
        detail,
    ))
}

/// The logs the JSON record cites, as (path, SHA-256), from every object marked `"local": true`.
fn json_logs<'a>(value: &'a Value, found: &mut Vec<(Option<&'a str>, &'a str)>) {
    match value {
        Value::Object(object) => {
            if object.get("local") == Some(&Value::Bool(true))
                && let Some(digest) = object.get("logSha256")
            {
                let named = |key: &str| {
                    object
                        .get(key)
                        .and_then(Value::as_str)
                        .filter(|path| !path.is_empty())
                };
                found.push((
                    named("log").or_else(|| named("file")),
                    digest.as_str().unwrap_or_default(),
                ));
            }
            object.values().for_each(|item| json_logs(item, found));
        }
        Value::Array(items) => items.iter().for_each(|item| json_logs(item, found)),
        _ => {}
    }
}

pub(crate) fn cited_logs(audit: &Audit) -> Result<Check> {
    let citation =
        Regex::new(r"`([\w.-]+\.log)` \(local\)(?:, exit \d+)?, SHA-256 `([0-9a-f]{64})`")?;
    let has = |path: &Path, digest: &str| sha256(path).is_ok_and(|actual| actual == digest);
    let evidence = audit.root.join(EVIDENCE);
    let mut wrong = Vec::new();
    let mut in_md = 0;
    for captures in citation.captures_iter(&audit.md) {
        let (_, [name, digest]) = captures.extract();
        in_md += 1;
        if !has(&evidence.join(name), digest) {
            wrong.push(name.to_owned());
        }
    }
    let mut in_json = Vec::new();
    json_logs(&audit.record, &mut in_json);
    for (path, digest) in &in_json {
        if !path.is_some_and(|path| has(&audit.root.join(path), digest)) {
            wrong.push(path.unwrap_or("a log without a path").to_owned());
        }
    }
    let detail = format!(
        "{in_md} citations in Markdown and {} in JSON; wrong: {}",
        in_json.len(),
        listed(&wrong)
    );
    Ok(Check::new("cited-log-hashes", wrong.is_empty(), detail))
}

/// Whether `word` stands in `text` with no ASCII letter just before or after it.
fn names_word(text: &str, word: &str) -> bool {
    let letter = |byte: Option<&u8>| byte.is_some_and(u8::is_ascii_alphabetic);
    text.match_indices(word).any(|(start, _)| {
        let before = start
            .checked_sub(1)
            .and_then(|index| text.as_bytes().get(index));
        !letter(before) && !letter(text.as_bytes().get(start + word.len()))
    })
}

pub(crate) fn privacy(audit: &Audit) -> Result<Check> {
    // The login name and home folder of the machine that runs the check, never written here.
    let variable = |name: &str| env::var(name).ok().filter(|value| !value.is_empty());
    let login = variable("LOGNAME")
        .or_else(|| variable("USER"))
        .ok_or("LOGNAME and USER are empty")?;
    let home = variable("HOME").ok_or("HOME is empty")?;
    let (login, home) = (login.to_ascii_lowercase(), home.to_ascii_lowercase());
    let zone = r"(?i)\b\d{2}:\d{2}(:\d{2})?\s*(?:[+-]\d{2}:?\d{2}|CET|CEST|MSK|EET|EEST|PST|EST)\b";
    let zone = Regex::new(zone)?;
    let json = audit.root.join(JSON);
    let mut files: BTreeSet<&Path> = audit.committed.iter().map(PathBuf::as_path).collect();
    files.insert(&json);
    files.extend(audit.harness_files.iter().map(PathBuf::as_path));
    let mut problems = Vec::new();
    for path in &files {
        let text = String::from_utf8_lossy(&fs::read(path)?).into_owned();
        let lower = text.to_ascii_lowercase();
        let other_home = lower.match_indices("/home/").any(|(start, found)| {
            let rest = &lower[start + found.len()..];
            !rest.starts_with("user/") && rest.starts_with(|c: char| c.is_ascii_lowercase())
        });
        // Text for readers is English; test data in the harnesses may hold any script.
        let prose = path
            .extension()
            .is_some_and(|extension| extension == "md" || extension == "json");
        let cyrillic = prose && text.chars().any(|c| ('\u{400}'..='\u{4ff}').contains(&c));
        let found = [
            (names_word(&lower, &login), "login name"),
            (lower.contains(&home), "home folder"),
            (other_home, "home folder other than /home/user/"),
            (zone.is_match(&text), "time outside UTC"),
            (cyrillic, "non-English script"),
        ];
        for (_, what) in found.iter().filter(|(present, _)| *present) {
            problems.push(format!("{}: {what}", audit.relative(path)));
        }
    }
    let detail = format!(
        "{} audit files; problems: {}",
        files.len(),
        listed(&problems)
    );
    Ok(Check::new(
        "privacy-and-language",
        problems.is_empty(),
        detail,
    ))
}

pub(crate) fn evidence_not_staged(audit: &Audit) -> Result<Check> {
    let staged = git(&audit.root, &["diff", "--cached", "--name-only"])?;
    let staged: Vec<&str> = staged.lines().collect();
    let tracked = git(&audit.root, &["ls-files", "--", EVIDENCE])?;
    let tracked: Vec<&str> = tracked.lines().collect();
    let status = git(
        &audit.root,
        &["status", "--porcelain", "--ignored", "--", EVIDENCE],
    )?;
    let status = status.trim();
    let ok = !staged.iter().any(|path| path.contains("AUD-002-evidence"))
        && tracked.is_empty()
        && status == format!("!! {EVIDENCE}/");
    let detail = json!({ "stagedFiles": staged, "trackedEvidenceFiles": tracked, "statusOfEvidenceFolder": status });
    Ok(Check::new("evidence-not-staged", ok, detail))
}
