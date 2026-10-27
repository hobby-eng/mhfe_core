//! AUD-002 record check: checks the audit record before it is committed, and writes the result.
//!
//!   aud002-validate-record <audit-report.schema.json> [<result.json>]
//!
//! Run it from inside the repository, with Git. It checks that the JSON record validates against
//! the workspace's schema and has no duplicate keys; that the Markdown and JSON records agree on
//! every finding (ID, category, kind, severity, status, title, release blocking) and on the
//! metadata; that finding IDs are unique and numbered per category in order; that every link of the
//! committed audit files resolves to a file git does not ignore; that every reference to the local
//! evidence folder is marked "(local)", or `"local": true` in the JSON; that every log a record
//! cites with a SHA-256 exists and has that SHA-256; that the audit files hold no login name, home
//! folder, time outside UTC or non-English script; and that git has no evidence file staged and
//! ignores the evidence folder. It prints PASS or FAIL per check, writes the result as JSON when a
//! path is given, and exits 0 when every check passes, 1 when one fails, 2 when it cannot run.

mod files;
mod findings;
mod schema;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const AUDIT_ID: &str = "AUD-002";
/// The record and its folders, relative to the repository's root.
const MD: &str = "docs/audits/AUD-002-2026-10-27.md";
const JSON: &str = "docs/audits/AUD-002-2026-10-27.json";
const AUDITS_README: &str = "docs/audits/README.md";
const EVIDENCE: &str = "docs/audits/AUD-002-evidence";
const HARNESSES: &str = "docs/audits/AUD-002-harnesses";
/// The most schema errors the detail lists.
const LISTED_SCHEMA_ERRORS: usize = 5;

/// The record and the files the checks read.
struct Audit {
    root: PathBuf,
    md: String,
    json_text: String,
    record: Value,
    /// The committed Markdown files: the report, the audits' README and the harnesses' READMEs.
    committed: Vec<PathBuf>,
    /// Every file of the harnesses' folder.
    harness_files: Vec<PathBuf>,
}

/// The result of one check, as printed and written.
struct Check {
    name: &'static str,
    ok: bool,
    detail: Value,
}

impl Check {
    fn new(name: &'static str, ok: bool, detail: impl Into<Value>) -> Self {
        Self {
            name,
            ok,
            detail: detail.into(),
        }
    }
}

/// `items` joined with "; ", or "none".
fn listed(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join("; ")
    }
}

fn sha256(path: &Path) -> Result<String> {
    let digest = Sha256::digest(fs::read(path)?);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Runs git with `arguments` in `root` and returns its output; a git that fails is an error.
fn git(root: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {} failed: {}", arguments.join(" "), message.trim()).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Every file under `folder`, in name order.
fn files_under(folder: &Path) -> Result<Vec<PathBuf>> {
    let mut entries: Vec<_> = fs::read_dir(folder)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    let mut files = Vec::new();
    for entry in entries {
        if entry.file_type()?.is_dir() {
            files.extend(files_under(&entry.path())?);
        } else {
            files.push(entry.path());
        }
    }
    Ok(files)
}

/// `text` without its fenced code blocks, whose examples are not the record's own links.
fn without_fences(text: &str) -> Result<String> {
    Ok(Regex::new(r"(?s)```.*?```")?
        .replace_all(text, "")
        .into_owned())
}

impl Audit {
    fn load() -> Result<Self> {
        let root = PathBuf::from(git(Path::new("."), &["rev-parse", "--show-toplevel"])?.trim());
        let root = fs::canonicalize(root)?;
        let read = |file: &str| {
            fs::read_to_string(root.join(file)).map_err(|error| format!("{file}: {error}"))
        };
        let json_text = read(JSON)?;
        let record = serde_json::from_str(&json_text)?;
        let harness_files = files_under(&root.join(HARNESSES))?;
        let mut committed = vec![root.join(MD), root.join(AUDITS_README)];
        committed.extend(
            harness_files
                .iter()
                .filter(|path| path.extension().is_some_and(|e| e == "md"))
                .cloned(),
        );
        Ok(Self {
            md: read(MD)?,
            root,
            json_text,
            record,
            committed,
            harness_files,
        })
    }

    /// `path` relative to the repository's root, for messages.
    fn relative(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .display()
            .to_string()
    }
}

fn run(schema_path: &Path, result_path: Option<&Path>) -> Result<bool> {
    let audit = Audit::load()?;
    let schema: Value = serde_json::from_str(&fs::read_to_string(schema_path)?)?;
    let mut schema_errors = Vec::new();
    schema::errors(&schema, &schema, &audit.record, "json", &mut schema_errors);
    let duplicates: Vec<String> = schema::duplicate_keys(&audit.json_text)
        .into_iter()
        .collect();
    let checks = [
        Check::new(
            "json-schema",
            schema_errors.is_empty(),
            format!(
                "{} schema errors: {}",
                schema_errors.len(),
                listed(&schema_errors[..schema_errors.len().min(LISTED_SCHEMA_ERRORS)])
            ),
        ),
        Check::new(
            "json-duplicate-keys",
            duplicates.is_empty(),
            format!("duplicate keys: {}", listed(&duplicates)),
        ),
        findings::in_both_records(&audit)?,
        findings::numbering(&audit)?,
        findings::metadata(&audit),
        files::links(&audit)?,
        files::local_evidence(&audit)?,
        files::cited_logs(&audit)?,
        files::privacy(&audit)?,
        files::evidence_not_staged(&audit)?,
    ];
    for check in &checks {
        let detail = check
            .detail
            .as_str()
            .map_or_else(|| check.detail.to_string(), str::to_owned);
        println!(
            "{} {}: {detail}",
            if check.ok { "PASS" } else { "FAIL" },
            check.name
        );
    }
    let passed = checks.iter().filter(|check| check.ok).count();
    println!("{passed} of {} checks pass", checks.len());
    let ok = passed == checks.len();
    if let Some(result_path) = result_path {
        let result = json!({
            "auditId": AUDIT_ID,
            "records": [MD, JSON],
            "recordSha256": { "md": sha256(&audit.root.join(MD))?, "json": sha256(&audit.root.join(JSON))? },
            "schemaSha256": sha256(schema_path)?,
            "head": git(&audit.root, &["rev-parse", "HEAD"])?.trim(),
            "checks": checks.iter().map(|check| json!({
                "check": check.name,
                "result": if check.ok { "PASS" } else { "FAIL" },
                "detail": check.detail,
            })).collect::<Vec<_>>(),
            "result": if ok { "PASS" } else { "FAIL" },
        });
        fs::write(
            result_path,
            format!("{}\n", serde_json::to_string_pretty(&result)?),
        )?;
    }
    Ok(ok)
}

fn main() -> ExitCode {
    let arguments: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let outcome = match arguments.as_slice() {
        [schema] => run(schema, None),
        [schema, result] => run(schema, Some(result)),
        _ => Err("usage: aud002-validate-record <audit-report.schema.json> [<result.json>]".into()),
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("ERROR {error}");
            ExitCode::from(2)
        }
    }
}
