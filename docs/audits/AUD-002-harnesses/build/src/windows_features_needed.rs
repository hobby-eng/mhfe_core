//! CHECK-BLD-001: every `windows-sys` feature of `Cargo.toml` is needed. For each feature of the
//! `[target.'cfg(windows)'.dependencies]` entry it removes that one feature in a clone of the
//! commit and requires `cargo clippy --lib` for x86_64-pc-windows-gnu to fail; for the
//! dev-dependency entry's feature, `cargo clippy --all-targets`. A feature whose removal still
//! builds is needed only when another feature implies it and the code imports its module; else it
//! is reported as not needed. The stand-in C compiler writes empty objects: only Rust is checked.

use std::fs;
use std::ops::Range;
use std::path::Path;

use crate::Error;
use crate::tools;

const USAGE: &str =
    "usage: windows-features-needed <repository> <commit> <stand-in C compiler> <work>";

const TARGET: &str = "x86_64-pc-windows-gnu";
const NORMAL_ENTRY: &str = "[target.'cfg(windows)'.dependencies]";
const DEV_ENTRY: &str = "[target.'cfg(windows)'.dev-dependencies]";

/// The prefix every feature of the entries has (windows-sys's API families).
const FEATURE_PREFIX: &str = "\"Win32_";

pub(crate) fn run(arguments: &[String]) -> Result<bool, Error> {
    let [repository, commit, stand_in, work] = arguments else {
        return Err(Error(USAGE.to_owned()));
    };
    let stand_in = tools::existing_file(stand_in)?;
    let work = tools::work_folder(work)?;
    let clone = work.join("features-clone");
    tools::clone_at(Path::new(repository), commit, &clone)?;
    tools::submodules_from(Path::new(repository), &clone)?;
    let log = work.join("features-last.log");
    let check = |scope: &str| {
        tools::logged(
            tools::tool("cargo")
                .args([
                    "clippy",
                    "--locked",
                    "--offline",
                    "--quiet",
                    scope,
                    "--target",
                    TARGET,
                    "--",
                    "-D",
                    "warnings",
                ])
                .current_dir(&clone)
                .env("CARGO_TARGET_DIR", work.join("features-target"))
                .env("CC_x86_64_pc_windows_gnu", &stand_in)
                .env("AR_x86_64_pc_windows_gnu", "ar"),
            &log,
        )
    };
    if !check("--all-targets")? {
        return Err(Error(format!(
            "the unchanged commit does not pass clippy for {TARGET}:\n{}",
            fs::read_to_string(&log)?
        )));
    }

    let manifest_path = clone.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)?;
    let code = rust_sources(&clone)?;
    let mut unneeded = 0;
    let mut features = 0;
    for (entry, scope) in [(NORMAL_ENTRY, "--lib"), (DEV_ENTRY, "--all-targets")] {
        let span = entry_span(&manifest, entry)
            .ok_or_else(|| Error(format!("Cargo.toml has no {entry}")))?;
        for feature in entry_features(&manifest[span.clone()]) {
            features += 1;
            fs::write(&manifest_path, without_feature(&manifest, &span, feature))?;
            let builds = check(scope);
            fs::write(&manifest_path, &manifest)?;
            // windows-sys turns on a module's parents with it (Win32_Security_Authorization turns
            // on Win32_Security, every Win32_* turns on Win32_Foundation): such a feature still
            // builds when removed, and is needed when the code imports its own module.
            let module = format!("windows_sys::{}", feature.replace('_', "::"));
            if !builds? {
                let errors = fs::read_to_string(&log)?;
                let error = first_error_code(&errors);
                println!("needed: {feature} ({scope} fails without it: {error})");
            } else if code.iter().any(|text| imports(text, &module)) {
                println!(
                    "needed: {feature} (implied by another feature; the code imports {module})"
                );
            } else {
                println!(
                    "NOT NEEDED: {feature} ({scope} still passes without it, and no code imports {module})"
                );
                unneeded += 1;
            }
        }
    }
    if features == 0 {
        return Err(Error(
            "no windows-sys feature found in Cargo.toml".to_owned(),
        ));
    }
    Ok(unneeded == 0)
}

/// The text of the entry under `heading`, up to the next blank line.
fn entry_span(manifest: &str, heading: &str) -> Option<Range<usize>> {
    let start = manifest.find(&format!("\n{heading}\n"))? + 1;
    let end = manifest[start..]
        .find("\n\n")
        .map_or(manifest.len(), |end| start + end);
    Some(start..end)
}

/// The `"Win32_…"` features named in an entry, without their quotes.
fn entry_features(entry: &str) -> Vec<&str> {
    entry
        .match_indices(FEATURE_PREFIX)
        .filter_map(|(start, _)| {
            let name = &entry[start + 1..];
            name.find('"').map(|end| &name[..end])
        })
        .collect()
}

/// The manifest with `feature` and the comma after it taken out of the entry at `span`.
fn without_feature(manifest: &str, span: &Range<usize>, feature: &str) -> String {
    let entry = &manifest[span.clone()];
    let quoted = format!("\"{feature}\"");
    let edited = entry.replacen(&format!("{quoted},"), "", 1);
    let edited = if edited == entry {
        entry.replacen(&quoted, "", 1)
    } else {
        edited
    };
    format!(
        "{}{edited}{}",
        &manifest[..span.start],
        &manifest[span.end..]
    )
}

/// The text of every Rust file under `src/` and `tests/` of the clone.
fn rust_sources(clone: &Path) -> Result<Vec<String>, Error> {
    let mut texts = Vec::new();
    for folder in ["src", "tests"] {
        let root = clone.join(folder);
        for file in tools::files_under(&root)? {
            if file.ends_with(".rs") {
                texts.push(fs::read_to_string(root.join(file))?);
            }
        }
    }
    Ok(texts)
}

/// Whether `text` imports `module` itself: `module::{` or `module::Item;`.
fn imports(text: &str, module: &str) -> bool {
    let prefix = format!("{module}::");
    text.match_indices(&prefix).any(|(start, _)| {
        let rest = &text[start + prefix.len()..];
        let item = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        rest.starts_with('{') || (item > 0 && rest[item..].starts_with(';'))
    })
}

/// The first `error[E…]` code of a Cargo log, or `error` when it has none.
fn first_error_code(log: &str) -> &str {
    log.find("error[E")
        .and_then(|start| log[start..].find(']').map(|end| &log[start..=start + end]))
        .unwrap_or("error")
}
