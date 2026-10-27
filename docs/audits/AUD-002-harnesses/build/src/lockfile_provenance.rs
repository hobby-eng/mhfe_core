//! CHECK-BLD-003: the provenance of the two lockfiles.
//!
//! `Cargo.lock`: every package but the workspace's own comes from the crates.io registry and has
//! a checksum, which is the SHA-256 of the `.crate` file in Cargo's local cache (offline); with
//! `--online`, it is also the `cksum` of the crates.io sparse index for that version, which must
//! not be yanked. `pnpm-lock.yaml`, where the tree has one: with `--online`, the integrity of
//! every `resolution` is the one the npm registry publishes for that version. `CARGO_HOME`
//! (default `$HOME/.cargo`) locates the cache.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::Error;
use crate::tools;

const USAGE: &str = "usage: lockfile-provenance <repository> [--online]";

/// The `source` of a crates.io package in `Cargo.lock`.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// The prefix of the cache folders of crates.io in `$CARGO_HOME/registry/cache/`.
const CACHE_PREFIX: &str = "index.crates.io-";

/// The SHA-256 of a checksum, in hex.
const CHECKSUM_HEX_DIGITS: usize = 64;

/// One `[[package]]` entry of `Cargo.lock`.
struct Locked<'a> {
    name: &'a str,
    version: &'a str,
    source: Option<&'a str>,
    checksum: Option<&'a str>,
}

pub(crate) fn run(arguments: &[String]) -> Result<bool, Error> {
    let (repository, online) = match arguments {
        [repository] => (repository, false),
        [repository, flag] if flag == "--online" => (repository, true),
        _ => return Err(Error(USAGE.to_owned())),
    };
    let repository = Path::new(repository);
    let lock = fs::read_to_string(repository.join("Cargo.lock"))?;
    let packages = cargo_packages(&lock);
    let caches = cache_folders()?;
    let mut problems = Vec::new();
    let (mut cached, mut indexed) = (0, 0);
    for package in &packages {
        let Locked {
            name,
            version,
            source,
            checksum,
        } = *package;
        if source.is_none() && checksum.is_none() {
            continue; // a package of the workspace itself
        }
        let id = format!("{name} {version}");
        if source != Some(CRATES_IO) {
            problems.push(format!("{id}: source {source:?} is not crates.io"));
        }
        let Some(checksum) = checksum.filter(|sum| is_sha256_hex(sum)) else {
            problems.push(format!("{id}: no checksum"));
            continue;
        };
        let file = caches
            .iter()
            .map(|cache| cache.join(format!("{name}-{version}.crate")))
            .find(|f| f.is_file());
        match file {
            None => problems.push(format!("{id}: not in the local cache")),
            Some(ref file) if tools::sha256_hex(&fs::read(file)?) != checksum => {
                problems.push(format!(
                    "{id}: the cached .crate does not have the lockfile's checksum"
                ));
            }
            Some(_) => cached += 1,
        }
        if online {
            match index_entry(name, version)? {
                Err(problem) => problems.push(format!("{id}: {problem}")),
                Ok(entry) if entry["cksum"].as_str() != Some(checksum) => {
                    problems.push(format!("{id}: the index has another checksum"));
                }
                Ok(entry) if entry["yanked"].as_bool() != Some(false) => {
                    problems.push(format!("{id}: yanked"))
                }
                Ok(_) => indexed += 1,
            }
        }
    }
    let crates = packages
        .iter()
        .filter(|package| package.checksum.is_some())
        .count();
    if crates == 0 {
        problems.push("Cargo.lock lists no package with a checksum".to_owned());
    }
    println!(
        "Cargo.lock: {} packages, {crates} from crates.io with a checksum",
        packages.len()
    );
    println!("  {cached} match the SHA-256 of the cached .crate");
    if online {
        println!("  {indexed} match the crates.io index and are not yanked");
        // dec9c81 has Node.js for Prettier; the release commit has none, and no pnpm lockfile.
        let pnpm_lock = repository.join("pnpm-lock.yaml");
        if pnpm_lock.exists() {
            npm_integrities(&fs::read_to_string(pnpm_lock)?, &mut problems)?;
        } else {
            println!("pnpm-lock.yaml: none in this tree");
        }
    }

    for problem in &problems {
        eprintln!("{problem}");
    }
    if problems.is_empty() {
        println!("Every lockfile entry has the recorded provenance.");
        return Ok(true);
    }
    eprintln!("{} provenance problems.", problems.len());
    Ok(false)
}

/// The `[[package]]` entries of `Cargo.lock`.
fn cargo_packages(lock: &str) -> Vec<Locked<'_>> {
    lock.split("[[package]]")
        .skip(1)
        .map(|entry| Locked {
            name: tools::manifest_value(entry, "name").unwrap_or_default(),
            version: tools::manifest_value(entry, "version").unwrap_or_default(),
            source: tools::manifest_value(entry, "source"),
            checksum: tools::manifest_value(entry, "checksum"),
        })
        .collect()
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == CHECKSUM_HEX_DIGITS
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The crates.io cache folders of Cargo's registry cache; none when the cache is missing.
fn cache_folders() -> Result<Vec<PathBuf>, Error> {
    let home = match env::var_os("CARGO_HOME") {
        Some(home) => PathBuf::from(home),
        None => PathBuf::from(
            env::var_os("HOME")
                .ok_or_else(|| Error("neither CARGO_HOME nor HOME is set".to_owned()))?,
        )
        .join(".cargo"),
    };
    let root = home.join("registry/cache");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut folders = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(CACHE_PREFIX)
        {
            folders.push(entry.path());
        }
    }
    Ok(folders)
}

/// The sparse-index path of a crate name (Cargo's index layout), or None for a name that is not
/// ASCII, which crates.io does not accept.
fn index_path(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    if !lower.is_ascii() {
        return None;
    }
    Some(match lower.len() {
        1 | 2 => format!("{}/{lower}", lower.len()),
        3 => format!("3/{}/{lower}", lower.get(..1)?),
        _ => format!("{}/{}/{lower}", lower.get(..2)?, lower.get(2..4)?),
    })
}

/// The crates.io index entry of one version, or the problem that kept it from being read.
fn index_entry(name: &str, version: &str) -> Result<Result<Value, String>, Error> {
    let Some(path) = index_path(name) else {
        return Ok(Err("a name crates.io cannot hold".to_owned()));
    };
    let body = match tools::download(&format!("https://index.crates.io/{path}")) {
        Ok(body) => body,
        Err(error) => return Ok(Err(format!("the index answers: {error}"))),
    };
    for line in String::from_utf8_lossy(&body)
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let entry: Value = serde_json::from_str(line)?;
        if entry["vers"].as_str() == Some(version) {
            return Ok(Ok(entry));
        }
    }
    Ok(Err("not in the index".to_owned()))
}

/// Compares every `resolution` integrity of `pnpm-lock.yaml` with npm's.
fn npm_integrities(lock: &str, problems: &mut Vec<String>) -> Result<(), Error> {
    let resolutions = pnpm_resolutions(lock);
    let mut matched = 0;
    for (name, version, integrity) in &resolutions {
        let url = format!("https://registry.npmjs.org/{name}/{version}");
        let body = match tools::download(&url) {
            Ok(body) => body,
            Err(error) => {
                problems.push(format!("npm {name}@{version}: {error}"));
                continue;
            }
        };
        let answer: Value = serde_json::from_slice(&body)?;
        match answer["dist"]["integrity"].as_str() {
            Some(published) if published == *integrity => matched += 1,
            published => problems.push(format!("npm {name}@{version}: integrity {published:?}")),
        }
    }
    if resolutions.is_empty() {
        problems.push("pnpm-lock.yaml lists no resolution".to_owned());
    }
    println!(
        "pnpm-lock.yaml: {matched} of {} integrities match npm",
        resolutions.len()
    );
    Ok(())
}

/// The `packages:` keys of `pnpm-lock.yaml` (`  name@version:`, quoted or not) whose next line
/// is `    resolution: {integrity: …}`, as name, version and integrity.
fn pnpm_resolutions(lock: &str) -> Vec<(&str, &str, &str)> {
    let lines: Vec<&str> = lock.lines().collect();
    lines
        .windows(2)
        .filter_map(|pair| {
            let [key, next] = pair else { return None };
            let key = key
                .strip_prefix("  ")
                .filter(|key| !key.starts_with(' '))?
                .strip_suffix(':')?;
            let key = key.trim_matches('\'');
            // A scoped name starts with `@`, so the version follows the last `@`.
            let (name, version) = key.rsplit_once('@').filter(|(name, _)| !name.is_empty())?;
            let integrity = next
                .strip_prefix("    resolution: {integrity: ")?
                .strip_suffix('}')?;
            Some((name, version, integrity))
        })
        .collect()
}
