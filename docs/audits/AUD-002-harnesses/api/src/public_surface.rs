//! The public surface of mhfe-core read from its rustdoc JSON (CHECK-API-003). Each check is a
//! failure when it does not hold:
//!
//! 1. the public items are exactly the paths of `docs/public-api.txt`;
//! 2. every secret type has `Debug` and no `Display`;
//! 3. `Error` and `repair::Error` have `Display` and `std::error::Error`;
//! 4. no public signature, field, variant or trait item names a type of a dependency (anything
//!    but std, core and alloc);
//! 5. every public type but the generic `Mhfe` is `Send` and `Sync` (rustdoc's auto-trait impls).
//!
//! It prints, for each public type, its trait impls and inherent methods, and for each trait its
//! items. The lines keep the form of the archived `public_surface.py`, which this replaces, so
//! that the two outputs compare byte for byte (RUST-14).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::Outcome;

/// The crates whose types a public signature may name.
const STD: [&str; 3] = ["std", "core", "alloc"];
/// The crate under review, crate 0 of its own rustdoc JSON.
const OWN: &str = "mhfe_core";
/// The types that hold a secret: `Debug` prints them redacted, and `Display` would not.
const SECRETS: [&str; 10] = [
    "Password",
    "Phrase",
    "Recovery",
    "Reading",
    "protect::Secret",
    "wallet_check::Seed",
    "repair::Card",
    "repair::Repaired",
    "repair::Change",
    "password_check::Check",
];
const ERRORS: [&str; 2] = ["Error", "repair::Error"];
/// The one public type that need not be `Send` and `Sync`: it is generic over its engine.
const GENERIC: &str = "Mhfe";
/// An absent list, such as the impls of an item rustdoc gives none.
const NONE: &[Value] = &[];

/// What the walk over the public items gathers: the trait names of each struct and enum, by its
/// path without the crate's name, and the failures so far.
#[derive(Default)]
struct Survey {
    traits: BTreeMap<String, BTreeSet<String>>,
    failures: Vec<String>,
}

/// Reads the rustdoc JSON at `json` and the list at `list`, prints the surface and checks it.
pub(crate) fn run(json: &Path, list: &Path) -> Outcome {
    let read = |path: &Path| {
        fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
    };
    let doc: Value = serde_json::from_str(&read(json)?)
        .map_err(|error| format!("{}: {error}", json.display()))?;
    let listed = listed_paths(&read(list)?)?;
    let mut public = BTreeMap::new();
    walk(&doc, item(&doc, &doc["root"])?, OWN, &mut public)?;
    let mut survey = Survey::default();
    let found: BTreeSet<String> = public.keys().cloned().collect();
    if found != listed {
        let only_code: Vec<&String> = found.difference(&listed).collect();
        let only_list: Vec<&String> = listed.difference(&found).collect();
        survey.failures.push(format!(
            "items differ from public-api.txt: only in code {}, only in list {}",
            py_list(only_code),
            py_list(only_list)
        ));
    }
    println!("{} public items", found.len());
    let crates = crate_names(&doc)?;
    for (path, it) in &public {
        survey_item(&doc, &crates, path, it, &mut survey)?;
    }
    check_traits(&mut survey);
    for failure in &survey.failures {
        println!("FAIL {failure}");
    }
    if survey.failures.is_empty() {
        println!("passed");
    } else {
        println!("{} failures", survey.failures.len());
    }
    Ok(survey.failures.is_empty())
}

/// The paths of `docs/public-api.txt`: the second field of each line that is not blank or a
/// comment.
fn listed_paths(text: &str) -> Result<BTreeSet<String>, String> {
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.split_whitespace()
                .nth(1)
                .map(str::to_owned)
                .ok_or_else(|| format!("public-api.txt: no path on the line {line:?}"))
        })
        .collect()
}

/// Every public item under `module`, by its path; a `use` stands for the item it re-exports.
fn walk<'a>(
    doc: &'a Value,
    module: &'a Value,
    path: &str,
    public: &mut BTreeMap<String, &'a Value>,
) -> Result<(), String> {
    for id in array(&module["inner"]["module"]["items"])? {
        let it = item(doc, id)?;
        if kind_of(it)? == "use" {
            let used = &it["inner"]["use"];
            public.insert(
                format!("{path}::{}", text(&used["name"])?),
                item(doc, &used["id"])?,
            );
        } else if it["visibility"] == "public" {
            let inner_path = format!("{path}::{}", text(&it["name"])?);
            if kind_of(it)? == "module" {
                walk(doc, it, &inner_path, public)?;
            } else {
                public.insert(inner_path, it);
            }
        }
    }
    Ok(())
}

/// Prints one public item's traits and methods or items, records the traits of a struct or an
/// enum, and records a failure when the item names a type of a dependency.
fn survey_item(
    doc: &Value,
    crates: &BTreeMap<u64, String>,
    path: &str,
    it: &Value,
    survey: &mut Survey,
) -> Result<(), String> {
    let kind = kind_of(it)?;
    let inner = &it["inner"][kind];
    let short = path.strip_prefix("mhfe_core::").unwrap_or(path);
    let mut mentioned = Vec::new();
    match kind {
        "function" => type_paths(&inner["sig"], &mut mentioned)?,
        "struct" | "enum" => {
            let mut names = BTreeSet::new();
            let mut methods = Vec::new();
            let impls = inner.get("impls").map_or(Ok(NONE), array)?;
            for id in impls {
                let imp = &item(doc, id)?["inner"]["impl"];
                if !imp["blanket_impl"].is_null() {
                    continue;
                }
                if imp["trait"].is_null() {
                    for member in array(&imp["items"])? {
                        let member = item(doc, member)?;
                        if member["visibility"] == "public" {
                            methods.push(text(&member["name"])?.to_owned());
                            type_paths(&member["inner"], &mut mentioned)?;
                        }
                    }
                } else {
                    let negative = if imp["is_negative"] == true { "!" } else { "" };
                    names.insert(format!("{negative}{}", text(&imp["trait"]["path"])?));
                }
            }
            let parts = if kind == "struct" {
                inner["kind"]
                    .get("plain")
                    .map_or(Ok(NONE), |plain| array(&plain["fields"]))?
            } else {
                array(&inner["variants"])?
            };
            for part in parts {
                type_paths(&item(doc, part)?["inner"], &mut mentioned)?;
            }
            println!(
                "{kind} {short}: traits {}; methods {}",
                py_list(&names),
                py_list(&methods)
            );
            survey.traits.insert(short.to_owned(), names);
        }
        "trait" => {
            let mut names = Vec::new();
            for member in array(&inner["items"])? {
                let member = item(doc, member)?;
                type_paths(&member["inner"], &mut mentioned)?;
                names.push(text(&member["name"])?.to_owned());
            }
            println!("trait {short}: items {}", py_list(&names));
        }
        "static" => type_paths(&inner["type"], &mut mentioned)?,
        _ => {}
    }
    let bad = foreign(doc, crates, &mentioned)?;
    if !bad.is_empty() {
        survey
            .failures
            .push(format!("{short} names dependency types {}", py_list(&bad)));
    }
    Ok(())
}

/// Checks 2, 3 and 5 on the traits the walk recorded.
fn check_traits(survey: &mut Survey) {
    let none = BTreeSet::new();
    for name in SECRETS {
        let has = survey.traits.get(name).unwrap_or(&none);
        let (debug, display) = (has.contains("Debug"), has.contains("Display"));
        if !debug || display {
            survey
                .failures
                .push(format!("{name}: Debug {debug}, Display {display}"));
        }
    }
    for name in ERRORS {
        let has = survey.traits.get(name).unwrap_or(&none);
        if !(has.contains("Display") && has.contains("Error")) {
            survey.failures.push(format!(
                "{name}: missing Display or Error, has {}",
                py_list(has)
            ));
        }
    }
    for (name, has) in &survey.traits {
        if name == GENERIC {
            continue;
        }
        for auto in ["Send", "Sync"] {
            if !has.contains(auto) {
                survey
                    .failures
                    .push(format!("{name} is not {auto}: {}", py_list(has)));
            }
        }
    }
}

/// Every resolved path id that a type, a signature or any other part of an item mentions.
fn type_paths(value: &Value, out: &mut Vec<u64>) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            if let Some(resolved) = map.get("resolved_path") {
                out.push(id_of(&resolved["id"])?);
            }
            for inner in map.values() {
                type_paths(inner, out)?;
            }
        }
        Value::Array(values) => {
            for inner in values {
                type_paths(inner, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The paths, sorted and once each, of the ids that belong to a crate other than std, core,
/// alloc and the crate itself. An id of an unknown crate counts as foreign.
fn foreign(
    doc: &Value,
    crates: &BTreeMap<u64, String>,
    ids: &[u64],
) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for id in ids {
        let Some(summary) = doc["paths"].get(id.to_string()) else {
            continue;
        };
        let owner = crates
            .get(&id_of(&summary["crate_id"])?)
            .map(String::as_str);
        if !owner.is_some_and(|owner| owner == OWN || STD.contains(&owner)) {
            let parts: Vec<&str> = array(&summary["path"])?
                .iter()
                .map(text)
                .collect::<Result<_, _>>()?;
            names.insert(parts.join("::"));
        }
    }
    Ok(names)
}

/// The name of each crate by its id; the crate itself is 0.
fn crate_names(doc: &Value) -> Result<BTreeMap<u64, String>, String> {
    let external = doc["external_crates"]
        .as_object()
        .ok_or("no external_crates in the rustdoc JSON")?;
    let mut crates = BTreeMap::from([(0, OWN.to_owned())]);
    for (id, external) in external {
        let id = id.parse().map_err(|_| format!("not a crate id: {id}"))?;
        crates.insert(id, text(&external["name"])?.to_owned());
    }
    Ok(crates)
}

fn item<'a>(doc: &'a Value, id: &Value) -> Result<&'a Value, String> {
    let key = id_of(id)?.to_string();
    doc["index"]
        .get(&key)
        .ok_or_else(|| format!("no item {key} in the index"))
}

/// The kind of an item: the one key of its `inner`.
fn kind_of(item: &Value) -> Result<&str, String> {
    item["inner"]
        .as_object()
        .and_then(|inner| inner.keys().next())
        .map(String::as_str)
        .ok_or_else(|| format!("an item without a kind: {}", item["id"]))
}

fn id_of(value: &Value) -> Result<u64, String> {
    value.as_u64().ok_or_else(|| format!("not an id: {value}"))
}

fn text(value: &Value) -> Result<&str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("not a string: {value}"))
}

fn array(value: &Value) -> Result<&[Value], String> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("not an array: {value}"))
}

/// Names as Python prints a list of plain identifiers and paths, `['a', 'b']`: the form of the
/// archived script's output.
fn py_list<T: AsRef<str>>(names: impl IntoIterator<Item = T>) -> String {
    let quoted: Vec<String> = names
        .into_iter()
        .map(|name| format!("'{}'", name.as_ref()))
        .collect();
    format!("[{}]", quoted.join(", "))
}
