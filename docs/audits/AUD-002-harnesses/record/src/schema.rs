//! The JSON checks of the record: the JSON Schema keywords that the workspace's
//! `audit-report.schema.json` uses (draft 2020-12), written out, and duplicate keys, which a JSON
//! parser drops silently. A keyword this file does not know fails the check, so that a later
//! schema is never half applied (CORE-22).

use std::collections::BTreeSet;

use regex::Regex;
use serde_json::Value;

/// Adds to `found` the errors of `instance` against `schema`, whose `$ref`s point into `root`.
pub(crate) fn errors(
    root: &Value,
    schema: &Value,
    instance: &Value,
    place: &str,
    found: &mut Vec<String>,
) {
    let Some(keywords) = schema.as_object() else {
        found.push(format!("{place}: the schema {schema} is not an object"));
        return;
    };
    for (keyword, rule) in keywords {
        let ok = match keyword.as_str() {
            // Annotations and definitions constrain nothing themselves.
            "$schema" | "$id" | "title" | "$defs" => true,
            "type" => match rule {
                Value::String(name) => has_type(instance, name),
                Value::Array(names) => names
                    .iter()
                    .any(|name| name.as_str().is_some_and(|name| has_type(instance, name))),
                _ => false,
            },
            "const" => instance == rule,
            "enum" => rule
                .as_array()
                .is_some_and(|values| values.contains(instance)),
            "required" => instance.as_object().is_none_or(|object| {
                rule.as_array().is_some_and(|keys| {
                    keys.iter()
                        .all(|key| key.as_str().is_some_and(|key| object.contains_key(key)))
                })
            }),
            "pattern" => instance.as_str().is_none_or(|text| {
                rule.as_str()
                    .and_then(|pattern| Regex::new(pattern).ok())
                    .is_some_and(|pattern| pattern.is_match(text))
            }),
            "minLength" => instance.as_str().is_none_or(|text| {
                rule.as_u64()
                    .and_then(|least| usize::try_from(least).ok())
                    .is_some_and(|least| text.chars().count() >= least)
            }),
            "minimum" => instance
                .as_f64()
                .is_none_or(|number| rule.as_f64().is_some_and(|least| number >= least)),
            "properties" => match (instance.as_object(), rule.as_object()) {
                (Some(object), Some(properties)) => {
                    for (name, property) in properties {
                        if let Some(value) = object.get(name) {
                            errors(root, property, value, &format!("{place}.{name}"), found);
                        }
                    }
                    true
                }
                (None, properties) => properties.is_some(),
                (Some(_), None) => false,
            },
            "items" => {
                for (index, item) in instance.as_array().into_iter().flatten().enumerate() {
                    errors(root, rule, item, &format!("{place}[{index}]"), found);
                }
                true
            }
            "allOf" => rule.as_array().is_some_and(|schemas| {
                schemas
                    .iter()
                    .for_each(|schema| errors(root, schema, instance, place, found));
                true
            }),
            "$ref" => {
                let pointer = rule
                    .as_str()
                    .and_then(|reference| reference.strip_prefix('#'));
                let target = pointer.and_then(|pointer| root.pointer(pointer));
                target.is_some_and(|target| {
                    errors(root, target, instance, place, found);
                    true
                })
            }
            _ => {
                found.push(format!(
                    "{place}: the schema keyword {keyword} is not written out here"
                ));
                true
            }
        };
        if !ok {
            found.push(format!("{place}: fails {keyword} {rule}"));
        }
    }
}

fn has_type(instance: &Value, name: &str) -> bool {
    match name {
        "null" => instance.is_null(),
        "boolean" => instance.is_boolean(),
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "number" => instance.is_number(),
        // JSON Schema counts a number without a fractional part, 1.0 included, as an integer.
        "integer" => instance
            .as_f64()
            .is_some_and(|number| number.fract() == 0.0),
        _ => false,
    }
}

/// The keys that appear twice in one object of `text`, a JSON document that has parsed already;
/// keys are compared as written, escapes included.
pub(crate) fn duplicate_keys(text: &str) -> BTreeSet<String> {
    let mut objects: Vec<BTreeSet<&str>> = Vec::new();
    let mut duplicates = BTreeSet::new();
    let mut index = 0;
    while let Some(&byte) = text.as_bytes().get(index) {
        match byte {
            b'{' => objects.push(BTreeSet::new()),
            b'}' => drop(objects.pop()),
            b'"' => {
                let start = index + 1;
                index = start;
                while let Some(&byte) = text.as_bytes().get(index) {
                    match byte {
                        b'"' => break,
                        // An escape: the next byte, `"` or `\` included, is part of the string.
                        b'\\' => index += 2,
                        _ => index += 1,
                    }
                }
                let string = text.get(start..index).unwrap_or_default();
                let is_key = text
                    .get(index + 1..)
                    .is_some_and(|rest| rest.trim_start().starts_with(':'));
                if let Some(keys) = objects.last_mut().filter(|_| is_key)
                    && !keys.insert(string)
                {
                    duplicates.insert(string.to_owned());
                }
            }
            _ => {}
        }
        index += 1;
    }
    duplicates
}
