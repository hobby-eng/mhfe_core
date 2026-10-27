//! The public API is the list of docs/public-api.txt: the items that src/lib.rs and its public
//! modules make public, read from the sources, each with its kind, its path and its `cfg` and
//! `non_exhaustive` attributes. The check also refuses `#[macro_export]` and `#[doc(hidden)]`
//! anywhere in src/, and a public enum without `#[non_exhaustive]`, but for the enums of
//! EXHAUSTIVE. It reads the sources as rustfmt writes them: an item of a module at the start of a
//! line, its attributes on the lines just above it.
//!
//! Run as `cargo xtask public-api`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::Failure;

const CRATE: &str = "mhfe_core";
/// The folder of the library's sources, which holds LIBRARY.
const SOURCES: &str = "src";
const LIBRARY: &str = "src/lib.rs";
const LIST: &str = "docs/public-api.txt";
/// The public enums that may stay exhaustive, by their paths in the crate: the outcomes of the
/// frozen MHFE-PASSWORD-CHECK-1.
const EXHAUSTIVE: &[&str] = &["password_check::Check"];
/// The kinds of a public item at the start of a line, `pub <kind> <rest>`, in the order they are
/// tried: `const fn` before `const`.
const KINDS: &[&str] = &[
    "const fn",
    "unsafe fn",
    "fn",
    "struct",
    "enum",
    "trait",
    "static",
    "const",
    "type",
    "union",
    "mod",
    "use",
];
/// The attributes that the list gives with an item: every `#[cfg(…)]`, and `#[non_exhaustive]`.
const CFG: &str = "#[cfg(";
const NON_EXHAUSTIVE: &str = "#[non_exhaustive]";
/// The attributes that make public items without listing them, or hide public items.
const REFUSED_ATTRIBUTES: &[&str] = &["#[macro_export]", "#[doc(hidden)]"];
/// The modules a `pub use` may not start from: the check follows a path down from its file only.
const UNREAD_MODULES: &[&str] = &["crate", "self", "super"];

/// An item at the start of a line of a module file, with the attributes just above it.
struct Item {
    kind: &'static str,
    /// What follows the kind: the item's name and the rest of its line, or a `use`'s whole tree.
    rest: String,
    attributes: Vec<String>,
}

/// An item as a module makes it public: its kind, its public name and its attributes.
struct Public {
    kind: &'static str,
    name: String,
    attributes: Vec<String>,
}

pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    let mut sources = BTreeMap::new();
    read_sources(root, SOURCES, &mut sources)?;
    let list = read(&root.join(LIST))?;
    match check(&sources, &list) {
        Ok(count) => {
            println!("The {count} public items are those of {LIST}.");
            Ok(())
        }
        Err(problems) => Err(Failure(format!(
            "{}\n{} problems with the public API.",
            problems.join("\n"),
            problems.len()
        ))),
    }
}

/// The problems of the public API, from the Rust files of src/ by their paths from the root and
/// the text of the list; without problems, the number of public items.
fn check(sources: &BTreeMap<String, String>, list: &str) -> Result<usize, Vec<String>> {
    let mut problems = Vec::new();
    for (file, text) in sources {
        for attribute in REFUSED_ATTRIBUTES {
            if text.contains(attribute) {
                problems.push(format!("{file}: {attribute} is refused"));
            }
        }
    }
    let mut api = Api { sources, problems };
    let in_code = unique(api.listed_items(LIBRARY, CRATE, &[]));
    let in_list = unique(
        list.split('\n')
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#')),
    );
    for line in &in_code {
        if !in_list.contains(&line.as_str()) {
            api.problems.push(format!("public, not in {LIST}: {line}"));
        }
    }
    for line in &in_list {
        if !in_code.iter().any(|listed| listed == line) {
            api.problems.push(format!("in {LIST}, not public: {line}"));
        }
    }
    // The same problem is found again each time a `pub use` is followed through its module.
    let problems = unique(api.problems);
    if problems.is_empty() {
        Ok(in_code.len())
    } else {
        Err(problems)
    }
}

/// The reader of the public items: the sources it reads them from, and what it found wrong.
struct Api<'a> {
    sources: &'a BTreeMap<String, String>,
    problems: Vec<String>,
}

impl Api<'_> {
    /// The public items of `file`, the module at `path`, as lines of the list.
    fn listed_items(&mut self, file: &str, path: &str, inherited: &[String]) -> Vec<String> {
        let mut lines = Vec::new();
        for item in self.items_of(file) {
            let items = match item.kind {
                "mod" => {
                    let name = declared_name(&item.rest);
                    let attributes = [inherited, &item.attributes].concat();
                    let module = format!("{path}::{name}");
                    lines.extend(self.listed_items(&module_file(file, name), &module, &attributes));
                    continue;
                }
                "use" => self.reexported(&item, file),
                kind => vec![Public {
                    kind,
                    name: declared_name(&item.rest).to_owned(),
                    attributes: item.attributes,
                }],
            };
            for public in items {
                let attributes = [inherited, &public.attributes].concat();
                let item_path = format!("{path}::{}", public.name);
                lines.push(self.list_line(public.kind, &item_path, &attributes));
            }
        }
        lines
    }

    /// The line of the list for one item; a public enum must be non-exhaustive (EXHAUSTIVE).
    fn list_line(&mut self, kind: &str, path: &str, attributes: &[String]) -> String {
        let mut listed: Vec<&str> = attributes
            .iter()
            .map(String::as_str)
            .filter(|attribute| attribute.starts_with(CFG) || *attribute == NON_EXHAUSTIVE)
            .collect();
        listed.sort_unstable();
        listed.dedup();
        let exhaustive = path
            .strip_prefix(CRATE)
            .and_then(|in_crate| in_crate.strip_prefix("::"))
            .is_some_and(|in_crate| EXHAUSTIVE.contains(&in_crate));
        if kind == "enum" && !listed.contains(&NON_EXHAUSTIVE) && !exhaustive {
            self.problems
                .push(format!("{path} is a public enum without {NON_EXHAUSTIVE}"));
        }
        [kind, path]
            .into_iter()
            .chain(listed)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The items a `pub use` of `file` re-exports, each with its public name and with the `use`'s
    /// attributes before its own.
    fn reexported(&mut self, item: &Item, file: &str) -> Vec<Public> {
        let Some((source_file, names)) = exports_of(&item.rest, file) else {
            let problem = format!(
                "{file}: pub use {} is not a form this check reads",
                item.rest
            );
            self.problems.push(problem);
            return Vec::new();
        };
        let mut exported = Vec::new();
        for (source, alias) in names {
            let Some(defined) = self.definition(&source_file, source) else {
                self.problems.push(format!("{file}: {source} is not found"));
                continue;
            };
            exported.push(Public {
                kind: defined.kind,
                name: alias.to_owned(),
                attributes: [item.attributes.as_slice(), &defined.attributes].concat(),
            });
        }
        exported
    }

    /// The item `name` that `file` defines or re-exports.
    fn definition(&mut self, file: &str, name: &str) -> Option<Public> {
        for item in self.items_of(file) {
            if item.kind == "use" {
                let reexported = self.reexported(&item, file);
                let found = reexported.into_iter().find(|public| public.name == name);
                if found.is_some() {
                    return found;
                }
            } else if declared_name(&item.rest) == name {
                return Some(Public {
                    kind: item.kind,
                    name: name.to_owned(),
                    attributes: item.attributes,
                });
            }
        }
        None
    }

    /// The public items of the module file `file`; a module declared without its file is reported.
    fn items_of(&mut self, file: &str) -> Vec<Item> {
        if let Some(text) = self.sources.get(file) {
            return public_items(text);
        }
        self.problems.push(format!("{file}: no such file"));
        Vec::new()
    }
}

/// The public items of a module file's text, each with the attributes just above it.
fn public_items(text: &str) -> Vec<Item> {
    let mut lines = text.split('\n');
    let mut items = Vec::new();
    let mut attributes = Vec::new();
    while let Some(line) = lines.next() {
        if line.starts_with("#[") {
            // An attribute may span lines: it ends where its brackets close.
            let mut attribute = line.to_owned();
            while attribute.matches('[').count() > attribute.matches(']').count() {
                let Some(next) = lines.next() else { break };
                attribute.push('\n');
                attribute.push_str(next);
            }
            attributes.push(attribute);
            continue;
        }
        // A comment between the attributes and their item keeps them.
        if line.starts_with("//") {
            continue;
        }
        if let Some((kind, first)) = public_item(line) {
            let mut rest = first.to_owned();
            while kind == "use" && !rest.contains(';') {
                let Some(next) = lines.next() else { break };
                rest.push(' ');
                rest.push_str(next.trim());
            }
            let kind = kind.strip_prefix("const ").unwrap_or(kind);
            items.push(Item {
                kind,
                rest,
                attributes: std::mem::take(&mut attributes),
            });
        }
        attributes.clear();
    }
    items
}

/// The kind and the rest of a line that starts a public item, `pub <kind> <rest>`.
fn public_item(line: &str) -> Option<(&'static str, &str)> {
    let item = line.strip_prefix("pub ")?;
    KINDS
        .iter()
        .find_map(|kind| Some((*kind, item.strip_prefix(kind)?.strip_prefix(' ')?)))
}

/// The file of the module `name` that `file` declares (RUST-03: `a.rs` beside `a/`).
fn module_file(file: &str, name: &str) -> String {
    let folder = if file == LIBRARY {
        SOURCES
    } else {
        file.strip_suffix(".rs").unwrap_or(file)
    };
    format!("{folder}/{name}.rs")
}

/// The name an item's line declares: the first identifier after its kind.
fn declared_name(rest: &str) -> &str {
    rest.split(|character: char| !is_word(character))
        .next()
        .unwrap_or_default()
}

/// What a `use` of `file` exports, `a::B;` or `a::{B, C as D};`: the file of its module, then
/// each name with its public name; `None` for another form.
fn exports_of<'a>(rest: &'a str, file: &str) -> Option<(String, Vec<(&'a str, &'a str)>)> {
    let tree = rest.split(';').next().unwrap_or_default().trim();
    let (prefix, names) = braced(tree).or_else(|| plain(tree))?;
    let modules: Vec<&str> = prefix.split("::").collect();
    if modules.iter().any(|module| UNREAD_MODULES.contains(module)) {
        return None;
    }
    let source_file = modules
        .iter()
        .fold(file.to_owned(), |file, name| module_file(&file, name));
    let names = names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.split_once(" as ").unwrap_or((name, name)))
        .collect();
    Some((source_file, names))
}

/// The module path and the names of `a::b::{C, D as E}`.
fn braced(tree: &str) -> Option<(&str, &str)> {
    let (prefix, names) = tree.strip_suffix('}')?.split_once("::{")?;
    (is_path(prefix) && !names.contains(['{', '}'])).then_some((prefix, names))
}

/// The module path and the name of `a::b::C` or `a::b::C as D`.
fn plain(tree: &str) -> Option<(&str, &str)> {
    let (prefix, name) = tree.rsplit_once("::")?;
    let words: Vec<&str> = name.split(" as ").collect();
    let named = words.len() <= 2
        && words
            .iter()
            .all(|word| !word.is_empty() && word.chars().all(is_word));
    (is_path(prefix) && named).then_some((prefix, name))
}

/// Whether `prefix` is made of identifiers and colons only, as a module path is.
fn is_path(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix
            .chars()
            .all(|character| is_word(character) || character == ':')
}

/// Whether `character` may be part of an identifier as this check reads one, ASCII only.
fn is_word(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

/// `values` without repeats, in the order they first come.
fn unique<T: PartialEq>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

/// Every Rust file under `directory`, by its path from the root, with its text.
fn read_sources(
    root: &Path,
    directory: &str,
    sources: &mut BTreeMap<String, String>,
) -> Result<(), Failure> {
    let folder = root.join(directory);
    let entries =
        fs::read_dir(&folder).map_err(|error| Failure(format!("{}: {error}", folder.display())))?;
    for entry in entries {
        let entry = entry?;
        let path = format!("{directory}/{}", entry.file_name().to_string_lossy());
        if entry.file_type()?.is_dir() {
            read_sources(root, &path, sources)?;
        } else if path.ends_with(".rs") {
            sources.insert(path, read(&entry.path())?);
        }
    }
    Ok(())
}

/// The text of the file at `path`.
fn read(path: &Path) -> Result<String, Failure> {
    fs::read_to_string(path).map_err(|error| Failure(format!("{}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sources of a crate, from pairs of a path and a text.
    fn crate_of(files: &[(&str, &str)]) -> BTreeMap<String, String> {
        files
            .iter()
            .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
            .collect()
    }

    /// A crate with a public module, re-exports through a `use` over several lines, a `const fn`,
    /// a method, and attributes over several lines with a comment below them.
    fn sample() -> BTreeMap<String, String> {
        crate_of(&[
            (
                "src/lib.rs",
                "mod cipher;\npub mod protect;\n#[cfg(unix)]\npub use cipher::{\n    Mhfe,\n    \
                 Suite as Kind,\n};\npub const fn words() -> usize {\n    24\n}\n",
            ),
            (
                "src/cipher.rs",
                "pub struct Mhfe;\n#[non_exhaustive]\n// The suites.\n#[derive(\n    Debug,\n)]\n\
                 pub enum Suite {}\nimpl Mhfe {\n    pub fn new() {}\n}\n",
            ),
            (
                "src/protect.rs",
                "#[cfg(not(target_arch = \"wasm32\"))]\npub fn write_secret() {}\n",
            ),
        ])
    }

    const SAMPLE_LIST: &str = "# The public items.\n\
        fn mhfe_core::protect::write_secret #[cfg(not(target_arch = \"wasm32\"))]\n\
        struct mhfe_core::Mhfe #[cfg(unix)]\n\
        enum mhfe_core::Kind #[cfg(unix)] #[non_exhaustive]\n\
        fn mhfe_core::words\n";

    #[test]
    fn the_items_of_the_list_pass_with_their_count() {
        assert_eq!(check(&sample(), SAMPLE_LIST), Ok(4));
    }

    #[test]
    fn an_item_public_but_not_listed_and_one_listed_but_not_public_are_refused() {
        let list = SAMPLE_LIST.replace("fn mhfe_core::words\n", "fn mhfe_core::sentences\n");
        assert_eq!(
            check(&sample(), &list),
            Err(vec![
                "public, not in docs/public-api.txt: fn mhfe_core::words".to_owned(),
                "in docs/public-api.txt, not public: fn mhfe_core::sentences".to_owned(),
            ])
        );
    }

    #[test]
    fn macro_export_and_doc_hidden_are_refused_anywhere_in_src() {
        let mut sources = sample();
        sources.insert(
            "src/hidden.rs".to_owned(),
            "#[doc(hidden)]\nfn a() {}\n".to_owned(),
        );
        sources.insert(
            "src/macros.rs".to_owned(),
            "#[macro_export]\nmacro_rules! a {}\n".to_owned(),
        );
        assert_eq!(
            check(&sources, SAMPLE_LIST),
            Err(vec![
                "src/hidden.rs: #[doc(hidden)] is refused".to_owned(),
                "src/macros.rs: #[macro_export] is refused".to_owned(),
            ])
        );
    }

    #[test]
    fn a_public_enum_without_non_exhaustive_is_refused_but_those_of_exhaustive() {
        let mut sources = sample();
        let cipher = sources["src/cipher.rs"].replace("#[non_exhaustive]\n", "");
        sources.insert("src/cipher.rs".to_owned(), cipher);
        sources.insert(
            "src/password_check.rs".to_owned(),
            "pub enum Check {}\n".to_owned(),
        );
        let lib = format!("pub mod password_check;\n{}", sources["src/lib.rs"]);
        sources.insert("src/lib.rs".to_owned(), lib);
        let list = SAMPLE_LIST.replace(" #[non_exhaustive]", "")
            + "enum mhfe_core::password_check::Check\n";
        assert_eq!(
            check(&sources, &list),
            Err(vec![
                "mhfe_core::Kind is a public enum without #[non_exhaustive]".to_owned()
            ])
        );
    }

    #[test]
    fn a_use_from_crate_and_a_name_its_module_lacks_are_refused() {
        let sources = crate_of(&[
            (
                "src/lib.rs",
                "mod cipher;\npub use crate::cipher::Mhfe;\npub use cipher::Gone;\n",
            ),
            ("src/cipher.rs", "pub struct Mhfe;\n"),
        ]);
        assert_eq!(
            check(&sources, ""),
            Err(vec![
                "src/lib.rs: pub use crate::cipher::Mhfe; is not a form this check reads"
                    .to_owned(),
                "src/lib.rs: Gone is not found".to_owned(),
            ])
        );
    }

    #[test]
    fn a_public_module_without_its_file_is_refused() {
        let sources = crate_of(&[("src/lib.rs", "pub mod protect;\n")]);
        assert_eq!(
            check(&sources, ""),
            Err(vec!["src/protect.rs: no such file".to_owned()])
        );
    }
}
