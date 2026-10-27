//! AUD-002 skeptic check of the Windows `no_core_dumps` claim of mhfe-core (see README.md beside
//! this crate). It reads the files of one commit with `git show`, so the working tree does not
//! matter, and prints PASS or FAIL per check. Exit 0 when every check passed, 1 when one failed, 2
//! when the harness stopped on an error.
//!
//!   aud002-skeptic-doc-wer [commit]   (default: the reviewed commit)

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// A harness prints its errors and stops; it has no module errors to tell apart.
type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The exit code when a check failed.
const FAILED: u8 = 1;
/// The exit code when the harness stopped on an error.
const UNDECIDED: u8 = 2;
/// The commit AUD-002 reviewed.
const REVIEWED: &str = "dec9c8115ff9ddbd32bb5fdd457ae9904043c966";
/// The calls that change Windows crash reports: WER's flags, the error mode, an exception filter or
/// handler, an excluded application and the `LocalDumps` registry key.
const CRASH_REPORT_CALLS: [&str; 6] = [
    "WerSetFlags(",
    "SetErrorMode",
    "SetUnhandledExceptionFilter",
    "WerAddExcludedApplication",
    "AddVectoredExceptionHandler",
    "LocalDumps",
];
/// The one call the finding says `enter()` makes: error reports leave out the heap.
const NOHEAP_CALL: &str = "WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)";
/// `no_core_dumps` on Windows as the NOHEAP flag read back.
const NOHEAP_READBACK: &str =
    "no_core_dumps: read && flags & WER_FAULT_REPORTING_FLAG_NOHEAP != 0,";
/// The field doc's opening that promises no dump on every system.
const NO_DUMP_PROMISE: &str = "/// A crash writes no core dump:";
/// What an error report still holds. "register" alone is no residue word here: these texts say
/// "registers" about other programs, "registry" and WerRegisterExcludedMemoryBlock.
const RESIDUE: &str = "stack";
/// How SECURITY.md and `enter()`'s doc name Android's crash residue, the documents' own standard.
const ANDROID_RESIDUE: &str = "tombstone holds the registers";

fn main() -> ExitCode {
    let commit = std::env::args().nth(1);
    match run(commit.as_deref().unwrap_or(REVIEWED)) {
        Ok(report) if report.failed.is_empty() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(FAILED),
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::from(UNDECIDED)
        }
    }
}

fn run(commit: &str) -> Result<Report> {
    let root = repository()?;
    let show = |path: &str| -> Result<String> {
        output(
            Command::new("git")
                .arg("-C")
                .arg(&root)
                .arg("show")
                .arg(format!("{commit}:{path}")),
        )
    };
    let texts = Texts {
        os: show("src/os.rs")?,
        windows: show("src/os/windows.rs")?,
        protect: show("src/protect.rs")?,
        security: show("SECURITY.md")?,
        readme: show("README.md")?,
    };
    let mut report = Report::default();
    check_claims(&texts, &mut report);
    Ok(report)
}

/// The files the claims are read from, at one commit.
struct Texts {
    os: String,
    windows: String,
    protect: String,
    security: String,
    readme: String,
}

fn check_claims(texts: &Texts, report: &mut Report) {
    check_windows_code(&texts.os, &texts.windows, report);
    check_field_doc(&texts.protect, report);
    check_windows_texts(texts, report);
    // Check 5, the documents' own standard: the Android text names its crash residue.
    report.check(
        "android-residue",
        texts.security.contains(ANDROID_RESIDUE) && texts.protect.contains(ANDROID_RESIDUE),
        "SECURITY.md and enter() name Android's crash residue",
        "Android's crash residue is not named either",
    );
}

/// Checks 1 and 2: the Windows module is what `enter()` runs on Windows; its only crash-report
/// setting is WER's NOHEAP flag, nothing turns error reports off, and `no_core_dumps` is that flag
/// read back.
fn check_windows_code(os: &str, windows: &str, report: &mut Report) {
    let routed = os.lines().any(|line| line == "#[cfg(windows)]")
        && os.contains("pub(crate) use windows::{enter");
    report.check(
        "windows-module",
        routed,
        "src/os.rs uses os/windows.rs's enter() on Windows",
        "src/os.rs does not route enter() to os/windows.rs on Windows",
    );
    let calls: Vec<String> = windows
        .lines()
        .enumerate()
        .filter(|(_, line)| CRASH_REPORT_CALLS.iter().any(|call| line.contains(call)))
        .map(|(index, line)| format!("{}:{line}", index + 1))
        .collect();
    println!("crash-report calls in src/os/windows.rs:");
    for call in &calls {
        println!("{call}");
    }
    report.check(
        "noheap-only",
        matches!(calls.as_slice(), [only] if only.contains(NOHEAP_CALL)),
        "enter() sets WER_FAULT_REPORTING_FLAG_NOHEAP and nothing else about reports",
        "enter() changes error reporting beyond NOHEAP; re-read the finding",
    );
    report.check(
        "readback",
        windows.contains(NOHEAP_READBACK),
        "no_core_dumps on Windows is the NOHEAP flag read back",
        "no_core_dumps on Windows is computed otherwise",
    );
}

/// Check 3: the field doc of `no_core_dumps` neither opens with a promise of no dump on every
/// system nor leaves out the stacks an error report keeps.
fn check_field_doc(protect: &str, report: &mut Report) {
    let Some(doc) = field_doc(protect) else {
        report.check(
            "field-doc",
            false,
            "",
            "no field doc of no_core_dumps in struct Isolation",
        );
        return;
    };
    println!("field doc:");
    print!("{doc}");
    report.check(
        "field-doc",
        !doc.contains(NO_DUMP_PROMISE),
        "the field doc does not promise no dump on every system",
        "the field doc's opening promises that a crash writes no core dump, on every system",
    );
    report.check(
        "field-doc-residue",
        doc.to_lowercase().contains(RESIDUE),
        "the field doc names the stacks an error report keeps",
        "the field doc never names the stacks an error report keeps",
    );
}

/// Check 4: every Windows text names the stacks an error report keeps: SECURITY.md's section, the
/// Windows paragraph of `enter()`'s doc and README's bullet.
fn check_windows_texts(texts: &Texts, report: &mut Report) {
    let sections = [
        (
            "SECURITY.md-windows",
            block(
                &texts.security,
                |line| line == "### Windows",
                |line| line.starts_with("### ") || line.starts_with("## "),
            ),
        ),
        (
            "enter-doc-windows",
            block(
                &texts.protect,
                |line| line.starts_with("    /// Windows, for the whole process"),
                |line| line == "    ///",
            ),
        ),
        (
            "README-windows",
            block(
                &texts.readme,
                |line| line.starts_with("- **Windows:**"),
                |line| line.starts_with("- **"),
            ),
        ),
    ];
    for (name, text) in sections {
        if text.is_empty() {
            report.check(name, false, "", "section not found");
        } else {
            report.check(
                name,
                text.to_lowercase().contains(RESIDUE),
                "names the stacks an error report keeps",
                "never names the stacks an error report keeps",
            );
        }
        println!("  (each \"register\" in {name}, in context:");
        for context in register_contexts(&text) {
            println!("    {context}");
        }
        println!("  )");
    }
}

/// The doc lines right above the field `no_core_dumps` of `struct Isolation`, or None when the
/// struct has no such field.
fn field_doc(protect: &str) -> Option<String> {
    let mut doc = String::new();
    let fields = protect
        .lines()
        .skip_while(|line| !line.starts_with("pub struct Isolation"))
        .skip(1);
    for line in fields {
        if line.starts_with("    ///") {
            doc.push_str(line);
            doc.push('\n');
        } else if line.contains("pub no_core_dumps") {
            return Some(doc);
        } else {
            doc.clear();
        }
    }
    None
}

/// The lines from the first one `starts` accepts up to the next one `ends` accepts, which is left
/// out; empty when no line starts it.
fn block(text: &str, starts: impl Fn(&str) -> bool, ends: impl Fn(&str) -> bool) -> String {
    let mut lines = text.lines().skip_while(|line| !starts(line));
    let first = lines.next();
    first
        .into_iter()
        .chain(lines.take_while(|line| !ends(line)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Each word that holds "register", with the two words before it and the one after, for a reader
/// to see that none of them names an error report's residue.
fn register_contexts(text: &str) -> Vec<String> {
    let mut contexts = Vec::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split(' ').collect();
        for (index, word) in words.iter().enumerate() {
            if word.to_lowercase().contains("register") && index >= 2 && index + 1 < words.len() {
                contexts.push(words[index - 2..=index + 1].join(" "));
            }
        }
    }
    contexts
}

/// The repository that holds this harness, four folders above this crate
/// (docs/audits/AUD-002-harnesses/skeptic-doc-wer).
fn repository() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .map(Path::to_path_buf)
        .ok_or_else(|| "the harness is not inside a repository's docs/audits/".into())
}

/// The standard output of a tool that must succeed.
fn output(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .map_err(|error| format!("{command:?}: {error}"))?;
    if !output.status.success() {
        let errors = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{command:?}: {}", errors.trim()).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// The names of the checks that failed so far.
#[derive(Default)]
struct Report {
    failed: Vec<&'static str>,
}

impl Report {
    fn check(&mut self, name: &'static str, passed: bool, pass: &str, fail: &str) {
        if passed {
            println!("PASS {name}: {pass}");
        } else {
            println!("FAIL {name}: {fail}");
            self.failed.push(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checks_that_pass_at_the_reviewed_commit_refuse_texts_that_break_them() {
        let texts = Texts {
            os: "#[cfg(unix)]\npub(crate) use unix::{enter, write_secret};\n".to_owned(),
            windows: "unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) };\n\
                      unsafe { SetErrorMode(SEM_NOGPFAULTERRORBOX) };\n\
                      no_core_dumps: read,\n"
                .to_owned(),
            protect: String::new(),
            security: "its tombstone holds the registers\n".to_owned(),
            readme: String::new(),
        };
        let mut report = Report::default();
        check_claims(&texts, &mut report);
        for name in [
            "windows-module",
            "noheap-only",
            "readback",
            "field-doc",
            "android-residue",
        ] {
            assert!(report.failed.contains(&name), "{name} passed");
        }
    }
}
