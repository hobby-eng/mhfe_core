//! CHECK-BLD-005: runs the step "Check the tag and write the release notes" of `release.yml`,
//! taken from the workflow file of a clone of the commit, the way GitHub runs a `run:` block
//! (`bash --noprofile --norc -eo pipefail`), and requires
//!   1. the tag `v<version of Cargo.toml>` to pass and to give the CHANGELOG section of that
//!      version;
//!   2. a tag of another version to fail;
//!   3. the right tag with a CHANGELOG that has no section for the version to fail.

use std::fs;
use std::path::Path;

use crate::Error;
use crate::tools;

const USAGE: &str = "usage: release-tag-step <repository> <commit> <work>";

/// The step's `- name:` line in `release.yml`.
const STEP: &str = "- name: Check the tag and write the release notes";

/// A tag of a version the crate does not have.
const OTHER_TAG: &str = "v9.9.9";

/// What check 3 puts in place of the version in its CHANGELOG heading.
const REMOVED_VERSION: &str = "0.0.0-removed";

pub(crate) fn run(arguments: &[String]) -> Result<bool, Error> {
    let [repository, commit, work] = arguments else {
        return Err(Error(USAGE.to_owned()));
    };
    let work = tools::work_folder(work)?;
    let clone = work.join("release-clone");
    tools::clone_at(Path::new(repository), commit, &clone)?;
    let workflow = fs::read_to_string(clone.join(".github/workflows/release.yml"))?;
    let step = step_script(&workflow)
        .ok_or_else(|| Error("the step was not found in release.yml".to_owned()))?;
    let script = work.join("release-step.sh");
    fs::write(&script, &step)?;
    println!("--- the step as run:\n{step}---");

    let manifest = fs::read_to_string(clone.join("Cargo.toml"))?;
    let version = tools::manifest_value(&manifest, "version")
        .ok_or_else(|| Error("Cargo.toml has no version".to_owned()))?;
    let tag = format!("v{version}");
    let changelog_path = clone.join("CHANGELOG.md");
    let changelog = fs::read_to_string(&changelog_path)?;
    let mut passed = true;

    if run_step(&clone, &script, &tag, &work)? {
        let notes = fs::read_to_string(work.join("runner-temp/notes.md"))?;
        let expected = section(&changelog, version);
        if !expected.is_empty() && notes.trim_end_matches('\n') == expected.trim_end_matches('\n') {
            let lines = notes.matches('\n').count();
            println!("1. {tag} passes; notes: {lines} lines of the CHANGELOG section {version}");
        } else {
            println!("1. FAILED: {tag} passes but the notes are not the CHANGELOG section");
            passed = false;
        }
    } else {
        println!("1. FAILED: {tag} is refused:");
        print!(
            "{}",
            fs::read_to_string(work.join(format!("step-{tag}.log")))?
        );
        passed = false;
    }

    if run_step(&clone, &script, OTHER_TAG, &work)? {
        println!("2. FAILED: the tag {OTHER_TAG} of another version passes");
        passed = false;
    } else {
        println!("2. the tag {OTHER_TAG} of another version is refused");
    }

    let without = without_section(&changelog, version)
        .ok_or_else(|| Error(format!("CHANGELOG.md has no heading `## {version} `")))?;
    fs::write(&changelog_path, without)?;
    let refused = !run_step(&clone, &script, &tag, &work)?;
    fs::write(&changelog_path, &changelog)?;
    if refused {
        println!("3. {tag} without a CHANGELOG section is refused");
    } else {
        println!("3. FAILED: {tag} passes without a CHANGELOG section");
        passed = false;
    }
    Ok(passed)
}

/// The `run: |` block of the step, its indentation removed: the lines after the step's first
/// `run: |` line that are blank or indented deeper than it.
fn step_script(workflow: &str) -> Option<String> {
    let mut lines = workflow
        .lines()
        .skip_while(|line| !line.contains(STEP))
        .skip(1);
    let run = lines.find(|line| {
        let rest = line.trim_start_matches(' ');
        rest.len() < line.len() && rest == "run: |"
    })?;
    // YAML's block scalar here is indented two spaces deeper than its key.
    let indent = run.len() - run.trim_start_matches(' ').len() + 2;
    let mut script = String::new();
    for line in lines {
        let blank = line.bytes().all(|byte| byte == b' ');
        if !blank
            && !line
                .get(..indent)
                .is_some_and(|start| start.bytes().all(|byte| byte == b' '))
        {
            break;
        }
        script.push_str(line.get(indent..).unwrap_or_default());
        script.push('\n');
    }
    (!script.is_empty()).then_some(script)
}

/// Runs the step for `tag` in the clone, offline; true when it passes.
fn run_step(clone: &Path, script: &Path, tag: &str, work: &Path) -> Result<bool, Error> {
    let runner_temp = work.join("runner-temp");
    tools::remove_folder(&runner_temp)?;
    fs::create_dir_all(&runner_temp)?;
    tools::logged(
        tools::tool("bash")
            .args(["--noprofile", "--norc", "-eo", "pipefail"])
            .arg(script)
            .current_dir(clone)
            .env("GITHUB_REF_NAME", tag)
            .env("RUNNER_TEMP", &runner_temp)
            .env("CARGO_NET_OFFLINE", "true"),
        &work.join(format!("step-{tag}.log")),
    )
}

/// The lines under the heading `## <version> …` up to the next `## ` heading.
fn section(changelog: &str, version: &str) -> String {
    let mut inside = false;
    let mut lines = String::new();
    for line in changelog.lines() {
        if line.starts_with("## ") {
            inside = line.split_whitespace().nth(1) == Some(version);
        } else if inside {
            lines.push_str(line);
            lines.push('\n');
        }
    }
    lines
}

/// The CHANGELOG with the version of its `## <version> ` headings replaced, or None when it has
/// no such heading, so that check 3 cannot pass without having removed the section.
fn without_section(changelog: &str, version: &str) -> Option<String> {
    let heading = format!("## {version} ");
    let replaced = changelog
        .split_inclusive('\n')
        .map(|line| match line.strip_prefix(&heading) {
            Some(rest) => format!("## {REMOVED_VERSION} {rest}"),
            None => line.to_owned(),
        })
        .collect::<String>();
    (replaced != changelog).then_some(replaced)
}
