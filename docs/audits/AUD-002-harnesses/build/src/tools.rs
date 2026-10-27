//! What several harnesses share: clones, child processes, file lists, hashes and downloads.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

use crate::Error;

/// The `<work>` folder, created and made absolute, since the harnesses run tools inside clones.
pub(crate) fn work_folder(path: &str) -> Result<PathBuf, Error> {
    fs::create_dir_all(path)?;
    Ok(fs::canonicalize(path)?)
}

/// An absolute path to an existing file, such as the stand-in C compiler.
pub(crate) fn existing_file(path: &str) -> Result<PathBuf, Error> {
    fs::canonicalize(path).map_err(|error| Error(format!("{path}: {error}")))
}

/// Removes a folder this harness wrote on an earlier run, if it is there.
pub(crate) fn remove_folder(path: &Path) -> Result<(), Error> {
    match fs::remove_dir_all(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// A command for a tool inside a clone: without the toolchain rustup chose for this harness, so
/// that the clone's own `rust-toolchain.toml` applies.
pub(crate) fn tool(program: &str) -> Command {
    let mut command = Command::new(program);
    command.env_remove("RUSTUP_TOOLCHAIN");
    command
}

/// The standard output of a command that must succeed.
pub(crate) fn output(command: &mut Command) -> Result<Vec<u8>, Error> {
    let result = command.stderr(Stdio::piped()).output().map_err(|error| {
        Error(format!(
            "{}: {error}",
            command.get_program().to_string_lossy()
        ))
    })?;
    if result.status.success() {
        return Ok(result.stdout);
    }
    Err(Error(format!(
        "{} {}: {}",
        command.get_program().to_string_lossy(),
        result.status,
        String::from_utf8_lossy(&result.stderr).trim()
    )))
}

/// Runs a command with its output and errors written to `log`; true when it succeeds.
pub(crate) fn logged(command: &mut Command, log: &Path) -> Result<bool, Error> {
    let file = fs::File::create(log)?;
    let status = command.stdout(file.try_clone()?).stderr(file).status()?;
    Ok(status.success())
}

/// A fresh clone of `repository` at `commit`, in `clone`.
pub(crate) fn clone_at(repository: &Path, commit: &str, clone: &Path) -> Result<(), Error> {
    remove_folder(clone)?;
    output(
        tool("git")
            .args(["clone", "--quiet", "--no-checkout"])
            .arg(repository)
            .arg(clone),
    )?;
    output(tool("git").arg("-C").arg(clone).args([
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "--quiet",
        commit,
    ]))?;
    Ok(())
}

/// Checks out each submodule of `clone` from `repository`'s own checkout of it, offline. Since the
/// release commit the tests read the specification's vectors from the submodule `tests/spec`, so
/// Clippy on the test targets needs it, as CI checks out with `submodules: true`. A commit without
/// submodules is left as it is.
pub(crate) fn submodules_from(repository: &Path, clone: &Path) -> Result<(), Error> {
    if !clone.join(".gitmodules").is_file() {
        return Ok(());
    }
    let source = fs::canonicalize(repository)?;
    let paths = output(tool("git").arg("-C").arg(clone).args([
        "config",
        "--file",
        ".gitmodules",
        "--get-regexp",
        r"^submodule\..*\.path$",
    ]))?;
    for line in String::from_utf8_lossy(&paths).lines() {
        let (name, path) = line
            .strip_prefix("submodule.")
            .and_then(|rest| rest.split_once(".path "))
            .ok_or_else(|| Error(format!(".gitmodules: unexpected line `{line}`")))?;
        output(
            tool("git")
                .arg("-C")
                .arg(clone)
                .arg("config")
                .arg(format!("submodule.{name}.url"))
                .arg(source.join(path)),
        )?;
    }
    output(tool("git").arg("-C").arg(clone).args([
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "--quiet",
        "update",
        "--init",
    ]))?;
    Ok(())
}

/// Every file under `root`, as sorted paths relative to it with `/` between their parts.
pub(crate) fn files_under(root: &Path) -> Result<Vec<String>, Error> {
    let mut files = Vec::new();
    let mut folders = vec![root.to_path_buf()];
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder)? {
            let path = entry?.path();
            if path.is_dir() {
                folders.push(path);
            } else {
                let relative = path.strip_prefix(root).map_err(|e| Error(e.to_string()))?;
                let parts: Vec<_> = relative.iter().map(|part| part.to_string_lossy()).collect();
                files.push(parts.join("/"));
            }
        }
    }
    files.sort();
    Ok(files)
}

/// The SHA-256 of `bytes` in lowercase hex.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The value of the first line `key = "value"` of a manifest, which for `name` and `version`
/// is the package's own.
pub(crate) fn manifest_value<'a>(manifest: &'a str, key: &str) -> Option<&'a str> {
    manifest.lines().find_map(|line| {
        line.strip_prefix(key)?
            .strip_prefix(" = \"")?
            .strip_suffix('"')
    })
}

/// Seconds after which a download counts as failed, the limit of the archived scripts.
const DOWNLOAD_SECONDS: &str = "120";

/// The body of an HTTPS download, through curl; the error says why it failed.
pub(crate) fn download(url: &str) -> Result<Vec<u8>, Error> {
    output(Command::new("curl").args([
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--max-time",
        DOWNLOAD_SECONDS,
        url,
    ]))
}
