//! CHECK-BLD-005, CHECK-DOC-002: what Cargo builds when a registry withdraws a version and
//! publishes other bytes under the same version, as CHANGELOG.md's 0.1.0 section says mhfe-core
//! does. A local sparse registry on 127.0.0.1, with a fresh `CARGO_HOME`, serves a synthetic crate
//! `probe` 0.1.0 whose code says "withdrawn"; a consumer builds it, which fills Cargo's cache. The
//! registry then serves other bytes as `probe` 0.1.0, saying "republished", with their checksum.
//! The harness requires, after that:
//!   1. `cargo update -p probe`, CHANGELOG's advice for a Cargo.lock that recorded the earlier
//!      package, to succeed in the first consumer;
//!   2. the first consumer, its lockfile renewed (by that advice, or else by
//!      `cargo generate-lockfile`), to run the republished code;
//!   3. a new consumer without a Cargo.lock, on the same machine, to run the republished code.
//!
//! Nothing leaves the computer, and the person's own `CARGO_HOME` is not used.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use crate::Error;
use crate::tools;

const USAGE: &str = "usage: republished-version <work>";

/// The toolchain of the audit (`rust-toolchain.toml` at dec9c81), named because the consumers
/// sit outside the repository.
const TOOLCHAIN: &str = "+1.99.1";

/// What `probe` says before and after the registry replaces it.
const WITHDRAWN: &str = "withdrawn";
const REPUBLISHED: &str = "republished";

/// The folders this harness writes in `<work>`, removed first on a rerun.
const FOLDERS: [&str; 6] = [
    "served",
    "cargo-home",
    "probe-withdrawn",
    "probe-republished",
    "first",
    "second",
];

pub(crate) fn run(arguments: &[String]) -> Result<bool, Error> {
    let [work] = arguments else {
        return Err(Error(USAGE.to_owned()));
    };
    let work = tools::work_folder(work)?;
    for folder in FOLDERS {
        tools::remove_folder(&work.join(folder))?;
    }
    let served = work.join("served");
    fs::create_dir_all(served.join("index/pr/ob"))?;
    fs::create_dir_all(served.join("dl"))?;
    let cargo_home = work.join("cargo-home");
    fs::create_dir_all(&cargo_home)?;
    let base = format!("http://127.0.0.1:{}", serve(served.clone())?);
    fs::write(
        served.join("index/config.json"),
        format!("{{\"dl\":\"{base}/dl/{{crate}}-{{version}}.crate\",\"api\":null}}\n"),
    )?;
    fs::write(
        cargo_home.join("config.toml"),
        format!("[registries.probe]\nindex = \"sparse+{base}/index/\"\n"),
    )?;
    let cargo = |folder: &Path| {
        let mut command = Command::new("cargo");
        command
            .arg(TOOLCHAIN)
            .current_dir(folder)
            .env("CARGO_HOME", &cargo_home)
            .env_remove("CARGO_TARGET_DIR");
        command
    };

    serve_probe(&work, WITHDRAWN, &cargo)?;
    let first = make_consumer(&work, "first")?;
    println!(
        "first consumer, first build: {}",
        run_consumer(&first, &cargo)?
    );
    let cache = cargo_home.join("registry/cache");
    let mut cached = Vec::new();
    for path in tools::files_under(&cache)? {
        if path.ends_with("/probe-0.1.0.crate") {
            cached.push(tools::sha256_hex(&fs::read(cache.join(path))?));
        }
    }
    println!("  cached: {}", cached.join(" "));

    serve_probe(&work, REPUBLISHED, &cargo)?;
    let mut passed = true;
    match cargo_outcome(cargo(&first).args(["run", "--quiet"]))? {
        Ok(output) => println!("first consumer, old Cargo.lock: runs and prints \"{output}\""),
        Err(error) => println!("first consumer, old Cargo.lock: refused: {error}"),
    }
    match cargo_outcome(cargo(&first).args(["update", "--quiet", "-p", "probe"]))? {
        Ok(_) => println!("1. cargo update -p probe succeeds"),
        Err(error) => {
            println!("1. FAILED: cargo update -p probe is refused: {error}");
            passed = false;
            tools::output(cargo(&first).args(["generate-lockfile", "--quiet"]))?;
            println!("   cargo generate-lockfile renews the lockfile instead");
        }
    }
    println!("   Cargo.lock now records: {}", locked_checksum(&first)?);
    let output = run_consumer(&first, &cargo)?;
    passed &= runs_republished(2, "the first consumer, its lockfile renewed,", &output);

    let second = make_consumer(&work, "second")?;
    let output = run_consumer(&second, &cargo)?;
    println!(
        "  the second consumer's Cargo.lock records: {}",
        locked_checksum(&second)?
    );
    passed &= runs_republished(3, "a new consumer on the same machine", &output);
    Ok(passed)
}

/// Serves the files under `root` on 127.0.0.1 for as long as the harness runs; returns the port.
fn serve(root: PathBuf) -> Result<u16, Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let root = root.clone();
            thread::spawn(move || {
                if let Err(error) = stream.and_then(|stream| answer(&stream, &root)) {
                    eprintln!("the local registry: {error}");
                }
            });
        }
    });
    Ok(port)
}

/// Answers one GET request with the file at its path, or 404, and closes the connection. It
/// sends no `ETag` or `Last-Modified`, so Cargo cannot revalidate its copy of the index and
/// always fetches the file as it now is (the archived script waited two seconds for that).
fn answer(stream: &TcpStream, root: &Path) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
            break;
        }
    }
    let path = request.split_whitespace().nth(1).unwrap_or("/");
    let file = (!path.contains("..")).then(|| root.join(path.trim_start_matches('/')));
    let (status, body) = match file.map(fs::read) {
        Some(Ok(body)) => ("200 OK", body),
        _ => ("404 Not Found", Vec::new()),
    };
    let mut writer = stream;
    write!(
        writer,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    writer.write_all(&body)
}

/// Packages `probe` 0.1.0 saying `text` and serves it with its checksum.
fn serve_probe(work: &Path, text: &str, cargo: &dyn Fn(&Path) -> Command) -> Result<(), Error> {
    let folder = work.join(format!("probe-{text}"));
    fs::create_dir_all(folder.join("src"))?;
    fs::write(
        folder.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
         description = \"audit probe\"\nlicense = \"MIT\"\n",
    )?;
    fs::write(
        folder.join("src/lib.rs"),
        format!("pub const CODE: &str = \"{text}\";\n"),
    )?;
    tools::output(
        cargo(&folder)
            .args([
                "package",
                "--quiet",
                "--no-verify",
                "--allow-dirty",
                "--target-dir",
            ])
            .arg(folder.join("target")),
    )?;
    let package = fs::read(folder.join("target/package/probe-0.1.0.crate"))?;
    let served = work.join("served");
    fs::write(served.join("dl/probe-0.1.0.crate"), &package)?;
    let sum = tools::sha256_hex(&package);
    fs::write(
        served.join("index/pr/ob/probe"),
        format!(
            "{{\"name\":\"probe\",\"vers\":\"0.1.0\",\"deps\":[],\"cksum\":\"{sum}\",\"features\":{{}},\"yanked\":false}}\n"
        ),
    )?;
    println!("the registry serves probe 0.1.0 saying \"{text}\", checksum {sum}");
    Ok(())
}

/// A binary crate that prints what `probe` says.
fn make_consumer(work: &Path, name: &str) -> Result<PathBuf, Error> {
    let folder = work.join(name);
    fs::create_dir_all(folder.join("src"))?;
    fs::write(
        folder.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
             [dependencies]\nprobe = {{ version = \"0.1.0\", registry = \"probe\" }}\n"
        ),
    )?;
    fs::write(
        folder.join("src/main.rs"),
        "fn main() {\n    println!(\"{}\", probe::CODE);\n}\n",
    )?;
    Ok(folder)
}

/// What a consumer prints when Cargo builds and runs it.
fn run_consumer(folder: &Path, cargo: &dyn Fn(&Path) -> Command) -> Result<String, Error> {
    let output = tools::output(cargo(folder).args(["run", "--quiet"]))?;
    Ok(String::from_utf8_lossy(&output).trim().to_owned())
}

/// The `checksum` line of a consumer's lockfile.
fn locked_checksum(folder: &Path) -> Result<String, Error> {
    let lock = fs::read_to_string(folder.join("Cargo.lock"))?;
    lock.lines()
        .find(|line| line.starts_with("checksum"))
        .map(str::to_owned)
        .ok_or_else(|| {
            Error(format!(
                "{}/Cargo.lock records no checksum",
                folder.display()
            ))
        })
}

/// Prints whether a consumer ran the republished code; true when it did.
fn runs_republished(number: u8, who: &str, output: &str) -> bool {
    if output == REPUBLISHED {
        println!("{number}. {who} runs the republished code");
        return true;
    }
    println!("{number}. FAILED: {who} runs \"{output}\"");
    false
}

/// What Cargo printed when it succeeded, or the first line of its errors that names an error
/// when it refused: a refusal is one of the outcomes this harness reports.
fn cargo_outcome(command: &mut Command) -> Result<Result<String, String>, Error> {
    let output = command.output()?;
    if output.status.success() {
        return Ok(Ok(String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_owned()));
    }
    let errors = String::from_utf8_lossy(&output.stderr);
    let line = errors
        .lines()
        .find(|line| line.contains("error"))
        .unwrap_or("no error line");
    Ok(Err(line.to_owned()))
}
