//! AUD-002 skeptic check of the finding AUD-002-BLD001, "publishing different bytes as version
//! 0.1.0 makes Cargo build the withdrawn 0.1.0 from its cache", reviewed commit
//! dec9c8115ff9ddbd32bb5fdd457ae9904043c966.
//!
//! A crate `probe` 0.1.0 is published to a local sparse registry on 127.0.0.1, which this program
//! serves, and a consumer with a fresh CARGO_HOME under <work> builds it; then different bytes are
//! published as the same 0.1.0. The program isolates which cache keeps the old code:
//!
//! - a. with the old Cargo.lock, a plain `cargo update` (not only `-p`) is refused too;
//! - b. removing only the extracted source re-extracts the cached .crate: still the old code;
//! - c. removing the extracted source and the cached .crate downloads the new bytes, which Cargo
//!   checks against the index; the old target folder is still reused, and only removing it as
//!   well gives the new code.
//!
//! It reads no repository: the result is Cargo's behaviour, the same at every commit.
//!
//! Exits 1 when a consumer that cached the old 0.1.0 gets the new code only after Cargo's cache is
//! deleted by hand (the hazard holds), 0 when a renewed lockfile gives the new code, 2 when the
//! check could not run or a build gave neither code.
//!
//!   aud002-skeptic-bld-republish <work folder>

mod registry;

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use registry::{DOWNLOADS, Registry};
use sha2::{Digest, Sha256};

/// The toolchain of mhfe-core's rust-toolchain.toml; the probe crates lie outside the repository.
const TOOLCHAIN: &str = "+1.99.1";
/// What each package's `CODE` says, and so what the consumer prints.
const WITHDRAWN: &str = "withdrawn";
const REPUBLISHED: &str = "republished";
const CONSUMER: &str = "first";
/// What the program makes under <work>, removed at the start of a run. Only these are removed, so
/// that a wrong <work> loses nothing else.
const MADE: [&str; 5] = [
    "served",
    "cargo-home",
    "probe-withdrawn",
    "probe-republished",
    CONSUMER,
];
const PACKAGE: &str = "probe-0.1.0.crate";
/// The folder of the extracted source in Cargo's registry/src/<registry>/.
const SOURCE: &str = "probe-0.1.0";
/// Exit code when the check could not run, apart from 1, "the hazard holds".
const NOT_RUN: u8 = 2;

/// Why the check could not run.
#[derive(Debug)]
struct Failure(String);

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Failure {}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

fn remove(path: &Path) -> Result<(), Failure> {
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// The one `<folder>/<registry>/<leaf>` there is, in Cargo's registry/src or registry/cache.
fn in_registry(folder: &Path, leaf: &str) -> Result<PathBuf, Failure> {
    let mut found = Vec::new();
    for entry in fs::read_dir(folder)? {
        let path = entry?.path().join(leaf);
        if path.exists() {
            found.push(path);
        }
    }
    match found.as_slice() {
        [path] => Ok(path.clone()),
        _ => Err(Failure(format!(
            "{} copies of {leaf} in Cargo's registry, not one",
            found.len()
        ))),
    }
}

/// The work folder, its Cargo home and the registry that serves it.
struct Work {
    root: PathBuf,
    registry: Registry,
}

impl Work {
    fn start(root: &Path) -> Result<Self, Failure> {
        for name in MADE {
            remove(&root.join(name))?;
        }
        let served = root.join("served");
        fs::create_dir_all(served.join("index/pr/ob"))?;
        fs::create_dir_all(served.join("dl"))?;
        fs::create_dir_all(root.join("cargo-home"))?;
        let registry = Registry::start(served.clone())?;
        let base = registry.base();
        fs::write(
            served.join("index/config.json"),
            format!("{{\"dl\":\"{base}{DOWNLOADS}{{crate}}-{{version}}.crate\",\"api\":null}}\n"),
        )?;
        fs::write(
            root.join("cargo-home/config.toml"),
            format!("[registries.probe]\nindex = \"sparse+{base}/index/\"\n"),
        )?;
        Ok(Self {
            root: root.to_path_buf(),
            registry,
        })
    }

    fn cargo_home(&self) -> PathBuf {
        self.root.join("cargo-home")
    }

    /// Cargo with the work folder's home, run in `folder`.
    fn cargo(&self, folder: &Path) -> Command {
        let mut command = Command::new("cargo");
        command
            .arg(TOOLCHAIN)
            .current_dir(folder)
            .env("CARGO_HOME", self.cargo_home())
            // The steps delete the consumer's target folder, so none may come from outside.
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("CARGO_BUILD_TARGET_DIR");
        command
    }

    /// Packages a `probe` 0.1.0 whose `CODE` is `code` and serves it in place of the last one.
    fn publish(&self, code: &str) -> Result<(), Failure> {
        let folder = self.root.join(format!("probe-{code}"));
        fs::create_dir_all(folder.join("src"))?;
        fs::write(
            folder.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             license = \"MIT\"\ndescription = \"p\"\n",
        )?;
        fs::write(
            folder.join("src/lib.rs"),
            format!("pub const CODE: &str = \"{code}\";\n"),
        )?;
        let packaged = self
            .cargo(&folder)
            .args([
                "package",
                "--quiet",
                "--no-verify",
                "--allow-dirty",
                "--target-dir",
            ])
            .arg(folder.join("target"))
            .status()?;
        if !packaged.success() {
            return Err(Failure(format!("cargo package of \"{code}\" failed")));
        }
        let package = fs::read(folder.join("target/package").join(PACKAGE))?;
        let served = self.root.join("served");
        fs::write(served.join("dl").join(PACKAGE), &package)?;
        let checksum: String = Sha256::digest(&package)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        fs::write(
            served.join("index/pr/ob/probe"),
            format!(
                "{{\"name\":\"probe\",\"vers\":\"0.1.0\",\"deps\":[],\"cksum\":\"{checksum}\",\
                 \"features\":{{}},\"yanked\":false}}\n"
            ),
        )?;
        println!("served \"{code}\" {checksum}");
        Ok(())
    }

    /// Writes the consumer, a program that prints the `CODE` of the `probe` it was built with.
    fn consumer(&self) -> Result<(), Failure> {
        let folder = self.root.join(CONSUMER);
        fs::create_dir_all(folder.join("src"))?;
        fs::write(
            folder.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{CONSUMER}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
                 [dependencies]\nprobe = {{ version = \"0.1.0\", registry = \"probe\" }}\n"
            ),
        )?;
        fs::write(
            folder.join("src/main.rs"),
            "fn main() { println!(\"{}\", probe::CODE); }\n",
        )?;
        Ok(())
    }

    /// Builds and runs the consumer, and returns the code it prints.
    fn run_consumer(&self) -> Result<String, Failure> {
        let output = self
            .cargo(&self.root.join(CONSUMER))
            .args(["run", "--quiet"])
            .output()?;
        let error = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            return Err(Failure(format!("cargo run failed: {}", error.trim())));
        }
        let code = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if code != WITHDRAWN && code != REPUBLISHED {
            return Err(Failure(format!("the consumer printed {code:?}")));
        }
        Ok(code)
    }

    /// Step a: a plain `cargo update` with the old lockfile.
    fn update(&self) -> Result<(), Failure> {
        let output = self
            .cargo(&self.root.join(CONSUMER))
            .args(["update", "--quiet"])
            .output()?;
        if output.status.success() {
            println!("a. plain cargo update succeeds");
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            let line = error.lines().find(|line| line.contains("error"));
            println!(
                "a. plain cargo update is refused: {}",
                line.unwrap_or("(no error line)")
            );
        }
        Ok(())
    }
}

fn run(arguments: &[String]) -> Result<bool, Failure> {
    let [work] = arguments else {
        return Err(Failure(
            "usage: aud002-skeptic-bld-republish <work folder>".to_owned(),
        ));
    };
    let work = Work::start(Path::new(work))?;
    let target = work.root.join(CONSUMER).join("target");
    let registry = work.cargo_home().join("registry");
    work.publish(WITHDRAWN)?;
    work.consumer()?;
    println!("first build: {}", work.run_consumer()?);
    work.publish(REPUBLISHED)?;
    work.update()?;

    remove(&work.root.join(CONSUMER).join("Cargo.lock"))?;
    let after_lock = work.run_consumer()?;
    println!("   lockfile removed; first consumer runs: {after_lock}");

    let source = in_registry(&registry.join("src"), SOURCE)?;
    remove(&source)?;
    remove(&target)?;
    let only_source = work.run_consumer()?;
    println!(
        "b. extracted source removed: runs \"{only_source}\"; downloads so far: {}",
        work.registry.downloads()
    );

    remove(&source)?;
    remove(&in_registry(&registry.join("cache"), PACKAGE)?)?;
    let kept_target = work.run_consumer()?;
    println!(
        "c. source and cached .crate removed, target kept: runs \"{kept_target}\"; \
         downloads so far: {}",
        work.registry.downloads()
    );

    remove(&target)?;
    let fresh = work.run_consumer()?;
    println!("   and target removed: runs \"{fresh}\"");
    if fresh != REPUBLISHED {
        return Err(Failure(
            "even a fresh download is not the new code".to_owned(),
        ));
    }
    let lockfile = fs::read_to_string(work.root.join(CONSUMER).join("Cargo.lock"))?;
    for line in lockfile.lines().filter(|line| line.starts_with("checksum")) {
        println!("lockfile records: {line}");
    }
    // The hazard holds when a renewed lockfile and a re-extraction still give the old code.
    if after_lock == WITHDRAWN && only_source == WITHDRAWN {
        println!("FAIL: only deleting the cached .crate by hand gives the new 0.1.0");
        return Ok(false);
    }
    println!("PASS: a renewed lockfile gives the new code");
    Ok(true)
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(failure) => {
            eprintln!("error: {failure}");
            ExitCode::from(NOT_RUN)
        }
    }
}
