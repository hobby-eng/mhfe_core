//! The stack check of the Argon2 engine's C code, on Linux, run as `cargo xtask argon2-stack`:
//! tests/argon2_stack.c, linked against the library that build.rs compiles, as shipped and with the
//! wrapper's clears left out (MHFE_STACK_MEASURE). The first must leave every byte it wrote on a
//! stack zero; the second prints how deep the vendored code writes, which must stay below
//! MHFE_STACK_CLEAR_BYTES. The C compiler is `$CC`, or `cc`.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::Failure;
use crate::check::{cargo, run_tool};

/// The library that build.rs compiles from the vendored code and the wrapper.
const LIBRARY: &str = "libmhfe_argon2.a";

/// How Cargo's JSON message for a build script that ran begins, and the key of the script's
/// output folder in it.
const BUILD_SCRIPT_EXECUTED: &str = r#"{"reason":"build-script-executed""#;
const OUT_DIR_KEY: &str = r#""out_dir":""#;

/// The two programs, each with the define it is compiled with: as shipped, and without the clears.
const MODES: [(&str, Option<&str>); 2] =
    [("check", None), ("measure", Some("-DMHFE_STACK_MEASURE"))];

/// The compiler's flags before the source, with the folders of the headers the test includes.
const COMPILE_FLAGS: [&str; 11] = [
    "-std=c11",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-I",
    "vendor/phc-winner-argon2/include",
    "-I",
    "vendor/phc-winner-argon2/src",
    "-I",
    "src/engine",
];
const SOURCE: &str = "tests/argon2_stack.c";

/// The linker's flags after the library. -z now binds every symbol at start, as Rust programs do on
/// Linux, so that no lazy binding writes the stack during the call.
const LINK_FLAGS: [&str; 3] = ["-pthread", "-ldl", "-Wl,-z,now"];

pub(crate) fn run(root: &Path) -> Result<(), Failure> {
    // The test is written for Linux: it takes the C library's thread functions over through
    // dlsym(RTLD_NEXT) and links with -z now.
    if !cfg!(target_os = "linux") {
        return Err(Failure(
            "the Argon2 stack check runs on Linux only".to_owned(),
        ));
    }
    let messages = run_tool(
        cargo(root)
            .args(["build", "--locked", "--message-format=json"])
            .stdout(Stdio::piped()),
    )?;
    let library = library(&String::from_utf8_lossy(&messages))?;
    let compiler = env::var_os("CC")
        .filter(|compiler| !compiler.is_empty())
        .unwrap_or_else(|| OsString::from("cc"));
    // The programs go beside this tool, in Cargo's target folder, where `cargo clean` removes them.
    let tool = env::current_exe()?;
    for (mode, define) in MODES {
        let program = tool.with_file_name(format!("argon2-stack-{mode}"));
        run_tool(
            Command::new(&compiler)
                .current_dir(root)
                .args(COMPILE_FLAGS)
                .args(define)
                .arg(SOURCE)
                .arg(&library)
                .args(LINK_FLAGS)
                .arg("-o")
                .arg(&program),
        )?;
        run_tool(&mut Command::new(&program))?;
    }
    Ok(())
}

/// The library in the output folder of a build script that `messages`, Cargo's JSON lines, report;
/// the last one when several do.
fn library(messages: &str) -> Result<PathBuf, Failure> {
    messages
        .lines()
        .filter_map(out_dir)
        .map(|out_dir| Path::new(out_dir).join(LIBRARY))
        .rfind(|library| library.is_file())
        .ok_or_else(|| Failure(format!("cargo build reported no {LIBRARY}")))
}

/// The output folder that `line` reports, when it is the message of a build script that ran.
fn out_dir(line: &str) -> Option<&str> {
    let (_, value) = line
        .strip_prefix(BUILD_SCRIPT_EXECUTED)?
        .rsplit_once(OUT_DIR_KEY)?;
    value.split_once('"').map(|(out_dir, _)| out_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The message of mhfe-core's build script, as Cargo 1.99 writes it, with shorter paths.
    const MESSAGE: &str = concat!(
        r#"{"reason":"build-script-executed","package_id":"path+file:///work/mhfe_core#mhfe-core@0.1.0","#,
        r#""linked_libs":["static=mhfe_argon2"],"linked_paths":["native=/work/target/debug/build/"#,
        r#"mhfe-core-351442688d6db6e9/out"],"cfgs":[],"env":[],"#,
        r#""out_dir":"/work/target/debug/build/mhfe-core-351442688d6db6e9/out"}"#,
    );

    #[test]
    fn the_output_folder_is_read_from_a_build_scripts_message() {
        assert_eq!(
            out_dir(MESSAGE),
            Some("/work/target/debug/build/mhfe-core-351442688d6db6e9/out")
        );
    }

    #[test]
    fn other_messages_report_no_output_folder() {
        let artifact = MESSAGE.replace("build-script-executed", "compiler-artifact");
        assert_eq!(out_dir(&artifact), None);
        assert_eq!(
            out_dir(r#"{"reason":"build-script-executed","env":[]}"#),
            None
        );
        assert_eq!(out_dir("   Compiling mhfe-core v0.1.0"), None);
    }

    #[test]
    fn a_build_whose_output_folders_hold_no_library_is_refused() {
        let messages = format!(
            "{MESSAGE}\n{BUILD_SCRIPT_EXECUTED},{OUT_DIR_KEY}{}\"}}",
            env!("CARGO_MANIFEST_DIR")
        );
        let failure = library(&messages).err().map(|failure| failure.0);
        assert_eq!(
            failure.as_deref(),
            Some("cargo build reported no libmhfe_argon2.a")
        );
    }
}
