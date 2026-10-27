//! Compiles the vendored reference Argon2 code, unchanged, and MHFE's wrapper around it for native
//! builds. A WebAssembly build compiles no C: its host supplies Argon2id, and a host's Emscripten
//! build takes the same files from the one list, [`SOURCES`]. Every build gets the words of the
//! vendored EFF list as `password_check::EFF_WORDS`.

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const ARGON2_DIR: &str = "vendor/phc-winner-argon2";
/// The C files of every build by part, and the renaming rule of the Argon2 core.
const SOURCES: &str = "src/engine/argon2-sources.txt";
/// The parts of [`SOURCES`].
const PARTS: [&str; 3] = ["common", "portable", "wrap"];
/// The EFF large wordlist, unchanged: lines of five dice digits, a tab and a word.
const EFF_LIST: &str = "vendor/eff-large-wordlist/eff_large_wordlist.txt";

fn main() -> Result<(), Box<dyn Error>> {
    for path in [
        "build.rs",
        SOURCES,
        ARGON2_DIR,
        "src/engine/argon2_wrap.c",
        "src/engine/argon2_wrap.h",
        EFF_LIST,
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .map_err(|error| format!("Cargo sets no target architecture: {error}"))?;
    let target_family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo sets no OUT_DIR")?);
    write_eff_words(&out_dir)?;
    if target_arch == "wasm32" {
        return Ok(());
    }

    let list = fs::read_to_string(SOURCES).map_err(|error| format!("{SOURCES}: {error}"))?;
    let mut build = c_build();
    build.files(files_of(&list, "common")?);
    // The wrapper is MHFE's own code, so its compiler warnings are shown.
    build.objects(
        c_build()
            .files(files_of(&list, "wrap")?)
            .warnings(true)
            .out_dir(out_dir.join("argon2-wrap"))
            .compile_intermediates(),
    );

    if target_arch == "x86_64" {
        // One program for every 64-bit x86 processor: opt.c is compiled twice, with SSE2, part of
        // the x86-64 baseline, and with SSSE3, 7 to 10% faster, and argon2_wrap.c picks one for
        // every call from the processor's features. SSSE3 is never assumed: a program that used
        // it unconditionally would stop with "Illegal instruction" on common virtual CPUs
        // (upstream issue #308) and on AMD processors made before 2011. AVX2 is never used.
        //
        // Microsoft's cl takes no -m options (warning D9002) and needs none: it compiles SSE2 and
        // SSSE3 intrinsics as they are. It never defines __SSSE3__, though, which is what selects
        // the SSSE3 code in opt.c, so cl gets that macro directly. clang-cl takes -m options.
        let compiler = build.get_compiler();
        let microsoft_cl = compiler.is_like_msvc() && !compiler.is_like_clang_cl();
        for (copy, flag, cl_macro) in [
            ("sse2", "-msse2", None),
            ("ssse3", "-mssse3", Some("__SSSE3__")),
        ] {
            let mut core = core_copy(copy, &out_dir);
            core.file(Path::new(ARGON2_DIR).join("src/opt.c"));
            if !microsoft_cl {
                core.flag(flag);
            } else if let Some(name) = cl_macro {
                core.define(name, None);
            }
            build.objects(core.compile_intermediates());
        }
    } else {
        // ARM64, including Apple M-series, and every other architecture use the portable core.
        let mut core = core_copy("ref", &out_dir);
        core.files(files_of(&list, "portable")?);
        build.objects(core.compile_intermediates());
    }

    if target_family == "unix" {
        // The four Argon2 lanes run on POSIX threads (Win32 threads on Windows).
        build.flag("-pthread");
    }

    build.compile("mhfe_argon2");
    Ok(())
}

/// A build of C files beside the vendored headers, always optimized, also in debug and test
/// builds, where an unoptimized Argon2 would make even small test runs slow. The vendored code is
/// kept unchanged, so its compiler warnings are not ours to fix.
fn c_build() -> cc::Build {
    let argon2 = Path::new(ARGON2_DIR);
    let mut build = cc::Build::new();
    build
        .include(argon2.join("include"))
        .include(argon2.join("src"))
        .opt_level(3)
        .warnings(false);
    build
}

/// A copy of the Argon2 core whose `fill_segment` is renamed to `mhfe_fill_segment_<copy>`, the
/// rule of [`SOURCES`], in a folder of its own: the two copies of opt.c would otherwise both be
/// opt.o.
fn core_copy(copy: &str, out_dir: &Path) -> cc::Build {
    let mut build = c_build();
    build
        .define("fill_segment", format!("mhfe_fill_segment_{copy}").as_str())
        .out_dir(out_dir.join(format!("argon2-{copy}")));
    build
}

/// The files that `list`, the text of [`SOURCES`], gives for `part`, in the order listed. Every
/// line other than a blank line or a `#` comment must be `<part> <path>` with one of [`PARTS`].
fn files_of<'a>(list: &'a str, part: &str) -> Result<Vec<&'a str>, String> {
    let mut files = Vec::new();
    for line in list
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
    {
        match line.split_whitespace().collect::<Vec<&str>>()[..] {
            [line_part, path] if PARTS.contains(&line_part) => {
                if line_part == part {
                    files.push(path);
                }
            }
            _ => {
                return Err(format!(
                    "{SOURCES}: not \"<part> <path>\" with a part of {PARTS:?}: {line}"
                ));
            }
        }
    }
    Ok(files)
}

/// Writes `eff_words.rs` into `out_dir`: the words of [`EFF_LIST`] in the order of its lines, as
/// the array that `src/password_check.rs` includes.
fn write_eff_words(out_dir: &Path) -> Result<(), String> {
    let list = fs::read_to_string(EFF_LIST).map_err(|error| format!("{EFF_LIST}: {error}"))?;
    let mut words = String::from("[");
    for line in list.lines() {
        let (_, word) = line
            .split_once('\t')
            .ok_or_else(|| format!("{EFF_LIST}: not \"<dice><TAB><word>\": {line}"))?;
        words.push_str(&format!("{word:?},"));
    }
    words.push(']');
    let path = out_dir.join("eff_words.rs");
    fs::write(&path, words).map_err(|error| format!("{}: {error}", path.display()))
}
