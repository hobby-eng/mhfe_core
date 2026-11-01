//! Gives every build the words of the vendored EFF list as `password_check::EFF_WORDS`.

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// The EFF large wordlist, unchanged: lines of five dice digits, a tab and a word.
const EFF_LIST: &str = "vendor/eff-large-wordlist/eff_large_wordlist.txt";

fn main() -> Result<(), Box<dyn Error>> {
    for path in ["build.rs", EFF_LIST] {
        println!("cargo:rerun-if-changed={path}");
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo sets no OUT_DIR")?);
    write_eff_words(&out_dir)?;
    Ok(())
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
