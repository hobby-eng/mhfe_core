//! AUD-006: the least thread stack, in steps of 4 KiB, on which each public call that clears the
//! stack runs without overflowing. A size is tried in a child process, whose thread of that size
//! makes the call; a stack overflow ends the child, so its exit status is the answer.
//!
//! Run: `cargo run --release` and `cargo run` in this folder. Prints one line per call with the
//! least size that worked, and exits 1 if a call needs more than the 144 KiB the crate documents.

use std::process::Command;

use mhfe_core::repair::{Card, Repaired};
use mhfe_core::{Password, Phrase};

/// The calls measured, by name.
const CALLS: [&str; 4] = ["phrase", "password", "card", "repair"];
/// What the crate's documents say a call needs.
const DOCUMENTED_KIB: usize = 144;

fn call(name: &str) {
    let container = Phrase::from_entropy(&[7; 32]).unwrap();
    match name {
        "phrase" => drop(Phrase::read(container.as_str()).unwrap()),
        "password" => drop(Password::new("correct horse battery staple").unwrap()),
        "card" => drop(Card::new(&container, 8).unwrap()),
        "repair" => {
            let card = Card::new(&container, 8).unwrap();
            let mut words: Vec<&str> = container.as_str().split(' ').collect();
            words[3] = "?";
            words[9] = "zoo";
            drop(Repaired::of(&words.join(" "), card.as_str()).unwrap());
        }
        _ => unreachable!(),
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if let [_, name, kib] = arguments.as_slice() {
        let bytes = kib.parse::<usize>().unwrap() * 1024;
        let name = name.clone();
        let worker = std::thread::Builder::new().stack_size(bytes);
        worker.spawn(move || call(&name)).unwrap().join().unwrap();
        return;
    }
    // Every Secret and the first isolation decision are made before the measured thread starts.
    call("card");
    let mut over = false;
    for name in CALLS {
        let least = (96..=512).step_by(4).find(|kib| {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([name, &kib.to_string()])
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            status.success()
        });
        println!("{name}: {least:?} KiB");
        over |= least.is_none_or(|kib| kib > DOCUMENTED_KIB);
    }
    std::process::exit(i32::from(over));
}
