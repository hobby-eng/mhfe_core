//! MHFE: Memory-Hard Feistel Encryption for BIP39 mnemonics, suites
//! `MHFE-BIP39-256-EXPERIMENTAL-3` and `MHFE-BIP39-LP-EXPERIMENTAL-4` of the MHFE specification
//! 0.7.0, with Unicode 18.0.0 for passwords.
//!
//! A container is itself a valid BIP39 phrase: suite 3 turns an English phrase of 12 to 24 words
//! into a 24-word container, suite 4 a 12- to 21-word phrase into one of its own length. Each of
//! the twelve Feistel rounds runs Argon2id, with 2 GiB of memory by default. [`Mhfe::encrypt`]
//! creates a container and checks it; [`Mhfe::decrypt`] recovers its state, which
//! [`Recovery::readings`] reads under the specification's length rules.
//!
//! Three optional profiles of the specification have modules of their own: [`wallet_check`], a
//! new 24-word phrase drawn to pass a check of its BIP39 seed; [`repair`], repair words for a
//! container; and [`password_check`], a password of EFF words with a check word.
//!
//! Native builds compute Argon2id with the vendored reference C code, [`NativeArgon2`], at every
//! memory level from 0 to 21, and only on 64-bit targets. A WebAssembly build has no engine of its
//! own: the host implements [`Argon2Engine`] and refuses the levels it cannot reach when it is
//! made, as a 32-bit WebAssembly host does above level 0.
//!
//! The crate reads no input. Every secret it holds lives in a [`protect::Secret`]: memory pages of
//! its own, locked and kept out of core dumps where the system allows it, and wiped when dropped.
//! [`protect::Isolation::enter`] applies what the system offers against a secret leaving the
//! process and reports what holds, and [`protect::write_secret`] shows a secret past the standard
//! library's output buffer. After each call that computes with a secret, but
//! [`repair::Repaired::changes`] and those of [`protect`] and the engine, the crate overwrites
//! 128 KiB of the stack below the caller's frame, so such a call needs about 140 KiB of free stack:
//! on a smaller thread stack, such as musl's default of 128 KiB, it ends the process.
//!
//! The construction is experimental and has not been independently reviewed. Do not use it to
//! protect real funds.
//!
//! A host isolates itself before it reads a secret, and does the creation duties the crate leaves
//! to it: it reads the password twice, warns about other lengths, checks free memory where the
//! example marks it, and shows the suite:
//!
//! ```no_run
//! use std::ops::ControlFlow;
//! use mhfe_core::{protect, Mhfe, Password, Phrase, Suite, WorkFactor};
//! # fn read_hidden(_prompt: &str) -> protect::Secret { unimplemented!() }
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let isolation = protect::Isolation::enter(); // before any secret is read
//!     eprintln!("{isolation:?}");
//!     let typed = read_hidden("Phrase: ");
//!     let phrase = Phrase::read(typed.as_str().ok_or("not UTF-8")?)?;
//!     let first = read_hidden("Password: ");
//!     let second = read_hidden("Password again: ");
//!     if first.as_bytes() != second.as_bytes() {
//!         return Err("the two entries differ".into()); // creation step 1
//!     }
//!     let password = Password::new(first.as_str().ok_or("not UTF-8")?)?;
//!     let others = phrase.other_detected_lengths(); // creation step 2
//!     if !others.is_empty() {
//!         eprintln!("Recovery will also match {others:?} words: note that the phrase has {} \
//!                    words and keep the note apart from the container.", phrase.words());
//!     }
//!     let suite = Suite::TwentyFourWords;
//!     // The host checks free memory before this ("Resources"): the core only reserves.
//!     let mut cipher = Mhfe::new(WorkFactor::default())?;
//!     let container = cipher.encrypt(&phrase, &password, suite,
//!         &mut |_, _| ControlFlow::Continue(()), &mut |_| ControlFlow::Continue(()))?;
//!     println!("Suite: {}", suite.id()); // shown at creation
//!     protect::write_secret(container.as_str())?;
//!     protect::write_secret("\n")?;
//!     Ok(())
//! }
//! ```

// Unsafe code is allowed in the operating-system modules, `os.rs` and `os/*.rs`, and in the
// binding of the C code, `engine/ffi.rs`, only.
#![deny(unsafe_code)]

mod cipher;
mod engine;
mod error;
mod feistel;
mod nfkd;
mod os;
mod packing;
mod password;
pub mod password_check;
mod phrase;
pub mod protect;
mod recovery;
pub mod repair;
mod stack;
mod suite;
// The unit tests include the integration tests' corpus helpers, which name the crate so.
#[cfg(test)]
extern crate self as mhfe_core;
#[cfg(test)]
mod test_support;
pub mod wallet_check;

pub use cipher::Mhfe;
pub use engine::Argon2Engine;
#[cfg(not(target_arch = "wasm32"))]
pub use engine::NativeArgon2;
pub use error::Error;
pub use password::Password;
pub use phrase::Phrase;
pub use recovery::{Reading, Recovery};
pub use suite::{Suite, WorkFactor};
