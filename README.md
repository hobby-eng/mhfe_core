# mhfe-core

[![CI](https://github.com/hobby-eng/mhfe_core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/mhfe_core/actions/workflows/ci.yml)
[![Release](https://github.com/hobby-eng/mhfe_core/actions/workflows/release.yml/badge.svg)](https://github.com/hobby-eng/mhfe_core/actions/workflows/release.yml)
[![RustSec audit](https://github.com/hobby-eng/mhfe_core/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/mhfe_core/actions/workflows/audit.yml)
[![Build provenance: GitHub attestations](https://img.shields.io/badge/build%20provenance-GitHub%20attestations-2ea44f)](https://github.com/hobby-eng/mhfe_core/attestations)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#licence)

<p align="center">
  <img
    src="assets/mhfe-mascot.png"
    alt="MHFE penguin mascot carrying a cold-storage metal backup"
    width="240"
  >
</p>

<p align="center">
  <sub>The penguin lives in the cold, like the backups MHFE is made for. It holds a
    steel backup with 24 words and waddles from side to side, much as a Feistel network swaps its two
    halves in every round.</sub>
</p>

mhfe-core is the Rust library of MHFE, Memory-Hard Feistel Encryption for BIP39 mnemonics. It
implements the [MHFE specification](https://github.com/hobby-eng/mhfe-spec) 0.7.0, with Unicode
18.0.0 for passwords. It turns an English BIP39 seed phrase into a password-protected container
phrase and back; the container phrase is itself a valid BIP39 phrase. Each of the twelve Feistel
rounds runs Argon2id, with 12 passes over 2 GiB of memory by default, so that a guess of the
password costs about as much work as a recovery.

The crate reads no input and shows nothing by itself: a program built on it asks for the phrase
and the password, calls the crate and shows the result.

> **Experimental.** The construction has not been reviewed by independent cryptographers. Do not
> use it to protect real funds.

## What it does

- Suite `MHFE-BIP39-256-EXPERIMENTAL-3`, the default (`Suite::TwentyFourWords`), turns a phrase of
  12 to 24 words into a container of 24 words. For a phrase of 12 to 21 words, the container also
  holds a check that tells a wrong password with high confidence.
- Suite `MHFE-BIP39-LP-EXPERIMENTAL-4` (`Suite::SameLength`) turns a phrase of 12 to 21 words into
  a container of the same length, which has no such check.
- `Mhfe::encrypt` creates a container and, before returning it, recovers it once as a check.
  `Mhfe::decrypt` recovers the state of a container, and `Recovery::readings` gives the phrases the
  specification's length rules allow, each marked verified or not.
- The crate also implements the specification's three optional profiles. `wallet_check`
  (MHFE-WALLET-CHECK-SEED-1) draws a new 24-word phrase whose BIP39 seed passes a 16-bit check, and
  evaluates that check for a 24-word recovery. `repair` (MHFE-REPAIR-1) makes repair words for a
  container and repairs a damaged copy with them. `password_check` (MHFE-PASSWORD-CHECK-1) gives a
  password of five EFF words a check word, which finds a typing error before any Argon2id work.

The specification leaves some duties to the program, and the crate does not take them over: asking
for the password twice, warning when a recovery would also match a phrase of another length,
showing the suite's identifier at creation, checking free memory before the Argon2id memory is
reserved, and every prompt, label and message. The example in the crate's documentation reads the
password twice, warns about other lengths and shows the suite, and marks where the program checks
free memory.

## Secrets in memory and in the process

Every secret the crate holds lies in a `protect::Secret`, on memory pages of its own, and is wiped
when it is dropped. `protect::write_secret` writes one to standard output without a copy in a buffer.
`protect::Isolation::enter()`, called before a secret is read, applies what the operating system
offers against a secret leaving the process and reports what holds. A call that computes with a
secret needs about 140 KiB of free stack. [SECURITY.md](SECURITY.md) says what holds on each system.

## The API at a glance

- `Phrase` reads a phrase as a person types it, or makes one from entropy; `Password` encodes a
  password; `WorkFactor` holds the PIM and the memory level; `Suite` names a suite.
- `Mhfe` creates and recovers containers with an `Argon2Engine`: `NativeArgon2` (RustCrypto's
  `argon2` on four threads of its own) on native targets, or the host's own engine in WebAssembly.
  A recovery is a `Recovery`, whose readings are `Reading`s. `Error` lists the refusals, and
  `Error::Cancelled` reports that a callback returned `ControlFlow::Break`.
- `protect`: `Secret`, `Isolation` and, on native targets, `write_secret`.
- `wallet_check`: `Seed` and `draw`. `repair`: `Card`, `Repaired`, `Change` and their `Error`.
  `password_check`: `EFF_WORDS`, `check_word` and `Check`.

The crate's documentation (`cargo doc --open`) describes every item, its errors and the order of
its calls.

## Building

The crate needs Rust 1.99 or later and has no Cargo features. A native build needs a 64-bit target
and no C compiler. On `wasm32-unknown-unknown` the host implements `Argon2Engine`.

Cargo compiles Argon2id without optimization in a debug build, where an operation takes about 16
times as long as in a release build. A program can ask for `opt-level = 3` in
`[profile.dev.package.argon2]`, which brings that down to about 4 times.

## Testing

The tests read the specification's test vectors from its repository, which this one holds as the
submodule `tests/spec`. Clone with `git clone --recurse-submodules`, or run
`git submodule update --init` in an existing clone.

- `cargo test --locked` runs the fast tests. They replay the specification's test vectors of both
  suites and of the profiles with the Argon2id keys the vectors record, so that no test needs
  gigabytes of memory. They also test the native engine against tags from OpenSSL at small costs,
  and check the secret pages and the isolation as the system reports them.
- `cargo xtask check` runs the checks of CI's `checks` job: the tests, Clippy, rustfmt, dprint,
  the documentation, and the code rules, the copy, public API and vendored-file checks. The tools
  are in the repository's `xtask` crate, which is not part of the package; dprint 0.63.0 formats
  the Markdown, JSON, TOML and YAML. CI's other jobs build and test the crate on other systems and
  on Rust 1.99, and check the package.
- `cargo test --locked --release --test full_cost -- --ignored --nocapture` replays both suites'
  vectors at full cost, which takes hours, with 2 or 3 GiB of memory per call.
  `MHFE_VECTOR_SHARE=k/n` splits the work among n processes.

## Licence

MIT OR Apache-2.0, at your option: see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). Unless you say otherwise, a contribution you submit for inclusion
in this crate, as the Apache-2.0 licence defines it, is offered under both licences, without other
terms. The EFF word list and the crates this one depends on keep their own licences: see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
