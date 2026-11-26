# mhfe-core

[![CI](https://github.com/hobby-eng/mhfe_core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/mhfe_core/actions/workflows/ci.yml)
[![Release](https://github.com/hobby-eng/mhfe_core/actions/workflows/release.yml/badge.svg)](https://github.com/hobby-eng/mhfe_core/actions/workflows/release.yml)
[![RustSec audit](https://github.com/hobby-eng/mhfe_core/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/mhfe_core/actions/workflows/audit.yml)
[![Build provenance: GitHub attestations](https://img.shields.io/badge/build%20provenance-GitHub%20attestations-2ea44f)](https://github.com/hobby-eng/mhfe_core/attestations)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#licence)

<p align="center">
  <img
    src="https://raw.githubusercontent.com/hobby-eng/mhfe_core/main/assets/mhfe-mascot.png"
    alt="MHFE penguin mascot carrying a cold-storage metal backup"
    width="240"
  >
</p>

<p align="center">
  <sub>The penguin lives in the cold, like the backups MHFE is made for. It holds a
    steel backup with 24 words and waddles from side to side, much as a Feistel network swaps its
    two halves in every round.</sub>
</p>

A seed phrase is the whole wallet: anyone who reads it can take the funds. So it has to be hidden,
or learned by heart word by word, for as long as the wallet lives. MHFE, Memory-Hard Feistel
Encryption for BIP39 mnemonics, changes what you have to protect. You remember a password, and you
keep a container on the usual paper or metal backup. The container is itself a valid BIP39 phrase,
so it fits the same backup, and reading or photographing it does not reveal your phrase.

It still has to stay private: whoever has it can try passwords. That is why every guess is made
expensive: twelve rounds of Argon2id, 2 GiB of memory and a minute or two each by default. You pay
that once to recover your phrase; someone guessing pays nearly all of it for every password they
try.

mhfe-core is the Rust library that does this work, and the `mhfe` tool is built on it. It implements
the published [MHFE specification](https://github.com/hobby-eng/mhfe-spec) 0.7.0, so a recovery does
not depend on this code: any program that follows the specification opens the same containers.

> **Experimental.** The construction has not been reviewed by independent cryptographers.

The [documentation index](https://github.com/hobby-eng/mhfe_core/blob/main/docs/README.md) lists
the documents of the repository; the [API documentation](https://docs.rs/mhfe-core) is the guide
most readers need first.

## Contents

| Section                       | What it covers                                                      |
| ----------------------------- | ------------------------------------------------------------------- |
| [What it does](#what-it-does) | The two kinds of container and the three optional extras            |
| [Using it](#using-it)         | The dependency, an example, the Rust version and the systems tested |
| [Security](#security)         | What the crate protects, and where the details are                  |
| [Testing](#testing)           | The tests, the gates, the full-cost vectors and the coverage        |
| [Audits](#audits)             | The audit records                                                   |
| [Licence](#licence)           | The crate's licences and those of what it uses                      |

## What it does

You give it a seed phrase and a password, and it gives you a container. With the same password and
settings, it gives you the phrase back.

There are two kinds of container. The usual one always has 24 words, whatever the length of your
phrase, and for a phrase of 12 to 21 words it tells a wrong password almost always: a wrong one
passes its check only by chance, about once in 2^32 at worst. A 24-word phrase has no such check.
The other kind keeps the length of your phrase, so it fits a backup made for that length, but a
wrong password then gives another valid phrase with no warning.

Three optional extras from the specification are here too: a check that lets a recovery recognise a
24-word phrase, a 16-bit test that a wrong phrase still passes about once in 65,536; repair words
that restore a damaged container; and a check word that catches a mistyped password before the long
computation starts.

## Using it

```toml
[dependencies]
mhfe-core = "0.2"
```

The line above names the latest release; the changelog lists what the repository has added since.

A container of a phrase, and the phrase back, in short (the API documentation's example adds the
duties a program has, such as isolating itself and asking for the password twice):

```rust
use std::ops::ControlFlow;
use mhfe_core::{Mhfe, Password, Phrase, Suite, WorkFactor};

/// Whether `phrase` comes back from its container; `None` if a callback stopped.
fn round_trip(phrase: &Phrase, password: &Password) -> Result<Option<bool>, mhfe_core::Error> {
    let mut cipher = Mhfe::new(WorkFactor::default())?; // 2 GiB, a minute or two a call
    let go = &mut |_, _| ControlFlow::Continue(());
    let checked = &mut |_: &Phrase| ControlFlow::Continue(());
    let ControlFlow::Continue(container) =
        cipher.encrypt(phrase, password, Suite::TwentyFourWords, go, checked)?
    else {
        return Ok(None);
    };
    let ControlFlow::Continue(recovery) = cipher.decrypt(&container, password, None, None, go)?
    else {
        return Ok(None);
    };
    // The reading of the phrase's own length, compared without showing either phrase: with 24
    // words stated, a shorter reading that matches comes first.
    let readings = recovery.readings(Some(phrase.words()))?;
    let own = readings.iter().find(|reading| reading.phrase().words() == phrase.words());
    Ok(Some(own.is_some_and(|reading| reading.phrase().as_str() == phrase.as_str())))
}
```

A program that shows a 24-word reading to a person also runs the wallet check on it,
`wallet_check::Seed::derive` with the passphrase they type or the empty one, and reports its result
(REC-3 of the specification), as the container does not say whether the phrase was made with it.

You need Rust 1.99 or later. A native build needs a 64-bit target; in WebAssembly, which is 32-bit,
your program supplies Argon2id itself. No C compiler is needed. The tests run on Linux (x86-64 and
ARM64), macOS (Apple silicon and Intel), Windows (MSVC and GNU) and WebAssembly (WASI in Wasmtime);
Android and iOS builds are compiled and linted, but no runner tests them yet.

The crate is a library: your program asks for the phrase and the password, shows the result and
warns the person where the specification asks for it. The example in the
[documentation](https://docs.rs/mhfe-core) shows all of that.

In a debug build Argon2id takes about 16 times as long. Setting `opt-level = 3` for `argon2` in
`[profile.dev.package]` brings that down to about 4 times.

## Security

Secrets are wiped after use, and in a native build they stay on memory pages of their own. A
program can close itself off from the network and from other programs before it reads one. On
Windows the network stays open, and none of this makes an everyday or compromised computer
trustworthy. What this covers on each system, and what it does not, is in
[SECURITY.md](https://github.com/hobby-eng/mhfe_core/blob/main/SECURITY.md).

## Testing

Clone with `git clone --recurse-submodules`: the test vectors come from the specification's
repository. `cargo test --locked` runs the fast tests, and `cargo xtask check` runs the gates, the
lints and the fast tests of the CI's main job on one computer; the other targets, the minimum Rust
and the package check run in CI. The full-cost vectors take hours:
`cargo test --locked --release --test full_cost -- --ignored --nocapture`.

The last coverage measurement, of commit `32651c2` on 2026-11-26, ran 104 checks on Linux x86-64
and covered **97.02%** of the measured source lines (2,279 of 2,349).
[Coverage report](https://github.com/hobby-eng/mhfe_core/blob/main/docs/COVERAGE.md)

## Audits

Every audit of the crate is in the
[audit records](https://github.com/hobby-eng/mhfe_core/blob/main/docs/audits/README.md), with its
findings and their fixes. They are reviews of the code made with AI models; no independent
person has reviewed the code or the construction yet.

## Licence

MIT OR Apache-2.0, at your option: see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). Unless you say otherwise, a contribution you submit for inclusion
in this crate, as the Apache-2.0 licence defines it, is offered under both licences, without other
terms. The EFF word list and the crates this one depends on keep their own licences: see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
