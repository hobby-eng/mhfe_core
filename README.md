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

A seed phrase is the whole wallet: anyone who reads it can take the funds. So it has to be hidden, or
learned by heart word by word, for as long as the wallet lives. MHFE, Memory-Hard Feistel Encryption
for BIP39 mnemonics, changes what you have to protect. You remember a password, and you keep a
container on the usual paper or metal backup. The container is itself a valid BIP39 phrase, so it
fits the same backup, and reading or photographing it does not reveal your phrase.

It still has to stay private: whoever has it can try passwords. That is why every guess is made
expensive: twelve rounds of Argon2id, 2 GiB of memory and a minute or two each by default. You pay
that once to recover your phrase; someone guessing pays nearly all of it for every password they
try.

mhfe-core is the Rust library that does this work, and the `mhfe` tool is built on it. It implements
the published [MHFE specification](https://github.com/hobby-eng/mhfe-spec) 0.7.0, so a recovery does
not depend on this code: any program that follows the specification opens the same containers.

> **Experimental.** The construction has not been reviewed by independent cryptographers. Do not
> use it to protect real funds.

## What it does

You give it a seed phrase and a password, and it gives you a container. With the same password and
settings, it gives you the phrase back.

There are two kinds of container. The usual one always has 24 words, whatever the length of your
phrase, and for a phrase of 12 to 21 words it can tell when the password is wrong. The other keeps
the length of your phrase, so it fits a backup made for that length, but a wrong password then gives
another valid phrase with no warning.

Three optional extras from the specification are here too: a check that lets a recovery recognise a
24-word phrase, repair words that restore a damaged container, and a check word that catches a
mistyped password before the long computation starts.

## Using it

```toml
[dependencies]
mhfe-core = "0.2"
```

You need Rust 1.99 or later and a 64-bit target. No C compiler is needed. In a browser, your program
supplies Argon2id itself.

The crate is a library: your program asks for the phrase and the password, shows the result and
warns the person where the specification asks for it. The example in the
[documentation](https://docs.rs/mhfe-core) shows all of that.

In a debug build Argon2id takes about 16 times as long. Setting `opt-level = 3` for `argon2` in
`[profile.dev.package]` brings that down to about 4 times.

## Security

Secrets stay on memory pages of their own and are wiped after use, and a program can close itself
off from the network and from other programs before it reads one. What this covers on each system,
and what it does not, is in [SECURITY.md](SECURITY.md).

## Testing

Clone with `git clone --recurse-submodules`: the test vectors come from the specification's
repository. `cargo test --locked` runs the fast tests, and `cargo xtask check` runs everything CI
checks on one computer. The full-cost vectors take hours:
`cargo test --locked --release --test full_cost -- --ignored --nocapture`.

## Licence

MIT OR Apache-2.0, at your option: see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). Unless you say otherwise, a contribution you submit for inclusion
in this crate, as the Apache-2.0 licence defines it, is offered under both licences, without other
terms. The EFF word list and the crates this one depends on keep their own licences: see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
