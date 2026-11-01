# Third-party notices

The `mhfe-core` package holds one piece of third-party material, under its own licence: the EFF
large wordlist. It also depends on the Rust crates listed below, which Cargo fetches on their own
and which keep their own licences. This file ships with the package.

## EFF large wordlist

- Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt, included unchanged in
  `vendor/eff-large-wordlist/`. `build.rs` builds its words into the crate as
  `password_check::EFF_WORDS`.
- "EFF large wordlist" by the Electronic Frontier Foundation (Joseph Bonneau), licensed under the
  Creative Commons Attribution 4.0 International licence (CC BY 4.0):
  https://creativecommons.org/licenses/by/4.0/. See `vendor/eff-large-wordlist.md`.

## Test data of the repository

The repository's tests use data that the package does not hold:

- `tests/spec/`, the repository of the
  [MHFE specification](https://github.com/hobby-eng/mhfe-spec) as a submodule, whose test vectors
  the tests read; the specification publishes them under CC0 1.0.
- `tests/fixtures/unicode18-ucd/NormalizationTest.txt`, Unicode 18.0.0's normalization test data,
  under the Unicode License v3: https://www.unicode.org/license.txt.

## Rust crates

The crates this one depends on, at the versions of this repository's `Cargo.lock`, with the
licence expression each publishes; a program built on the crate resolves its own versions within
the requirements of `Cargo.toml`, compiles them in and takes on their licences. `base64ct` is here
only because `argon2` requires it; the engine does not use it.

Direct dependencies, each for one need:

- `argon2` 0.6.0, `MIT OR Apache-2.0`, on native targets: Argon2id for the native engine.
- `bip39` 3.0.0, `CC0-1.0`: the English word list, the checksum, entropy and words, and the BIP39
  seed.
- `blake2` 0.11.0, `MIT OR Apache-2.0`: the round salt.
- `hmac` 0.13.0, `MIT OR Apache-2.0`: the round mask.
- `sha2` 0.11.1, `MIT OR Apache-2.0`: the verifier and the wallet-check digest.
- `unicode-normalization` 0.1.26, `(MIT OR Apache-2.0) AND Unicode-3.0`: the NFKD of a password
  and a passphrase, with Unicode 18.0.0's tables.
- `zeroize` 1.9.1, `Apache-2.0 OR MIT`: wiping.
- `libc` 0.2.191, `MIT OR Apache-2.0`, on Unix systems: the calls for memory pages, process
  protections and the secret writer.
- `rayon` 1.12.0, `MIT OR Apache-2.0`, on native targets: the native engine's own pool of threads
  for the Argon2id lanes.
- `windows-sys` 0.61.2, `MIT OR Apache-2.0`, on Windows: the same calls there.

Crates they bring in:

- `CC0-1.0`: `bitcoin_hashes` 0.14.101, `hex-conservative` 0.2.3.
- `MIT OR Apache-2.0`, or the same two in the other order: `arrayvec` 0.7.8, `base64ct` 1.8.3,
  `block-buffer` 0.12.1, `cfg-if` 1.0.5, `cmov` 0.5.4, `cpufeatures` 0.3.1, `crossbeam-deque` 0.8.8,
  `crossbeam-epoch` 0.9.21, `crossbeam-utils` 0.8.23, `crypto-common` 0.2.2, `ctutils` 0.4.6,
  `digest` 0.11.3, `either` 1.19.0, `hybrid-array` 0.4.15, `rayon-core` 1.13.0, `typenum` 1.20.1,
  `windows-link` 0.2.1.
- `Zlib OR Apache-2.0 OR MIT`: `tinyvec` 1.13.3.
- At build time only, `MIT OR Apache-2.0` or `Apache-2.0 OR MIT`: `zeroize_derive` 1.5.0,
  `proc-macro2` 1.0.107, `quote` 1.0.47, `syn` 2.0.119; and `unicode-ident` 1.0.27,
  `(MIT OR Apache-2.0) AND Unicode-3.0`.

The tests also use `serde_json` 1.0.154 with the crates it brings in, under `MIT OR Apache-2.0` or
the same two in the other order, but `memchr` 2.8.3 (`Unlicense OR MIT`) and `zmij` 1.0.23 (`MIT`);
a program built on this crate does not compile them.
