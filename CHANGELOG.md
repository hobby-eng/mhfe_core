# Changelog

## 0.1.0 (2026-10-27)

This release implements the MHFE specification 0.7.0: suites `MHFE-BIP39-256-EXPERIMENTAL-3` and
`MHFE-BIP39-LP-EXPERIMENTAL-4` with Unicode 18.0.0 for passwords, and the profiles
MHFE-WALLET-CHECK-SEED-1, MHFE-REPAIR-1 and MHFE-PASSWORD-CHECK-1. Its tests replay the
specification's test vectors, which they read from the specification's repository.

It replaces an earlier 0.1.0 of this crate, which was withdrawn from crates.io.

The code was cut from the `mhfe` repository at commit `67e0b4c` (the code of mhfe 0.6.0, its
dependency update to Unicode 18.0.0 and the fixes that followed), and gives the same containers,
readings, repair words and check words. What came from where:

- The suites, from mhfe's `src/suite.rs`, `password.rs`, `phrase.rs`, `packing.rs`, `feistel.rs`,
  `mhfe.rs` and `detection.rs`. `Mhfe::encrypt` and `Mhfe::decrypt` each replace two steps, and
  the callbacks return `ControlFlow`.
- The Argon2id engine, from mhfe's `src/engine.rs`, `engine/ffi.rs`, `engine/native.rs` and
  `build.rs`, with the vendored Argon2 and EFF word list trees byte for byte. MHFE's wrapper
  `src/engine/argon2_wrap.c` replaces mhfe's `src/engine/argon2_simd.c` and clears the stack the
  vendored code leaves.
- The profiles, from mhfe's `src/wallet_check.rs`, `wallet.rs`, `repair.rs`, `check_word.rs` and
  `eff.rs`. The draw tries one phrase after another, where mhfe drew on several threads.
- The protections, from mhfe's `src/memory.rs`, the memory calls of its `src/engine/ffi.rs` and its
  `src/bin/mhfe/protect.rs`. New: secret memory on Linux, the filter's rules for file changes,
  other processes and `ioctl`s and its limit on newer calls, the protections of macOS and Windows,
  and `protect::write_secret`.
- The tests of the vectors, from mhfe's `tests/suite3_vectors.rs`, `suite4_vectors.rs`,
  `validation_cases.rs` and `vector_share/share.rs`, rewritten for this API without mhfe's vector
  generator. The workflows follow mhfe's; the gates, Node scripts in mhfe, are Rust here, as
  `cargo xtask` tasks, and dprint formats the documents instead of Prettier.
