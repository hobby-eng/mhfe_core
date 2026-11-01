# Changelog

## 0.2.0 (2026-11-01)

Same specification 0.7.0, same containers, readings, repair words and check words as 0.1.0.

- The native engine is RustCrypto's `argon2` instead of vendored C, so a build needs no C compiler.
  It runs on four threads of its own, about 7% faster.
- Call `protect::Isolation::enter` before `NativeArgon2::new` or `Mhfe::new`, on the thread that
  makes the engine: its threads start there and inherit it.
- `new` can return `Error::Argon2Failed`: -33 for a refused thread. What `argon2` refuses is -25,
  where 0.1.0 gave -12, -14 or -5; no call through `Mhfe` reaches these.
- `NativeArgon2` and `Mhfe<NativeArgon2>` are no longer `UnwindSafe` or `RefUnwindSafe`.
- A debug build runs Argon2id unoptimized, about 16 times slower.
- Fixed: on Linux with kernel commit 97d34aa65c29, in Ubuntu from 7.0.0-39, a low `RLIMIT_MEMLOCK`
  ended the process at its first write to a `Secret`. It now takes anonymous pages.
- macOS: isolation also refuses file writes.
- The tests read specification 0.7.0's JSON vectors. A Windows clone no longer needs
  `core.autocrlf=false`.

A correction to 0.1.0: its cut point, commit `67e0b4c` of `mhfe`, is on no branch now; the same code
is at `3b58a02`, which differs only in `README.md`.

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
