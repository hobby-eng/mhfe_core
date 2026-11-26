# Corrections to AUD-010

[AUD-010](AUD-010-2026-11-26.md) is kept as its reviewer wrote it. Its findings, AUD-010-ARC001
and AUD-010-DOC001, and its observations reproduce, and its coverage measurement of `00c070c`
(96.84% of 2,373 lines) was repeated with the same result at `1fe8761`. Its text also states facts
that its own evidence, which stayed on the reviewer's machine, and the reviewed commit contradict.
Read these points instead of the report's text; [AUD-011](AUD-011-2026-11-26.md), section
"Observations and limitations", checked the second, eleventh and twelfth independently.

1. **Tool versions.** The environment log records cargo-audit 0.23.0, cargo-deny 0.20.2,
   cargo-llvm-cov 0.9.1, cargo-semver-checks 0.51.0 and Node.js 26.13.0, where the report gives
   0.22.1, 0.19.0, 0.8.5, 0.47.0 and 26.12.1.
2. **cargo semver-checks.** It compared `v0.2.0` with `0.3.0` as a major change and skipped all 260
   of its checks ("no semver update required"). It did not find "0 breaking changes": 0.3.0 breaks
   the API as the [changelog](../../CHANGELOG.md) lists, and the crate has no `protect::Issue`.
3. **WebAssembly exports.** The module of `wasm/` exports `memory` and `checks`, not four functions.
   Its 28 checks cover cards, repairs, check words, erasure and the wallet check's digest, not a
   wallet fingerprint.
4. **Code of another repository.** `src/mhfe.rs`, `src/wallet.rs`, `src/passphrase.rs` and
   `src/check_word.rs` are not in this repository, `src/protect.rs` has 11 lines that re-export
   secret-protection-core (there is no `protect::apply`), and the derivation of a wallet
   fingerprint through secp256k1 and HASH160 belongs to mhfe. CHECK-FUN-002, the scope and the
   assessment describe code that this audit did not review.
5. **Suite names.** "MHFE3-R12-ARGON2ID-SHA256" and "MHFE4-R12-ARGON2ID-SHA512" appear nowhere; the
   format identifier is `MHFE-BIP39-256-EXPERIMENTAL-3`, and no suite uses SHA-512.
6. **Dependency versions.** `Cargo.lock` holds ctutils 0.4.6, sha2 0.11.1, bip39 3.0.0 and
   unicode-normalization 0.1.26, not 0.4.8, 0.11.2, 2.2.2 and 0.2.0.
7. **secret-protection-core 0.2.0** has no `Secret::try_zeroed`; Miri stops at `sigfillset` when the
   first `Secret` is made.
8. **AUD-006-API001.** A passphrase whose NFKD is longer than `isize::MAX` bytes gets
   `Error::PassphraseTooLong`; `Error::SecretFull` no longer exists.
9. **The 32-bit guard** is the `compile_error!` of `src/engine/native.rs`, not `build.rs`.
10. **Fuzz reach.** `cargo fuzz coverage` failed for all six targets (its summary records exit code
    1 for each), which the report does not say: the reach of the corpora was not measured.
11. **Machine code.** The code-generation log records only the builds and the paths of the
    assembly and IR files; the report's claim of branch-free code on secret lookups has no retained
    evidence.
12. **Miri of the cast.** The harness ran its own copy of the cast to Argon2's blocks under Miri,
    not `blocks` of `src/engine/native.rs`.
