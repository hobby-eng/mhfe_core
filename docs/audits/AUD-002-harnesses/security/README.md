# AUD-002 security harnesses

Audit AUD-002 of mhfe-core 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`,
security reviewer. A small Cargo package that depends on the crate in this repository by path
(`../../../..`) and on `libc` 0.2.191; its own `Cargo.lock` pins both. It uses public inputs only
and runs no full-size Argon2id.

## What the programs check

- `isolation-probe` (Linux only; elsewhere it exits 2): a process of one thread calls
  `protect::Isolation::enter()` and reads each protection back from the kernel, apart from the
  crate's own probes: `Seccomp: 2`, `Seccomp_filters: 1` and `NoNewPrivs: 1` in
  `/proc/self/status`, the dumpable flag, `RLIMIT_CORE` 0 and 0, new sockets of five families and
  `io_uring_setup` refused with `EACCES`, calls 437 (openat2), 472 and 600 (past the newest call of
  Linux 7.0) answered with `ENOSYS`, creating and renaming files refused, a Landlock refusal that
  the filter cannot give (connect on a TCP socket opened before the call, Landlock ABI 4 or later),
  the empty network namespace where the system allows one (the overflow IDs 65534, only `lo`, no
  IPv4 route), the `VmFlags` of a `Secret` made after the call (`lo`, `dd`, and `dc` for secret
  memory or `wf` for anonymous pages), the work area of `NativeArgon2` (`dd`, `wf`, `lo` exactly
  when `is_locked()`), and a 1 MiB Argon2id call whose lanes start after the call, against the tag
  OpenSSL's ARGON2ID KDF gives for the same input (`e0e8eba3…`). It exits 2 when a call its setup
  needs is refused (the TCP socket, the fork of the namespace probe).
- `input-bounds` (any native system): how the time of public entry points grows with their text.
  `Seed::derive` and `wallet_check::draw` (cancelled at its first trial) with a BIP39 passphrase of
  16 to 128 KiB, ASCII and one letter followed by combining acute accents (U+0301), must grow by at
  most 3 times per doubling; `Password::new` and `Phrase::read` must refuse 64 MiB inputs within
  1 s; the worst search of `Repaired::of` must end within 1 s. Times are medians of three runs.

Each program prints `PASS` or `FAIL` per check and exits 1 when any check fails.

## How to run

From the repository root, on Linux x86-64 or AArch64 with Rust 1.99.1:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/security/Cargo.toml
<target>/release/isolation-probe
<target>/release/input-bounds
```

The lockfile pins mhfe-core 0.1.0 and its dependencies, which the release commit keeps, so
`--locked` holds at both commits. Recorded at `2cfaa22`: exit 0,
`rerun-release-security-build.log` (local). The published release commit `c6eaa70` keeps the
library code, changing only `#[cfg(test)]` modules of `src/`, so the runs below at `2cfaa22` stand
there.

## Expected output

- `isolation-probe`, at `dec9c81` and at the release commit: 22 `PASS` lines, `0 failed`, exit 0,
  on Linux 7.0.0-38 with Landlock ABI 8, secret memory and user namespaces allowed. Recorded at
  `2cfaa22`: exit 0, the same bytes as the record (local),
  `rerun-release-isolation-probe.log` (local).
- `input-bounds` at `dec9c81`: exit 1. The two passphrase checks with combining marks `FAIL` with a
  growth of about 4 per doubling (about 0.04 to 0.1, 0.15 to 0.6, 0.5 to 2.5 and 2.3 to 9 s for 16,
  32, 64 and 128 KiB, by the load of the machine), while the ASCII passphrase of the same lengths
  takes a few milliseconds each; the other checks `PASS`. This is the report's finding on the
  passphrase NFKD (AUD-002-SEC001): the NFKD writer re-reads the whole run of non-starters for each
  one it adds, and nothing bounds the length of a passphrase.
- `input-bounds` at the release commit: every check `PASS`, `0 failed`, exit 0; the passphrases of
  combining marks take about as long as ASCII ones. Recorded at `2cfaa22`: exit 0, `Seed::derive`
  1 to 3 ms with either passphrase, `rerun-release-input-bounds.log` (local).

## Changes on 2026-10-27

Both programs return an error and exit 2 instead of panicking where the original asserted; the
refusal checks of `input-bounds` report a non-refusal as `FAIL` instead of a panic, and add
`refused true` to their line. The isolation probe's magic values are named constants with their
source, its long function carries the CORE-15 exception with its reason, and its `unsafe` code is
allowed, with a reason, on its Linux module only. `libc` is pinned exactly, and `Cargo.toml` has
the lints table of RUST-01. The checks are unchanged: rerun at `dec9c81`, `isolation-probe` printed
the same bytes as the record (local) and `input-bounds` the same verdicts.
