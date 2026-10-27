# mhfe-core

[![CI](https://github.com/hobby-eng/mhfe_core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/mhfe_core/actions/workflows/ci.yml)
[![Release](https://github.com/hobby-eng/mhfe_core/actions/workflows/release.yml/badge.svg)](https://github.com/hobby-eng/mhfe_core/actions/workflows/release.yml)
[![Test vectors](https://github.com/hobby-eng/mhfe_core/actions/workflows/vectors.yml/badge.svg?event=push)](https://github.com/hobby-eng/mhfe_core/actions/workflows/vectors.yml)
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

Every secret the crate holds, from the encoded password and the phrases to the round keys, seeds
and repair words, lives in a `protect::Secret`, which has memory pages of its own and is wiped when
it is dropped. A program can keep its own secrets, such as a typed line, in one too.
`protect::write_secret` writes a secret to standard output without leaving a copy in the standard
library's output buffer. The Argon2id work area is wiped after every round. After each call that
computes with a secret, other than calls to `Repaired::changes`, `protect` and the engine, the
crate overwrites 128 KiB of the stack below the caller's frame. Such a call therefore needs about
140 KiB of free stack; on a smaller thread stack, such as musl's default of 128 KiB, it ends the
process.

`protect::Isolation::enter()`, called before a secret is read, applies the protections the
operating system offers against a secret leaving the process. It reads each protection back and
reports which ones hold: a refusal shows as `false`, never as an error. On every system, whatever
the process opened before the call, such as a socket or a file open for writing, stays usable.
What each system allows:

- **Linux:** secret pages come from the kernel's secret memory on x86-64 and AArch64 where the
  kernel offers it; otherwise they are locked and left out of core dumps. Other processes, root's
  included, cannot read the secret memory directly through `/proc/PID/mem`, `process_vm_readv` or
  `PTRACE_PEEKDATA`, and while it exists the computer cannot hibernate. Isolation forbids core
  dumps and keeps other programs of the user from reading the process's memory. On x86-64 and
  little-endian AArch64, its filter refuses new sockets, io_uring, `ptrace`, `process_vm_writev`,
  `pidfd_getfd` and every change to files. On other architectures, where the kernel has Landlock,
  it refuses writing, creating, renaming and removing files; on newer kernels also truncating them
  and device `ioctl`s, and from Linux 6.7 also TCP bind and connect. These refusals cover the
  calling thread and the threads it starts. When isolation is entered while the process has one
  thread, they cover the whole process; where user namespaces are allowed, the process then also
  gets a network of its own with no interface up. Root, or a program with `CAP_SYS_PTRACE`, can
  still read the process's memory, the work area included, and so can a program that opened
  `/proc/PID/mem` or attached as a tracer before the call, such as a debugger the program was
  started under.
- **Android:** secret pages are locked and left out of core dumps. Isolation forbids core dumps and
  memory reading as on Linux, and applies the same filter to the calling thread only, which must be
  a native thread of its own. For the whole process, the app's only barrier against the network is
  going without the `INTERNET` permission. After a crash, Android's crash handler reads the
  process, and its report holds memory near the registers.
- **macOS:** secret pages are locked, and a child process does not get them. Isolation, for the
  whole process, forbids core dumps, refuses debuggers unless one already traces the process, and
  enters the sandbox without network. Files are not restricted, and root is not kept out.
- **iOS:** secret pages are locked where the system allows it; isolation can only forbid core
  dumps. Build with `IPHONEOS_DEPLOYMENT_TARGET` set to 13.0 or later, as Xcode sets it, so that
  the C code and Rust target the same version: the stack probes of the C code's large frames need
  iOS 13.
- **Windows:** secret pages are locked and left out of error reports. Isolation, for the whole
  process, leaves the heap out of error reports, which still hold the threads' stacks and
  registers. It keeps programs of the same user from opening the process or its threads to read or
  change them, and lowers the process to low integrity, which refuses writes to the user's files
  but not to volumes without access control, such as FAT and exFAT USB sticks and SD cards.
  Every object the process, or a program it starts, creates afterwards without an access list of
  its own, such as threads and pipes, gets the threads' access list. Even the process itself can
  then open such an object by name or ID for little more than waiting for it, so the process
  cannot, for instance, start a program with piped standard streams. Programs of the same user can
  still suspend a program the process starts. Sockets are not restricted, and administrators are
  not kept out.
- **WebAssembly:** a secret is an ordinary buffer that is only wiped, and isolation applies
  nothing.

The Argon2id work area, 2 GiB at the default memory level, is locked only where the limit on
locked memory holds all of it, which on Linux it usually does not (8 MiB). Where it is not locked,
the system may write it to swap, so use encrypted swap or none. [SECURITY.md](SECURITY.md) gives
the details and what stays exposed.

## The API at a glance

- `Phrase` reads a phrase as a person types it, or makes one from entropy; `Password` encodes a
  password; `WorkFactor` holds the PIM and the memory level; `Suite` names a suite.
- `Mhfe` creates and recovers containers with an `Argon2Engine`: `NativeArgon2` (the vendored
  reference C code) on native targets, or the host's own engine in WebAssembly. A recovery is a
  `Recovery`, whose readings are `Reading`s. `Error` lists the refusals, and `Error::Cancelled`
  reports that a callback returned `ControlFlow::Break`.
- `protect`: `Secret`, `Isolation` and, on native targets, `write_secret`.
- `wallet_check`: `Seed` and `draw`. `repair`: `Card`, `Repaired`, `Change` and their `Error`.
  `password_check`: `EFF_WORDS`, `check_word` and `Check`.

The crate's documentation (`cargo doc --open`) describes every item, its errors and the order of
its calls.

## Building

The crate needs Rust 1.99 or later and has no Cargo features. A native build compiles the vendored
Argon2 C code and needs a 64-bit target and a C compiler that the `cc` crate finds (GCC or Clang,
Microsoft's compiler, the Android NDK's or Xcode's Clang). `wasm32-unknown-unknown` needs no C
compiler: there the host implements `Argon2Engine`.

## Testing

The tests read the specification's test vectors from its repository, which this one holds as the
submodule `tests/spec`. Clone with `git clone --recurse-submodules`, or run
`git submodule update --init` in an existing clone. On Windows, clone with
`git -c core.autocrlf=false`, so that the specification's files keep the line endings their
`SHA256SUMS` hash.

- `cargo test --locked` runs the fast tests. They replay the specification's test vectors of both
  suites and of the profiles with the Argon2id keys the vectors record, so that no test needs
  gigabytes of memory. They also test the native engine against an independent Argon2
  implementation at small costs, and check the secret pages and the isolation as the system
  reports them.
- `cargo xtask check` runs the checks of CI's `checks` job: the tests, Clippy, rustfmt, dprint,
  the documentation, the code rules, the copy, public API and vendored-file checks, and a check of
  the stack that the Argon2 C code leaves. The tools are in the repository's `xtask` crate, which
  is not part of the package; dprint 0.63.0 formats the Markdown, JSON, TOML and YAML. CI's other
  jobs build and test the crate on other systems and on Rust 1.99, and check the package.
- `cargo test --locked --release --test full_cost -- --ignored --nocapture` replays both suites'
  vectors at full cost, which takes hours, with 2 or 3 GiB of memory per call.
  `MHFE_VECTOR_SHARE=k/n` splits the work among n processes.

## Licence

MIT OR Apache-2.0, at your option: see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE). Unless you say otherwise, a contribution you submit for inclusion
in this crate, as the Apache-2.0 licence defines it, is offered under both licences, without other
terms. The vendored Argon2 code and the EFF word list keep their own licences: see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
