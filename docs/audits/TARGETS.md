# Targets of mhfe-core

What each target is for the crate, and how CI and an audit check it, beyond the workspace's audit
guide, version 2, whose section 17, "Rust crates and native targets", applies here. The audit
reconciles this file with `rust-toolchain.toml`, the workflows
[ci.yml](../../.github/workflows/ci.yml), [vectors.yml](../../.github/workflows/vectors.yml),
[audit.yml](../../.github/workflows/audit.yml) and
[release.yml](../../.github/workflows/release.yml), and the [README](../../README.md), and reports a
mismatch. A report records the SHA-256 of this file.

## Target matrix

Whether the crate supports a target, whether a release audit must run it, and what CI does now
stay apart. A result belongs to the report, never to this file.

| Target | Support | Release audit runs it | CI now | Runner and minimum cases |
| --- | --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | Supported | Required | `cargo xtask check`: formatting, Clippy, documentation and every fast test, the isolation and secret-memory programs included; the fuzz targets linted; the minimum Rust; the package; the corpora at full cost in `vectors.yml` | Native Linux. The corpora, the profiles, the engine's tag, the isolation report and what the filter refuses, where secrets and the work area lie, the stack clearing. |
| `aarch64-unknown-linux-gnu` | Supported | Required | Fast tests | ARM64 Linux: the cases of the x86-64 row with the page size the runner has. |
| `aarch64-apple-darwin` | Supported | Required | Clippy; fast tests; the isolation program again under the hardened runtime | Apple silicon: the isolation report, which confirms that memory cannot be read only under the hardened runtime, and 16 KiB pages. |
| `x86_64-apple-darwin` | Supported | Required | Fast tests; the isolation program again under the hardened runtime | Intel macOS on `macos-15-intel`: the cases of the Apple silicon row with 4 KiB pages. |
| `x86_64-pc-windows-msvc` | Supported | Required | Fast tests | Native Windows: the isolation report, the access lists and the work area's lock. |
| `x86_64-pc-windows-gnu` | Supported, the toolchain of a Windows program cross-built on Linux | Required | Clippy and the tests built on Linux with MinGW; fast tests on Windows | The cases of the MSVC row, linked with MinGW. |
| `wasm32-unknown-unknown` | Supported, the browser build: no engine of its own | Required | Clippy; build | No runner: its code is the `wasm32` code that the WASI row runs, without the WASI system calls the crate does not make. |
| `wasm32-wasip1` | Test only: the `wasm32` code in an engine | Required | Fast tests in Wasmtime, pinned with its SHA-256 | Wasmtime: the fast tests that build there, the profiles and the isolation that applies nothing and says so among them. |
| `aarch64-linux-android` | Built and linted; no runner tests it | Optional until a runner exists | Clippy; the tests built | A device or emulator with an app's threads. |
| `x86_64-linux-android` | Built and linted; no runner tests it | Optional until a runner exists | Clippy; the tests built | An emulator. |
| `aarch64-apple-ios` | Built and linted; no runner tests it | Optional until a runner exists | Clippy; the tests built | A signed test app on a device. |
| `aarch64-apple-ios-sim` | Not built yet: the simulator of the iOS row, for apps tested there | Optional until CI runs it | None | The iOS simulator on a macOS runner, for the cases of the device row it can show. |
| `x86_64-unknown-linux-gnu`, fuzzing | Test only | Required | `release.yml`: each fuzz target for 90 seconds with `nightly-2026-11-13`, cargo-fuzz 0.13.2 and AddressSanitizer | Native Linux: the fuzz targets of `fuzz/` with their own lockfile, which must stay unchanged. |

Not built: 32-bit native targets, where the native engine does not compile, as suite 3 needs at
least 2 GiB; musl; and big-endian Linux.

## Fuzzing and analysis budgets

- The four targets under `fuzz/` (`phrase`, `password`, `repair`, `password_check`), with their own
  lockfile, are linted by `cargo xtask check`. `release.yml` runs each for 90 seconds before it
  packages a tag.
- Ordinary audit: each fuzz target for 5 minutes; Miri on the host for the unit tests that make no
  system call.
- Release audit: each fuzz target for 30 minutes, and AddressSanitizer on the Linux x86-64 suite.

## Tests

- `tests/isolation.rs` and `tests/secret_memory.rs` have their own `main` and start this executable
  again in child roles: count from their output that every check ran.
- `tests/full_cost.rs` replays the corpora at full cost, hours for both suites: `vectors.yml` runs
  it, never the fast tests.
- The engine's Argon2id tag is checked against tags that OpenSSL computed, independent of the
  RustCrypto engine.

## Permanent gaps

The Android and iOS runs: a hosted runner can run an Android emulator and the iOS simulator, which
CI does not do yet, and an Android app process or a signed iOS app on a device, which no runner
offers; `wasm32-unknown-unknown` in a browser engine, which only a program built on the crate runs,
and the Intel macOS run if GitHub stops offering an Intel macOS runner.
