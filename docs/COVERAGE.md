# Test coverage

The Linux x86-64 run on 2026-11-25 covered **97.09%** (2,403 of 2,475 measured source lines). All
104 checks passed: 77 unit tests, 3 isolation checks, 5 secret-memory checks, 3 password tests, 7
profile tests, 5 suite 3 tests, 3 suite 4 tests and the doctest. The full-cost test, which takes
hours, was left out as always.

## Measurement

Rust 1.99.1 and cargo-llvm-cov 0.9.1 measured commit `129736e`
(`129736ee96f0cca598cb81ea5179280d2627a661`), before the release of 0.3.0. secret-protection-core
0.2.0 was not yet on crates.io, so the run took it from its commit `cd06231` through a
`[patch.crates-io]` entry passed with `--config`. The commit that adds this report changes only
documentation, comments, the requirement on secret-protection-core and the `xtask` list that allows
it, so the measured code is unchanged.

## Scope and exclusions

The percentage counts the library's source lines compiled for Linux x86-64 and its unit tests. The
integration test files, `xtask`, the dependencies, secret-protection-core among them, and the code
of other systems are outside the denominator. `test_support.rs`, a helper compiled only for the
unit tests, is counted.

| File                | Measured lines | Covered | Coverage |
| ------------------- | -------------: | ------: | -------: |
| `cipher.rs`         |            291 |     269 |   92.44% |
| `engine/native.rs`  |            166 |     160 |   96.39% |
| `error.rs`          |             40 |      16 |   40.00% |
| `feistel.rs`        |            366 |     365 |   99.73% |
| `nfkd.rs`           |            153 |     153 |  100.00% |
| `packing.rs`        |            107 |     107 |  100.00% |
| `password.rs`       |            155 |     154 |   99.35% |
| `password_check.rs` |            105 |     104 |   99.05% |
| `phrase.rs`         |            268 |     268 |  100.00% |
| `recovery.rs`       |            235 |     232 |   98.72% |
| `repair.rs`         |            187 |     176 |   94.12% |
| `repair/field.rs`   |            225 |     223 |   99.11% |
| `suite.rs`          |             83 |      83 |  100.00% |
| `test_support.rs`   |             17 |      17 |  100.00% |
| `wallet_check.rs`   |             77 |      76 |   98.70% |
| Total               |          2,475 |   2,403 |   97.09% |

`error.rs` is mostly the `Display` texts of the refusals, and the tests compare the refusals as
values. CI also runs the tests on Linux ARM64, macOS and Windows, and in WebAssembly under WASI, and
builds them for Android and iOS.

## Reproduce on Linux

From the repository root, in bash, with the pinned toolchain:

```sh
mkdir -p target
export CARGO_TARGET_DIR="$(mktemp -d "$PWD/target/coverage.XXXXXXXX")"
export CARGO_LLVM_COV_TARGET_DIR="$CARGO_TARGET_DIR"
source <(cargo llvm-cov show-env --sh)
export RUSTFLAGS="-C llvm-args=-runtime-counter-relocation"
export LLVM_PROFILE_FILE="$CARGO_TARGET_DIR/mhfe-core-%p%c.profraw"
cargo test --locked --offline -p mhfe-core
cargo llvm-cov report --summary-only --ignore-filename-regex '(/tests/|/xtask/)'
```

`%p` gives each process its own profile, and `%c` lets a child process record its counters after
isolation has taken away its right to open files.
