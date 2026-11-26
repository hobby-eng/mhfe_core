# Test coverage

The Linux x86-64 run on 2026-11-26 covered **96.84%** (2,298 of 2,373 measured source lines). All
105 checks passed: 78 unit tests, 3 isolation checks, 5 secret-memory checks, 3 password tests, 7
profile tests, 5 suite 3 tests, 3 suite 4 tests and the doctest. The full-cost test, which takes
hours, was left out as always.

## Measurement

Rust 1.99.1 and cargo-llvm-cov 0.9.1 measured commit `1fe8761`
(`1fe87612b259f9acd8bf7a7b824b20d438cc6297`), before the release of 0.3.0, with
secret-protection-core 0.2.0 and reed-solomon-core 0.2.0 from crates.io as Cargo.lock names them.
The commit that adds this report changes only documentation and audit records, so the measured
code is unchanged.

## Scope and exclusions

The percentage counts the library's source lines compiled for Linux x86-64 and its unit tests. The
integration test files, `xtask`, the fuzz targets, the dependencies, secret-protection-core and
reed-solomon-core among them, and the code of other systems are outside the denominator.
`test_support.rs`, a helper compiled only for the unit tests, is counted.

| File                | Measured lines | Covered | Coverage |
| ------------------- | -------------: | ------: | -------: |
| `cipher.rs`         |            291 |     269 |   92.44% |
| `engine/native.rs`  |            166 |     160 |   96.39% |
| `error.rs`          |             42 |      16 |   38.10% |
| `feistel.rs`        |            365 |     364 |   99.73% |
| `nfkd.rs`           |            153 |     153 |  100.00% |
| `packing.rs`        |            106 |     106 |  100.00% |
| `password.rs`       |            154 |     153 |   99.35% |
| `password_check.rs` |            105 |     104 |   99.05% |
| `phrase.rs`         |            267 |     267 |  100.00% |
| `recovery.rs`       |            235 |     232 |   98.72% |
| `repair.rs`         |            187 |     176 |   94.12% |
| `repair/code.rs`    |             99 |      99 |  100.00% |
| `same.rs`           |             19 |      19 |  100.00% |
| `suite.rs`          |             83 |      83 |  100.00% |
| `test_support.rs`   |             17 |      17 |  100.00% |
| `wallet_check.rs`   |             84 |      80 |   95.24% |
| Total               |          2,373 |   2,298 |   96.84% |

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
