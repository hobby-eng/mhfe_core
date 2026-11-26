# AUD-011 verification commands

The reviewed commit is `aeefbdf70b43a9e889245e9312cd91599c18945d` in mhfe-core. Use the repository's pinned Rust toolchain, the
checked-out specification submodule, and the workspace resource guard. Each command processes
public fixtures or synthetic input. Command records and their outcomes are in the
[structured report](../AUD-011-2026-11-26.json). Retained earlier checks are labeled by revision.

From the repository root, with the workspace toolchains on PATH:

```sh
cargo fmt --all --check
cargo xtask check
cargo test --locked --offline --workspace --release --no-fail-fast
```

The two native profiles each report 105 core checks and 62 xtask tests, with exit 0. The
full-cost vector replay remains ignored. Clippy and hosted-platform records name the explicit
target and build profile.

The six fuzz targets are `phrase`, `password`, `passphrase`, `recovery`, `repair` and
`password_check`. Build with the pinned nightly, then run the compiled target under a hard
30-second process limit. Use distinct synthetic corpus and artifact directories under local
evidence.

```sh
cargo +nightly-2026-11-13 fetch --locked --offline --manifest-path fuzz/Cargo.toml
cargo +nightly-2026-11-13 fuzz build --fuzz-dir fuzz   --target x86_64-unknown-linux-gnu --target-dir <audit-build-dir> <target>
timeout --signal=KILL 30s <audit-build-dir>/x86_64-unknown-linux-gnu/release/<target>   <audit-corpus-dir> -max_total_time=28 -rss_limit_mb=2000 -max_len=4096   -artifact_prefix=<audit-artifact-dir>/
```

A completed short campaign exits 0 and reports its run count and elapsed time. Check that the
fuzz lockfile is unchanged. Extended campaign and coverage evidence belongs to hosted CI/CD.
Corpus data, build outputs and raw logs stay local. No
historical registry service or write to historical test data was needed for the static review.
