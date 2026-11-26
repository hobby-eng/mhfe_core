# AUD-010 audit-probes harness

Runs two independent probes for audit AUD-010 of reviewed commit
`00c070ce20fdf7dc4d0ffaba9c1f8a9f07ae4b72`:

1. **Dependency-gate bypass (`AUD-010-ARC001`):** invokes `xtask/src/code_rules.rs` directly on a
   synthetic repository root whose `Cargo.toml` declares unpinned wildcard (`"*"`) dependencies
   through a TOML dependency sub-table (`[dependencies.subtable-dep]`), a commented dependency
   header (`[dependencies] # comment`) and a multi-line inline table, confirming that
   `code_rules::run` accepts all three without a CORE-25 error while still rejecting an ordinary
   single-line unpinned entry under `[dependencies]`.
2. **Miri soundness of `slice_as_blocks` and `CyclicWords`:** exercises the exact raw-slice cast of
   `src/engine/native.rs` (`slice_as_blocks`, the crate's sole `unsafe` block) across aligned,
   misaligned and non-multiple byte buffers, and runs `reed-solomon-core` 0.2.0 (`default-features =
   false`, without `secret-protection-core`'s `sigfillset` call) across MHFE's `GF(2^11)` card
   shapes (`12` to `24` data words, `2` to `8` parity words, erasures and unknown symbol errors).

Inputs: none; synthetic manifests and fixed deterministic word indices.

Run from this folder, writing build outputs to the root ignored `target/` folder:

```sh
CARGO_TARGET_DIR=../../../../target/aud-010-harnesses cargo test --locked
CARGO_TARGET_DIR=../../../../target/aud-010-harnesses \
  MIRIFLAGS="-Zmiri-strict-provenance" \
  cargo +nightly-2026-11-13 miri test --locked
CARGO_TARGET_DIR=../../../../target/aud-010-harnesses \
  MIRIFLAGS="-Zmiri-tree-borrows" \
  cargo +nightly-2026-11-13 miri test --locked
```

Exit code 0 when every check passes.
