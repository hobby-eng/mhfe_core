# AUD-010 harnesses

The harnesses of audit AUD-010 of mhfe-core, reviewed commit
`00c070ce20fdf7dc4d0ffaba9c1f8a9f07ae4b72`. Each is a crate of its own with its own lockfile; run
it from its folder.

- [audit-probes](audit-probes/README.md): reproduces `AUD-010-ARC001` against
  `xtask/src/code_rules.rs`, and checks the `slice_as_blocks` cast of `src/engine/native.rs` and
  `reed-solomon-core` 0.2.0's `CyclicWords` over `GF(2^11)` under Miri (`-Zmiri-strict-provenance`
  and `-Zmiri-tree-borrows`) with `secret-protection-core`'s signal-set system call isolated out.
  Exit code 0 when every probe holds.
