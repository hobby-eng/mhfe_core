# AUD-002 documentation harness

The crate in this folder, `aud002-doc-claims`, belongs to audit AUD-002 of mhfe-core 0.1.0, which
reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It reads the working tree of the
repository that holds it and checks three documentation claims against the code and the package it
replaces:

- `audit-references` (CHECK-DOC-003): no tracked file outside `docs/audits/`, `tests/fixtures/`,
  `tests/spec/` and `vendor/` names an audit record (`AUD-` and a digit). `tests/spec` is the
  submodule of the published release commit, the specification's repository, which git lists as
  one entry; the code-rules gate leaves it out too.
- `no-core-dumps-field` and `windows-report-residue` (CHECK-DOC-001, AUD-002-DOC002): on Windows,
  `Isolation::no_core_dumps` reads back only the error-reporting flag that leaves out the heap. The
  field doc must not say that a crash writes no core dump, and the Windows section of `SECURITY.md`
  must name the threads' stacks that an error report still holds. When `src/os/windows.rs` no
  longer reads that flag back alone, one `SKIP no-core-dumps` line replaces both checks.
- `withdrawn-release` (CHECK-DOC-001, AUD-002-DOC001): the paragraph of the CHANGELOG's 0.1.0
  section that names the withdrawn 0.1.0 must name each difference from that package: its licence,
  its features and its public modules (`API`). `src/notes.rs`, which finds that paragraph, is also
  read by the harness in `../skeptic-doc-withdrawn/`.

The harness was rewritten in Rust from the script `doc-claims.sh`, which the archive
`original-harnesses` (local) keeps, on 2026-10-27 at the owner's decision (TOOL-01). Its checks and
messages are the script's, with two differences: a skipped check makes the exit code 2 where the
script counted it as a pass (CORE-22), and the package given must have the SHA-256 below.

## Inputs

- The repository, Git, `tar`, and the Rust toolchain of `rust-toolchain.toml` with its registry
  cache: the crate's only dependency is `sha2` 0.11.1, which mhfe-core locks too.
- For `withdrawn-release`, the withdrawn package as the only argument: `mhfe-core-0.1.0.crate`,
  SHA-256 `bc23d4d1dcdbdcef54100eb9a04cd6634ca37898ea1098e4385505724906269d`, which crates.io
  served from 2026-10-25 until it was deleted and which Cargo's cache no longer holds. The audit
  used a local copy on the reviewer's machine,
  `/home/user/Documents/bip_tools/tmp/mhfe-core-public-release-0.1.0/mhfe-core-0.1.0-registry.crate`.
  Without the argument the check prints `SKIP withdrawn-release`.

## Running

From the repository root, with `<target>` a Cargo target folder outside the repository:

```sh
CARGO_TARGET_DIR=<target> cargo run --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/docs/Cargo.toml -- <mhfe-core-0.1.0.crate>
```

`cargo test` with the same options and no argument runs its unit tests.

## Output

Each check prints `PASS`, `FAIL` or `SKIP` and what it found. The exit code is 1 when a check
failed; 2 when none failed but one was skipped, or when the harness stopped on an error (a file it
cannot read, a package with another SHA-256, a tool that failed); 0 when every check passed.

- At `dec9c81`: `audit-references` passes and the other three checks fail, which reproduces
  AUD-002-DOC001 and AUD-002-DOC002; exit 1. The output is the script's record (local), line for
  line.
- On the audit's fixed 0.2.0 tree all four checks passed (the script, 2026-10-27).
- At the published release commit `c6eaa70`, which keeps version 0.1.0 and the one-line paragraph
  by the owner's decision (AUD-002-DOC001 accepted, not fixed): `audit-references` and the two
  Windows checks pass and `withdrawn-release` fails on the features and the API; exit 1. The
  licence is no longer a difference: the release commit licenses the crate `MIT OR Apache-2.0`, as
  the withdrawn package did, where an earlier release commit of 2026-10-27, `4296f06`, had `MIT`
  and failed on the licence too. The rerun of 2026-10-27 at `c6eaa70`, whose tracked files and
  CHANGELOG changed: `rerun-release-doc-claims.log` (local), exit 1, SHA-256
  `96cd071394e42e611ebb2443f62673c8ca0b51afb59086a13240960c705e7c4e`. Its first run there read
  the submodule's entry as a file and stopped with exit 2, `ERROR: tests/spec: Is a directory`:
  `rerun-release-doc-claims-attempt1.log` (local); since then the check leaves `tests/spec` out,
  which changes nothing at `dec9c81` and `2cfaa22`, where no such entry exists. At the earlier
  release commit `2cfaa22` the run gave the same verdicts. `audit-references`
  passes only while no tracked file names an audit identifier: the release commit's
  `xtask/src/code_rules.rs` puts the sample identifiers of its tests together with `concat!`, where
  an earlier release tree of 2026-10-27 held them whole (`AUD-012`, `AUD-0`, `AUD-1`) and failed it.
