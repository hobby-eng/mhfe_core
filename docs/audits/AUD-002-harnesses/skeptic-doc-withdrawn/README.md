# AUD-002 skeptic: consumers of the withdrawn 0.1.0

Audit AUD-002 of mhfe-core 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. The
crate in this folder, `aud002-skeptic-doc-withdrawn`, challenges the finding AUD-002-DOC001: the
0.1.0 notes replace a withdrawn 0.1.0 without saying what a user of that package meets. It writes
two consumers of the withdrawn package and builds them offline against the repository that holds
it:

- `features` depends on mhfe-core with the feature `browser-core`, which the withdrawn package
  declared; `cargo metadata` resolves it.
- `api` imports `Completion` and `ErrorCode`, which the withdrawn package's `src/lib.rs` exported
  at its root; `cargo check` builds it.

It fails when such a consumer breaks and the paragraph of the CHANGELOG's 0.1.0 section that names
the withdrawn package does not name the break (`features`, `API`, in any case). That paragraph is
found by `../docs/src/notes.rs`, which the documentation harness uses too.

The feature and the two items were read from the withdrawn package (SHA-256
`bc23d4d1dcdbdcef54100eb9a04cd6634ca37898ea1098e4385505724906269d`) when the audit wrote the check:
the harness needs neither the package nor Cargo's cache of it, which no longer holds it.

The harness was rewritten in Rust from the script `old-consumer.sh`, which the archive
`original-harnesses` (local) keeps, on 2026-10-27 at the owner's decision (TOOL-01). Its output is
the script's, but for one trailing space. Two differences: a consumer that fails for another reason
than the missing feature or items (such as a dependency missing from the offline cache) stops the
harness with exit 2, where the script counted it as a break; and the scratch folder is not emptied:
the harness overwrites the files it writes there.

## Inputs

- The repository with its `Cargo.lock`, which each consumer copies, and its `rust-toolchain.toml`,
  whose channel the consumers outside the repository get through `RUSTUP_TOOLCHAIN`.
- The Rust toolchain with its registry cache holding mhfe-core's dependencies (all runs offline).
- A scratch folder outside the repository, the only argument; the harness writes `features/` and
  `api/` into it. With `CARGO_TARGET_DIR` set, the consumers build there too.

## Running

From the repository root, with `<target>` a Cargo target folder and `<work>` a scratch folder, both
outside the repository:

```sh
CARGO_TARGET_DIR=<target> cargo run --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-doc-withdrawn/Cargo.toml -- <work>
```

## Output

One line per consumer, then the verdict. The exit code is 1 when the claim fails, 2 when the
harness stopped on an error, and 0 otherwise.

- At `dec9c81`: both consumers break and the paragraph names neither:
  `FAIL: a consumer of the withdrawn 0.1.0 breaks on: features API; the 0.1.0 notes never name:
  features API`, exit 1.
- On the audit's control, `dec9c81` with "Its API, features and licence (now MIT alone) differ."
  added to the paragraph, the script passed.
- At the published release commit `c6eaa70`, which keeps version 0.1.0 and the one-line paragraph
  by the owner's decision (AUD-002-DOC001 accepted, not fixed): the same `FAIL`, exit 1. The rerun
  of 2026-10-27, after the CHANGELOG changed: `rerun-release-old-consumer.log` (local), exit 1,
  SHA-256 `c8ef83b86219fde4f3519cedf57287d9468a48148dc801d1b871831ff677cb01`. It replaced the
  run at the earlier release commit `2cfaa22`, with the same verdict.
