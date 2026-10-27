# AUD-002 challenge harness: the unsafe_code lint of lib.rs

Audit AUD-002 of mhfe-core 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It
challenges a report that the review withdrew: "lib.rs repeats the manifest's unsafe_code lint".

The program exports a commit twice with `git archive`, appends one unsafe block with its SAFETY
comment to `src/suite.rs` in both, removes the line `#![deny(unsafe_code)]` from `src/lib.rs` in the
second (and checks that `Cargo.toml` still has `unsafe_code = "deny"`), and runs
`cargo check --locked --offline` four ways:

| Case | `#![deny(unsafe_code)]` | `RUSTFLAGS`     | Required                                    |
| ---- | ----------------------- | --------------- | ------------------------------------------- |
| A    | kept                    | none            | refused, at the lint level of `src/lib.rs`  |
| B    | removed                 | none            | refused, by the manifest's `-D unsafe-code` |
| C    | kept                    | `-Aunsafe_code` | refused, at the lint level of `src/lib.rs`  |
| D    | removed                 | `-Aunsafe_code` | accepted                                    |

A refusal is Cargo's exit 101 with rustc's ``error: usage of an `unsafe` block`` and the note that
names where the lint level comes from. C against D shows that the attribute is not redundant:
without it, a `RUSTFLAGS` of `-Aunsafe_code` turns the manifest's lint off.

## Commands

From the repository root, with `<target>` a build folder and `<work>` a scratch folder:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-arc-unsafe/Cargo.toml
<target>/release/aud002-skeptic-arc-unsafe . dec9c8115ff9ddbd32bb5fdd457ae9904043c966 <work>
```

At the release commit, pass `HEAD` as the commit. Inputs: the repository and a commit it holds. The
program needs Git, `tar`, the toolchain of `rust-toolchain.toml` (the exported tree's own file picks
it) and the Cargo registry cache of mhfe-core's dependencies; it uses no network. It replaces
`<work>/src-keep` and `<work>/src-drop` on each run, builds into `<work>/target-plain` and
`<work>/target-flags`, and writes each run's output to `<work>/check-<case>.log`. The variables
`RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` of the caller are cleared for every run. The audit ran
the program under its memory guard, which also covers the Cargo runs it starts; that is optional.

## Output and exit code

One line per case, `A: ok (exit 101)` to `D: ok (exit 0)`, or
`<case>: FAIL (exit <got>, wanted <exit>; missing [<text>])`. Exit 0 when all four hold, 1 when
one differs, 2 when the check could not run (the error is printed).

- At `dec9c81`: four `ok` lines, exit 0. Recorded: exit 0.
- At the release commit: the same, exit 0: `src/lib.rs` keeps the attribute and `Cargo.toml` keeps
  the lint. Recorded at `2cfaa22`: exit 0, `rerun-release-skeptic-arc-unsafe.log` (local). The
  published release commit `c6eaa70` keeps `src/lib.rs`, `src/suite.rs`, `Cargo.toml` and the
  library code that `cargo check` compiles, so that run stands there.

## History

Rewritten in Rust from the archived script `lint-precedence.sh` on 2026-10-27 at the owner's
decision (TOOL-01). The script is kept, read-only, in the local evidence folder
`docs/audits/AUD-002-evidence/original-harnesses` (local). Changes from it: no memory-guard
argument (the guard runs the whole program) and no log-prefix argument (the logs go to `<work>`);
each refusal must also show rustc's unsafe-block error, not only where the lint level comes from;
an error that stops the check exits 2 instead of 1. The harness review's TOOL-02 finding on the
script (H5: no `set -e`, unquoted expansions) has no object in the Rust version.

The rerun at `dec9c81` on 2026-10-27 printed the same bytes as the run of the record:
`rerun-dec9c81-skeptic-arc-unsafe.log` (local), SHA-256
`83d7a3bfb89a274579fb9fbd85dfffb98288643a3f1b21cc648c6b8d19fca4d3`. The rerun at the release
commit `2cfaa229fbe0fb046ecdb2d45291b380da4a12bf` on the same day, with `HEAD` as the commit and
after its build (exit 0, `rerun-release-skeptic-arc-unsafe-build.log` (local)), printed the same
four `ok` lines, byte for byte, and exited 0:
`rerun-release-skeptic-arc-unsafe.log` (local), SHA-256
`83d7a3bfb89a274579fb9fbd85dfffb98288643a3f1b21cc648c6b8d19fca4d3`.
