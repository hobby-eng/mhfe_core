# AUD-002 api harnesses

Audit-only checks of the "api" reviewer of AUD-002, for mhfe-core 0.1.0 at the reviewed commit
`dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. They cover CHECK-API-001 to CHECK-API-003 and
CHECK-ARC-002 of the workspace's audit guide. One Rust crate, `aud002-api`, built against the crate
in this repository by path, with its own `Cargo.lock`; one subcommand per check. The copies check
with `tests/` read is a crate of its own in `copies-with-tests/`: it compiles the copies gate of the
release tree, which dec9c81 lacks, while the probes build at both commits. Each check exits 0 when
it holds, 1 when it fails, and 2 when it could not run (a wrong argument, a file it cannot read, a
tool that does not start). None changes a file of the repository, and none runs full-size
Argon2id.

The public surface and the copies check were rewritten in Rust on 2026-10-27 from the scripts
`public_surface.py` and `copies-with-tests.sh`, which the archive `original-harnesses` (local)
keeps, at the owner's decision (TOOL-01). The probes, the former crate `probes/`, kept there too,
became subcommands of the same crate and return errors instead of panicking.

## Build

From the repository root, with a target folder outside the repository:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/api/Cargo.toml
```

The lockfile pins mhfe-core 0.1.0 and its dependencies, which the release commit keeps, so
`--locked` holds at both commits. Recorded at `2cfaa22`: exit 0,
`rerun-release-api-build.log` (local). The published release commit `c6eaa70` keeps the library
code, changing only `#[cfg(test)]` modules of `src/`, and `docs/public-api.txt`, so the runs of
the four subcommands below at `2cfaa22` stand there; `copies-with-tests`, which reads the tests,
ran again.

## Subcommands

### truncation

`<target>/release/aud002-api truncation` calls `NativeArgon2::argon2id` with a password of
2^32 + 1 zero bytes (zero pages from the allocator, of which only the first is touched when the
length is cut) and with the one-byte password `[0]`, at 32 KiB and one pass. The check: the two tags
differ, or the long password is refused.

- At `dec9c81`: `Ok(())` and equal tags, exit 1 (AUD-002-API001: the length is cut to 32 bits).
- At the release commit: `Err(Argon2Failed { code: -5 })`, the long password refused, exit 0.
  Recorded at `2cfaa22`: exit 0, `rerun-release-api-truncation.log` (local).

### stack-floor

`<target>/release/aud002-api stack-floor` finds, for `Phrase::read_word`, `Phrase::read`,
`Password::new`, `Check::of`, `Seed::derive` and `wallet_check::draw`, the smallest thread stack
among 64, 96, 128, 136, 144, 160, 192 and 256 KiB on which one call completes. Each call runs in a
child process (`aud002-api stack <KiB> <function>`), since an overflow ends the process; a child
killed by a signal is an overflow, and a child that exits with a code other than 0 stops the run
with exit 2. The check: every function runs on a thread of 128 KiB, the default thread stack of
musl's `pthread_create`.

- At `dec9c81`, release build on x86-64 Linux with glibc: 136 KiB for every function, exit 1
  (AUD-002-API002).
- At the release commit: the same, exit 1. The fix documents the stack a call needs (about
  140 KiB) rather than lowering it. Recorded at `2cfaa22`: exit 1, the same bytes as at `dec9c81`,
  `rerun-release-api-stack-floor.log` (local).

### nfkd

`<target>/release/aud002-api nfkd` times `Seed::derive` with a passphrase of one letter and 10,000,
20,000, 40,000 and 80,000 U+0301 COMBINING ACUTE ACCENT, one run of non-starters. The check: the
last doubling at most triples the time.

- At `dec9c81`: ratios of about 3 to 4 per doubling (4 s or more for 160 KB), exit 1
  (AUD-002-SEC001).
- At the release commit: a few milliseconds each, exit 0; its NFKD writer is linear in a run.
  Recorded at `2cfaa22`: 3 to 4 ms each, exit 0, `rerun-release-api-nfkd.log` (local).

### public-surface

Reads the crate's rustdoc JSON and checks the public surface: the public items are exactly the 22
paths of `docs/public-api.txt`; every secret type (`Password`, `Phrase`, `Recovery`, `Reading`,
`protect::Secret`, `wallet_check::Seed`, `repair::Card`, `repair::Repaired`, `repair::Change`,
`password_check::Check`) implements `Debug` and not `Display`; `Error` and `repair::Error`
implement `Display` and `std::error::Error`; no public signature, field, variant or trait item names
a type of a dependency; and every public type but the generic `Mhfe` is `Send` and `Sync`. It also
prints each public type's traits and methods, in the same lines as the archived script (local).
Stable Rust 1.99.1 writes the rustdoc JSON with `RUSTC_BOOTSTRAP=1`:

```sh
RUSTC_BOOTSTRAP=1 RUSTDOCFLAGS="-Z unstable-options --output-format json" \
  CARGO_TARGET_DIR=<target> cargo doc --locked --offline --no-deps
<target>/release/aud002-api public-surface <target>/doc/mhfe_core.json docs/public-api.txt
```

- At `dec9c81` and at the release commit: `22 public items`, the traits and methods of each, then
  `passed`, exit 0. The output is byte for byte that of the archived `public_surface.py` (local).
  Recorded at `2cfaa22`: exit 0, the same bytes as at `dec9c81`,
  `rerun-release-api-public-surface.log` (local); the rustdoc JSON was built with exit 0,
  `rerun-release-api-rustdoc-json.log` (local).

## copies-with-tests

The crate `aud002-api-copies-with-tests` in `copies-with-tests/`, with its own `Cargo.lock` and no
dependencies, runs the repository's copies gate (CORE-10) over `src/` and `tests/` of a tree; the
gate itself reads `src/` and `xtask/src/`, not `tests/`. The gate is the release tree's
`cargo xtask copies`: the crate compiles its source, `xtask/src/copies.rs` and its tokenizer
`xtask/src/copies/tokens.rs`, unchanged through a `#[path]` module. So the crate builds only in a
tree that has `xtask/`, the release commit, and the program built there scans a dec9c81 checkout as
well. dec9c81's own gate, `scripts/verify-no-copies.mjs`, is a Node.js script, which this
repository no longer runs (TOOL-01); the Rust gate applies the same rule, the one of mhfe's
`scripts/verify-no-copies.mjs` that the headers of both name.

From the root of a clone at the release commit with this folder copied into its `docs/audits/`,
`<tree>` being the checkout scanned and `<work>` a scratch folder outside it:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/api/copies-with-tests/Cargo.toml
<target>/release/aud002-api-copies-with-tests <tree> <work>
```

It gives the gate the root `<work>/copies-with-tests`, replaced on every run: the tree's `src/`,
its `tests/` at `src/tests/`, and an empty `xtask/src/`. It prints
`INFO the <n> Rust files of tests/ are read as src/tests/`, then the gate's summary, or each copy
the gate names as `<place> = <place> (<n> tokens)` and the gate's advice, which names the gate's
source by the path the compiler was given (`src/../../../../../../xtask/src/copies.rs`). Exit 0 when
the gate finds no copy, 1 when it names one, and 2 when it could not run (a wrong argument, `<work>`
inside `<tree>`, a `tests/` without Rust files, a file it cannot read). The gate's unit tests come
with its source; run them in the xtask crate, since one of them checks the path that `file!()`
gives there.

- At `dec9c81`, the program built at the release commit and run from a dec9c81 checkout with
  `<tree>` `.`: three copies of 50 to 53 tokens, `src/cipher.rs:288-296` against
  `src/tests/full_cost.rs:36-44` and `src/tests/support/corpus.rs:156-164`, and
  `src/tests/suite3.rs:74-78` against `src/tests/suite4.rs:39-43`; exit 1. They are the copies,
  lines and token counts that the review's run of dec9c81's Node.js gate found, which named the
  `tests/` files without `src/`, in `record-copies-with-tests.log` (local). Recorded on
  2026-10-27: exit 1, `rerun-dec9c81-api-copies-with-tests.log` (local).
- At the published release commit `c6eaa706866b9868cb51048d64b3d21752abce44`: the same three
  copies, exit 1; their lines in the tests moved with the tests, to
  `src/tests/support/corpus.rs:239-247` and `src/tests/suite3.rs:82-86`. Its tests read the
  specification's vectors from the submodule `tests/spec`, which holds no Rust file. Recorded:
  exit 1,
  `rerun-release-api-copies-with-tests.log` (local), after the build, exit 0,
  `rerun-release-api-copies-with-tests-build.log` (local). At the earlier release commit `2cfaa22`
  the log was that of `dec9c81`, byte for byte.

Until 2026-10-27 this check was a subcommand of `aud002-api` that copied the repository and ran the
tree's own gate, at dec9c81 `node scripts/verify-no-copies.mjs`. The owner allows no Node.js
anywhere, harnesses included (TOOL-01), so the release tree's Rust gate replaced it.

The audit records these copies as observations, not findings: each is the signature of an
`Argon2Engine` implementation or three lines of test setup.
