# AUD-002 harnesses

These programs belong to audit AUD-002 of mhfe-core, reported in
[AUD-002-2026-10-27.md](../AUD-002-2026-10-27.md). The reviewed snapshot is commit
`dec9c8115ff9ddbd32bb5fdd457ae9904043c966` (version 0.1.0). The release commit
`c6eaa706866b9868cb51048d64b3d21752abce44` ("mhfe-core 0.1.0", tag `v0.1.0`), from which
mhfe-core 0.1.0 was published on 2026-10-27, holds the fixes and keeps version 0.1.0 by the owner's
decision; it replaced `dec9c81` on `main`, after three earlier release commits of the same day
(`4296f06`, `bc173a7` and `2cfaa22`) that were replaced before publication. Its tests read the
specification's vectors from the submodule `tests/spec`. This folder and the record are not in the
release commit: they stand untracked over it until they are committed. The folders `verify/` and
`verify2/` check the fixes.

Each harness checks one claim and exits 0 when the claim holds, 1 when it fails and 2 when it cannot
decide (a wrong argument, a tool that failed, an input it does not recognise). A harness written to
reproduce a finding therefore exits 1 at the reviewed commit. Each one uses public inputs only, and
none runs full-size Argon2id. The repository's gates leave `docs/audits/` out. Raw logs stay in the
local folder `docs/audits/AUD-002-evidence/` (local), which git ignores; this file and the report
quote what a reader needs.

The harnesses were rewritten in Rust on 2026-10-27 at the owner's decision (TOOL-01: a Rust
repository's scripts, gates and harnesses are Rust, and it uses no Node.js). Each folder is a Rust
crate of its own, with its own `Cargo.lock` and outside the repository's workspace; `build/`,
`api/` and `verify/` hold one subcommand per check. Python stays only for the independent protocol
reference (`protocol/mhfe_ref.py` and the three scripts that compare the crate with it), and shell
only as the thin wrapper `protocol/run.sh`. The scripts the review ran are archived, with their
SHA-256, in `docs/audits/AUD-002-evidence/original-harnesses` (local) and
`original-harnesses.SHA256SUMS` (local). Each folder's README says what changed from its script;
on the same inputs the Rust harnesses give the scripts' verdicts.

## What you need

- Linux on x86-64; `isolation-probe` also runs on AArch64. The audit used Linux 7.0.0-38 with
  Landlock ABI 8, secret memory and unprivileged user namespaces.
- Git, and the Rust toolchain of `rust-toolchain.toml` (1.99.1) with its registry cache: every
  crate builds offline with `--locked` at both commits. `build republished-version` and
  `skeptic-bld-republish/` run `cargo +1.99.1`, so they need rustup.
- Python 3.11 or later with its standard library only, for `protocol/` alone.
- No Node.js, anywhere. The three harnesses that ran the checked-out tree's own gate, a Node.js
  script at `dec9c81`, no longer run it: `api/copies-with-tests` compiles the release tree's
  `cargo xtask copies` code and scans any tree with it, and `skeptic-bld-gate/` and
  `verify gate-skip` exit 2 at `dec9c81`, naming the archived run in which the record reproduced
  the finding with that gate. At the release commit they run `cargo xtask`.
- At the published release commit, its submodule `tests/spec` (clone with `--recurse-submodules`).
  `build windows-features-needed`, `build macos-clippy-gap` and `verify macos-lint` build its test
  targets in clones of their own, into which they check out each submodule from the clone they run
  in, offline.
- For the cross checks, the targets `x86_64-pc-windows-gnu`, `aarch64-apple-darwin` and
  `aarch64-apple-ios`, and a stand-in C compiler (below).
- For `protocol/`: a checkout of the specification repository `mhfe_spec` at version 0.7.0
  (commit `6f7537e8c268e010c710a889175e353ec02f66e1`), the BIP39 English word list (SHA-256
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`) and `UnicodeData.txt` of
  Unicode 18.0.0 (SHA-256 `0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950`).
- For the `withdrawn-release` check of `docs/`: the withdrawn `mhfe-core-0.1.0.crate`, SHA-256
  `bc23d4d1dcdbdcef54100eb9a04cd6634ca37898ea1098e4385505724906269d`, which crates.io served from
  2026-10-25 until it was deleted and which Cargo's cache no longer holds. Without it that check
  prints `SKIP`.
- The network, read-only, for `skeptic-doc-pvr/` (`gh`), `build vendored-upstream` (`gh` and
  `curl`), `build lockfile-provenance --online` (`curl`), for cloning the published release commit
  with its submodule, and for saving the CI log that
  `skeptic-build-cidup/` reads (`gh`).

The stand-in C compiler writes an empty file wherever `-o` or `-Fo<path>` points and exits 0, so
that a cross check covers the Rust code without a cross C toolchain. It also appends its arguments
to `stubcc.log` in its own folder. The audit used this script:

```sh
#!/usr/bin/env bash
# Stand-in C compiler: writes an empty object file wherever -o or -Fo points, so that a cross check
# of the Rust code needs no cross C toolchain.
echo "$@" >> "$(dirname "$0")/stubcc.log"
out=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  case "$arg" in -Fo*) out="${arg#-Fo}";; esac
  case "$arg" in --version|-v|-E|-dM) exit 0;; esac
  prev="$arg"
done
if [ -n "$out" ]; then : > "$out"; fi
exit 0
```

## Running them

Run every command from the root of a clone, with this folder copied into its `docs/audits/`.
`<work>` is a scratch folder outside the repository, which a harness may replace; `<stubcc>` is the
stand-in C compiler; `<target>` is a Cargo target folder outside the repository; `<commit>` is the
commit checked, `dec9c8115ff9ddbd32bb5fdd457ae9904043c966` or
`c6eaa706866b9868cb51048d64b3d21752abce44`.

At the reviewed commit, which `main` no longer holds, fetch it by its hash:

```sh
git clone https://github.com/hobby-eng/mhfe_core <clone>
git -C <clone> fetch origin dec9c8115ff9ddbd32bb5fdd457ae9904043c966
git -C <clone> checkout --detach dec9c8115ff9ddbd32bb5fdd457ae9904043c966
mkdir -p <clone>/docs/audits
cp -R docs/audits/AUD-002-harnesses <clone>/docs/audits/
```

At the release commit, the same with `git clone --recurse-submodules`,
`git -C <clone> checkout --detach v0.1.0` and no fetch. The release commit has no `docs/audits/`
folder, hence the `mkdir`. `skeptic-doc-wer/` without an
argument reads `dec9c81`, so a clone that does not hold it gives exit 2 there.

The crates run with `cargo run` build themselves. Build each other crate once, with `<folder>` one
of `security`, `api`, `api/copies-with-tests`, `skeptic-sec-nfkd`, `skeptic-fun-nfkd`,
`skeptic-api-nfkd`, `skeptic-api-trunc`, `skeptic-api-stack`, `skeptic-bld-republish`,
`skeptic-bld-gate`, `skeptic-build-cidup`, `skeptic-arc-unsafe`, `verify`, `verify/nfkd-shapes`,
`verify2` and `record`:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/<folder>/Cargo.toml
```

The audit ran every command through a memory guard that pauses a command when the machine runs
short of memory; that is optional. The timing checks compare medians of short runs and want an
otherwise idle machine. `protocol/run.sh` runs Python with `-B`, so it writes no `__pycache__`.

## What each harness checks

The finding IDs are those of the report. Each folder's README gives the details, its inputs and
its output. The evidence names are the logs of the reruns of 2026-10-27, at `dec9c81` and at the
release commit (see the last sections); each has a command record of the same name ending in
`.command.json`. "The release commit" in the tables is the published commit `c6eaa70` for the
harnesses whose inputs it changed, which ran again there, and `2cfaa22` for the others, whose
inputs `c6eaa70` leaves as they were; the report's rerun table names the commit of each run and
why.

### Review harnesses

| Harness | Checks | Command | Exit at `dec9c81` | Exit at the release commit | Evidence |
| --- | --- | --- | --- | --- | --- |
| `security/` `isolation-probe` | CHECK-SEC-002, 003, 005: after `Isolation::enter()` in a one-thread process, every protection read back from the kernel. See [security/README.md](security/README.md). | `<target>/release/isolation-probe` | 0: 22 `PASS` lines, `0 failed` | 0: the same (`2cfaa22`) | `rerun-dec9c81-isolation-probe.log` (local), `rerun-release-isolation-probe.log` (local) |
| `security/` `input-bounds` | CHECK-SEC-007: time growth of `Seed::derive` and `draw` with a passphrase of combining marks; refusal time of 64 MiB inputs; worst `Repaired::of` search. | `<target>/release/input-bounds` | 1: the two combining-marks checks grow about 4 per doubling (AUD-002-SEC001) | 0: every check passes (`2cfaa22`) | `rerun-dec9c81-input-bounds.log` (local), `rerun-release-input-bounds.log` (local) |
| `protocol/run.sh` | CHECK-FUN-001, FUN-006, API-004: vector replays, Unicode 18 NFKD of every scalar value, a differential against `mhfe_ref.py`, and the adapter's `nfkd-cost`. See [protocol/README.md](protocol/README.md). | `CARGO_TARGET_DIR=<target> CARGO_NET_OFFLINE=true docs/audits/AUD-002-harnesses/protocol/run.sh <mhfe_spec> <english.txt> <UnicodeData.txt>` | 1: three scripts match, `nfkd-cost` ends `FAILED` (AUD-002-SEC001) | 0: three scripts match, `nfkd-cost` grows at most n log n (`2cfaa22`) | `rerun-dec9c81-protocol-run.log` (local), `rerun-release-protocol-run.log` (local) |
| `api` `public-surface` | CHECK-API-003: the 22 public items, hidden `Debug` and no `Display` on secret types, error traits, no dependency type in a signature, `Send` and `Sync`. See [api/README.md](api/README.md). | `RUSTC_BOOTSTRAP=1 RUSTDOCFLAGS="-Z unstable-options --output-format json" CARGO_TARGET_DIR=<target> cargo doc --locked --offline --no-deps`, then `<target>/release/aud002-api public-surface <target>/doc/mhfe_core.json docs/public-api.txt` | 0: `passed` | 0: the same bytes (`2cfaa22`) | `rerun-dec9c81-api-public-surface.log` (local), `rerun-release-api-public-surface.log` (local) |
| `api` `truncation` | CHECK-API-001: `NativeArgon2::argon2id` with a password of 2^32 + 1 bytes. | `<target>/release/aud002-api truncation` | 1: `Ok(())` and the tag of the 1-byte password (AUD-002-API001) | 0: `Err(Argon2Failed { code: -5 })` (`2cfaa22`) | `rerun-dec9c81-api-truncation.log` (local), `rerun-release-api-truncation.log` (local) |
| `api` `stack-floor` | CHECK-API-003: the smallest thread stack on which six public functions complete. | `<target>/release/aud002-api stack-floor` | 1: 136 KiB for each function (AUD-002-API002) | 1: the same; the release documents it (`2cfaa22`) | `rerun-dec9c81-api-stack-floor.log` (local), `rerun-release-api-stack-floor.log` (local) |
| `api` `nfkd` | CHECK-API-001: `Seed::derive` time as a run of U+0301 doubles. | `<target>/release/aud002-api nfkd` | 1: about 3 to 4 per doubling (AUD-002-SEC001) | 0: a few milliseconds each (`2cfaa22`) | `rerun-dec9c81-api-nfkd.log` (local), `rerun-release-api-nfkd.log` (local) |
| `api` `copies-with-tests` | CHECK-ARC-002: the copies gate with `tests/` read too. | `<target>/release/aud002-api-copies-with-tests . <work>` | 1: three copies, an observation, as the review's Node.js gate found them | 1: the same three, at moved lines (`c6eaa70`) | `rerun-dec9c81-api-copies-with-tests.log` (local), `rerun-release-api-copies-with-tests.log` (local) |
| `build` `package-reproducible` | CHECK-BLD-004: two clones give byte-identical `.crate` files equal to the commit's blobs. See [build/README.md](build/README.md) for every build harness. | `cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- package-reproducible . <commit> <work>` | 0: SHA-256 `2d43ab36…`, 62 files | 0: SHA-256 `d44e15ab…`, the published package, 63 files (`c6eaa70`) | `rerun-dec9c81-package-reproducible.log` (local), `rerun-release-package-reproducible.log` (local) |
| `build` `release-tag-step` | CHECK-BLD-005: the tag and notes step of `release.yml`. | `cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- release-tag-step . <commit> <work>` | 0: `v0.1.0` passes with 30 lines of notes; two refusals | 0: the same with 29 lines (`c6eaa70`) | `rerun-dec9c81-release-tag-step.log` (local), `rerun-release-release-tag-step.log` (local) |
| `build` `lockfile-provenance` | CHECK-BLD-003: every `Cargo.lock` checksum against the cached `.crate`; with `--online`, against the crates.io index and, where the tree has one, `pnpm-lock.yaml` against npm. | `cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- lockfile-provenance .` (add `--online` for the registries) | 0: 40 of 40 crates; online also 16 of 16 npm integrities | 0: 40 of 40 crates; no `pnpm-lock.yaml` (`2cfaa22`) | `rerun-dec9c81-lockfile-provenance-offline.log` (local), `rerun-dec9c81-lockfile-provenance-online.log` (local), `rerun-release-lockfile-provenance-offline.log` (local), `rerun-release-lockfile-provenance-online.log` (local) |
| `build` `vendored-upstream` | CHECK-BLD-003: the vendored Argon2 tree, EFF list and `NormalizationTest.txt` against upstream (network). | `cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- vendored-upstream . <work>` | 0: 22 Argon2 files and both downloads match | 0: the same (`2cfaa22`) | `rerun-dec9c81-vendored-upstream.log` (local), `rerun-release-vendored-upstream.log` (local) |
| `build` `windows-features-needed` | CHECK-BLD-001: every `windows-sys` feature is needed. | `cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- windows-features-needed . <commit> <stubcc> <work>` | 0: 11 features needed | 0: the same (`c6eaa70`) | `rerun-dec9c81-windows-features-needed.log` (local), `rerun-release-windows-features-needed.log` (local) |
| `build` `macos-clippy-gap` | CHECK-BLD-002: plants two Clippy violations in `mod macos` and requires a CI command to refuse them. | `cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- macos-clippy-gap . <commit> <stubcc> <work>` | 1: only the control refuses (AUD-002-BLD002) | 0: the ios job's host lint refuses (`c6eaa70`) | `rerun-dec9c81-macos-clippy-gap.log` (local), `rerun-release-macos-clippy-gap.log` (local) |
| `build` `republished-version` | CHECK-BLD-005: a local registry on 127.0.0.1 serves other bytes as a withdrawn version; `cargo update -p` and later builds must get the new code. | `cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- republished-version <work>` | 1: `cargo update -p` refused, both consumers run the withdrawn code (AUD-002-BLD001) | 1: the same; Cargo's behaviour, which the owner accepted (`2cfaa22`) | `rerun-dec9c81-republished-version.log` (local), `rerun-release-republished-version.log` (local) |
| `docs/` (doc-claims) | CHECK-DOC-001, DOC-003: no tracked file names an audit record; the Windows core-dump wording; the withdrawn-release paragraph. See [docs/README.md](docs/README.md). | `CARGO_TARGET_DIR=<target> cargo run --locked --offline --manifest-path docs/audits/AUD-002-harnesses/docs/Cargo.toml -- <mhfe-core-0.1.0.crate>` | 1: `audit-references` passes, three checks fail (AUD-002-DOC001, DOC002) | 1: only `withdrawn-release` fails (AUD-002-DOC001, accepted) (`c6eaa70`) | `rerun-dec9c81-doc-claims.log` (local), `rerun-release-doc-claims.log` (local) |

### Challenge harnesses

Each finding was challenged by a reviewer who had not reported it, with a harness of their own.
Two reported findings were withdrawn this way; their harnesses stay as the evidence.

| Harness | Checks | Command | Exit at `dec9c81` | Exit at the release commit | Evidence |
| --- | --- | --- | --- | --- | --- |
| `skeptic-sec-nfkd/` | AUD-002-SEC001: seeds equal BIP39's seed of the reference NFKD; `Seed::derive` growth for ASCII, `nfkd()`, an in-order run and an out-of-order run (16 to 128 KiB). See [its README](skeptic-sec-nfkd/README.md). | `<target>/release/aud002-skeptic-sec-nfkd` | 1: both combining-marks lines fail | 0: every line passes (`2cfaa22`) | `rerun-dec9c81-skeptic-sec-nfkd.log` (local), `rerun-release-skeptic-sec-nfkd.log` (local) |
| `skeptic-fun-nfkd/` | AUD-002-SEC001: one run of one class and of two classes, `draw` cancelled at once, stream-safe runs as a control (20 to 160 KB). | `<target>/release/aud002-skeptic-fun-nfkd` | 1: the three single-run cases fail | 0: every line passes (`2cfaa22`) | `rerun-dec9c81-skeptic-fun-nfkd.log` (local), `rerun-release-skeptic-fun-nfkd.log` (local) |
| `skeptic-api-nfkd/` | AUD-002-SEC001: the cost comes from the length of one run, not of the passphrase. | `<target>/release/aud002-skeptic-api-nfkd` | 1: the control passes, one run fails | 0: every line passes (`2cfaa22`) | `rerun-dec9c81-skeptic-api-nfkd.log` (local), `rerun-release-skeptic-api-nfkd.log` (local) |
| `skeptic-api-trunc/` | AUD-002-API001: a password of exactly 2^32 bytes, after a control of 2,000 bytes. | `<target>/release/aud002-skeptic-trunc` | 1: `Ok(())` with the tag of the empty password | 0: `Err(Argon2Failed { code: -5 })` (`2cfaa22`) | `rerun-dec9c81-skeptic-api-trunc.log` (local), `rerun-release-skeptic-api-trunc.log` (local) |
| `skeptic-api-stack/` | AUD-002-API002: `Phrase::read_word` on 128 KiB std and `pthread_create` threads, with controls. See [its README](skeptic-api-stack/README.md). | `<target>/release/aud002-skeptic-api-stack` | 1: `read_word` on 128 KiB fails, the controls complete | 1: the same bytes; the release documents the need (`2cfaa22`) | `rerun-dec9c81-skeptic-api-stack.log` (local), `rerun-release-skeptic-api-stack.log` (local) |
| `skeptic-bld-republish/` | AUD-002-BLD001: which cache makes the old code run (plain `cargo update`, extracted source, cached `.crate`, target folder). | `<target>/release/aud002-skeptic-bld-republish <work>` | 1: only deleting the cached `.crate` and the target folder gives the new code | 1: the same bytes; accepted (`2cfaa22`) | `rerun-dec9c81-skeptic-bld-republish.log` (local), `rerun-release-skeptic-bld-republish.log` (local) |
| `skeptic-bld-gate/` | AUD-002-BLD003: the commit's code-rules gate in five states, including with the one-line fix. | `<target>/release/aud002-skeptic-bld-gate . docs/audits/AUD-002-harnesses <work>` | 2: no gate runs, since the commit's gate is a Node.js script; the archived run, every state as the finding states, is the reproduction | 1: the xtask gate holds the fix, so the finding no longer holds (`c6eaa70`) | `rerun-dec9c81-skeptic-bld-gate.log` (local), `rerun-release-skeptic-bld-gate.log` (local) |
| `skeptic-build-cidup/` | AUD-002-ARC001: a fast check of the checks job run again by another job on the same runner. | `<target>/release/aud002-skeptic-build-cidup . <commit> [<run log>]` | 1: `repeated commands: 2`, with the log of run 40492969676 | 0: `repeated commands: 0`, without a run log and with the log of run 40562937779 (`c6eaa70`) | `rerun-dec9c81-skeptic-build-cidup.log` (local), `rerun-release-skeptic-build-cidup.log` (local), `rerun-release-skeptic-build-cidup-with-log.log` (local) |
| `skeptic-doc-withdrawn/` | AUD-002-DOC001: consumers written for the withdrawn 0.1.0 (a feature, two items) against this checkout. | `CARGO_TARGET_DIR=<target> cargo run --locked --offline --manifest-path docs/audits/AUD-002-harnesses/skeptic-doc-withdrawn/Cargo.toml -- <work>` | 1: both consumers break, the notes do not say so | 1: the same; accepted (`c6eaa70`) | `rerun-dec9c81-old-consumer.log` (local), `rerun-release-old-consumer.log` (local) |
| `skeptic-doc-wer/` | AUD-002-DOC002: the Windows error-report claims, read from a commit with `git show`. See [its README](skeptic-doc-wer/README.md). | `CARGO_TARGET_DIR=<target> cargo run --locked --offline --manifest-path docs/audits/AUD-002-harnesses/skeptic-doc-wer/Cargo.toml -- [commit]` | 1: five `FAIL` lines | 1 without an argument (it reads `dec9c81`; `2cfaa22`); 0 given the release commit (`c6eaa70`) | `rerun-dec9c81-wer-claims.log` (local), `rerun-release-wer-claims.log` (local), `rerun-release-wer-claims-release.log` (local) |
| `skeptic-arc-unsafe/` | Withdrawn report "lib.rs repeats the manifest's unsafe_code lint": `cargo check` four ways. | `<target>/release/aud002-skeptic-arc-unsafe . <commit> <work>` | 0: A, B and C refused, D accepted | 0: the same bytes (`HEAD` as the commit) (`2cfaa22`) | `rerun-dec9c81-skeptic-arc-unsafe.log` (local), `rerun-release-skeptic-arc-unsafe.log` (local) |
| `skeptic-doc-pvr/` | Withdrawn report on the private reporting channel: fails when `SECURITY.md` names GitHub's security advisories while private vulnerability reporting is off (network). | `CARGO_TARGET_DIR=<target> cargo run --locked --offline --manifest-path docs/audits/AUD-002-harnesses/skeptic-doc-pvr/Cargo.toml` | 0: `PASS: visibility=public pvr=true` | 0: the same (`2cfaa22`) | `rerun-dec9c81-pvr-check.log` (local), `rerun-release-pvr-check.log` (local) |

### Verification harnesses

The first verification rounds ran these, as scripts, on the uncommitted fixed tree of version 0.2.0.
They now run at both commits: at `dec9c81` they reproduce the findings, at the release commit they
check the fixes as the release settles them. See [verify/README.md](verify/README.md).

| Harness | Checks | Command | Exit at `dec9c81` | Exit at the release commit | Evidence |
| --- | --- | --- | --- | --- | --- |
| `verify/nfkd-shapes/` | AUD-002-SEC001: five passphrase shapes give BIP39's seed of the reference NFKD; three must grow at most 3 times per doubling, two are printed as `INFO`. See [its README](verify/nfkd-shapes/README.md). | `<target>/release/aud002-verify-nfkd-shapes` | 1: the two in-order shapes fail | 0: every shape linear (`2cfaa22`) | `rerun-dec9c81-verify-nfkd-shapes.log` (local), `rerun-release-verify-nfkd-shapes.log` (local) |
| `verify` `gate-skip` | AUD-002-BLD003: with the audit folder present the tree's code-rules gate passes; a probe under `docs/audits/` passes; under `tests/` and elsewhere in `docs/` it is refused. | `CARGO_TARGET_DIR=<target> <target>/release/aud002-verify gate-skip . <work>/gate-skip` | 2: no gate runs, since the commit's gate is a Node.js script; the archived run reproduced the finding | 0: four `PASS` lines (`c6eaa70`) | `rerun-dec9c81-verify-gate-skip.log` (local), `rerun-release-verify-gate-skip.log` (local) |
| `verify` `macos-lint` | AUD-002-BLD002: the ios job lints its macOS host; that command passes and refuses the two planted violations. | `CARGO_TARGET_DIR=<target> <target>/release/aud002-verify macos-lint . <stubcc> <work>/macos-lint` | 1: the ios job has no host lint | 0: five `PASS` lines (`c6eaa70`) | `rerun-dec9c81-verify-macos-lint.log` (local), `rerun-release-verify-macos-lint.log` (local) |
| `verify` `version` | AUD-002-BLD001, DOC001 as the release settles them: one version, the release notes, no cleanup advice. | `<target>/release/aud002-verify version .` | 1: the CHANGELOG advises `cargo update -p` | 0: three `PASS` lines (`c6eaa70`) | `rerun-dec9c81-verify-version.log` (local), `rerun-release-verify-version.log` (local) |
| `verify2/` | The second verification round: no file outside `docs/audits/` changed after a reference file, and no untracked file outside it. See [verify2/README.md](verify2/README.md). | `<target>/release/aud002-verify2-tree-unchanged . <reference>` | 0: unchanged after the setup | 0: unchanged after the harnesses ran (`c6eaa70`) | `rerun-dec9c81-verify2-tree-unchanged.log` (local), `rerun-release-verify2-tree-unchanged.log` (local) |

### Record check

`record/` checks the record itself before it is committed: the JSON twin validates against the
workspace's `audit-report.schema.json` with no duplicate keys; both records agree on every finding
and on the metadata; finding IDs are unique and numbered per category in order; every link of the
committed audit Markdown files resolves to a file git does not ignore; every reference to the local
evidence folder is marked "(local)", or `"local": true` in the JSON; every cited log exists and has
the cited SHA-256; the audit files hold no login name or home folder of the machine, no time
outside UTC and no non-English script; and git has no evidence file staged and ignores the
evidence folder. See [record/README.md](record/README.md).

| Harness | Checks | Command | Exit at `dec9c81` | Exit at the release commit | Evidence |
| --- | --- | --- | --- | --- | --- |
| `record/` | The ten checks above, on the record in the repository that runs it. | `<target>/release/aud002-validate-record <multi-chain-wallet-tools>/docs/audit-report.schema.json [<result.json>]` | 2: a clone of `dec9c81` holds no record | 0 with the final record over the release commit `c6eaa70`; it failed on earlier versions of the record | `rerun-dec9c81-validate-record.log` (local), `rerun-release-validate-record.log` (local), `report-validation.json` (local) |

It prints `PASS` or `FAIL` per check and `<n> of 10 checks pass`. The validation of the final
record is `report-validation.json` (local).

## The run of this record

This is the run that the first version of the record made, before the rewrite in Rust. The names
are those of the scripts, which `docs/audits/AUD-002-evidence/original-harnesses` (local) keeps.

On 2026-10-27, from 12:33 to 12:57 UTC, every harness but one ran once: the review and
challenge harnesses in a clean clone at `dec9c81` with this folder copied in, and the verification
harnesses on the uncommitted fixed tree (working-tree diff against `dec9c81` with SHA-256
`8d626d4acd8fe5ae7fbb440b5ac24ddc707624f1ec438b3f4aa1300c379df061`). Every exit code is the one
expected then. The machine was busy with other work (load average 7 to 14 on 16 threads), so the
timings of that run are slower and noisier than the reviewers' and should not be compared with
them; the pass or fail outcomes are the same.

- `isolation-probe` printed the same bytes as the security reviewer's run (log SHA-256
  `922b1de495bf785317c9a9ba9602ed5d245c0c30c7281d806694622dd34afcb8`): 22 `PASS` lines and
  `0 failed`. The reviewer's summary had counted 23.
- `build/vendored-upstream.sh` was not rerun, because it downloads two files from the network; the
  build reviewer's run of 2026-10-27 exited 0. `lockfile-provenance.mjs` ran offline only; its
  `--online` run by the build reviewer exited 0.
- `verify2/tree-unchanged.sh` ran last of the harnesses, at 12:56:59 UTC: no file outside
  `docs/audits/` had changed since the first verification round, and the working-tree diff still
  had that SHA-256.

Each run's log and command record are in the local evidence folder as `record-<name>.log` and
`record-<name>.command.json` (local); the report lists their SHA-256. After the first version of
the report was written, the then-Python `record/validate-record.py` checked it at 13:12 UTC, ten
checks passing.

## The reruns of 2026-10-27

- At `dec9c81`, from 14:31 to 14:51 UTC: each Rust harness, just rewritten, ran once in a clean
  clone at `dec9c81` with this folder copied in, on a busy machine (load average about 10 to 15).
  Every exit code is the one in the tables above. Logs and command records are
  `rerun-dec9c81-<harness>.log` and `.command.json` in the local evidence folder (local), the
  builds as `rerun-dec9c81-<name>-build.log` (local). The verdicts are those of the scripts, with
  two differences the report names: the `Seed::derive` line of `skeptic-api-nfkd/` passed on the
  busy machine in both attempts, while its `draw` line still failed; and `build macos-clippy-gap`
  names the ios command by its target. The record check, with no record in the clone, exited 2.
- From 16:39 to 16:43 UTC, at `dec9c81`: `api/copies-with-tests`, `skeptic-bld-gate/` and
  `verify gate-skip` ran again without Node.js; their records replaced the runs with the Node.js
  gate, as the tables above give them.
- At the first release commit `4296f068ca1cc2b5f4e9d8c631586ce9cf687984`, from 14:59 to 15:31 UTC,
  and at the release commit `2cfaa229fbe0fb046ecdb2d45291b380da4a12bf`, from 17:03 to 17:11 UTC:
  each harness ran once in a clean clone at that commit with this folder copied in, the runs at
  `2cfaa22` replacing those at `4296f06`. At `2cfaa22` `build package-reproducible` first failed on
  its own defect, the reviewed include list held in its code, and was fixed. Both commits were
  replaced before publication.
- At the published release commit `c6eaa706866b9868cb51048d64b3d21752abce44`, from 20:05 to 20:17
  UTC, on an idle machine: the harnesses whose inputs its change to `2cfaa22` touched ran again, in
  a clone made from GitHub with `--recurse-submodules` with this folder copied in, each run
  replacing the one at `2cfaa22`: `build` package-reproducible, release-tag-step,
  windows-features-needed and macos-clippy-gap, `docs/`, `skeptic-doc-wer/` given the commit,
  `skeptic-doc-withdrawn/`, `skeptic-bld-gate/`, `skeptic-build-cidup/`, `api/copies-with-tests`,
  the three `verify` subcommands and `verify2/`, and the record check, in the repository. Every
  other harness builds the library alone, whose code that change keeps (it touches only
  `#[cfg(test)]` modules of `src/`), or reads files it keeps, so its run at `2cfaa22` stands.
  Four harnesses did not handle the submodule at first: `build windows-features-needed` and
  `verify macos-lint` cloned the commit without it, so its test targets did not build;
  `build macos-clippy-gap` did the same and counted the build failures as refusals, a false pass;
  `docs/` read the submodule's entry as a file. Their first attempts are kept as
  `rerun-release-<harness>-attempt1.log` (local); the fixes are in the next section.
  `skeptic-build-cidup/` first ran without a run log, since `gh` 2.46 prints nothing for that run's
  log archive; with `gh` 2.102.0, whose log names no steps, it ran again with the log after the
  harness learnt to read such a log, and gave the same verdict.

Logs and command records are `rerun-release-<harness>.log` and `.command.json` in the local
evidence folder (local). The final record's check is `report-validation.json` (local).

The report lists every log with its exit code and SHA-256.

## Changes after the review

Two edits were made to this folder after the harnesses ran in review, before the first version of
the record was written:

- `skeptic-doc-pvr/check-pvr.sh` took the repository from a default path that held the machine
  owner's username. Its default is now the repository that contains the script. Nothing else in the
  script changed.
- `protocol/__pycache__/`, which Python wrote while the protocol reviewer ran the scripts, was
  deleted.

On 2026-10-27, after that record, every harness was rewritten in Rust as described at the top, and
the confirmed findings of the final review of the harnesses (H1 to H22 but H8 and H16, which were
refuted) were addressed by the rewrite; each folder's README names its changes.

Later on 2026-10-27, at the release commits:

- At `2cfaa22`, `build package-reproducible` reads the include list from the commit's manifest
  instead of holding the reviewed list in its code; its log at `dec9c81` is unchanged.
- At `c6eaa70`, whose tests read the submodule `tests/spec`: `build windows-features-needed`,
  `build macos-clippy-gap` and `verify macos-lint` check out each submodule of their clones from
  the repository they run in, offline, as CI checks out with `submodules: true`;
  `build macos-clippy-gap` stops with exit 2 when a command fails without a Clippy lint, so that a
  tree that does not build is no longer counted as a refusal; `docs/` leaves `tests/spec` out of
  `audit-references`, as the code-rules gate does. At `dec9c81` and `2cfaa22`, which have no
  submodule and whose failing commands name their lints, the changed code does nothing.
