# AUD-002 verify: gate, macOS lint and version

Verification harnesses of audit AUD-002 of mhfe-core, as one Rust crate, `aud002-verify`, with a
subcommand per check. The audit reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`
(version 0.1.0). Its fixes were verified on the uncommitted tree over that commit, then version
0.2.0; the release commit amends dec9c81, keeps version 0.1.0 by the owner's decision (AUD-002-BLD001
and DOC001 accepted, not fixed) and runs its gates as `cargo xtask` tasks instead of the scripts of
`scripts/`. Each subcommand runs at both commits and picks the tools the checked-out tree holds,
except that `gate-skip` does not run dec9c81's gate, a Node.js script (below). The folder
`nfkd-shapes/` is a crate of its own, with [its README](nfkd-shapes/README.md).

Each subcommand prints a `PASS` or `FAIL` line per check and exits 0 when every check passes, 1
when one fails and 2 when it cannot run. The harnesses use public inputs only; none runs Argon2id
or the network.

## Running

From the repository root, with `<target>` a Cargo target folder and `<work>` a scratch folder, both
outside the repository:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/verify/Cargo.toml
CARGO_TARGET_DIR=<target> <target>/release/aud002-verify gate-skip . <work>/gate-skip
CARGO_TARGET_DIR=<target> <target>/release/aud002-verify macos-lint . <stubcc> <work>/macos-lint
<target>/release/aud002-verify version .
```

`gate-skip` and `macos-lint` run Cargo themselves, offline, and `CARGO_TARGET_DIR` lets them share
the target folder. They need Git and the registry cache of the crate's dependencies, and
`macos-lint` the target `aarch64-apple-darwin` (`rustup target add aarch64-apple-darwin`) and the
stand-in C compiler `<stubcc>` that the top README describes. To check dec9c81 or the published
release commit `c6eaa706866b9868cb51048d64b3d21752abce44`, clone the repository (with
`--recurse-submodules` for the release commit, whose tests read the specification's vectors from
the submodule `tests/spec`), check out the commit, copy this audit's harness folder into the
clone's `docs/audits/` and run there with `.` naming the clone. At the published release commit
the crate builds with `--locked`, exit 0: `rerun-release-verify-build.log` (local).

## gate-skip: the code-rules gate and the audit folder

AUD-002-BLD003, "The code-rules gate reads audit records and harnesses under docs/audits/". It
clones the repository into `<work>/gate-clone`, applies the working tree's changes outside
`docs/audits/` (none at a commit), copies `docs/audits/` in, and runs the tree's code-rules gate,
`cargo xtask code-rules`. It checks that the gate passes with the audit folder present, that a lint
exception without a reason in `docs/audits/AUD-999-harnesses/probe/probe.rs` passes, and that the
same file as `tests/probe.rs` and as `docs/probe.rs` is refused with a line that names it.

A tree without `xtask/` whose gate is still `scripts/verify-code-rules.mjs`, a Node.js script, is
not checked: this repository runs no Node.js (TOOL-01), harnesses included. The subcommand then
exits 2 with one line that names the archived run in which the audit record reproduced the finding
at dec9c81 with that gate, `record-gate-reads-audits.log` (local), made by the original script of
`skeptic-bld-gate/`: the gate passed on the clean commit and refused a harness under
`docs/audits/`.

- At dec9c81: exit 2 with the line `ERROR the reviewed commit's code-rules gate is the Node.js
  script scripts/verify-code-rules.mjs, which this repository no longer runs (TOOL-01); the
  original reproduction of AUD-002-BLD003 is the archived evidence
  docs/audits/AUD-002-evidence/record-gate-reads-audits.log (local)`. Recorded on 2026-10-27:
  exit 2, `rerun-dec9c81-verify-gate-skip.log` (local), after the build, exit 0,
  `rerun-dec9c81-verify-gate-skip-build.log` (local). Run with Node.js before that day, the gate
  read `docs/audits/` and refused the harnesses' lint exceptions, so the first two checks failed
  and the two refusals passed; exit 1, the finding.
- At the published release commit `c6eaa706866b9868cb51048d64b3d21752abce44`, whose gate leaves
  the submodule `tests/spec` out too: four `PASS` lines, the gate holding in 73 files; exit 0.
  Recorded on 2026-10-27: exit 0, `rerun-release-verify-gate-skip.log` (local), after the crate's
  build, exit 0, `rerun-release-verify-build.log` (local). At the earlier release commit
  `2cfaa22` the gate held in 72 files.

## macos-lint: Clippy on the macOS-only code

AUD-002-BLD002, "No CI job runs Clippy on the macOS-only code". It checks that the `ios` job of
`.github/workflows/ci.yml` runs on `macos-latest`, an aarch64-apple-darwin host, and has the line
`cargo clippy --locked --all-targets -- -D warnings`. Then, in a clone made as `gate-skip` makes it,
with each submodule checked out from the repository's own checkout of it, offline (the release
commit's test targets read the specification's vectors from `tests/spec`), it runs that command
with `--target aarch64-apple-darwin` and the stand-in C compiler, which must pass, plants in `src/os/apple.rs` the finding's two violations (an `unwrap` and an unsafe block
without its SAFETY comment), and runs it again, which must fail naming `clippy::unwrap_used` and
`clippy::undocumented_unsafe_blocks`. The logs of both runs are `<work>/macos-lint/clean.log` and
`planted.log`.

- At dec9c81: the `ios` job has no host lint, so that check fails; the lint itself passes and
  refuses both violations; exit 1, the finding.
- At the published release commit `c6eaa70`, whose `ci.yml` and tests changed: five `PASS` lines;
  exit 0, `rerun-release-verify-macos-lint.log` (local). Its first run there cloned the commit
  without the submodule, so the clean host lint could not build the test targets and failed; exit
  1: `rerun-release-verify-macos-lint-attempt1.log` (local). The submodule step came from that
  run; at dec9c81, which has no submodule, it does nothing.

## version: one version and the release notes

AUD-002-BLD001 and DOC001 as the release settles them. The audit's fix was version 0.2.0 with a
CHANGELOG paragraph naming what differs from the withdrawn 0.1.0; the owner kept 0.1.0 instead, and
the CHANGELOG keeps one line: "It replaces an earlier 0.1.0 of this crate, which was withdrawn from
crates.io." So this checks what the release holds:

- `one-version`: the manifest, the lockfile's `mhfe-core` entry, the first CHANGELOG section and
  `cargo pkgid --locked --offline` all name 0.1.0.
- `release-notes`: `.github/workflows/release.yml` still selects the notes with its `awk` line, and
  that selection of the CHANGELOG for the `cargo pkgid` version has text.
- `no-cleanup-advice`: the CHANGELOG holds no `cargo update` advice, across line breaks too.

It also prints the CHANGELOG's paragraph on the withdrawn release. The original script's checks of
version 0.2.0 (a new version, the paragraph naming the differences, no other file naming 0.1.0, the
package's file list, no cached package of the new version) are gone with that version: the owner
accepted that a consumer's cache may still hold the withdrawn 0.1.0.

- At dec9c81: `one-version` and `release-notes` pass; `no-cleanup-advice` fails, since the
  CHANGELOG advises `cargo update -p mhfe-core`; exit 1.
- At the published release commit `c6eaa70`, whose CHANGELOG changed: three `PASS` lines; exit 0,
  `rerun-release-verify-version.log` (local).

## History

The three subcommands were rewritten in Rust on 2026-10-27, at the owner's decision (TOOL-01), from
the scripts `gate-skip.sh`, `macos-lint.sh` and `version.sh` of this folder, which the archive
`original-harnesses` (local) keeps. The rewrite fixes findings of the audit's final review: H3
(`git apply` refused the empty diff of a commit that holds the fix), H17 (the cache check passed
when it could not read the index; the check is gone with version 0.2.0) and H1 for `version`. On
the same day `gate-skip` stopped running dec9c81's Node.js gate, at the owner's decision that no
Node.js runs anywhere, harnesses included (TOOL-01).
