# AUD-002 build harnesses

The build checks of audit AUD-002 of mhfe-core 0.1.0, which reviewed commit
`dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. They are one Rust crate, `aud002-build`, with one
subcommand per check. Each exits 0 when every check holds, 1 when one fails, and 2 when it cannot
decide (a wrong argument, a tool that failed, an input it does not recognise).

The harnesses were rewritten in Rust from the archived scripts on 2026-10-27 at the owner's decision
(TOOL-01). The scripts as the build reviewer wrote and ran them are kept, with their SHA-256, in the
folder `build/` of the archive `original-harnesses` (local); on the same inputs the Rust harnesses
print the same lines, except where this file says otherwise.

## Building and running

From the repository root:

```sh
cargo build --locked --offline --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml
cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- <harness> <arguments>
```

The crate has its own `Cargo.lock`, does not depend on mhfe-core, and is outside the repository's
workspace (the root manifest is a plain package at `dec9c81`, and leaves `docs/audits` out of its
workspace at the release commit), so `--locked` holds at both commits. Its two dependencies, sha2
0.11.1 and serde_json 1.0.154, are versions of mhfe-core's own lockfile, so the registry cache of a
build of mhfe-core serves them offline.

`<work>` is a folder outside the repository, where a harness replaces the subfolders it writes; set
`CARGO_TARGET_DIR` outside the repository too. `<commit>` is the commit to check: `dec9c81…` for the
review, or the release commit. The release commit keeps version 0.1.0 by the owner's decision; its
root manifest is a workspace with the member `xtask`, its gates are `cargo xtask` tasks, and it has
no Node.js. A harness reads what the checked-out tree holds, so each runs at both commits. The
published release commit `c6eaa70` reads the specification's vectors from the submodule
`tests/spec`, so clone it with `--recurse-submodules`: `windows-features-needed` and
`macos-clippy-gap` build its test targets in clones of their own, into which they check out each
submodule from the repository they run in, offline, as CI checks out with `submodules: true`.

The harnesses need git, tar and the Rust toolchain of `rust-toolchain.toml` (1.99.1) with its
registry cache. The cross checks also need the targets `x86_64-pc-windows-gnu`,
`aarch64-apple-darwin` and `aarch64-apple-ios`, and the stand-in C compiler of the top
[README](../README.md), which writes empty objects so that only the Rust code is checked.
`vendored-upstream` and `lockfile-provenance --online` read the network, read-only.

## package-reproducible

CHECK-BLD-004. Clones `<commit>` twice, sets every file and folder time of the second clone (but its
`.git`) to 2001-01-01T00:00:00Z, runs `cargo package --locked --offline --no-verify` in each, and
requires:

1. the two `.crate` files to be byte-identical;
2. every packaged file to be the commit's blob, `Cargo.toml.orig` the commit's `Cargo.toml`, and
   the package's `Cargo.lock` the commit's. At the release commit Cargo leaves the entry of the
   workspace member `xtask` out of the package's lockfile, so the harness compares without the
   entries of other workspace members and says so in one line;
3. the package's files to be the tracked files of the include list of the commit's `Cargo.toml`
   (at `dec9c81` `src`, `vendor`, `build.rs`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `README.md`,
   `CHANGELOG.md`, as ci.yml's package job lists them; the release commit has `LICENSE-MIT` and
   `LICENSE-APACHE` in place of `LICENSE`) plus Cargo's `.cargo_vcs_info.json`, `Cargo.lock`,
   `Cargo.toml` and `Cargo.toml.orig`.

```sh
cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- package-reproducible . <commit> <work>
```

At `dec9c81`: SHA-256 `2d43ab36ae3f70cb72c309a71ec2664ce07093c5a1bbab65e11a75dcba6ec393` for
`mhfe-core-0.1.0.crate`, 62 files, exit 0. At the release commit: the SHA-256 of its own package,
the line about `xtask`'s entry, 63 files (two licence files for one), exit 0. The archived script
held the reviewed include list in its code, and so did this harness until its first run at the
release commit, which reported both licence files as extra, exit 1; reading the list from the
commit's manifest lets the harness see the release's licences and leaves its `dec9c81` log as it
was, byte for byte.
The package holds nothing of `tests/`, so its clones need no submodule, as the release workflow's
draft job checks out none. Recorded at the published release commit `c6eaa70`: SHA-256
`d44e15ab9e3f25c1c787a0b10f6b8467441463dd57b137940a97a1deb390247d`, the published package, the
line about `xtask`'s entry, 63 files, exit 0, `rerun-release-package-reproducible.log` (local). At
the earlier release commit `2cfaa22` it was
`27d4037e2b93207738e5613ffdf4526bdb6c1f39b98eb812dc8b207c1986c9c9`, 63 files.

## release-tag-step

CHECK-BLD-005. Takes the `run: |` block of the step "Check the tag and write the release notes"
from `.github/workflows/release.yml` of a clone of `<commit>`, runs it offline as GitHub does
(`bash --noprofile --norc -eo pipefail`), and requires `v<version of Cargo.toml>` to pass with the
CHANGELOG section of that version as its notes, `v9.9.9` to be refused, and the right tag to be
refused once the CHANGELOG heading of the version is renamed.

```sh
cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- release-tag-step . <commit> <work>
```

At `dec9c81`: `v0.1.0 passes; notes: 30 lines`, both refusals, exit 0. At the release commit: the
same with the length of its 0.1.0 section, exit 0. Recorded at `c6eaa70`, whose CHANGELOG
changed: `v0.1.0 passes; notes: 29 lines`, both refusals, exit 0, the same bytes as at `2cfaa22`,
`rerun-release-release-tag-step.log` (local).

## lockfile-provenance

CHECK-BLD-003. Every `Cargo.lock` package but the workspace's own comes from crates.io with a
checksum equal to the SHA-256 of the `.crate` in Cargo's cache (`$CARGO_HOME/registry/cache`, by
default `$HOME/.cargo`). With `--online` (curl, read-only), the checksum also equals the crates.io
sparse index entry, which must not be yanked, and every integrity of `pnpm-lock.yaml`, where the
tree has one, equals the npm registry's.

```sh
cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- lockfile-provenance .
cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- lockfile-provenance . --online
```

At `dec9c81`: `41 packages, 40 from crates.io with a checksum`, 40 matching the cache, exit 0;
online also 40 matching the index and `16 of 16 integrities match npm`, exit 0. At the release
commit: 42 packages (with `xtask`), the same 40 crates, exit 0; online, `pnpm-lock.yaml: none in
this tree`. Recorded at `2cfaa22`: exit 0, `rerun-release-lockfile-provenance-offline.log` (local);
online exit 0, `rerun-release-lockfile-provenance-online.log` (local). The published release
commit `c6eaa70` keeps `Cargo.lock`, so both runs stand there.

## vendored-upstream

CHECK-BLD-003, over the network. Every file of `vendor/phc-winner-argon2/` has the Git blob ID of
the same path in upstream commit `f57e61e19229e23c4445b85494dbf7c07de721cb` (GitHub's tree API
through `gh api`), and the tree holds all of upstream's `include/`, `src/`, `LICENSE` and
`README.md`; `vendor/eff-large-wordlist/eff_large_wordlist.txt` and
`tests/fixtures/unicode18-ucd/NormalizationTest.txt` equal their downloads from eff.org and
unicode.org. The downloads, saved in `<work>`, are only compared and hashed.

```sh
cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- vendored-upstream . <work>
```

At `dec9c81` and at the release commit, whose vendored files are the same: 22 Argon2 files, EFF
SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`, Unicode SHA-256
`25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3`, exit 0. Recorded at
`2cfaa22`: exit 0, `rerun-release-vendored-upstream.log` (local). The published release commit
`c6eaa70` keeps `vendor/` and `tests/fixtures/unicode18-ucd/`, so this run stands there.

## windows-features-needed

CHECK-BLD-001. In a clone of `<commit>`, with its submodules checked out from the repository,
removes each `windows-sys` feature of
`[target.'cfg(windows)'.dependencies]` in turn and requires `cargo clippy --lib` for
`x86_64-pc-windows-gnu` to fail, and for the feature of the dev-dependency entry
`cargo clippy --all-targets`. A feature whose removal still builds is needed only when another
feature implies it and the code imports its own module; otherwise it is reported as not needed and
the harness fails.

```sh
cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- windows-features-needed . <commit> <stand-in C compiler> <work>
```

At `dec9c81` and at the release commit, which changes no feature: 11 features needed, two of them
implied (`Win32_Foundation`, `Win32_Security`), exit 0. Recorded at the published release commit
`c6eaa70`: exit 0, the same bytes as at `dec9c81`,
`rerun-release-windows-features-needed.log` (local). Its first run there cloned the commit without
the submodule, so the commit's test targets did not build and the harness stopped with exit 2:
`rerun-release-windows-features-needed-attempt1.log` (local).

## macos-clippy-gap

CHECK-BLD-002. In a clone of `<commit>`, with its submodules checked out from the repository,
plants an `unwrap()` and an unsafe block without its SAFETY
comment in the macOS-only `mod macos` of `src/os/apple.rs`, then runs, with the stand-in C
compiler, the CI commands that could see that code: the checks job's Clippy on its Linux host,
each `cargo clippy` line of the ios job read from the commit's `ci.yml` (for `$TARGET`, or for the
job's `aarch64-apple-darwin` host when the line has no `--target`), and the compile part of the
native job's macOS test (`cargo check --all-targets` for `aarch64-apple-darwin` with
`RUSTFLAGS=-D warnings`). The control, Clippy for `aarch64-apple-darwin`, must refuse the plants.
The harness passes when a CI command refuses them. A command that fails without naming a Clippy
lint failed for another reason than the plants, such as a tree that does not build; the harness
then stops with exit 2.

```sh
cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- macos-clippy-gap . <commit> <stand-in C compiler> <work>
```

At `dec9c81`: `checks`, `ios-aarch64-apple-ios` and `native-macos` pass, only the control refuses
(`clippy::undocumented-unsafe-blocks clippy::unwrap-used`), exit 1 (finding AUD-002-BLD002). At the
release commit the ios job also lints its macOS host, so `ios-aarch64-apple-darwin` refuses too and
the harness exits 0. The archived script named the ios command `ios` and hard-coded the reviewed
commands; reading them from `ci.yml` lets the harness see the fix. Recorded at the published
release commit `c6eaa70`, whose `ci.yml` and tests changed: exit 0, the same bytes as at `2cfaa22`,
`rerun-release-macos-clippy-gap.log` (local). Its first run there cloned the commit without the
submodule: the checks, ios-aarch64-apple-ios and native-macos commands failed to build, and the
harness counted those failures as refusals and exited 0, a false pass:
`rerun-release-macos-clippy-gap-attempt1.log` (local). Both fixes above come from that run.

## republished-version

CHECK-BLD-005, CHECK-DOC-002. Reads nothing of the repository. A local sparse registry on
127.0.0.1, served by the harness itself, with a fresh `CARGO_HOME` in `<work>`, serves a synthetic
crate `probe` 0.1.0 saying "withdrawn"; a consumer builds it, which fills Cargo's cache. The
registry then serves other bytes as `probe` 0.1.0, saying "republished". The harness requires
`cargo update -p probe` to succeed in the first consumer, the first consumer with its lockfile
renewed to run the republished code, and a new consumer on the same machine to run it too.

```sh
cargo run --locked --offline --quiet --manifest-path docs/audits/AUD-002-harnesses/build/Cargo.toml -- republished-version <work>
```

It needs `cargo +1.99.1`. At both commits: `cargo update -p probe` refused, both consumers run the
withdrawn code while their lockfiles record the new checksum, exit 1 (finding AUD-002-BLD001, which
the owner accepted: it shows Cargo's behaviour, which the release does not change). Recorded at
`2cfaa22`: exit 1, `rerun-release-republished-version.log` (local). It reads nothing of the
repository, so this run stands at the published release commit `c6eaa70`.

## Reruns at the reviewed commit

On 2026-10-27 each harness ran once in a clean clone at `dec9c81` with this folder copied into its
`docs/audits/`. Every exit code is the recorded one: package-reproducible, release-tag-step,
lockfile-provenance (offline and online), vendored-upstream and windows-features-needed 0;
macos-clippy-gap and republished-version 1. The logs are byte-identical to the scripts' logs but
for macos-clippy-gap's, which names the ios command by its target and drops a trailing space. Logs
and command records are in the local evidence folder as `rerun-dec9c81-<harness>.log` (local) and
`rerun-dec9c81-<harness>.command.json` (local).

## Reruns at the release commit

On 2026-10-27 each harness ran in a clean clone at the release commit
`2cfaa229fbe0fb046ecdb2d45291b380da4a12bf` with this folder copied into its `docs/audits/`. In the
first round every exit was the expected one but package-reproducible's, 1: its check 3 reported
`LICENSE-APACHE` and `LICENSE-MIT` as extra, since the harness held the reviewed include list in
its code: `rerun-release-package-reproducible-attempt1.log` (local). With the list read from the
commit's manifest, the crate was built again and every harness ran once more, each exit code the
one this file expects at the release commit. The fixed package-reproducible, run at `dec9c81`
without a record, printed `rerun-dec9c81-package-reproducible.log` (local) byte for byte. Those
runs replaced the records of the earlier release commit `4296f06`.

The published release commit `c6eaa706866b9868cb51048d64b3d21752abce44` then made the tests read
the specification's vectors from the submodule `tests/spec` and changed `ci.yml` and the
CHANGELOG. The harnesses whose inputs that change touched ran again there on 2026-10-27, in a
clone made with `--recurse-submodules` with this folder copied in, after the build of this crate
with the submodule fix, exit 0, `rerun-release-build-crate-build.log` (local): package-reproducible,
release-tag-step, windows-features-needed and macos-clippy-gap, each exit 0, with the first
attempts named above. lockfile-provenance (offline and online), vendored-upstream and
republished-version keep their runs at `2cfaa22`, for the reasons given in their sections. At
`dec9c81` and `2cfaa22`, which have no submodule and whose failing commands name their Clippy
lints, the fixes change nothing. Logs and command records are in the local evidence folder as
`rerun-release-<harness>.log` (local) and `rerun-release-<harness>.command.json` (local).
