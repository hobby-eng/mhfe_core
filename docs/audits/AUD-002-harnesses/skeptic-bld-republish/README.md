# AUD-002 challenge harness: which cache keeps a withdrawn 0.1.0

Audit AUD-002 of mhfe-core 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It
challenges finding AUD-002-BLD001: publishing different bytes as version 0.1.0 makes Cargo build
the withdrawn 0.1.0 from its cache.

The program serves a local sparse registry over HTTP on 127.0.0.1 from `<work>/served`, publishes
a crate `probe` 0.1.0 whose constant says `withdrawn`, and builds a consumer of it with a fresh
`CARGO_HOME` (`<work>/cargo-home`). Then it publishes different bytes, saying `republished`, as the
same 0.1.0 and isolates which cache keeps the old code:

- a. with the old `Cargo.lock`, a plain `cargo update` (not only `-p`) is refused as well, and
  with the lockfile removed the consumer still runs the old code;
- b. removing only the extracted source re-extracts the cached `.crate`: still the old code;
- c. removing the extracted source and the cached `.crate` downloads the new bytes, which Cargo
  checks against the index, but the kept target folder still gives the old code; only removing the
  target folder as well gives the new code.

It reads no repository: the result is Cargo's behaviour, the same at every commit. Each build that
prints neither code stops the check.

## Commands

From the repository root, with `<target>` a build folder and `<work>` a scratch folder outside any
Cargo project:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-bld-republish/Cargo.toml
<target>/release/aud002-skeptic-bld-republish <work>
```

Inputs: none. The program needs the toolchain 1.99.1 through rustup (it runs `cargo +1.99.1`) and
uses no network beyond its own registry on 127.0.0.1. It removes and recreates `<work>/served`,
`<work>/cargo-home`, `<work>/probe-withdrawn`, `<work>/probe-republished` and `<work>/first`, and
nothing else under `<work>`. The caller's `CARGO_TARGET_DIR` is cleared for the Cargo runs it
starts, since the steps delete the consumer's own target folder.

## Output and exit code

The checksum of each package served, the code each build runs, the number of package downloads
after steps b and c, the checksum the final lockfile records, then
`FAIL: only deleting the cached .crate by hand gives the new 0.1.0` or
`PASS: a renewed lockfile gives the new code`. Exit 1 when the hazard holds (a renewed lockfile and
a re-extraction both still give the old code), 0 when it does not, 2 when the check could not run.

- At `dec9c81` and at the release commit: steps a to c as described, `FAIL`, exit 1. Recorded:
  exit 1. The release keeps version 0.1.0 by the owner's decision, which accepts AUD-002-BLD001,
  so the hazard stays. Recorded at `2cfaa22`: exit 1,
  `rerun-release-skeptic-bld-republish.log` (local). The harness reads nothing of the repository,
  so that run stands at the published release commit `c6eaa70`.

## History

Rewritten in Rust from the archived script `cache-cause.sh` on 2026-10-27 at the owner's decision
(TOOL-01). The script is kept, read-only, in the local evidence folder
`docs/audits/AUD-002-evidence/original-harnesses` (local). Changes from it: the registry is
served by the program itself instead of Python's `http.server`; it sends no `Last-Modified`
header, so Cargo always gets the current index file and the script's two-second wait is gone; it
removes only the folders it makes instead of the whole `<work>`; a Cargo run that fails stops the
check with exit 2 instead of printing an empty code. The harness review's TOOL-02 finding on the
script (H5, unquoted `cargo $tc`) has no object in the Rust version.

The rerun at `dec9c81` on 2026-10-27 printed the same bytes as the run of the record, package
checksums included: `rerun-dec9c81-skeptic-bld-republish.log` (local), SHA-256
`cb69669abb081e1dcdb168d948f181d57ebdb4f893a82cf181d7fc35885c9c28`. The rerun at the release
commit `2cfaa229fbe0fb046ecdb2d45291b380da4a12bf` on the same day, after its build (exit 0,
`rerun-release-skeptic-bld-republish-build.log` (local)), printed the same bytes again and exited
1: `rerun-release-skeptic-bld-republish.log` (local), SHA-256
`cb69669abb081e1dcdb168d948f181d57ebdb4f893a82cf181d7fc35885c9c28`.
