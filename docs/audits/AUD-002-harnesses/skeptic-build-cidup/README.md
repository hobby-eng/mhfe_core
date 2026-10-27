# AUD-002 challenge harness: CI runs a fast check twice

Audit AUD-002 of mhfe-core 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It
challenges finding AUD-002-ARC001: CI repeats two commands of the checks job.

The program reads `.github/workflows/ci.yml` of a commit with `git show` and the checks job's fast
checks, which are the lines of `scripts/check-fast.sh` where the commit has it. It finds the
checks job's runner and two candidate repeats on that runner: the `cargo test` command of the
native matrix, when the matrix lists that runner, and the line after the wasm job's `- name: Lint`,
when the wasm job runs there. A candidate that is a line of `check-fast.sh` is a repeated command.
At a commit where the checks job runs `cargo xtask check` instead, the fast checks are Rust code
that the program does not read: a candidate is then unknown, and the check cannot tell.

Given the log of a CI run, the program also prints, for comparison, the runner images of the
checks job and of the native job on the same runner and whether their sorted test lines are
identical. That comparison does not change the exit code.

## Commands

From the repository root, with `<target>` a build folder:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-build-cidup/Cargo.toml
<target>/release/aud002-skeptic-build-cidup . dec9c8115ff9ddbd32bb5fdd457ae9904043c966 \
  <run log>
```

Inputs: the repository, a commit it holds, and optionally the log of the CI run of that commit.
For `dec9c81` that is run 40492969676, saved read-only with
`gh run view 40492969676 --repo hobby-eng/mhfe_core --log > <run log>`; the audit's copy is
`docs/audits/AUD-002-evidence/build-gh-ci-run-log.log` (local), SHA-256
`7895eba56e204f71657f142be49d85ca02f47ab26bbc1b1d392e23f2ca1a8c00`. At the release commit, pass
`HEAD` and no log until CI has run it. For the published release commit `c6eaa70` that is run
40562937779, which passed every job in its first attempt. `gh` 2.46 prints nothing for
`gh run view 40562937779 --log`: GitHub's log archive of that run keeps each job's log as one file,
without the per-step files that version reads. So the harness first ran without a run log there,
and each job's log was saved read-only through GitHub's API as
`rerun-release-skeptic-build-cidup-ci-log.log` (local). `gh` 2.102.0 reads the archive and writes
`UNKNOWN STEP` in place of each step's name; the harness then counts every line of the job. That
log is `rerun-release-skeptic-build-cidup-gh-run-log.log` (local), SHA-256
`0b2dfe880831dd99ea329420955c8164dee561b2c1f1fb01f0e7c29a4d5a2535`. The program needs Git and no
network.

## Output and exit code

Where the fast checks come from, the checks job's runner, the native matrix and command, the wasm
Lint line, a `REPEATED:` line for each repeat and an `UNKNOWN:` line for each candidate it cannot
tell; with a log, the two runner images, the counts of test lines and either
`SAME RESULTS: identical test lines on the identical runner image` or
`DIFFERENT RESULTS or runner images`; last, `repeated commands: <n>`. Exit 0 when no command
repeats, 1 when one does, 2 when the check cannot tell or could not run.

- At `dec9c81` with the run log: `cargo test --locked` (line 22) and the wasm32 Clippy line
  (line 20) repeated, 130 identical test lines on the same image, `repeated commands: 2`, exit 1.
  Recorded: exit 1.
- At the release commit: the fast checks are `cargo xtask check`; the native matrix no longer
  lists `ubuntu-24.04` and the wasm job has no Lint step, so there is no candidate:
  `repeated commands: 0`, exit 0. With the run log, the comparison prints
  `DIFFERENT RESULTS or runner images`, since no native job runs on `ubuntu-24.04` (0 test lines
  against the checks job's 197). Recorded at the published release commit `c6eaa70`: without a run
  log, exit 0, `rerun-release-skeptic-build-cidup.log` (local); with the log of `gh` 2.102.0,
  exit 0, `rerun-release-skeptic-build-cidup-with-log.log` (local). After the change for logs
  without step names, the run at `dec9c81` with its log gives the result above again:
  `rerun-dec9c81-skeptic-build-cidup-after-fix.log` (local), exit 1.

## History

Rewritten in Rust from the archived script `check-ci-duplicates.sh` on 2026-10-27 at the owner's
decision (TOOL-01). The script is kept, read-only, in the local evidence folder
`docs/audits/AUD-002-evidence/original-harnesses` (local). Changes from it: the description now
says what the exit code depends on, since the script's header claimed that the run-log comparison
counted (harness review finding H15); the run log is optional; the native candidate counts when its
matrix lists the checks job's runner, and the wasm candidate when the wasm job runs on it, where
the script compared with `ubuntu-24.04` and `cargo test --locked` written into it; a commit
without `check-fast.sh` gives unknown, not none. The harness review's TOOL-02 finding on the
script (H5, unquoted expansions) has no object in the Rust version.

The rerun at `dec9c81` on 2026-10-27 exited 1 with the record's verdict and counts:
`rerun-dec9c81-skeptic-build-cidup.log` (local), SHA-256
`0fbb800b0b0a65c0e594408384e9529e7eea6d235ba42bf299f27cb02a25dcbe`. At the earlier release commit
`2cfaa22`, with `HEAD` and the log of run 40544589421, it exited 0 with no candidate. The rerun at
the published release commit `c6eaa706866b9868cb51048d64b3d21752abce44` on the same day, whose
`ci.yml` changed, after its build (exit 0,
`rerun-release-skeptic-build-cidup-build.log` (local)), with `HEAD` and no run log, exited 0 with
no candidate:
`rerun-release-skeptic-build-cidup.log` (local), SHA-256
`fe8702628f173d709b0714346b8310ff40fa8966deff272e00927374955fb830`. Its first attempt there read
the empty output of `gh run view --log` and gave the same verdict:
`rerun-release-skeptic-build-cidup-ci-log-attempt1.log` (local) and
`rerun-release-skeptic-build-cidup-attempt1.log` (local).
