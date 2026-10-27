# AUD-002 challenge harness: the code-rules gate reads docs/audits/

Audit AUD-002 of mhfe-core 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It
challenges finding AUD-002-BLD003: the code-rules gate walks `docs/audits/`, so committing an
audit's harnesses turns the gate red.

The program clones the repository at its checked-out commit into `<scratch>/clone` and runs that
commit's code-rules gate, `cargo xtask code-rules`, which the release commit has. It runs the gate
in five states and checks each result against the finding:

1. The clean commit passes (exit 0).
2. A synthetic harness `docs/audits/AUD-999-harnesses/probe/probe.rs` holding
   `#![allow(unsafe_code)]` fails (exit 1) with the line
   `docs/audits/AUD-999-harnesses/probe/probe.rs: #![allow(unsafe_code)] has no reason`.
3. With this audit's harness folder copied in as well, the gate fails (exit 1). The probe of state
   2 stays, as in the finding's run.
4. With `"docs/audits",` added after `"tests/fixtures",` in the gate's skipped folders, the
   finding's one-line fix, the gate passes (exit 0). Where a source of the gate already names
   `"docs/audits`, nothing is added and the program says so.
5. With the fix, the same probe under `tests/` still fails (exit 1) with the line
   `tests/probe.rs: #![allow(unsafe_code)] has no reason`: the fix hides nothing else.

## Commands

From the repository root, with `<target>` a build folder and `<scratch>` a scratch folder:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-bld-gate/Cargo.toml
<target>/release/aud002-skeptic-bld-gate . docs/audits/AUD-002-harnesses <scratch>
```

Inputs: the repository and this audit's harness folder; relative paths work. To check a commit,
run in a clone checked out at it with this folder copied into its `docs/audits/`, as the audit did.
The program needs Git, the toolchain of `rust-toolchain.toml` and the Cargo registry cache, from
which it builds the xtask gate offline. It replaces `<scratch>/clone` on each run.

At a commit without `xtask/` whose gate is still `scripts/verify-code-rules.mjs`, a Node.js script,
the program runs no gate: this repository runs no Node.js (TOOL-01), harnesses included. It exits 2
with one line that names the archived run of this check at `dec9c81`, which the audit record made
with the original script and that gate: `record-gate-reads-audits.log` (local).

## Output and exit code

The gate in use, then for each state its header, the gate's output and `PASS exit <n>`,
`FAIL exit <n>, expected <m>` or `FAIL missing line: <line>`; state 4 also prints where the fix
went and `git diff`. Last, `Every result matches the finding.` or
`Some results differ from the finding.`. Exit 0 when every result matches the finding, 1 when one
differs, 2 when the check could not run, including a gate that exits with neither 0 nor 1 and a
commit whose gate is the Node.js script.

- At `dec9c81`: no gate runs; exit 2 with the line `error: the reviewed commit's code-rules gate is
  the Node.js script scripts/verify-code-rules.mjs, which this repository no longer runs (TOOL-01);
  the original run of this check is the archived evidence
  docs/audits/AUD-002-evidence/record-gate-reads-audits.log (local)`. In that archived run, with
  the Node.js gate, every state passed, exit 0: the finding holds at `dec9c81`. Its state 3 named
  `security/src/isolation_probe.rs` and the shell headers of two scripts.
- At the published release commit `c6eaa706866b9868cb51048d64b3d21752abce44`: the xtask gate,
  with the fix already in `xtask/src/code_rules.rs`, which also leaves the submodule `tests/spec`
  out. States 1, 4 and 5 pass; states 2 and 3 print
  `FAIL exit 0, expected 1`, because the fixed gate leaves `docs/audits/` out; exit 1: the finding
  no longer holds there.

## History

Rewritten in Rust from the archived script `gate-reads-audits.sh` on 2026-10-27 at the owner's
decision (TOOL-01). The script is kept, read-only, in the local evidence folder
`docs/audits/AUD-002-evidence/original-harnesses` (local). Changes from it: it tests the checked-out
commit instead of a fixed `dec9c81`; it never changes its working folder, so the relative harness
folder of the command above works (the script's `cd` broke it, harness review finding H2); an error
that stops the check exits 2. On the same day it stopped running the Node.js gate of `dec9c81`, at
the owner's decision that no Node.js runs anywhere, harnesses included (TOOL-01).

The reruns of 2026-10-27, each after its build (exit 0,
`rerun-dec9c81-skeptic-bld-gate-build.log` (local) and
`rerun-release-skeptic-bld-gate-build.log` (local)): at `dec9c81`, exit 2,
`rerun-dec9c81-skeptic-bld-gate.log` (local), SHA-256
`58782f8e37ec677f3fbf21c68e99228037db5ecd9619b8cf123b3aefcc010219`; at the published release
commit `c6eaa706866b9868cb51048d64b3d21752abce44`, whose gate changed, exit 1 as described above,
the gate holding in 73 files, `rerun-release-skeptic-bld-gate.log` (local), SHA-256
`21feecf6a712c150746e9266ae66ab4967ebeed84f7e675c3438880ce2310fb1`. That run replaced the one at
the earlier release commit `2cfaa22`, with the same verdicts.
