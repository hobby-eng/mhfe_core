# AUD-002 skeptic: the private reporting channel

Audit AUD-002 of mhfe-core 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. A
reviewer reported that `SECURITY.md` sends vulnerability reports to GitHub's security advisories of
a repository that does not accept them. The crate in this folder, `aud002-skeptic-doc-pvr`, was the
challenge that withdrew the report: it fails when `SECURITY.md` at `HEAD` names GitHub's security
advisories while the public repository `hobby-eng/mhfe_core` has private vulnerability reporting
off.

The harness was rewritten in Rust from the script `check-pvr.sh`, which the archive
`original-harnesses` (local) keeps, on 2026-10-27 at the owner's decision (TOOL-01). Its output is
the script's. One difference, the fix of the final review's H4: a `gh` or Git call that fails, or
an answer the check cannot read, stops the harness with exit 2, where the script printed `PASS`
with the error text as the values.

It prints:

- the lines of `SECURITY.md` at `HEAD` that hold "report", "advisor", "mail" or "contact";
- the email addresses in tracked files outside `vendor/` and `tests/fixtures/`, no-reply and
  example addresses left out, at most 20;
- for `hobby-eng/mhfe_core`, `hobby-eng/mhfe` and `hobby-eng/mhfe-spec`: the visibility, whether the
  repository is archived and has issues, and GitHub's answer on private vulnerability reporting;
- the verdict for `hobby-eng/mhfe_core`.

## Inputs

The repository (its `HEAD` is the commit read), Git, the Rust toolchain of `rust-toolchain.toml`
(the crate has no dependencies), and the network: read-only `gh api` calls to `repos/<name>` and
`repos/<name>/private-vulnerability-reporting`, with the GitHub CLI signed in. The optional argument
is another repository folder to read.

## Running

From the repository root, with `<target>` a Cargo target folder outside the repository:

```sh
CARGO_TARGET_DIR=<target> cargo run --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-doc-pvr/Cargo.toml
```

`--offline` is Cargo's; the harness itself calls GitHub. `cargo test` with the same options runs
its unit test, which shows the verdict refusing a public repository without private reporting.

## Output

The exit code is 1 when the claim fails, 2 when the harness stopped on an error, and 0 otherwise.
The verdict follows GitHub's live settings as well as the commit.

- At `dec9c81` and at the release commit: `SECURITY.md` names the security advisories, the
  repository is public, and private vulnerability reporting has been on since 11:41 UTC on
  2026-10-27: `PASS: visibility=public pvr=true`, exit 0. The rerun at the release commit `2cfaa22`
  on 2026-10-27, which prints its SECURITY.md lines with their new numbers:
  `rerun-release-pvr-check.log` (local), exit 0, SHA-256
  `8397a20798ae1b8890b21c5b0108407abe83a96372e8bbfcae93798d4ede822c`. The published release
  commit `c6eaa70` keeps `SECURITY.md` and adds or removes no e-mail address, so that run stands
  there; GitHub's settings are not part of a commit.
