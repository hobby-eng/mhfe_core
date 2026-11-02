# AUD-005 harnesses

These Rust tools belong to AUD-005, the full-scope audit of mhfe-core at
`9e8cff90f5e85ca1b4b9499c4e500311a310f3e4`. They use public synthetic data only and do not change
library sources, tests, fixtures, dependencies or cryptographic parameters. The full-cost and complete
published vector corpora are not replayed.

Run every command from the repository root with Rust 1.99.1 and the workspace `CARGO_HOME` and
`RUSTUP_HOME`. Initialize `tests/spec` first. Set `CARGO_TARGET_DIR` outside the repository and use
`../tmp/memguard.sh` for builds and test suites. The audit assigned a combined review budget of
4 GiB; this is a budget, not a measured peak.

Build the tools offline:

```sh
cargo build --offline --locked --release --manifest-path docs/audits/AUD-005-harnesses/Cargo.toml
```

The examples below name the resulting program `aud005`. Replace it with its actual path under
`CARGO_TARGET_DIR`.

- `aud005 run <label> <command> [arguments...]` executes one command from the repository root and
  writes its exact arguments, selected environment, UTC start/end, exit result, combined log and
  log SHA-256 under `docs/audits/AUD-005-evidence/` (local). It refuses to overwrite a log and
  returns nonzero when the child cannot start or fails. For example:
  `aud005 run fast ../tmp/memguard.sh cargo xtask check`.
- `aud005 inventory` reads `all-paths.nul` and `source-SHA256SUMS` from the local evidence folder,
  checks every original recursive source file byte for byte, and writes `inventory.json` (local).
  It exits nonzero for a missing, added-within-the-baseline-set, duplicate or changed baseline path.
- `aud005 source-findings` checks the five reported defect groups and writes `finding-probes.json`
  (local). It executes actual `Mhfe::encrypt` through a deterministic public synthetic engine and
  requires `Ok(ControlFlow::Break(()))` at round 13 before the reverse comparison. It checks the
  exact 32-bit NFKD overflow arithmetic, Windows WER block counts, unread-page handling in the
  retained stack probe, and stale documentation facts. The 32-bit and Windows branches are
  source/arithmetic evidence; this command does not claim to execute those operating environments.
  It exits nonzero if a reviewed source fact or reproduction is absent.
- `aud005 validate` validates the final Markdown/JSON report pair against the canonical schema,
  rejects duplicate literal JSON keys, compares finding fields and ID sets, requires 32 unique
  coverage rows and all procedure IDs, checks index links, unknown reviewer metadata, English-only
  text and privacy/wording rules.
- `aud005 negative-controls` requires the valid pair and publication-guidance sources to pass and
  nine deliberately inconsistent variants to be refused: changed severity, title, status and
  category, a duplicate heading, an extra Markdown finding, prohibited wording and corrected
  publication guidance in either source document. Every accepted invalid control makes the command
  exit nonzero.

Successful probes print a short result and exit zero. Raw evidence stays in
`docs/audits/AUD-005-evidence/`, which Git ignores; it is not a public artifact. The baseline files
were prepared before any AUD-005 record or harness was added:

```sh
git ls-files --recurse-submodules -z > docs/audits/AUD-005-evidence/all-paths.nul
git ls-files --recurse-submodules -z | xargs -0 sha256sum \
  > docs/audits/AUD-005-evidence/source-SHA256SUMS
```

Report validation needs `docs/audits/AUD-005-2026-11-02.md`, its JSON twin, the audit index and the
canonical procedure/schema in the adjacent workspace checkouts. No command contacts a live wallet,
uses a real secret, dispatches CI or publishes anything.
