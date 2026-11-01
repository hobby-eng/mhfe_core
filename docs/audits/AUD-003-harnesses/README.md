# AUD-003 harnesses

Probes of audit AUD-003 of mhfe-core, at tree `b50946b1fe5717321afce182074f3ac766a01a6a`. The report
is [`../AUD-003-2026-11-01.md`](../AUD-003-2026-11-01.md). Public test data only.

- `run-logged.sh <evidence folder> <name> <command...>` runs one command and keeps its output, exact
  command, UTC times, exit code and the SHA-256 of its log.
- `sec/`: `run-matrix.sh <name> <environment...>` builds `probe-stack` against the crate in a build
  profile and scans the pool threads' stacks; it exits non-zero when a secret word is found.
- `fun/`, `bld/`: the probes behind their findings.

Run them from the repository root with `CARGO_TARGET_DIR` set to a build folder.
