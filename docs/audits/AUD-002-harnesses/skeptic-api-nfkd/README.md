# AUD-002 skeptic check: where the NFKD cost comes from

Audit-only check by the skeptic of AUD-002 for mhfe-core 0.1.0 at the reviewed commit
`dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It challenges the finding AUD-002-SEC001: does a run
of combining marks in a BIP39 passphrase make `Seed::derive` and `wallet_check::draw` quadratic,
and does the cost come from the length of one run rather than from the length of the passphrase?
A crate of its own, built against the crate in this repository by path, with its own `Cargo.lock`.
Public inputs only.

Each case is timed at 10,000, 20,000, 40,000 and 80,000 marks (median of 3) and passes when the
last doubling at most triples the time:

- the control: `Seed::derive` with the same marks, each after its own letter, so that every run
  has length 1;
- `Seed::derive` with one letter and one run of U+0301;
- `draw` with the same passphrase and a fill that cancels at its first trial, so that only its NFKD
  runs.

A line `INFO` times one run of 4,096 marks, the size of an 8 KiB typed line. Exit 1 when a case
fails, 0 when all pass, 2 when the test phrase is refused or `draw` is not cancelled.

From the repository root, with a target folder outside the repository, on an otherwise idle
machine:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-api-nfkd/Cargo.toml
<target>/release/aud002-skeptic-api-nfkd
```

Expected at `dec9c81`: the control passes; `Seed::derive` and `draw` with one run fail with a
growth of about 4 per doubling (3 to 12 s at 80,000 marks, by the load of the machine), and the
program ends with "quadratic growth in a run of combining marks"; exit 1. The check reads only the
last doubling, so on a busy machine a slow middle size can bring one of the two lines under 3 while
the times still grow about 64 times over the three doublings; the exit code stays 1 as long as one
of them fails.

Expected at the release commit, whose NFKD writer is linear in a run: every line `PASS`, each time
a few milliseconds, exit 0. Recorded at `2cfaa22`: exit 0, at most 9 ms each,
`rerun-release-skeptic-api-nfkd.log` (local), built in
`rerun-release-skeptic-api-nfkd-build.log` (local). The published release commit `c6eaa70` keeps the
library code, changing only `#[cfg(test)]` modules of `src/`, so this run stands there.

Changes on 2026-10-27: the program exits 2 with a message instead of panicking when the test phrase
is refused or `draw` is not cancelled; its sizes and limits are named constants; `Cargo.toml` has
the lints table of RUST-01. The timed calls are unchanged.
