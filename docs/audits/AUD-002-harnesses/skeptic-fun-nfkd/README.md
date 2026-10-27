# AUD-002 skeptic check: the NFKD writer in a run of marks

Audit-only check by the skeptic of AUD-002 for mhfe-core 0.1.0 at the reviewed commit
`dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It challenges the finding AUD-002-SEC001, that the
NFKD writer is quadratic in a run of combining marks. A crate of its own, built against the crate
in this repository by path, with `bip39` 3.0.0 and `unicode-normalization` 0.1.26 pinned exactly
and its own `Cargo.lock`. Public inputs only.

Checks, each timing the minimum of 3 runs, for passphrases of 20,000 to 160,000 bytes:

- every timed seed equals the seed `bip39` computes, without mhfe-core, from the passphrase
  normalized by unicode-normalization's `nfkd()` (so a timing is of a correct result);
- `Seed::derive` with one run of U+0301, one run of U+0316 U+0301 and ASCII grows by at most 3 times
  per doubling, counted only where the larger time is above 100 ms (below it the fixed cost of
  PBKDF2 and the timer's noise dominate);
- `wallet_check::draw` with a fill that cancels at once, so that only its NFKD runs, grows the same;
- the same length made of stream-safe runs (a starter and 30 marks, 61 bytes, repeated), a control.

A line `INFO` times one run of 512 marks (1,024 bytes, the size limit of an MHFE password). Exit 1
when a check fails, 0 when all pass, 2 when the test phrase is refused or `draw` is not cancelled.

From the repository root, with a target folder outside the repository, on an otherwise idle
machine:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-fun-nfkd/Cargo.toml
<target>/release/aud002-skeptic-fun-nfkd
```

Expected at `dec9c81`: the ASCII and stream-safe lines `PASS`; the two single-run `Seed::derive`
lines and the `draw` line `FAIL` with a growth of about 4 per doubling; `3 failed`, exit 1.

Expected at the release commit, whose NFKD writer is linear in every order: every line `PASS`, each
time a few milliseconds, `all passed`, exit 0. Recorded at `2cfaa22`: exit 0, at most 16 ms each,
`rerun-release-skeptic-fun-nfkd.log` (local), built in
`rerun-release-skeptic-fun-nfkd-build.log` (local). The published release commit `c6eaa70` keeps the
library code, changing only `#[cfg(test)]` modules of `src/`, so this run stands there.

Changes on 2026-10-27: the program exits 2 with a message instead of panicking when the test phrase
is refused or `draw` is not cancelled; a comment gave a stream-safe run 62 bytes where it has 61;
the limits are named constants; `Cargo.toml` has the lints table of RUST-01. The rerun at `dec9c81`
gave the same verdicts as the record (local).
