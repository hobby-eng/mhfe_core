# AUD-002 skeptic harness: NFKD passphrase cost

Audit AUD-002 of mhfe-core 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It
challenges the finding that a BIP39 passphrase with a long run of combining marks makes
`wallet_check::Seed::derive` take quadratic time (CHECK-SEC-007, availability bounds, finding
AUD-002-SEC001).

The program checks, in a release build with public inputs only:

- the seed of each test passphrase, at 16 KiB, equals the seed that the `bip39` crate computes,
  without mhfe-core, from the same passphrase normalized by unicode-normalization's `nfkd()` (so
  the timings are of a correct result, and an in-order run, which is already in NFKD, is not
  compared with the crate itself);
- for passphrases of 16, 32, 64 and 128 KiB, median of 3 runs, that the time grows by at most 3.0
  per doubling for `Seed::derive` with ASCII, for `nfkd()` on `a` + U+0301 repeated, for
  `Seed::derive` on `a` + U+0301 repeated (a run already in canonical order) and for `Seed::derive`
  on `a` + (U+0301 U+0316) repeated (classes 230 and 220, out of order).

It exits 1 when any check fails, 0 when all pass, and 2 when the test phrase is refused.

Inputs: none. From the repository root, with a target folder outside the repository, on an
otherwise idle machine:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-sec-nfkd/Cargo.toml
<target>/release/aud002-skeptic-sec-nfkd
```

Expected output at `dec9c81`: the two correctness lines and the ASCII and `nfkd()` lines `PASS`;
both `Seed::derive` lines with combining marks `FAIL` with a growth of about 4 per doubling (2 to
5 s in order and 3.5 to 8.5 s out of order at 128 KiB on the audit machine, by its load); exit 1.

Expected output at the release commit, whose NFKD writer is linear in every order: every line
`PASS`, each `Seed::derive` a few milliseconds, `0 failed`, exit 0. Recorded at `2cfaa22`: exit 0,
`rerun-release-skeptic-sec-nfkd.log` (local), built in
`rerun-release-skeptic-sec-nfkd-build.log` (local). The published release commit `c6eaa70` keeps the
library code, changing only `#[cfg(test)]` modules of `src/`, so this run stands there.

Changes on 2026-10-27: the expected seed comes from `bip39` 3.0.0 (pinned exactly, as in
`skeptic-fun-nfkd`) instead of a second call of the crate; the test phrase's refusal exits 2 with a
message; the growth limits are named constants; `Cargo.toml` has the lints table of RUST-01. The
rerun at `dec9c81` gave the same verdicts as the record (local).
