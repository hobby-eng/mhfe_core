# AUD-002 verify: NFKD writer shapes

Verification of AUD-002-SEC001, the cost of a passphrase's NFKD in `Seed::derive`, in audit AUD-002
of mhfe-core. The audit reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`; its fix was
verified on the uncommitted tree over that commit, then version 0.2.0, and the release commit keeps
version 0.1.0 with a writer that sorts an out-of-order run once.

For passphrases of 16, 32, 64 and 128 KiB it times `Seed::derive` (median of 3, release build) on
five shapes. Three are checked and must grow at most 3 times per doubling of the length: one run of
U+0301 (one class, in order), a run of U+0316 then a run of U+0301 (two classes, in order), and
ASCII. Two are printed as `INFO` only, since the audit's fix left them quadratic and documented
them: U+0301 U+0316 repeated (classes alternate), and one U+0301 above a long run of U+0316. For
each shape it also checks, at 16 KiB, that the crate's seed equals the seed that the `bip39` crate
derives from the passphrase normalized by `unicode-normalization`'s own iterator, so that the
expected seed never goes through the crate's NFKD writer. Inputs are public: the entropy of
BIP39's first 24-word test vector and generated passphrases. No Argon2id runs.

From the repository root, with `<target>` a Cargo target folder outside the repository:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/verify/nfkd-shapes/Cargo.toml
<target>/release/aud002-verify-nfkd-shapes
```

The crate depends on mhfe-core by path and has its own `Cargo.lock`, which pins mhfe-core 0.1.0,
`bip39` 3.0.0 and `unicode-normalization` 0.1.26, so `--locked` holds at dec9c81 and at the
release commit. It prints a `PASS`, `FAIL` or `INFO` line per item and `<n> failed`, and exits 0
when every checked item passes, 1 when one fails and 2 when it cannot run.

- At dec9c81: the seeds pass, the two in-order shapes fail (they grow 4 or more times per
  doubling, the finding), ASCII passes; exit 1.
- At the release commit: every checked item passes; exit 0. The two `INFO` shapes grow linearly
  there as well: no shape grows more than 1.5 times per doubling, and none takes 10 ms at 128 KiB.
  The build is `rerun-release-verify-nfkd-shapes-build.log` (local), the run
  `rerun-release-verify-nfkd-shapes.log` (local), both at the release commit `2cfaa22`. The
  published release commit `c6eaa70` keeps the library code, changing only `#[cfg(test)]` modules
  of `src/`, so this run stands there.

Changed on 2026-10-27, after the audit's record run (finding H11 of the final review): the
expected seed came from `Seed::derive` itself on the reference NFKD, which for the in-order shapes
is the same string, so that check could not fail. The lockfile pinned the 0.2.0 tree; it now pins
0.1.0. The crate gained its lints table, and the README its commands from the repository root.
