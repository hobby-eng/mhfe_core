# AUD-002 protocol harness

Audit AUD-002 of `mhfe-core` 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`,
protocol review: checks `CHECK-FUN-001` (BIP39 phrase reading, entropy, the wallet-check seed),
`CHECK-FUN-006` (suites 3 and 4, recovery and its length rules, the repair card, the password check
word) and `CHECK-API-004` (NFKD with the Unicode 18.0.0 tables, UTF-8, word lists) against the MHFE
specification 0.7.0.

The checks compare the crate with an independent implementation written from the specification
text, `mhfe_ref.py` (Python standard library only), never with another call of the crate's own
code. No check runs Argon2id: the vector replays use each round's recorded Argon2id output, and
the differential probes use a stand-in engine (a SHA-256 of the whole Argon2id input, cost
included) that both sides compute.

## What each script checks

- `replay_vectors.py`, without the crate: every file of the specification's `vectors/suite3`,
  `vectors/suite4` and `vectors/unicode18` against its `SHA256SUMS`; all 27 transcripts in both
  directions, round by round (salt and mask inputs, salt, mask, halves, states, container, readings
  under the length rules); the recovery cases that recorded keys reach, and the expectations of the
  others under the length rules; the 54 fast cases of suite 3 and the 67 of suite 4 (the admission
  table); the eight Unicode 18 password cases; and every vector of `vectors/profiles/README.md`
  (wallet-check digests, the generator polynomials, all 16 cards, the three repairs, the check
  words).
- `unicode_check.py`: first checks the Python NFKD, built from `UnicodeData.txt` 18.0.0, against
  every line of `NormalizationTest.txt` 18.0.0 and every code point outside its Part 1; then sends
  every Unicode scalar value alone, 200,000 seeded random strings and 2,000 random BIP39
  passphrases through `Password::new` and `Seed::derive`, and compares `P_enc`, the refusals and the
  64-byte seeds.
- `differential.py`: literal rows of the official BIP39 vectors (entropy, mnemonic, seed with
  `TREZOR`); `Phrase::read` on seeded typed forms (letter case, four-letter prefixes, any
  White_Space, damaged tokens) and `Phrase::read_word` on every prefix of every word;
  `Phrase::from_entropy` for 0 to 40 bytes; creation step 2; `Mhfe::encrypt` of both suites at every
  length with random passwords and settings (container, unchecked container, round callbacks, and
  every Argon2id call's salt, memory, passes and `P_enc`); `Mhfe::decrypt` and
  `Recovery::readings` for those containers, the right password or another, with every stated
  length and suite, and for arbitrary states (the corpus's ambiguous ones included) made into
  containers by the Python permutation; the admission table exhaustively, with the number of
  Argon2id calls of each refusal (zero); repair cards for every size; repairs within the bound
  (must give the original) and beyond it (exhaustive Gaussian-elimination search on short codes,
  properties of the answer on long ones); `check_word` and `Check::of`; `wallet_check::draw`; and
  `EFF_WORDS` against the list file.
- `adapter/`: a Rust program that puts the crate's public API behind JSON lines, used by the three
  scripts that call the crate. A request it cannot read ends it with exit 2, so that the script
  that sent it fails. Its mode `nfkd-cost` times `Seed::derive` as a passphrase of 10,000 to 80,000
  copies of a unit doubles: ASCII `a`, U+0301 (one run in canonical order) and U+0316 U+0301 (one
  run out of canonical order). It fails when the last doubling more than triples a time above
  100 ms; below 100 ms the fixed cost of PBKDF2 and the timer's noise dominate the ratio.

`nfkd_cost.py`, which the archive `original-harnesses` (local) keeps, was rewritten in Rust on
2026-10-27 as the adapter's `nfkd-cost` mode, at the owner's decision (TOOL-01); it prints the same
lines. `mhfe_ref.py` and the three scripts that compare the crate with it stay in Python, since a
second language is the point of the check.

## Inputs

- A checkout of the specification repository `mhfe_spec` at version 0.7.0, commit
  `6f7537e8c268e010c710a889175e353ec02f66e1` (its `vectors/` and `README.md`), for example a clone
  with `git -C <clone> checkout --detach 6f7537e8c268e010c710a889175e353ec02f66e1`.
- The BIP39 English word list, `bip-0039/english.txt` of `bitcoin/bips`, SHA-256
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
- `UnicodeData.txt` of the Unicode Character Database 18.0.0
  (`https://www.unicode.org/Public/18.0.0/ucd/UnicodeData.txt`), SHA-256
  `0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950`.
- From this repository: `vendor/eff-large-wordlist/eff_large_wordlist.txt` (SHA-256 pinned by the
  specification) and `tests/fixtures/unicode18-ucd/NormalizationTest.txt`.
- Rust 1.99.1 with Cargo, a C compiler for the crate's Argon2 code, and Python 3.11 or later.

`mhfe_ref.py` checks the SHA-256 of `english.txt`, the EFF list, `UnicodeData.txt` and
`NormalizationTest.txt` and stops on a mismatch. `replay_vectors.py` checks each file listed in the
`SHA256SUMS` of `suite3`, `suite4` and `unicode18`, and counts a mismatch as a failure. The other
files of the specification checkout (`validation-cases.json` and the README files) are read without
a check.

## Running

From the repository root, with a target folder outside the repository:

```sh
CARGO_TARGET_DIR=<target> CARGO_NET_OFFLINE=true docs/audits/AUD-002-harnesses/protocol/run.sh \
  <mhfe_spec checkout> <english.txt> <UnicodeData.txt>
```

`run.sh` builds the adapter with `cargo build --release --locked`, then runs the three scripts with
`python3 -I -B`, which writes no `__pycache__` into the repository, and `adapter nfkd-cost`. An
optional fourth argument scales the number of seeded differential cases (default 10). The run takes
a few minutes and little memory. To time the NFKD alone after a build:

```sh
<target>/release/aud002-protocol-adapter nfkd-cost
```

## Expected output

At `dec9c81`, `replay_vectors.py`, `unicode_check.py` and `differential.py` each end with a line
saying that everything matches, after their counts per group. `nfkd-cost` ends with `FAILED`:
doubling a passphrase of combining marks multiplies the time of `Seed::derive` by about four, in
canonical order and out of it (AUD-002-SEC001). `run.sh` therefore exits 1.

At the release commit, whose NFKD writer sorts an out-of-order run once and so is linear in every
order, the three scripts match as before and `nfkd-cost` ends with `Seed::derive grows at most
n log n.`, every time a few milliseconds; `run.sh` exits 0. (A first fix, checked on the fixed tree
of the record, was linear only for runs in canonical order, and its out-of-order unit still
failed.) Recorded at `2cfaa22`, with the inputs above: exit 0, every `nfkd-cost` time under 21 ms,
`rerun-release-protocol-run.log` (local). The published release commit `c6eaa70` keeps the library
code, changing only `#[cfg(test)]` modules of `src/`, and the inputs above, so this run stands
there. Its tests read the same specification commit through the submodule `tests/spec`, which a
clone made with `--recurse-submodules` can pass as `<mhfe_spec checkout>`.

## Changes on 2026-10-27

Besides the rewrite of `nfkd_cost.py`: `run.sh` runs Python with `-B`; the docstrings of
`replay_vectors.py` and `differential.py` state the exit rule and the `--ucd` argument; the
invisible and look-alike characters of `differential.py` and `mhfe_ref.py` are written as escapes
with the same values; `differential.py` uses nested functions instead of lambda assignments, and
each `noqa` names its reason; a comment on the seed of `unicode_check.py` names its ASCII text,
"AUD0022"; the adapter returns an error instead of panicking, pins its dependencies exactly
(`serde_json` 1.0.154, `sha2` 0.11.1, the versions its lockfile already held) and has the lints
table of RUST-01. The values the scripts send and compare are unchanged.
