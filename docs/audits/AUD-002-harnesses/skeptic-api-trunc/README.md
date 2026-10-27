# AUD-002 skeptic check: a password of exactly 2^32 bytes

Audit-only check by the skeptic of AUD-002 for mhfe-core 0.1.0 at the reviewed commit
`dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It challenges the finding AUD-002-API001, that
`NativeArgon2::argon2id` cuts the password length to 32 bits. A crate of its own, built against the
crate in this repository by path, with its own `Cargo.lock`. Public inputs only, Argon2id at
32 KiB and one pass.

A control first checks that a password of 2,000 zero bytes does not get the tag of its first byte.
Then a password of exactly 2^32 zero bytes, whose length cut to 32 bits is 0, is compared with the
empty password. Exit 1 when the two tags are equal (the length is cut), 0 when the long password is
refused or gets another tag, 2 when the control fails or a call it needs is refused.

From the repository root, with a target folder outside the repository and 4 GiB of address space
(the zero pages are not touched when the length is cut):

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-api-trunc/Cargo.toml
<target>/release/aud002-skeptic-trunc
```

Expected at `dec9c81`: `password of 4294967296 bytes: Ok(()); its tag equals that of the empty
password: true`, exit 1.

Expected at the release commit, which refuses a password whose length does not fit 32 bits:
`Err(Argon2Failed { code: -5 })` and `false`, exit 0. Recorded at `2cfaa22`: exit 0,
`rerun-release-skeptic-api-trunc.log` (local), built in
`rerun-release-skeptic-api-trunc-build.log` (local). The published release commit `c6eaa70` keeps
the library code, changing only `#[cfg(test)]` modules of `src/`, so this run stands there.

Changes on 2026-10-27: the program returns an error and exits 2 instead of panicking when the
control fails or a call it needs is refused; the Argon2id cost and the lengths are named constants;
`Cargo.toml` has the lints table of RUST-01. The rerun at `dec9c81` printed the same bytes as the
record (local).
