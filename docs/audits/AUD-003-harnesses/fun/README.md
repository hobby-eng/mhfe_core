# AUD-003 fun: the engine of 0.1.0 and of the audited commit

The Rust crate `aud003-fun-engines` links the published mhfe-core 0.1.0 and this repository's commit
into one program, which Cargo allows now that the audited commit has no `links` key.

- `traits` prints the auto traits of `NativeArgon2` and `Mhfe<NativeArgon2>` of both versions.
- `call published` and `call audited` make one Argon2id call of 1 MiB and one pass on an engine of
  that version; run them under `RUST_MIN_STACK`.

From the repository root, with `<target>` a Cargo target folder outside the repository:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-003-harnesses/fun/Cargo.toml
<target>/release/aud003-fun-engines traits
RUST_MIN_STACK=131072 <target>/release/aud003-fun-engines call published
RUST_MIN_STACK=131072 <target>/release/aud003-fun-engines call audited
```

At commit 0daa611 the audited engine's two types are neither `UnwindSafe` nor `RefUnwindSafe`, and
the audited call ends the process with a stack overflow on a pool thread (exit 134) where the
published one prints its tag.
