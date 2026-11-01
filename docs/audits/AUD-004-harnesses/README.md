# AUD-004 harnesses

These Rust tools belong to the full audit of commit
`9ee72442a2185ea699862b96f3c7110dc9f5f07f` of mhfe-core. They use public synthetic data only.
They do not change library sources or cryptographic parameters. Run from the repository root,
with the workspace's pinned Rust toolchain and memory guard. Builds share the machine's heavy
check lock; set `CARGO_TARGET_DIR` outside the repository for independent audit build output.

Build with `cargo build --offline --locked --release --manifest-path docs/audits/AUD-004-harnesses/Cargo.toml`.
The resulting `aud004` program accepts:

- `run <label> <command> [arguments...]`: runs one command and records its exact arguments,
  selected environment, UTC times, exit, combined log and SHA-256 in `AUD-004-evidence/` (local).
  A failed or signalled child fails the runner. Memory limits and timeouts are explicit arguments
  to the child command, not supplied implicitly by this tool.
- `inventory`: hashes every path from the baseline recursive Git inventory and fails on missing
  or changed source bytes. Writes the source inventory and its aggregate fingerprint locally.
- `provenance`: checks every resolved registry archive against `Cargo.lock`, then compares every
  packaged file byte for byte with the registry source directory, streaming `tar` entries without
  extracting another tree. Reads the retained metadata log.
- `registry`: reads each resolved version's checksum and yank state from the official crates.io
  sparse index using `curl`, retaining responses locally without updating Cargo's index.
- `wallet-boundary`: finds a public synthetic 24-word seed whose check starts with a zero byte
  followed by a nonzero byte. Independently hashes the public seed and requires rejection by the
  actual 16-bit check. At most 4,096 trials; no Argon2 calls. Prints the trial and public digest.
- `small-stack`: runs the native engine from a 32 KiB caller stack at a 1 MiB diagnostic cost and
  compares its tag with the retained independent OpenSSL tag. This is an engine API diagnostic,
  not an MHFE container or reduced-cost vector replay.
- `validate`: checks the new report against the canonical schema, rejects duplicate literal JSON
  keys, compares every finding's Markdown fields and JSON fields, checks privacy and verifies
  that the report contains each of the 32 procedure IDs. The schema checker is imported from
  the frozen AUD-002 harness; it rejects schema keywords it does not implement.
- `negative-controls`: requires refusal of six inconsistent report variants and an extra
  compiler input, `build.rs`; also requires acceptance of the valid report and listed input.

Successful checks print their measured result and exit zero. The source inventory covers the
original reviewed snapshot; the audit's newly added report and harnesses have separate digests.
Peak memory is not measured by this tool. The command records must not be read as a memory trace.

`inventory` needs the two baseline files retained in `AUD-004-evidence/` (local). At the reviewed
commit, before editing tracked files, prepare them with `git ls-files --recurse-submodules -z`
saved as `all-paths.nul`, and `git ls-files --recurse-submodules -z | xargs -0 sha256sum` saved as
`source-SHA256SUMS`. Initialize `tests/spec` first. `provenance` reads the JSON produced by
`aud004 run metadata cargo metadata --locked --offline --format-version 1`; `registry` reads the
successful `provenance.json` result. Report checks need the final AUD-004 Markdown/JSON pair.
