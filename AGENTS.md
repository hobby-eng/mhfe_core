# mhfe-core agent instructions

This repository is part of the `bip_tools` workspace. Read the workspace `AGENTS.md` one directory
above first, and the coding guide it names in `.github/instructions/`: the CORE, RUST, TOOL, CI
and DOC rules apply here. The specification and its test vectors live in `../mhfe_spec`: a change
of the protocol or of a vector is checked against both. The crate keeps no vectors of its own: the
tests read the specification's vectors through the submodule `tests/spec`, which pins a commit of
the specification whose header names version 0.7.0, as a test checks. Clone with
`--recurse-submodules`, or run `git submodule update --init`. A new specification version moves the
submodule to its commit and the version in `tests/suite3.rs` with it. The specification alone
records this crate's releases. `tests/fixtures/unicode18-ucd/` is Unicode's
`NormalizationTest.txt` 18.0.0 with its README and `SHA256SUMS`.

## Commands

- Toolchain: Rust 1.99.1 from `rust-toolchain.toml`, and dprint 0.63.0 for the Markdown, JSON,
  TOML and YAML (CORE-21), with the plugins and their SHA-256 that `dprint.json` pins. No Node.js.
- Tools (TOOL-01): the `xtask` crate of the workspace, run as `cargo xtask <task>`; it is not part
  of the package. Every new tool, gate or check is a task there, in Rust.
- Fast gates (CORE-43), as CI runs them: `cargo xtask check`.
- Targeted: `cargo test --locked <name>`;
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, and for the crate alone
  `cargo clippy --locked -p mhfe-core --all-targets --target wasm32-unknown-unknown -- -D warnings`;
  `cargo fmt --all --check`; `dprint check`; `cargo xtask <gate>` for the code rules
  (`code-rules`), copies (`copies`), public API (`public-api`), vendored files (`vendored`) and the
  Argon2 stack (`argon2-stack`).
- The public API is `docs/public-api.txt`: a change of a public item changes it in the same
  commit.
- Full cost, announced first and run by the owner:
  `cargo test --locked --release --test full_cost -- --ignored --nocapture`, shared among
  processes with `MHFE_VECTOR_SHARE=k/n`.
- Workflows: `.github/workflows/ci.yml` (every push), `vectors.yml` (on request and on version
  tags), `release.yml` (version tags; it calls ci.yml and drafts the release), `audit.yml` (RustSec,
  when Cargo.toml or Cargo.lock changes, weekly and on request).

On the owner's computer, builds, tests and Clippy run through his memory guard,
`../tmp/memguard.sh <command>`: a local tool, not part of this repository.
