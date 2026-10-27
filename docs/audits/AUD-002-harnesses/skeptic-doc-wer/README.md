# AUD-002 skeptic: the Windows `no_core_dumps` claim

Audit AUD-002 of mhfe-core 0.1.0, reviewed commit `dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. The
crate in this folder, `aud002-skeptic-doc-wer`, challenges the documentation finding AUD-002-DOC002:
`Isolation::no_core_dumps` is described as "a crash writes no core dump" while, on Windows,
`enter()` only sets WER's NOHEAP flag, so an error report still holds the threads' stacks.

The harness was rewritten in Rust from the script `check-wer-claims.sh`, which the archive
`original-harnesses` (local) keeps, on 2026-10-27 at the owner's decision (TOOL-01). Its checks and
output are the script's; one difference: when `struct Isolation` has no field `no_core_dumps`, one
`FAIL field-doc` line says so, where the script passed `field-doc` on an empty doc.

It reads the files of the given commit (default: the reviewed one) with `git show`, so the working
tree does not matter. It checks that:

1. `src/os.rs` runs `src/os/windows.rs`'s `enter()` on Windows;
2. that `enter()` changes error reporting only through
   `WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)` (no `SetErrorMode`, exception filter, excluded
   application or `LocalDumps` setting), and `no_core_dumps` is that flag read back;
3. the field doc of `no_core_dumps` neither opens with "A crash writes no core dump" for every
   system nor fails to name the stacks an error report keeps;
4. SECURITY.md's Windows section, the Windows paragraph of `Isolation::enter`'s doc and README's
   Windows bullet each name the stacks an error report keeps (the word "register" is not
   accepted, since these texts use it for other programs and for `WerRegisterExcludedMemoryBlock`;
   each occurrence is printed in context);
5. SECURITY.md and `enter()`'s doc name Android's crash residue, the documents' own standard.

## Inputs

The repository, holding the commit to read, Git, and the Rust toolchain of `rust-toolchain.toml`;
the crate has no dependencies. The release commit amends `dec9c81`, so a later clone may not hold
it: the harness then stops on Git's error.

## Running

From the repository root, with `<target>` a Cargo target folder outside the repository:

```sh
CARGO_TARGET_DIR=<target> cargo run --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-doc-wer/Cargo.toml -- [commit]
```

`cargo test` with the same options and no argument runs its unit test, which gives the checks that
pass at `dec9c81` texts they must refuse.

## Output

`PASS` or `FAIL` per check, with the crash-report calls, the field doc and each "register" in
context. The exit code is 1 when a check failed, 2 when the harness stopped on an error (such as a
commit the repository does not hold), and 0 when every check passed.

- At `dec9c81`, without an argument: checks 1, 2 and 5 pass and checks 3 and 4 fail (five `FAIL`
  lines); exit 1. The output is the script's record (local), byte for byte.
- At a release commit: without an argument it still reads `dec9c81`, with the same output and
  exit 1, where the clone holds that commit. Given the release commit, every check passes and it
  exits 0: the release keeps the Windows wording of the fixes. Without an argument, run at the
  release commit `2cfaa22`: `rerun-release-wer-claims.log` (local), exit 1, SHA-256
  `abd59d220079906aa9194b776825865a859c7168f1d53cc85c06a691b91f5db1` (the clone, made from the
  local repository, held `dec9c81`); that run reads only `dec9c81`, so it stands. Given the
  published release commit `c6eaa70`, whose README changed:
  `rerun-release-wer-claims-release.log` (local), exit 0, SHA-256
  `9d94fed6d202f03280a4ca4e34ea81753c64448bf54239b1ddb00cf3975b2488`.
