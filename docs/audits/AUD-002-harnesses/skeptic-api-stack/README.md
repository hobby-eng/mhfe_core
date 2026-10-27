# AUD-002 skeptic check: the stack a public function needs

Audit-only check by the skeptic of AUD-002 for mhfe-core 0.1.0 at commit
`dec9c8115ff9ddbd32bb5fdd457ae9904043c966`. It challenges the api finding that every public
function that clears the stack needs about 136 KiB of free stack. A crate of its own, built against
the crate under review by path, with its own `Cargo.lock` (the probes' versions plus `libc`
0.2.191, pinned exactly).
Linux with glibc only (it reads the thread's stack bounds with `pthread_getattr_np`). No Argon2id
work: `Mhfe::encrypt` runs with a stand-in engine.

Each case runs in a child process, since a stack overflow ends the process:

- controls: a std thread and a `pthread_create` thread, of 64 and 128 KiB, call `Suite::id`, which
  does not clear the stack, and print the free stack below their frame; both read
  `Phrase::read_word` on 256 KiB;
- the check: `Phrase::read_word` on a 128 KiB std thread and on a 128 KiB `pthread_create` thread,
  the size of musl's default thread stack;
- for information: the smallest std thread `Phrase::read_word` and `Mhfe::encrypt` complete on.

Run from the repository root:

```sh
CARGO_TARGET_DIR=<target> cargo build --release --locked --offline \
  --manifest-path docs/audits/AUD-002-harnesses/skeptic-api-stack/Cargo.toml
<target>/release/aud002-skeptic-api-stack
```

Exit 0: `Phrase::read_word` completes on both 128 KiB threads. Exit 1: it fails there while the
controls complete. Exit 2: a control failed, or a case could not run (a child that exits with a
code other than 0; a child killed by a signal is an overflow). Expected at dec9c81, release and
debug: exit 1; the
controls complete with about 123 KiB free on a 128 KiB thread; `Phrase::read_word` on 128 KiB
ends with "stack overflow, aborting" (std thread, SIGABRT) or SIGSEGV (`pthread_create` thread);
`Phrase::read_word` completes from 136 KiB, `Mhfe::encrypt` from 136 KiB in release and 144 KiB in
debug.

Expected at the release commit: the same lines and exit 1. The release documents the stack a call
needs (about 140 KiB, in `src/lib.rs`) rather than lowering it. Recorded at `2cfaa22`: exit 1, the
same bytes as at `dec9c81`, `rerun-release-skeptic-api-stack.log` (local), built in
`rerun-release-skeptic-api-stack-build.log` (local). The published release commit `c6eaa70` keeps
the library code, changing only `#[cfg(test)]` modules of `src/`, so this run stands there.

Changes on 2026-10-27: the program returns an error instead of asserting, so that a case that
could not run gives exit 2 instead of reading as an overflow; the stack sizes are named constants;
its `unsafe` code is allowed, with a reason, for the pthread calls only; `libc` is pinned exactly,
and `Cargo.toml` has the lints table of RUST-01. The rerun at `dec9c81` printed the same bytes as
the record (local).
