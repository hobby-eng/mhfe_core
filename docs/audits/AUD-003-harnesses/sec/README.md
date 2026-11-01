# AUD-003 harness of the security review

Audit AUD-003 of mhfe-core 0.2.0, reviewed commit 0daa611. These scripts show what the native
Argon2id engine leaves in process memory after a call. Public test data only.

- `probe-stack/`: a crate of its own that depends on this repository's `mhfe-core`. Linux on x86-64.
  It reads the stacks of the four pool threads and every writable mapping through /proc/self/mem,
  from the main thread, after `NativeArgon2::argon2id` has returned and the threads sleep, and
  searches them for every 8-byte window of the password, H0 and the tag and for the words of the
  blocks. It needs a process that may read itself, and no isolation.
- `run-matrix.sh`: builds the probe under one host profile and scans.

From the repository root:

    CARGO_TARGET_DIR=<a build folder> docs/audits/AUD-003-harnesses/sec/run-matrix.sh thin \
      CARGO_PROFILE_RELEASE_LTO=thin

`<label> scan 40 calls: N hits` prints 38 when nothing is left: 13 windows of the password and 25 of
the tag, in the probe's own heap copies. More than 38 and the lines with `H0+40 words` to `H0+48
words` are the defect of AUD-003-SEC001: bytes 40 to 55 of H0 at 40 to 55 bytes above the sleeping
thread's stack pointer. Subcommands of the probe:

- `scan <calls> <memory KiB> <passes> <password bytes>`: the search above.
- `depth`: the same calls on a pool of the probe's own, without the overwrite, which gives how deep
  each thread writes below its stack pointer.
- `below`: the real engine; what changed below the part it clears.
- `hold`: stops at `probe_stop` for a debugger when a word is found, then looks again after the
  engine was dropped.
- `call`, `secret`, `isolated`: one call, one `Secret` in or out of the isolation, and calls in a
  process isolated whole, for `prlimit` and `strace`.

`sec001-tried-fix.diff` is the fix tried in a private copy of the tree, which the probe then found
clean under thin LTO. `gdb-hold.txt` is the debugger script of the `hold` subcommand: it shows the
sleeping threads' frames while the words are on the stack.
