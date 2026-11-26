# Changelog

## Unreleased

- The repair words are computed and repaired by reed-solomon-core 0.2.0, the same code over
  GF(2^11) with the first root alpha and a step of 1: cards and repairs are unchanged. Its decoder
  finds wrong words algebraically, where the crate's own tried every set of places, which took a
  time that depended on where the damage was; the field's tables are no longer on the heap.
- The release workflow packages the crate in a job that can neither write nor sign. Only the
  attestation and the release draft hold those rights, and they run no code of the repository.
- Four fuzz targets read what a person gives the crate: a phrase, a password, a container with its
  card, and a password under the password-check profile; the release workflow runs each for 90
  seconds before it packages a tag. CI also runs the tests on Intel macOS and on Windows with the
  GNU toolchain, and on macOS the isolation tests again under the hardened runtime.
- `wallet_check::draw` is gone: the crate draws no new seed phrases. A host that draws a phrase
  until it passes the wallet check does so itself and checks it with `Seed::passes`.
- A cancelled operation is no longer an error: `Mhfe::encrypt` and `Mhfe::decrypt` return
  `Result<ControlFlow<(), T>, Error>`, and `Break` from a callback comes back as the result.
  `Error::Cancelled` is gone.
- `NativeArgon2::is_out_of_dumps` says whether all of the work area is left out of core dumps, which
  on Windows holds only as far as a process's 512 exclusions reach.
- On a 32-bit target, a password whose NFKD passes 4 GiB is refused as too long instead of ending
  the process.
- `protect` is secret-protection-core 0.2: `Secret`, `Isolation` and `write_secret` are its own,
  re-exported, and this crate's copies of the system calls are gone. `Secret` also has that crate's
  `locked`, `zeroed`, `as_mut_bytes` and `is_out_of_children`. A program that needs more of it,
  such as `Isolation::enter_with`, depends on the same version.
- This crate requires secret-protection-core exactly at 0.2.0. A later 0.2 release, with its fixes,
  reaches programs through a release of this crate, and a program whose other dependencies need a
  later one cannot use this crate until then.
- `Secret::push` returns `protect::SecretError`, that crate's refusal, when the secret is full;
  `Error::SecretFull` is gone.
- On Linux secret-protection-core decides once whether a `Secret` may try the kernel's secret
  memory: at the first `Secret`, or at an earlier `Isolation::enter` made while the process has one
  thread, and only a process of one thread at that moment may. A `Secret` then gets it on x86-64 and
  AArch64 where the kernel offers it and lets the pages be charged. Otherwise it lies on anonymous
  pages, which root can read and which do not keep the system from hibernating.
  secret-protection-core tries to lock them with `mlock`, and a refusal, such as one over
  `RLIMIT_MEMLOCK`, leaves them unlocked. `Secret::is_locked` says whether a `Secret` is locked, and
  `Secret::locked` refuses one that is not. A program makes its first `Secret`, or isolates itself,
  before it starts a thread, `NativeArgon2::new` included.
- The isolation report confirms only what it reads back. On Windows `no_core_dumps` and
  `no_file_changes` are always false: error reports still hold the stacks, and low integrity writes
  where a low label allows it. A second `enter` on Windows may read `no_memory_reading` as false, as
  Windows can hide the threads it checks from a process that lowered itself. On Linux
  `no_memory_reading` is false in a nested PID namespace, such as a container's, where a tracer
  outside could hide, and `no_new_sockets` and `no_file_changes` are false on processors without
  the seccomp filter, all but x86-64 and little-endian AArch64. New fields report further
  protections, and two reports are equal only when the outcome of every protection is.
- `Isolation::enter` refuses more by default. On Linux and Android the filter refuses starting a
  program, System V IPC, message queues and kernel keyrings; `connect`, `bind`, `listen`, `accept`
  and `sendmmsg`, on a socket opened before too; and calls on a process or a thread named by its
  number, the process's own too, such as `pthread_setaffinity_np` and `pthread_setschedparam`.
  Linux enters an IPC namespace with the network one, and from Linux 6.12 its Landlock layer keeps
  signals and abstract UNIX sockets within the layer, so that a child started before the call can
  no longer be signalled. The macOS sandbox now denies all it does not allow: it writes only to
  /dev/null and the process's own terminal, reads no other terminal, and refuses every Mach
  service, such as the pasteboard and opening URLs, signals to other processes, starting a process
  and mapping code from outside /usr/lib and /System. Windows puts the process in a job that allows
  one process and keeps it from writing the clipboard, from other programs' windows, from global
  atoms and from changing the desktop; it refuses child processes and narrows where DLLs load from,
  extension points included. Where these hold, a program can no longer start another after
  isolating itself: on Linux and Android with the seccomp filter, on Windows under the
  child-process policy and the job, and on macOS under the sandbox.
- `Isolation::enter` also asks to limit speculation. On Linux and Android it asks the kernel to
  force speculative store bypass and indirect branch speculation off for the calling thread and the
  threads it starts afterwards, the engine's lanes included. On Windows it asks for the side-channel
  isolation policy: branch targets not shared with the core's other thread, a security domain of its
  own, no combined pages and speculative store bypass off. A limit the system applies cannot be
  undone and may cost speed. `speculation_limited`, the outcome of `Protection::SpeculationLimited`,
  says what came of it: on Linux and Android a processor that needs no limit counts as limited, and
  a limit refused or left unreported reads as refused or unknown; on Windows it is the policy as
  read back.
- On macOS `no_memory_reading` is true only for a program signed with the hardened runtime and
  without `get-task-allow`: refusing a debugger alone leaves `task_for_pid` open.
- In a child of `fork`, a `Secret` of the parent reports no protection, and the child ends at the
  first access to its bytes.
- In WebAssembly nothing clears the stack after a call: a stack that runs over there has no guard
  page. What a computation leaves on it stays in the instance's memory until it is overwritten or
  the instance ends. Buffers are still wiped when they are dropped.

## 0.2.0 (2026-11-01)

Same specification 0.7.0, same containers, readings, repair words and check words as 0.1.0.

- The native engine is RustCrypto's `argon2` instead of vendored C, so a build needs no C compiler.
  It runs on four threads of its own, about 7% faster.
- Call `protect::Isolation::enter` before `NativeArgon2::new` or `Mhfe::new`, on the thread that
  makes the engine: its threads start there and inherit it.
- `new` can return `Error::Argon2Failed`: -33 for a refused thread. What `argon2` refuses is -25,
  where 0.1.0 gave -12, -14 or -5; no call through `Mhfe` reaches these.
- `NativeArgon2` and `Mhfe<NativeArgon2>` are no longer `UnwindSafe` or `RefUnwindSafe`.
- A debug build runs Argon2id unoptimized, about 16 times slower.
- Fixed: on Linux with kernel commit 97d34aa65c29, in Ubuntu from 7.0.0-39, a low `RLIMIT_MEMLOCK`
  ended the process at its first write to a `Secret`. It now takes anonymous pages.
- macOS: isolation also refuses file writes.
- The tests read specification 0.7.0's JSON vectors. A Windows clone no longer needs
  `core.autocrlf=false`.

A correction to 0.1.0: its cut point, commit `67e0b4c` of `mhfe`, is on no branch now; the same code
is at `3b58a02`, which differs only in `README.md`.

## 0.1.0 (2026-10-27)

This release implements the MHFE specification 0.7.0: suites `MHFE-BIP39-256-EXPERIMENTAL-3` and
`MHFE-BIP39-LP-EXPERIMENTAL-4` with Unicode 18.0.0 for passwords, and the profiles
MHFE-WALLET-CHECK-SEED-1, MHFE-REPAIR-1 and MHFE-PASSWORD-CHECK-1. Its tests replay the
specification's test vectors, which they read from the specification's repository.

It replaces an earlier 0.1.0 of this crate, which was withdrawn from crates.io.

The code was cut from the `mhfe` repository at commit `67e0b4c` (the code of mhfe 0.6.0, its
dependency update to Unicode 18.0.0 and the fixes that followed), and gives the same containers,
readings, repair words and check words. What came from where:

- The suites, from mhfe's `src/suite.rs`, `password.rs`, `phrase.rs`, `packing.rs`, `feistel.rs`,
  `mhfe.rs` and `detection.rs`. `Mhfe::encrypt` and `Mhfe::decrypt` each replace two steps, and
  the callbacks return `ControlFlow`.
- The Argon2id engine, from mhfe's `src/engine.rs`, `engine/ffi.rs`, `engine/native.rs` and
  `build.rs`, with the vendored Argon2 and EFF word list trees byte for byte. MHFE's wrapper
  `src/engine/argon2_wrap.c` replaces mhfe's `src/engine/argon2_simd.c` and clears the stack the
  vendored code leaves.
- The profiles, from mhfe's `src/wallet_check.rs`, `wallet.rs`, `repair.rs`, `check_word.rs` and
  `eff.rs`. The draw tries one phrase after another, where mhfe drew on several threads.
- The protections, from mhfe's `src/memory.rs`, the memory calls of its `src/engine/ffi.rs` and its
  `src/bin/mhfe/protect.rs`. New: secret memory on Linux, the filter's rules for file changes,
  other processes and `ioctl`s and its limit on newer calls, the protections of macOS and Windows,
  and `protect::write_secret`.
- The tests of the vectors, from mhfe's `tests/suite3_vectors.rs`, `suite4_vectors.rs`,
  `validation_cases.rs` and `vector_share/share.rs`, rewritten for this API without mhfe's vector
  generator. The workflows follow mhfe's; the gates, Node scripts in mhfe, are Rust here, as
  `cargo xtask` tasks, and dprint formats the documents instead of Prettier.
