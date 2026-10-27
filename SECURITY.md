# Security

mhfe-core is experimental research software. Its construction has not been reviewed by
independent cryptographers; do not use it to protect real funds. A passing test or a matching
vector does not show that the construction is secure. The protocol and its limits, such as suite
4's missing password check or the 16 bits of the wallet check, are described in the
[specification](https://github.com/hobby-eng/mhfe-spec) and in the documentation of each item.

Report a suspected vulnerability privately through GitHub's security advisories for this
repository. Never include a real seed phrase, password, private key or wallet file.

## Secrets in memory

- Every secret the crate holds lives in a `protect::Secret`: whole memory pages of its own, which
  no other data shares, of a fixed size that never grows, overwritten when the `Secret` is dropped.
  These are the encoded password; the text of every phrase; the entropy and the cipher's state;
  each round's halves, message, salt, Argon2id key and mask; a BIP39 passphrase in NFKD and the
  BIP39 seed; the word numbers of a repair and what it changed; the word indexes of a password
  check; and the entropy of each trial of a draw.
- The NFKD of a password or a passphrase is written straight into its `Secret`, and a test shows
  that neither takes memory from the heap. A typed word is read in an 8-byte array on the stack,
  which is wiped; a longer token is refused without a copy. The repair words are computed in
  arrays on the stack, which the stack clear below overwrites.
- The hash and MAC states of `blake2`, `hmac` and `sha2` are wiped when they are dropped. The
  `bip39` crate keeps its parsing and encoding states and its PBKDF2 states on the stack and does
  not wipe them, so every public function that computes with a secret, but `Repaired::changes` and
  those of `protect` and the engine, and every round, overwrites 128 KiB of the stack below its
  frame when it is done. How deep these calls write is not measured: this is best effort. Such a
  call therefore needs about 140 KiB of free stack: on a smaller thread stack, such as musl's
  default of 128 KiB, it ends the process.
- MHFE's wrapper around the vendored Argon2 C code overwrites 16 KiB of the stack after every
  segment on each lane thread and after every call on the calling thread.
  `cargo xtask argon2-stack` measures on Linux that the vendored code writes about 6 KiB deep
  and that no byte it wrote stays.
- The Argon2id work area, 2 GiB or more, lies on pages of its own, left out of core dumps on Linux,
  Android and Windows and out of a child process on Linux, Android, macOS and iOS. The C code wipes
  it at the end of every successful call, and the crate after a failed one. It is locked only where
  the limit on locked memory holds all of it (`RLIMIT_MEMLOCK` on Unix, 8 MiB by default on Linux
  since 5.16; a working set Windows lets grow by its size); `NativeArgon2::is_locked` says whether.
  Its blocks let anyone who reads them test a password guess cheaply, so a swap area that can hold
  them must be encrypted.
- No secret leaves the crate but the results a program asks for. Every type that holds a secret
  prints as hidden in `Debug` and has no `Display`; errors carry counts, positions, settings and
  the reference code's return values, never text that was passed in.

What the crate cannot protect:

- The text a program passes in and what it does with a result: a `String` read from a terminal is
  neither locked nor wiped, and a copy of `Phrase::as_str` is the program's own. A program reads
  secrets into a `Secret` and shows them with `protect::write_secret`.
- `Mhfe::encrypt` shows the container to `on_unchecked` before its creation check; only the program
  can keep a copy from being released before `encrypt` returns `Ok`.
- A process that is ended, which the specification allows at any moment, is not wiped: the system
  discards its memory.
- Hibernation writes locked pages and the work area to disk. On Linux, the kernel refuses to
  hibernate while a `Secret` in secret memory exists; elsewhere, use an encrypted disk or no
  hibernation.
- `NativeArgon2::new` reserves the work area and estimates no free memory: a reservation the system
  grants can still end the process when it is used (overcommit, the out-of-memory or low-memory
  killer, jetsam). The program checks free memory first.

## Each system

`protect::Isolation::enter()` applies what the system offers, for good, and reads each protection
back: a field of the report is true only when reading it back confirmed it. A refusal of the
system shows as `false`, never as an error. Descriptors and handles opened before the call, such
as a socket or a file open for writing, stay usable on every system, so the computer is still to
be trusted and offline.

### Linux

- Secret pages: on x86-64 and AArch64, the kernel's secret memory (`memfd_secret`, on by default
  since Linux 6.5) where it is offered. Its pages leave the kernel's direct map, so that no process,
  root included, reads them directly through `/proc/PID/mem`, `process_vm_readv` or
  `PTRACE_PEEKDATA`; they are locked, out of core dumps and not given to a child process.
  Otherwise, and on other architectures, anonymous pages with `mlock`, `MADV_DONTDUMP` and
  `MADV_WIPEONFORK` (Linux 4.14 and later). Both count against `RLIMIT_MEMLOCK`; a lock it refuses
  is reported by `Secret::is_locked`.
- Isolation: `RLIMIT_CORE` 0 and `PR_SET_DUMPABLE` 0, which also keeps other programs of the user
  from `ptrace` and `/proc/PID/mem`; `PR_SET_NO_NEW_PRIVS`; on x86-64 and little-endian AArch64 a
  seccomp filter that refuses with `EACCES` new sockets, io_uring, `ptrace`, `process_vm_writev`,
  `pidfd_getfd`, every call that changes the file system and every `ioctl` but the terminal's, and
  answers `ENOSYS` to `openat2` and to every call newer than Linux 7.0; and Landlock where the
  kernel has it (5.13 and later), which refuses writing, creating, removing and renaming files, on
  newer kernels truncating them and device `ioctl`s, and from Linux 6.7 TCP bind and connect. They
  hold for the calling thread and the threads it starts, such as the Argon2id lanes. Called while
  the process has one thread, they hold for the whole process, which also enters a user and network
  namespace of its own where the system allows it: no ID map is written, so `getuid()` and
  `getgid()` read 65534 afterwards.
- The filter allows `ftruncate`, which sizes the secret memory of every `Secret`; it changes only a
  file that was open for writing before the call. A program that needs another `ioctl` in an
  isolated thread, such as `FIONBIO`, which the standard library's `Command::output` uses, is
  refused it.
- Not covered: root and `CAP_SYS_PTRACE`; a `/proc/PID/mem` descriptor opened or a tracer attached
  before the call, such as a debugger the process was started under; and on architectures without
  the filter (all but little-endian x86-64 and AArch64), what only the filter refuses: new sockets,
  io_uring, modes, owners, extended attributes, times and the `ioctl`s on files that are not
  devices (fs-verity, encryption policies, btrfs subvolumes), and on a kernel without Landlock
  `ptrace`, `process_vm_writev` and `pidfd_getfd` on other processes.

### Android

- Secret pages: anonymous pages with `mlock`, `MADV_DONTDUMP` and `MADV_WIPEONFORK`, within the
  app's limit on locked memory; never secret memory, which the app's seccomp policy forbids.
- Isolation: the same dump settings and filter as on Linux, without Landlock, the namespace or any
  io_uring call, at which the app's policy would end the process. The filter holds for the calling
  thread only, which must be a native thread of its own: made with `pthread_create`, never
  attached to the virtual machine, never running Java, reporting progress through shared memory
  rather than JNI, and ending with the operation. The only barrier of the whole app against the
  network is an app without the `INTERNET` permission.
- Not covered: on a crash, Android's crash handler makes the process dumpable again for
  `crash_dump`, whose tombstone holds the registers and memory near them. CI only builds the code
  for Android; it has not run on a device.

### macOS

- Secret pages: anonymous pages with `mlock`, not given to a child process
  (`minherit(VM_INHERIT_NONE)`). No call keeps single pages out of a core dump.
- Isolation, for the whole process: `RLIMIT_CORE` 0; `ptrace(PT_DENY_ATTACH)`, unless a debugger
  already traces the process, which the call would end (`no_memory_reading` is then false; the
  kernel's answer to the call stands for reading it back, which no public call allows); and the
  sandbox profile without network.
- Not covered: root, a process started under a debugger, and file changes.

### iOS

- Secret pages as on macOS; whether `mlock` holds on a device has not been checked.
- Isolation: `RLIMIT_CORE` 0 only. An app can neither refuse a debugger nor narrow its sandbox,
  which already keeps its writes inside its own container. CI only builds the code for iOS; it
  has not run on a device.

### Windows

- Secret pages: `VirtualAlloc`, locked with `VirtualLock` after the working set grew once by 1 MiB,
  and left out of Windows Error Reporting dumps (`WerRegisterExcludedMemoryBlock`, given back when
  the `Secret` is dropped, since a process holds 512 such entries).
- Isolation, for the whole process: error reports leave out the heap; the access list of the
  process is replaced by one entry for its owner, which grants only waiting for it, reading its
  basic information and ending it, so that a program of the same user can neither open it to read
  its memory nor restore the list; the access list of every thread is replaced by one entry for
  its owner that grants only waiting for it and reading its basic information and its list, and
  the token's default access list becomes that entry, so that the threads started afterwards, the
  Argon2id lanes among them, get it too: a program of the same user can open none of them to read
  or change its registers, suspend it or change its list; and the process token is lowered to low
  integrity, which refuses writes to the user's files and registry, of child processes too.
  Low-integrity folders stay writable, and so do volumes without access control, such as FAT and
  exFAT USB sticks and SD cards.
- Side effect: every object that the process, or a process it starts, creates after the call
  without an access list of its own (threads, pipes, events and others) gets the default list, so
  that opening it by name or ID, from the process itself too, grants little more than waiting for
  it; but programs of the same user can also suspend and resume a process it starts, since on a
  process the entry's `THREAD_QUERY_LIMITED_INFORMATION` bit means `PROCESS_SUSPEND_RESUME`. The
  process cannot, for instance, run a child with piped standard streams (the standard library's
  `Command::output`), as in an isolated thread on Linux, and a thread started after the call
  cannot suspend itself or change its own context through `GetCurrentThread()`, as some runtimes
  need.
- Not covered: administrators (`SeDebugPrivilege`); the threads' stacks and registers, which an
  error report still holds; handles opened before the call, such as the parent's from
  `CreateProcess`, which a program of the same user can duplicate from the parent; sockets, which
  only administrators can restrict.

### WebAssembly

A `Secret` is an ordinary heap buffer, wiped when it is dropped; isolation applies nothing, and
every field of its report is false. The host's own Argon2id engine and its memory are the host's.

## The C code and unsafe Rust

- Argon2 is the reference C implementation, vendored unchanged (see
  [`vendor/phc-winner-argon2.md`](vendor/phc-winner-argon2.md); `cargo xtask vendored` checks
  every file's SHA-256). MHFE's own C is `src/engine/argon2_wrap.c` with its header: Rust
  calls only its `mhfe_argon2_ctx()`, and its `fill_segment()` runs the renamed vendored one.
  The manifest's `links = "mhfe_argon2"` keeps two versions of this crate, and so two copies of
  these C symbols, out of one program.
- The library denies unsafe code (`#![deny(unsafe_code)]`) but in `src/engine/ffi.rs`, the binding
  of the C code, and in `src/os.rs` and `src/os/*.rs`, the system calls; each `unsafe` block says
  why it is sound. The binding's copy of `argon2_context` is checked field by field at compile
  time, and a test shows that every field reaches the C code.
- Every pointer handed to C refers to a live buffer of the stated length that outlives the call.
  The work area reaches C through the allocation callback; `argon2_ctx` joins its four lane threads
  before it returns. A refused allocation is `Error::OutOfMemory`, and any other failure
  `Error::Argon2Failed` with the reference code's return value.
