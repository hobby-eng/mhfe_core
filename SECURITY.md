# Security

mhfe-core is experimental research software. Independent cryptographers have not reviewed its
construction, so do not use it to protect real funds. Passing tests and matching vectors do not show
that the construction is secure. The [specification](https://github.com/hobby-eng/mhfe-spec) and the
documentation of each item describe the protocol and its limits, such as suite 4's missing password
check and the 16 bits of the wallet check.

Report a suspected vulnerability privately through
[GitHub's security advisory form](https://github.com/hobby-eng/mhfe_core/security/advisories/new).
Never include a real seed phrase, password, private key or wallet file.

## Secrets in memory

Every secret the crate holds lives in a `protect::Secret`. A `Secret` has whole memory pages of its
own, shared with no other data, keeps a fixed size and is overwritten when it is dropped. This
covers the encoded password, the text of every phrase, the entropy and the cipher's state, each
round's halves, message, salt, Argon2id key and mask, a BIP39 passphrase in NFKD, the BIP39 seed,
the word numbers of a repair and what it changed, the word indexes of a password check, and the
entropy of each trial of a draw.

A password or passphrase is normalized (NFKD) directly into its `Secret`, so no copy of it reaches
ordinary memory: `tests/secret_memory.rs` counts the heap allocations while this happens and finds
none. Each typed word is read into an 8-byte buffer on the stack, which is wiped afterwards, and a
longer word is refused without being copied. Repair words are computed on the stack too.

The `blake2`, `hmac` and `sha2` libraries wipe their internal state when they finish. The `bip39`
library does not: when it reads or writes a phrase or computes a seed, its intermediate values stay
on the stack. So every round, and every public function that computes with a secret, overwrites 128
KiB of the stack below its frame when it is done. The exceptions are `Repaired::changes` and the
functions of `protect` and the engine. How deep these calls write has not been measured, so this is
best effort. Such a call needs about 140 KiB of free stack: on a smaller thread stack, such as
musl's default of 128 KiB, it ends the process.

Argon2id runs on four threads of the engine's own, the lanes and the first and last hash, so the
caller's stack stays out of it. RustCrypto's `argon2` keeps H0, its hashes and the blocks of its
compression on those stacks and does not promise to wipe them. After every call each thread
therefore overwrites 128 KiB of its stack, and the thread that held H0 starts above the frames of
the hash. A test on Linux shows that no block of a call stays on those stacks. Measured on x86-64,
the code writes about 11 KiB deep in a release build and 89 KiB in an unoptimized one.

The Argon2id work area, 2 GiB or more, lies on pages of its own. They are left out of core dumps on
Linux, Android and Windows, and out of a child process on Linux, Android, macOS and iOS. Windows
gives a process 512 such exclusions of less than 4 GiB each, which every live `Secret` shares, so
there the area is left out only as far as they reach: never at memory levels 20 and 21, and not
while about 500 `Secret`s are alive. `NativeArgon2::is_out_of_dumps` says whether all of it is. The engine
wipes the area after every call, whether the call succeeded or not. The area is locked only where
the limit on locked memory holds all of it: `RLIMIT_MEMLOCK` on Unix, 8 MiB by default on Linux
since 5.16, or a working set that Windows lets grow by its size. `NativeArgon2::is_locked` says
whether it is. Anyone who reads its blocks can test a password guess cheaply, so a swap area that
can hold them must be encrypted.

No secret leaves the crate except the results a program asks for. Every type that holds a secret
prints as hidden in `Debug` and has no `Display`. Errors carry counts, positions, settings and the
reference implementation's error numbers, never text that was passed in.

## What the crate cannot protect

- The text a program passes in, and what it does with a result. A `String` read from a terminal is
  neither locked nor wiped, and a copy of `Phrase::as_str` is the program's own. A program should
  read secrets into a `Secret` and show them with `protect::write_secret`.
- The unchecked container. `Mhfe::encrypt` shows it to `on_unchecked` before its creation check, and
  only the program can keep a copy, and its repair card, from being released before `encrypt`
  returns `Ok(ControlFlow::Continue(_))`. After `Break` they stay unchecked.
- A process that is ended, which the specification allows at any moment. Its memory is not wiped:
  the system discards it.
- Hibernation, which writes locked pages and the work area to disk. On Linux the kernel refuses to
  hibernate while a `Secret` in secret memory exists. Elsewhere, use an encrypted disk or no
  hibernation.
- Free memory. `NativeArgon2::new` reserves the work area without estimating what is free, and a
  reservation the system grants can still end the process when it is used (overcommit, the
  out-of-memory or low-memory killer, jetsam). The program checks free memory first.

## Each system

`protect::Isolation::enter()` applies what the system offers, for good, and reads each protection
back. A field of its report is true only when that reading confirmed it, and a refusal shows as
`false`, never as an error. On every system, descriptors and handles opened before the call, such as
a socket or a file open for writing, stay usable, so the computer must still be trusted and offline.

### Linux

On x86-64 and AArch64, a `Secret` uses the kernel's secret memory (`memfd_secret`, on by default
since Linux 6.5) where it is offered. Its pages leave the kernel's direct map, so no process, root
included, can read them directly through `/proc/PID/mem`, `process_vm_readv` or `PTRACE_PEEKDATA`.
They never reach swap, stay out of core dumps and are not given to a child process. Otherwise, and
on other architectures, a `Secret` uses anonymous pages with `mlock`, `MADV_DONTDUMP` and
`MADV_WIPEONFORK` (Linux 4.14 and later).

Both kinds count against `RLIMIT_MEMLOCK`, and on newer kernels secret memory counts for all of the
user's processes together. A `Secret` beyond the limit takes anonymous pages, and
`Secret::is_locked` reports a lock that was refused.

Isolation applies:

- `RLIMIT_CORE` 0 and `PR_SET_DUMPABLE` 0, which also keeps other programs of the user from `ptrace`
  and `/proc/PID/mem`.
- `PR_SET_NO_NEW_PRIVS`.
- On x86-64 and little-endian AArch64, a seccomp filter. It refuses with `EACCES` new sockets,
  io_uring, `ptrace`, `process_vm_writev`, `pidfd_getfd`, every call that changes the file system
  and every `ioctl` but the terminal's, and it answers `ENOSYS` to `openat2` and to every call newer
  than Linux 7.0.
- Landlock where the kernel has it (5.13 and later), which refuses writing, creating, removing and
  renaming files, on newer kernels also truncating them and device `ioctl`s, and from Linux 6.7 also
  TCP bind and connect.

These hold for the calling thread and the threads it starts, such as its engine's lanes. Called
while the process has one thread, they hold for the whole process, which then also enters a user and
network namespace of its own where the system allows it. No ID map is written, so `getuid()` and
`getgid()` read 65534 afterwards.

The filter allows `ftruncate`, which sizes the secret memory of every `Secret`; it changes only a
file that was open for writing before the call. A program that needs another `ioctl` in an isolated
thread is refused it, such as `FIONBIO`, which the standard library's `Command::output` uses.

Isolation does not cover:

- Root and `CAP_SYS_PTRACE`.
- A `/proc/PID/mem` descriptor opened or a tracer attached before the call, such as a debugger the
  process was started under.
- On architectures without the filter, what only the filter refuses: new sockets, io_uring, modes,
  owners, extended attributes, times and the `ioctl`s on files that are not devices (fs-verity,
  encryption policies, btrfs subvolumes). On a kernel without Landlock, also `ptrace`,
  `process_vm_writev` and `pidfd_getfd` on other processes.

### Android

A `Secret` uses anonymous pages with `mlock`, `MADV_DONTDUMP` and `MADV_WIPEONFORK`, within the
app's limit on locked memory. It never uses secret memory, which the app's seccomp policy forbids.

Isolation applies the same dump settings and filter as on Linux, without Landlock, the namespace or
any io_uring call, at which the app's policy would end the process. The filter holds for the calling
thread only. That thread must be a native thread of its own: made with `pthread_create`, never
attached to the virtual machine, never running Java, reporting progress through shared memory rather
than JNI, and ending with the operation. The only barrier of the whole app against the network is to
have no `INTERNET` permission.

On a crash, Android's crash handler makes the process dumpable again for `crash_dump`, whose
tombstone holds the registers and the memory near them. CI only builds the code for Android; it has
not run on a device.

### macOS

A `Secret` uses anonymous pages with `mlock`, which a child process does not get
(`minherit(VM_INHERIT_NONE)`). No call keeps single pages out of a core dump.

Isolation, for the whole process, sets `RLIMIT_CORE` to 0, calls `ptrace(PT_DENY_ATTACH)` and enters
a sandbox without network or file writes, except for the terminal and `/dev/null`. The call to
`ptrace` would end a process that a debugger already traces, so it is skipped there and
`no_memory_reading` is false. Otherwise the kernel's answer stands in for a reading back, which no
public call allows.

Isolation does not cover root or a process started under a debugger.

### iOS

A `Secret` works as on macOS, though whether `mlock` holds on a device has not been checked.
Isolation can only set `RLIMIT_CORE` to 0: an app can neither refuse a debugger nor narrow its
sandbox, which already keeps its writes inside its own container. CI only builds the code for iOS;
it has not run on a device.

### Windows

A `Secret` uses `VirtualAlloc` and is locked with `VirtualLock` after the working set has grown once
by 1 MiB. It is left out of Windows Error Reporting dumps by `WerRegisterExcludedMemoryBlock`, given
back when the `Secret` is dropped, since a process holds 512 such entries.

Isolation, for the whole process, applies:

- Error reports leave out the heap.
- The access list of the process becomes one entry for its owner, granting only waiting for it,
  reading its basic information and ending it. A program of the same user can then neither open it
  to read its memory nor restore the list.
- The access list of every thread becomes one entry for its owner, granting only waiting for it and
  reading its basic information and its list. The token's default access list becomes that entry
  too, so threads started afterwards, the Argon2id lanes among them, get it as well. A program of
  the same user can open none of them to read or change its registers, suspend it or change its
  list.
- The process token drops to low integrity, which refuses writes to the user's files and registry,
  for child processes too. Low-integrity folders stay writable, and so do volumes without access
  control, such as FAT and exFAT USB sticks and SD cards.

This has side effects. Every object that the process, or a process it starts, creates after the call
without an access list of its own (threads, pipes, events and others) gets the default list, so
opening it by name or ID, from the process itself too, grants little more than waiting for it.
Programs of the same user can also suspend and resume a process it starts, since on a process the
entry's `THREAD_QUERY_LIMITED_INFORMATION` bit means `PROCESS_SUSPEND_RESUME`. The process cannot,
for instance, run a child with piped standard streams (the standard library's `Command::output`), as
in an isolated thread on Linux. A thread started after the call cannot suspend itself or change its
own context through `GetCurrentThread()`, as some runtimes need.

Isolation does not cover:

- Administrators (`SeDebugPrivilege`).
- The threads' stacks and registers, which an error report still holds.
- Handles opened before the call, such as the parent's from `CreateProcess`, which a program of the
  same user can duplicate from the parent.
- Sockets, which only administrators can restrict.

### WebAssembly

A `Secret` is an ordinary heap buffer, wiped when it is dropped. Isolation applies nothing, and
every field of its report is false. The Argon2id engine and its memory belong to the host.

## Unsafe Rust and failures

Rust checks memory safety by itself, and the library forbids switching that off, except for calls to
the operating system and for one function that hands memory to Argon2. Each of these places explains
in a comment why it is safe.

If the system refuses Argon2's memory, or a call asks for more than was reserved, the library
reports `Error::OutOfMemory`. Any other Argon2 failure is `Error::Argon2Failed`, with an error
number from the list of the reference Argon2 code.
