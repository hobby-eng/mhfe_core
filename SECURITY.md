# Security

mhfe-core is experimental research software. Independent cryptographers have not reviewed its
construction. Passing tests and matching vectors do not show that the construction is secure. The
[specification](https://github.com/hobby-eng/mhfe-spec) and the documentation of each item describe
the protocol and its limits, such as suite 4's missing password check and the 16 bits of the wallet
check.

Report a suspected vulnerability privately through
[GitHub's security advisory form](https://github.com/hobby-eng/mhfe_core/security/advisories/new).
Never include a real seed phrase, password, private key or wallet file.

## Secrets in memory

Every secret the crate holds lives in a `protect::Secret`. On Unix and Windows a `Secret` has whole
memory pages of its own, shared with no other data; in WebAssembly it is an ordinary heap buffer. It
keeps a fixed size and is overwritten when it is dropped. This
covers the encoded password, the text of every phrase, the entropy and the cipher's state, each
round's halves, message, salt, Argon2id key and mask, a BIP39 passphrase in NFKD, the BIP39 seed,
the word numbers of a repair and what it changed, and the word indexes of a password check.

A password or passphrase is normalized (NFKD) directly into its `Secret`, so no copy of it reaches
ordinary memory: `tests/secret_memory.rs` counts the heap allocations while this happens and finds
none. Each typed word is read into an 8-byte buffer on the stack, which is wiped afterwards, and a
longer word is refused without being copied. Repair words are computed on the stack too.

The `blake2`, `hmac` and `sha2` libraries wipe their internal state when they finish. The `bip39`
library does not: when it reads or writes a phrase or computes a seed, its intermediate values stay
on the stack. So every round, and every public function that computes with a secret, overwrites 128
KiB of the stack below its frame when it is done. The exceptions are `Repaired::changes` and the
functions of `protect` and the engine. How deep these calls write has not been measured, so this is
best effort. Such a call needs up to 144 KiB of free stack, the repair calls the most, as
reed-solomon-core clears inside them too: on a smaller thread stack, such as musl's default of 128
KiB, it ends the process. In WebAssembly nothing is overwritten, as a stack
that runs over there has no guard page and would write into other memory: what these functions
leave stays in the instance's memory until later calls overwrite it or the host ends the instance.

Argon2id runs on four threads of the engine's own, the lanes and the first and last hash, so the
caller's stack stays out of it. RustCrypto's `argon2` keeps H0, its hashes and the blocks of its
compression on those stacks and does not promise to wipe them. After every call each thread
therefore overwrites 128 KiB of its stack, and the thread that held H0 starts above the frames of
the hash. A test on Linux shows that no block of a call stays on those stacks. Measured on x86-64,
the code writes about 11 KiB deep in a release build and 89 KiB in an unoptimized one.

The Argon2id work area, 2 GiB or more, lies on pages of its own. They are left out of core dumps on
Linux, Android and Windows, and out of a child process on Linux, Android, macOS and iOS. Windows
gives a process 512 such exclusions of less than 4 GiB each, which every live `Secret` shares, so
there the area is left out only as far as they reach: never whole at memory levels 20 and 21, and at
lower levels not once live `Secret`s have taken the entries it needs.
`NativeArgon2::is_out_of_dumps` says whether all of it is. The engine wipes the area after every
call, whether the call succeeded or not. The area is locked only where the system lets all of it be
locked: on Unix when `RLIMIT_MEMLOCK` holds it, 8 MiB by default on Linux since 5.16, and on Windows
when `VirtualLock` takes it after the working set was asked to grow by its size.
`NativeArgon2::is_locked` says whether it is. Anyone who reads
its blocks can test a password guess cheaply, so a swap area that can hold them must be encrypted.

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
- The settings of an operation. While Argon2id runs, another process can see how much memory the
  process uses, on Linux in `/proc/PID/status` even when it cannot read the memory itself, and from
  it the memory level; the time each round takes then gives the PIM. The specification lets the
  settings be kept secret like part of the password; such a secret holds only while no other process
  watches the computer, or where the system hides other processes' details, as Linux's `hidepid`
  does.

## Each system

`protect::Secret`, `protect::Isolation::enter()` and `protect::write_secret` are those of
[secret-protection-core](https://github.com/hobby-eng/secret-protection-core) 0.2: its
[security policy](https://github.com/hobby-eng/secret-protection-core/blob/v0.2.0/SECURITY.md) and
[technical guide](https://github.com/hobby-eng/secret-protection-core/blob/v0.2.0/docs/TECHNICAL.md)
say what each system offers a `Secret`, what isolation applies there, for which threads, and what it
does not cover. A field of the isolation report is true only when reading the protection back
confirmed it, and a refusal shows as `false`, never as an error. On every system, descriptors and
handles opened before the call, such as a file open for writing or a connected socket, stay usable
for reading and writing, so the computer must still be trusted and offline; on Linux with the filter
a socket can no longer connect, bind, listen or accept.

What this crate adds to it:

- The engine's four threads, the Argon2id lanes, start in `NativeArgon2::new`. A program calls
  `Isolation::enter()` before it, while it has one thread, so that the protections hold for the
  whole process, the lanes included. On Linux it also lets every `Secret` try the kernel's secret
  memory: secret-protection-core decides that once, at an `enter()` made while the process has one
  thread or at the first `Secret`, whichever comes first, and only a process of one thread then
  may. A `Secret` gets it on x86-64 and AArch64 where the kernel offers it and grants the pages.
  Otherwise it lies on anonymous pages, which root can read. secret-protection-core tries to lock
  them with `mlock`, and a refusal, such as one over the lock limit, leaves them unlocked:
  `Secret::is_locked` tells, and `Secret::locked` refuses a secret that would not be locked.
- `Isolation::enter()` applies every protection that has no option of its own: the dump settings of
  each system; on Linux and Android the seccomp filter where there is one and a request to limit
  speculation, on Linux also Landlock and the namespaces; on macOS the sandbox and the refusal of a
  debugger, while `no_memory_reading` holds there only for a program signed with the hardened
  runtime and without `get-task-allow`; on Windows the access lists, low integrity, the job and the
  mitigation policies, side-channel isolation among them. A speculation limit or side-channel policy
  that the system applies cannot be undone and may cost speed, Argon2id's too; the report's
  `speculation_limited` says whether one holds. These already refuse starting another program where
  they hold, on Windows writing the clipboard, and from Linux 6.12 signals to processes outside the
  Landlock layer. The options stay off: refusing file locks and `sendmsg`, signals only to the
  process itself, locking all memory, refusing new executable code, loading only DLLs that Microsoft
  signed, and putting the filter on threads that already run. A program that needs one takes
  secret-protection-core itself, exactly the version this crate pins (0.2.0), and calls
  `Isolation::enter_with` with its `Options`.
- In WebAssembly a `Secret` is an ordinary heap buffer, wiped when it is dropped, and the stack is
  not cleared after a call. Ending the instance, after an operation or after a session of several,
  frees what the stack held, though nothing promises that the memory is overwritten. Isolation
  applies nothing there, and the Argon2id engine and its memory belong to the host.

## Unsafe Rust and failures

Rust checks memory safety by itself, and the library forbids switching that off, except for one
function that hands memory to Argon2, which explains in a comment why it is safe. The calls to the
operating system are secret-protection-core's, each with its own such comment.

If the system refuses Argon2's memory, or a call asks for more than was reserved, the library
reports `Error::OutOfMemory`. Any other Argon2 failure is `Error::Argon2Failed`, with an error
number from the list of the reference Argon2 code.

## Release workflow

A version tag runs the fast checks and the fuzz targets, then three jobs with the rights each needs
and no more. The package job builds and checks the package with read access only; its check runs
the build scripts of the crate and its dependencies, so it chooses the bytes that are attested. The
attestation job holds `id-token: write` and `attestations: write`, with which it could also sign
another file of this repository, and runs no code of the repository. The draft job holds
`contents: write`, with which it could also push to a branch or move a tag or a release, and runs
only `gh` on the files the package job made. No narrower token scope exists for either; the
maintainer checks the tag's signature, the package and its attestation before publishing.
