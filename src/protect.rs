//! Protection of secrets: [`Secret`], the buffer every secret of this crate lives in, which a host
//! uses for its own secrets too, such as a typed line or a row of output; [`Isolation`], what the
//! process does against a secret leaving it; and [`write_secret`], the output of a secret.

use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::io::{self, Write};

use zeroize::Zeroize;

use crate::Error;
use crate::os::Pages;

/// A buffer for secret bytes in whole memory pages of its own, which no other data shares. Where
/// the system allows it, the pages are locked in memory, so that they never reach swap, and kept
/// out of core dumps; a child process gets none of the bytes; and on drop they are overwritten
/// before they are unlocked and given back. Its capacity is fixed: it never grows, so it never
/// leaves a copy behind.
///
/// Per system: on Linux on x86-64 and AArch64 the pages are secret memory (`memfd_secret`) where
/// the kernel offers it, which no other process, root included, can read directly through
/// `/proc/PID/mem`, `process_vm_readv` or `PTRACE_PEEKDATA`, and which stops hibernation while it
/// exists; otherwise, on other Linux architectures and on Android, anonymous pages with `mlock`,
/// `MADV_DONTDUMP` and `MADV_WIPEONFORK`. macOS and iOS lock the pages and leave them out of a
/// child process; no call keeps these pages out of a core dump, which [`Isolation::enter`] refuses
/// for the process as a whole. Windows locks them with `VirtualLock` and leaves them out of
/// Windows Error Reporting dumps. In WebAssembly the buffer is an ordinary heap buffer, only
/// wiped. A refusal, such as a lock beyond `RLIMIT_MEMLOCK`, never fails: [`Secret::is_locked`]
/// and [`Secret::is_out_of_dumps`] report what holds.
pub struct Secret {
    pages: Pages,
    capacity: usize,
    len: usize,
}

impl Secret {
    /// An empty buffer that holds up to `bytes` bytes. Like a `Vec`, it ends the process when the
    /// system has no memory for it.
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            // mmap and VirtualAlloc refuse a length of zero.
            pages: Pages::new(bytes.max(1)),
            capacity: bytes,
            len: 0,
        }
    }

    /// Appends `bytes`, or refuses with [`Error::SecretFull`] and writes nothing when they do not
    /// fit.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let full = Error::SecretFull {
            capacity: self.capacity,
        };
        let end = self
            .len
            .checked_add(bytes.len())
            .filter(|&end| end <= self.capacity)
            .ok_or(full)?;
        self.pages.as_mut_slice()[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    /// Shortens the contents to `len` bytes and wipes what it cuts; a longer `len` changes
    /// nothing.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.pages.as_mut_slice()[len..self.len].zeroize();
            self.len = len;
        }
    }

    /// The bytes pushed so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.pages.as_slice()[..self.len]
    }

    /// The bytes as text, or `None` when they are not UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()).ok()
    }

    /// The most bytes it holds.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether the system keeps the pages in memory, never in swap.
    pub fn is_locked(&self) -> bool {
        self.pages.is_locked()
    }

    /// Whether the system leaves these pages out of the dumps it writes of the process.
    pub fn is_out_of_dumps(&self) -> bool {
        self.pages.is_out_of_dumps()
    }

    /// A buffer of `bytes` zero bytes, to be written in place.
    pub(crate) fn zeroed(bytes: usize) -> Self {
        let mut secret = Self::with_capacity(bytes);
        secret.len = bytes;
        secret
    }

    /// The bytes pushed so far, to change in place; as a slice, they cannot outgrow the buffer.
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.pages.as_mut_slice()[..self.len]
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Volatile writes, which the compiler keeps although nothing reads the bytes again.
        self.pages.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(hidden)")
    }
}

/// What holds against a secret leaving the process, as [`Isolation::enter`] read it back after it
/// applied what the system offers: a field is true only when reading it back confirmed it, so a
/// refusal of the system shows as false.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Isolation {
    /// On Unix a crash writes no core dump: RLIMIT_CORE is 0, and on Linux and Android the process
    /// is not dumpable, which a pipe in `core_pattern` respects too; on Windows, error reports,
    /// which still hold the threads' stacks and registers, leave out the heap.
    pub no_core_dumps: bool,
    /// Other programs of the same user cannot open the process to read or change its memory, nor
    /// on Windows its threads to read or change their registers.
    pub no_memory_reading: bool,
    /// No new socket can be opened, nor on Linux and Android an io_uring, which could open one; on
    /// macOS a socket can still be made, but the sandbox refuses to bind or connect it.
    pub no_new_sockets: bool,
    /// The process runs in a network namespace of its own, with only a loopback interface, which
    /// stays down, and no route (Linux).
    pub empty_network: bool,
    /// Files cannot be opened for writing, created, renamed or removed, apart from the exceptions
    /// [`Isolation::enter`] names for each system; what else is refused depends on the system too.
    pub no_file_changes: bool,
    /// The protections above cover every thread of the process, not only the calling one.
    pub whole_process: bool,
}

impl Isolation {
    /// Applies what this system offers against a secret leaving the process, for good, and returns
    /// what reads back as holding; call it before a secret is read. A refusal is reported, never
    /// an error. Descriptors and handles opened before the call stay usable, a socket or a file
    /// open for writing among them, so the computer is still to be trusted and offline.
    ///
    /// Linux: RLIMIT_CORE 0 and not dumpable, which also keeps other programs of the user from
    /// `ptrace` and `/proc/PID/mem`; `no_new_privs`; on x86-64 and little-endian AArch64 a seccomp
    /// filter that refuses with EACCES new sockets, io_uring, `ptrace`, `process_vm_writev`,
    /// `pidfd_getfd`, every call that changes the file system (opening for writing, creating,
    /// renaming, removing, linking, truncating by path, `fallocate`, modes, owners, extended
    /// attributes, times, `mount`) and every `ioctl` but the terminal's, and that answers ENOSYS to
    /// `openat2` and to every call newer than Linux 7.0, so that a C library falls back to a call
    /// the filter reads and a later kernel's call cannot get past it; and Landlock where the kernel
    /// has it, which refuses writing, creating, removing and renaming files, truncating them from
    /// Linux 6.2, TCP bind and connect from Linux 6.7 and device `ioctl`s from Linux 6.10. They
    /// hold for the calling thread and the threads it starts afterwards, such as the lanes of
    /// Argon2id. Called while the process has one thread, they hold for the whole process, which
    /// also enters a network namespace of its own where the system allows it: no ID map is written,
    /// so `getuid()` and `getgid()` read 65534 for the rest of the process, which holds every
    /// capability inside its new user namespace and none over the system's files. On other
    /// architectures, big-endian AArch64 included, only Landlock applies, which refuses no new
    /// socket and leaves open modes, owners, extended attributes, times and the `ioctl`s on files
    /// that are not devices, such as fs-verity, encryption policies and btrfs subvolumes. Not
    /// covered: root and `CAP_SYS_PTRACE`; and a `/proc/PID/mem` descriptor opened or a tracer
    /// attached before the call, such as a debugger the process was started under.
    ///
    /// Android: the same dump settings and filter, without Landlock, the namespace or any io_uring
    /// call: the app seccomp policy ends the process at such calls. The filter holds for the
    /// calling thread only (`whole_process` is false), which must be a native thread of its own:
    /// made with `pthread_create`, never attached to the virtual machine, never running Java,
    /// reporting progress through shared memory rather than JNI, and ending with the operation. A
    /// Java or Kotlin pool thread would go back to its pool restricted for good, its binder calls
    /// would fail, and the runtime's concurrent compaction makes a thread call `ioctl`
    /// (`UFFDIO_COPY`) from its SIGBUS handler, which the filter refuses. The only barrier of the
    /// whole app against the network is an app without the `INTERNET` permission. Not covered: on
    /// a crash, Android's crash handler makes the process dumpable again for `crash_dump`, whose
    /// tombstone holds the registers and memory near them.
    ///
    /// macOS, for the whole process: RLIMIT_CORE 0; `ptrace(PT_DENY_ATTACH)`, unless a debugger
    /// already traces the process, which the call would end (`no_memory_reading` is then false;
    /// otherwise the call's answer stands for a read-back); and the sandbox profile without
    /// network. Files are not restricted. Not covered: root.
    ///
    /// iOS: RLIMIT_CORE 0 only; an app can neither deny a debugger nor narrow its sandbox, which
    /// already keeps its writes inside its own container.
    ///
    /// Windows, for the whole process: error reports leave out the heap; the access list of the
    /// process is replaced by one entry for its owner (OWNER RIGHTS), which grants only waiting
    /// for it, reading its basic information and ending it, so that a program of the same user
    /// can neither open it to read its memory nor restore the list; the access list of every
    /// thread is replaced by one entry for its owner that grants only waiting for it and reading
    /// its basic information and its list, and the token's default list becomes that entry, so
    /// that the threads started afterwards, the lanes of Argon2id among them, get it too: a
    /// program of the same user can open none of them to read or change its registers, suspend
    /// it or change its list; and the process token is lowered to low integrity, which refuses
    /// writes to the user's files and registry, of a child process too (low-integrity folders and
    /// volumes without access control, such as FAT and exFAT USB sticks and SD cards, stay
    /// writable). Sockets are not restricted: that needs administrator rights. Side effect: every
    /// object that the process, or a process it starts, creates afterwards without an access list
    /// of its own (threads, pipes, events and others) gets the default list, so that opening it
    /// by name or ID, from the process itself too, grants little more than waiting for it; but
    /// programs of the same user can also suspend and resume a process it starts, since on a
    /// process the entry's THREAD_QUERY_LIMITED_INFORMATION bit means PROCESS_SUSPEND_RESUME. The
    /// process cannot, for instance, run a child with piped standard streams (the standard
    /// library's `Command::output`), as in an isolated thread on Linux, and a thread started
    /// afterwards cannot suspend itself or change its own context through `GetCurrentThread()`,
    /// as some runtimes need. Not covered: administrators (`SeDebugPrivilege`); the threads'
    /// stacks and registers, which an error report still holds; and handles opened before the
    /// call, such as the parent's from `CreateProcess`, which a program of the same user can
    /// duplicate from the parent.
    ///
    /// WebAssembly and other systems: nothing; every field is false.
    pub fn enter() -> Self {
        crate::os::enter()
    }
}

/// Writes `text` to standard output past the standard library's buffer, which is never wiped and
/// keeps the last bytes written to it: it flushes that buffer first, so that the public output
/// written before comes first, then writes the caller's bytes without a copy of its own (on a
/// Windows console, a UTF-16 copy in a [`Secret`]), again after an interruption and for what a
/// partial write left. For terminal programs: Android and iOS apps show a secret in their own
/// views.
#[cfg(not(target_arch = "wasm32"))]
pub fn write_secret(text: &str) -> io::Result<()> {
    io::stdout().flush()?;
    crate::os::write_secret(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pushed_bytes_stay_within_the_capacity() {
        let mut secret = Secret::with_capacity(8);
        secret.push(b"public").unwrap();
        assert_eq!(
            secret.push(b"bytes"),
            Err(Error::SecretFull { capacity: 8 })
        );
        assert_eq!(
            secret.as_bytes(),
            b"public",
            "a refused push writes nothing"
        );
        secret.push(b"!!").unwrap();
        assert_eq!(secret.as_str(), Some("public!!"));
        assert_eq!(secret.capacity(), 8);
        let mut empty = Secret::with_capacity(0);
        assert_eq!(empty.push(b""), Ok(()));
        assert_eq!(empty.push(b"x"), Err(Error::SecretFull { capacity: 0 }));
    }

    #[test]
    fn truncation_wipes_what_it_cuts() {
        let mut secret = Secret::with_capacity(16);
        secret.push(b"public test").unwrap();
        secret.truncate(6);
        assert_eq!(secret.as_bytes(), b"public");
        assert_eq!(
            &secret.pages.as_slice()[..16],
            b"public\0\0\0\0\0\0\0\0\0\0"
        );
        secret.truncate(10);
        assert_eq!(secret.as_bytes(), b"public");
        secret.push(&[0xff]).unwrap();
        assert_eq!(secret.as_str(), None);
    }

    /// One page fits any usual RLIMIT_MEMLOCK (64 KiB or more) and any working set.
    #[test]
    fn a_secret_is_locked_and_out_of_dumps_where_the_system_allows() {
        let secret = Secret::with_capacity(1024);
        assert_eq!(secret.is_locked(), cfg!(any(unix, windows)));
        assert_eq!(
            secret.is_out_of_dumps(),
            cfg!(any(target_os = "linux", target_os = "android", windows))
        );
    }

    #[test]
    fn debug_output_hides_the_bytes() {
        let mut secret = Secret::with_capacity(8);
        secret.push(b"public").unwrap();
        assert_eq!(format!("{secret:?}"), "Secret(hidden)");
    }
}
