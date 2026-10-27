//! Secret pages on Unix: a private anonymous mapping, locked with `mlock`; on Linux and Android kept
//! out of core dumps and given to a child process as zeros, on Apple systems not given to a child
//! at all. On Linux on x86-64 and AArch64, secret memory comes first where the kernel offers it.
//! The work area of Argon2id is such a mapping too. Every Unix system also shares the core-dump
//! limit of [`crate::protect::Isolation::enter`] and the secret writer.
#![allow(
    unsafe_code,
    reason = "mmap, mlock, getrlimit, setrlimit, madvise, minherit, munmap and write are foreign \
              functions"
)]

use std::io;
use std::ptr::{self, NonNull};

use super::Pages;

impl Pages {
    /// `bytes` bytes, at least one, in pages of their own.
    pub(crate) fn new(bytes: usize) -> Self {
        #[cfg(target_os = "linux")]
        if let Some(start) = super::linux::secret_pages(bytes) {
            // Secret memory is locked and out of core dumps by construction.
            return Self {
                start,
                bytes,
                locked: true,
                out_of_dumps: true,
            };
        }
        Self::anonymous(bytes, true).unwrap_or_else(|| super::out_of_memory(bytes))
    }

    /// The work area of Argon2id: anonymous pages as for a secret, never secret memory, or `None`
    /// when the system refuses them. They are locked only when RLIMIT_MEMLOCK holds all of them,
    /// which also commits them; a refused lock leaves them as they are.
    pub(crate) fn work_area(bytes: usize) -> Option<Self> {
        Self::anonymous(bytes, lock_limit_holds(bytes))
    }

    fn anonymous(bytes: usize, lock: bool) -> Option<Self> {
        // SAFETY: a new private anonymous mapping, at an address the kernel chooses, takes no
        // memory that anything else owns.
        let mapped = unsafe {
            libc::mmap(
                ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        let start = NonNull::new(mapped.cast::<u8>()).filter(|_| mapped != libc::MAP_FAILED)?;
        // SAFETY: mlock only changes how the kernel keeps the pages of the mapping just made; a
        // refusal, such as beyond RLIMIT_MEMLOCK, leaves them as they are.
        let locked = lock && unsafe { libc::mlock(start.as_ptr().cast(), bytes) } == 0;
        Some(Self {
            start,
            bytes,
            locked,
            out_of_dumps: advise(start, bytes),
        })
    }

    pub(crate) fn is_out_of_dumps(&self) -> bool {
        self.out_of_dumps
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: the mapping belongs to this value alone and nothing borrows it any more;
        // unmapping it also unlocks it.
        unsafe { libc::munmap(self.start.as_ptr().cast(), self.bytes) };
    }
}

/// Whether RLIMIT_MEMLOCK lets this process lock `bytes` bytes, counted alone.
fn lock_limit_holds(bytes: usize) -> bool {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the limit into the struct it is given.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } == 0;
    // RLIM_INFINITY is the largest value, so no size exceeds it.
    read && libc::rlim_t::try_from(bytes).is_ok_and(|bytes| bytes <= limit.rlim_cur)
}

/// Keeps the pages out of core dumps and gives a child process zeros instead of them (Linux 4.14
/// and later, which nothing reports when an older kernel refuses). Returns whether the dump
/// exclusion holds.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn advise(start: NonNull<u8>, bytes: usize) -> bool {
    // SAFETY: madvise marks the pages of a mapping this process owns and changes no content.
    unsafe { libc::madvise(start.as_ptr().cast(), bytes, libc::MADV_WIPEONFORK) };
    // SAFETY: as above.
    unsafe { libc::madvise(start.as_ptr().cast(), bytes, libc::MADV_DONTDUMP) == 0 }
}

/// Leaves the pages out of a child process. No call keeps single pages out of a core dump here;
/// the process as a whole writes none once it is isolated.
#[cfg(target_vendor = "apple")]
fn advise(start: NonNull<u8>, bytes: usize) -> bool {
    // SAFETY: minherit changes only what a child process inherits of a mapping this process owns.
    unsafe { libc::minherit(start.as_ptr().cast(), bytes, libc::VM_INHERIT_NONE) };
    false
}

/// Other Unix systems lock the pages only.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn advise(_start: NonNull<u8>, _bytes: usize) -> bool {
    false
}

/// Sets both limits of RLIMIT_CORE to 0, so that a crash writes no core file and the limit cannot
/// be raised again, and returns whether they read back so.
pub(super) fn forbid_core_dumps() -> bool {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads the struct, which lives for the call.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: getrlimit writes the struct, which lives for the call.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } == 0;
    read && (limit.rlim_cur, limit.rlim_max) == (0, 0)
}

/// Writes `text` to descriptor 1 with `write(2)`, again after an interruption and for what a
/// partial write left.
pub(crate) fn write_secret(text: &str) -> io::Result<()> {
    let mut rest = text.as_bytes();
    while !rest.is_empty() {
        // SAFETY: write reads at most `rest.len()` bytes of `rest`, which lives for the call.
        let written = unsafe { libc::write(libc::STDOUT_FILENO, rest.as_ptr().cast(), rest.len()) };
        match usize::try_from(written) {
            // As `Write::write_all` does: a write that takes nothing would be asked again forever.
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => rest = &rest[written..],
            Err(_) => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}
