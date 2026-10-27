//! The operating-system calls behind [`crate::protect`], each system in a module of its own.
//!
//! [`Pages`] is the memory of one [`crate::protect::Secret`], or the work area of Argon2id: whole
//! pages of its own, which no other data shares, so that what is asked of them touches nothing
//! else. They are zero when made; their owner wipes them before they are dropped and given back.
//! Each system's module maps, locks, advises and unmaps them and keeps what it reports; reading
//! and writing them is written once, here. The modules also apply and read back the protections
//! of [`crate::protect::Isolation::enter`], and write a secret to standard output.

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(target_vendor = "apple")]
pub(crate) use apple::enter;
#[cfg(not(any(unix, windows)))]
pub(crate) use heap::Pages;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::enter;
#[cfg(unix)]
pub(crate) use unix::write_secret;
#[cfg(windows)]
pub(crate) use windows::{enter, write_secret};

/// Where this crate knows no protection of the process, as in WebAssembly, it applies none.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
pub(crate) fn enter() -> crate::protect::Isolation {
    crate::protect::Isolation::default()
}

/// Pages that a system's module mapped: `bytes` bytes from `start`, which belong to this value
/// alone.
#[cfg(any(unix, windows))]
pub(crate) struct Pages {
    start: std::ptr::NonNull<u8>,
    bytes: usize,
    locked: bool,
    /// Whether the pages are left out of core dumps.
    #[cfg(unix)]
    out_of_dumps: bool,
    /// The blocks registered with Windows Error Reporting, which holds 512 per process.
    #[cfg(windows)]
    excluded: usize,
    /// What the working set grew by for these pages alone, given back on drop.
    #[cfg(windows)]
    raised: usize,
}

#[cfg(any(unix, windows))]
#[allow(
    unsafe_code,
    reason = "the mapped pages are reached through a raw pointer"
)]
impl Pages {
    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: the pages hold `bytes` initialized bytes (the system fills them with zeros),
        // belong to this value alone and live as long as it.
        unsafe { std::slice::from_raw_parts(self.start.as_ptr(), self.bytes) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as for `as_slice`; the exclusive borrow of `self` rules out any other access.
        unsafe { std::slice::from_raw_parts_mut(self.start.as_ptr(), self.bytes) }
    }

    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }
}

#[cfg(any(unix, windows))]
#[allow(
    unsafe_code,
    reason = "a raw pointer is neither Send nor Sync by itself"
)]
// SAFETY: the pages belong to one value; moving it to another thread moves the only handle, and
// a shared reference only reads them.
unsafe impl Send for Pages {}
#[cfg(any(unix, windows))]
#[allow(
    unsafe_code,
    reason = "a raw pointer is neither Send nor Sync by itself"
)]
// SAFETY: as for `Send`.
unsafe impl Sync for Pages {}

/// Ends the process as a full heap does, for pages the system cannot give.
#[cfg(any(unix, windows))]
fn out_of_memory(bytes: usize) -> ! {
    let layout = std::alloc::Layout::array::<u8>(bytes).unwrap_or(std::alloc::Layout::new::<u8>());
    std::alloc::handle_alloc_error(layout)
}

/// Where there are no pages to ask for, such as in WebAssembly: an ordinary heap buffer, wiped
/// like the others but never locked or kept out of anything.
#[cfg(not(any(unix, windows)))]
mod heap {
    pub(crate) struct Pages(Box<[u8]>);

    impl Pages {
        pub(crate) fn new(bytes: usize) -> Self {
            Self(vec![0; bytes].into_boxed_slice())
        }

        pub(crate) fn as_slice(&self) -> &[u8] {
            &self.0
        }

        pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.0
        }

        pub(crate) fn is_locked(&self) -> bool {
            false
        }

        pub(crate) fn is_out_of_dumps(&self) -> bool {
            false
        }
    }
}
