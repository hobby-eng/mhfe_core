//! macOS and iOS: the protections of [`crate::protect::Isolation::enter`], each for the whole
//! process. macOS refuses a debugger and enters a sandbox without network or file writes; iOS offers
//! an app neither, so there only the core-dump limit applies.
#![allow(
    unsafe_code,
    reason = "sysctl, ptrace and sandbox_init are foreign functions"
)]

use crate::protect::Isolation;

pub(crate) fn enter() -> Isolation {
    let no_core_dumps = super::unix::forbid_core_dumps();
    #[cfg(target_os = "macos")]
    let (no_memory_reading, (no_new_sockets, no_file_changes)) =
        (macos::refuse_debuggers(), macos::enter_sandbox());
    #[cfg(not(target_os = "macos"))]
    let (no_memory_reading, no_new_sockets, no_file_changes) = (false, false, false);
    Isolation {
        no_core_dumps,
        no_memory_reading,
        no_new_sockets,
        no_file_changes,
        whole_process: true,
        ..Isolation::default()
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::ptr;

    unsafe extern "C" {
        fn sandbox_init(
            profile: *const libc::c_char,
            flags: u64,
            error: *mut *mut libc::c_char,
        ) -> libc::c_int;
        fn sandbox_free_error(error: *mut libc::c_char);
    }

    /// The sandbox: no network and no file writes, but for the terminal. Descriptors opened before
    /// it stay usable.
    const PROFILE: &std::ffi::CStr = c"(version 1)(allow default)(deny network*)(deny file-write*)\
        (allow file-write* (literal \"/dev/null\") (literal \"/dev/tty\") \
        (regex #\"^/dev/ttys[0-9]+$\"))";
    /// P_TRACED of sys/proc.h, as `kern.proc.pid` reports it in `kp_proc.p_flag`.
    const TRACED: i32 = 0x0000_0800;

    /// Refuses a debugger from now on (`PT_DENY_ATTACH`), and returns whether the kernel agreed.
    /// A process that a debugger already traces would end at the call, with ENOTSUP, so it is left
    /// as it is. No public call reads the refusal back: the kernel's answer stands for it.
    pub(super) fn refuse_debuggers() -> bool {
        if traced() != Some(false) {
            return false;
        }
        // SAFETY: PT_DENY_ATTACH takes no process, address or data and touches no memory.
        unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, ptr::null_mut(), 0) == 0 }
    }

    /// Whether a debugger traces this process, as `kern.proc.pid` reports it.
    fn traced() -> Option<bool> {
        /// The size of `struct kinfo_proc` (sys/sysctl.h) on a 64-bit system, and the offset of
        /// `kp_proc.p_flag` in it (sys/proc.h), after a 16-byte union and two pointers.
        const KINFO_PROC_BYTES: usize = 648;
        const FLAG: usize = 32;
        let pid = libc::c_int::try_from(std::process::id()).ok()?;
        let mut name = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        let mut info = [0u8; KINFO_PROC_BYTES];
        let mut size = info.len();
        // SAFETY: sysctl reads the four parts of the name and writes at most `size` bytes into
        // `info` and their number into `size`, all of which live for the call.
        let read = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                4,
                info.as_mut_ptr().cast(),
                &mut size,
                ptr::null_mut(),
                0,
            )
        } == 0;
        let flags =
            i32::from_ne_bytes([info[FLAG], info[FLAG + 1], info[FLAG + 2], info[FLAG + 3]]);
        (read && size == KINFO_PROC_BYTES).then_some(flags & TRACED != 0)
    }

    /// Enters the sandbox, for the whole process and for good, and returns whether the network and
    /// file writes read back as refused.
    pub(super) fn enter_sandbox() -> (bool, bool) {
        let mut error = ptr::null_mut();
        // SAFETY: the profile is a NUL-terminated text; on a failure the call allocates a message
        // into `error`, freed below.
        let entered = unsafe { sandbox_init(PROFILE.as_ptr(), 0, &mut error) } == 0;
        if !entered && !error.is_null() {
            // SAFETY: frees the message sandbox_init allocated, once.
            unsafe { sandbox_free_error(error) };
        }
        (network_refused(), file_writes_refused())
    }

    /// Whether the sandbox refuses a new file in the temporary folder.
    fn file_writes_refused() -> bool {
        let path = std::env::temp_dir().join(format!("mhfe-core-{}", std::process::id()));
        match std::fs::File::create(&path) {
            Ok(_) => {
                let _ = std::fs::remove_file(&path);
                false
            }
            Err(error) => error.kind() == io::ErrorKind::PermissionDenied,
        }
    }

    /// Whether the sandbox refuses to bind or connect a UDP socket on the loopback address, which
    /// sends nothing; a refusal for another reason does not count.
    fn network_refused() -> bool {
        let refused = |error: io::Error| error.raw_os_error() == Some(libc::EPERM);
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
            Err(error) => refused(error),
            // The discard port: nothing would answer even with a network.
            Ok(socket) => socket.connect((Ipv4Addr::LOCALHOST, 9)).is_err_and(refused),
        }
    }
}
