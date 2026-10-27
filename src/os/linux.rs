//! Linux and Android.
//!
//! Linux's secret memory (`memfd_secret`, on by default since Linux 6.5): its pages leave the
//! kernel's direct map, so that no process, root included, reads them directly through
//! `/proc/PID/mem`, `process_vm_readv` or `PTRACE_PEEKDATA`; they are locked and out of core dumps
//! by construction, and the kernel refuses to hibernate while they exist, so that they never reach
//! a hibernation image.
//! Android never calls it.
//!
//! The protections of [`crate::protect::Isolation::enter`]: the dump settings, a seccomp filter,
//! on Linux Landlock and an empty network namespace, and the probes that read them back. An
//! Android app's own seccomp policy ends the process at a call outside it, so there only `prctl`,
//! `prlimit64`, `socket`, `openat`, `close` and the memory calls are made: no Landlock, `unshare`,
//! io_uring or listing of the process's threads.
#![allow(
    unsafe_code,
    reason = "memfd_secret, ftruncate, mmap, madvise, munmap, prctl, unshare, socket, open, close \
              and the io_uring and Landlock calls are foreign functions"
)]

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::ptr::{self, NonNull};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

use crate::protect::Isolation;

/// The number of `memfd_secret` on x86-64 and AArch64, the Linux architectures this crate is
/// tested on, where it is called; on another one it is `None`, and a secret takes anonymous pages.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const MEMFD_SECRET: Option<libc::c_long> = Some(libc::SYS_memfd_secret);
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
const MEMFD_SECRET: Option<libc::c_long> = None;

/// `bytes` bytes of secret memory, or `None` where the kernel refuses: one without secret memory,
/// a policy that forbids the call, or a request beyond RLIMIT_MEMLOCK, which these pages count
/// against.
#[cfg(target_os = "linux")]
pub(super) fn secret_pages(bytes: usize) -> Option<NonNull<u8>> {
    let number = MEMFD_SECRET?;
    // SAFETY: memfd_secret takes one flags argument and returns a new descriptor or -1.
    let descriptor = unsafe { libc::syscall(number, 0) };
    let descriptor = i32::try_from(descriptor).ok().filter(|&fd| fd >= 0)?;
    // SAFETY: the descriptor was just opened and nothing else owns it; it is closed on return,
    // while the mapping stays.
    let file = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let size = libc::off_t::try_from(bytes).ok()?;
    // SAFETY: ftruncate sizes the file of a descriptor this function owns.
    if unsafe { libc::ftruncate(file.as_raw_fd(), size) } != 0 {
        return None;
    }
    // SAFETY: a new shared mapping of that file, at an address the kernel chooses, takes no
    // memory that anything else owns.
    let mapped = unsafe {
        libc::mmap(
            ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return None;
    }
    // The mapping is shared, so a child process would share the secret: it gets no mapping
    // instead, or the pages are given back and anonymous ones taken.
    // SAFETY: madvise marks the pages of the mapping just made and changes no content.
    if unsafe { libc::madvise(mapped, bytes, libc::MADV_DONTFORK) } != 0 {
        // SAFETY: the mapping was just made and nothing refers to it.
        unsafe { libc::munmap(mapped, bytes) };
        return None;
    }
    NonNull::new(mapped.cast())
}

/// The error number of a call that the filter or Landlock refuses. Both answer before the call
/// itself, so a refusal with another number did not come from them.
const REFUSED: i32 = libc::EACCES;

pub(crate) fn enter() -> Isolation {
    let whole_process = one_thread();
    #[cfg(target_os = "linux")]
    let empty_network = whole_process && enter_empty_network() && network_empty();
    #[cfg(target_os = "android")]
    let empty_network = false;
    let core_limit = super::unix::forbid_core_dumps();
    // SAFETY: PR_SET_DUMPABLE takes integers and touches no memory of this process.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    // Seccomp and Landlock require no_new_privs of an unprivileged process: no program it starts
    // can gain privileges, as a set-user-ID program would.
    // SAFETY: as above.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0 {
        #[cfg(target_os = "linux")]
        landlock::restrict_self();
        seccomp::install();
    }
    // SAFETY: PR_GET_DUMPABLE takes no pointer and returns the flag.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0;
    Isolation {
        // A pipe in core_pattern, as systemd-coredump and apport use, ignores RLIMIT_CORE: there
        // only a process that is not dumpable keeps a crash off the disk.
        no_core_dumps: core_limit && !dumpable,
        no_memory_reading: !dumpable,
        no_new_sockets: sockets_refused(),
        empty_network,
        no_file_changes: writing_refused(),
        whole_process,
    }
}

/// Whether the process has one thread: only then may it enter a user namespace of its own, and
/// only then do the filters, which a thread passes on to the threads it starts, hold for the whole
/// process. An Android app always has other threads.
fn one_thread() -> bool {
    #[cfg(target_os = "linux")]
    return std::fs::read_dir("/proc/self/task").is_ok_and(|threads| threads.count() == 1);
    #[cfg(target_os = "android")]
    false
}

/// A network namespace of its own for the process, with only a loopback interface that stays down
/// and no route, in a user namespace of its own, without which an unprivileged process may not
/// make one; the kernel allows it only to a process of one thread, and where the system allows
/// user namespaces. Returns whether this call or an earlier one made it: the kernel refuses a
/// second one inside it, and a namespace that the process was started in can look empty while its
/// loopback is up and other processes share it. A refusal changes nothing.
#[cfg(target_os = "linux")]
fn enter_empty_network() -> bool {
    static MADE: AtomicBool = AtomicBool::new(false);
    // SAFETY: unshare takes flags only and touches no memory of this process.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } == 0 {
        MADE.store(true, Ordering::Relaxed);
    }
    MADE.load(Ordering::Relaxed)
}

/// Whether the network namespace holds only the loopback interface and no IPv4 route. The kernel
/// lists the interfaces after two heading lines, each as "name: counters", and the routes after a
/// heading that starts with "Iface"; an empty table may lack that heading.
#[cfg(target_os = "linux")]
fn network_empty() -> bool {
    /// Heading lines of /proc/net/dev.
    const DEVICE_HEADINGS: usize = 2;
    let (Ok(devices), Ok(routes)) = (
        std::fs::read_to_string("/proc/self/net/dev"),
        std::fs::read_to_string("/proc/self/net/route"),
    ) else {
        return false;
    };
    let only_loopback = devices
        .lines()
        .skip(DEVICE_HEADINGS)
        .filter_map(|line| line.split(':').next())
        .all(|name| name.trim() == "lo");
    let no_route = routes
        .lines()
        .all(|line| line.trim().is_empty() || line.starts_with("Iface"));
    only_loopback && no_route
}

/// `Ok` after closing what a probe opened, else the error number of the refusal.
fn opened(descriptor: libc::c_long) -> Result<(), i32> {
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    // SAFETY: closes the descriptor the probe just opened, once.
    unsafe { libc::close(descriptor as libc::c_int) };
    Ok(())
}

/// Whether the filter refuses a new socket and, on Linux, an io_uring. The probe asks for a Unix
/// socket: Android refuses a network socket with EACCES as well to an app without the `INTERNET`
/// permission, which must not pass for the filter.
fn sockets_refused() -> bool {
    // SAFETY: socket takes integers and touches no memory of this process.
    let socket = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    let refused = opened(socket.into()) == Err(REFUSED);
    // An io_uring could open a socket without the socket call. An Android app's policy ends the
    // process at any io_uring call, so it is not probed there; the filter refuses it all the same.
    #[cfg(target_os = "linux")]
    return refused && io_uring_refused();
    #[cfg(target_os = "android")]
    refused
}

#[cfg(target_os = "linux")]
fn io_uring_refused() -> bool {
    // `struct io_uring_params` of linux/io_uring.h is 120 bytes; zero asks for the defaults.
    let mut params = [0u8; 120];
    // SAFETY: the kernel reads and fills the 120 bytes of `params`, which live for the call.
    let ring = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
    opened(ring) == Err(REFUSED)
}

/// Whether opening /dev/null for writing is refused by the filter or Landlock. A system without
/// /dev/null, or one that refuses it for another reason, cannot tell.
fn writing_refused() -> bool {
    // SAFETY: the path is a NUL-terminated literal; open touches nothing else.
    let file = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    opened(file.into()) == Err(REFUSED)
}

/// A seccomp filter for the calling thread and the threads it starts afterwards. It refuses with
/// EACCES new sockets; io_uring, whose operations, a socket among them, run inside the kernel
/// without a call the filter would see; the calls that act on another process, which could take a
/// connected socket from it or drive it where Yama allows; every call that changes the file
/// system; and every ioctl but the terminal's, since an ioctl can change a file through a
/// descriptor open only for reading (fs-verity, encryption policies, btrfs subvolumes). It
/// answers ENOSYS to `openat2`, whose flags lie in a structure it cannot read, and to every call
/// newer than its table, so that the C library falls back to a call it reads and a later kernel's
/// call cannot get past it. Written for little-endian x86-64 and AArch64, whose numbers it holds.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
))]
mod seccomp {
    /// The numbers of Linux 7.0's arch/x86/entry/syscalls/syscall_64.tbl, written out because
    /// libc 0.2.191 lacks some of them.
    #[cfg(target_arch = "x86_64")]
    mod calls {
        /// AUDIT_ARCH_X86_64 of linux/audit.h.
        pub(super) const ARCH: u32 = 0xC000_003E;
        /// An x32 call carries this bit in its number (__X32_SYSCALL_BIT).
        pub(super) const X32_BIT: u32 = 0x4000_0000;
        /// rseq_slice_yield, the newest call of Linux 7.0.
        pub(super) const NEWEST: u32 = 471;
        pub(super) const OPENAT2: u32 = 437;
        pub(super) const IOCTL: u32 = 16;
        /// open, whose flags are its second argument, and openat, whose flags are its third.
        pub(super) const OPENS: &[(u32, u32)] = &[(2, 1), (257, 2)];
        /// Refused whatever their arguments. Not ftruncate: it sizes the secret memory of every
        /// `Secret`, and it changes only a file already open for writing, which `write` changes
        /// anyway.
        pub(super) const REFUSED: &[u32] = &[
            41, 53, // socket, socketpair
            425, 426, 427, // io_uring_setup, io_uring_enter, io_uring_register
            101, 311, 438, // ptrace, process_vm_writev, pidfd_getfd
            85, 304, // creat, open_by_handle_at
            82, 264, 316, // rename, renameat, renameat2
            87, 263, 84, // unlink, unlinkat, rmdir
            83, 258, 133, 259, // mkdir, mkdirat, mknod, mknodat
            86, 265, 88, 266, // link, linkat, symlink, symlinkat
            76, 285, // truncate, fallocate
            90, 91, 268, 452, // chmod, fchmod, fchmodat, fchmodat2
            92, 93, 94, 260, // chown, fchown, lchown, fchownat
            188, 189, 190, 463, // setxattr, lsetxattr, fsetxattr, setxattrat
            197, 198, 199, 466, // removexattr, lremovexattr, fremovexattr, removexattrat
            469, // file_setattr
            132, 235, 261, 280, // utime, utimes, futimesat, utimensat
            165, // mount
        ];
    }

    /// The numbers of Linux 7.0's scripts/syscall.tbl as AArch64 has them, written out because
    /// libc 0.2.191 lacks some of them. AArch64 has no open, creat, rename, unlink, rmdir, mkdir,
    /// mknod, link, symlink, chmod, chown, lchown, utime, utimes or futimesat.
    #[cfg(target_arch = "aarch64")]
    mod calls {
        /// AUDIT_ARCH_AARCH64 of linux/audit.h.
        pub(super) const ARCH: u32 = 0xC000_00B7;
        /// rseq_slice_yield, the newest call of Linux 7.0.
        pub(super) const NEWEST: u32 = 471;
        pub(super) const OPENAT2: u32 = 437;
        pub(super) const IOCTL: u32 = 29;
        /// openat, whose flags are its third argument.
        pub(super) const OPENS: &[(u32, u32)] = &[(56, 2)];
        /// Refused whatever their arguments. Not ftruncate: it sizes the secret memory of every
        /// `Secret`, and it changes only a file already open for writing, which `write` changes
        /// anyway.
        pub(super) const REFUSED: &[u32] = &[
            198, 199, // socket, socketpair
            425, 426, 427, // io_uring_setup, io_uring_enter, io_uring_register
            117, 271, 438, // ptrace, process_vm_writev, pidfd_getfd
            265, // open_by_handle_at
            38, 276, // renameat, renameat2
            35,  // unlinkat
            34, 33, // mkdirat, mknodat
            37, 36, // linkat, symlinkat
            45, 47, // truncate, fallocate
            52, 53, 452, // fchmod, fchmodat, fchmodat2
            55, 54, // fchown, fchownat
            5, 6, 7, 463, // setxattr, lsetxattr, fsetxattr, setxattrat
            14, 15, 16, 466, // removexattr, lremovexattr, fremovexattr, removexattrat
            469, // file_setattr
            88,  // utimensat
            40,  // mount
        ];
    }

    /// The terminal's requests, which a program that reads a hidden line makes: TCGETS, TCSETS,
    /// TCSETSW and TCSETSF, their termios2 forms, which newer C libraries use (glibc 2.42 and
    /// later), and TIOCGWINSZ. Tracing a terminal program that reads hidden input with glibc 2.43
    /// shows no other.
    const TERMINAL_REQUESTS: [u32; 9] = [
        libc::TCGETS as u32,
        libc::TCSETS as u32,
        libc::TCSETSW as u32,
        libc::TCSETSF as u32,
        libc::TCGETS2 as u32,
        libc::TCSETS2 as u32,
        libc::TCSETSW2 as u32,
        libc::TCSETSF2 as u32,
        libc::TIOCGWINSZ as u32,
    ];

    /// The flags of an open that can change a file.
    const WRITE_FLAGS: u32 =
        (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u32;

    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const REFUSE: u32 = libc::SECCOMP_RET_ERRNO | super::REFUSED as u32;
    const NO_SUCH_CALL: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

    /// Offsets in `struct seccomp_data` (linux/seccomp.h): `int nr`, `__u32 arch`, then from 16
    /// the six `__u64` arguments.
    const NUMBER_OFFSET: u32 = 0;
    const ARCH_OFFSET: u32 = 4;

    /// The offset of the low half of an argument, on a little-endian system: all that the kernel
    /// reads of an `int` or `unsigned int` argument, such as the flags of an open or the request
    /// of an ioctl.
    const fn argument(index: u32) -> u32 {
        16 + 8 * index
    }

    /// Instruction codes of linux/bpf_common.h, which libc does not give for Android.
    const LOAD_WORD: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const IF_EQUAL: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const IF_ABOVE: u16 = 0x25; // BPF_JMP | BPF_JGT | BPF_K
    #[cfg(target_arch = "x86_64")]
    const IF_AT_LEAST: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
    const IF_ANY_BIT: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
    const RETURN: u16 = 0x06; // BPF_RET | BPF_K

    fn instruction(code: u16, if_true: u8, if_false: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: if_true,
            jf: if_false,
            k,
        }
    }

    /// Returns `action` when the loaded value passes `test` with `value`, else goes on.
    fn answer_if(test: u16, value: u32, action: u32) -> [libc::sock_filter; 2] {
        [
            instruction(test, 0, 1, value),
            instruction(RETURN, 0, 0, action),
        ]
    }

    /// The filter, in which every test is followed by the answer it leads to, or skips a block
    /// that ends in answers, so that no jump goes further than the block it belongs to.
    fn program() -> Vec<libc::sock_filter> {
        let mut program = vec![instruction(LOAD_WORD, 0, 0, ARCH_OFFSET)];
        // A call of another ABI, such as a 32-bit one, has other numbers: it is refused.
        program.extend([
            instruction(IF_EQUAL, 1, 0, calls::ARCH),
            instruction(RETURN, 0, 0, REFUSE),
            instruction(LOAD_WORD, 0, 0, NUMBER_OFFSET),
        ]);
        #[cfg(target_arch = "x86_64")]
        program.extend(answer_if(IF_AT_LEAST, calls::X32_BIT, REFUSE));
        program.extend(answer_if(IF_ABOVE, calls::NEWEST, NO_SUCH_CALL));
        program.extend(answer_if(IF_EQUAL, calls::OPENAT2, NO_SUCH_CALL));
        for &number in calls::REFUSED {
            program.extend(answer_if(IF_EQUAL, number, REFUSE));
        }
        for &(number, flags) in calls::OPENS {
            program.extend([
                instruction(IF_EQUAL, 0, 4, number),
                instruction(LOAD_WORD, 0, 0, argument(flags)),
                instruction(IF_ANY_BIT, 0, 1, WRITE_FLAGS),
                instruction(RETURN, 0, 0, REFUSE),
                instruction(RETURN, 0, 0, ALLOW),
            ]);
        }
        // Last, as its final answer allows every other call: an ioctl is allowed only with a
        // terminal request, each test of which jumps to that answer.
        let requests = TERMINAL_REQUESTS.len() as u8;
        program.extend([
            instruction(IF_EQUAL, 0, requests + 2, calls::IOCTL),
            instruction(LOAD_WORD, 0, 0, argument(1)),
        ]);
        for (index, &request) in (0..).zip(&TERMINAL_REQUESTS) {
            program.push(instruction(IF_EQUAL, requests - index, 0, request));
        }
        program.extend([
            instruction(RETURN, 0, 0, REFUSE),
            instruction(RETURN, 0, 0, ALLOW),
        ]);
        program
    }

    pub(super) fn install() {
        let mut program = program();
        let filter = libc::sock_fprog {
            len: program.len() as u16,
            filter: program.as_mut_ptr(),
        };
        // SAFETY: the filter points to `len` instructions that live for the call; the kernel
        // copies them. It holds for the calling thread and the threads it starts afterwards.
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const filter,
                0,
                0,
            )
        };
    }
}

/// No filter is written for other architectures: there Landlock alone restricts Linux.
#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
)))]
mod seccomp {
    pub(super) fn install() {}
}

/// A Landlock ruleset that handles every right to change the file system the kernel knows and
/// grants none, so that files cannot be opened for writing, created, renamed, removed or truncated
/// and devices take no ioctl, wherever they are; descriptors already open stay usable, and reading
/// stays unrestricted. From Linux 6.7 it also refuses TCP bind and connect.
#[cfg(target_os = "linux")]
mod landlock {
    use std::mem::size_of;
    use std::ptr;

    /// `struct landlock_ruleset_attr` of linux/landlock.h; ABI 1 to 3 know only its first field.
    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    /// LANDLOCK_CREATE_RULESET_VERSION: asks for the ABI version instead of creating a ruleset.
    const CREATE_RULESET_VERSION: u32 = 1;
    /// The rights of linux/landlock.h that change the file system, by the ABI that added them.
    const WRITE_FILE: u64 = 1 << 1;
    const REMOVE_DIR: u64 = 1 << 4;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_CHAR: u64 = 1 << 6;
    const MAKE_DIR: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SOCK: u64 = 1 << 9;
    const MAKE_FIFO: u64 = 1 << 10;
    const MAKE_BLOCK: u64 = 1 << 11;
    const MAKE_SYM: u64 = 1 << 12;
    const REFER: u64 = 1 << 13; // ABI 2
    const TRUNCATE: u64 = 1 << 14; // ABI 3
    const IOCTL_DEV: u64 = 1 << 15; // ABI 5
    const BIND_TCP: u64 = 1 << 0; // ABI 4, network rights
    const CONNECT_TCP: u64 = 1 << 1;

    pub(super) fn restrict_self() {
        // SAFETY: with a null attribute and the version flag the call only returns a number.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        };
        if abi < 1 {
            // No Landlock in this kernel, or it is switched off.
            return;
        }
        let mut handled_fs = WRITE_FILE
            | REMOVE_DIR
            | REMOVE_FILE
            | MAKE_CHAR
            | MAKE_DIR
            | MAKE_REG
            | MAKE_SOCK
            | MAKE_FIFO
            | MAKE_BLOCK
            | MAKE_SYM;
        for (since, right) in [(2, REFER), (3, TRUNCATE), (5, IOCTL_DEV)] {
            if abi >= since {
                handled_fs |= right;
            }
        }
        let with_network = abi >= 4;
        let attr = RulesetAttr {
            handled_access_fs: handled_fs,
            handled_access_net: if with_network {
                BIND_TCP | CONNECT_TCP
            } else {
                0
            },
        };
        let size = if with_network {
            size_of::<RulesetAttr>()
        } else {
            size_of::<u64>()
        };
        // SAFETY: the attribute lives for the call and `size` covers only the fields this ABI
        // knows; the kernel returns a new file descriptor or an error.
        let ruleset = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &raw const attr,
                size,
                0u32,
            )
        };
        if ruleset < 0 {
            return;
        }
        let ruleset = ruleset as libc::c_int;
        // No rule grants any of the handled rights: they are refused everywhere.
        // SAFETY: the descriptor came from the call above and is closed once.
        unsafe {
            libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32);
            libc::close(ruleset);
        }
    }
}
