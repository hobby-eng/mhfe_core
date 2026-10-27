//! The protections of `protect::Isolation::enter` and the secret writer, checked from outside the
//! code that applies them. The program has a `main` of its own (`harness = false`): a process of
//! one thread, which a test harness never has, is a child process that it starts again in a role,
//! and so are the processes the checks look at from outside.
#![allow(
    unsafe_code,
    reason = "the checks make the system calls that a program inside the isolation could make"
)]
#![allow(
    clippy::unwrap_used,
    reason = "a test program with a main of its own, which clippy does not see as a test: a failed \
              check ends it, as in a test harness"
)]

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};

#[cfg(not(target_arch = "wasm32"))]
use mhfe_core::protect;
use mhfe_core::protect::Isolation;
#[cfg(any(target_os = "linux", windows))]
use mhfe_core::{Argon2Engine, NativeArgon2};

/// The variable that gives a child process its role.
const ROLE: &str = "MHFE_CORE_TEST_ROLE";

fn main() {
    match std::env::var(ROLE).as_deref() {
        Ok("isolated") => isolated(),
        Ok("idle") => idle(),
        #[cfg(not(target_arch = "wasm32"))]
        Ok("writer") => writer(),
        _ if cfg!(target_family = "wasm") => run(
            "WebAssembly applies nothing and says so",
            webassembly_applies_nothing_and_says_so,
        ),
        _ => {
            #[cfg(target_os = "linux")]
            run(
                "an isolated thread is refused what the filter names and keeps what it needs",
                linux::an_isolated_thread_is_refused_what_the_filter_names,
            );
            run(
                "a process of one thread is isolated as a whole",
                a_process_of_one_thread_is_isolated_as_a_whole,
            );
            #[cfg(not(target_arch = "wasm32"))]
            run(
                "a secret is written after the buffered public output",
                a_secret_is_written_after_the_buffered_public_output,
            );
        }
    }
}

fn run(name: &str, check: fn()) {
    check();
    println!("test {name} ... ok");
}

/// Starts this program again in `role`, its standard streams piped.
fn child(role: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .env(ROLE, role)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The `isolated` role: enters the isolation, on Unix while it has one thread, checks the report,
/// says so and waits until its standard input closes, so that the test can look at it from
/// outside. On Windows, where the isolation holds for every thread, it starts a thread before the
/// call and one after, which wait with it, and runs Argon2id after the call.
fn isolated() {
    #[cfg(windows)]
    waiting_thread();
    let isolation = Isolation::enter();
    expect_whole_process(isolation);
    // A second call reads back the same, what the first one set included: on Linux the namespace,
    // on Windows the access lists and the integrity level.
    #[cfg(any(target_os = "linux", windows))]
    assert_eq!(Isolation::enter(), isolation);
    #[cfg(windows)]
    {
        waiting_thread();
        argon2id_still_works();
    }
    println!("entered");
    idle();
}

/// Starts a thread that waits until the process ends.
#[cfg(windows)]
fn waiting_thread() {
    std::thread::spawn(|| {
        loop {
            std::thread::park();
        }
    });
}

/// The `idle` role: waits until its standard input closes.
fn idle() {
    std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
}

/// The `writer` role: public output that the standard library buffers, then a secret.
#[cfg(not(target_arch = "wasm32"))]
fn writer() {
    print!("public ");
    protect::write_secret("test words").unwrap();
    protect::write_secret("\n").unwrap();
}

fn webassembly_applies_nothing_and_says_so() {
    assert_eq!(Isolation::enter(), Isolation::default());
}

fn a_process_of_one_thread_is_isolated_as_a_whole() {
    let mut process = child("isolated");
    let mut line = String::new();
    BufReader::new(process.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    if line == "entered\n" {
        cannot_be_read_from_outside(process.id());
    }
    // Closing its standard input ends the child.
    process.stdin = None;
    let output = process.wait_with_output().unwrap();
    let errors = String::from_utf8_lossy(&output.stderr);
    eprint!("{errors}");
    assert!(output.status.success(), "the isolated process failed");
    assert_eq!(line, "entered\n");
}

#[cfg(not(target_arch = "wasm32"))]
fn a_secret_is_written_after_the_buffered_public_output() {
    let output = child("writer").wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"public test words\n");
}

/// Argon2id runs its lanes on threads started after the isolation. The tag of this call was
/// computed with OpenSSL through Python cryptography 46.0.5.
#[cfg(any(target_os = "linux", windows))]
fn argon2id_still_works() {
    let mut engine = NativeArgon2::new(1024).unwrap();
    let mut key = [0u8; 32];
    engine
        .argon2id(
            b"public test password",
            b"0123456789abcdef",
            1024,
            1,
            &mut key,
        )
        .unwrap();
    let tag: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        tag,
        "e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2"
    );
}

/// What a process of one thread reports.
fn expect_whole_process(isolation: Isolation) {
    // An Android app is never a process of one thread.
    assert_eq!(
        isolation.whole_process,
        cfg!(any(unix, windows)) && cfg!(not(target_os = "android")),
        "{isolation:?}"
    );
    #[cfg(target_os = "linux")]
    linux::expect_whole_process(isolation);
    #[cfg(target_os = "macos")]
    assert!(
        isolation.no_core_dumps && isolation.no_memory_reading && isolation.no_new_sockets,
        "{isolation:?}"
    );
    #[cfg(windows)]
    assert!(
        isolation.no_core_dumps && isolation.no_memory_reading && isolation.no_file_changes,
        "{isolation:?}"
    );
}

/// Another program of the same user cannot read the memory of the isolated process.
fn cannot_be_read_from_outside(pid: u32) {
    #[cfg(target_os = "linux")]
    assert_eq!(
        std::fs::File::open(format!("/proc/{pid}/mem"))
            .err()
            .map(|error| error.kind()),
        Some(std::io::ErrorKind::PermissionDenied)
    );
    #[cfg(windows)]
    windows::cannot_be_opened(pid);
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = pid;
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::mem::size_of;
    use std::net::TcpListener;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Path;
    use std::ptr;

    use mhfe_core::protect::{Isolation, Secret};

    /// Requests of linux/fsverity.h, linux/fscrypt.h and linux/btrfs.h that change a file or make
    /// a folder through a descriptor open only for reading.
    const FS_IOC_ENABLE_VERITY: u32 = 0x4080_6685;
    const FS_IOC_SET_ENCRYPTION_POLICY: u32 = 0x800c_6613;
    const BTRFS_IOC_SUBVOL_CREATE: u32 = 0x5000_940e;

    /// Calls that the filter refuses whatever their arguments, by libc's numbers, a source of
    /// their own beside the filter's table, and by Linux 7.0's where libc 0.2.191 lacks them.
    const REFUSED_CALLS: &[libc::c_long] = &[
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_open_by_handle_at,
        // Linux on riscv64 and loongarch64 has no renameat, and no filter.
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_truncate,
        libc::SYS_fallocate,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        libc::SYS_utimensat,
        libc::SYS_mount,
        452, // fchmodat2
        463, // setxattrat
        466, // removexattrat
        469, // file_setattr
    ];
    /// The older calls that x86-64 has and AArch64 does not.
    #[cfg(target_arch = "x86_64")]
    const OLDER_CALLS: &[libc::c_long] = &[
        libc::SYS_creat,
        libc::SYS_rename,
        libc::SYS_unlink,
        libc::SYS_rmdir,
        libc::SYS_mkdir,
        libc::SYS_mknod,
        libc::SYS_link,
        libc::SYS_symlink,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ];
    #[cfg(not(target_arch = "x86_64"))]
    const OLDER_CALLS: &[libc::c_long] = &[];

    /// In a thread of its own, so that the rest of the test process stays free: what the filter
    /// and Landlock refuse is refused, and what a secret command needs still works.
    pub(super) fn an_isolated_thread_is_refused_what_the_filter_names() {
        let folder =
            std::env::temp_dir().join(format!("mhfe-core-isolation-{}", std::process::id()));
        fs::create_dir_all(&folder).unwrap();
        let file = folder.join("file");
        fs::write(&file, "public").unwrap();
        // Opened before: /dev/ptmx opens only for reading and writing.
        let (_controller, terminal) = pseudo_terminal();
        let mut idle = super::child("idle");
        let secret_memory = is_secret_memory(&Secret::with_capacity(1));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let unconnected = tcp_socket();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let isolation = Isolation::enter();
                assert!(
                    isolation.no_core_dumps
                        && isolation.no_memory_reading
                        && isolation.no_new_sockets
                        && isolation.no_file_changes,
                    "{isolation:?}"
                );
                assert!(!isolation.whole_process && !isolation.empty_network);
                calls_are_refused(idle.id());
                connecting_is_refused(&unconnected, listener.local_addr().unwrap().port());
                files_stay_as_they_are(&folder, &file);
                what_a_secret_command_needs_still_works(&terminal, secret_memory);
            });
        });
        // The rest of the process is not isolated.
        TcpListener::bind("127.0.0.1:0").unwrap();
        fs::rename(&file, folder.join("renamed")).unwrap();
        idle.stdin = None;
        idle.wait().unwrap();
        fs::remove_dir_all(&folder).unwrap();
    }

    fn calls_are_refused(idle: u32) {
        for &number in REFUSED_CALLS.iter().chain(OLDER_CALLS) {
            // SAFETY: a descriptor of -1 and null pointers: without the filter, every call fails at
            // once and changes nothing.
            let result =
                unsafe { libc::syscall(number, -1_i64, 0_i64, 0_i64, 0_i64, 0_i64, 0_i64) };
            assert_eq!(error_of(result), Some(libc::EACCES), "call {number}");
        }
        let pid = libc::pid_t::try_from(idle).unwrap();
        // SAFETY: attaching passes no memory; it would stop the idle child, which the test ends.
        let attach = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0_i64, 0_i64) };
        assert_eq!(error_of(attach), Some(libc::EACCES), "ptrace");
        // openat2, whose flags the filter cannot read, and a call newer than Linux 7.0.
        for number in [437, 472] {
            // SAFETY: as above.
            let result = unsafe { libc::syscall(number, -1_i64, 0_i64, 0_i64, 0_i64) };
            assert_eq!(error_of(result), Some(libc::ENOSYS), "call {number}");
        }
    }

    /// From Linux 6.7 (Landlock's ABI 4), Landlock refuses to connect even a TCP socket opened
    /// before, which the filter cannot refuse.
    fn connecting_is_refused(socket: &OwnedFd, port: u16) {
        // SAFETY: with a null attribute and the version flag the call only returns a number.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                ptr::null::<u8>(),
                0_usize,
                1_u32,
            )
        };
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: connect reads the address, which lives for the call.
        let result = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&raw const address).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        let expected = (abi >= 4).then_some(libc::EACCES);
        assert_eq!(error_of(result.into()), expected, "Landlock {abi}");
    }

    /// A TCP socket, not connected.
    fn tcp_socket() -> OwnedFd {
        // SAFETY: socket takes integers and returns a new descriptor, which nothing else owns.
        unsafe {
            let socket = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(socket >= 0);
            OwnedFd::from_raw_fd(socket)
        }
    }

    fn files_stay_as_they_are(folder: &Path, file: &Path) {
        let refused = |result: io::Result<()>| {
            result.map_err(|error| error.raw_os_error()) == Err(Some(libc::EACCES))
        };
        assert!(refused(OpenOptions::new().write(true).open(file).map(drop)));
        assert!(refused(File::create(folder.join("new")).map(drop)));
        assert!(refused(fs::rename(file, folder.join("renamed"))));
        assert!(refused(fs::remove_file(file)));
        assert!(refused(fs::create_dir(folder.join("folder"))));
        // The filter refuses such an open itself: Landlock leaves a pipe open, which is no file of
        // a file system. On x86-64 also through open, which glibc's open does not issue; a mode of
        // 0 leaves the write bits to its flags.
        let (_reader, writer) = io::pipe().unwrap();
        let pipe = format!("/proc/self/fd/{}", writer.as_raw_fd());
        #[cfg(target_arch = "x86_64")]
        {
            let path = std::ffi::CString::new(pipe.as_str()).unwrap();
            // SAFETY: open reads the path, which lives for the call.
            let result =
                unsafe { libc::syscall(libc::SYS_open, path.as_ptr(), libc::O_WRONLY, 0_i64) };
            assert_eq!(error_of(result), Some(libc::EACCES), "open");
        }
        assert!(refused(OpenOptions::new().write(true).open(pipe).map(drop)));
        // Reading stays open; an ioctl that changes a file through a descriptor open for reading
        // is refused.
        assert_eq!(fs::read(file).unwrap(), b"public");
        let (file, folder) = (File::open(file).unwrap(), File::open(folder).unwrap());
        for (target, request) in [
            (&file, FS_IOC_ENABLE_VERITY),
            (&folder, FS_IOC_SET_ENCRYPTION_POLICY),
            (&folder, BTRFS_IOC_SUBVOL_CREATE),
        ] {
            // SAFETY: a null argument: without the filter, the call fails at once.
            let result =
                unsafe { libc::ioctl(target.as_raw_fd(), request.into(), ptr::null_mut::<u8>()) };
            assert_eq!(error_of(result.into()), Some(libc::EACCES), "{request:#x}");
        }
    }

    fn what_a_secret_command_needs_still_works(terminal: &OwnedFd, secret_memory: bool) {
        let terminal = terminal.as_raw_fd();
        // SAFETY: a termios and a winsize of zeros are valid; each call fills or reads the one it
        // is given, which lives for the call. tcgetattr and tcsetattr use the termios2 requests of
        // newer C libraries.
        unsafe {
            let mut settings: libc::termios = std::mem::zeroed();
            assert_eq!(libc::ioctl(terminal, libc::TCGETS, &raw mut settings), 0);
            assert_eq!(libc::tcgetattr(terminal, &raw mut settings), 0);
            for when in [libc::TCSANOW, libc::TCSADRAIN, libc::TCSAFLUSH] {
                assert_eq!(libc::tcsetattr(terminal, when, &raw const settings), 0);
            }
            let mut size: libc::winsize = std::mem::zeroed();
            assert_eq!(libc::ioctl(terminal, libc::TIOCGWINSZ, &raw mut size), 0);
        }
        // A secret still gets secret memory where the rest of the process gets it.
        assert_eq!(is_secret_memory(&Secret::with_capacity(1)), secret_memory);
        super::argon2id_still_works();
    }

    /// What a process of one thread reports on Linux, and the side effects of the empty network.
    pub(super) fn expect_whole_process(isolation: Isolation) {
        assert!(
            isolation.no_core_dumps
                && isolation.no_memory_reading
                && isolation.no_new_sockets
                && isolation.no_file_changes,
            "{isolation:?}"
        );
        if isolation.empty_network {
            // No ID map is written in the new user namespace.
            // SAFETY: getuid and getgid only read.
            assert_eq!(unsafe { (libc::getuid(), libc::getgid()) }, (65534, 65534));
            let devices = fs::read_to_string("/proc/self/net/dev").unwrap();
            let interfaces: Vec<&str> = devices
                .lines()
                .skip(2)
                .filter_map(|line| line.split(':').next())
                .map(str::trim)
                .collect();
            assert_eq!(interfaces, ["lo"]);
        } else {
            // SAFETY: unshare takes flags only.
            let allowed = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } == 0;
            assert!(
                !allowed,
                "the system allows the empty network, which enter left out"
            );
            eprintln!("This system allows no user namespace: the empty network is not checked.");
        }
    }

    /// The error number of a call that returned -1, or `None` for one that succeeded.
    fn error_of(result: libc::c_long) -> Option<i32> {
        (result == -1).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    /// A pseudo-terminal: its controller and the terminal a secret command reads from.
    fn pseudo_terminal() -> (OwnedFd, OwnedFd) {
        let (mut controller, mut terminal) = (-1, -1);
        // SAFETY: openpty writes the two descriptors it opens; no name, settings or size is
        // given.
        let opened = unsafe {
            libc::openpty(
                &mut controller,
                &mut terminal,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        };
        assert_eq!(opened, 0);
        // SAFETY: both descriptors were just opened, and nothing else owns them.
        unsafe {
            (
                OwnedFd::from_raw_fd(controller),
                OwnedFd::from_raw_fd(terminal),
            )
        }
    }

    /// Whether the pages of `secret` are secret memory, as /proc/self/maps names them.
    fn is_secret_memory(secret: &Secret) -> bool {
        let address = secret.as_bytes().as_ptr() as usize;
        let maps = fs::read_to_string("/proc/self/maps").unwrap();
        maps.lines().any(|line| {
            let range = line
                .split(' ')
                .next()
                .and_then(|range| range.split_once('-'));
            let holds = range.is_some_and(|(start, end)| {
                let bound = |hex| usize::from_str_radix(hex, 16).unwrap();
                (bound(start)..bound(end)).contains(&address)
            });
            holds && line.ends_with("/secretmem (deleted)")
        })
    }
}

#[cfg(windows)]
mod windows {
    use std::mem::size_of;

    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_NOT_ALL_ASSIGNED,
        ERROR_SUCCESS, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME,
        SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    };
    use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, PROCESS_VM_READ,
        THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_CONTEXT,
        THREAD_SUSPEND_RESUME,
    };

    /// A program of the same user can open the isolated process neither to read its memory nor
    /// to change its access list, and none of its threads to read or change its context, suspend
    /// it or change its access list; it can still read a thread's basic information.
    pub(super) fn cannot_be_opened(pid: u32) {
        drop_debug_privilege();
        // SAFETY: each call opens the process object of the child, inheriting no handle.
        expect_refused(
            "the process",
            &[PROCESS_VM_READ, WRITE_DAC],
            |access| unsafe { OpenProcess(access, 0, pid) },
        );
        // SAFETY: takes a snapshot of the threads of the system, closed below.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        assert_ne!(snapshot, INVALID_HANDLE_VALUE);
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..THREADENTRY32::default()
        };
        let mut threads = 0;
        // SAFETY: fills `entry`, whose size it names, from the snapshot.
        let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        while more {
            if entry.th32OwnerProcessID == pid && thread_cannot_be_opened(entry.th32ThreadID) {
                threads += 1;
            }
            // SAFETY: as above.
            more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        // SAFETY: closes the snapshot taken above, once.
        unsafe { CloseHandle(snapshot) };
        // The main thread and the two it started; Windows may have started more.
        assert!(threads >= 3, "{threads} threads");
    }

    /// Removes the debug privilege from this test's own token. A program that holds it opens every
    /// process and thread whatever its access list, which the isolation does not cover, and the
    /// test runner of a CI machine may hold it.
    fn drop_debug_privilege() {
        let mut token = ptr::null_mut();
        // SAFETY: opens the token of this process to change its privileges; closed below.
        let opened =
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) };
        assert_ne!(opened, 0);
        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: LUID::default(),
                Attributes: SE_PRIVILEGE_REMOVED,
            }],
        };
        // SAFETY: the name is NUL-terminated; the call writes the privilege's number.
        let found = unsafe {
            LookupPrivilegeValueW(
                ptr::null(),
                SE_DEBUG_NAME,
                &mut privileges.Privileges[0].Luid,
            )
        };
        assert_ne!(found, 0);
        // SAFETY: the list lives for the call, which is asked for no earlier state.
        let adjusted = unsafe {
            AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut())
        };
        // SAFETY: reads this thread's last error, which AdjustTokenPrivileges set.
        let error = unsafe { GetLastError() };
        // SAFETY: closes the token opened above, once.
        unsafe { CloseHandle(token) };
        // ERROR_NOT_ALL_ASSIGNED: the token does not hold the privilege.
        assert!(
            adjusted != 0 && matches!(error, ERROR_SUCCESS | ERROR_NOT_ALL_ASSIGNED),
            "error {error}"
        );
    }

    /// Checks the thread numbered `id`, and returns false for one that has ended since the
    /// snapshot.
    fn thread_cannot_be_opened(id: u32) -> bool {
        // SAFETY: opens the thread object, inheriting no handle; it stays open until the checks
        // end, so that its number names the same thread.
        let thread = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, id) };
        // SAFETY: reads this thread's last error, which OpenThread set.
        let error = unsafe { GetLastError() };
        if thread.is_null() && error == ERROR_INVALID_PARAMETER {
            return false;
        }
        assert!(!thread.is_null(), "thread {id}: error {error}");
        let refused_rights = [
            THREAD_GET_CONTEXT,
            THREAD_SET_CONTEXT,
            THREAD_SUSPEND_RESUME,
            WRITE_DAC,
        ];
        // SAFETY: each call opens the thread object, inheriting no handle.
        expect_refused(&format!("thread {id}"), &refused_rights, |access| unsafe {
            OpenThread(access, 0, id)
        });
        // SAFETY: closes the handle opened above, once.
        unsafe { CloseHandle(thread) };
        true
    }

    /// `open` refuses each of `rights` to `object` with ERROR_ACCESS_DENIED.
    fn expect_refused(object: &str, rights: &[u32], open: impl Fn(u32) -> HANDLE) {
        for &access in rights {
            let handle = open(access);
            // SAFETY: reads this thread's last error, which `open` set.
            let error = unsafe { GetLastError() };
            if !handle.is_null() {
                // SAFETY: closes the handle just opened, once.
                unsafe { CloseHandle(handle) };
            }
            assert!(
                handle.is_null() && error == ERROR_ACCESS_DENIED,
                "{object}, access {access:#x}: error {error}"
            );
        }
    }
}
