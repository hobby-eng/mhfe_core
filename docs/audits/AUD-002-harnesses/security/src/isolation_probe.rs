//! AUD-002 (mhfe-core dec9c81), CHECK-SEC-002, SEC-003 and SEC-005 on Linux: a process of one
//! thread enters `protect::Isolation::enter()` and reads every protection back from the kernel
//! itself, independently of the crate's own probes: the seccomp mode and filter count, no_new_privs
//! and the dumpable flag in /proc/self/status, RLIMIT_CORE, refused socket families and io_uring,
//! refused file writes, the ENOSYS answers, a Landlock refusal that the filter cannot give (connect
//! on a TCP socket opened before), the empty network namespace, the VmFlags of a secret and of the
//! Argon2id work area in /proc/self/smaps, and an Argon2id call whose lanes start after the call.
//! Prints PASS or FAIL per check and exits 1 when any check fails, 2 when it cannot run.

use std::process::ExitCode;

/// The exit code of a check that failed; 0 is every check held.
const FAILED: u8 = 1;
/// The exit code of a probe that could not run: another system, or a call the setup needs refused.
const BROKEN: u8 = 2;

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("isolation-probe runs on Linux only");
    ExitCode::from(BROKEN)
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match linux::run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(FAILED),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(BROKEN)
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "the probe reads the protections back with system calls of its own, through libc"
)]
mod linux {
    use std::fs;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use mhfe_core::protect::{Isolation, Secret};
    use mhfe_core::{Argon2Engine, NativeArgon2};

    struct Checks {
        failed: usize,
    }

    impl Checks {
        fn check(&mut self, name: &str, ok: bool, detail: impl std::fmt::Display) {
            println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
            if !ok {
                self.failed += 1;
            }
        }
    }

    fn errno_of(result: libc::c_long) -> Option<i32> {
        (result < 0).then(|| io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    /// Every mapping of /proc/self/smaps: its addresses, name and VmFlags.
    fn mappings() -> Vec<(std::ops::Range<usize>, String, Vec<String>)> {
        let smaps = fs::read_to_string("/proc/self/smaps").unwrap_or_default();
        let mut all: Vec<(std::ops::Range<usize>, String, Vec<String>)> = Vec::new();
        for line in smaps.lines() {
            if let Some(flags) = line.strip_prefix("VmFlags:") {
                if let Some(last) = all.last_mut() {
                    last.2 = flags.split_whitespace().map(str::to_owned).collect();
                }
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some((start, end)) = fields.next().and_then(|range| range.split_once('-')) else {
                continue;
            };
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) else {
                continue;
            };
            let name = fields.skip(4).collect::<Vec<_>>().join(" ");
            all.push((start..end, name, Vec::new()));
        }
        all
    }

    /// The name and VmFlags of the mapping that holds `address`.
    fn mapping_of(address: usize) -> Option<(String, Vec<String>)> {
        mappings()
            .into_iter()
            .find(|(range, _, _)| range.contains(&address))
            .map(|(_, name, flags)| (name, flags))
    }

    fn status_field(status: &str, field: &str) -> String {
        status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
    }

    /// Overflow user and group ID: the kernel's default `overflowuid` and `overflowgid`, which an
    /// ID without a mapping reads as inside the new user namespace.
    const OVERFLOW_ID: u32 = 65534;
    /// Calls the filter must answer with ENOSYS: 437 is openat2; 472 and 600 lie past the newest
    /// call of Linux 7.0 (471), as src/os/linux.rs lists them.
    const ENOSYS_CALLS: [libc::c_long; 3] = [437, 472, 600];
    /// The Argon2id tag of the password "public test password" and salt "0123456789abcdef" with
    /// 1024 KiB, one pass, four lanes and 32 bytes, from OpenSSL's ARGON2ID KDF (an independent
    /// implementation).
    const OPENSSL_TAG: &str = "e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2";

    #[expect(
        clippy::too_many_lines,
        reason = "one probe that reads every protection back in order after Isolation::enter; the \
                  checks share the state the call set up"
    )]
    pub(super) fn run() -> Result<bool, String> {
        let mut checks = Checks { failed: 0 };
        let threads = fs::read_dir("/proc/self/task")
            .map(|t| t.count())
            .unwrap_or(0);
        checks.check("one thread before the call", threads == 1, threads);
        let before = Secret::with_capacity(16);
        let secret_memory = mapping_of(before.as_bytes().as_ptr() as usize)
            .is_some_and(|(name, _)| name.starts_with("/secretmem"));
        println!("INFO secret memory offered before the call: {secret_memory}");
        // SAFETY: socket takes integers and returns a new descriptor or -1.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(format!(
                "TCP socket before the call: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: `fd` is a descriptor just opened and owned by nothing else.
        let tcp = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: unshare is only asked whether the system allows it, in a child that ends at once.
        let namespaces_allowed = unsafe {
            let child = libc::fork();
            if child == 0 {
                let code = (libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) == 0) as i32;
                libc::_exit(code);
            }
            let mut status = 0;
            if child < 0 || libc::waitpid(child, &mut status, 0) != child {
                return Err(format!(
                    "the namespace probe: {}",
                    io::Error::last_os_error()
                ));
            }
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 1
        };
        println!("INFO the system allows a user and network namespace: {namespaces_allowed}");

        let isolation = Isolation::enter();
        println!("INFO report: {isolation:?}");
        checks.check(
            "report",
            isolation.no_core_dumps
                && isolation.no_memory_reading
                && isolation.no_new_sockets
                && isolation.no_file_changes
                && isolation.whole_process
                && isolation.empty_network == namespaces_allowed,
            format!("{isolation:?}"),
        );

        let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
        let (mode, filters, nnp) = (
            status_field(&status, "Seccomp:"),
            status_field(&status, "Seccomp_filters:"),
            status_field(&status, "NoNewPrivs:"),
        );
        checks.check(
            "kernel: seccomp filter mode, one filter, no_new_privs",
            mode == "2" && filters == "1" && nnp == "1",
            format!("Seccomp {mode}, Seccomp_filters {filters}, NoNewPrivs {nnp}"),
        );
        // SAFETY: PR_GET_DUMPABLE takes no pointer.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        checks.check("kernel: not dumpable", dumpable == 0, dumpable);
        let mut core = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: getrlimit writes the struct.
        unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) };
        checks.check(
            "kernel: RLIMIT_CORE 0 and 0",
            (core.rlim_cur, core.rlim_max) == (0, 0),
            format!("{} {}", core.rlim_cur, core.rlim_max),
        );

        for (family, kind, name) in [
            (libc::AF_INET, libc::SOCK_STREAM, "AF_INET stream"),
            (libc::AF_INET6, libc::SOCK_DGRAM, "AF_INET6 datagram"),
            (libc::AF_UNIX, libc::SOCK_STREAM, "AF_UNIX stream"),
            (libc::AF_NETLINK, libc::SOCK_RAW, "AF_NETLINK"),
            (libc::AF_PACKET, libc::SOCK_RAW, "AF_PACKET"),
        ] {
            // SAFETY: socket takes integers; a descriptor it returned is closed.
            let fd = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, 0) };
            let error = errno_of(fd.into());
            if fd >= 0 {
                // SAFETY: closes the descriptor just opened.
                unsafe { libc::close(fd) };
            }
            checks.check(
                &format!("new socket {name} refused"),
                error == Some(libc::EACCES),
                format!("{error:?}"),
            );
        }
        let mut params = [0u8; 120];
        // SAFETY: the kernel reads and fills the 120 bytes of params.
        let ring = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
        checks.check(
            "io_uring_setup refused",
            errno_of(ring) == Some(libc::EACCES),
            format!("{:?}", errno_of(ring)),
        );
        for number in ENOSYS_CALLS {
            // SAFETY: an unknown or refused call with zero arguments touches nothing.
            let result = unsafe { libc::syscall(number, 0, 0, 0, 0) };
            checks.check(
                &format!("call {number} answers ENOSYS"),
                errno_of(result) == Some(libc::ENOSYS),
                format!("{:?}", errno_of(result)),
            );
        }

        let folder = std::env::temp_dir();
        let path = folder.join(format!("aud002-isolation-probe-{}", std::process::id()));
        let created = fs::File::create(&path).map_err(|error| error.raw_os_error());
        checks.check(
            "creating a file refused",
            created.as_ref().err() == Some(&Some(libc::EACCES)),
            format!("{created:?}"),
        );
        let renamed = fs::rename("/proc/self/status", &path).map_err(|error| error.raw_os_error());
        checks.check(
            "rename refused",
            renamed == Err(Some(libc::EACCES)),
            format!("{renamed:?}"),
        );
        checks.check(
            "reading still works",
            !status.is_empty(),
            "/proc/self/status read",
        );

        // Landlock ABI 4 or later refuses to connect even a TCP socket opened before the call.
        // SAFETY: with a null attribute and the version flag the call only returns a number.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0usize,
                1u32,
            )
        };
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 9u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: connect reads the address, which lives for the call.
        let connected = unsafe {
            libc::connect(
                tcp.as_raw_fd(),
                (&raw const address).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        let error = errno_of(connected.into());
        checks.check(
            "Landlock refuses TCP connect on a socket opened before",
            abi < 4 || error == Some(libc::EACCES),
            format!("ABI {abi}, {error:?}"),
        );

        if isolation.empty_network {
            // SAFETY: getuid and getgid only read.
            let ids = unsafe { (libc::getuid(), libc::getgid()) };
            let devices = fs::read_to_string("/proc/self/net/dev").unwrap_or_default();
            let names: Vec<&str> = devices
                .lines()
                .skip(2)
                .filter_map(|line| line.split(':').next())
                .map(str::trim)
                .collect();
            let routes = fs::read_to_string("/proc/self/net/route").unwrap_or_default();
            let route_lines = routes
                .lines()
                .skip(1)
                .filter(|line| !line.trim().is_empty())
                .count();
            checks.check(
                "empty network: ids 65534, only lo, no IPv4 route",
                ids == (OVERFLOW_ID, OVERFLOW_ID) && names == ["lo"] && route_lines == 0,
                format!("ids {ids:?}, interfaces {names:?}, routes {route_lines}"),
            );
        } else {
            println!("INFO empty network not entered; the system refuses the namespace");
        }

        let after = Secret::with_capacity(16);
        match mapping_of(after.as_bytes().as_ptr() as usize) {
            Some((name, flags)) => {
                let is_secret_memory = name.starts_with("/secretmem");
                let child_flag = if is_secret_memory { "dc" } else { "wf" };
                let has = |flag: &str| flags.iter().any(|own| own == flag);
                checks.check(
                    "secret after the call: locked, out of dumps, kept from a child",
                    has("lo") && has("dd") && has(child_flag) && is_secret_memory == secret_memory,
                    format!("{name} {flags:?}"),
                );
            }
            None => checks.check("secret after the call: mapping found", false, "no mapping"),
        }
        drop(before);

        // One page more than 1 MiB, a size no other mapping of this program has.
        const AREA_KIB: u32 = 1028;
        let old = mappings();
        match NativeArgon2::new(AREA_KIB) {
            Ok(mut engine) => {
                let mut key = [0u8; 32];
                let result = engine.argon2id(
                    b"public test password",
                    b"0123456789abcdef",
                    1024,
                    1,
                    &mut key,
                );
                let tag: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
                checks.check(
                    "Argon2id lanes run after the call",
                    result.is_ok() && tag == OPENSSL_TAG,
                    format!("{result:?} {tag}"),
                );
                let new: Vec<_> = mappings()
                    .into_iter()
                    .filter(|(range, _, _)| range.len() == AREA_KIB as usize * 1024)
                    .filter(|(range, _, _)| old.iter().all(|(own, _, _)| own != range))
                    .collect();
                let marked = new.len() == 1 && {
                    let flags = &new[0].2;
                    let has = |flag: &str| flags.iter().any(|own| own == flag);
                    has("dd") && has("wf") && has("lo") == engine.is_locked()
                };
                checks.check(
                    "work area out of dumps, wiped on fork, locked as reported",
                    marked,
                    format!(
                        "{:?}, is_locked {}",
                        new.iter().map(|m| &m.2).collect::<Vec<_>>(),
                        engine.is_locked()
                    ),
                );
            }
            Err(error) => checks.check("work area reserved", false, error),
        }

        println!("{} failed", checks.failed);
        Ok(checks.failed == 0)
    }
}
