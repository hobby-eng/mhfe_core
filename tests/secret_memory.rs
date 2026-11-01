//! Where the pages of a secret and the work area of Argon2id lie, as the system reports them, and
//! that encoding a password and deriving a BIP39 seed take nothing from the heap. The program has a
//! `main` of its own (`harness = false`), so that the counting allocator sees no allocation of
//! another thread; a process under a low lock limit, which may end by a signal, is a child process
//! that it starts again in a role.
#![allow(
    unsafe_code,
    reason = "a global allocator, and the system calls that tell where pages lie and set the lock \
              limit"
)]
#![allow(
    clippy::unwrap_used,
    reason = "a test program with a main of its own, which clippy does not see as a test: a failed \
              check ends it, as in a test harness"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(target_arch = "wasm32"))]
use mhfe_core::NativeArgon2;
use mhfe_core::protect::Secret;
#[cfg(any(unix, windows))]
use mhfe_core::{Password, Phrase, wallet_check::Seed};

/// The system's allocator, counting the allocations it makes.
struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call goes to the system's allocator unchanged; reallocation and zeroed allocation
// go through `alloc`, so they are counted too.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`, which `System` needs.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as for `alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn main() {
    #[cfg(target_os = "linux")]
    if std::env::var_os(linux::ROLE).is_some() {
        linux::secrets_under_every_lock_limit();
        return;
    }
    // WebAssembly has no pages of its own to give a secret: it is a heap buffer there.
    #[cfg(any(unix, windows))]
    run(
        "encoding a password and deriving a seed take nothing from the heap",
        encoding_a_password_and_deriving_a_seed_take_nothing_from_the_heap,
    );
    #[cfg(any(target_os = "linux", windows))]
    run(
        "a secret lies on pages kept out of swap and core dumps",
        a_secret_lies_on_pages_kept_out_of_swap_and_core_dumps,
    );
    #[cfg(target_os = "linux")]
    run(
        "a secret works under every lock limit and says whether it is locked",
        linux::a_secret_works_under_every_lock_limit,
    );
    #[cfg(not(target_arch = "wasm32"))]
    run(
        "the work area lies on pages of its own, locked where the limit allows",
        the_work_area_lies_on_pages_of_its_own,
    );
    run(
        "six hundred secrets made one after another each report their core-dump exclusion",
        six_hundred_secrets_made_one_after_another_report_their_core_dump_exclusion,
    );
}

fn run(name: &str, check: fn()) {
    check();
    println!("test {name} ... ok");
}

#[cfg(any(unix, windows))]
fn encoding_a_password_and_deriving_a_seed_take_nothing_from_the_heap() {
    let phrase = Phrase::from_entropy(&[0; 32]).unwrap();
    // An ASCII text, and one that NFKD decomposes (a ligature, a Hangul syllable, a starter that
    // decomposes into non-starters) and puts in canonical order, as a password and as a BIP39
    // passphrase.
    for text in [
        "public test password",
        "\u{FB01}x \u{AC01} a\u{0F72}\u{0F73}\u{0301}\u{0316}",
    ] {
        let before = ALLOCATIONS.load(Ordering::Relaxed);
        let password = Password::new(text).unwrap();
        assert_eq!(
            ALLOCATIONS.load(Ordering::Relaxed),
            before,
            "password {text:?}"
        );
        let seed = Seed::derive(&phrase, text);
        assert_eq!(
            ALLOCATIONS.load(Ordering::Relaxed),
            before,
            "passphrase {text:?}"
        );
        drop((password, seed));
    }
}

/// What the system reports of the pages; the unit tests check what `Secret` reports itself.
#[cfg(any(target_os = "linux", windows))]
fn a_secret_lies_on_pages_kept_out_of_swap_and_core_dumps() {
    let mut secret = Secret::with_capacity(16);
    secret.push(b"public").unwrap();
    #[cfg(target_os = "linux")]
    linux::secret_pages_are_marked(&secret);
    #[cfg(windows)]
    assert!(windows::locked(secret.as_bytes().as_ptr()));
}

#[cfg(not(target_arch = "wasm32"))]
fn the_work_area_lies_on_pages_of_its_own() {
    /// One page more than 1 MiB: a size that no other mapping of this program has.
    const AREA_KIB: u32 = 1028;
    #[cfg(target_os = "linux")]
    let before = linux::mappings();
    let engine = NativeArgon2::new(AREA_KIB).unwrap();
    // Unix locks the area when RLIMIT_MEMLOCK holds all of it; Windows once the working set grew
    // by its size, which the process of a user may ask for.
    #[cfg(unix)]
    let lockable = lock_limit() >= u64::from(AREA_KIB) * 1024;
    #[cfg(not(unix))]
    let lockable = true;
    assert_eq!(engine.is_locked(), lockable);
    #[cfg(target_os = "linux")]
    linux::work_area_is_marked(&before, AREA_KIB as usize * 1024, engine.is_locked());
}

fn six_hundred_secrets_made_one_after_another_report_their_core_dump_exclusion() {
    // More than the 512 error-report exclusions that Windows holds for a process: each secret
    // gives its own back.
    let out_of_dumps = cfg!(any(target_os = "linux", target_os = "android", windows));
    for _ in 0..600 {
        assert_eq!(Secret::with_capacity(1).is_out_of_dumps(), out_of_dumps);
    }
}

/// RLIMIT_MEMLOCK, the most memory this process may lock.
#[cfg(unix)]
fn lock_limit() -> u64 {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct, which lives for the call.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
    assert_eq!(read, 0);
    limit.rlim_cur
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ops::Range;
    use std::process::Command;

    use mhfe_core::protect::Secret;

    /// The variable that starts this program as the child of the lock-limit test.
    pub(super) const ROLE: &str = "MHFE_CORE_TEST_LOCK_LIMITS";

    /// The highest lock limit tried, Linux's default: a higher one, or none, only makes the way
    /// down longer.
    const HIGHEST_LOCK_LIMIT: u64 = 8 << 20;

    /// One mapping of /proc/self/smaps: its addresses, its name and its VmFlags.
    pub(super) struct Mapping {
        range: Range<usize>,
        name: String,
        flags: Vec<String>,
    }

    impl Mapping {
        fn has(&self, flag: &str) -> bool {
            self.flags.iter().any(|own| own == flag)
        }
    }

    pub(super) fn mappings() -> Vec<Mapping> {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut mappings: Vec<Mapping> = Vec::new();
        for line in smaps.lines() {
            if let Some(flags) = line.strip_prefix("VmFlags:") {
                let mapping = mappings.last_mut().unwrap();
                mapping.flags = flags.split_whitespace().map(str::to_owned).collect();
                continue;
            }
            let mut fields = line.split_whitespace();
            let range = fields.next().and_then(|range| range.split_once('-'));
            let Some((Ok(start), Ok(end))) = range.map(|(start, end)| {
                (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            }) else {
                continue;
            };
            // After the range: permissions, offset, device and inode, then the name, which may
            // hold a space.
            let name = fields.skip(4).collect::<Vec<_>>().join(" ");
            mappings.push(Mapping {
                range: start..end,
                name,
                flags: Vec::new(),
            });
        }
        mappings
    }

    /// Out of core dumps (`dd`) on pages of either kind. Anonymous pages are locked (`lo`) and give
    /// a child process zeros (`wf`). Secret memory is shared, so a child gets none of it (`dc`),
    /// and its kind is what keeps it out of swap: since Linux commit 97d34aa65c29 its folios are
    /// unevictable and the mapping has no `lo`, which an older kernel's has.
    pub(super) fn secret_pages_are_marked(secret: &Secret) {
        let address = secret.as_bytes().as_ptr() as usize;
        let mappings = mappings();
        let mapping = mappings
            .iter()
            .find(|mapping| mapping.range.contains(&address))
            .unwrap();
        let flags: &[&str] = if mapping.name.starts_with("/secretmem") {
            &["dd", "dc"]
        } else {
            &["dd", "lo", "wf"]
        };
        assert!(
            flags.iter().all(|flag| mapping.has(flag)),
            "{} {:?}",
            mapping.name,
            mapping.flags
        );
    }

    /// The one new mapping of `bytes` bytes is out of core dumps and gives a child zeros, and it
    /// is locked exactly when the engine says so.
    pub(super) fn work_area_is_marked(before: &[Mapping], bytes: usize, locked: bool) {
        let mappings = mappings();
        let new: Vec<&Mapping> = mappings
            .iter()
            .filter(|mapping| mapping.range.len() == bytes)
            .filter(|mapping| before.iter().all(|old| old.range != mapping.range))
            .collect();
        assert_eq!(new.len(), 1);
        let area = new[0];
        assert!(area.has("dd") && area.has("wf"), "{:?}", area.flags);
        assert_eq!(area.has("lo"), locked, "{:?}", area.flags);
    }

    /// In a child process: the limit stays its own, and so does a SIGBUS at a write to a page
    /// beyond the limit.
    pub(super) fn a_secret_works_under_every_lock_limit() {
        let status = Command::new(std::env::current_exe().unwrap())
            .env(ROLE, "child")
            .status()
            .unwrap();
        assert!(status.success(), "{status}");
    }

    /// The child's part: a secret of two pages is written and read back under each limit, down to
    /// 0. The limit comes down a page at a time because secret memory is charged to the user's
    /// count, which other programs add to, so that only one limit, unknown here, falls between the
    /// two pages. They are locked exactly when the limit holds them, on anonymous pages if the
    /// count leaves no room for secret memory; `mlock` lets a process with CAP_IPC_LOCK past any
    /// limit, so this needs one without it.
    pub(super) fn secrets_under_every_lock_limit() {
        // SAFETY: sysconf takes an integer and touches no memory of this process.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let public = vec![0x5a; page as usize + 1];
        let highest = super::lock_limit().min(HIGHEST_LOCK_LIMIT);
        for pages in (0..=highest / page).rev() {
            let limit = libc::rlimit {
                rlim_cur: pages * page,
                rlim_max: pages * page,
            };
            // SAFETY: setrlimit reads the struct, which lives for the call.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) }, 0);
            let mut secret = Secret::with_capacity(public.len());
            secret.push(&public).unwrap();
            assert_eq!(secret.as_bytes(), public, "{pages} pages");
            assert_eq!(
                secret.is_locked(),
                limit.rlim_cur >= public.len() as u64,
                "{pages} pages"
            );
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::mem::size_of;

    use windows_sys::Win32::System::ProcessStatus::{
        K32QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    /// Valid (bit 0) and Locked (bit 22) of PSAPI_WORKING_SET_EX_BLOCK.
    const VALID_AND_LOCKED: usize = 1 | 1 << 22;

    /// Whether the page that holds `address` lies in the working set, locked there.
    pub(super) fn locked(address: *const u8) -> bool {
        let mut page = PSAPI_WORKING_SET_EX_INFORMATION {
            VirtualAddress: address.cast_mut().cast(),
            ..Default::default()
        };
        // SAFETY: the query fills the attributes of the one page that `page` names; the pseudo
        // handle of this process needs no closing.
        let read = unsafe {
            K32QueryWorkingSetEx(
                GetCurrentProcess(),
                (&raw mut page).cast(),
                size_of::<PSAPI_WORKING_SET_EX_INFORMATION>() as u32,
            )
        } != 0;
        // SAFETY: the attributes are one word, which the query wrote.
        read && unsafe { page.VirtualAttributes.Flags } & VALID_AND_LOCKED == VALID_AND_LOCKED
    }
}
