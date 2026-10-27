//! Secret pages on Windows: committed with `VirtualAlloc`, locked with `VirtualLock` once the
//! working set has room for them, and left out of Windows Error Reporting dumps. The work area of
//! Argon2id is such a region too. Also the protections of [`crate::protect::Isolation::enter`],
//! each for the whole process, and the secret writer.
#![allow(
    unsafe_code,
    reason = "the memory, error-reporting, security, thread and console calls of Windows are \
              foreign functions"
)]

use std::io;
use std::mem::size_of;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::Once;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, ERROR_SUCCESS, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree, S_OK,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid, GetSecurityDescriptorDacl,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, SID_AND_ATTRIBUTES, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenDefaultDacl,
    TokenIntegrityLevel,
};
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_OUTPUT_HANDLE, WriteConsoleW,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::ErrorReporting::{
    WER_FAULT_REPORTING_FLAG_NOHEAP, WerGetFlags, WerRegisterExcludedMemoryBlock, WerSetFlags,
    WerUnregisterExcludedMemoryBlock,
};
use windows_sys::Win32::System::Memory::{
    GetProcessWorkingSetSizeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    SetProcessWorkingSetSizeEx, VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessIdOfThread, OpenProcessToken, OpenThread,
};
use windows_sys::core::{PCWSTR, w};

use super::Pages;
use crate::protect::{Isolation, Secret};

/// What the working set grows by, once, so that the secrets of a process fit into what Windows
/// lets it lock: a process may lock little more than its minimum working set.
const WORKING_SET_RAISE: usize = 1 << 20;
/// The largest block one registration leaves out of error reports: its size is a 32-bit value.
const REPORT_BLOCK: usize = u32::MAX as usize;

static WORKING_SET_RAISED: Once = Once::new();

impl Pages {
    /// `bytes` bytes, at least one, in pages of their own.
    pub(crate) fn new(bytes: usize) -> Self {
        let start = commit(bytes).unwrap_or_else(|| super::out_of_memory(bytes));
        WORKING_SET_RAISED.call_once(|| {
            move_working_set(WORKING_SET_RAISE.cast_signed());
        });
        // SAFETY: VirtualLock only changes how Windows keeps the pages of the region just made.
        let locked = unsafe { VirtualLock(start.as_ptr().cast(), bytes) } != 0;
        Self {
            start,
            bytes,
            locked,
            excluded: exclude_from_reports(start, bytes),
            raised: 0,
        }
    }

    /// The work area of Argon2id: committed pages, or `None` when Windows refuses them. They are
    /// locked after the working set grew by their size, which a refusal, such as
    /// `ERROR_NO_SYSTEM_RESOURCES`, leaves unlocked; they are left out of error reports in blocks
    /// below 4 GiB, as far as the 512 registrations of a process reach.
    pub(crate) fn work_area(bytes: usize) -> Option<Self> {
        let start = commit(bytes)?;
        let raised = if move_working_set(bytes.cast_signed()) {
            bytes
        } else {
            0
        };
        // SAFETY: as in `new`.
        let locked = raised > 0 && unsafe { VirtualLock(start.as_ptr().cast(), bytes) } != 0;
        Some(Self {
            start,
            bytes,
            locked,
            excluded: exclude_from_reports(start, bytes),
            raised,
        })
    }

    pub(crate) fn is_out_of_dumps(&self) -> bool {
        self.excluded == self.bytes.div_ceil(REPORT_BLOCK)
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        let start = self.start.as_ptr();
        for block in 0..self.excluded {
            // SAFETY: gives back a registration `exclude_from_reports` made for this region.
            unsafe {
                WerUnregisterExcludedMemoryBlock(start.wrapping_add(block * REPORT_BLOCK).cast())
            };
        }
        if self.locked {
            // SAFETY: unlocks the pages the constructor locked.
            unsafe { VirtualUnlock(start.cast(), self.bytes) };
        }
        // SAFETY: the region belongs to this value alone and nothing borrows it any more.
        unsafe { VirtualFree(start.cast(), 0, MEM_RELEASE) };
        if self.raised > 0 {
            move_working_set(-self.raised.cast_signed());
        }
    }
}

/// A new committed region of `bytes` bytes, or `None` when Windows refuses it.
fn commit(bytes: usize) -> Option<NonNull<u8>> {
    // SAFETY: a new committed region, at an address Windows chooses, takes no memory that
    // anything else owns.
    let mapped =
        unsafe { VirtualAlloc(ptr::null(), bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    NonNull::new(mapped.cast::<u8>())
}

/// Registers the region with Windows Error Reporting in blocks of [`REPORT_BLOCK`] bytes or fewer,
/// until a registration is refused, and returns how many were made.
fn exclude_from_reports(start: NonNull<u8>, bytes: usize) -> usize {
    let mut excluded = 0;
    for offset in (0..bytes).step_by(REPORT_BLOCK) {
        let size = (bytes - offset).min(REPORT_BLOCK) as u32;
        // SAFETY: the block lies inside the region, which stays until `drop` unregisters it.
        let registered = unsafe {
            WerRegisterExcludedMemoryBlock(start.as_ptr().wrapping_add(offset).cast(), size)
        } == S_OK;
        if !registered {
            break;
        }
        excluded += 1;
    }
    excluded
}

/// Moves the minimum and maximum working set by `change` bytes, and returns whether Windows
/// agreed. A refusal leaves them, and `VirtualLock` then locks what still fits.
fn move_working_set(change: isize) -> bool {
    let (mut minimum, mut maximum, mut flags) = (0, 0, 0);
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing; the call writes
    // the three values it is given.
    let read = unsafe {
        GetProcessWorkingSetSizeEx(GetCurrentProcess(), &mut minimum, &mut maximum, &mut flags)
    } != 0;
    // SAFETY: changes only the working-set limits of this process.
    read && unsafe {
        SetProcessWorkingSetSizeEx(
            GetCurrentProcess(),
            minimum.saturating_add_signed(change),
            maximum.saturating_add_signed(change),
            flags,
        )
    } != 0
}

/// The access list the process gets: one entry, for its owner (OWNER RIGHTS, `OW`), which replaces
/// the owner's implicit rights to read and change the list, and grants only SYNCHRONIZE,
/// PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_TERMINATE (0x0010_1001); `P` keeps out the entries
/// a parent would pass on.
const PROCESS_ACCESS: PCWSTR = w!("D:P(A;;0x101001;;;OW)");
/// The access list of every thread, and the default list of the token, which the threads started
/// later get: one entry for the owner, as above, granting only READ_CONTROL, SYNCHRONIZE and
/// THREAD_QUERY_LIMITED_INFORMATION (0x0012_0800). READ_CONTROL lets a later call read the lists
/// back, which it can no longer change.
const THREAD_ACCESS: PCWSTR = w!("D:P(A;;0x120800;;;OW)");
/// MAXIMUM_ALLOWED of winnt.h: a handle with every right that the object's list grants.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// The low mandatory level (S-1-16-4096), and its last sub-authority, SECURITY_MANDATORY_LOW_RID.
const LOW_INTEGRITY: PCWSTR = w!("S-1-16-4096");
const LOW_INTEGRITY_RID: u32 = 0x1000;
/// SE_GROUP_INTEGRITY of winnt.h: the SID of a label is a mandatory level.
const GROUP_INTEGRITY: u32 = 0x20;

pub(crate) fn enter() -> Isolation {
    // SAFETY: changes only what Windows Error Reporting collects when this process fails.
    unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) };
    let mut token = ptr::null_mut();
    // Once the token is low, Windows may refuse a later call the right to change it: reading it is
    // enough for the read-backs below.
    // SAFETY: opens the token of this process for reading and changing its defaults, or else for
    // reading only; closed below.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
            &mut token,
        ) != 0
            || OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0
    };
    // The access lists are set while the token still has its own integrity level, and the default
    // one before the threads are listed, so that a thread started meanwhile gets it.
    // SAFETY: the pseudo handle of this process needs no closing and has every right to it,
    // WRITE_DAC included.
    let process = restrict_access(unsafe { GetCurrentProcess() }, PROCESS_ACCESS);
    let default_list = opened && restrict_default(token);
    let threads = restrict_threads();
    let no_file_changes = opened && lower_integrity(token);
    if opened {
        // SAFETY: closes the token opened above, once.
        unsafe { CloseHandle(token) };
    }
    let mut flags = 0;
    // SAFETY: the pseudo handle of this process needs no closing; the call writes the flags.
    let read = unsafe { WerGetFlags(GetCurrentProcess(), &mut flags) } == S_OK;
    Isolation {
        no_core_dumps: read && flags & WER_FAULT_REPORTING_FLAG_NOHEAP != 0,
        no_memory_reading: process && default_list && threads,
        no_file_changes,
        whole_process: true,
        ..Isolation::default()
    }
}

/// Hands the access list of the descriptor `access` to `apply`, and returns its answer; false
/// when the string makes no list.
fn with_access_list(access: PCWSTR, apply: impl FnOnce(*mut ACL) -> bool) -> bool {
    let mut descriptor = ptr::null_mut();
    // SAFETY: the string is NUL-terminated; the call allocates the descriptor, freed below.
    let made = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            access,
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } != 0;
    if !made {
        return false;
    }
    let (mut present, mut defaulted, mut list) = (0, 0, ptr::null_mut());
    // SAFETY: points `list` into the descriptor just made, which lives until it is freed.
    let found =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut list, &mut defaulted) }
            != 0
            && present != 0;
    let holds = found && apply(list);
    // SAFETY: frees the descriptor the conversion allocated, once, after its last use.
    unsafe { LocalFree(descriptor) };
    holds
}

/// Gives `object` the access list of `access`, and returns whether its list reads back as that
/// one entry. Only the reading decides: a list that an earlier call or the token's default gave
/// the object refuses the change, and holds.
fn restrict_access(object: HANDLE, access: PCWSTR) -> bool {
    with_access_list(access, |wanted| {
        // SAFETY: the handle is open, and the list lives for the call.
        unsafe {
            SetSecurityInfo(
                object,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                wanted,
                ptr::null(),
            )
        };
        access_reads_back(object, wanted)
    })
}

/// Whether the access list of `object` holds exactly the one entry of `wanted`.
fn access_reads_back(object: HANDLE, wanted: *const ACL) -> bool {
    let (mut current, mut descriptor) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: the call points `current` into a descriptor it allocates, freed below.
    let read = unsafe {
        GetSecurityInfo(
            object,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut current,
            ptr::null_mut(),
            &mut descriptor,
        )
    } == ERROR_SUCCESS;
    if !read {
        return false;
    }
    // SAFETY: both lists are valid while their descriptors live, which they do here.
    let same = unsafe { same_only_entry(current, wanted) };
    // SAFETY: frees the descriptor GetSecurityInfo allocated, once, after its last use.
    unsafe { LocalFree(descriptor) };
    same
}

/// Makes the access list of [`THREAD_ACCESS`] the default list of `token`, which every object the
/// process makes afterwards without a list of its own gets, and returns whether it reads back as
/// that one entry.
fn restrict_default(token: HANDLE) -> bool {
    with_access_list(THREAD_ACCESS, |wanted| {
        let default = TOKEN_DEFAULT_DACL {
            DefaultDacl: wanted,
        };
        // SAFETY: the structure and its list live for the call, which copies them into the token.
        unsafe {
            SetTokenInformation(
                token,
                TokenDefaultDacl,
                (&raw const default).cast(),
                size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
        };
        // TOKEN_DEFAULT_DACL and the list after it, of one entry with a SID of one sub-authority:
        // 36 bytes, well within 256, in words aligned for the pointer.
        let mut buffer = [0u64; 32];
        let mut length = 0;
        // SAFETY: the call writes at most the buffer's length into it, and the length it needed.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenDefaultDacl,
                buffer.as_mut_ptr().cast(),
                size_of::<[u64; 32]>() as u32,
                &mut length,
            )
        } != 0;
        // SAFETY: the call filled the buffer with a pointer to a list inside it, or a null one;
        // `wanted` lives for the closure.
        read && unsafe {
            let current = (*buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl;
            same_only_entry(current, wanted)
        }
    })
}

/// Gives every thread of the process [`THREAD_ACCESS`] as its access list, and returns whether
/// each reads back so.
fn restrict_threads() -> bool {
    // SAFETY: takes a snapshot of the threads of the system, closed below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return false;
    }
    // SAFETY: returns the number of this process.
    let process = unsafe { GetCurrentProcessId() };
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    // SAFETY: fills `entry`, whose size it names, from the snapshot.
    let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    // The list holds the calling thread at least.
    let mut all = more;
    while more {
        if entry.th32OwnerProcessID == process {
            all &= restrict_thread(entry.th32ThreadID, process);
        }
        // SAFETY: as above.
        more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    // SAFETY: reads this thread's last error, which Thread32Next set: the end of the list, or a
    // failure that may have left threads out.
    all &= unsafe { GetLastError() } == ERROR_NO_MORE_FILES;
    // SAFETY: closes the snapshot taken above, once.
    unsafe { CloseHandle(snapshot) };
    all
}

/// Gives the thread numbered `id` [`THREAD_ACCESS`] as its access list, and returns whether it
/// reads back so. A thread that has ended since the snapshot is left out, and so is the thread
/// of another process that has taken its number since.
fn restrict_thread(id: u32, process: u32) -> bool {
    // SAFETY: opens the thread with what its list grants: every right while it has the list it
    // started with; READ_CONTROL and THREAD_QUERY_LIMITED_INFORMATION once it has THREAD_ACCESS.
    // Closed below.
    let thread = unsafe { OpenThread(MAXIMUM_ALLOWED, 0, id) };
    if thread.is_null() {
        // SAFETY: reads this thread's last error, which OpenThread set.
        return unsafe { GetLastError() } == ERROR_INVALID_PARAMETER;
    }
    // SAFETY: the handle is open, with THREAD_QUERY_LIMITED_INFORMATION under either list.
    let owner = unsafe { GetProcessIdOfThread(thread) };
    let holds = owner != 0 && (owner != process || restrict_access(thread, THREAD_ACCESS));
    // SAFETY: closes the handle opened above, once.
    unsafe { CloseHandle(thread) };
    holds
}

/// Whether the access lists `current` and `wanted` each hold one entry, and the same one.
///
/// # Safety
///
/// Each list is null or points to a valid access list.
unsafe fn same_only_entry(current: *const ACL, wanted: *const ACL) -> bool {
    // The bytes of the one entry of a list; `None` for a list with none or several.
    let only_entry = |list: *const ACL| {
        // SAFETY: by the contract above.
        if unsafe { list.as_ref() }?.AceCount != 1 {
            return None;
        }
        let mut entry = ptr::null_mut();
        // SAFETY: the list holds entry 0; GetAce points `entry` at it, inside the list.
        if unsafe { GetAce(list, 0, &mut entry) } == 0 {
            return None;
        }
        // SAFETY: an entry starts with its header, whose AceSize counts the whole entry, which
        // lies inside the list.
        Some(unsafe {
            let size = (*entry.cast::<ACE_HEADER>()).AceSize;
            slice::from_raw_parts(entry.cast::<u8>(), size.into())
        })
    };
    only_entry(current).is_some_and(|entry| only_entry(wanted) == Some(entry))
}

/// Lowers `token`, the token of the process, to low integrity, and returns whether it reads back
/// so.
fn lower_integrity(token: HANDLE) -> bool {
    let mut low = ptr::null_mut();
    // SAFETY: the string is NUL-terminated; the call allocates the SID, freed below.
    if unsafe { ConvertStringSidToSidW(LOW_INTEGRITY, &mut low) } != 0 {
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: low,
                Attributes: GROUP_INTEGRITY,
            },
        };
        // SAFETY: the label and its SID live for the call, whose length counts both; lowering
        // the level needs no privilege. Then frees the SID the conversion allocated, once.
        unsafe {
            let length = size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(low);
            SetTokenInformation(
                token,
                TokenIntegrityLevel,
                (&raw const label).cast(),
                length,
            );
            LocalFree(low);
        }
    }
    integrity_of(token).is_some_and(|rid| rid <= LOW_INTEGRITY_RID)
}

/// The mandatory level of `token`: the last sub-authority of its label's SID.
fn integrity_of(token: HANDLE) -> Option<u32> {
    // TOKEN_MANDATORY_LABEL and the SID it points to, which has one sub-authority: well within 64
    // bytes, in words aligned for the pointer.
    let mut buffer = [0u64; 8];
    let mut length = 0;
    // SAFETY: the call writes at most the buffer's length into it, and the length it needed.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            buffer.as_mut_ptr().cast(),
            size_of::<[u64; 8]>() as u32,
            &mut length,
        )
    } != 0;
    if !read {
        return None;
    }
    // SAFETY: the call filled the buffer with a label whose SID lies inside it; the SID's count
    // of sub-authorities names the last one.
    unsafe {
        let sid = (*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        let last = u32::from(*GetSidSubAuthorityCount(sid)).checked_sub(1)?;
        Some(*GetSidSubAuthority(sid, last))
    }
}

/// Writes `text` to standard output: on a console as UTF-16 with `WriteConsoleW`, from a
/// [`Secret`], else as UTF-8 with `WriteFile`; again for what a partial write left.
pub(crate) fn write_secret(text: &str) -> io::Result<()> {
    // SAFETY: returns the handle of standard output, which this process does not own and keeps
    // open; a missing one makes the writes below fail.
    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let mut mode = 0;
    // SAFETY: writes the console mode into `mode`, and fails when the handle is no console.
    if unsafe { GetConsoleMode(output, &mut mode) } == 0 {
        return write_all(text.as_bytes(), 1, |bytes, length, written| {
            // SAFETY: WriteFile reads `length` bytes of `bytes`, which live for the call.
            unsafe { WriteFile(output, bytes.as_ptr(), length, written, ptr::null_mut()) }
        });
    }
    let mut wide = Secret::zeroed(2 * text.encode_utf16().count());
    let (units, _) = wide.as_mut_bytes().as_chunks_mut::<2>();
    for (bytes, unit) in units.iter_mut().zip(text.encode_utf16()) {
        *bytes = unit.to_ne_bytes();
    }
    write_all(wide.as_bytes(), 2, |bytes, length, written| {
        // SAFETY: the pages of a secret begin on a page, so its bytes are aligned UTF-16 units;
        // WriteConsoleW reads `length` of them, which live for the call.
        unsafe { WriteConsoleW(output, bytes.as_ptr().cast(), length, written, ptr::null()) }
    })
}

/// Hands `bytes`, in units of `unit` bytes, to `write` until it has taken them all; `write` takes
/// the rest, the number of units to write and where it counts those it wrote, and returns
/// nonzero on success.
fn write_all(
    mut bytes: &[u8],
    unit: usize,
    write: impl Fn(&[u8], u32, &mut u32) -> i32,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let length = u32::try_from(bytes.len() / unit).unwrap_or(u32::MAX);
        let mut written = 0;
        if write(bytes, length, &mut written) == 0 {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            // As `Write::write_all` does: a write that takes nothing would be asked again forever.
            return Err(io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[written as usize * unit..];
    }
    Ok(())
}
