//! AUD-002 skeptic check of mhfe-core dec9c81: does `Phrase::read_word` fail on a 128 KiB thread
//! because of the crate's stack clear, where a call that does not clear the stack runs?
//!
//!   aud002-skeptic-api-stack                     every case below, each in a child process
//!   aud002-skeptic-api-stack <case> <KiB>        one case on a thread of <KiB> KiB
//!
//! Cases: `std-control` (a std thread calls `Suite::id`, which does not clear the stack, and prints
//! the free stack below its frame), `std-read-word` (a std thread calls `Phrase::read_word`),
//! `pthread-control` and `pthread-read-word` (the same on a thread made by `pthread_create` with
//! that stack size, as a C host makes one; musl's default is 128 KiB), `std-encrypt` (a std thread
//! runs `Mhfe::encrypt` with a stand-in engine, so no Argon2id work, to see the nested round clear).
//! The run also prints, for information, the smallest of a list of std thread sizes each of
//! `Phrase::read_word` and `Mhfe::encrypt` completes on.
//!
//! Exit 0: `Phrase::read_word` completes on every 128 KiB thread. Exit 1: it fails there while the
//! control completes (the finding holds). Exit 2: a control fails, or a case could not run (the
//! harness proves nothing).
#![allow(
    unsafe_code,
    reason = "the free stack and the C host's threads need pthread calls through libc"
)]

use std::ops::ControlFlow;
use std::process::{Command, ExitCode};

use mhfe_core::{Argon2Engine, Error, Mhfe, Password, Phrase, Suite, WorkFactor};

/// The exit code of a run in which the finding holds; 0 is a run in which it does not.
const HOLDS: u8 = 1;
/// The exit code of a run that proves nothing: a control failed, or a case could not run.
const BROKEN: u8 = 2;
/// The default thread stack of musl's pthread_create, in KiB, which a C host may give a caller.
const MUSL_DEFAULT_KIB: usize = 128;
/// A thread small enough to show the control's own need, in KiB.
const SMALL_KIB: usize = 64;
/// A thread on which every case completes, in KiB.
const LARGE_KIB: usize = 256;
/// The std thread sizes tried for the smallest that completes, in KiB.
const FLOOR_SIZES_KIB: [usize; 12] = [128, 136, 144, 152, 160, 176, 192, 224, 256, 320, 384, 512];

/// A stand-in for Argon2id: a key that depends on the password and the salt, with no memory work.
struct StandIn;

impl Argon2Engine for StandIn {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; 16],
        _memory_kib: u32,
        _passes: u32,
        key: &mut [u8; 32],
    ) -> Result<(), Error> {
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = salt[i % 16] ^ password[i % password.len()] ^ i as u8;
        }
        Ok(())
    }
}

fn encrypt() -> Result<(), String> {
    let phrase = Phrase::read(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         about",
    )
    .map_err(|error| format!("the test phrase: {error}"))?;
    let password = Password::new("public test password")
        .map_err(|error| format!("the test password: {error}"))?;
    let mut cipher = Mhfe::with_engine(WorkFactor::default(), StandIn);
    let result = cipher.encrypt(
        &phrase,
        &password,
        Suite::TwentyFourWords,
        &mut |_, _| ControlFlow::Continue(()),
        &mut |_| ControlFlow::Continue(()),
    );
    print!("encrypt: {:?}; ", result.map(|c| c.words()));
    Ok(())
}

/// The bytes between this frame and the low end of the calling thread's stack.
fn free_stack() -> Result<usize, String> {
    let here = 0u8;
    let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
    let mut low = std::ptr::null_mut();
    let mut size = 0;
    // SAFETY: getattr fills `attr` for the calling thread; getstack reads it only when getattr
    // succeeded; destroy frees it.
    let read = unsafe {
        if libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()) != 0 {
            return Err("pthread_getattr_np failed".to_owned());
        }
        let read = libc::pthread_attr_getstack(attr.as_ptr(), &mut low, &mut size);
        libc::pthread_attr_destroy(attr.as_mut_ptr());
        read
    };
    if read != 0 {
        return Err("pthread_attr_getstack failed".to_owned());
    }
    Ok(std::ptr::from_ref(&here) as usize - low as usize)
}

fn body(read_word: bool) -> Result<(), String> {
    let free = free_stack()?;
    if read_word && std::env::args().nth(1).as_deref() == Some("std-encrypt") {
        encrypt()?;
    } else if read_word {
        if Phrase::read_word("aban") != Some("abandon") {
            return Err("read_word misread aban".to_owned());
        }
    } else if Suite::TwentyFourWords.id().is_empty() {
        return Err("the suite has no id".to_owned());
    }
    println!("free stack at the call: {} KiB", free / 1024);
    Ok(())
}

extern "C" fn pthread_body(read_word: *mut libc::c_void) -> *mut libc::c_void {
    if let Err(message) = body(!read_word.is_null()) {
        eprintln!("{message}");
        std::process::exit(BROKEN.into());
    }
    std::ptr::null_mut()
}

/// Runs one case on a thread of `kib` KiB.
fn one(case: &str, kib: usize) -> Result<(), String> {
    let read_word = case.ends_with("read-word") || case == "std-encrypt";
    if case.starts_with("std-") {
        return std::thread::Builder::new()
            .stack_size(kib * 1024)
            .spawn(move || body(read_word))
            .map_err(|error| format!("thread of {kib} KiB: {error}"))?
            .join()
            .map_err(|_| "the thread panicked".to_owned())?;
    }
    let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
    let mut thread = 0;
    // Any pointer that is not null says "read_word" to the thread.
    let arg = if read_word {
        std::ptr::dangling_mut::<libc::c_void>()
    } else {
        std::ptr::null_mut()
    };
    // SAFETY: a fresh attribute object with the given stack size; each call goes on only when the
    // one before succeeded, and the thread is joined before the function returns.
    let failed = unsafe {
        if libc::pthread_attr_init(attr.as_mut_ptr()) != 0 {
            "pthread_attr_init"
        } else if libc::pthread_attr_setstacksize(attr.as_mut_ptr(), kib * 1024) != 0 {
            "pthread_attr_setstacksize"
        } else if libc::pthread_create(&mut thread, attr.as_ptr(), pthread_body, arg) != 0 {
            "pthread_create"
        } else if libc::pthread_join(thread, std::ptr::null_mut()) != 0 {
            "pthread_join"
        } else {
            ""
        }
    };
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("{failed} failed"))
    }
}

/// Whether the case completes on `kib` KiB, in a child process. A signal is the overflow (SIGABRT
/// from Rust's guard page handler, or SIGSEGV); an exit code other than 0 is a case that could not
/// run, which says nothing of the stack.
fn completes(case: &str, kib: usize) -> Result<bool, String> {
    let me = std::env::current_exe().map_err(|error| format!("this program's path: {error}"))?;
    let out = Command::new(me)
        .args([case, &kib.to_string()])
        .output()
        .map_err(|error| format!("child for {case} on {kib} KiB: {error}"))?;
    let said = String::from_utf8_lossy(&out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    println!(
        "{case} on {kib} KiB: {} {}{}",
        out.status,
        said.trim(),
        err.lines().last().unwrap_or("")
    );
    match out.status.code() {
        Some(0) => Ok(true),
        None => Ok(false),
        Some(_) => Err(format!("{case} on {kib} KiB could not run")),
    }
}

/// Every case: the controls, the check and the smallest sizes. Returns whether the controls
/// completed and whether `read_word` completed on every 128 KiB thread.
fn all() -> Result<(bool, bool), String> {
    let mut controls = true;
    let mut held = true;
    for kind in ["std", "pthread"] {
        controls &= completes(&format!("{kind}-control"), SMALL_KIB)?;
        controls &= completes(&format!("{kind}-control"), MUSL_DEFAULT_KIB)?;
        held &= completes(&format!("{kind}-read-word"), MUSL_DEFAULT_KIB)?;
        controls &= completes(&format!("{kind}-read-word"), LARGE_KIB)?;
    }
    for case in ["std-read-word", "std-encrypt"] {
        let mut floor = None;
        for kib in FLOOR_SIZES_KIB {
            if completes(case, kib)? {
                floor = Some(kib);
                break;
            }
        }
        println!("{case}: smallest std thread that completes: {floor:?} KiB");
    }
    Ok((controls, held))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let outcome = if let [_, case, kib] = &args[..] {
        kib.parse()
            .map_err(|_| format!("not a size in KiB: {kib}"))
            .and_then(|kib| one(case, kib))
            .map(|()| (true, true))
    } else {
        all()
    };
    match outcome {
        Ok((true, true)) => ExitCode::SUCCESS,
        Ok((true, false)) => ExitCode::from(HOLDS),
        Ok((false, _)) => ExitCode::from(BROKEN),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(BROKEN)
        }
    }
}
