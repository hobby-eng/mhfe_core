//! The binding of the vendored reference Argon2 C code, which Rust reaches only through MHFE's own
//! wrapper `argon2_wrap.c`, and the work area the C code computes in. Every `unsafe` block states
//! what it relies on.
#![allow(
    unsafe_code,
    reason = "the vendored C code is reached through foreign functions"
)]

use std::cell::Cell;
use std::ffi::c_int;
use std::ptr::{self, NonNull};

use zeroize::Zeroize;

use crate::Error;
use crate::os::Pages;

// Values from vendor/phc-winner-argon2/include/argon2.h.
const ARGON2_OK: c_int = 0;
const ARGON2_PWD_TOO_LONG: c_int = -5;
const ARGON2_MEMORY_ALLOCATION_ERROR: c_int = -22;
/// `Argon2_id` in `enum Argon2_type`.
const ARGON2_ID: c_int = 2;
pub(super) const ARGON2_VERSION_13: u32 = 0x13;
/// None of argon2.h's flags: the core wipes its own copies of the password.
const ARGON2_DEFAULT_FLAGS: u32 = 0;

type AllocateCallback = unsafe extern "C" fn(memory: *mut *mut u8, bytes: usize) -> c_int;
type FreeCallback = unsafe extern "C" fn(memory: *mut u8, bytes: usize);

/// Field-for-field copy of `argon2_context` in include/argon2.h.
#[repr(C)]
struct Argon2Context {
    out: *mut u8,
    outlen: u32,
    pwd: *mut u8,
    pwdlen: u32,
    salt: *mut u8,
    saltlen: u32,
    secret: *mut u8,
    secretlen: u32,
    ad: *mut u8,
    adlen: u32,
    t_cost: u32,
    m_cost: u32,
    lanes: u32,
    threads: u32,
    version: u32,
    allocate_cbk: Option<AllocateCallback>,
    free_cbk: Option<FreeCallback>,
    flags: u32,
}

// The Rust copy must have exactly the C layout, or the C code would read the wrong fields.
// Each pointer takes the pointer size and alignment, each uint32_t four bytes, and a
// pointer that follows a uint32_t starts at the next pointer-aligned offset.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<Argon2Context>() == 120);
    assert!(align_of::<Argon2Context>() == 8);
    assert!(offset_of!(Argon2Context, out) == 0);
    assert!(offset_of!(Argon2Context, outlen) == 8);
    assert!(offset_of!(Argon2Context, pwd) == 16);
    assert!(offset_of!(Argon2Context, pwdlen) == 24);
    assert!(offset_of!(Argon2Context, salt) == 32);
    assert!(offset_of!(Argon2Context, saltlen) == 40);
    assert!(offset_of!(Argon2Context, secret) == 48);
    assert!(offset_of!(Argon2Context, secretlen) == 56);
    assert!(offset_of!(Argon2Context, ad) == 64);
    assert!(offset_of!(Argon2Context, adlen) == 72);
    assert!(offset_of!(Argon2Context, t_cost) == 76);
    assert!(offset_of!(Argon2Context, m_cost) == 80);
    assert!(offset_of!(Argon2Context, lanes) == 84);
    assert!(offset_of!(Argon2Context, threads) == 88);
    assert!(offset_of!(Argon2Context, version) == 92);
    assert!(offset_of!(Argon2Context, allocate_cbk) == 96);
    assert!(offset_of!(Argon2Context, free_cbk) == 104);
    assert!(offset_of!(Argon2Context, flags) == 112);
};

unsafe extern "C" {
    /// `argon2_ctx`, then a clear of the stack it used on the calling thread (argon2_wrap.c).
    fn mhfe_argon2_ctx(context: *mut Argon2Context, argon2_type: c_int) -> c_int;
    /// `MHFE_FLAG_SSSE3` of argon2_wrap.h, the bit of `flags` that runs the SSSE3 copy of the
    /// Argon2 core, read from the C code rather than copied.
    safe static mhfe_flag_ssse3: u32;
    /// The C code wipes its internal buffers only while this global is non-zero (core.c).
    #[cfg(test)]
    static FLAG_clear_internal_memory: c_int;
}

/// Inputs of one Argon2 call. MHFE leaves the secret and the associated data empty; the tests
/// fill them to check this binding against the RFC 9106 test vector.
pub(super) struct Argon2Inputs<'a> {
    pub(super) password: &'a [u8],
    pub(super) salt: &'a [u8],
    pub(super) secret: &'a [u8],
    pub(super) associated_data: &'a [u8],
    pub(super) passes: u32,
    pub(super) memory_kib: u32,
    pub(super) lanes: u32,
    pub(super) threads: u32,
    pub(super) version: u32,
    /// Run the SSSE3 copy of the Argon2 core instead of the SSE2 one; only x86-64 has both, and
    /// only a processor with SSSE3 may get `true`.
    pub(super) ssse3: bool,
}

/// Runs Argon2id in `work_area` and writes the tag into `output`. Errors:
/// [`Error::OutOfMemory`] when the call needs more memory than the area holds, else
/// [`Error::Argon2Failed`] with the reference code's return value.
pub(super) fn argon2id(
    inputs: &Argon2Inputs<'_>,
    work_area: &mut WorkArea,
    output: &mut [u8],
) -> Result<(), Error> {
    // A password longer than a uint32_t holds is refused, as the C code's own entry points refuse
    // it; every other length fits: a 16-byte salt and a 32-byte tag, and the tests' inputs are
    // short too.
    let pwdlen = u32::try_from(inputs.password.len()).map_err(|_| Error::Argon2Failed {
        code: ARGON2_PWD_TOO_LONG,
    })?;
    let mut context = Argon2Context {
        out: output.as_mut_ptr(),
        outlen: output.len() as u32,
        // The C struct has non-const pointers, but the C code writes through `pwd` and
        // `secret` only when a CLEAR flag is set, and `flags` below never sets one.
        pwd: pointer_or_null(inputs.password),
        pwdlen,
        salt: pointer_or_null(inputs.salt),
        saltlen: inputs.salt.len() as u32,
        secret: pointer_or_null(inputs.secret),
        secretlen: inputs.secret.len() as u32,
        ad: pointer_or_null(inputs.associated_data),
        adlen: inputs.associated_data.len() as u32,
        t_cost: inputs.passes,
        m_cost: inputs.memory_kib,
        lanes: inputs.lanes,
        threads: inputs.threads,
        version: inputs.version,
        allocate_cbk: Some(hand_out_work_area),
        free_cbk: Some(keep_work_area),
        flags: if inputs.ssse3 {
            ARGON2_DEFAULT_FLAGS | mhfe_flag_ssse3
        } else {
            ARGON2_DEFAULT_FLAGS
        },
    };
    run(&mut context, work_area)
}

fn run(context: &mut Argon2Context, work_area: &mut WorkArea) -> Result<(), Error> {
    let area = work_area.pages.as_mut_slice();
    let handed_out = (NonNull::from(&mut *area).cast::<u8>(), area.len());
    CURRENT_WORK_AREA.with(|slot| slot.set(Some(handed_out)));
    // SAFETY: every pointer in `context` is either NULL with length 0 or points to a live
    // buffer of the stated length that outlives this call: the inputs are shared borrows the C
    // code only reads, `out` is an exclusive borrow, and the work area is exclusively borrowed
    // through `&mut WorkArea`, so nothing else touches it meanwhile. argon2_ctx joins all its
    // worker threads before it returns, also when creating one fails, so no thread keeps these
    // pointers afterwards; only a failing join could leave one running, and a join fails only
    // for a thread that is invalid or would deadlock, which the C code never passes. It keeps
    // no other global state, so calls on different threads do not interfere.
    let code = unsafe { mhfe_argon2_ctx(context, ARGON2_ID) };
    CURRENT_WORK_AREA.with(|slot| slot.set(None));
    if code == ARGON2_OK {
        return Ok(());
    }
    // After a failure in the filling step, for example a thread that could not be created,
    // argon2_ctx returns before finalize(), which is where the C code wipes the work area.
    // Blocks derived from the password may be left in it, so wipe it here.
    work_area.wipe();
    Err(if code == ARGON2_MEMORY_ALLOCATION_ERROR {
        Error::OutOfMemory
    } else {
        Error::Argon2Failed { code }
    })
}

/// The C code expects NULL for an empty secret or associated data.
fn pointer_or_null(buffer: &[u8]) -> *mut u8 {
    if buffer.is_empty() {
        ptr::null_mut()
    } else {
        buffer.as_ptr().cast_mut()
    }
}

/// The Argon2 memory of one engine on pages of its own: reserved once, handed to the C code in
/// every call and given back when the engine is dropped.
pub(super) struct WorkArea {
    pages: Pages,
}

impl WorkArea {
    /// `memory_kib` KiB, or [`Error::OutOfMemory`] when the system refuses them.
    pub(super) fn allocate(memory_kib: u32) -> Result<Self, Error> {
        let bytes = memory_kib as usize * 1024;
        let pages = Pages::work_area(bytes).ok_or(Error::OutOfMemory)?;
        Ok(Self { pages })
    }

    /// Whether the system keeps the area in memory, never in swap.
    pub(super) fn is_locked(&self) -> bool {
        self.pages.is_locked()
    }

    /// Overwrites the whole area with zeros. The C code wipes it at the end of every successful
    /// call; this covers the calls that fail before that point (see `run`).
    fn wipe(&mut self) {
        // SAFETY: every bit pattern is a valid u64, so the bytes may be read as words. The area
        // starts on a page, so the words cover it whole and the two byte ends are empty: as
        // words it takes eight times fewer volatile writes.
        let (head, words, tail) = unsafe { self.pages.as_mut_slice().align_to_mut::<u64>() };
        // zeroize writes through volatile stores, which the compiler may not remove even
        // though the memory is not read again before it is given back.
        head.zeroize();
        words.zeroize();
        tail.zeroize();
    }
}

thread_local! {
    /// The work area of the Argon2 call running on this thread. The C allocation callbacks
    /// receive no pointer of our own, so `run` places the area here for the length of one call.
    static CURRENT_WORK_AREA: Cell<Option<(NonNull<u8>, usize)>> = const { Cell::new(None) };
}

/// `allocate_cbk`: gives the C code the prepared work area instead of allocating new memory.
/// The C code calls it on the thread that called `argon2_ctx`, before any worker thread starts.
unsafe extern "C" fn hand_out_work_area(memory: *mut *mut u8, bytes: usize) -> c_int {
    let area = CURRENT_WORK_AREA.try_with(Cell::get).ok().flatten();
    let pointer = match area {
        Some((start, size)) if bytes <= size => start.as_ptr(),
        // The C code turns NULL into ARGON2_MEMORY_ALLOCATION_ERROR.
        _ => ptr::null_mut(),
    };
    // SAFETY: `memory` points to the `uint8_t *` variable of allocate_memory() in core.c.
    unsafe { *memory = pointer };
    // allocate_memory() ignores this value and checks the pointer instead.
    ARGON2_OK
}

/// `free_cbk`: keeps the work area for the next round. The C code has already wiped it:
/// free_memory() in core.c calls clear_internal_memory() before this callback.
unsafe extern "C" fn keep_work_area(_memory: *mut u8, _bytes: usize) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::native::processor_has_ssse3;
    use crate::test_support::hex;

    /// The RFC 9106 test vector of Argon2id (section 5.3), in which every input differs and the
    /// secret and the associated data are set, so that every field of the context takes part.
    mod rfc_9106 {
        pub(super) const PASSWORD: [u8; 32] = [0x01; 32];
        pub(super) const SALT: [u8; 16] = [0x02; 16];
        pub(super) const SECRET: [u8; 8] = [0x03; 8];
        pub(super) const ASSOCIATED_DATA: [u8; 12] = [0x04; 12];
        pub(super) const PASSES: u32 = 3;
        pub(super) const MEMORY_KIB: u32 = 32;
        pub(super) const LANES: u32 = 4;
        pub(super) const TAG: &str =
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";
    }

    /// The RFC 9106 call, on the SSSE3 copy of the core if `ssse3`.
    fn rfc_inputs(ssse3: bool) -> Argon2Inputs<'static> {
        Argon2Inputs {
            password: &rfc_9106::PASSWORD,
            salt: &rfc_9106::SALT,
            secret: &rfc_9106::SECRET,
            associated_data: &rfc_9106::ASSOCIATED_DATA,
            passes: rfc_9106::PASSES,
            memory_kib: rfc_9106::MEMORY_KIB,
            lanes: rfc_9106::LANES,
            threads: rfc_9106::LANES,
            version: ARGON2_VERSION_13,
            ssse3,
        }
    }

    fn inputs<'a>(password: &'a [u8], salt: &'a [u8]) -> Argon2Inputs<'a> {
        Argon2Inputs {
            password,
            salt,
            secret: &[],
            associated_data: &[],
            passes: 1,
            memory_kib: 64,
            lanes: 4,
            threads: 4,
            version: ARGON2_VERSION_13,
            ssse3: false,
        }
    }

    /// Runs the C engine with a fresh work area of the memory `inputs` asks for.
    fn c_tag(inputs: &Argon2Inputs<'_>, output_len: usize) -> Result<Vec<u8>, Error> {
        let mut work_area = WorkArea::allocate(inputs.memory_kib)?;
        let mut output = vec![0u8; output_len];
        argon2id(inputs, &mut work_area, &mut output)?;
        Ok(output)
    }

    /// The same computation with RustCrypto `argon2`, an independent implementation.
    fn rustcrypto_tag(inputs: &Argon2Inputs<'_>, output_len: usize) -> Vec<u8> {
        use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};

        let version = match inputs.version {
            0x10 => Version::V0x10,
            0x13 => Version::V0x13,
            other => panic!("unexpected version {other:#x}"),
        };
        let params = ParamsBuilder::new()
            .m_cost(inputs.memory_kib)
            .t_cost(inputs.passes)
            .p_cost(inputs.lanes)
            .output_len(output_len)
            .data(AssociatedData::new(inputs.associated_data).unwrap())
            .build()
            .unwrap();
        let mut blocks = vec![Block::default(); params.block_count()];
        let argon2 =
            Argon2::new_with_secret(inputs.secret, Algorithm::Argon2id, version, params).unwrap();
        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into_with_memory(inputs.password, inputs.salt, &mut output, &mut blocks)
            .unwrap();
        output
    }

    #[test]
    fn matches_the_rfc_9106_argon2id_test_vector() {
        let rfc = rfc_inputs(false);
        assert_eq!(c_tag(&rfc, 32).unwrap(), hex(rfc_9106::TAG));
        assert_eq!(rustcrypto_tag(&rfc, 32), hex(rfc_9106::TAG));
    }

    #[test]
    fn both_copies_of_the_argon2_core_give_the_rfc_9106_tag() {
        assert_eq!(c_tag(&rfc_inputs(false), 32).unwrap(), hex(rfc_9106::TAG));
        // Only x86-64 has the SSSE3 copy, and only a processor with SSSE3 may run it; every
        // GitHub runner and the development laptops have it.
        if processor_has_ssse3() {
            assert_eq!(c_tag(&rfc_inputs(true), 32).unwrap(), hex(rfc_9106::TAG));
        }
    }

    #[test]
    fn threads_do_not_change_the_result() {
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        let mut single = inputs(password, salt);
        single.threads = 1;
        let parallel = inputs(password, salt);
        assert_eq!(c_tag(&single, 32).unwrap(), c_tag(&parallel, 32).unwrap());
    }

    #[test]
    fn every_context_field_reaches_the_c_code() {
        // Changing one input at a time must change the tag, so no field is silently ignored or
        // read from the wrong offset. `threads` is covered by the test above; the callbacks and
        // flags by the work-area tests below.
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        let base = c_tag(&inputs(password, salt), 32).unwrap();
        type ChangeOneField = fn(&mut Argon2Inputs<'_>);
        let variants: [(&str, ChangeOneField); 8] = [
            ("pwd", |i| i.password = b"public test passworD"),
            ("salt", |i| i.salt = b"0123456789abcdeF"),
            ("secret", |i| i.secret = b"secret"),
            ("ad", |i| i.associated_data = b"data"),
            ("t_cost", |i| i.passes = 2),
            ("m_cost", |i| i.memory_kib = 128),
            ("lanes", |i| i.lanes = 2),
            ("version", |i| i.version = 0x10),
        ];
        for (field, change) in variants {
            let mut changed = inputs(password, salt);
            change(&mut changed);
            assert_ne!(c_tag(&changed, 32).unwrap(), base, "{field} is ignored");
            assert_eq!(
                c_tag(&changed, 32).unwrap(),
                rustcrypto_tag(&changed, 32),
                "{field} is read wrongly"
            );
        }
        let longer = c_tag(&inputs(password, salt), 64).unwrap();
        assert_ne!(longer[..32], base[..], "outlen is ignored");
    }

    #[test]
    fn reuses_one_work_area_and_leaves_it_wiped() {
        // SAFETY: the C code only reads this global, which is 1 unless someone changes it.
        let clear_internal_memory = unsafe { FLAG_clear_internal_memory };
        assert_eq!(clear_internal_memory, 1, "C code would not wipe");
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        let mut work_area = WorkArea::allocate(64).unwrap();
        let start = work_area.pages.as_slice().as_ptr();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        argon2id(&inputs(password, salt), &mut work_area, &mut first).unwrap();
        assert!(work_area.pages.as_slice().iter().all(|&byte| byte == 0));
        argon2id(&inputs(password, salt), &mut work_area, &mut second).unwrap();
        assert!(work_area.pages.as_slice().iter().all(|&byte| byte == 0));
        assert_eq!(work_area.pages.as_slice().as_ptr(), start);
        assert_eq!(first, second);
    }

    #[test]
    fn a_work_area_too_small_is_refused_by_the_c_code() {
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        let mut work_area = WorkArea::allocate(32).unwrap();
        let mut output = [0u8; 32];
        let error = argon2id(&inputs(password, salt), &mut work_area, &mut output).unwrap_err();
        assert_eq!(error, Error::OutOfMemory);
    }

    #[test]
    fn wipe_clears_every_byte() {
        let mut work_area = WorkArea::allocate(64).unwrap();
        work_area.pages.as_mut_slice().fill(0xff);
        work_area.wipe();
        assert!(work_area.pages.as_slice().iter().all(|&byte| byte == 0));
    }

    #[test]
    fn a_failed_call_leaves_the_work_area_wiped() {
        // The C code refuses this area after it was handed out, so the call fails on its error
        // path, where the C code itself wipes nothing; `run` must wipe instead. A failing
        // thread, which the C code reaches after filling blocks, takes the same path.
        let mut work_area = WorkArea::allocate(32).unwrap();
        work_area.pages.as_mut_slice().fill(0xff);
        let mut output = [0u8; 32];
        let password = b"public test password";
        let salt = b"0123456789abcdef";
        argon2id(&inputs(password, salt), &mut work_area, &mut output).unwrap_err();
        assert!(work_area.pages.as_slice().iter().all(|&byte| byte == 0));
    }

    #[test]
    fn argon2_errors_carry_the_reference_code() {
        // ARGON2_SALT_TOO_SHORT in include/argon2.h.
        let short_salt = inputs(b"password", b"1234567");
        assert_eq!(
            c_tag(&short_salt, 32).unwrap_err(),
            Error::Argon2Failed { code: -6 }
        );
    }

    #[test]
    fn the_clear_password_flag_is_read_from_its_offset() {
        // With ARGON2_FLAG_CLEAR_PASSWORD (bit 0) the C code wipes the password buffer; this
        // proves that `flags` sits where the C code reads it. MHFE itself never sets it.
        let mut password = *b"public test password";
        let salt = *b"0123456789abcdef";
        let mut output = [0u8; 32];
        let mut work_area = WorkArea::allocate(64).unwrap();
        let mut context = Argon2Context {
            out: output.as_mut_ptr(),
            outlen: 32,
            pwd: password.as_mut_ptr(),
            pwdlen: password.len() as u32,
            salt: salt.as_ptr().cast_mut(),
            saltlen: salt.len() as u32,
            secret: ptr::null_mut(),
            secretlen: 0,
            ad: ptr::null_mut(),
            adlen: 0,
            t_cost: 1,
            m_cost: 64,
            lanes: 4,
            threads: 4,
            version: ARGON2_VERSION_13,
            allocate_cbk: Some(hand_out_work_area),
            free_cbk: Some(keep_work_area),
            flags: 1,
        };
        run(&mut context, &mut work_area).unwrap();
        assert_eq!(password, [0u8; 20]);
    }
}
