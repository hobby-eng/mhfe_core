//! Argon2id on the vendored reference C code, with one work area for every round.

use super::ffi::{self, ARGON2_VERSION_13, Argon2Inputs, WorkArea};
use super::{Argon2Engine, KEY_BYTES, SALT_BYTES};
use crate::Error;

// A native 32-bit build cannot run even level 0: Rust refuses an allocation of 2 GiB or more
// there (a layout may not exceed isize::MAX), and the reference C code would stop at 2 GiB anyway.
// Such a build is refused here rather than failing at the first operation. A WebAssembly build
// has no native engine: its host supplies Argon2id.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("the native Argon2id engine needs a 64-bit target: suite 3 needs at least 2 GiB");

/// Argon2id lanes, fixed by the specification; each runs on a thread of its own.
const LANES: u32 = 4;

/// The vendored reference C implementation of Argon2id, its four lanes on four threads, the engine
/// of every native build. Its work area lies on memory pages of its own, kept out of core dumps
/// and out of a child process where the system allows it, and wiped after every call.
pub struct NativeArgon2 {
    work_area: WorkArea,
    /// Whether the Argon2 core runs its SSSE3 copy; see argon2_wrap.c.
    ssse3: bool,
}

impl NativeArgon2 {
    /// Reserves `memory_kib` KiB once, for every call; a call with more memory is
    /// [`Error::OutOfMemory`], as is a reservation the system refuses. The host encodes the
    /// password first, so that a refused one costs no reservation. It estimates no free memory: a
    /// reservation the system grants can still end the process when it is used (overcommit; the
    /// OOM or low-memory killer, jetsam), so the host checks free memory before (the
    /// specification's "Resources").
    ///
    /// The area is locked where the system's limit on locked memory holds all of it, which also
    /// commits it: on Linux, Android, macOS and iOS when RLIMIT_MEMLOCK is at least its size, on
    /// Windows when the working set could grow by its size.
    pub fn new(memory_kib: u32) -> Result<Self, Error> {
        Ok(Self {
            work_area: WorkArea::allocate(memory_kib)?,
            ssse3: processor_has_ssse3(),
        })
    }

    /// Whether the system keeps the work area in memory, never in swap.
    pub fn is_locked(&self) -> bool {
        self.work_area.is_locked()
    }
}

// A deliberate copy of the trait's signature, which an implementation repeats.
impl Argon2Engine for NativeArgon2 {
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), Error> {
        let inputs = Argon2Inputs {
            password,
            salt,
            secret: &[],
            associated_data: &[],
            passes,
            memory_kib,
            lanes: LANES,
            threads: LANES,
            version: ARGON2_VERSION_13,
            ssse3: self.ssse3,
        };
        ffi::argon2id(&inputs, &mut self.work_area, key)
    }
}

/// Whether this processor can run the SSSE3 copy of the Argon2 core, which only x86-64 builds
/// have. Without SSSE3 the SSE2 copy runs, which every 64-bit x86 processor can.
pub(super) fn processor_has_ssse3() -> bool {
    #[cfg(target_arch = "x86_64")]
    return std::arch::is_x86_feature_detected!("ssse3");
    #[cfg(not(target_arch = "x86_64"))]
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::hex;

    const PASSWORD: &[u8] = b"public test password";
    const SALT: &[u8; SALT_BYTES] = b"0123456789abcdef";

    /// MHFE's call at 1 MiB and one pass, the cost the host passes with each call. The tag was
    /// computed with OpenSSL through Python cryptography 46.0.5, an implementation independent of
    /// the reference C code.
    #[test]
    fn gives_the_openssl_tag_at_a_small_cost() {
        let mut engine = NativeArgon2::new(1024).unwrap();
        let mut key = [0u8; KEY_BYTES];
        engine.argon2id(PASSWORD, SALT, 1024, 1, &mut key).unwrap();
        assert_eq!(
            key[..],
            hex("e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2")
        );
    }

    #[test]
    fn a_call_with_more_memory_than_reserved_is_refused() {
        let mut engine = NativeArgon2::new(64).unwrap();
        let mut key = [0u8; KEY_BYTES];
        assert_eq!(
            engine.argon2id(PASSWORD, SALT, 128, 1, &mut key),
            Err(Error::OutOfMemory)
        );
        assert_eq!(engine.argon2id(PASSWORD, SALT, 64, 1, &mut key), Ok(()));
    }
}
