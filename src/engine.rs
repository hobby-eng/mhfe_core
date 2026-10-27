//! Argon2id as MHFE uses it: version 0x13, four lanes, a 16-byte salt, an empty secret and empty
//! associated data, and a 32-byte tag. Only the memory and the passes change, and the core passes
//! both with every call.
//!
//! Native builds have [`NativeArgon2`], the vendored reference C code; a WebAssembly host supplies
//! its own engine.

use crate::Error;

#[cfg(not(target_arch = "wasm32"))]
mod ffi;
#[cfg(not(target_arch = "wasm32"))]
mod native;

#[cfg(not(target_arch = "wasm32"))]
pub use native::NativeArgon2;

/// The length of the round salt `S_i`.
pub(crate) const SALT_BYTES: usize = 16;
/// The length of the Argon2id tag `K_i`.
pub(crate) const KEY_BYTES: usize = 32;

/// Computes Argon2id version 0x13 with four lanes, an empty secret and empty associated data and a
/// 32-byte tag. A host implements it where the crate has no engine of its own, as in WebAssembly,
/// and a test to stand in for Argon2id.
pub trait Argon2Engine {
    /// Writes the tag of `password` and `salt` at `memory_kib` KiB and `passes` passes into `key`,
    /// which lies in the core's own secret memory. An engine that cannot compute it returns
    /// [`Error::OutOfMemory`] or [`Error::Argon2Failed`], never a tag of another cost.
    fn argon2id(
        &mut self,
        password: &[u8],
        salt: &[u8; SALT_BYTES],
        memory_kib: u32,
        passes: u32,
        key: &mut [u8; KEY_BYTES],
    ) -> Result<(), Error>;
}
