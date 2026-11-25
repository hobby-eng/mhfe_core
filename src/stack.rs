//! Clearing what a secret computation leaves on the stack, by secret-protection-core: the copies
//! that moves leave behind, and what dependencies keep there and never wipe, such as the bits,
//! words and SHA-256 state of bip39's parsing and encoding and the HMAC states of its PBKDF2. Every
//! public function that computes with a secret, but `Repaired::changes` and those of `protect` and
//! the engine, runs its body through [`cleared`] once, and so does every round of the permutation;
//! each thread of the Argon2id engine runs `overwrite` after a call.

#[cfg(all(test, target_os = "linux"))]
pub(crate) use secret_protection_core::CLEARED_STACK_BYTES as CLEARED_BYTES;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use secret_protection_core::clear_stack as overwrite;
pub(crate) use secret_protection_core::with_cleared_stack as cleared;
