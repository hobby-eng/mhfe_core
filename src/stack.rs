//! Clearing what a secret computation leaves on the stack: the copies that moves leave behind, and
//! what dependencies keep there and never wipe, such as the bits, words and SHA-256 state of
//! bip39's parsing and encoding and the HMAC states of its PBKDF2. Best effort: how deep a body
//! writes is not measured, so the cleared depth has a margin.

use std::hint::black_box;

use zeroize::Zeroize;

/// The stack below the caller's frame that [`cleared`] overwrites after the body.
const CLEARED_BYTES: usize = 128 * 1024;

/// Runs `body` in a frame of its own, then overwrites [`CLEARED_BYTES`] of the stack below the
/// caller's frame, where that frame and the ones it called lay. Every public function that computes
/// with a secret, but `Repaired::changes` and those of `protect` and the engine, runs its body
/// through it once, and so does every round of the permutation.
#[inline(never)]
pub(crate) fn cleared<T>(body: impl FnOnce() -> T) -> T {
    let result = run(body);
    overwrite();
    result
}

#[inline(never)]
fn run<T>(body: impl FnOnce() -> T) -> T {
    body()
}

#[inline(never)]
fn overwrite() {
    let mut stack = [0u8; CLEARED_BYTES];
    // Volatile writes; `black_box` keeps the array, and so the writes, where the body's frames were.
    stack.zeroize();
    black_box(&stack);
}
