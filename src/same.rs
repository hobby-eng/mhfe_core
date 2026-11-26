//! Comparisons of bytes derived from a secret, by RustCrypto's `ctutils`, with no exit at the first
//! difference; the lengths are public here. On x86, x86-64 and AArch64 its `cmov` crate compares in
//! assembly, with `cmov` and `csel`, and the release builds of these two functions for x86-64 and
//! AArch64 Linux branch only on the lengths. Elsewhere, WebAssembly included, `cmov` uses portable
//! code that it calls best effort: a compiler, or the engine that runs WebAssembly, may still
//! branch on a byte.

use ctutils::CtEq;

/// Whether `a` and `b` hold the same bytes.
pub(crate) fn same(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).to_bool()
}

/// Whether every byte of `bytes` is zero.
pub(crate) fn all_zero(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .fold(ctutils::Choice::TRUE, |zero, byte| zero & byte.ct_eq(&0))
        .to_bool()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_bytes_are_the_same_and_any_difference_is_seen() {
        assert!(same(b"", b""));
        assert!(same(&[1, 2, 3], &[1, 2, 3]));
        assert!(!same(&[1, 2, 3], &[1, 2, 4]));
        assert!(!same(&[0x80, 2, 3], &[0, 2, 3]));
        assert!(!same(&[1, 2], &[1, 2, 3]));
        assert!(all_zero(&[0, 0, 0]) && all_zero(&[]));
        assert!(!all_zero(&[0, 0, 1]) && !all_zero(&[0x80, 0]));
    }
}
