//! Comparisons of bytes derived from a secret in a time that depends on their length alone: every
//! byte is read, with no exit at the first difference, and the difference passes through
//! `black_box`, so that the compiler can neither stop the loop early nor turn it into a branch on
//! each byte. Lengths are public here.

use std::hint::black_box;

/// Whether `a` and `b` hold the same bytes.
pub(crate) fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && black_box(a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y))) == 0
}

/// Whether every byte of `bytes` is zero.
pub(crate) fn all_zero(bytes: &[u8]) -> bool {
    black_box(bytes.iter().fold(0, |acc, byte| acc | byte)) == 0
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
