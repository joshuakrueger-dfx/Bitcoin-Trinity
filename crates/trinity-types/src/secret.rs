//! Crate-internal secret buffer — SPECIFICATION.md §1.3.
//!
//! Path: `crates/trinity-types/src/secret.rs`.
//! **Not** an exported uniffi type. Passphrase / recovery words cross the FFI
//! boundary only as borrowed `&[u8]`; the core copies into `SecretBytes` on
//! entry and zeros on drop (WP-10 acceptance, Appendix B.2).

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Zeroizing byte buffer for secrets that must never leave the Rust core.
///
/// # Invariants (SPECIFICATION.md §1.3, WP-10)
/// - No [`Clone`]: a second live copy would defeat zero-on-drop.
/// - [`Debug`] / [`Display`] print only `"[redacted]"` — never contents.
/// - Not `#[uniffi::export]` / `uniffi::Object` — this crate has no uniffi dep.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wrap an owned buffer. The buffer is zeroed when this value is dropped.
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Copy a borrowed slice (e.g. the platform-owned `&[u8]` from FFI).
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// Borrow the secret bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Mutable borrow for in-place use before drop zeros the buffer.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    /// Length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    #[inline]
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for SecretBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_accessors() {
        let s = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(s.as_slice(), &[1, 2, 3]);
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
        assert_eq!(s.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn from_slice_copies() {
        let src = [9u8, 8, 7];
        let s = SecretBytes::from_slice(&src);
        assert_eq!(s.as_slice(), &src);
    }

    #[test]
    fn from_vec() {
        let s = SecretBytes::from(vec![4, 5]);
        assert_eq!(s.as_slice(), &[4, 5]);
    }

    #[test]
    fn empty_buffer() {
        let s = SecretBytes::new(Vec::new());
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn mut_slice_writable() {
        let mut s = SecretBytes::new(vec![0, 0]);
        s.as_mut_slice()[0] = 1;
        assert_eq!(s.as_slice(), &[1, 0]);
    }

    #[test]
    fn debug_is_redacted() {
        let s = SecretBytes::new(vec![0xde, 0xad]);
        assert_eq!(format!("{s:?}"), "[redacted]");
        // Must not contain any hex of the payload.
        assert!(!format!("{s:?}").contains("de"));
        assert!(!format!("{s:?}").contains("ad"));
    }

    #[test]
    fn display_is_redacted() {
        let s = SecretBytes::new(vec![0xbe, 0xef]);
        assert_eq!(format!("{s}"), "[redacted]");
        assert!(!format!("{s}").contains("be"));
        assert!(!format!("{s}").contains("ef"));
    }
}
