//! Base64-encoded PSBT newtype — SPECIFICATION.md §1.1, §1.3.

use core::fmt;
use serde::{Deserialize, Serialize};

/// PSBT carried as BIP-174 base64 across the trust boundary.
///
/// Spec §1.3: `String` (PSBT base64) is allowed ⇄ across the FFI boundary and
/// "Contains xpubs and derivation paths, **never** private material."
/// Spec §1.1 lists `PsbtB64` as a core type in `trinity-types`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PsbtB64(String);

impl PsbtB64 {
    /// Wrap an already-encoded base64 PSBT string.
    ///
    /// Validation of PSBT structure is the job of builders/verifiers
    /// (WP-12 / WP-20), not of this pure value type.
    #[inline]
    pub fn new(b64: impl Into<String>) -> Self {
        Self(b64.into())
    }

    /// Borrow the base64 string.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the inner `String` (facade returns `String` per §1.3).
    #[inline]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for PsbtB64 {
    #[inline]
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for PsbtB64 {
    #[inline]
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl AsRef<str> for PsbtB64 {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for PsbtB64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // PSBT base64 is public (xpubs/paths only) but can be large; show length
        // rather than full payload so logs stay readable. No secrets by Spec §1.3.
        f.debug_struct("PsbtB64")
            .field("len", &self.0.len())
            .finish()
    }
}

impl fmt::Display for PsbtB64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_and_access() {
        let p = PsbtB64::new("cHNidP8BAH0");
        assert_eq!(p.as_str(), "cHNidP8BAH0");
        assert_eq!(p.as_ref(), "cHNidP8BAH0");
        assert_eq!(PsbtB64::from("abc").as_str(), "abc");
        assert_eq!(PsbtB64::from(String::from("xyz")).into_string(), "xyz");
    }

    #[test]
    fn debug_shows_len_not_full_body_requirement() {
        let p = PsbtB64::new("abcd");
        let d = format!("{p:?}");
        assert!(d.contains("PsbtB64"));
        assert!(d.contains("len"));
        assert!(d.contains('4'));
    }

    #[test]
    fn display_is_base64() {
        let p = PsbtB64::new("cHNidP8=");
        assert_eq!(format!("{p}"), "cHNidP8=");
    }

    #[test]
    fn serde_as_string() {
        let p = PsbtB64::new("hello");
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "\"hello\"");
        assert_eq!(serde_json::from_str::<PsbtB64>("\"hello\"").unwrap(), p);
    }
}
