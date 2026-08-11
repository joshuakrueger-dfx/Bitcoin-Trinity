//! BIP-32 master key fingerprint — SPECIFICATION.md §1.1, §1.5, §2.3.

use core::fmt;
use serde::{Deserialize, Serialize};

/// 4-byte BIP-32 key fingerprint (first 4 bytes of HASH160(pubkey)).
///
/// Spec §1.1 lists `Fingerprint` as a core type. Spec §1.5 grammar uses
/// `[fingerprint/origin_path]` on every key expression. Spec §2.3: origin
/// info is always required. Spec §6.6 `Signer::fingerprint() -> Fingerprint`.
///
/// Public metadata — never secret material.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; 4]);

impl Fingerprint {
    /// Construct from the raw 4-byte fingerprint.
    #[inline]
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Consume into the raw array.
    #[inline]
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0
    }

    /// Parse an 8-character lowercase or uppercase hex string.
    pub fn from_hex(s: &str) -> Result<Self, FingerprintParseError> {
        if s.len() != 8 {
            return Err(FingerprintParseError::InvalidLength);
        }
        let mut out = [0u8; 4];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0]).ok_or(FingerprintParseError::InvalidHex)?;
            let lo = hex_nibble(chunk[1]).ok_or(FingerprintParseError::InvalidHex)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    /// Format as 8 lowercase hex characters (BIP-32 / descriptor convention).
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(8);
        for b in self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Fingerprint").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<[u8; 4]> for Fingerprint {
    #[inline]
    fn from(bytes: [u8; 4]) -> Self {
        Self::new(bytes)
    }
}

/// Error parsing a fingerprint hex string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FingerprintParseError {
    /// Input was not exactly 8 hex characters.
    #[error("fingerprint hex must be exactly 8 characters")]
    InvalidLength,
    /// Input contained a non-hex character.
    #[error("fingerprint hex contains a non-hex character")]
    InvalidHex,
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_roundtrip() {
        let fp = Fingerprint::new([0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(fp.as_bytes(), &[0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(fp.to_bytes(), [0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(Fingerprint::from([1, 2, 3, 4]).to_bytes(), [1, 2, 3, 4]);
    }

    #[test]
    fn hex_roundtrip() {
        let fp = Fingerprint::from_hex("1234abcd").unwrap();
        assert_eq!(fp.to_hex(), "1234abcd");
        assert_eq!(format!("{fp}"), "1234abcd");
        // Uppercase accepted.
        assert_eq!(
            Fingerprint::from_hex("1234ABCD").unwrap().to_hex(),
            "1234abcd"
        );
    }

    #[test]
    fn hex_errors() {
        assert_eq!(
            Fingerprint::from_hex("123"),
            Err(FingerprintParseError::InvalidLength)
        );
        assert_eq!(
            Fingerprint::from_hex("123456789"),
            Err(FingerprintParseError::InvalidLength)
        );
        assert_eq!(
            Fingerprint::from_hex("1234abcz"),
            Err(FingerprintParseError::InvalidHex)
        );
        assert_eq!(
            Fingerprint::from_hex("gggggggg"),
            Err(FingerprintParseError::InvalidHex)
        );
    }

    #[test]
    fn debug_shows_hex() {
        let fp = Fingerprint::new([0xff, 0x00, 0xaa, 0x11]);
        let d = format!("{fp:?}");
        assert!(d.contains("ff00aa11"));
    }

    #[test]
    fn error_display() {
        assert!(!FingerprintParseError::InvalidLength.to_string().is_empty());
        assert!(!FingerprintParseError::InvalidHex.to_string().is_empty());
    }

    #[test]
    fn serde_as_bytes() {
        let fp = Fingerprint::new([1, 2, 3, 4]);
        let j = serde_json::to_string(&fp).unwrap();
        assert_eq!(j, "[1,2,3,4]");
        assert_eq!(serde_json::from_str::<Fingerprint>(&j).unwrap(), fp);
    }
}
