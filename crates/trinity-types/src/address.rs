//! Revealed address info — SPECIFICATION.md §1.3 (facade / BDK mapping).

use core::fmt;
use serde::{Deserialize, Serialize};

/// BDK keychain kind mapped for the FFI-facing address type.
///
/// Spec §1.1: `KeychainKind::External = receive, ::Internal = change`.
/// Spec §1.3: facade `reveal_next_address` uses External on the receive path.
/// Not listed as a standalone WP-10 export name, but required by
/// [`AddressInfo`] field shape (BDK `AddressInfo { index, address, keychain }`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeychainKind {
    /// Receive addresses (`/0/*`). Spec §1.1 External.
    External,
    /// Change addresses (`/1/*`). Spec §1.1 Internal.
    Internal,
}

impl KeychainKind {
    /// `true` for the change keychain.
    #[inline]
    pub const fn is_internal(self) -> bool {
        matches!(self, KeychainKind::Internal)
    }

    /// `true` for the receive keychain.
    #[inline]
    pub const fn is_external(self) -> bool {
        matches!(self, KeychainKind::External)
    }
}

impl fmt::Display for KeychainKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeychainKind::External => f.write_str("external"),
            KeychainKind::Internal => f.write_str("internal"),
        }
    }
}

/// A revealed wallet address with its derivation index and keychain.
///
/// Spec §1.3 facade: `pub fn reveal_next_address(&self) -> AddressInfo`.
/// Field shape follows BDK 3.1.0 `AddressInfo` (Spec Appendix B.1 /
/// `wallet/mod.rs:651`): `index`, `address`, `keychain`. Address crosses the
/// boundary as `String` (Spec §1.3 allowed types).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddressInfo {
    /// Bech32 (or other network) address string. Spec §1.3 public.
    pub address: String,
    /// BIP-32 child index on the keychain. Spec §1.3 allows `u32` (index).
    pub index: u32,
    /// Receive vs change keychain. Spec §1.1 / BDK `KeychainKind`.
    pub keychain: KeychainKind,
}

impl AddressInfo {
    /// Construct a revealed address record.
    #[inline]
    pub fn new(address: impl Into<String>, index: u32, keychain: KeychainKind) -> Self {
        Self {
            address: address.into(),
            index,
            keychain,
        }
    }
}

impl fmt::Debug for AddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Addresses are public (Spec §1.3).
        f.debug_struct("AddressInfo")
            .field("address", &self.address)
            .field("index", &self.index)
            .field("keychain", &self.keychain)
            .finish()
    }
}

impl fmt::Display for AddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_and_display() {
        let a = AddressInfo::new("bc1qexample", 7, KeychainKind::External);
        assert_eq!(a.address, "bc1qexample");
        assert_eq!(a.index, 7);
        assert_eq!(a.keychain, KeychainKind::External);
        assert_eq!(format!("{a}"), "bc1qexample");
    }

    #[test]
    fn keychain_flags() {
        assert!(KeychainKind::External.is_external());
        assert!(!KeychainKind::External.is_internal());
        assert!(KeychainKind::Internal.is_internal());
        assert!(!KeychainKind::Internal.is_external());
    }

    #[test]
    fn keychain_display() {
        assert_eq!(format!("{}", KeychainKind::External), "external");
        assert_eq!(format!("{}", KeychainKind::Internal), "internal");
    }

    #[test]
    fn debug_shows_fields() {
        let a = AddressInfo::new("tb1qzz", 0, KeychainKind::Internal);
        let d = format!("{a:?}");
        assert!(d.contains("tb1qzz"));
        assert!(d.contains("Internal"));
    }

    #[test]
    fn serde_roundtrip() {
        let a = AddressInfo::new("bc1qab", 1, KeychainKind::External);
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<AddressInfo>(&j).unwrap(), a);
    }
}
