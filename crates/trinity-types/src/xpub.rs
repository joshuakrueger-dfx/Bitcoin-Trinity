//! Extended public key with BIP-32 origin — SPECIFICATION.md §1.3, §2.3, §2.7.

use core::fmt;
use serde::{Deserialize, Serialize};

use crate::fingerprint::Fingerprint;

/// An account-level xpub plus the origin info required by Spec §2.3.
///
/// Spec §1.3 facade: `hw_import_xpub(...) -> Result<XpubWithOrigin, …>`
/// (confirmation on device display). Spec §2.3: origin `[fingerprint/path]`
/// is **always** required; without it foreign signers cannot derive.
/// Spec §1.5 grammar: `keyexpr := "[" fingerprint "/" origin_path "]" xpub "/…"`.
///
/// The xpub string is public (watch-only material) — never an xpriv.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct XpubWithOrigin {
    /// Master fingerprint of the originating key (Spec §2.3 origin info).
    pub fingerprint: Fingerprint,
    /// Absolute origin derivation path without leading `m/` (e.g. `48'/0'/0'/2'`).
    ///
    /// Spec §2.3 BIP-48 multisig path; coin type depends on [`crate::Network`].
    pub origin_path: String,
    /// Base58check xpub at the origin path (public). Spec §1.3 allows xpubs
    /// across the boundary; private material is forbidden.
    pub xpub: String,
}

impl XpubWithOrigin {
    /// Construct from the three origin fields.
    #[inline]
    pub fn new(
        fingerprint: Fingerprint,
        origin_path: impl Into<String>,
        xpub: impl Into<String>,
    ) -> Self {
        Self {
            fingerprint,
            origin_path: origin_path.into(),
            xpub: xpub.into(),
        }
    }

    /// Descriptor-style key expression prefix: `[fingerprint/origin_path]xpub`.
    ///
    /// Spec §1.5 grammar `keyexpr` (without the trailing `/derivation` segment,
    /// which is added by the descriptor builder in WP-11).
    pub fn key_origin_prefix(&self) -> String {
        format!("[{}/{}]{}", self.fingerprint, self.origin_path, self.xpub)
    }
}

impl fmt::Debug for XpubWithOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public data only — fingerprint + path + xpub are watch-only.
        f.debug_struct("XpubWithOrigin")
            .field("fingerprint", &self.fingerprint)
            .field("origin_path", &self.origin_path)
            .field("xpub", &self.xpub)
            .finish()
    }
}

impl fmt::Display for XpubWithOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key_origin_prefix())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> XpubWithOrigin {
        XpubWithOrigin::new(
            Fingerprint::new([0x12, 0x34, 0x56, 0x78]),
            "48'/0'/0'/2'",
            "xpub6Example",
        )
    }

    #[test]
    fn key_origin_prefix_format() {
        let x = sample();
        assert_eq!(x.key_origin_prefix(), "[12345678/48'/0'/0'/2']xpub6Example");
        assert_eq!(format!("{x}"), "[12345678/48'/0'/0'/2']xpub6Example");
    }

    #[test]
    fn debug_lists_public_fields() {
        let d = format!("{:?}", sample());
        assert!(d.contains("XpubWithOrigin"));
        assert!(d.contains("12345678"));
        assert!(d.contains("xpub6Example"));
    }

    #[test]
    fn serde_roundtrip() {
        let x = sample();
        let j = serde_json::to_string(&x).unwrap();
        assert_eq!(serde_json::from_str::<XpubWithOrigin>(&j).unwrap(), x);
    }
}
