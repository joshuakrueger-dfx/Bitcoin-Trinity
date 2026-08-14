//! [`SignerKind`] — Spec §6.6.

use core::fmt;

/// How a [`crate::Signer`] produces signatures.
///
/// All four variants exist so the trait is complete from v1 (E5). Only
/// [`SignerKind::Local`] is produced by this WP; the external variants are
/// returned by `trinity-transport` implementations (WP-50+).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignerKind {
    /// On-device key via [`crate::LocalSigner`].
    Local,
    /// External hardware over NFC.
    ExternalNfc,
    /// External hardware over QR (BBQr / UR).
    ExternalQr,
    /// External hardware over USB.
    ExternalUsb,
}

impl SignerKind {
    /// Stable label. Not secret.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            SignerKind::Local => "local",
            SignerKind::ExternalNfc => "external-nfc",
            SignerKind::ExternalQr => "external-qr",
            SignerKind::ExternalUsb => "external-usb",
        }
    }
}

impl fmt::Display for SignerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_display() {
        assert_eq!(SignerKind::Local.as_str(), "local");
        assert_eq!(SignerKind::ExternalNfc.as_str(), "external-nfc");
        assert_eq!(SignerKind::ExternalQr.as_str(), "external-qr");
        assert_eq!(SignerKind::ExternalUsb.as_str(), "external-usb");
        assert_eq!(SignerKind::Local.to_string(), "local");
        assert_eq!(SignerKind::ExternalNfc.to_string(), "external-nfc");
        assert_eq!(SignerKind::ExternalQr.to_string(), "external-qr");
        assert_eq!(SignerKind::ExternalUsb.to_string(), "external-usb");
    }

    #[test]
    fn copy_eq_debug() {
        let a = SignerKind::Local;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, SignerKind::ExternalQr);
        let d = format!("{a:?}");
        assert!(d.contains("Local"));
    }
}
