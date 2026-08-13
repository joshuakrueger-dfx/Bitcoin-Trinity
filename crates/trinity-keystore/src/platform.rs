//! Platform KEK wrap/unwrap callback — Spec §2.4 / §1.3.
//!
//! Rust calls the platform; the platform does not call Rust. This crate has
//! no Secure Enclave / Android Keystore access — the real implementations
//! are WP-41 / WP-42. This module is the trait plus the fail-closed error
//! type those implementations will return.
//!
//! # No `load_key` composition
//!
//! This WP does **not** add a `load_key(store, slot, wrapped, blob)` helper
//! that chains [`PlatformKeyStore::unwrap_kek`] into [`crate::decrypt`].
//! WP-32's acceptance list does not ask for it; the first real caller is
//! the signer (WP-33, S9 / S28). Unused composition would be a premature
//! abstraction. KEK bytes that *do* cross this trait stay `Vec<u8>` (FFI
//! shape, Spec §1.3) — a foreign impl cannot consume a Rust-only
//! zeroizing type.

use thiserror::Error;
use trinity_types::KeySlot;

use crate::policy::SlotPolicy;

/// Fail-closed platform-callback error (Spec §2.4).
///
/// One variant per rejection the platform can actually produce. No generic
/// string payload — a foreign impl that wants to smuggle a message has to
/// pick a closed reason. `KeyInvalidated` is split from `UnwrapRejected`
/// because the recovery path is different (guided re-setup vs retry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PlatformError {
    /// Biometric / user-presence prompt failed or was cancelled.
    /// Retry is meaningful.
    #[error("platform rejected KEK unwrap (auth failed or cancelled)")]
    UnwrapRejected,

    /// Wrapping key is permanently gone (new biometric enrollment, passcode
    /// removed). Slot A is a planned loss; do not retry unwrap.
    #[error("platform wrapping key is permanently invalidated")]
    KeyInvalidated,

    /// `wrap_kek` failed (hardware refused the wrap, or the slot has no
    /// wrapping key).
    #[error("platform refused to wrap the KEK")]
    WrapFailed,

    /// `provision` failed: Secure Enclave / StrongBox / Keystore missing,
    /// policy rejected, or the slot is already provisioned.
    #[error("platform failed to provision a wrapping key")]
    ProvisionFailed,

    /// `destroy` failed. The wrapping key may still exist.
    #[error("platform failed to destroy the wrapping key")]
    DestroyFailed,

    /// Slot C has no device blob, or `provision(slot, policy)` was called
    /// with `policy.slot != slot`.
    #[error("slot is not valid for an on-device wrapping key")]
    InvalidSlot,

    /// Platform returned a failure that does not map to a more specific
    /// variant. Fail closed — do not treat this as success.
    #[error("unclassified platform keystore failure")]
    Unexpected,
}

/// Platform-owned KEK wrap/unwrap (Spec §1.3, §2.4).
///
/// Plain `Vec<u8>` at the boundary is deliberate: the foreign side of this
/// trait (Swift / Kotlin, WP-41 / WP-42) cannot take a Rust `SecretBytes`.
/// Callers that hold the returned KEK inside this crate must wrap it in
/// `SecretBytes` immediately.
///
/// No `#[uniffi::export(with_foreign)]` here — that is WP-40.
pub trait PlatformKeyStore: Send + Sync {
    /// Unwrap the KEK. Triggers the platform presence check for `slot`.
    fn unwrap_kek(&self, slot: KeySlot, wrapped: Vec<u8>) -> Result<Vec<u8>, PlatformError>;

    /// Wrap a freshly generated KEK under the slot's hardware key.
    fn wrap_kek(&self, slot: KeySlot, plain: Vec<u8>) -> Result<Vec<u8>, PlatformError>;

    /// Create the slot's wrapping key according to `policy`.
    fn provision(&self, slot: KeySlot, policy: SlotPolicy) -> Result<(), PlatformError>;

    /// Irreversibly delete the slot's wrapping key.
    fn destroy(&self, slot: KeySlot) -> Result<(), PlatformError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_covers_every_variant() {
        let cases: &[PlatformError] = &[
            PlatformError::UnwrapRejected,
            PlatformError::KeyInvalidated,
            PlatformError::WrapFailed,
            PlatformError::ProvisionFailed,
            PlatformError::DestroyFailed,
            PlatformError::InvalidSlot,
            PlatformError::Unexpected,
        ];
        for e in cases {
            assert!(!e.to_string().is_empty(), "{e:?}");
        }
    }

    #[test]
    fn error_is_copy_and_eq() {
        let a = PlatformError::KeyInvalidated;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, PlatformError::UnwrapRejected);
    }
}
