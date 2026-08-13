//! Test double for [`PlatformKeyStore`].
//!
//! Gated by `cfg(test)` or the crate's non-default `test-util` feature so
//! `trinity-signer` (WP-33) can import it as a dev-dependency. Not
//! `#[cfg(test)]` only — that never crosses crate boundaries.
//!
//! Default wrap/unwrap is identity (input bytes come back). Each method can
//! be configured to fail with a specific [`PlatformError`] or to succeed
//! with caller-supplied bytes. Call counters are the S9 / S28 hook: after a
//! rejected verify, [`FakePlatformKeyStore::unwrap_kek_calls`] must stay `0`.
//!
//! Configured KEK / wrapped-KEK payloads live in [`SecretBytes`] and are
//! zeroed on drop. This type is not [`Clone`]. [`Debug`] never prints
//! payload bytes.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use trinity_types::{KeySlot, SecretBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::platform::{PlatformError, PlatformKeyStore};
use crate::policy::SlotPolicy;

/// Reusable [`PlatformKeyStore`] mock with per-method failure injection
/// and call counts.
///
/// If both a failure and a success payload are configured for the same
/// method, the failure wins (fail-closed).
pub struct FakePlatformKeyStore {
    unwrap_calls: AtomicUsize,
    wrap_calls: AtomicUsize,
    provision_calls: AtomicUsize,
    destroy_calls: AtomicUsize,
    unwrap_error: Mutex<Option<PlatformError>>,
    wrap_error: Mutex<Option<PlatformError>>,
    provision_error: Mutex<Option<PlatformError>>,
    destroy_error: Mutex<Option<PlatformError>>,
    unwrap_plain: Mutex<Option<SecretBytes>>,
    wrap_wrapped: Mutex<Option<SecretBytes>>,
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakePlatformKeyStore {
    /// Identity wrap/unwrap, no failures, all counters at zero.
    pub fn new() -> Self {
        Self {
            unwrap_calls: AtomicUsize::new(0),
            wrap_calls: AtomicUsize::new(0),
            provision_calls: AtomicUsize::new(0),
            destroy_calls: AtomicUsize::new(0),
            unwrap_error: Mutex::new(None),
            wrap_error: Mutex::new(None),
            provision_error: Mutex::new(None),
            destroy_error: Mutex::new(None),
            unwrap_plain: Mutex::new(None),
            wrap_wrapped: Mutex::new(None),
        }
    }

    /// Next `unwrap_kek` returns `error`. Wins over a configured payload.
    pub fn fail_unwrap(&self, error: PlatformError) {
        *locked(&self.unwrap_error) = Some(error);
    }

    /// Next `wrap_kek` returns `error`. Wins over a configured payload.
    pub fn fail_wrap(&self, error: PlatformError) {
        *locked(&self.wrap_error) = Some(error);
    }

    /// Next `provision` returns `error`.
    pub fn fail_provision(&self, error: PlatformError) {
        *locked(&self.provision_error) = Some(error);
    }

    /// Next `destroy` returns `error`.
    pub fn fail_destroy(&self, error: PlatformError) {
        *locked(&self.destroy_error) = Some(error);
    }

    /// Successful `unwrap_kek` calls return a copy of `plain` instead of
    /// echoing the input, until [`Self::clear_unwrap`]. The store keeps the
    /// bytes in [`SecretBytes`].
    pub fn succeed_unwrap_with(&self, plain: Vec<u8>) {
        *locked(&self.unwrap_plain) = Some(SecretBytes::new(plain));
    }

    /// Successful `wrap_kek` calls return a copy of `wrapped` instead of
    /// echoing the input, until [`Self::clear_wrap`].
    pub fn succeed_wrap_with(&self, wrapped: Vec<u8>) {
        *locked(&self.wrap_wrapped) = Some(SecretBytes::new(wrapped));
    }

    /// Drop unwrap failure and payload; unwrap returns to identity.
    pub fn clear_unwrap(&self) {
        *locked(&self.unwrap_error) = None;
        *locked(&self.unwrap_plain) = None;
    }

    /// Drop wrap failure and payload; wrap returns to identity.
    pub fn clear_wrap(&self) {
        *locked(&self.wrap_error) = None;
        *locked(&self.wrap_wrapped) = None;
    }

    /// Drop provision failure.
    pub fn clear_provision(&self) {
        *locked(&self.provision_error) = None;
    }

    /// Drop destroy failure.
    pub fn clear_destroy(&self) {
        *locked(&self.destroy_error) = None;
    }

    /// Times `unwrap_kek` has been entered (including rejected calls).
    pub fn unwrap_kek_calls(&self) -> usize {
        self.unwrap_calls.load(Ordering::SeqCst)
    }

    /// Times `wrap_kek` has been entered.
    pub fn wrap_kek_calls(&self) -> usize {
        self.wrap_calls.load(Ordering::SeqCst)
    }

    /// Times `provision` has been entered.
    pub fn provision_calls(&self) -> usize {
        self.provision_calls.load(Ordering::SeqCst)
    }

    /// Times `destroy` has been entered.
    pub fn destroy_calls(&self) -> usize {
        self.destroy_calls.load(Ordering::SeqCst)
    }

    /// Set every counter to zero. Does not change configured errors/payloads.
    pub fn reset_calls(&self) {
        self.unwrap_calls.store(0, Ordering::SeqCst);
        self.wrap_calls.store(0, Ordering::SeqCst);
        self.provision_calls.store(0, Ordering::SeqCst);
        self.destroy_calls.store(0, Ordering::SeqCst);
    }
}

impl Default for FakePlatformKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for FakePlatformKeyStore {
    fn zeroize(&mut self) {
        *locked(&self.unwrap_plain) = None;
        *locked(&self.wrap_wrapped) = None;
    }
}

impl Drop for FakePlatformKeyStore {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for FakePlatformKeyStore {}

impl fmt::Debug for FakePlatformKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakePlatformKeyStore")
            .field("unwrap_kek_calls", &self.unwrap_kek_calls())
            .field("wrap_kek_calls", &self.wrap_kek_calls())
            .field("provision_calls", &self.provision_calls())
            .field("destroy_calls", &self.destroy_calls())
            .field("unwrap_plain", &"[redacted]")
            .field("wrap_wrapped", &"[redacted]")
            .finish()
    }
}

impl PlatformKeyStore for FakePlatformKeyStore {
    fn unwrap_kek(&self, slot: KeySlot, mut wrapped: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
        self.unwrap_calls.fetch_add(1, Ordering::SeqCst);
        if !slot.has_device_blob() {
            wrapped.zeroize();
            return Err(PlatformError::InvalidSlot);
        }
        if let Some(error) = *locked(&self.unwrap_error) {
            wrapped.zeroize();
            return Err(error);
        }
        if let Some(ref plain) = *locked(&self.unwrap_plain) {
            let out = plain.as_slice().to_vec();
            wrapped.zeroize();
            return Ok(out);
        }
        Ok(wrapped)
    }

    fn wrap_kek(&self, slot: KeySlot, mut plain: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
        self.wrap_calls.fetch_add(1, Ordering::SeqCst);
        if !slot.has_device_blob() {
            plain.zeroize();
            return Err(PlatformError::InvalidSlot);
        }
        if let Some(error) = *locked(&self.wrap_error) {
            plain.zeroize();
            return Err(error);
        }
        if let Some(ref wrapped) = *locked(&self.wrap_wrapped) {
            let out = wrapped.as_slice().to_vec();
            plain.zeroize();
            return Ok(out);
        }
        Ok(plain)
    }

    fn provision(&self, slot: KeySlot, policy: SlotPolicy) -> Result<(), PlatformError> {
        self.provision_calls.fetch_add(1, Ordering::SeqCst);
        if !slot.has_device_blob() || policy.slot != slot {
            return Err(PlatformError::InvalidSlot);
        }
        if let Some(error) = *locked(&self.provision_error) {
            return Err(error);
        }
        Ok(())
    }

    fn destroy(&self, slot: KeySlot) -> Result<(), PlatformError> {
        self.destroy_calls.fetch_add(1, Ordering::SeqCst);
        if !slot.has_device_blob() {
            return Err(PlatformError::InvalidSlot);
        }
        if let Some(error) = *locked(&self.destroy_error) {
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{POLICY_A, POLICY_B};

    const KEK: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    ];

    #[test]
    fn default_unwrap_is_identity() {
        let fake = FakePlatformKeyStore::new();
        let out = fake.unwrap_kek(KeySlot::A, KEK.to_vec()).unwrap();
        assert_eq!(out, KEK);
        assert_eq!(fake.unwrap_kek_calls(), 1);
        assert_eq!(fake.wrap_kek_calls(), 0);
        assert_eq!(fake.provision_calls(), 0);
        assert_eq!(fake.destroy_calls(), 0);
    }

    #[test]
    fn default_wrap_is_identity() {
        let fake = FakePlatformKeyStore::default();
        let out = fake.wrap_kek(KeySlot::B, KEK.to_vec()).unwrap();
        assert_eq!(out, KEK);
        assert_eq!(fake.wrap_kek_calls(), 1);
    }

    #[test]
    fn configured_unwrap_payload() {
        let fake = FakePlatformKeyStore::new();
        let expected = vec![0xABu8; 32];
        fake.succeed_unwrap_with(expected.clone());
        let out = fake.unwrap_kek(KeySlot::A, vec![0x00; 32]).unwrap();
        assert_eq!(out, expected);
        assert_eq!(fake.unwrap_kek_calls(), 1);
    }

    #[test]
    fn configured_wrap_payload() {
        let fake = FakePlatformKeyStore::new();
        let expected = vec![0xCDu8; 32];
        fake.succeed_wrap_with(expected.clone());
        let out = fake.wrap_kek(KeySlot::B, vec![0x00; 32]).unwrap();
        assert_eq!(out, expected);
        assert_eq!(fake.wrap_kek_calls(), 1);
    }

    #[test]
    fn configured_failure_wins_over_payload() {
        let fake = FakePlatformKeyStore::new();
        fake.succeed_unwrap_with(vec![0x11; 32]);
        fake.fail_unwrap(PlatformError::UnwrapRejected);
        assert_eq!(
            fake.unwrap_kek(KeySlot::A, vec![0x22; 32]).unwrap_err(),
            PlatformError::UnwrapRejected
        );
        assert_eq!(fake.unwrap_kek_calls(), 1);

        fake.succeed_wrap_with(vec![0x33; 32]);
        fake.fail_wrap(PlatformError::WrapFailed);
        assert_eq!(
            fake.wrap_kek(KeySlot::A, vec![0x44; 32]).unwrap_err(),
            PlatformError::WrapFailed
        );
        assert_eq!(fake.wrap_kek_calls(), 1);
    }

    #[test]
    fn every_method_failure_surfaces() {
        let fake = FakePlatformKeyStore::new();
        fake.fail_unwrap(PlatformError::KeyInvalidated);
        fake.fail_wrap(PlatformError::WrapFailed);
        fake.fail_provision(PlatformError::ProvisionFailed);
        fake.fail_destroy(PlatformError::DestroyFailed);

        assert_eq!(
            fake.unwrap_kek(KeySlot::A, vec![1]).unwrap_err(),
            PlatformError::KeyInvalidated
        );
        assert_eq!(
            fake.wrap_kek(KeySlot::A, vec![1]).unwrap_err(),
            PlatformError::WrapFailed
        );
        assert_eq!(
            fake.provision(KeySlot::A, POLICY_A).unwrap_err(),
            PlatformError::ProvisionFailed
        );
        assert_eq!(
            fake.destroy(KeySlot::B).unwrap_err(),
            PlatformError::DestroyFailed
        );
        assert_eq!(fake.unwrap_kek_calls(), 1);
        assert_eq!(fake.wrap_kek_calls(), 1);
        assert_eq!(fake.provision_calls(), 1);
        assert_eq!(fake.destroy_calls(), 1);
    }

    #[test]
    fn unexpected_is_injectable() {
        let fake = FakePlatformKeyStore::new();
        fake.fail_unwrap(PlatformError::Unexpected);
        assert_eq!(
            fake.unwrap_kek(KeySlot::B, vec![0]).unwrap_err(),
            PlatformError::Unexpected
        );
    }

    #[test]
    fn slot_c_is_rejected_and_counted() {
        let fake = FakePlatformKeyStore::new();
        assert_eq!(
            fake.unwrap_kek(KeySlot::C, vec![0x55; 8]).unwrap_err(),
            PlatformError::InvalidSlot
        );
        assert_eq!(
            fake.wrap_kek(KeySlot::C, vec![0x55; 8]).unwrap_err(),
            PlatformError::InvalidSlot
        );
        assert_eq!(
            fake.provision(KeySlot::C, POLICY_A).unwrap_err(),
            PlatformError::InvalidSlot
        );
        assert_eq!(
            fake.destroy(KeySlot::C).unwrap_err(),
            PlatformError::InvalidSlot
        );
        assert_eq!(fake.unwrap_kek_calls(), 1);
        assert_eq!(fake.wrap_kek_calls(), 1);
        assert_eq!(fake.provision_calls(), 1);
        assert_eq!(fake.destroy_calls(), 1);
    }

    #[test]
    fn provision_rejects_slot_policy_mismatch() {
        let fake = FakePlatformKeyStore::new();
        assert_eq!(
            fake.provision(KeySlot::A, POLICY_B).unwrap_err(),
            PlatformError::InvalidSlot
        );
        assert_eq!(fake.provision_calls(), 1);
    }

    #[test]
    fn provision_and_destroy_succeed_for_matching_slots() {
        let fake = FakePlatformKeyStore::new();
        fake.provision(KeySlot::A, POLICY_A).unwrap();
        fake.provision(KeySlot::B, POLICY_B).unwrap();
        fake.destroy(KeySlot::A).unwrap();
        fake.destroy(KeySlot::B).unwrap();
        assert_eq!(fake.provision_calls(), 2);
        assert_eq!(fake.destroy_calls(), 2);
    }

    #[test]
    fn counters_accumulate_then_reset() {
        let fake = FakePlatformKeyStore::new();
        fake.unwrap_kek(KeySlot::A, vec![1]).unwrap();
        fake.unwrap_kek(KeySlot::A, vec![2]).unwrap();
        fake.wrap_kek(KeySlot::A, vec![3]).unwrap();
        fake.provision(KeySlot::A, POLICY_A).unwrap();
        fake.destroy(KeySlot::A).unwrap();
        assert_eq!(fake.unwrap_kek_calls(), 2);
        assert_eq!(fake.wrap_kek_calls(), 1);
        assert_eq!(fake.provision_calls(), 1);
        assert_eq!(fake.destroy_calls(), 1);

        fake.reset_calls();
        assert_eq!(fake.unwrap_kek_calls(), 0);
        assert_eq!(fake.wrap_kek_calls(), 0);
        assert_eq!(fake.provision_calls(), 0);
        assert_eq!(fake.destroy_calls(), 0);

        // Reset does not clear configuration.
        fake.fail_unwrap(PlatformError::UnwrapRejected);
        assert_eq!(
            fake.unwrap_kek(KeySlot::A, vec![9]).unwrap_err(),
            PlatformError::UnwrapRejected
        );
        assert_eq!(fake.unwrap_kek_calls(), 1);
    }

    #[test]
    fn clear_restores_identity_and_success() {
        let fake = FakePlatformKeyStore::new();
        fake.fail_unwrap(PlatformError::UnwrapRejected);
        fake.succeed_unwrap_with(vec![0x99; 4]);
        fake.clear_unwrap();
        assert_eq!(fake.unwrap_kek(KeySlot::A, vec![0x42]).unwrap(), vec![0x42]);

        fake.fail_wrap(PlatformError::WrapFailed);
        fake.succeed_wrap_with(vec![0x88; 4]);
        fake.clear_wrap();
        assert_eq!(fake.wrap_kek(KeySlot::A, vec![0x43]).unwrap(), vec![0x43]);

        fake.fail_provision(PlatformError::ProvisionFailed);
        fake.clear_provision();
        fake.provision(KeySlot::A, POLICY_A).unwrap();

        fake.fail_destroy(PlatformError::DestroyFailed);
        fake.clear_destroy();
        fake.destroy(KeySlot::A).unwrap();
    }

    #[test]
    fn debug_redacts_payloads() {
        let fake = FakePlatformKeyStore::new();
        fake.succeed_unwrap_with(vec![0xab, 0xcd, 0x12, 0x34]);
        fake.succeed_wrap_with(vec![0xfe, 0xdc, 0xba, 0x98]);
        let _ = fake.unwrap_kek(KeySlot::A, vec![0]);
        let rendered = format!("{fake:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("unwrap_kek_calls: 1"));
        assert!(!rendered.contains("abcd"));
        assert!(!rendered.contains("fedc"));
        assert!(!rendered.contains("1234"));
        assert!(!rendered.to_lowercase().contains("ab cd"));
    }

    #[test]
    fn zeroize_clears_configured_payloads() {
        let mut fake = FakePlatformKeyStore::new();
        fake.succeed_unwrap_with(vec![0xAA; 32]);
        fake.succeed_wrap_with(vec![0xBB; 32]);
        fake.zeroize();
        assert_eq!(
            fake.unwrap_kek(KeySlot::A, vec![0x01, 0x02]).unwrap(),
            vec![0x01, 0x02]
        );
        assert_eq!(
            fake.wrap_kek(KeySlot::A, vec![0x03, 0x04]).unwrap(),
            vec![0x03, 0x04]
        );
    }
}
