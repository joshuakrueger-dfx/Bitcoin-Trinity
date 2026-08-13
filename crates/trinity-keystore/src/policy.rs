//! Slot policy types — Spec §2.4.
//!
//! A and B share one code path. The difference is a [`SlotPolicy`]: unlock
//! factor, biometric-invalidation, and device-unlocked. Argon2id parameters
//! are named data ([`ArgonProfile`]); this module does not run Argon2id
//! (WP-35).
//!
//! # `hw_binding` is not baked into [`POLICY_A`] / [`POLICY_B`]
//!
//! The spec sketch lists `hw_binding: HwBinding` (`SecureEnclaveEcies` |
//! `KeystoreAesGcm`) on `SlotPolicy`. That enum names the *cryptographic
//! wrapping mechanism*, not the unlock policy (already captured by
//! [`UnlockFactor`], [`SlotPolicy::invalidate_on_biometric_change`], and
//! [`SlotPolicy::require_device_unlocked`]).
//!
//! A single compiled binary targets one platform. This crate has no
//! `#[cfg(target_os)]` split (WP-41 / WP-42). A `const` policy therefore
//! cannot name one `HwBinding` without lying about the other platform, and
//! both slots on the same device use the *same* wrapping mechanism anyway —
//! the A/B split is the access class, not ECIES vs AES-GCM.
//!
//! So [`SlotPolicy::hw_binding`] is `Option<HwBinding>` and both published
//! constants leave it `None`. The platform layer fills it in at
//! `provision()` time (WP-41 / WP-42), e.g. via
//! [`SlotPolicy::with_hw_binding`]. Treating either variant as a default
//! here would paper over an under-specified point.

use trinity_types::KeySlot;

/// How the user proves presence to unwrap this slot's KEK.
///
/// Spec §2.4's struct comment still says `Biometry | Passphrase`. That is
/// stale after decision E7: the passphrase authorizes (spend limit, export,
/// rotation) and does **not** decrypt `blob_B`. The live access classes are
/// biometry (A) and user presence (B).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockFactor {
    /// Current biometric enrollment (iOS `.biometryCurrentSet` / Android
    /// `AUTH_BIOMETRIC_STRONG` with invalidation on re-enrollment).
    Biometry,
    /// Biometrics **or** the device passcode (iOS `.userPresence` / Android
    /// `AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL`).
    UserPresence,
}

impl UnlockFactor {
    /// Stable label. These values are not secret.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            UnlockFactor::Biometry => "biometry",
            UnlockFactor::UserPresence => "user-presence",
        }
    }
}

impl core::fmt::Display for UnlockFactor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Platform wrapping mechanism for the 32-byte KEK.
///
/// Not an unlock policy. Not a `const` field of [`POLICY_A`] / [`POLICY_B`].
/// WP-41 (iOS) and WP-42 (Android) pick the variant that matches the binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwBinding {
    /// iOS Secure Enclave: P-256 ECIES wrap (`SecKeyCreateDecryptedData`).
    SecureEnclaveEcies,
    /// Android Keystore: AES-256-GCM wrap (StrongBox when available).
    KeystoreAesGcm,
}

impl HwBinding {
    /// Stable label. Not secret.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            HwBinding::SecureEnclaveEcies => "secure-enclave-ecies",
            HwBinding::KeystoreAesGcm => "keystore-aes-gcm",
        }
    }
}

impl core::fmt::Display for HwBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Named Argon2id parameter set (Decision E4). Plain data — no KDF here.
///
/// | Profile | m (KiB) | t | p | output |
/// |---------|---------|---|---|--------|
/// | [`ArgonProfile::High`] | 262144 | 3 | 4 | 32 B |
/// | [`ArgonProfile::Low`]  | 65536  | 6 | 4 | 32 B |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgonProfile {
    /// Default. Target ≥ 4 GB RAM. RFC 9106-class memory, `t = 3`.
    High,
    /// Fallback for < 4 GB RAM. RFC 9106 option 2 memory, `t` doubled to 6.
    Low,
}

impl ArgonProfile {
    /// Both named profiles, High first.
    pub const ALL: [ArgonProfile; 2] = [ArgonProfile::High, ArgonProfile::Low];

    /// Memory cost `m` in KiB.
    #[inline]
    pub const fn memory_kib(self) -> u32 {
        match self {
            ArgonProfile::High => 262_144,
            ArgonProfile::Low => 65_536,
        }
    }

    /// Time cost `t` (passes).
    #[inline]
    pub const fn time_cost(self) -> u32 {
        match self {
            ArgonProfile::High => 3,
            ArgonProfile::Low => 6,
        }
    }

    /// Parallelism `p`.
    #[inline]
    pub const fn parallelism(self) -> u32 {
        4
    }

    /// Tag / output length in bytes.
    #[inline]
    pub const fn output_len(self) -> u32 {
        32
    }

    /// Spec table name (`HIGH` / `LOW`).
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            ArgonProfile::High => "HIGH",
            ArgonProfile::Low => "LOW",
        }
    }
}

impl core::fmt::Display for ArgonProfile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-slot access policy (Spec §2.4).
///
/// Not a secret type: these fields are configuration, not key material.
/// [`Clone`] / [`Debug`] are therefore fine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotPolicy {
    /// Slot this policy applies to (`A` or `B`; `C` has no device blob).
    pub slot: KeySlot,
    /// Presence check required to unwrap the KEK.
    pub unlock: UnlockFactor,
    /// Platform wrapping mechanism. `None` on the published constants —
    /// see the module docs.
    pub hw_binding: Option<HwBinding>,
    /// Argon2id profile for the *passphrase verifier* (WP-35). Both
    /// published constants are `None`: the verifier lives in the spend-policy
    /// record, not in the blob and not in these access-class constants.
    pub argon: Option<ArgonProfile>,
    /// Destroy the wrapping key if the biometric enrollment set changes.
    pub invalidate_on_biometric_change: bool,
    /// Refuse unwrap while the device is locked.
    pub require_device_unlocked: bool,
}

impl SlotPolicy {
    /// Attach a platform wrapping mechanism.
    ///
    /// Intended for WP-41 / WP-42 at `provision()` time. Does not change any
    /// other field.
    #[inline]
    pub const fn with_hw_binding(mut self, hw_binding: HwBinding) -> Self {
        self.hw_binding = Some(hw_binding);
        self
    }
}

/// Slot A: current biometrics, invalidated on re-enrollment.
///
/// iOS `.biometryCurrentSet` / Android `AUTH_BIOMETRIC_STRONG` +
/// `setInvalidatedByBiometricEnrollment(true)`. `hw_binding` is unset.
pub const POLICY_A: SlotPolicy = SlotPolicy {
    slot: KeySlot::A,
    unlock: UnlockFactor::Biometry,
    hw_binding: None,
    argon: None,
    invalidate_on_biometric_change: true,
    require_device_unlocked: true,
};

/// Slot B: user presence (biometrics or device passcode), survives
/// re-enrollment.
///
/// iOS `.userPresence` / Android `AUTH_BIOMETRIC_STRONG |
/// AUTH_DEVICE_CREDENTIAL` + `setInvalidatedByBiometricEnrollment(false)`.
/// `hw_binding` is unset. The passphrase is **not** this slot's unlock
/// factor (E7).
pub const POLICY_B: SlotPolicy = SlotPolicy {
    slot: KeySlot::B,
    unlock: UnlockFactor::UserPresence,
    hw_binding: None,
    argon: None,
    invalidate_on_biometric_change: false,
    require_device_unlocked: true,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_a_matches_spec_access_class() {
        let policy = POLICY_A;
        assert_eq!(policy.slot, KeySlot::A);
        assert_eq!(policy.unlock, UnlockFactor::Biometry);
        assert_eq!(policy.hw_binding, None);
        assert_eq!(policy.argon, None);
        assert!(policy.invalidate_on_biometric_change);
        assert!(policy.require_device_unlocked);
    }

    #[test]
    fn policy_b_matches_spec_access_class() {
        let policy = POLICY_B;
        assert_eq!(policy.slot, KeySlot::B);
        assert_eq!(policy.unlock, UnlockFactor::UserPresence);
        assert_eq!(policy.hw_binding, None);
        assert_eq!(policy.argon, None);
        assert!(!policy.invalidate_on_biometric_change);
        assert!(policy.require_device_unlocked);
    }

    #[test]
    fn with_hw_binding_fills_only_that_field() {
        let ios = POLICY_A.with_hw_binding(HwBinding::SecureEnclaveEcies);
        assert_eq!(ios.hw_binding, Some(HwBinding::SecureEnclaveEcies));
        assert_eq!(ios.slot, POLICY_A.slot);
        assert_eq!(ios.unlock, POLICY_A.unlock);
        assert_eq!(ios.argon, POLICY_A.argon);
        assert_eq!(
            ios.invalidate_on_biometric_change,
            POLICY_A.invalidate_on_biometric_change
        );
        assert_eq!(
            ios.require_device_unlocked,
            POLICY_A.require_device_unlocked
        );

        let android = POLICY_B.with_hw_binding(HwBinding::KeystoreAesGcm);
        assert_eq!(android.hw_binding, Some(HwBinding::KeystoreAesGcm));
        assert_eq!(android.slot, KeySlot::B);
    }

    #[test]
    fn argon_profiles_match_decision_e4() {
        assert_eq!(ArgonProfile::High.memory_kib(), 262_144);
        assert_eq!(ArgonProfile::High.time_cost(), 3);
        assert_eq!(ArgonProfile::High.parallelism(), 4);
        assert_eq!(ArgonProfile::High.output_len(), 32);
        assert_eq!(ArgonProfile::Low.memory_kib(), 65_536);
        assert_eq!(ArgonProfile::Low.time_cost(), 6);
        assert_eq!(ArgonProfile::Low.parallelism(), 4);
        assert_eq!(ArgonProfile::Low.output_len(), 32);
        assert_eq!(ArgonProfile::ALL, [ArgonProfile::High, ArgonProfile::Low]);
    }

    #[test]
    fn labels_and_display() {
        assert_eq!(UnlockFactor::Biometry.as_str(), "biometry");
        assert_eq!(UnlockFactor::UserPresence.as_str(), "user-presence");
        assert_eq!(UnlockFactor::Biometry.to_string(), "biometry");
        assert_eq!(UnlockFactor::UserPresence.to_string(), "user-presence");
        assert_eq!(
            HwBinding::SecureEnclaveEcies.as_str(),
            "secure-enclave-ecies"
        );
        assert_eq!(HwBinding::KeystoreAesGcm.as_str(), "keystore-aes-gcm");
        assert_eq!(
            HwBinding::SecureEnclaveEcies.to_string(),
            "secure-enclave-ecies"
        );
        assert_eq!(HwBinding::KeystoreAesGcm.to_string(), "keystore-aes-gcm");
        assert_eq!(ArgonProfile::High.as_str(), "HIGH");
        assert_eq!(ArgonProfile::Low.as_str(), "LOW");
        assert_eq!(ArgonProfile::High.to_string(), "HIGH");
        assert_eq!(ArgonProfile::Low.to_string(), "LOW");
    }

    #[test]
    fn slot_policy_is_copy_and_debug_is_not_secret() {
        let a = POLICY_A;
        let b = a;
        assert_eq!(a, b);
        let rendered = format!("{a:?}");
        assert!(rendered.contains("Biometry"));
        assert!(rendered.contains("slot: A"));
    }
}
