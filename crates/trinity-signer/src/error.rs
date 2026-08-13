//! Fail-closed signing errors — Spec §3.3 / §3.4.
//!
//! Only variants this WP can actually produce. `PassphraseRequired` and
//! `SpendLimitExceeded` belong to WP-34 / WP-35 and are not defined here.
//! No string payload — a caller that wants a message maps a closed reason.

use thiserror::Error;
use trinity_keystore::{BlobError, PlatformError};
use trinity_verify::VerifyError;

/// Hard rejection while preparing or producing a signature.
///
/// Every path is a concrete variant (fail-closed). `Verify` wraps the
/// independent V1–V10 result so S9 can match
/// [`VerifyError::ForeignChangeOutput`] without a second classification.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SignError {
    /// Independent verification rejected the PSBT (Spec §3.3 runs 2 and 3).
    #[error("independent verification rejected the PSBT")]
    Verify(#[from] VerifyError),

    /// The signature we just produced does not verify against our pubkey
    /// and sighash, or is not low-s.
    #[error("self-verification of the produced signature failed")]
    SelfVerificationFailed,

    /// Input sighash field or an existing partial signature is not `SIGHASH_ALL`.
    #[error("input {input_index}: sighash is not SIGHASH_ALL")]
    NonSighashAll {
        /// PSBT input index.
        input_index: usize,
    },

    /// Platform KEK unwrap (or other platform callback) failed.
    #[error("platform keystore failed")]
    Platform(#[from] PlatformError),

    /// `unsigned_tx` txid changed between the A signature and the B step (S10).
    #[error("unsigned transaction changed between signature A and B")]
    UnsignedTxChanged,

    /// The A signature is missing, belongs to the wrong pubkey, or does not
    /// verify against the current sighash.
    #[error("key-A signature is missing or does not belong to the expected pubkey")]
    UnexpectedKeyASignature,

    /// Encrypted blob failed structural or AEAD checks.
    #[error("encrypted key blob rejected")]
    Blob(#[from] BlobError),

    /// Entropy → BIP-39 seed failed (wrong length or BIP-39 rejection).
    #[error("entropy to BIP-39 seed derivation failed")]
    Entropy,

    /// BIP-32 master or child derivation failed.
    #[error("BIP-32 derivation failed")]
    Bip32,

    /// Platform returned a KEK that is not 32 bytes.
    #[error("platform returned a KEK of the wrong length")]
    InvalidKekLength,

    /// Slot C (no device blob), or the decrypted blob's slot ≠ this signer.
    #[error("slot is not valid for a local signer")]
    InvalidSlot,

    /// Unlocked master fingerprint does not match the fingerprint declared
    /// at construction.
    #[error("derived master fingerprint does not match the signer")]
    FingerprintMismatch,

    /// Input has no `witness_utxo`.
    #[error("input {input_index}: missing witness_utxo")]
    MissingWitnessUtxo {
        /// PSBT input index.
        input_index: usize,
    },

    /// Input has no `witness_script` (Trinity spends P2WSH only).
    #[error("input {input_index}: missing witness_script")]
    MissingWitnessScript {
        /// PSBT input index.
        input_index: usize,
    },

    /// Input has no `bip32_derivation` entry for this signer's fingerprint.
    #[error("input {input_index}: no bip32 derivation for this signer")]
    MissingDerivation {
        /// PSBT input index.
        input_index: usize,
    },

    /// Derived child pubkey does not match the pubkey next to our fingerprint.
    #[error("input {input_index}: derived pubkey does not match bip32_derivation")]
    PubkeyMismatch {
        /// PSBT input index.
        input_index: usize,
    },

    /// Sighash computation rejected the input index.
    #[error("input {input_index}: sighash computation failed")]
    Sighash {
        /// PSBT input index.
        input_index: usize,
    },

    /// PSBT has no inputs.
    #[error("PSBT has no inputs")]
    EmptyPsbt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use trinity_keystore::PlatformError;
    use trinity_verify::VerifyError;

    #[test]
    fn display_covers_every_variant() {
        let cases: &[SignError] = &[
            SignError::Verify(VerifyError::PsbtDecode),
            SignError::SelfVerificationFailed,
            SignError::NonSighashAll { input_index: 0 },
            SignError::Platform(PlatformError::UnwrapRejected),
            SignError::UnsignedTxChanged,
            SignError::UnexpectedKeyASignature,
            SignError::Blob(trinity_keystore::BlobError::Aead),
            SignError::Entropy,
            SignError::Bip32,
            SignError::InvalidKekLength,
            SignError::InvalidSlot,
            SignError::FingerprintMismatch,
            SignError::MissingWitnessUtxo { input_index: 1 },
            SignError::MissingWitnessScript { input_index: 1 },
            SignError::MissingDerivation { input_index: 1 },
            SignError::PubkeyMismatch { input_index: 1 },
            SignError::Sighash { input_index: 1 },
            SignError::EmptyPsbt,
        ];
        for e in cases {
            assert!(!e.to_string().is_empty(), "{e:?}");
        }
    }

    #[test]
    fn from_verify_and_platform_and_blob() {
        let v: SignError = VerifyError::FeeNonPositive.into();
        assert!(matches!(v, SignError::Verify(VerifyError::FeeNonPositive)));
        let p: SignError = PlatformError::KeyInvalidated.into();
        assert!(matches!(
            p,
            SignError::Platform(PlatformError::KeyInvalidated)
        ));
        let b: SignError = trinity_keystore::BlobError::Truncated.into();
        assert!(matches!(
            b,
            SignError::Blob(trinity_keystore::BlobError::Truncated)
        ));
    }

    #[test]
    fn eq_distinguishes_variants() {
        assert_ne!(SignError::EmptyPsbt, SignError::UnsignedTxChanged);
        assert_eq!(
            SignError::NonSighashAll { input_index: 2 },
            SignError::NonSighashAll { input_index: 2 }
        );
        assert_ne!(
            SignError::NonSighashAll { input_index: 2 },
            SignError::NonSighashAll { input_index: 3 }
        );
    }
}
