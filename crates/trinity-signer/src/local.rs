//! [`LocalSigner`] — on-device slot A or B.
//!
//! # No `Keystore` type
//!
//! Spec §6.6 sketches `keystore: Arc<Keystore>`, but no `Keystore` type
//! exists in this workspace (WP-32 left the unwrap→decrypt composition
//! to this WP). Adding a wrapper in `trinity-keystore` would open surface
//! on a merged crate. This type therefore holds `Arc<dyn PlatformKeyStore>`
//! plus the sealed blob and the wrapped KEK, and chains
//! [`PlatformKeyStore::unwrap_kek`] → [`trinity_keystore::decrypt`] itself.
//!
//! Unlock happens only after [`crate::sign::preflight_inputs`] (and, on
//! the `sign_a` / `sign_b` path, after [`trinity_verify::verify`]).

use std::fmt;
use std::sync::Arc;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use trinity_keystore::{decrypt, PlatformKeyStore};
use trinity_types::{Fingerprint, KeySlot, SecretBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SignError;
use crate::kind::SignerKind;
use crate::sign::{
    erase_secret_key, erase_xpriv, map_bip32, preflight_inputs, seed_from_entropy, sign_inputs,
};
use crate::Signer;

/// Local software signer for one on-device slot.
///
/// `wrapped_kek` is platform-wrapped ciphertext in production. The test
/// fake identity-wraps, so the field is always treated as secret material
/// and lives in [`SecretBytes`]. The sealed blob is AEAD ciphertext and
/// is not a secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LocalSigner {
    #[zeroize(skip)]
    slot: KeySlot,
    #[zeroize(skip)]
    fingerprint: Fingerprint,
    #[zeroize(skip)]
    platform: Arc<dyn PlatformKeyStore>,
    wrapped_kek: SecretBytes,
    #[zeroize(skip)]
    blob: Vec<u8>,
}

impl LocalSigner {
    /// Construct a signer for slot A or B.
    ///
    /// `fingerprint` is the BIP-32 **master** fingerprint declared at
    /// setup (public). It is checked against the unlocked master after
    /// decrypt — a swapped blob cannot silently sign.
    pub fn new(
        slot: KeySlot,
        fingerprint: Fingerprint,
        platform: Arc<dyn PlatformKeyStore>,
        wrapped_kek: SecretBytes,
        blob: Vec<u8>,
    ) -> Result<Self, SignError> {
        if !slot.has_device_blob() {
            return Err(SignError::InvalidSlot);
        }
        Ok(Self {
            slot,
            fingerprint,
            platform,
            wrapped_kek,
            blob,
        })
    }

    /// Slot this signer unlocks.
    #[inline]
    pub fn slot(&self) -> KeySlot {
        self.slot
    }
}

impl fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSigner")
            .field("slot", &self.slot)
            .field("fingerprint", &self.fingerprint)
            .field("wrapped_kek", &"[redacted]")
            .field("blob_len", &self.blob.len())
            .finish()
    }
}

impl Signer for LocalSigner {
    fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    fn sign(&self, psbt: Psbt) -> Result<Psbt, SignError> {
        preflight_inputs(&psbt, self.fingerprint)?;
        let mut master = self.unlock_master()?;
        let result = sign_with_master(psbt, &master, self.fingerprint);
        erase_xpriv(&mut master);
        result
    }

    fn kind(&self) -> SignerKind {
        SignerKind::Local
    }
}

impl LocalSigner {
    fn unlock_master(&self) -> Result<Xpriv, SignError> {
        let wrapped = self.wrapped_kek.as_slice().to_vec();
        let mut kek = self.platform.unwrap_kek(self.slot, wrapped)?;
        if kek.len() != 32 {
            kek.zeroize();
            return Err(SignError::InvalidKekLength);
        }
        let mut kek_arr = [0u8; 32];
        kek_arr.copy_from_slice(&kek);
        kek.zeroize();
        let decoded = decrypt(&kek_arr, &self.blob);
        kek_arr.zeroize();
        let decoded = decoded?;
        if decoded.slot() != self.slot {
            return Err(SignError::InvalidSlot);
        }
        let seed = seed_from_entropy(decoded.entropy().as_slice())?;
        // Network does not affect key material or the fingerprint.
        // trinity-entropy::finish pins Bitcoin the same way.
        let mut master = map_bip32(Xpriv::new_master(Network::Bitcoin, seed.as_slice()))?;
        let secp = Secp256k1::signing_only();
        let got = master.fingerprint(&secp);
        if *got.as_bytes() != self.fingerprint.to_bytes() {
            erase_xpriv(&mut master);
            return Err(SignError::FingerprintMismatch);
        }
        Ok(master)
    }
}

fn sign_with_master(
    psbt: Psbt,
    master: &Xpriv,
    fingerprint: Fingerprint,
) -> Result<Psbt, SignError> {
    let secp = Secp256k1::signing_only();
    let mut derived = Vec::with_capacity(psbt.inputs.len());
    let want = fingerprint.to_bytes();
    let result = (|| {
        for (i, input) in psbt.inputs.iter().enumerate() {
            let (pk, (_, path)) = input
                .bip32_derivation
                .iter()
                .find(|(_, (fp, _))| *fp.as_bytes() == want)
                .expect("preflight required our fingerprint");
            let (child_pk, mut sk) = derive_child(master, path, &secp)?;
            if child_pk != *pk {
                erase_secret_key(&mut sk);
                return Err(SignError::PubkeyMismatch { input_index: i });
            }
            derived.push((i, child_pk, sk));
        }
        sign_inputs(psbt, &mut derived)
    })();
    for (_, _, sk) in &mut derived {
        erase_secret_key(sk);
    }
    result
}

fn derive_child<C: bitcoin::secp256k1::Signing>(
    master: &Xpriv,
    path: &DerivationPath,
    secp: &Secp256k1<C>,
) -> Result<(SecpPublicKey, SecretKey), SignError> {
    let mut child = map_bip32(master.derive_priv(secp, path))?;
    let sk = child.private_key;
    erase_xpriv(&mut child);
    let pk = SecpPublicKey::from_secret_key(secp, &sk);
    Ok((pk, sk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trinity_keystore::FakePlatformKeyStore;
    use trinity_types::KeySlot;

    #[test]
    fn new_rejects_slot_c() {
        let fake = Arc::new(FakePlatformKeyStore::new());
        let err = LocalSigner::new(
            KeySlot::C,
            Fingerprint::new([0; 4]),
            fake,
            SecretBytes::from_slice(&[0u8; 32]),
            vec![],
        )
        .unwrap_err();
        assert_eq!(err, SignError::InvalidSlot);
    }

    #[test]
    fn new_accepts_a_and_b() {
        let fake = Arc::new(FakePlatformKeyStore::new());
        for slot in [KeySlot::A, KeySlot::B] {
            let s = LocalSigner::new(
                slot,
                Fingerprint::new([1, 2, 3, 4]),
                fake.clone(),
                SecretBytes::from_slice(&[0u8; 32]),
                vec![1, 2, 3],
            )
            .unwrap();
            assert_eq!(s.slot(), slot);
            assert_eq!(s.fingerprint(), Fingerprint::new([1, 2, 3, 4]));
            assert_eq!(s.kind(), SignerKind::Local);
        }
    }

    #[test]
    fn debug_redacts_kek() {
        let fake = Arc::new(FakePlatformKeyStore::new());
        let s = LocalSigner::new(
            KeySlot::A,
            Fingerprint::new([0xab, 0xcd, 0x12, 0x34]),
            fake,
            SecretBytes::from_slice(&[0xde, 0xad, 0xbe, 0xef]),
            vec![9; 8],
        )
        .unwrap();
        let rendered = format!("{s:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("abcd1234"));
        assert!(!rendered.contains("dead"));
        assert!(!rendered.contains("beef"));
        assert!(rendered.contains("blob_len: 8"));
    }
}
