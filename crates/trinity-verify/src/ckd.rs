//! Own BIP-32 public child key derivation (CKDpub) — independent of the builder.
//!
//! Source: <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
//! (Child key derivation (CKD) functions → Public parent key → public child key;
//! Serialization of extended keys for field layout of chain code + pubkey).
//!
//! Spec §1.5 independence table: verifier must implement CKDpub itself so a
//! `bitcoin::bip32` bug in the builder cannot confirm itself. Shared remain
//! only HMAC-SHA512 (`bitcoin::hashes`) and EC point arithmetic
//! (`bitcoin::secp256k1`). This module deliberately does **not** call
//! `Xpub::derive_pub` / `ckd_pub` / `derive_priv`.

use bitcoin::hashes::{sha512, Hash as _, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::error::DeriveError;

/// Highest non-hardened child index (`2³¹ − 1`).
pub const MAX_NON_HARDENED_INDEX: u32 = 0x7fff_ffff;

/// Hardened-index bit (`2³¹`). Indices with this bit set are rejected.
const HARDENED_BIT: u32 = 0x8000_0000;

/// One non-hardened CKD step: parent chain code + compressed pubkey → child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildKey {
    /// BIP-32 child chain code (32 bytes).
    pub chain_code: [u8; 32],
    /// Child compressed SEC1 public key (33 bytes).
    pub public_key: [u8; 33],
}

/// BIP-32 CKDpub: non-hardened public child derivation.
///
/// ```text
/// I     = HMAC-SHA512(Key = c_par, Data = serP(K_par) || ser32(i))
/// I_L   = I[0..32],  I_R = I[32..64]
/// K_i   = point(I_L) + K_par
/// c_i   = I_R
/// ```
///
/// `index` must be non-hardened (`index < 2³¹`). Hardened derivation is
/// impossible without the private key and is rejected as
/// [`DeriveError::HardenedIndex`].
pub fn ckd_pub(
    parent_chain_code: &[u8; 32],
    parent_pubkey: &[u8; 33],
    index: u32,
) -> Result<ChildKey, DeriveError> {
    if index & HARDENED_BIT != 0 {
        return Err(DeriveError::HardenedIndex(index));
    }

    let parent_pk =
        PublicKey::from_slice(parent_pubkey).map_err(|_| DeriveError::InvalidPublicKey)?;

    // I = HMAC-SHA512(Key = c_par, Data = serP(K_par) || ser32(i))
    let mut engine: HmacEngine<sha512::Hash> = HmacEngine::new(parent_chain_code);
    engine.input(parent_pubkey);
    engine.input(&index.to_be_bytes());
    let i: Hmac<sha512::Hash> = Hmac::from_engine(engine);

    let il = parse_il(&i[..32])?;
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i[32..]);

    let child_pk = tweak_add_parent(&parent_pk, &il)?;

    Ok(ChildKey {
        chain_code: ir,
        public_key: child_pk.serialize(),
    })
}

/// Parse `I_L` (32 bytes) as a secp256k1 secret key / scalar tweak.
///
/// BIP-32: if `parse₂₅₆(I_L) ≥ n` or `I_L = 0`, the key is invalid.
fn parse_il(il: &[u8]) -> Result<SecretKey, DeriveError> {
    SecretKey::from_slice(il).map_err(|_| DeriveError::InvalidTweak)
}

/// `K_i = point(I_L) + K_par` via `add_exp_tweak` (shared EC layer, allowed).
fn tweak_add_parent(parent: &PublicKey, il: &SecretKey) -> Result<PublicKey, DeriveError> {
    let secp = Secp256k1::verification_only();
    parent
        .add_exp_tweak(&secp, &(*il).into())
        .map_err(|_| DeriveError::InvalidTweak)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn rejects_hardened_index() {
        let cc = [1u8; 32];
        // A real compressed pubkey from BIP-32 test vector 1 master.
        let pk = hex_pk("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
        assert_eq!(
            ckd_pub(&cc, &pk, HARDENED_BIT),
            Err(DeriveError::HardenedIndex(HARDENED_BIT))
        );
        assert_eq!(
            ckd_pub(&cc, &pk, HARDENED_BIT | 1),
            Err(DeriveError::HardenedIndex(HARDENED_BIT | 1))
        );
        assert_eq!(
            ckd_pub(&cc, &pk, u32::MAX),
            Err(DeriveError::HardenedIndex(u32::MAX))
        );
    }

    #[test]
    fn rejects_invalid_parent_pubkey() {
        let cc = [2u8; 32];
        let bad = [0u8; 33];
        assert_eq!(ckd_pub(&cc, &bad, 0), Err(DeriveError::InvalidPublicKey));
        // Wrong prefix.
        let mut almost =
            hex_pk("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
        almost[0] = 0x04;
        assert_eq!(ckd_pub(&cc, &almost, 0), Err(DeriveError::InvalidPublicKey));
    }

    #[test]
    fn parse_il_rejects_zero() {
        assert_eq!(parse_il(&[0u8; 32]), Err(DeriveError::InvalidTweak));
    }

    #[test]
    fn parse_il_rejects_above_order() {
        // Curve order n (not a valid secret key).
        let n = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];
        assert_eq!(parse_il(&n), Err(DeriveError::InvalidTweak));
    }

    #[test]
    fn parse_il_accepts_one() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(parse_il(&one).is_ok());
    }

    #[test]
    fn tweak_add_rejects_point_at_infinity() {
        // K + (−k)·G = ∞ when K = k·G.
        let secp = Secp256k1::new();
        let mut raw = [0u8; 32];
        raw[31] = 7;
        let sk = SecretKey::from_slice(&raw).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let neg = sk.negate();
        assert_eq!(tweak_add_parent(&pk, &neg), Err(DeriveError::InvalidTweak));
    }

    #[test]
    fn max_non_hardened_index_is_accepted_by_gate() {
        // Gate only: not a full vector. Index 2³¹−1 must pass the hardened check.
        assert_eq!(MAX_NON_HARDENED_INDEX, HARDENED_BIT - 1);
        assert_eq!(MAX_NON_HARDENED_INDEX & HARDENED_BIT, 0);
    }

    fn hex_pk(s: &str) -> [u8; 33] {
        assert_eq!(s.len(), 66);
        let mut out = [0u8; 33];
        for i in 0..33 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }
}
