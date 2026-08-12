//! Own witnessScript / P2WSH construction — independent of the builder.
//!
//! Builds `OP_k <sorted pk₁> … <sorted pkₙ> OP_n OP_CHECKMULTISIG` from
//! already BIP-67-sorted compressed pubkeys. Spec §1.5: script construction
//! must not go through `miniscript`. Shared remain only `bitcoin::script`
//! assembly opcodes and SHA-256 for the P2WSH program (hash layer, allowed).
//!
//! Trinity production path is always `k = 2`, `n = 3`. The general builder is
//! exposed so BIP-67 official script vectors (2-of-2, 2-of-4) can be checked
//! bit-for-bit without a separate code path.

use bitcoin::blockdata::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::{Address, Network, Script};

use crate::error::DeriveError;

/// Build a bare CHECKMULTISIG script from already-sorted compressed pubkeys.
///
/// ```text
/// OP_k <pk₁> … <pkₙ> OP_n OP_CHECKMULTISIG
/// ```
///
/// `sorted_pubkeys` must already be BIP-67 ordered. `k` and `n = sorted_pubkeys.len()`
/// must satisfy `1 ≤ k ≤ n ≤ 16` (standard pushnum range). Each key must be a
/// 33-byte compressed SEC1 encoding (prefix `0x02` / `0x03`). Curve-point
/// validity is not re-checked here — BIP-67 sorts and encodes the bytes; the
/// production path obtains keys only via [`crate::ckd::ckd_pub`], which always
/// emits valid points. Official BIP-67 vector 3 deliberately uses edge-case
/// byte strings that are not on-curve.
pub fn build_checkmultisig_script(
    k: u32,
    sorted_pubkeys: &[[u8; 33]],
) -> Result<ScriptBuf, DeriveError> {
    let n = sorted_pubkeys.len() as u32;
    if !(1..=16).contains(&k) || !(1..=16).contains(&n) || k > n {
        return Err(DeriveError::InvalidMultisigParams { k, n });
    }

    for (i, pk) in sorted_pubkeys.iter().enumerate() {
        // Compressed SEC1 prefix only (BIP-67 requires compressed form).
        if pk[0] != 0x02 && pk[0] != 0x03 {
            return Err(DeriveError::InvalidCompressedPubkey(i));
        }
    }

    let mut builder = Builder::new().push_int(i64::from(k));
    for pk in sorted_pubkeys {
        builder = builder.push_slice(pk);
    }
    builder = builder.push_int(i64::from(n)).push_opcode(OP_CHECKMULTISIG);
    Ok(builder.into_script())
}

/// Trinity 2-of-3 witnessScript from three BIP-67-sorted compressed pubkeys.
#[inline]
pub fn witness_script_2of3(sorted: &[[u8; 33]; 3]) -> Result<ScriptBuf, DeriveError> {
    build_checkmultisig_script(2, sorted)
}

/// P2WSH `scriptPubKey`: `OP_0 <sha256(witnessScript)>`.
#[inline]
pub fn p2wsh_script_pubkey(witness_script: &Script) -> ScriptBuf {
    witness_script.to_p2wsh()
}

/// Bech32 P2WSH address for a witnessScript on `network`.
#[inline]
pub fn p2wsh_address(witness_script: &Script, network: Network) -> Address {
    Address::p2wsh(witness_script, network)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_pk(tag: u8) -> [u8; 33] {
        // Deterministic valid compressed keys via secret key tag.
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let mut raw = [0u8; 32];
        raw[31] = tag.max(1);
        let sk = SecretKey::from_slice(&raw).unwrap();
        PublicKey::from_secret_key(&secp, &sk).serialize()
    }

    #[test]
    fn rejects_bad_params() {
        let pks = [valid_pk(1), valid_pk(2), valid_pk(3)];
        assert_eq!(
            build_checkmultisig_script(0, &pks),
            Err(DeriveError::InvalidMultisigParams { k: 0, n: 3 })
        );
        assert_eq!(
            build_checkmultisig_script(4, &pks),
            Err(DeriveError::InvalidMultisigParams { k: 4, n: 3 })
        );
        assert_eq!(
            build_checkmultisig_script(1, &[]),
            Err(DeriveError::InvalidMultisigParams { k: 1, n: 0 })
        );
        assert_eq!(
            build_checkmultisig_script(17, &[valid_pk(1)]),
            Err(DeriveError::InvalidMultisigParams { k: 17, n: 1 })
        );
    }

    #[test]
    fn rejects_invalid_pubkey_bytes() {
        let mut pks = [valid_pk(1), valid_pk(2), [0u8; 33]];
        assert_eq!(
            build_checkmultisig_script(2, &pks),
            Err(DeriveError::InvalidCompressedPubkey(2))
        );
        // Uncompressed / wrong prefix rejected.
        pks[2] = valid_pk(3);
        pks[2][0] = 0x04;
        assert_eq!(
            build_checkmultisig_script(2, &pks),
            Err(DeriveError::InvalidCompressedPubkey(2))
        );
        // Prefix 0x02 with arbitrary payload is accepted at this layer (byte
        // encoding only); production keys are always CKD-valid.
        pks[2] = [0x02; 33];
        assert!(build_checkmultisig_script(2, &pks).is_ok());
    }

    #[test]
    fn two_of_three_shape() {
        let mut pks = [valid_pk(3), valid_pk(1), valid_pk(2)];
        crate::bip67::sort_pubkeys(&mut pks);
        let ws = witness_script_2of3(&pks).unwrap();
        let bytes = ws.as_bytes();
        // OP_2 = 0x52, OP_3 = 0x53, OP_CHECKMULTISIG = 0xae
        assert_eq!(bytes[0], 0x52);
        assert_eq!(*bytes.last().unwrap(), 0xae);
        // Three 33-byte pushes with OP_PUSHBYTES_33 (0x21).
        assert_eq!(bytes[1], 0x21);
        assert_eq!(bytes[1 + 1 + 33], 0x21);
        assert_eq!(bytes[1 + 2 * (1 + 33)], 0x21);
        assert_eq!(bytes[1 + 3 * (1 + 33)], 0x53);
        let spk = p2wsh_script_pubkey(&ws);
        assert!(spk.is_p2wsh());
        let addr = p2wsh_address(&ws, Network::Bitcoin);
        assert!(addr.to_string().starts_with("bc1"));
    }
}
