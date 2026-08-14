//! Crate-internal `sign_a` / `sign_b` and the RFC-6979 signing primitive.
//!
//! Spec §3.3: the verifier runs **before** any key access. Spec §3.4:
//! ECDSA via `bitcoin::secp256k1::Secp256k1::sign_ecdsa_low_r` (RFC 6979
//! nonce, then deterministic low-R grind — same as Core `CKey::Sign`),
//! low-s checked, `SIGHASH_ALL` only, self-verify after every signature.
//! No RNG on this path.

use bitcoin::bip32::Xpriv;
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::secp256k1::{ecdsa, Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{ecdsa as btc_ecdsa, Amount, PublicKey, Script, Transaction, Txid};
use trinity_types::Fingerprint;
use trinity_verify::{parse, VerifyPolicy};

use crate::error::SignError;
use crate::Signer;

/// Verify, then sign with key A. Crate-internal (Spec §1.3 / §3.3).
///
/// The independent verifier runs **before** [`Signer::sign`], so a rejected
/// PSBT never reaches `unwrap_kek` (S9).
pub(crate) fn sign_a<S: Signer>(
    signer: &S,
    psbt: Psbt,
    descriptor: &str,
    policy: &VerifyPolicy,
) -> Result<Psbt, SignError> {
    trinity_verify::verify(&psbt, descriptor, policy)?;
    signer.sign(psbt)
}

/// Verify, bind the unsigned txid from the A step, check A's signature,
/// then sign with key B. Crate-internal (Spec §3.3 run 3 / S10).
///
/// `unsigned_txid_at_a` is `psbt.unsigned_tx.compute_txid()` captured
/// **before** `sign_a`. Comparison is over that txid, not a re-hash of
/// outputs alone.
pub(crate) fn sign_b<S: Signer>(
    signer: &S,
    psbt: Psbt,
    unsigned_txid_at_a: Txid,
    descriptor: &str,
    policy: &VerifyPolicy,
) -> Result<Psbt, SignError> {
    trinity_verify::verify(&psbt, descriptor, policy)?;
    if psbt.unsigned_tx.compute_txid() != unsigned_txid_at_a {
        return Err(SignError::UnsignedTxChanged);
    }
    check_key_a_signatures(&psbt, descriptor)?;
    signer.sign(psbt)
}

/// Crate-visible A-then-B composition. FFI export of this function is WP-40.
///
/// Captures the unsigned txid **before** `sign_a` so the S10 check in
/// [`sign_b`] is meaningful.
pub fn sign_ab<A: Signer, B: Signer>(
    signer_a: &A,
    signer_b: &B,
    psbt: Psbt,
    descriptor: &str,
    policy: &VerifyPolicy,
) -> Result<Psbt, SignError> {
    let unsigned_txid = psbt.unsigned_tx.compute_txid();
    let after_a = sign_a(signer_a, psbt, descriptor, policy)?;
    sign_b(signer_b, after_a, unsigned_txid, descriptor, policy)
}

/// A's fingerprint is the first key expression (descriptor order A, B, C).
/// Every input must already carry a valid `SIGHASH_ALL` signature from that
/// pubkey over the current sighash.
pub(crate) fn check_key_a_signatures(psbt: &Psbt, descriptor: &str) -> Result<(), SignError> {
    let parsed = parse(descriptor).map_err(trinity_verify::VerifyError::from)?;
    let a_fp = parsed.keys[0].fingerprint;
    for (i, input) in psbt.inputs.iter().enumerate() {
        let pk = pubkey_for_fingerprint(input, a_fp).ok_or(SignError::UnexpectedKeyASignature)?;
        let sig = input
            .partial_sigs
            .get(&PublicKey::new(pk))
            .ok_or(SignError::UnexpectedKeyASignature)?;
        if sig.sighash_type != EcdsaSighashType::All {
            return Err(SignError::NonSighashAll { input_index: i });
        }
        let msg = sighash_message(&psbt.unsigned_tx, i, input)?;
        verify_own_signature(&msg, &sig.signature, &pk)?;
    }
    Ok(())
}

fn pubkey_for_fingerprint(
    input: &bitcoin::psbt::Input,
    fingerprint: Fingerprint,
) -> Option<SecpPublicKey> {
    let want = fingerprint.to_bytes();
    input.bip32_derivation.iter().find_map(|(pk, (fp, _))| {
        if *fp.as_bytes() == want {
            Some(*pk)
        } else {
            None
        }
    })
}

/// Structural PSBT checks that must pass **before** `unwrap_kek`.
pub(crate) fn preflight_inputs(psbt: &Psbt, fingerprint: Fingerprint) -> Result<(), SignError> {
    if psbt.inputs.is_empty() {
        return Err(SignError::EmptyPsbt);
    }
    let want = fingerprint.to_bytes();
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(sht) = input.sighash_type {
            if !sighash_is_all(sht) {
                return Err(SignError::NonSighashAll { input_index: i });
            }
        }
        for sig in input.partial_sigs.values() {
            if sig.sighash_type != EcdsaSighashType::All {
                return Err(SignError::NonSighashAll { input_index: i });
            }
        }
        if input.witness_utxo.is_none() {
            return Err(SignError::MissingWitnessUtxo { input_index: i });
        }
        if input.witness_script.is_none() {
            return Err(SignError::MissingWitnessScript { input_index: i });
        }
        let has_ours = input
            .bip32_derivation
            .iter()
            .any(|(_, (fp, _))| *fp.as_bytes() == want);
        if !has_ours {
            return Err(SignError::MissingDerivation { input_index: i });
        }
    }
    Ok(())
}

/// RFC-6979 ECDSA over the provided derived children.
///
/// Caller has already run [`preflight_inputs`] and unlocked the matching
/// `SecretKey` per input. Every `SecretKey` in `derived` is
/// [`erase_secret_key`]'d before this function returns, including on error.
pub(crate) fn sign_inputs(
    mut psbt: Psbt,
    derived: &mut [(usize, SecpPublicKey, SecretKey)],
) -> Result<Psbt, SignError> {
    let result = sign_inputs_inner(&mut psbt, derived);
    for (_, _, sk) in derived.iter_mut() {
        erase_secret_key(sk);
    }
    result.map(|()| psbt)
}

fn sign_inputs_inner(
    psbt: &mut Psbt,
    derived: &[(usize, SecpPublicKey, SecretKey)],
) -> Result<(), SignError> {
    let secp = Secp256k1::new();
    let mut produced: Vec<(usize, PublicKey, btc_ecdsa::Signature)> =
        Vec::with_capacity(derived.len());

    for (i, expected_pk, sk) in derived {
        let input = &psbt.inputs[*i];
        let msg = sighash_message(&psbt.unsigned_tx, *i, input)?;
        let sig = secp.sign_ecdsa_low_r(&msg, sk);
        reject_high_s(&sig)?;
        verify_own_signature(&msg, &sig, expected_pk)?;
        produced.push((
            *i,
            PublicKey::new(*expected_pk),
            btc_ecdsa::Signature::sighash_all(sig),
        ));
    }

    for (i, pk, sig) in produced {
        psbt.inputs[i].partial_sigs.insert(pk, sig);
        psbt.inputs[i].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
    }
    Ok(())
}

/// Best-effort wipe of a [`SecretKey`].
///
/// `secp256k1 0.29.1::SecretKey` is `Copy` and does **not** implement
/// [`zeroize::Zeroize`] (no `Zeroize` impl exists on that crate at this
/// pin — confirmed in `vendor/secp256k1`). `Zeroizing<SecretKey>` therefore
/// does not compile. The only hook is [`SecretKey::non_secure_erase`],
/// which overwrites the 32 bytes with `0x01` (not zero) via a volatile
/// write. The compiler may have copied the key elsewhere first; this is
/// best-effort, as the method's own docs state.
pub(crate) fn erase_secret_key(sk: &mut SecretKey) {
    sk.non_secure_erase();
}

/// Best-effort wipe of an [`Xpriv`]'s secret scalar and chain code.
///
/// `bitcoin 0.32.11::bip32::Xpriv` is `Copy` and has no zeroize code at
/// all. `Copy` and `Drop` are mutually exclusive, so it can never grow
/// `ZeroizeOnDrop` while it stays `Copy`. The scalar is overwritten via
/// [`SecretKey::non_secure_erase`] (`0x01`). `chain_code` has no such
/// hook; it is replaced with `[1u8; 32]` (same fill, via `From` — this
/// pin has no `ChainCode::from_byte_array`).
pub(crate) fn erase_xpriv(xpriv: &mut Xpriv) {
    xpriv.private_key.non_secure_erase();
    xpriv.chain_code = bitcoin::bip32::ChainCode::from([1u8; 32]);
}

pub(crate) fn sighash_is_all(sht: PsbtSighashType) -> bool {
    match sht.ecdsa_hash_ty() {
        Ok(EcdsaSighashType::All) => true,
        Ok(_) => false,
        Err(_) => false,
    }
}

pub(crate) fn sighash_message(
    tx: &Transaction,
    input_index: usize,
    input: &bitcoin::psbt::Input,
) -> Result<Message, SignError> {
    let utxo = input
        .witness_utxo
        .as_ref()
        .ok_or(SignError::MissingWitnessUtxo { input_index })?;
    let script = input
        .witness_script
        .as_ref()
        .ok_or(SignError::MissingWitnessScript { input_index })?;
    p2wsh_sighash(tx, input_index, script.as_script(), utxo.value)
}

pub(crate) fn p2wsh_sighash(
    tx: &Transaction,
    input_index: usize,
    witness_script: &Script,
    value: Amount,
) -> Result<Message, SignError> {
    let mut cache = SighashCache::new(tx);
    let hash = cache
        .p2wsh_signature_hash(input_index, witness_script, value, EcdsaSighashType::All)
        .map_err(|_| SignError::Sighash { input_index })?;
    Ok(Message::from_digest(hash.to_byte_array()))
}

pub(crate) fn reject_high_s(sig: &ecdsa::Signature) -> Result<(), SignError> {
    let mut normalized = *sig;
    normalized.normalize_s();
    if normalized != *sig {
        return Err(SignError::SelfVerificationFailed);
    }
    Ok(())
}

pub(crate) fn verify_own_signature(
    msg: &Message,
    sig: &ecdsa::Signature,
    pk: &SecpPublicKey,
) -> Result<(), SignError> {
    let secp = Secp256k1::verification_only();
    secp.verify_ecdsa(msg, sig, pk)
        .map_err(|_| SignError::SelfVerificationFailed)
}

pub(crate) fn map_bip32<T>(result: Result<T, bitcoin::bip32::Error>) -> Result<T, SignError> {
    result.map_err(|_| SignError::Bip32)
}

pub(crate) fn seed_from_entropy(entropy: &[u8]) -> Result<trinity_types::SecretBytes, SignError> {
    let material = trinity_entropy::bip39_from_entropy(entropy).map_err(|_| SignError::Entropy)?;
    Ok(trinity_types::SecretBytes::from_slice(
        material.seed.as_slice(),
    ))
}

#[cfg(test)]
mod helper_tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::transaction::Version;
    use bitcoin::{ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use core::str::FromStr;

    #[test]
    fn sighash_is_all_accepts_only_all() {
        assert!(sighash_is_all(PsbtSighashType::from(EcdsaSighashType::All)));
        assert!(!sighash_is_all(PsbtSighashType::from(
            EcdsaSighashType::None
        )));
        assert!(!sighash_is_all(PsbtSighashType::from(
            EcdsaSighashType::Single
        )));
        assert!(!sighash_is_all(PsbtSighashType::from(
            EcdsaSighashType::AllPlusAnyoneCanPay
        )));
        assert!(!sighash_is_all(PsbtSighashType::from_u32(0xFF)));
    }

    #[test]
    fn p2wsh_sighash_rejects_out_of_range_index() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let err =
            p2wsh_sighash(&tx, 0, ScriptBuf::new().as_script(), Amount::from_sat(1)).unwrap_err();
        assert_eq!(err, SignError::Sighash { input_index: 0 });
    }

    #[test]
    fn verify_own_signature_rejects_wrong_key() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk = SecpPublicKey::from_secret_key(&secp, &sk);
        let other = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_pk = SecpPublicKey::from_secret_key(&secp, &other);
        let msg = Message::from_digest([3u8; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);
        verify_own_signature(&msg, &sig, &pk).unwrap();
        assert_eq!(
            verify_own_signature(&msg, &sig, &other_pk).unwrap_err(),
            SignError::SelfVerificationFailed
        );
    }

    #[test]
    fn seed_from_entropy_rejects_bad_length() {
        assert_eq!(
            seed_from_entropy(&[0u8; 15]).unwrap_err(),
            SignError::Entropy
        );
        assert!(seed_from_entropy(&[0u8; 16]).is_ok());
        assert!(seed_from_entropy(&[0u8; 32]).is_ok());
    }

    #[test]
    fn map_bip32_maps_error() {
        let err = bitcoin::bip32::Xpriv::from_str("not-an-xprv").expect_err("malformed");
        assert_eq!(map_bip32::<()>(Err(err)).unwrap_err(), SignError::Bip32);
    }

    #[test]
    fn non_secure_erase_overwrites_secret_key_bytes() {
        // secp256k1 0.29.1 fills with 0x01, not 0x00. Start from a
        // different scalar so the call is observable.
        let mut sk = SecretKey::from_slice(&[0xAAu8; 32]).unwrap();
        let before = sk.secret_bytes();
        assert_ne!(before, [1u8; 32]);
        erase_secret_key(&mut sk);
        let after = sk.secret_bytes();
        assert_ne!(before, after);
        assert_eq!(after, [1u8; 32]);
    }

    #[test]
    fn non_secure_erase_overwrites_xpriv_private_key() {
        let seed = [0x5Au8; 64];
        let mut xpriv = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed).unwrap();
        let before = xpriv.private_key.secret_bytes();
        assert_ne!(before, [1u8; 32]);
        erase_xpriv(&mut xpriv);
        let after = xpriv.private_key.secret_bytes();
        assert_ne!(before, after);
        assert_eq!(after, [1u8; 32]);
    }

    #[test]
    fn erase_xpriv_overwrites_chain_code() {
        let seed = [0x5Au8; 64];
        let mut xpriv = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed).unwrap();
        let before = xpriv.chain_code.to_bytes();
        assert_ne!(before, [1u8; 32]);
        erase_xpriv(&mut xpriv);
        let after = xpriv.chain_code.to_bytes();
        assert_ne!(before, after);
        assert_eq!(after, [1u8; 32]);
    }

    #[test]
    fn reject_high_s_detects_high_s() {
        let high_der = vec![
            0x30, 0x46, 0x02, 0x21, 0x00, 0x83, 0x9c, 0x1f, 0xbc, 0x53, 0x04, 0xde, 0x94, 0x4f,
            0x69, 0x7c, 0x9f, 0x4b, 0x1d, 0x01, 0xd1, 0xfa, 0xeb, 0xa3, 0x2d, 0x75, 0x1c, 0x0f,
            0x7a, 0xcb, 0x21, 0xac, 0x8a, 0x0f, 0x43, 0x6a, 0x72, 0x02, 0x21, 0x00, 0xe8, 0x9b,
            0xd4, 0x6b, 0xb3, 0xa5, 0xa6, 0x2a, 0xdc, 0x67, 0x9f, 0x65, 0x9b, 0x7c, 0xe8, 0x76,
            0xd8, 0x3e, 0xe2, 0x97, 0xc7, 0xa5, 0x58, 0x7b, 0x20, 0x11, 0xc4, 0xfc, 0xc7, 0x2e,
            0xab, 0x45,
        ];
        let high = ecdsa::Signature::from_der(&high_der).unwrap();
        assert_eq!(
            reject_high_s(&high).unwrap_err(),
            SignError::SelfVerificationFailed
        );
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let msg = Message::from_digest([9u8; 32]);
        let low = secp.sign_ecdsa(&msg, &sk);
        reject_high_s(&low).unwrap();
    }

    #[test]
    fn sighash_message_requires_utxo_and_script() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![],
        };
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert_eq!(
            sighash_message(&psbt.unsigned_tx, 0, &psbt.inputs[0]).unwrap_err(),
            SignError::MissingWitnessUtxo { input_index: 0 }
        );
        let mut psbt = psbt;
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        });
        assert_eq!(
            sighash_message(&psbt.unsigned_tx, 0, &psbt.inputs[0]).unwrap_err(),
            SignError::MissingWitnessScript { input_index: 0 }
        );
    }

    #[test]
    fn preflight_empty_psbt() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert_eq!(
            preflight_inputs(&psbt, Fingerprint::new([0; 4])).unwrap_err(),
            SignError::EmptyPsbt
        );
    }

    #[test]
    fn preflight_missing_fields() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let fp = Fingerprint::new([1, 2, 3, 4]);
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert_eq!(
            preflight_inputs(&psbt, fp).unwrap_err(),
            SignError::MissingWitnessUtxo { input_index: 0 }
        );
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(2),
            script_pubkey: ScriptBuf::new(),
        });
        assert_eq!(
            preflight_inputs(&psbt, fp).unwrap_err(),
            SignError::MissingWitnessScript { input_index: 0 }
        );
        psbt.inputs[0].witness_script = Some(ScriptBuf::new());
        assert_eq!(
            preflight_inputs(&psbt, fp).unwrap_err(),
            SignError::MissingDerivation { input_index: 0 }
        );
    }
}
