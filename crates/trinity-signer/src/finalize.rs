//! Finalize a twice-signed PSBT into a broadcastable transaction (Spec §3.5).
//!
//! Witness stack is `OP_0 <sig> <sig> <witnessScript>` with signatures in
//! **BIP-67 pubkey order** (`DerivedOutput::sorted_pubkeys_slice`), not the
//! order the keys signed. Before any `witness_utxo` is used for the spent
//! map or the fee, it is checked against [`VerifyPolicy::known_utxos`] with
//! the same semantics as V7 (outpoint present **and** value/script
//! byte-for-byte). The finished transaction is then checked with
//! `bitcoin::Transaction::verify` (`bitcoinconsensus`, O7) and the exact
//! vsize feerate is compared to [`VerifyPolicy::max_feerate`]. The
//! `bitcoinconsensus` crate feature is on by default; without it
//! `Transaction::verify` does not compile.

use std::collections::BTreeMap;

use bitcoin::bip32::ChildNumber;
use bitcoin::psbt::Psbt;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{Transaction, Witness};
use trinity_verify::{
    derive_at, parse, witness_script_2of3, DerivedOutput, ParsedDescriptor, VerifyError,
    VerifyPolicy,
};

use crate::error::SignError;

/// Build the finished transaction from a twice-signed PSBT.
///
/// `descriptor` is the receive descriptor. Change-chain inputs use
/// [`VerifyPolicy::change_descriptor`]. Nothing is sent here; broadcast
/// belongs on the facade, with a separately configurable backend
/// (Spec §1.6: same path as sync is the strongest linkage).
pub fn finalize(
    psbt: &Psbt,
    descriptor: &str,
    policy: &VerifyPolicy,
) -> Result<Transaction, SignError> {
    if psbt.inputs.is_empty() {
        return Err(SignError::EmptyPsbt);
    }
    if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err(SignError::Verify(VerifyError::InconsistentPsbt {
            detail: "input count",
        }));
    }

    let receive = parse(descriptor).map_err(VerifyError::from)?;
    let change = match policy.change_descriptor.as_deref() {
        Some(s) => Some(parse(s).map_err(VerifyError::from)?),
        None => None,
    };

    let mut spent = BTreeMap::new();
    let mut finished = psbt.clone();
    for (i, input) in psbt.inputs.iter().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or(SignError::MissingWitnessUtxo { input_index: i })?;
        // V7 (`trinity_verify::verify` `check_v7`): outpoint must be in
        // `known_utxos`, and `witness_utxo` must match that record
        // byte-for-byte. Empty `known_utxos` is UnknownInput, not a skip.
        let prevout = psbt.unsigned_tx.input[i].previous_output;
        let known = policy
            .known_utxos
            .get(&prevout)
            .ok_or(VerifyError::UnknownInput { input_index: i })?;
        if utxo.value != known.value || utxo.script_pubkey != known.script_pubkey {
            return Err(VerifyError::MismatchedUtxo { input_index: i }.into());
        }
        spent.insert(prevout, known.clone());

        let derived = derived_for_input(input, i, &receive, change.as_ref())?;
        if utxo.script_pubkey != derived.script_pubkey {
            return Err(SignError::WitnessScriptMismatch { input_index: i });
        }
        let sorted = derived.sorted_pubkeys_slice();
        let script = witness_script_2of3(sorted).unwrap_or(derived.witness_script.clone());
        match input.witness_script.as_ref() {
            Some(ws) if *ws == script => {}
            Some(_) => return Err(SignError::WitnessScriptMismatch { input_index: i }),
            None => return Err(SignError::MissingWitnessScript { input_index: i }),
        }
        finished.inputs[i].final_script_witness =
            Some(witness_for_sorted(input, i, sorted, &script)?);
    }

    let fee_sats = psbt.fee().map_err(|_| SignError::UnbalancedPsbt)?.to_sat();
    if fee_sats == 0 {
        return Err(SignError::UnbalancedPsbt);
    }

    let tx = finished.extract_tx_unchecked_fee_rate();

    tx.verify(|op| spent.remove(op))
        .map_err(|_| SignError::ConsensusRejected)?;

    let vsize = tx.vsize() as u64;
    let feerate_sat_vb = fee_sats.div_ceil(vsize);
    if feerate_sat_vb > policy.max_feerate {
        return Err(SignError::FinalFeerateTooHigh {
            feerate_sat_vb,
            max_sat_vb: policy.max_feerate,
        });
    }
    Ok(tx)
}

fn derived_for_input(
    input: &bitcoin::psbt::Input,
    input_index: usize,
    receive: &ParsedDescriptor,
    change: Option<&ParsedDescriptor>,
) -> Result<DerivedOutput, SignError> {
    let (branch, index) = branch_and_index(input, input_index)?;
    let descriptor = if branch == 0 {
        receive
    } else {
        change.ok_or(SignError::InvalidDerivationPath { input_index })?
    };
    Ok(derive_at(descriptor, index)
        .expect("non-hardened Trinity receive/change index always derives"))
}

fn branch_and_index(
    input: &bitcoin::psbt::Input,
    input_index: usize,
) -> Result<(u32, u32), SignError> {
    let (_, path) = input
        .bip32_derivation
        .values()
        .next()
        .ok_or(SignError::MissingDerivation { input_index })?;
    let n = path.len();
    if n < 2 {
        return Err(SignError::InvalidDerivationPath { input_index });
    }
    let branch = match path[n - 2] {
        ChildNumber::Normal { index } => index,
        ChildNumber::Hardened { .. } => {
            return Err(SignError::InvalidDerivationPath { input_index })
        }
    };
    let addr = match path[n - 1] {
        ChildNumber::Normal { index } => index,
        ChildNumber::Hardened { .. } => {
            return Err(SignError::InvalidDerivationPath { input_index })
        }
    };
    if branch > 1 {
        return Err(SignError::InvalidDerivationPath { input_index });
    }
    Ok((branch, addr))
}

/// `OP_0 <sig…> <witnessScript>` — at most two signatures, BIP-67 key order.
fn witness_for_sorted(
    input: &bitcoin::psbt::Input,
    input_index: usize,
    sorted: &[[u8; 33]; 3],
    script: &bitcoin::ScriptBuf,
) -> Result<Witness, SignError> {
    let mut sigs = Vec::with_capacity(2);
    for pk_bytes in sorted {
        let sig = input.partial_sigs.iter().find_map(|(pk, sig)| {
            if pk.inner.serialize() == *pk_bytes {
                Some(sig)
            } else {
                None
            }
        });
        if let Some(sig) = sig {
            if sig.sighash_type != EcdsaSighashType::All {
                return Err(SignError::NonSighashAll { input_index });
            }
            sigs.push(sig);
            if sigs.len() == 2 {
                break;
            }
        }
    }
    if sigs.len() < 2 {
        return Err(SignError::IncompleteWitness { input_index });
    }
    let mut witness = Witness::new();
    witness.push([]);
    witness.push_ecdsa_signature(sigs[0]);
    witness.push_ecdsa_signature(sigs[1]);
    witness.push(script.as_bytes());
    Ok(witness)
}
