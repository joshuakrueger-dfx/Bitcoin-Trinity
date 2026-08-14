//! Independent PSBT verification — checks V1–V10 (Spec §1.5, §3.3).
//!
//! ```text
//! verify(psbt, descriptor, policy) → Result<PsbtVerdict, VerifyError>
//! ```
//!
//! Call sites (display via `verify_psbt`, and before each of the two internal
//! signature steps in `sign_ab` / `sign_ab_with_passphrase`) are WP-33+; this
//! module only provides the pure check function those layers will call.
//!
//! **Independence:** descriptor parse, BIP-32 CKD, BIP-67 sort, and
//! witnessScript construction use this crate's own code (WP-20/WP-21). PSBT
//! deserialization is the shared `bitcoin::psbt` layer (Spec §1.5 table).
//!
//! **V10 scope:** when a partial signature is already present, validate low-s
//! (BIP-62) and `SIGHASH_ALL`. No key access, no re-signing, no determinism
//! re-derivation (signer self-test is §3.4 / WP-33–36). Inputs without a
//! signature simply skip the V10 body for that input.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, KeySource};
use bitcoin::psbt::{Output, Psbt, PsbtSighashType};
use bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{Address, Network, ScriptBuf};
use trinity_types::PsbtVerdict;

use crate::derive;
use crate::error::VerifyError;
use crate::parse;
use crate::policy::VerifyPolicy;
use crate::types::{KeyExpr, ParsedDescriptor};

/// Hard upper bound on PSBT input count (and separately on output count).
///
/// Checked in V8 **before** any gap-window derivation (V2/V3). Trinity is a
/// personal 2-of-3 wallet: even aggressive consolidations stay far below a
/// few dozen UTXOs. **100** is generous for any realistic send while still
/// bounding worst-case CKD cost (`inputs × gap_limit` HMAC+EC steps) on a
/// phone battery. Not a consensus rule — a local resource guard.
pub const MAX_PSBT_INS_OR_OUTS: usize = 100;

/// Result of classifying one transaction output under V3/V4.
#[derive(Clone, Debug)]
struct ClassifiedOutput {
    is_change: bool,
    amount_sats: u64,
    address: String,
}

/// Verify a PSBT against a Trinity descriptor and policy (Spec §1.5).
///
/// `descriptor` is typically the receive (`/0/*`) string. Change reconstruction
/// uses [`VerifyPolicy::change_descriptor`] when present.
pub fn verify(
    psbt: &Psbt,
    descriptor: &str,
    policy: &VerifyPolicy,
) -> Result<PsbtVerdict, VerifyError> {
    // --- V1: descriptor checksum + grammar ---
    let receive = parse::parse(descriptor)?;
    let change = match policy.change_descriptor.as_deref() {
        Some(s) => Some(parse::parse(s)?),
        None => None,
    };

    // --- V8: structure / proprietary ---
    check_v8(psbt)?;

    // --- V9: witness_utxo required ---
    check_v9(psbt)?;

    // --- V7: known outpoints ---
    check_v7(psbt, policy)?;

    // --- V2: reconstruct each input script_pubkey ---
    check_v2(psbt, &receive, change.as_ref(), policy)?;

    // --- V3 + V4: classify every output ---
    let classified = classify_outputs(psbt, change.as_ref(), policy)?;

    // --- V5: fee and feerate caps ---
    let (fee_sats, feerate_sat_vb) = check_v5(psbt, policy)?;

    // --- V6: non-change sum bit-exact ---
    check_v6(&classified, policy)?;

    // --- V10 + P11: present signatures / sighash ---
    check_v10(psbt)?;

    // Build verdict from classified outputs.
    let mut amount_sats = 0u64;
    let mut change_sats = 0u64;
    let mut recipient = String::new();
    for c in &classified {
        if c.is_change {
            change_sats = change_sats.saturating_add(c.amount_sats);
        } else {
            amount_sats = amount_sats.saturating_add(c.amount_sats);
            if recipient.is_empty() {
                recipient = c.address.clone();
            }
        }
    }
    // Display uses the caller's declared recipient string (UI casing) when present.
    if let Some(decl) = policy.declared_recipients.first() {
        recipient = decl.clone();
    }

    Ok(PsbtVerdict::new(
        true,
        recipient,
        amount_sats,
        change_sats,
        fee_sats,
        feerate_sat_vb,
    ))
}

/// Exported entry: base64 PSBT string → verdict (Spec §1.3 `verify_psbt`).
///
/// Deserialization is the shared `bitcoin::psbt` layer. The three runtime call
/// sites from §3.3 are not wired here (signer / UI WPs).
pub fn verify_psbt(
    psbt_b64: &str,
    descriptor: &str,
    policy: &VerifyPolicy,
) -> Result<PsbtVerdict, VerifyError> {
    let psbt = Psbt::from_str(psbt_b64).map_err(|_| VerifyError::PsbtDecode)?;
    verify(&psbt, descriptor, policy)
}

// ---------------------------------------------------------------------------
// V8
// ---------------------------------------------------------------------------

fn check_v8(psbt: &Psbt) -> Result<(), VerifyError> {
    if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err(VerifyError::InconsistentPsbt {
            detail: "input map length ≠ unsigned_tx.input length",
        });
    }
    if psbt.outputs.len() != psbt.unsigned_tx.output.len() {
        return Err(VerifyError::InconsistentPsbt {
            detail: "output map length ≠ unsigned_tx.output length",
        });
    }
    if psbt.unsigned_tx.input.is_empty() {
        return Err(VerifyError::InconsistentPsbt {
            detail: "unsigned_tx has no inputs",
        });
    }
    // Resource bound before any gap-window CKD (V2/V3).
    if psbt.unsigned_tx.input.len() > MAX_PSBT_INS_OR_OUTS {
        return Err(VerifyError::TooManyInputsOutputs {
            detail: "input count exceeds MAX_PSBT_INS_OR_OUTS",
        });
    }
    if psbt.unsigned_tx.output.len() > MAX_PSBT_INS_OR_OUTS {
        return Err(VerifyError::TooManyInputsOutputs {
            detail: "output count exceeds MAX_PSBT_INS_OR_OUTS",
        });
    }
    for txin in &psbt.unsigned_tx.input {
        if !txin.script_sig.is_empty() {
            return Err(VerifyError::InconsistentPsbt {
                detail: "unsigned_tx input has non-empty script_sig",
            });
        }
        if !txin.witness.is_empty() {
            return Err(VerifyError::InconsistentPsbt {
                detail: "unsigned_tx input has non-empty witness",
            });
        }
    }
    if !psbt.proprietary.is_empty() {
        return Err(VerifyError::ProprietaryField);
    }
    for input in &psbt.inputs {
        if !input.proprietary.is_empty() {
            return Err(VerifyError::ProprietaryField);
        }
    }
    for output in &psbt.outputs {
        if !output.proprietary.is_empty() {
            return Err(VerifyError::ProprietaryField);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// V9
// ---------------------------------------------------------------------------

fn check_v9(psbt: &Psbt) -> Result<(), VerifyError> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        match (&input.witness_utxo, &input.non_witness_utxo) {
            (Some(_), _) => {}
            (None, Some(_)) => {
                return Err(VerifyError::NonWitnessUtxoOnly { input_index: i });
            }
            (None, None) => {
                return Err(VerifyError::MissingWitnessUtxo { input_index: i });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// V7
// ---------------------------------------------------------------------------

fn check_v7(psbt: &Psbt, policy: &VerifyPolicy) -> Result<(), VerifyError> {
    for (i, (txin, psbt_in)) in psbt
        .unsigned_tx
        .input
        .iter()
        .zip(psbt.inputs.iter())
        .enumerate()
    {
        let known = policy
            .known_utxos
            .get(&txin.previous_output)
            .ok_or(VerifyError::UnknownInput { input_index: i })?;
        let utxo = psbt_in
            .witness_utxo
            .as_ref()
            .expect("V9 already required witness_utxo");
        // Byte-for-byte: value and script_pubkey must match the watch-only record.
        if utxo.value != known.value || utxo.script_pubkey != known.script_pubkey {
            return Err(VerifyError::MismatchedUtxo { input_index: i });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// V2
// ---------------------------------------------------------------------------

fn check_v2(
    psbt: &Psbt,
    receive: &ParsedDescriptor,
    change: Option<&ParsedDescriptor>,
    policy: &VerifyPolicy,
) -> Result<(), VerifyError> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .expect("V9 already required witness_utxo");
        if !matches_any_derived(
            &utxo.script_pubkey,
            receive,
            change,
            policy.gap_limit,
            bip32_index_hint(&input.bip32_derivation),
        )? {
            return Err(VerifyError::ForeignInput { input_index: i });
        }
    }
    Ok(())
}

fn matches_any_derived(
    script_pubkey: &ScriptBuf,
    receive: &ParsedDescriptor,
    change: Option<&ParsedDescriptor>,
    gap_limit: u32,
    hint: Option<u32>,
) -> Result<bool, VerifyError> {
    if find_index_matching(script_pubkey, receive, gap_limit, hint)?.is_some() {
        return Ok(true);
    }
    match change {
        Some(chg) => Ok(find_index_matching(script_pubkey, chg, gap_limit, hint)?.is_some()),
        None => Ok(false),
    }
}

/// Last normal child of every `bip32_derivation` path, if they all agree.
///
/// Trinity PSBTs carry `…/{0|1}/{index}` on every key. Trying that index
/// first makes V2/V3 O(1) instead of O(index) when `gap_limit` is large
/// (D7/D8 use 1_000). A missing or disagreeing map falls back to the scan.
fn bip32_index_hint(derivation: &BTreeMap<SecpPublicKey, KeySource>) -> Option<u32> {
    let mut hint = None;
    for (_, path) in derivation.values() {
        let last = path.into_iter().last()?;
        let idx = match last {
            bitcoin::bip32::ChildNumber::Normal { index } => *index,
            bitcoin::bip32::ChildNumber::Hardened { .. } => return None,
        };
        match hint {
            None => hint = Some(idx),
            Some(h) if h != idx => return None,
            Some(_) => {}
        }
    }
    hint.filter(|_| !derivation.is_empty())
}

fn find_index_matching(
    script_pubkey: &ScriptBuf,
    descriptor: &ParsedDescriptor,
    gap_limit: u32,
    hint: Option<u32>,
) -> Result<Option<u32>, VerifyError> {
    if let Some(h) = hint {
        if h < gap_limit {
            let derived = derive::derive_at(descriptor, h)?;
            if derived.script_pubkey == *script_pubkey {
                return Ok(Some(h));
            }
        }
    }
    for i in 0..gap_limit {
        if hint == Some(i) {
            continue;
        }
        let derived = derive::derive_at(descriptor, i)?;
        if derived.script_pubkey == *script_pubkey {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// V3 + V4
// ---------------------------------------------------------------------------

fn classify_outputs(
    psbt: &Psbt,
    change: Option<&ParsedDescriptor>,
    policy: &VerifyPolicy,
) -> Result<Vec<ClassifiedOutput>, VerifyError> {
    let mut out = Vec::with_capacity(psbt.unsigned_tx.output.len());
    for (i, txout) in psbt.unsigned_tx.output.iter().enumerate() {
        let address = address_from_script(&txout.script_pubkey, policy.network, i)?;
        let is_declared = policy
            .declared_recipients
            .iter()
            .any(|r| addresses_equal(&address, r));

        if is_declared {
            out.push(ClassifiedOutput {
                is_change: false,
                amount_sats: txout.value.to_sat(),
                address,
            });
            continue;
        }

        // Not a declared recipient → must be change in the gap window (V3).
        let chg = change.ok_or(VerifyError::ForeignChangeOutput { output_index: i })?;
        let hint = bip32_index_hint(&psbt.outputs[i].bip32_derivation);
        let idx = find_index_matching(&txout.script_pubkey, chg, policy.gap_limit, hint)?
            .ok_or(VerifyError::ForeignChangeOutput { output_index: i })?;

        // V4 on this change output. V8 already equalised map vs unsigned_tx lengths.
        check_v4_change(&psbt.outputs[i], chg, idx, &txout.script_pubkey)
            .map_err(|_| VerifyError::MismatchedDerivation { output_index: i })?;

        out.push(ClassifiedOutput {
            is_change: true,
            amount_sats: txout.value.to_sat(),
            address,
        });
    }
    Ok(out)
}

/// V4: bip32_derivation has all three fingerprints, paths `…/1/i`, and the
/// independently derived pubkeys match the change output's keys.
fn check_v4_change(
    output: &Output,
    change_desc: &ParsedDescriptor,
    index: u32,
    _script_pubkey: &ScriptBuf,
) -> Result<(), ()> {
    // `index` was found by matching `script_pubkey` via `derive_at`, so the
    // independent reconstruction already locks the SPK. V4 checks the PSBT's
    // bip32_derivation map against that same derivation.
    let derived = derive::derive_at(change_desc, index).map_err(|_| ())?;

    let expected_fps: BTreeSet<[u8; 4]> = change_desc
        .keys
        .iter()
        .map(|k| *k.fingerprint.as_bytes())
        .collect();
    if output.bip32_derivation.len() != 3 {
        return Err(());
    }

    let mut seen_fps = BTreeSet::new();
    let mut map_pubkeys_vec: Vec<[u8; 33]> = Vec::with_capacity(3);

    for (pk, (fp, path)) in &output.bip32_derivation {
        let fp_bytes = *fp.as_bytes();
        if !seen_fps.insert(fp_bytes) {
            return Err(());
        }
        // Bind this entry's fingerprint to *its own* KeyExpr origin_path —
        // not "any of the three" origins (heterogeneous origins are legal
        // under the WP-20 grammar).
        let resolve_key = key_expr_for_fingerprint;
        let key = resolve_key(change_desc, &fp_bytes).ok_or(())?;
        if !path_is_change_at(path, key, index) {
            return Err(());
        }
        map_pubkeys_vec.push(pk.serialize());
    }
    // Loop already enforces: three unique fingerprints, each bound to its own
    // KeyExpr and path. Silence unused after the insert side-effects.
    let _ = (seen_fps, expected_fps);

    let derived_set: BTreeSet<[u8; 33]> = derived.children.iter().map(|c| c.public_key).collect();
    let map_set: BTreeSet<[u8; 33]> = map_pubkeys_vec.iter().copied().collect();
    if derived_set != map_set {
        return Err(());
    }
    // BIP-67 sort is deterministic over the key set (exercises sort path).
    let three = [map_pubkeys_vec[0], map_pubkeys_vec[1], map_pubkeys_vec[2]];
    let _sorted = crate::bip67::sort_three(three);
    Ok(())
}

fn key_expr_for_fingerprint<'a>(
    desc: &'a ParsedDescriptor,
    fp_bytes: &[u8; 4],
) -> Option<&'a KeyExpr> {
    desc.keys
        .iter()
        .find(|k| k.fingerprint.as_bytes() == fp_bytes)
}

/// Path must be `m/{this key's origin}/1/{index}` (change branch).
fn path_is_change_at(path: &DerivationPath, key: &KeyExpr, index: u32) -> bool {
    if path.len() != 6 {
        return false;
    }
    match (path[4], path[5]) {
        (
            bitcoin::bip32::ChildNumber::Normal { index: 1 },
            bitcoin::bip32::ChildNumber::Normal { index: idx },
        ) if idx == index => {}
        _ => return false,
    }
    origin_matches_prefix(path, &key.origin_path)
}

fn origin_matches_prefix(path: &DerivationPath, origin_path: &str) -> bool {
    // Origin paths always come from a successful parse (`48'/{0|1}'/0'/2'`).
    let origin: DerivationPath = format!("m/{origin_path}")
        .parse()
        .expect("origin_path is parser-validated BIP-48");
    debug_assert_eq!(origin.len(), 4);
    (0..4).all(|i| path[i] == origin[i])
}

fn address_from_script(
    script: &ScriptBuf,
    network: Network,
    output_index: usize,
) -> Result<String, VerifyError> {
    Address::from_script(script.as_script(), network)
        .map(|a| a.to_string())
        .map_err(|_| VerifyError::InvalidOutputAddress { output_index })
}

fn addresses_equal(a: &str, b: &str) -> bool {
    // Bech32 is case-insensitive per BIP-173.
    a.eq_ignore_ascii_case(b)
}

// ---------------------------------------------------------------------------
// V5
// ---------------------------------------------------------------------------

fn check_v5(psbt: &Psbt, policy: &VerifyPolicy) -> Result<(u64, u64), VerifyError> {
    let mut sum_in: u64 = 0;
    for input in &psbt.inputs {
        let utxo = input
            .witness_utxo
            .as_ref()
            .expect("V9 already required witness_utxo");
        sum_in = sum_in
            .checked_add(utxo.value.to_sat())
            .ok_or(VerifyError::FeeNonPositive)?;
    }
    let mut sum_out: u64 = 0;
    for txout in &psbt.unsigned_tx.output {
        sum_out = sum_out
            .checked_add(txout.value.to_sat())
            .ok_or(VerifyError::FeeNonPositive)?;
    }
    let fee_sats = sum_in
        .checked_sub(sum_out)
        .ok_or(VerifyError::FeeNonPositive)?;
    if fee_sats == 0 {
        return Err(VerifyError::FeeNonPositive);
    }
    if fee_sats > policy.max_absolute_fee {
        return Err(VerifyError::FeeTooHigh {
            fee_sats,
            max_sats: policy.max_absolute_fee,
        });
    }
    // Pin fee to a prior display-run value when the caller supplies one (P2).
    if let Some(expected) = policy.declared_fee_sats {
        if fee_sats != expected {
            return Err(VerifyError::FeeMismatch {
                actual_sats: fee_sats,
                expected_sats: expected,
            });
        }
    }

    // Feerate over the unsigned transaction's vsize (empty witnesses).
    // Underestimating vsize overestimates feerate → fail-closed.
    // vsize is always ≥ 1 for a transaction that passed V8 (has inputs).
    let vsize = (psbt.unsigned_tx.vsize() as u64).max(1);
    let feerate_sat_vb = fee_sats.div_ceil(vsize);
    if feerate_sat_vb > policy.max_feerate {
        return Err(VerifyError::FeerateTooHigh {
            feerate_sat_vb,
            max_sat_vb: policy.max_feerate,
        });
    }
    Ok((fee_sats, feerate_sat_vb))
}

// ---------------------------------------------------------------------------
// V6
// ---------------------------------------------------------------------------

fn check_v6(classified: &[ClassifiedOutput], policy: &VerifyPolicy) -> Result<(), VerifyError> {
    // Amounts already passed V5 (sum_out ≤ sum_in ≤ u64 without overflow on the
    // fee path), so saturating add is fine and keeps this branch free of a
    // hard-to-trigger overflow arm.
    let actual: u64 = classified
        .iter()
        .filter(|c| !c.is_change)
        .map(|c| c.amount_sats)
        .fold(0u64, |a, b| a.saturating_add(b));
    if actual != policy.declared_amount_sats {
        return Err(VerifyError::AmountMismatch {
            actual_sats: actual,
            expected_sats: policy.declared_amount_sats,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// V10 + P11
// ---------------------------------------------------------------------------

fn check_v10(psbt: &Psbt) -> Result<(), VerifyError> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        // P11: explicit sighash_type field, when present, must be ALL.
        if let Some(sht) = input.sighash_type {
            if !is_sighash_all(sht) {
                return Err(VerifyError::NonSighashAll { input_index: i });
            }
        }
        for sig in input.partial_sigs.values() {
            if sig.sighash_type != EcdsaSighashType::All {
                return Err(VerifyError::NonSighashAll { input_index: i });
            }
            // Low-s: normalize_s must be a no-op.
            let mut normalized = sig.signature;
            normalized.normalize_s();
            if normalized != sig.signature {
                return Err(VerifyError::BadSignature { input_index: i });
            }
        }
    }
    Ok(())
}

fn is_sighash_all(sht: PsbtSighashType) -> bool {
    match sht.ecdsa_hash_ty() {
        Ok(EcdsaSighashType::All) => true,
        Ok(_) => false,
        Err(_) => false,
    }
}
