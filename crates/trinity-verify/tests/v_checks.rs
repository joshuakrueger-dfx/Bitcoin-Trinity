//! V1–V10 positive/negative checks and property tests P1, P2, P3, P11, P12.
//!
//! Mutation probes exercise the real [`trinity_verify::verify`] path with a
//! mutated PSBT or policy — never a parallel reimplementation of the check.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint as BtcFingerprint, KeySource};
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
// Re-exports used by edge-case tests below.
use proptest::prelude::*;
use trinity_verify::{
    derive_at, parse, DerivationBranch, ParsedDescriptor, VerifyError, VerifyPolicy,
};

const RECEIVE: &str = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*\
))#ttrgvxfp";

const CHANGE: &str = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/1/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/1/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/1/*\
))#w7gjjqef";

fn outpoint(n: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([n; 32]),
        vout: 0,
    }
}

fn bip32_derivation_for(
    descriptor: &ParsedDescriptor,
    index: u32,
) -> BTreeMap<SecpPublicKey, KeySource> {
    let derived = derive_at(descriptor, index).unwrap();
    let mut map = BTreeMap::new();
    for (key_expr, child) in descriptor.keys.iter().zip(derived.children.iter()) {
        let pk = SecpPublicKey::from_slice(&child.public_key).unwrap();
        let branch = match key_expr.derivation {
            DerivationBranch::External => 0u32,
            DerivationBranch::Internal => 1u32,
        };
        let path_str = format!("m/{}/{branch}/{index}", key_expr.origin_path);
        let path = DerivationPath::from_str(&path_str).unwrap();
        let fp = BtcFingerprint::from(*key_expr.fingerprint.as_bytes());
        map.insert(pk, (fp, path));
    }
    map
}

fn txout(spk: ScriptBuf, sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: spk,
    }
}

fn known_map(op: OutPoint, utxo: TxOut) -> BTreeMap<OutPoint, TxOut> {
    let mut m = BTreeMap::new();
    m.insert(op, utxo);
    m
}

/// Build a valid 1-in / 2-out PSBT (recipient + change) for the WP-11 fixture keys.
fn build_valid(
    input_index: u32,
    change_index: u32,
    recipient_index: u32,
    input_sats: u64,
    send_sats: u64,
    fee_sats: u64,
) -> (Psbt, VerifyPolicy) {
    let recv = parse(RECEIVE).unwrap();
    let chg = parse(CHANGE).unwrap();
    let in_der = derive_at(&recv, input_index).unwrap();
    let ch_der = derive_at(&chg, change_index).unwrap();
    let recip_der = derive_at(&recv, recipient_index).unwrap();
    let recip_addr = recip_der.address(Network::Regtest).to_string();
    let change_sats = input_sats
        .checked_sub(send_sats)
        .unwrap()
        .checked_sub(fee_sats)
        .unwrap();

    let op = outpoint((input_index as u8).wrapping_add(1).max(1));
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            txout(recip_der.script_pubkey.clone(), send_sats),
            txout(ch_der.script_pubkey.clone(), change_sats),
        ],
    };
    let witness_utxo = TxOut {
        value: Amount::from_sat(input_sats),
        script_pubkey: in_der.script_pubkey,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(witness_utxo.clone());
    psbt.inputs[0].bip32_derivation = bip32_derivation_for(&recv, input_index);
    psbt.outputs[1].bip32_derivation = bip32_derivation_for(&chg, change_index);

    let mut known = BTreeMap::new();
    known.insert(op, witness_utxo);
    let policy = VerifyPolicy::new(
        vec![recip_addr],
        send_sats,
        fee_sats.saturating_mul(10).max(50_000),
        5_000,
        None,
        20,
        known,
        Some(CHANGE.to_owned()),
        Network::Regtest,
    );
    (psbt, policy)
}

// ---------------------------------------------------------------------------
// Positive coverage per check (V1–V10)
// ---------------------------------------------------------------------------

#[test]
fn v1_positive_valid_descriptor_checksum() {
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
}

#[test]
fn v2_positive_input_spk_matches_derived() {
    let (psbt, policy) = build_valid(2, 1, 6, 200_000, 80_000, 2_000);
    let v = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap();
    assert!(v.ok);
}

#[test]
fn v3_positive_change_in_gap_window() {
    let (psbt, policy) = build_valid(0, 7, 4, 150_000, 50_000, 1_500);
    let v = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap();
    assert!(v.change_sats > 0);
}

#[test]
fn v4_positive_bip32_derivation_matches() {
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    // bip32_derivation is fully populated for change in build_valid.
    assert_eq!(psbt.outputs[1].bip32_derivation.len(), 3);
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
}

#[test]
fn v5_positive_fee_within_caps() {
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let v = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap();
    assert_eq!(v.fee_sats, 1_000);
    assert!(v.feerate_sat_vb <= policy.max_feerate);
}

#[test]
fn v6_positive_amount_bit_exact() {
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let v = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap();
    assert_eq!(v.amount_sats, policy.declared_amount_sats);
}

#[test]
fn v7_positive_known_outpoint() {
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    assert_eq!(policy.known_utxos.len(), 1);
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
}

#[test]
fn v8_positive_consistent_maps() {
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    assert_eq!(psbt.inputs.len(), psbt.unsigned_tx.input.len());
    assert_eq!(psbt.outputs.len(), psbt.unsigned_tx.output.len());
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
}

#[test]
fn v9_positive_witness_utxo_present() {
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    assert!(psbt.inputs[0].witness_utxo.is_some());
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
}

#[test]
fn v10_positive_no_signature_yet() {
    // V10 does not apply when no partial_sigs — unsigned PSBT still Ok.
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    assert!(psbt.inputs[0].partial_sigs.is_empty());
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
}

// ---------------------------------------------------------------------------
// Extra negatives / branch coverage
// ---------------------------------------------------------------------------

#[test]
fn v4_negative_missing_bip32_entries() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.outputs[1].bip32_derivation.clear();
    let err = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err();
    assert_eq!(err, VerifyError::MismatchedDerivation { output_index: 1 });
}

#[test]
fn v4_negative_wrong_fingerprint() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let key = *psbt.outputs[1].bip32_derivation.keys().next().unwrap();
    let (_fp, path) = psbt.outputs[1].bip32_derivation.get(&key).unwrap().clone();
    psbt.outputs[1]
        .bip32_derivation
        .insert(key, (BtcFingerprint::from([0xff; 4]), path));
    // Now 3 entries but one fingerprint is foreign (and may have replaced one).
    // Force exactly one bad fingerprint by rebuilding:
    let chg = parse(CHANGE).unwrap();
    let mut map = bip32_derivation_for(&chg, 0);
    let first_key = *map.keys().next().unwrap();
    let (_, path) = map.remove(&first_key).unwrap();
    map.insert(
        first_key,
        (BtcFingerprint::from([0xde, 0xad, 0xbe, 0xef]), path),
    );
    psbt.outputs[1].bip32_derivation = map;
    let err = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err();
    assert_eq!(err, VerifyError::MismatchedDerivation { output_index: 1 });
}

#[test]
fn v8_negative_script_sig_on_unsigned() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.unsigned_tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
    let err = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err();
    assert!(matches!(err, VerifyError::InconsistentPsbt { .. }));
}

#[test]
fn v8_negative_proprietary_on_input() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.inputs[0].proprietary.insert(
        bitcoin::psbt::raw::ProprietaryKey {
            prefix: b"x".to_vec(),
            subtype: 1,
            key: vec![],
        },
        vec![0],
    );
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::ProprietaryField
    );
}

#[test]
fn v8_negative_proprietary_on_output() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.outputs[0].proprietary.insert(
        bitcoin::psbt::raw::ProprietaryKey {
            prefix: b"y".to_vec(),
            subtype: 2,
            key: vec![],
        },
        vec![0],
    );
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::ProprietaryField
    );
}

#[test]
fn v8_negative_output_len_mismatch() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.outputs.pop();
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::InconsistentPsbt { .. }
    ));
}

#[test]
fn v3_negative_no_change_descriptor_with_extra_output() {
    let (psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    policy.change_descriptor = None;
    // Change output is not declared → ForeignChangeOutput
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::ForeignChangeOutput { output_index: 1 }
    );
}

#[test]
fn invalid_output_address_rejected() {
    let (mut psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    // Bare OP_RETURN is not an address.
    psbt.unsigned_tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00]);
    policy.declared_recipients = vec!["not-used".into()];
    let err = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err();
    assert_eq!(err, VerifyError::InvalidOutputAddress { output_index: 0 });
}

#[test]
fn v1_negative_change_descriptor_bad_checksum() {
    let (psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let mut bad = CHANGE.to_owned();
    bad.pop();
    bad.push('x');
    policy.change_descriptor = Some(bad);
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::Descriptor(_)
    ));
}

// ---------------------------------------------------------------------------
// P1 — every valid constructed PSBT verifies Ok
// ---------------------------------------------------------------------------

fn p1_strategy() -> impl Strategy<Value = (u32, u32, u32, u64, u64, u64)> {
    (
        0u32..10,
        0u32..10,
        10u32..20, // recipient index disjoint from input
        50_000u64..500_000,
        1_000u64..40_000,
        200u64..5_000,
    )
        .prop_filter("room for change", |&(_, _, _, input, send, fee)| {
            input > send + fee + 546
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// P1: For every valid setup and every PSBT built from it: verify == Ok.
    ///
    /// Construction here is hand-built (builder WP not yet present); amounts,
    /// fee, and indices vary. Fixed structure keeps coin-selection out of scope.
    #[test]
    fn p1_valid_psbt_verifies(
        (in_i, ch_i, recip_i, input, send, fee) in p1_strategy()
    ) {
        let (psbt, policy) = build_valid(in_i, ch_i, recip_i, input, send, fee);
        prop_assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
    }
}

// ---------------------------------------------------------------------------
// P2 — change mutations → Err
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// P2: Every mutation of a change output (address / amount / derivation)
    /// leads to verify → Err.
    ///
    /// Amount mutations are pinned via `declared_fee_sats` from a prior display
    /// run (Spec §3.3 / §5.2): shifting sats between fee and change without
    /// that pin would still pass the fee *caps*.
    #[test]
    fn p2_change_mutation_rejected(kind in 0u8..3) {
        let (mut psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
        // Pin the true fee from the base PSBT (display-run → pre-sign run).
        let true_fee = {
            let v = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap();
            v.fee_sats
        };
        policy.declared_fee_sats = Some(true_fee);
        // Caps stay loose so only the pin (or V3/V4) rejects the mutation.
        policy.max_absolute_fee = u64::MAX;
        policy.max_feerate = u64::MAX;

        match kind {
            0 => {
                // Address mutation: swap change SPK for a foreign receive index.
                let recv = parse(RECEIVE).unwrap();
                let foreign = derive_at(&recv, 9).unwrap();
                psbt.unsigned_tx.output[1].script_pubkey = foreign.script_pubkey;
                psbt.outputs[1].bip32_derivation.clear();
            }
            1 => {
                // Amount mutation: move 1 sat from fee into change (fee↓, change↑).
                // Still within loose caps; rejected only because declared_fee_sats
                // pins the display-run fee.
                let ch = psbt.unsigned_tx.output[1].value.to_sat();
                psbt.unsigned_tx.output[1].value = Amount::from_sat(ch + 1);
            }
            _ => {
                // Derivation path mutation on change bip32_derivation.
                if let Some((fp, path)) = psbt.outputs[1].bip32_derivation.values_mut().next() {
                    let mut children: Vec<_> = path.into_iter().copied().collect();
                    children[5] = bitcoin::bip32::ChildNumber::from_normal_idx(3).unwrap();
                    *path = DerivationPath::from(children);
                    let _ = fp;
                }
            }
        }
        prop_assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_err());
    }
}

// ---------------------------------------------------------------------------
// P3 — bip32_derivation path mutations → Err
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// P3: Every mutation of derivation paths in bip32_derivation → Err.
    #[test]
    fn p3_derivation_path_mutation_rejected(new_idx in 1u32..15) {
        let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
        if let Some((fp, path)) = psbt.outputs[1].bip32_derivation.values_mut().next() {
            let mut children: Vec<_> = path.into_iter().copied().collect();
            children[5] = bitcoin::bip32::ChildNumber::from_normal_idx(new_idx).unwrap();
            *path = DerivationPath::from(children);
            let _ = fp;
        }
        let err = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err();
        prop_assert_eq!(err, VerifyError::MismatchedDerivation { output_index: 1 });
    }
}

// ---------------------------------------------------------------------------
// P11 — non-SIGHASH_ALL rejected
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6))]

    /// P11: A PSBT with SIGHASH other than SIGHASH_ALL is rejected.
    #[test]
    fn p11_non_sighash_all_rejected(
        which in prop::sample::select(vec![
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ])
    ) {
        let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(which));
        prop_assert_eq!(
            trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
            VerifyError::NonSighashAll { input_index: 0 }
        );
    }
}

// ---------------------------------------------------------------------------
// P12 — non_witness_utxo instead of witness_utxo rejected (V9)
// ---------------------------------------------------------------------------

#[test]
fn p12_non_witness_utxo_only_rejected() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let prev = psbt.unsigned_tx.clone();
    psbt.inputs[0].witness_utxo = None;
    psbt.inputs[0].non_witness_utxo = Some(prev);
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::NonWitnessUtxoOnly { input_index: 0 }
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// P12 property form: constructed non_witness_utxo-only PSBTs reject (V9).
    #[test]
    fn p12_property_non_witness_only(seed in 0u8..20) {
        let (mut psbt, policy) = build_valid(seed as u32 % 5, 0, 5, 100_000, 40_000, 1_000);
        let prev = psbt.unsigned_tx.clone();
        psbt.inputs[0].witness_utxo = None;
        psbt.inputs[0].non_witness_utxo = Some(prev);
        prop_assert_eq!(
            trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
            VerifyError::NonWitnessUtxoOnly { input_index: 0 }
        );
    }
}

// ---------------------------------------------------------------------------
// Additional edge coverage (moved from in-module unit tests)
// ---------------------------------------------------------------------------

#[test]
fn v1_negative_bad_receive_checksum() {
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let mut bad = RECEIVE.to_owned();
    bad.pop();
    bad.push('x');
    assert!(matches!(
        trinity_verify::verify(&psbt, &bad, &policy).unwrap_err(),
        VerifyError::Descriptor(_)
    ));
}

#[test]
fn v2_negative_foreign_input() {
    let (mut psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&[0xAAu8; 32]);
    let new_spk = ScriptBuf::from_bytes(spk);
    psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = new_spk.clone();
    // Keep V7 happy so V2 is the rejecting check.
    let op = psbt.unsigned_tx.input[0].previous_output;
    let val = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
    policy.known_utxos.insert(
        op,
        TxOut {
            value: val,
            script_pubkey: new_spk,
        },
    );
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::ForeignInput { input_index: 0 }
    );
}

#[test]
fn v2_positive_change_chain_input() {
    let chg = parse(CHANGE).unwrap();
    let recv = parse(RECEIVE).unwrap();
    let in_der = derive_at(&chg, 2).unwrap();
    let recip_der = derive_at(&recv, 5).unwrap();
    let recip = recip_der.address(Network::Regtest).to_string();
    let op = outpoint(3);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![txout(recip_der.script_pubkey.clone(), 90_000)],
    };
    let utxo = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: in_der.script_pubkey,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(utxo.clone());
    let policy = VerifyPolicy::new(
        vec![recip],
        90_000,
        20_000,
        1_000,
        None,
        20,
        known_map(op, utxo),
        Some(CHANGE.to_owned()),
        Network::Regtest,
    );
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
}

#[test]
fn v2_foreign_without_change_descriptor() {
    let (mut psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    policy.change_descriptor = None;
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&[0x66u8; 32]);
    let new_spk = ScriptBuf::from_bytes(spk);
    psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = new_spk.clone();
    let op = psbt.unsigned_tx.input[0].previous_output;
    let val = psbt.inputs[0].witness_utxo.as_ref().unwrap().value;
    policy.known_utxos.insert(
        op,
        TxOut {
            value: val,
            script_pubkey: new_spk,
        },
    );
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::ForeignInput { input_index: 0 }
    );
}

#[test]
fn v3_negative_forged_change() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let recv = parse(RECEIVE).unwrap();
    let foreign = derive_at(&recv, 9).unwrap();
    psbt.unsigned_tx.output[1].script_pubkey = foreign.script_pubkey;
    psbt.outputs[1].bip32_derivation.clear();
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::ForeignChangeOutput { output_index: 1 }
    );
}

#[test]
fn v4_negative_wrong_path() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let (fp, path) = psbt.outputs[1]
        .bip32_derivation
        .values_mut()
        .next()
        .unwrap();
    let mut children: Vec<_> = path.into_iter().copied().collect();
    children[5] = bitcoin::bip32::ChildNumber::from_normal_idx(1).unwrap();
    *path = DerivationPath::from(children);
    let _ = fp;
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MismatchedDerivation { output_index: 1 }
    );
}

#[test]
fn v4_negative_short_path() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let (fp, path) = psbt.outputs[1]
        .bip32_derivation
        .values_mut()
        .next()
        .unwrap();
    let short: DerivationPath = "m/48'/1'/0'/2'".parse().unwrap();
    *path = short;
    let _ = fp;
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MismatchedDerivation { output_index: 1 }
    );
}

#[test]
fn v4_negative_wrong_branch() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let (fp, path) = psbt.outputs[1]
        .bip32_derivation
        .values_mut()
        .next()
        .unwrap();
    let mut children: Vec<_> = path.into_iter().copied().collect();
    children[4] = bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap();
    *path = DerivationPath::from(children);
    let _ = fp;
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MismatchedDerivation { output_index: 1 }
    );
}

#[test]
fn v4_negative_wrong_origin_coin() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    for (_fp, path) in psbt.outputs[1].bip32_derivation.values_mut() {
        let mut children: Vec<_> = path.into_iter().copied().collect();
        children[1] = bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap();
        *path = DerivationPath::from(children);
    }
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MismatchedDerivation { output_index: 1 }
    );
}

#[test]
fn v4_negative_wrong_pubkey() {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
    let foreign = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let old_key = *psbt.outputs[1].bip32_derivation.keys().next().unwrap();
    let source = psbt.outputs[1].bip32_derivation.remove(&old_key).unwrap();
    psbt.outputs[1].bip32_derivation.insert(foreign, source);
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MismatchedDerivation { output_index: 1 }
    );
}

#[test]
fn v4_negative_duplicate_map_fingerprint() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let keys: Vec<_> = psbt.outputs[1].bip32_derivation.keys().copied().collect();
    let (fp0, path0) = psbt.outputs[1]
        .bip32_derivation
        .get(&keys[0])
        .unwrap()
        .clone();
    psbt.outputs[1]
        .bip32_derivation
        .insert(keys[1], (fp0, path0));
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MismatchedDerivation { output_index: 1 }
    );
}

#[test]
fn v5_negative_fee_and_feerate() {
    let (psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    policy.max_absolute_fee = 500;
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::FeeTooHigh { .. }
    ));
    policy.max_absolute_fee = 1_000_000;
    policy.max_feerate = 0;
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::FeerateTooHigh { .. }
    ));
}

#[test]
fn v5_negative_zero_fee() {
    let (mut psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let in_val = psbt.inputs[0].witness_utxo.as_ref().unwrap().value.to_sat();
    psbt.unsigned_tx.output[0].value = Amount::from_sat(in_val);
    psbt.unsigned_tx.output[1].value = Amount::from_sat(0);
    policy.declared_amount_sats = in_val;
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::FeeNonPositive
    );
}

#[test]
fn v6_negative_amount() {
    let (psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    policy.declared_amount_sats = 1;
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::AmountMismatch { .. }
    ));
}

#[test]
fn v7_negative_unknown() {
    let (psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    policy.known_utxos.clear();
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::UnknownInput { input_index: 0 }
    );
}

#[test]
fn v7_negative_mismatched_utxo_value() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    // Outpoint still known; lie about the amount on the PSBT.
    psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(99_999);
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MismatchedUtxo { input_index: 0 }
    );
}

#[test]
fn v7_negative_mismatched_utxo_script() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&[0x11u8; 32]);
    psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = ScriptBuf::from_bytes(spk);
    // V7 runs before V2; mismatch on known UTXO is MismatchedUtxo (not ForeignInput).
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MismatchedUtxo { input_index: 0 }
    );
}

#[test]
fn v8_negative_empty_inputs() {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![txout(ScriptBuf::new(), 1)],
    };
    let psbt = Psbt {
        inputs: vec![],
        outputs: vec![Default::default()],
        unsigned_tx: tx,
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
    };
    let policy = VerifyPolicy::new(
        vec![],
        0,
        1,
        1,
        None,
        1,
        BTreeMap::new(),
        None,
        Network::Regtest,
    );
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::InconsistentPsbt { .. }
    ));
}

#[test]
fn v8_negative_input_len_and_witness() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.inputs.push(Default::default());
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::InconsistentPsbt { .. }
    ));
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.unsigned_tx.input[0].witness.push(vec![0x01]);
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::InconsistentPsbt { .. }
    ));
}

#[test]
fn v8_negative_global_proprietary() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.proprietary.insert(
        bitcoin::psbt::raw::ProprietaryKey {
            prefix: b"test".to_vec(),
            subtype: 0,
            key: vec![],
        },
        vec![1],
    );
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::ProprietaryField
    );
}

#[test]
fn v9_negatives() {
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.inputs[0].witness_utxo = None;
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MissingWitnessUtxo { input_index: 0 }
    );
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let dummy = psbt.unsigned_tx.clone();
    psbt.inputs[0].witness_utxo = None;
    psbt.inputs[0].non_witness_utxo = Some(dummy);
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::NonWitnessUtxoOnly { input_index: 0 }
    );
}

#[test]
fn v10_low_s_ok_and_high_s_bad() {
    use bitcoin::secp256k1::ecdsa::Signature as SecpSig;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::{ecdsa, PublicKey};

    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
    let msg = Message::from_digest([2u8; 32]);
    let sig = secp.sign_ecdsa(&msg, &sk);
    psbt.inputs[0]
        .partial_sigs
        .insert(pk, ecdsa::Signature::sighash_all(sig));
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());

    let high_der = vec![
        0x30, 0x46, 0x02, 0x21, 0x00, 0x83, 0x9c, 0x1f, 0xbc, 0x53, 0x04, 0xde, 0x94, 0x4f, 0x69,
        0x7c, 0x9f, 0x4b, 0x1d, 0x01, 0xd1, 0xfa, 0xeb, 0xa3, 0x2d, 0x75, 0x1c, 0x0f, 0x7a, 0xcb,
        0x21, 0xac, 0x8a, 0x0f, 0x43, 0x6a, 0x72, 0x02, 0x21, 0x00, 0xe8, 0x9b, 0xd4, 0x6b, 0xb3,
        0xa5, 0xa6, 0x2a, 0xdc, 0x67, 0x9f, 0x65, 0x9b, 0x7c, 0xe8, 0x76, 0xd8, 0x3e, 0xe2, 0x97,
        0xc7, 0xa5, 0x58, 0x7b, 0x20, 0x11, 0xc4, 0xfc, 0xc7, 0x2e, 0xab, 0x45,
    ];
    let secp_sig = SecpSig::from_der(&high_der).unwrap();
    let pk2 = PublicKey::from_slice(&[
        0x03, 0x1e, 0xe9, 0x9d, 0x2b, 0x78, 0x6a, 0xb3, 0xb0, 0x99, 0x13, 0x25, 0xf2, 0xde, 0x84,
        0x89, 0x24, 0x6a, 0x6a, 0x3f, 0xdb, 0x70, 0x0f, 0x6d, 0x05, 0x11, 0xb1, 0xd8, 0x0c, 0xf5,
        0xf4, 0xcd, 0x43,
    ])
    .unwrap();
    psbt.inputs[0].partial_sigs.clear();
    psbt.inputs[0].partial_sigs.insert(
        pk2,
        ecdsa::Signature {
            signature: secp_sig,
            sighash_type: EcdsaSighashType::All,
        },
    );
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::BadSignature { input_index: 0 }
    );
}

#[test]
fn v10_non_all_via_field_and_sig() {
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::{ecdsa, PublicKey};

    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::None));
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::NonSighashAll { input_index: 0 }
    );

    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
    let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
    let msg = Message::from_digest([4u8; 32]);
    let sig = secp.sign_ecdsa(&msg, &sk);
    psbt.inputs[0].partial_sigs.insert(
        pk,
        ecdsa::Signature {
            signature: sig,
            sighash_type: EcdsaSighashType::None,
        },
    );
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::NonSighashAll { input_index: 0 }
    );
}

#[test]
fn verify_psbt_base64_ok_and_bad() {
    let (psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let b64 = psbt.to_string();
    assert!(
        trinity_verify::verify_psbt(&b64, RECEIVE, &policy)
            .unwrap()
            .ok
    );
    assert_eq!(
        trinity_verify::verify_psbt("not-a-psbt!!!", RECEIVE, &policy).unwrap_err(),
        VerifyError::PsbtDecode
    );
}

#[test]
fn changeless_and_change_only() {
    let recv = parse(RECEIVE).unwrap();
    let in_der = derive_at(&recv, 0).unwrap();
    let recip_der = derive_at(&recv, 3).unwrap();
    let recip = recip_der.address(Network::Regtest).to_string();
    let op = outpoint(1);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![txout(recip_der.script_pubkey.clone(), 90_000)],
    };
    let utxo = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: in_der.script_pubkey.clone(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(utxo.clone());
    let policy = VerifyPolicy::new(
        vec![recip.clone()],
        90_000,
        20_000,
        1_000,
        None,
        20,
        known_map(op, utxo.clone()),
        None,
        Network::Regtest,
    );
    let v = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap();
    assert_eq!(v.change_sats, 0);
    assert_eq!(v.recipient, recip);

    // Change-only (empty declared recipients, amount 0).
    let chg = parse(CHANGE).unwrap();
    let ch_der = derive_at(&chg, 0).unwrap();
    let op2 = outpoint(5);
    let tx2 = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op2,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![txout(ch_der.script_pubkey.clone(), 99_000)],
    };
    let mut psbt2 = Psbt::from_unsigned_tx(tx2).unwrap();
    psbt2.inputs[0].witness_utxo = Some(utxo.clone());
    psbt2.outputs[0].bip32_derivation = bip32_derivation_for(&chg, 0);
    let policy2 = VerifyPolicy::new(
        vec![],
        0,
        20_000,
        1_000,
        None,
        20,
        known_map(op2, utxo),
        Some(CHANGE.to_owned()),
        Network::Regtest,
    );
    let v2 = trinity_verify::verify(&psbt2, RECEIVE, &policy2).unwrap();
    assert_eq!(v2.amount_sats, 0);
    assert_eq!(v2.change_sats, 99_000);
}

#[test]
fn two_recipients() {
    let recv = parse(RECEIVE).unwrap();
    let in_der = derive_at(&recv, 0).unwrap();
    let r0 = derive_at(&recv, 5).unwrap();
    let r1 = derive_at(&recv, 6).unwrap();
    let a0 = r0.address(Network::Regtest).to_string();
    let a1 = r1.address(Network::Regtest).to_string();
    let op = outpoint(4);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            txout(r0.script_pubkey.clone(), 30_000),
            txout(r1.script_pubkey.clone(), 60_000),
        ],
    };
    let utxo = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: in_der.script_pubkey,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(utxo.clone());
    let policy = VerifyPolicy::new(
        vec![a0.clone(), a1],
        90_000,
        20_000,
        1_000,
        None,
        20,
        known_map(op, utxo),
        None,
        Network::Regtest,
    );
    let v = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap();
    assert_eq!(v.amount_sats, 90_000);
    assert_eq!(v.recipient, a0);
}

#[test]
fn invalid_output_and_sum_overflow() {
    let (mut psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.unsigned_tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00]);
    policy.declared_recipients = vec!["unused".into()];
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::InvalidOutputAddress { output_index: 0 }
    );

    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.unsigned_tx.output[0].value = Amount::from_sat(u64::MAX / 2 + 1);
    psbt.unsigned_tx.output[1].value = Amount::from_sat(u64::MAX / 2 + 1);
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::FeeNonPositive
    );
}

#[test]
fn error_display_variants() {
    let samples = [
        VerifyError::FeeNonPositive,
        VerifyError::FeeTooHigh {
            fee_sats: 1,
            max_sats: 0,
        },
        VerifyError::FeerateTooHigh {
            feerate_sat_vb: 9,
            max_sat_vb: 1,
        },
        VerifyError::FeeMismatch {
            actual_sats: 1,
            expected_sats: 2,
        },
        VerifyError::AmountMismatch {
            actual_sats: 1,
            expected_sats: 2,
        },
        VerifyError::UnknownInput { input_index: 0 },
        VerifyError::MismatchedUtxo { input_index: 0 },
        VerifyError::InconsistentPsbt { detail: "x" },
        VerifyError::TooManyInputsOutputs { detail: "x" },
        VerifyError::ProprietaryField,
        VerifyError::MissingWitnessUtxo { input_index: 0 },
        VerifyError::NonWitnessUtxoOnly { input_index: 0 },
        VerifyError::BadSignature { input_index: 0 },
        VerifyError::NonSighashAll { input_index: 0 },
        VerifyError::PsbtDecode,
        VerifyError::InvalidOutputAddress { output_index: 0 },
        VerifyError::ForeignInput { input_index: 0 },
        VerifyError::ForeignChangeOutput { output_index: 0 },
        VerifyError::MismatchedDerivation { output_index: 0 },
    ];
    for e in samples {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn declared_recipient_casing_preserved() {
    let (psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let upper = policy.declared_recipients[0].to_uppercase();
    policy.declared_recipients = vec![upper.clone()];
    let v = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap();
    assert_eq!(v.recipient, upper);
}

#[test]
fn is_sighash_all_nonstandard_via_psbt() {
    // Non-standard sighash type field → NonSighashAll.
    let (mut psbt, policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0xFF));
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::NonSighashAll { input_index: 0 }
    );
}

// ---------------------------------------------------------------------------
// Review-fix findings (V4 fingerprint↔origin bind, I/O bound, fee pin)
// ---------------------------------------------------------------------------

/// Change descriptor with heterogeneous BIP-48 origins (coin type 0' on key0,
/// 1' on key1/2). Checksum precomputed with BIP-380 (matches crate algorithm).
const CHANGE_MIXED_ORIGIN: &str = "wsh(sortedmulti(2,\
[73756c7f/48'/0'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/1/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/1/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/1/*\
))#9c0ngcmr";

#[test]
fn v4_negative_fingerprint_bound_to_own_origin_path() {
    // Heterogeneous origins are legal under the WP-20 grammar. V4 must bind
    // each bip32_derivation entry's path to the KeyExpr that owns that
    // fingerprint — not "any origin among the three keys".
    let recv = parse(RECEIVE).unwrap();
    let chg = parse(CHANGE_MIXED_ORIGIN).unwrap();
    assert_eq!(chg.keys[0].origin_path, "48'/0'/0'/2'");
    assert_eq!(chg.keys[1].origin_path, "48'/1'/0'/2'");

    let in_der = derive_at(&recv, 0).unwrap();
    let ch_der = derive_at(&chg, 0).unwrap();
    let recip_der = derive_at(&recv, 5).unwrap();
    let recip = recip_der.address(Network::Regtest).to_string();
    let op = outpoint(7);
    let utxo = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: in_der.script_pubkey,
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            txout(recip_der.script_pubkey.clone(), 40_000),
            txout(ch_der.script_pubkey.clone(), 59_000),
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(utxo.clone());
    psbt.outputs[1].bip32_derivation = bip32_derivation_for(&chg, 0);

    // Cross-bind: keep fingerprint of key1 (coin type 1'), force path prefix
    // to key0's origin (coin type 0'). Old "any origin" check would accept;
    // per-key binding must reject.
    let pk1 = {
        let child = &derive_at(&chg, 0).unwrap().children[1];
        SecpPublicKey::from_slice(&child.public_key).unwrap()
    };
    let (fp1, _path1) = psbt.outputs[1].bip32_derivation.get(&pk1).unwrap().clone();
    let wrong_path: DerivationPath = "m/48'/0'/0'/2'/1/0".parse().unwrap();
    psbt.outputs[1]
        .bip32_derivation
        .insert(pk1, (fp1, wrong_path));

    let policy = VerifyPolicy::new(
        vec![recip],
        40_000,
        50_000,
        5_000,
        None,
        20,
        known_map(op, utxo),
        Some(CHANGE_MIXED_ORIGIN.to_owned()),
        Network::Regtest,
    );
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::MismatchedDerivation { output_index: 1 }
    );
}

#[test]
fn v4_positive_heterogeneous_origins_when_paths_match_own_keys() {
    // Same mixed-origin descriptor: correctly built bip32_derivation passes.
    let recv = parse(RECEIVE).unwrap();
    let chg = parse(CHANGE_MIXED_ORIGIN).unwrap();
    let in_der = derive_at(&recv, 0).unwrap();
    let ch_der = derive_at(&chg, 0).unwrap();
    let recip_der = derive_at(&recv, 5).unwrap();
    let recip = recip_der.address(Network::Regtest).to_string();
    let op = outpoint(8);
    let utxo = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: in_der.script_pubkey,
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            txout(recip_der.script_pubkey.clone(), 40_000),
            txout(ch_der.script_pubkey.clone(), 59_000),
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(utxo.clone());
    psbt.outputs[1].bip32_derivation = bip32_derivation_for(&chg, 0);
    let policy = VerifyPolicy::new(
        vec![recip],
        40_000,
        50_000,
        5_000,
        None,
        20,
        known_map(op, utxo),
        Some(CHANGE_MIXED_ORIGIN.to_owned()),
        Network::Regtest,
    );
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
}

#[test]
fn v8_negative_too_many_outputs() {
    use trinity_verify::MAX_PSBT_INS_OR_OUTS;
    // One real input; MAX+1 tiny outputs. Cheap to construct — no gap-limit
    // derivation runs because V8 rejects first.
    let recv = parse(RECEIVE).unwrap();
    let in_der = derive_at(&recv, 0).unwrap();
    let op = outpoint(9);
    let utxo = TxOut {
        value: Amount::from_sat(1_000_000),
        script_pubkey: in_der.script_pubkey,
    };
    let n = MAX_PSBT_INS_OR_OUTS + 1;
    let outputs: Vec<TxOut> = (0..n).map(|_| txout(ScriptBuf::new(), 1)).collect();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(utxo.clone());
    let policy = VerifyPolicy::new(
        vec![],
        0,
        u64::MAX,
        u64::MAX,
        None,
        1, // tiny gap — not reached
        known_map(op, utxo),
        None,
        Network::Regtest,
    );
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::TooManyInputsOutputs { .. }
    ));
}

#[test]
fn v8_negative_too_many_inputs() {
    use trinity_verify::MAX_PSBT_INS_OR_OUTS;
    let n = MAX_PSBT_INS_OR_OUTS + 1;
    let inputs: Vec<TxIn> = (0..n)
        .map(|i| TxIn {
            previous_output: outpoint((i % 250) as u8),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        })
        .collect();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![txout(ScriptBuf::new(), 1)],
    };
    // Maps sized by from_unsigned_tx; V8 rejects before UTXO/V2 work.
    let psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let policy = VerifyPolicy::new(
        vec![],
        0,
        1,
        1,
        None,
        1,
        BTreeMap::new(),
        None,
        Network::Regtest,
    );
    assert!(matches!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::TooManyInputsOutputs { .. }
    ));
}

#[test]
fn v8_positive_at_max_outputs_bound_reaches_later_checks() {
    use trinity_verify::MAX_PSBT_INS_OR_OUTS;
    // Exactly MAX outputs: bound does not fire; later checks reject for other
    // reasons (empty scripts are not valid addresses). Proves the bound is
    // exclusive upper (`>`), not `>=`.
    let recv = parse(RECEIVE).unwrap();
    let in_der = derive_at(&recv, 0).unwrap();
    let op = outpoint(10);
    let utxo = TxOut {
        value: Amount::from_sat(1_000_000),
        script_pubkey: in_der.script_pubkey,
    };
    let outputs: Vec<TxOut> = (0..MAX_PSBT_INS_OR_OUTS)
        .map(|_| txout(ScriptBuf::new(), 1))
        .collect();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(utxo.clone());
    let policy = VerifyPolicy::new(
        vec![],
        0,
        u64::MAX,
        u64::MAX,
        None,
        1,
        known_map(op, utxo),
        None,
        Network::Regtest,
    );
    let err = trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err();
    assert!(
        !matches!(err, VerifyError::TooManyInputsOutputs { .. }),
        "at-bound must not hit TooManyInputsOutputs, got {err:?}"
    );
}

#[test]
fn v5_declared_fee_mismatch() {
    let (mut psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let true_fee = trinity_verify::verify(&psbt, RECEIVE, &policy)
        .unwrap()
        .fee_sats;
    policy.declared_fee_sats = Some(true_fee);
    // Shift 1 sat into change → fee drops by 1.
    let ch = psbt.unsigned_tx.output[1].value.to_sat();
    psbt.unsigned_tx.output[1].value = Amount::from_sat(ch + 1);
    policy.max_absolute_fee = u64::MAX;
    policy.max_feerate = u64::MAX;
    assert_eq!(
        trinity_verify::verify(&psbt, RECEIVE, &policy).unwrap_err(),
        VerifyError::FeeMismatch {
            actual_sats: true_fee - 1,
            expected_sats: true_fee,
        }
    );
}

#[test]
fn v5_declared_fee_match_ok() {
    // Display-run pin equals actual fee → still Ok (covers fee_sats == expected arm).
    let (psbt, mut policy) = build_valid(0, 0, 5, 100_000, 40_000, 1_000);
    let true_fee = trinity_verify::verify(&psbt, RECEIVE, &policy)
        .unwrap()
        .fee_sats;
    policy.declared_fee_sats = Some(true_fee);
    assert!(trinity_verify::verify(&psbt, RECEIVE, &policy).is_ok());
}
