//! WP-36: finalize, BIP-67 witness order, consensus, S11, S12.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use trinity_types::{Balance, SecretBytes};
use trinity_verify::{derive_at, parse, DerivationBranch, VerifyError, VerifyPolicy};

use crate::sign::{sighash_message, sign_a, sign_b};
use crate::tests_wp33::{
    bip32_derivation_for, build_psbt, default_wallet, pair_signers, BuiltPsbt, WalletFixture,
};
use crate::{
    finalize, sign_ab, FakeBlockHeightSource, FakeClock, SignError, Signer, SpendPolicy,
    SpendSession, WindowCounter,
};

const CORE_KEK: [u8; 32] = [0x3C; 32];
const ENTROPY_C: [u8; 32] = [0xC0; 32];

fn ready_counter() -> WindowCounter {
    let mut c = WindowCounter::new(SecretBytes::from_slice(&CORE_KEK)).unwrap();
    c.set_passphrase_used_since_install(true);
    c
}

fn session<'a>(
    policy: &'a SpendPolicy,
    counter: &'a mut WindowCounter,
    clock: &'a FakeClock,
    blocks: &'a FakeBlockHeightSource,
    confirmed: u64,
) -> SpendSession<'a> {
    SpendSession {
        policy,
        counter,
        clock,
        blocks,
        balance: Balance {
            confirmed_sats: confirmed,
            trusted_pending_sats: 0,
            untrusted_pending_sats: 0,
            immature_sats: 0,
        },
        wall_unix_ns: None,
    }
}

fn sign_both(wallet: &WalletFixture, built: BuiltPsbt) -> (Psbt, VerifyPolicy) {
    let (a, _, b, _) = pair_signers(wallet);
    let txid = built.psbt.unsigned_tx.compute_txid();
    let after_a = sign_a(&a, built.psbt, &wallet.receive, &built.policy).unwrap();
    let signed = sign_b(&b, after_a, txid, &wallet.receive, &built.policy).unwrap();
    (signed, built.policy)
}

fn index_where(wallet: &WalletFixture, pred: impl Fn(&[[u8; 33]; 3]) -> bool) -> u32 {
    let recv = parse(&wallet.receive).unwrap();
    let mut found = 0u32;
    for i in 0..64 {
        let d = derive_at(&recv, i).unwrap();
        if pred(&[
            d.children[0].public_key,
            d.children[1].public_key,
            d.children[2].public_key,
        ]) {
            found = i;
            break;
        }
    }
    let d = derive_at(&recv, found).unwrap();
    assert!(pred(&[
        d.children[0].public_key,
        d.children[1].public_key,
        d.children[2].public_key,
    ]));
    found
}

fn index_where_a_sorts_after_b(wallet: &WalletFixture) -> u32 {
    index_where(wallet, |c| c[0] > c[1])
}

fn index_where_a_sorts_before_b(wallet: &WalletFixture) -> u32 {
    index_where(wallet, |c| c[0] < c[1])
}

fn index_where_c_sorts_last(wallet: &WalletFixture) -> u32 {
    index_where(wallet, |c| (c[2] > c[0]) & (c[2] > c[1]))
}

fn master_c() -> Xpriv {
    let material = trinity_entropy::bip39_from_entropy(&ENTROPY_C).unwrap();
    Xpriv::new_master(Network::Bitcoin, material.seed.as_slice()).unwrap()
}

fn sign_c_into(psbt: &mut Psbt) {
    let secp = Secp256k1::new();
    let master = master_c();
    let fp = master.fingerprint(&secp);
    let want = *fp.as_bytes();
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        let (pk, path) = input
            .bip32_derivation
            .iter()
            .find_map(|(pk, (got, path))| {
                if *got.as_bytes() == want {
                    Some((*pk, path.clone()))
                } else {
                    None
                }
            })
            .expect("C derivation");
        let child = master.derive_priv(&secp, &path).unwrap();
        let msg = sighash_message(&psbt.unsigned_tx, i, input).unwrap();
        let sig = secp.sign_ecdsa_low_r(&msg, &child.private_key);
        input.partial_sigs.insert(
            PublicKey::new(pk),
            bitcoin::ecdsa::Signature::sighash_all(sig),
        );
    }
}

#[test]
fn finalize_happy_path_and_change_input() {
    let wallet = default_wallet();
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let (signed, policy) = sign_both(&wallet, built);
    let tx = finalize(&signed, &wallet.receive, &policy).unwrap();
    assert_eq!(tx.input.len(), 1);
    let stack = tx.input[0].witness.to_vec();
    assert_eq!(stack.len(), 4);
    assert!(stack[0].is_empty());

    // Change-chain input (branch /1/*).
    let recv = parse(&wallet.receive).unwrap();
    let chg = parse(&wallet.change).unwrap();
    let in_der = derive_at(&chg, 0).unwrap();
    let recip = derive_at(&recv, 6).unwrap();
    let op = crate::tests_wp33::outpoint(9);
    let tx_u = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: recip.script_pubkey.clone(),
        }],
    };
    let utxo = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: in_der.script_pubkey.clone(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx_u).unwrap();
    psbt.inputs[0].witness_utxo = Some(utxo.clone());
    psbt.inputs[0].witness_script = Some(in_der.witness_script.clone());
    psbt.inputs[0].bip32_derivation = bip32_derivation_for(&chg, 0);
    let mut known = BTreeMap::new();
    known.insert(op, utxo);
    let policy = VerifyPolicy::new(
        vec![recip.address(Network::Regtest).to_string()],
        40_000,
        50_000,
        5_000,
        None,
        20,
        known,
        Some(wallet.change.clone()),
        Network::Regtest,
    );
    let (a, _, b, _) = pair_signers(&wallet);
    let txid = psbt.unsigned_tx.compute_txid();
    let after_a = sign_a(&a, psbt, &wallet.receive, &policy).unwrap();
    let signed = sign_b(&b, after_a, txid, &wallet.receive, &policy).unwrap();
    finalize(&signed, &wallet.receive, &policy).unwrap();
}

#[test]
fn witness_follows_bip67_not_signing_order() {
    let wallet = default_wallet();
    let idx = index_where_a_sorts_before_b(&wallet);
    let built = build_psbt(&wallet, idx, 0, 5, 100_000, 40_000, 1_000);
    let (a, _, b, _) = pair_signers(&wallet);
    // Sign B first, then A — opposite of descriptor / sign_ab order.
    let after_b = b.sign(built.psbt.clone()).unwrap();
    let signed = a.sign(after_b).unwrap();
    assert_eq!(signed.inputs[0].partial_sigs.len(), 2);

    let tx = finalize(&signed, &wallet.receive, &built.policy).unwrap();
    let recv = parse(&wallet.receive).unwrap();
    let derived = derive_at(&recv, idx).unwrap();
    assert_eq!(derived.children[0].branch, DerivationBranch::External);
    let sorted = derived.sorted_pubkeys_slice();
    let mut expected = Vec::new();
    for pk_bytes in sorted {
        let pk = PublicKey::from_slice(pk_bytes).unwrap();
        if let Some(sig) = signed.inputs[0].partial_sigs.get(&pk) {
            expected.push(sig.to_vec());
        }
    }
    let stack = tx.input[0].witness.to_vec();
    assert_eq!(stack[1], expected[0]);
    assert_eq!(stack[2], expected[1]);
    // Signing order was B then A; BIP-67 of A,B is A then B at this index.
    let a_pk = PublicKey::from_slice(&derived.children[0].public_key).unwrap();
    let b_pk = PublicKey::from_slice(&derived.children[1].public_key).unwrap();
    assert!(derived.children[0].public_key < derived.children[1].public_key);
    assert_eq!(stack[1], signed.inputs[0].partial_sigs[&a_pk].to_vec());
    assert_eq!(stack[2], signed.inputs[0].partial_sigs[&b_pk].to_vec());
}

#[test]
fn finalize_ignores_third_signature_after_first_two() {
    let wallet = default_wallet();
    let idx = index_where_c_sorts_last(&wallet);
    let built = build_psbt(&wallet, idx, 0, 5, 100_000, 40_000, 1_000);
    let (mut signed, policy) = sign_both(&wallet, built);
    sign_c_into(&mut signed);
    assert_eq!(signed.inputs[0].partial_sigs.len(), 3);
    let tx = finalize(&signed, &wallet.receive, &policy).unwrap();
    let recv = parse(&wallet.receive).unwrap();
    let derived = derive_at(&recv, idx).unwrap();
    let c_pk = PublicKey::from_slice(&derived.children[2].public_key).unwrap();
    let c_sig = signed.inputs[0].partial_sigs[&c_pk].to_vec();
    // C sorts last: first two BIP-67 keys are A and B. `[]` fails if missing.
    let sorted = derived.sorted_pubkeys_slice();
    let first = PublicKey::from_slice(&sorted[0]).unwrap();
    let second = PublicKey::from_slice(&sorted[1]).unwrap();
    let stack = tx.input[0].witness.to_vec();
    assert_eq!(stack[1], signed.inputs[0].partial_sigs[&first].to_vec());
    assert_eq!(stack[2], signed.inputs[0].partial_sigs[&second].to_vec());
    assert_ne!(stack[1], c_sig);
    assert_ne!(stack[2], c_sig);
}

#[test]
fn s11_absurd_fee_rejected_before_key_access() {
    let wallet = default_wallet();
    let (a, fake_a, b, fake_b) = pair_signers(&wallet);
    // 0.5 BTC fee. Override the fixture cap so V5 fires.
    let mut built = build_psbt(&wallet, 0, 0, 5, 60_000_000, 9_000_000, 50_000_000);
    built.policy.max_absolute_fee = 100_000;
    fake_a.reset_calls();
    fake_b.reset_calls();
    let mut counter = ready_counter();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(100));
    let spend_policy = SpendPolicy::off();
    let mut spend = session(&spend_policy, &mut counter, &clock, &blocks, 60_000_000);
    let err = sign_ab(
        &a,
        &b,
        built.psbt,
        &wallet.receive,
        &built.policy,
        &mut spend,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        SignError::Verify(VerifyError::FeeTooHigh {
            fee_sats: 50_000_000,
            ..
        })
    ));
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);
}

#[test]
fn s12_rbf_bump_runs_full_verification() {
    let wallet = default_wallet();
    let (a, _, b, _) = pair_signers(&wallet);
    let spend_policy = SpendPolicy::off();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(100));

    let original = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let mut counter = ready_counter();
    let mut spend = session(&spend_policy, &mut counter, &clock, &blocks, 100_000);
    let signed = sign_ab(
        &a,
        &b,
        original.psbt,
        &wallet.receive,
        &original.policy,
        &mut spend,
    )
    .unwrap();
    let tx1 = finalize(&signed, &wallet.receive, &original.policy).unwrap();

    let bumped = build_psbt(&wallet, 0, 0, 5, 100_000, 39_000, 2_000);
    let mut counter = ready_counter();
    let mut spend = session(&spend_policy, &mut counter, &clock, &blocks, 100_000);
    let signed = sign_ab(
        &a,
        &b,
        bumped.psbt,
        &wallet.receive,
        &bumped.policy,
        &mut spend,
    )
    .unwrap();
    let tx2 = finalize(&signed, &wallet.receive, &bumped.policy).unwrap();

    assert_eq!(tx1.input[0].previous_output, tx2.input[0].previous_output);
    assert_eq!(tx1.input[0].sequence, Sequence::ENABLE_RBF_NO_LOCKTIME);
    assert!(tx2.output.iter().map(|o| o.value.to_sat()).sum::<u64>() < 99_000);
}

#[test]
fn consensus_rejects_swapped_signatures() {
    let wallet = default_wallet();
    let idx = index_where_a_sorts_after_b(&wallet);
    let built = build_psbt(&wallet, idx, 0, 5, 100_000, 40_000, 1_000);
    let (mut signed, policy) = sign_both(&wallet, built);
    let keys: Vec<PublicKey> = signed.inputs[0].partial_sigs.keys().copied().collect();
    assert_eq!(keys.len(), 2);
    let s0 = signed.inputs[0].partial_sigs[&keys[0]];
    let s1 = signed.inputs[0].partial_sigs[&keys[1]];
    signed.inputs[0].partial_sigs.insert(keys[0], s1);
    signed.inputs[0].partial_sigs.insert(keys[1], s0);
    assert_eq!(
        finalize(&signed, &wallet.receive, &policy).unwrap_err(),
        SignError::ConsensusRejected
    );
}

#[test]
fn final_feerate_boundary_is_strict_greater() {
    let wallet = default_wallet();
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let (signed, mut policy) = sign_both(&wallet, built);
    let tx = finalize(&signed, &wallet.receive, &policy).unwrap();
    let fee = signed.fee().unwrap().to_sat();
    let exact = fee.div_ceil((tx.vsize() as u64).max(1));
    policy.max_feerate = exact;
    finalize(&signed, &wallet.receive, &policy).unwrap();
    policy.max_feerate = exact - 1;
    let err = finalize(&signed, &wallet.receive, &policy).unwrap_err();
    assert_eq!(
        err,
        SignError::FinalFeerateTooHigh {
            feerate_sat_vb: exact,
            max_sat_vb: exact - 1,
        }
    );
}

#[test]
fn finalize_error_paths() {
    let wallet = default_wallet();
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let policy = built.policy.clone();
    let (a, _, b, _) = pair_signers(&wallet);

    assert_eq!(
        finalize(&built.psbt, "not-a-descriptor", &policy).unwrap_err(),
        SignError::Verify(VerifyError::from(
            trinity_verify::parse("not-a-descriptor").unwrap_err()
        ))
    );

    let empty = Psbt::from_unsigned_tx(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    })
    .unwrap();
    assert_eq!(
        finalize(&empty, &wallet.receive, &policy).unwrap_err(),
        SignError::EmptyPsbt
    );

    let only_a = sign_a(&a, built.psbt.clone(), &wallet.receive, &policy).unwrap();
    assert_eq!(
        finalize(&only_a, &wallet.receive, &policy).unwrap_err(),
        SignError::IncompleteWitness { input_index: 0 }
    );

    let txid = built.psbt.unsigned_tx.compute_txid();
    let signed = sign_b(&b, only_a, txid, &wallet.receive, &policy).unwrap();

    let mut no_utxo = signed.clone();
    no_utxo.inputs[0].witness_utxo = None;
    assert_eq!(
        finalize(&no_utxo, &wallet.receive, &policy).unwrap_err(),
        SignError::MissingWitnessUtxo { input_index: 0 }
    );

    let mut no_script = signed.clone();
    no_script.inputs[0].witness_script = None;
    assert_eq!(
        finalize(&no_script, &wallet.receive, &policy).unwrap_err(),
        SignError::MissingWitnessScript { input_index: 0 }
    );

    let mut bad_script = signed.clone();
    bad_script.inputs[0].witness_script = Some(ScriptBuf::new());
    assert_eq!(
        finalize(&bad_script, &wallet.receive, &policy).unwrap_err(),
        SignError::WitnessScriptMismatch { input_index: 0 }
    );

    let mut bad_spk = signed.clone();
    bad_spk.inputs[0]
        .witness_utxo
        .as_mut()
        .expect("signed input has witness_utxo")
        .script_pubkey = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x11; 20]));
    assert_eq!(
        finalize(&bad_spk, &wallet.receive, &policy).unwrap_err(),
        SignError::Verify(VerifyError::MismatchedUtxo { input_index: 0 })
    );

    let mut no_der = signed.clone();
    no_der.inputs[0].bip32_derivation.clear();
    assert_eq!(
        finalize(&no_der, &wallet.receive, &policy).unwrap_err(),
        SignError::MissingDerivation { input_index: 0 }
    );

    let mut short_path = signed.clone();
    for src in short_path.inputs[0].bip32_derivation.values_mut() {
        src.1 = DerivationPath::from_str("m/0").unwrap();
    }
    assert_eq!(
        finalize(&short_path, &wallet.receive, &policy).unwrap_err(),
        SignError::InvalidDerivationPath { input_index: 0 }
    );

    // Exactly two components is the minimum valid tail (`branch/index`).
    // Kills `n < 2` → `n <= 2`.
    let mut two_comp = signed.clone();
    for src in two_comp.inputs[0].bip32_derivation.values_mut() {
        src.1 = DerivationPath::from_str("m/0/0").unwrap();
    }
    finalize(&two_comp, &wallet.receive, &policy).unwrap();

    let mut hard_last = signed.clone();
    for src in hard_last.inputs[0].bip32_derivation.values_mut() {
        let mut c: Vec<ChildNumber> = src.1.clone().into();
        let n = c.len();
        c[n - 1] = ChildNumber::Hardened { index: 0 };
        src.1 = c.into();
    }
    assert_eq!(
        finalize(&hard_last, &wallet.receive, &policy).unwrap_err(),
        SignError::InvalidDerivationPath { input_index: 0 }
    );

    let mut hard_branch = signed.clone();
    for src in hard_branch.inputs[0].bip32_derivation.values_mut() {
        let mut c: Vec<ChildNumber> = src.1.clone().into();
        let n = c.len();
        c[n - 2] = ChildNumber::Hardened { index: 0 };
        src.1 = c.into();
    }
    assert_eq!(
        finalize(&hard_branch, &wallet.receive, &policy).unwrap_err(),
        SignError::InvalidDerivationPath { input_index: 0 }
    );

    let mut branch2 = signed.clone();
    for src in branch2.inputs[0].bip32_derivation.values_mut() {
        let mut c: Vec<ChildNumber> = src.1.clone().into();
        let n = c.len();
        c[n - 2] = ChildNumber::Normal { index: 2 };
        src.1 = c.into();
    }
    assert_eq!(
        finalize(&branch2, &wallet.receive, &policy).unwrap_err(),
        SignError::InvalidDerivationPath { input_index: 0 }
    );

    let mut no_change_policy = policy.clone();
    no_change_policy.change_descriptor = None;
    let mut change_branch = signed.clone();
    for src in change_branch.inputs[0].bip32_derivation.values_mut() {
        let mut c: Vec<ChildNumber> = src.1.clone().into();
        let n = c.len();
        c[n - 2] = ChildNumber::Normal { index: 1 };
        src.1 = c.into();
    }
    assert_eq!(
        finalize(&change_branch, &wallet.receive, &no_change_policy).unwrap_err(),
        SignError::InvalidDerivationPath { input_index: 0 }
    );

    let mut bad_change = policy.clone();
    bad_change.change_descriptor = Some("not-a-descriptor".into());
    let mut change_in = signed.clone();
    for src in change_in.inputs[0].bip32_derivation.values_mut() {
        let mut c: Vec<ChildNumber> = src.1.clone().into();
        let n = c.len();
        c[n - 2] = ChildNumber::Normal { index: 1 };
        src.1 = c.into();
    }
    assert!(matches!(
        finalize(&change_in, &wallet.receive, &bad_change).unwrap_err(),
        SignError::Verify(_)
    ));

    let mut non_all = signed.clone();
    for sig in non_all.inputs[0].partial_sigs.values_mut() {
        sig.sighash_type = EcdsaSighashType::None;
    }
    assert_eq!(
        finalize(&non_all, &wallet.receive, &policy).unwrap_err(),
        SignError::NonSighashAll { input_index: 0 }
    );

    let mut extra_in = signed.clone();
    extra_in.unsigned_tx.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
    assert!(matches!(
        finalize(&extra_in, &wallet.receive, &policy).unwrap_err(),
        SignError::Verify(VerifyError::InconsistentPsbt { .. })
    ));

    let mut no_fee = signed.clone();
    let in_sats = no_fee.inputs[0]
        .witness_utxo
        .as_ref()
        .unwrap()
        .value
        .to_sat();
    no_fee.unsigned_tx.output[0].value = Amount::from_sat(in_sats);
    no_fee.unsigned_tx.output[1].value = Amount::from_sat(0);
    assert_eq!(
        finalize(&no_fee, &wallet.receive, &policy).unwrap_err(),
        SignError::UnbalancedPsbt
    );
}

#[test]
fn finalize_rejects_witness_utxo_not_matching_known_utxos() {
    let wallet = default_wallet();
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let (signed, policy) = sign_both(&wallet, built);

    let mut empty = policy.clone();
    empty.known_utxos.clear();
    assert_eq!(
        finalize(&signed, &wallet.receive, &empty).unwrap_err(),
        SignError::Verify(VerifyError::UnknownInput { input_index: 0 })
    );

    let mut wrong_op = policy.clone();
    let original = wrong_op
        .known_utxos
        .remove(&signed.unsigned_tx.input[0].previous_output);
    assert!(original.is_some());
    assert_eq!(
        finalize(&signed, &wallet.receive, &wrong_op).unwrap_err(),
        SignError::Verify(VerifyError::UnknownInput { input_index: 0 })
    );

    let mut value_mismatch = signed.clone();
    value_mismatch.inputs[0]
        .witness_utxo
        .as_mut()
        .expect("signed input has witness_utxo")
        .value = Amount::from_sat(1);
    assert_eq!(
        finalize(&value_mismatch, &wallet.receive, &policy).unwrap_err(),
        SignError::Verify(VerifyError::MismatchedUtxo { input_index: 0 })
    );

    let mut script_mismatch = signed.clone();
    script_mismatch.inputs[0]
        .witness_utxo
        .as_mut()
        .expect("signed input has witness_utxo")
        .script_pubkey = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x22; 20]));
    assert_eq!(
        finalize(&script_mismatch, &wallet.receive, &policy).unwrap_err(),
        SignError::Verify(VerifyError::MismatchedUtxo { input_index: 0 })
    );
}

#[test]
fn derive_error_from_huge_index() {
    let wallet = default_wallet();
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let (mut signed, policy) = sign_both(&wallet, built);
    for src in signed.inputs[0].bip32_derivation.values_mut() {
        let mut c: Vec<ChildNumber> = src.1.clone().into();
        let n = c.len();
        c[n - 1] = ChildNumber::Normal { index: 0x7000_0000 };
        src.1 = c.into();
    }
    assert!(matches!(
        finalize(&signed, &wallet.receive, &policy).unwrap_err(),
        SignError::Verify(VerifyError::Derive(_)) | SignError::WitnessScriptMismatch { .. }
    ));
}
