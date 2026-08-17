//! P4, S9, S10 and the remaining LocalSigner / sign_a / sign_b paths.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint as BtcFingerprint, KeySource, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::transaction::Version;
use bitcoin::{
    ecdsa, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use proptest::prelude::*;
use trinity_keystore::{encrypt, FakePlatformKeyStore};
use trinity_types::{Fingerprint, KeySlot, SecretBytes, WordCount};
use trinity_verify::{
    derive_at, parse, DerivationBranch, ParsedDescriptor, VerifyError, VerifyPolicy,
};

use crate::sign::preflight_inputs;
use crate::sign::{check_key_a_signatures, sign_a, sign_b};
use crate::{
    sign_ab, FakeBlockHeightSource, FakeClock, LocalSigner, SignError, Signer, SignerKind,
    SpendPolicy, SpendSession, WindowCounter,
};
use trinity_types::Balance;

const KEK_A: [u8; 32] = [0x11; 32];
const KEK_B: [u8; 32] = [0x22; 32];
const ENTROPY_A: [u8; 32] = [0xA0; 32];
const ENTROPY_B: [u8; 32] = [0xB0; 32];
const ENTROPY_C: [u8; 32] = [0xC0; 32];

// ---------------------------------------------------------------------------
// BIP-380 checksum (test-only; production descriptors come from trinity-watch)
// ---------------------------------------------------------------------------

const INPUT_CHARSET: &[u8] = b"0123456789()[],'/*abcdefgh@:$%{}\
IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~\
ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u64; 5] = [
    0x00_00_f5_de_e5_19_89,
    0x00_00_a9_fd_ca_33_12,
    0x00_00_1b_ab_10_e3_2d,
    0x00_00_37_06_b1_67_7a,
    0x00_00_64_4d_62_6f_fd,
];

fn expand(s: &str) -> Vec<u64> {
    let mut groups: Vec<u64> = Vec::new();
    let mut symbols: Vec<u64> = Vec::new();
    for c in s.bytes() {
        let v = INPUT_CHARSET.iter().position(|&x| x == c).expect("charset") as u64;
        symbols.push(v & 31);
        groups.push(v >> 5);
        if groups.len() == 3 {
            symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
            groups.clear();
        }
    }
    if groups.len() == 1 {
        symbols.push(groups[0]);
    } else if groups.len() == 2 {
        symbols.push(groups[0] * 3 + groups[1]);
    }
    symbols
}

fn polymod(symbols: &[u64]) -> u64 {
    let mut chk: u64 = 1;
    for &value in symbols {
        let top = chk >> 35;
        chk = ((chk & 0x7_ff_ff_ff_ff) << 5) ^ value;
        for (i, gen) in GENERATOR.iter().enumerate() {
            if ((top >> i) & 1) == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

#[test]
fn bip380_expand_remainder_lengths() {
    // Leftover group flushes: 0, 1, and 2 (payload length mod 3).
    let zero = with_checksum("wsh");
    let one = with_checksum("w");
    let two = with_checksum("ws");
    assert!(zero.contains('#'));
    assert!(one.contains('#'));
    assert!(two.contains('#'));
    assert_ne!(one, two);
    assert_ne!(zero, one);
}

fn with_checksum(script: &str) -> String {
    let mut symbols = expand(script);
    symbols.extend(std::iter::repeat_n(0u64, 8));
    let checksum_val = polymod(&symbols) ^ 1;
    let mut out = String::with_capacity(script.len() + 9);
    out.push_str(script);
    out.push('#');
    for i in 0..8 {
        let shift = 5 * (7 - i);
        let idx = ((checksum_val >> shift) & 31) as usize;
        out.push(CHECKSUM_CHARSET[idx] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

pub(crate) struct KeyMat {
    pub(crate) entropy: Vec<u8>,
    pub(crate) fp: Fingerprint,
    pub(crate) xpub: String,
}

pub(crate) struct WalletFixture {
    pub(crate) a: KeyMat,
    pub(crate) b: KeyMat,
    pub(crate) receive: String,
    pub(crate) change: String,
}

fn key_mat(entropy: &[u8]) -> KeyMat {
    let material = trinity_entropy::bip39_from_entropy(entropy).unwrap();
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Regtest, material.seed.as_slice()).unwrap();
    let fp = Fingerprint::new(master.fingerprint(&secp).to_bytes());
    let origin = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let account = master.derive_priv(&secp, &origin).unwrap();
    let xpub = Xpub::from_priv(&secp, &account).to_string();
    KeyMat {
        entropy: entropy.to_vec(),
        fp,
        xpub,
    }
}

fn wallet_from_entropies(ea: &[u8], eb: &[u8], ec: &[u8]) -> WalletFixture {
    let a = key_mat(ea);
    let b = key_mat(eb);
    let c = key_mat(ec);
    let key =
        |k: &KeyMat, branch: &str| format!("[{}/48'/1'/0'/2']{}/{}", k.fp.to_hex(), k.xpub, branch);
    let recv_body = format!(
        "wsh(sortedmulti(2,{},{},{}))",
        key(&a, "0/*"),
        key(&b, "0/*"),
        key(&c, "0/*")
    );
    let chg_body = format!(
        "wsh(sortedmulti(2,{},{},{}))",
        key(&a, "1/*"),
        key(&b, "1/*"),
        key(&c, "1/*")
    );
    WalletFixture {
        a,
        b,
        receive: with_checksum(&recv_body),
        change: with_checksum(&chg_body),
    }
}

pub(crate) fn default_wallet() -> WalletFixture {
    wallet_from_entropies(&ENTROPY_A, &ENTROPY_B, &ENTROPY_C)
}

fn blob_for(slot: KeySlot, kek: &[u8; 32], entropy: &[u8], wc: WordCount) -> Vec<u8> {
    encrypt(kek, slot, wc, 0, entropy, 0).unwrap()
}

fn signer_for(
    slot: KeySlot,
    fp: Fingerprint,
    kek: &[u8; 32],
    entropy: &[u8],
    wc: WordCount,
    fake: Arc<FakePlatformKeyStore>,
) -> LocalSigner {
    LocalSigner::new(
        slot,
        fp,
        fake,
        SecretBytes::from_slice(kek),
        blob_for(slot, kek, entropy, wc),
    )
    .unwrap()
}

pub(crate) fn bip32_derivation_for(
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
        let fp = BtcFingerprint::from(key_expr.fingerprint.to_bytes());
        map.insert(pk, (fp, path));
    }
    map
}

pub(crate) fn outpoint(n: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([n; 32]),
        vout: 0,
    }
}

pub(crate) struct BuiltPsbt {
    pub(crate) psbt: Psbt,
    pub(crate) policy: VerifyPolicy,
}

pub(crate) fn build_psbt(
    wallet: &WalletFixture,
    input_index: u32,
    change_index: u32,
    recipient_index: u32,
    input_sats: u64,
    send_sats: u64,
    fee_sats: u64,
) -> BuiltPsbt {
    let recv = parse(&wallet.receive).unwrap();
    let chg = parse(&wallet.change).unwrap();
    let in_der = derive_at(&recv, input_index).unwrap();
    let ch_der = derive_at(&chg, change_index).unwrap();
    let recip_der = derive_at(&recv, recipient_index).unwrap();
    let recip_addr = recip_der.address(Network::Regtest).to_string();
    let change_sats = input_sats - send_sats - fee_sats;
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
            TxOut {
                value: Amount::from_sat(send_sats),
                script_pubkey: recip_der.script_pubkey.clone(),
            },
            TxOut {
                value: Amount::from_sat(change_sats),
                script_pubkey: ch_der.script_pubkey.clone(),
            },
        ],
    };
    let witness_utxo = TxOut {
        value: Amount::from_sat(input_sats),
        script_pubkey: in_der.script_pubkey.clone(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(witness_utxo.clone());
    psbt.inputs[0].witness_script = Some(in_der.witness_script.clone());
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
        Some(wallet.change.clone()),
        Network::Regtest,
    );
    BuiltPsbt { psbt, policy }
}

pub(crate) fn pair_signers(
    wallet: &WalletFixture,
) -> (
    LocalSigner,
    Arc<FakePlatformKeyStore>,
    LocalSigner,
    Arc<FakePlatformKeyStore>,
) {
    let fake_a = Arc::new(FakePlatformKeyStore::new());
    let fake_b = Arc::new(FakePlatformKeyStore::new());
    let a = signer_for(
        KeySlot::A,
        wallet.a.fp,
        &KEK_A,
        &wallet.a.entropy,
        WordCount::Words24,
        fake_a.clone(),
    );
    let b = signer_for(
        KeySlot::B,
        wallet.b.fp,
        &KEK_B,
        &wallet.b.entropy,
        WordCount::Words24,
        fake_b.clone(),
    );
    (a, fake_a, b, fake_b)
}

// ---------------------------------------------------------------------------
// Happy path + P4
// ---------------------------------------------------------------------------

#[test]
fn sign_a_then_sign_b_produces_two_partial_sigs() {
    let wallet = default_wallet();
    let (a, fake_a, b, fake_b) = pair_signers(&wallet);
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let txid = built.psbt.unsigned_tx.compute_txid();
    let signed_a = sign_a(&a, built.psbt, &wallet.receive, &built.policy).unwrap();
    assert_eq!(fake_a.unwrap_kek_calls(), 1);
    assert_eq!(signed_a.inputs[0].partial_sigs.len(), 1);
    let signed_ab = sign_b(&b, signed_a, txid, &wallet.receive, &built.policy).unwrap();
    assert_eq!(fake_b.unwrap_kek_calls(), 1);
    assert_eq!(signed_ab.inputs[0].partial_sigs.len(), 2);
    assert_eq!(
        signed_ab.inputs[0].sighash_type,
        Some(PsbtSighashType::from(EcdsaSighashType::All))
    );

    let again = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let mut counter = WindowCounter::new(SecretBytes::from_slice(&[0x7Au8; 32])).unwrap();
    counter.set_passphrase_used_since_install(true);
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(100));
    let policy = SpendPolicy::off();
    let mut spend = SpendSession {
        policy: &policy,
        counter: &mut counter,
        clock: &clock,
        blocks: &blocks,
        balance: Balance {
            confirmed_sats: 100_000,
            trusted_pending_sats: 0,
            untrusted_pending_sats: 0,
            immature_sats: 0,
        },
        wall_unix_ns: None,
    };
    let via_ab = sign_ab(
        &a,
        &b,
        again.psbt,
        &wallet.receive,
        &again.policy,
        &mut spend,
    )
    .unwrap();
    assert_eq!(via_ab.inputs[0].partial_sigs.len(), 2);
}

#[test]
fn p4_sign_is_bit_identical() {
    let wallet = default_wallet();
    let (a, _, _, _) = pair_signers(&wallet);
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let first = a.sign(built.psbt.clone()).unwrap();
    let second = a.sign(built.psbt).unwrap();
    assert_eq!(first.serialize(), second.serialize());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn p4_sign_determinism_over_random_keys(
        ea in prop::array::uniform32(1u8..=255u8),
        eb in prop::array::uniform32(1u8..=255u8),
        ec in prop::array::uniform32(1u8..=255u8),
        send in 10_000u64..40_000u64,
    ) {
        prop_assume!(ea != eb && eb != ec && ea != ec);
        let wallet = wallet_from_entropies(&ea, &eb, &ec);
        prop_assume!(wallet.a.fp != wallet.b.fp && wallet.b.fp != key_mat(&ec).fp);
        let fake = Arc::new(FakePlatformKeyStore::new());
        let signer = signer_for(
            KeySlot::A,
            wallet.a.fp,
            &KEK_A,
            &wallet.a.entropy,
            WordCount::Words24,
            fake,
        );
        let built = build_psbt(&wallet, 0, 1, 4, 100_000, send, 1_000);
        let first = signer.sign(built.psbt.clone()).unwrap();
        let second = signer.sign(built.psbt).unwrap();
        prop_assert_eq!(first.serialize(), second.serialize());
    }
}

#[test]
fn words12_blob_signs() {
    let ea = [0x12u8; 16];
    let wallet = wallet_from_entropies(&ea, &ENTROPY_B, &ENTROPY_C);
    let fake = Arc::new(FakePlatformKeyStore::new());
    let signer = signer_for(
        KeySlot::A,
        wallet.a.fp,
        &KEK_A,
        &ea,
        WordCount::Words12,
        fake,
    );
    let built = build_psbt(&wallet, 0, 0, 5, 80_000, 30_000, 1_000);
    let signed = signer.sign(built.psbt).unwrap();
    assert_eq!(signed.inputs[0].partial_sigs.len(), 1);
}

// ---------------------------------------------------------------------------
// S9 / S10
// ---------------------------------------------------------------------------

#[test]
fn s9_manipulated_change_output_blocks_before_key_access() {
    let wallet = default_wallet();
    let (a, fake_a, _, _) = pair_signers(&wallet);
    let mut built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    // Foreign change: replace the change SPK with a P2WPKH that is not ours.
    let foreign_spk = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x42; 20]));
    built.psbt.unsigned_tx.output[1].script_pubkey = foreign_spk;
    fake_a.reset_calls();
    let err = sign_a(&a, built.psbt, &wallet.receive, &built.policy).unwrap_err();
    assert_eq!(
        err,
        SignError::Verify(VerifyError::ForeignChangeOutput { output_index: 1 })
    );
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
}

#[test]
fn s10_manipulation_between_a_and_b_is_detected() {
    let wallet = default_wallet();
    let (a, _, b, fake_b) = pair_signers(&wallet);
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let txid = built.psbt.unsigned_tx.compute_txid();
    let mut signed_a = sign_a(&a, built.psbt, &wallet.receive, &built.policy).unwrap();
    // Locktime is not a V-check; the txid comparison is what must fire.
    signed_a.unsigned_tx.lock_time = LockTime::from_height(100_000).unwrap();
    fake_b.reset_calls();
    let err = sign_b(&b, signed_a, txid, &wallet.receive, &built.policy).unwrap_err();
    assert_eq!(err, SignError::UnsignedTxChanged);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);
}

#[test]
fn sign_b_rejects_missing_or_wrong_a_signature() {
    let wallet = default_wallet();
    let (a, _, b, fake_b) = pair_signers(&wallet);
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let txid = built.psbt.unsigned_tx.compute_txid();

    fake_b.reset_calls();
    let err = sign_b(&b, built.psbt.clone(), txid, &wallet.receive, &built.policy).unwrap_err();
    assert_eq!(err, SignError::UnexpectedKeyASignature);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);

    let mut signed_a = sign_a(&a, built.psbt, &wallet.receive, &built.policy).unwrap();
    signed_a.inputs[0].partial_sigs.clear();
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
    let msg = bitcoin::secp256k1::Message::from_digest([8u8; 32]);
    let sig = secp.sign_ecdsa(&msg, &sk);
    signed_a.inputs[0]
        .partial_sigs
        .insert(pk, ecdsa::Signature::sighash_all(sig));
    fake_b.reset_calls();
    let err = sign_b(&b, signed_a, txid, &wallet.receive, &built.policy).unwrap_err();
    assert_eq!(err, SignError::UnexpectedKeyASignature);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);
}

#[test]
fn check_key_a_signatures_maps_parse_error() {
    let wallet = default_wallet();
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let err = check_key_a_signatures(&built.psbt, "not-a-descriptor").unwrap_err();
    assert!(matches!(err, SignError::Verify(_)));
}

#[test]
fn sign_a_non_all_is_verify_error_without_unwrap() {
    let wallet = default_wallet();
    let (a, fake_a, _, _) = pair_signers(&wallet);
    let mut built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    built.psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::None));
    fake_a.reset_calls();
    let err = sign_a(&a, built.psbt, &wallet.receive, &built.policy).unwrap_err();
    assert!(matches!(
        err,
        SignError::Verify(VerifyError::NonSighashAll { input_index: 0 })
    ));
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
}

// ---------------------------------------------------------------------------
// Signer::sign structural / key-material errors
// ---------------------------------------------------------------------------

#[test]
fn sign_rejects_non_all_sighash_without_verify() {
    let wallet = default_wallet();
    let (a, fake_a, _, _) = pair_signers(&wallet);
    let mut built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    built.psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::None));
    fake_a.reset_calls();
    let err = a.sign(built.psbt).unwrap_err();
    assert_eq!(err, SignError::NonSighashAll { input_index: 0 });
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
}

#[test]
fn sign_rejects_non_all_partial_sig() {
    let wallet = default_wallet();
    let (a, fake_a, _, _) = pair_signers(&wallet);
    let mut built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[3u8; 32]).unwrap();
    let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
    let msg = bitcoin::secp256k1::Message::from_digest([4u8; 32]);
    let sig = secp.sign_ecdsa(&msg, &sk);
    built.psbt.inputs[0].partial_sigs.insert(
        pk,
        ecdsa::Signature {
            signature: sig,
            sighash_type: EcdsaSighashType::None,
        },
    );
    fake_a.reset_calls();
    let err = a.sign(built.psbt).unwrap_err();
    assert_eq!(err, SignError::NonSighashAll { input_index: 0 });
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
}

#[test]
fn sign_rejects_nonstandard_sighash_field() {
    let wallet = default_wallet();
    let (a, _, _, _) = pair_signers(&wallet);
    let mut built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    built.psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0xFF));
    assert_eq!(
        a.sign(built.psbt).unwrap_err(),
        SignError::NonSighashAll { input_index: 0 }
    );
}

#[test]
fn sign_platform_error_after_preflight() {
    let wallet = default_wallet();
    let fake = Arc::new(FakePlatformKeyStore::new());
    fake.fail_unwrap(trinity_keystore::PlatformError::UnwrapRejected);
    let a = signer_for(
        KeySlot::A,
        wallet.a.fp,
        &KEK_A,
        &wallet.a.entropy,
        WordCount::Words24,
        fake.clone(),
    );
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let err = a.sign(built.psbt).unwrap_err();
    assert_eq!(
        err,
        SignError::Platform(trinity_keystore::PlatformError::UnwrapRejected)
    );
    assert_eq!(fake.unwrap_kek_calls(), 1);
}

#[test]
fn sign_invalid_kek_length() {
    let wallet = default_wallet();
    let fake = Arc::new(FakePlatformKeyStore::new());
    fake.succeed_unwrap_with(vec![0xAA; 8]);
    let a = signer_for(
        KeySlot::A,
        wallet.a.fp,
        &KEK_A,
        &wallet.a.entropy,
        WordCount::Words24,
        fake,
    );
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    assert_eq!(a.sign(built.psbt).unwrap_err(), SignError::InvalidKekLength);
}

#[test]
fn sign_blob_aead_on_wrong_kek() {
    let wallet = default_wallet();
    let fake = Arc::new(FakePlatformKeyStore::new());
    fake.succeed_unwrap_with(vec![0x99; 32]);
    let a = signer_for(
        KeySlot::A,
        wallet.a.fp,
        &KEK_A,
        &wallet.a.entropy,
        WordCount::Words24,
        fake,
    );
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    assert!(matches!(
        a.sign(built.psbt).unwrap_err(),
        SignError::Blob(_)
    ));
}

#[test]
fn sign_fingerprint_mismatch() {
    let wallet = default_wallet();
    let fake = Arc::new(FakePlatformKeyStore::new());
    let wrong_fp = Fingerprint::new([0xFF; 4]);
    let a = signer_for(
        KeySlot::A,
        wrong_fp,
        &KEK_A,
        &wallet.a.entropy,
        WordCount::Words24,
        fake,
    );
    let mut built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    // Preflight looks up wrong_fp — inject it so we reach unlock.
    let dummy_pk = SecpPublicKey::from_slice(&[
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ])
    .unwrap();
    built.psbt.inputs[0].bip32_derivation.insert(
        dummy_pk,
        (
            BtcFingerprint::from(wrong_fp.to_bytes()),
            DerivationPath::from_str("m/48'/1'/0'/2'/0/0").unwrap(),
        ),
    );
    assert_eq!(
        a.sign(built.psbt).unwrap_err(),
        SignError::FingerprintMismatch
    );
}

#[test]
fn sign_slot_mismatch_after_decrypt() {
    let wallet = default_wallet();
    let fake = Arc::new(FakePlatformKeyStore::new());
    // Blob sealed as B, signer claims A.
    let blob_b = blob_for(KeySlot::B, &KEK_A, &wallet.a.entropy, WordCount::Words24);
    let a = LocalSigner::new(
        KeySlot::A,
        wallet.a.fp,
        fake,
        SecretBytes::from_slice(&KEK_A),
        blob_b,
    )
    .unwrap();
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    assert_eq!(a.sign(built.psbt).unwrap_err(), SignError::InvalidSlot);
}

#[test]
fn sign_pubkey_mismatch() {
    let wallet = default_wallet();
    let (a, _, _, _) = pair_signers(&wallet);
    let mut built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    // Replace our derivation entry's pubkey with a different one, keep the fp.
    let our_fp = BtcFingerprint::from(wallet.a.fp.to_bytes());
    let old_key = *built.psbt.inputs[0]
        .bip32_derivation
        .iter()
        .find(|(_, (fp, _))| *fp == our_fp)
        .unwrap()
        .0;
    let source = built.psbt.inputs[0]
        .bip32_derivation
        .remove(&old_key)
        .unwrap();
    let dummy_pk = SecpPublicKey::from_slice(&[
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ])
    .unwrap();
    built.psbt.inputs[0]
        .bip32_derivation
        .insert(dummy_pk, source);
    assert_eq!(
        a.sign(built.psbt).unwrap_err(),
        SignError::PubkeyMismatch { input_index: 0 }
    );
}

#[test]
fn check_key_a_signatures_rejects_non_all() {
    let wallet = default_wallet();
    let (a, _, _, _) = pair_signers(&wallet);
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let mut signed_a = a.sign(built.psbt).unwrap();
    let pk = *signed_a.inputs[0].partial_sigs.keys().next().unwrap();
    let mut sig = signed_a.inputs[0].partial_sigs[&pk];
    sig.sighash_type = EcdsaSighashType::None;
    signed_a.inputs[0].partial_sigs.insert(pk, sig);
    assert_eq!(
        check_key_a_signatures(&signed_a, &wallet.receive).unwrap_err(),
        SignError::NonSighashAll { input_index: 0 }
    );
}

#[test]
fn signer_trait_object_and_kind() {
    let wallet = default_wallet();
    let (a, _, _, _) = pair_signers(&wallet);
    let s: &dyn Signer = &a;
    assert_eq!(s.kind(), SignerKind::Local);
    assert_eq!(s.fingerprint(), wallet.a.fp);
}

#[test]
fn preflight_non_all_is_independent_of_verify() {
    let wallet = default_wallet();
    let built = build_psbt(&wallet, 0, 0, 5, 100_000, 40_000, 1_000);
    let mut psbt = built.psbt;
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::Single));
    assert_eq!(
        preflight_inputs(&psbt, wallet.a.fp).unwrap_err(),
        SignError::NonSighashAll { input_index: 0 }
    );
}
