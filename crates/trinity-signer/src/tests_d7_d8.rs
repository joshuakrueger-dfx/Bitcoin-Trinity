//! D7 / D8 — `sign_a` / `sign_b` against Core `walletprocesspsbt`.
//!
//! Lives **inside** this crate under `#[cfg(all(test, feature = "differential"))]`
//! so it can call crate-internal `sign_a` / `sign_b` without widening the
//! public surface (Spec: those functions remain crate-internal). The
//! external `tests/differential/` crate cannot see `pub(crate)` items.
//! RPC helpers come from `trinity-differential` (path dev-dep, feature
//! `differential`).
//!
//! Spec §5.1: bit-identical signatures vs Core `walletprocesspsbt`
//! (RFC 6979 + low-R grind, same as `sign_ecdsa_low_r`).

#![allow(clippy::print_stderr)] // progress, same role as D4's eprintln

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint as BtcFingerprint, KeySource, Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{PublicKey as SecpPublicKey, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use trinity_differential::rpc::{connect, unload_wallet};
use trinity_differential::rpc_signer::{
    create_signing_wallet, import_private_descriptor, wallet_process_psbt,
};
use trinity_differential::{D7D8_PSBTS, D7D8_SEED};
use trinity_keystore::{encrypt, FakePlatformKeyStore};
use trinity_types::{Fingerprint, KeySlot, SecretBytes, WordCount};
use trinity_verify::{derive_at, parse, DerivationBranch, ParsedDescriptor, VerifyPolicy};

use crate::sign::{sign_a, sign_b};
use crate::LocalSigner;

const KEK_A: [u8; 32] = [0x11; 32];
const KEK_B: [u8; 32] = [0x22; 32];

// ---------------------------------------------------------------------------
// BIP-380 checksum (test-only; same algorithm as `tests_wp33.rs`)
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
// Fixture — same derivation chain as `tests_wp33.rs` `key_mat` /
// `wallet_from_entropies`, entropy mixed from [`D7D8_SEED`].
// ---------------------------------------------------------------------------

struct KeyMat {
    entropy: Vec<u8>,
    fp: Fingerprint,
    xpub: String,
    xprv: String,
}

struct WalletFixture {
    a: KeyMat,
    b: KeyMat,
    c: KeyMat,
    receive: String,
    change: String,
}

fn entropy_from_tag(tag: u32) -> [u8; 32] {
    let mut material = [0u8; 12];
    material[..8].copy_from_slice(&D7D8_SEED.to_be_bytes());
    material[8..].copy_from_slice(&tag.to_be_bytes());
    sha256::Hash::hash(&material).to_byte_array()
}

fn key_mat(entropy: &[u8]) -> KeyMat {
    let material = trinity_entropy::bip39_from_entropy(entropy).unwrap();
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Regtest, material.seed.as_slice()).unwrap();
    let fp = Fingerprint::new(master.fingerprint(&secp).to_bytes());
    let origin = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let account = master.derive_priv(&secp, &origin).unwrap();
    let xpub = Xpub::from_priv(&secp, &account).to_string();
    let xprv = account.to_string();
    KeyMat {
        entropy: entropy.to_vec(),
        fp,
        xpub,
        xprv,
    }
}

fn d7d8_wallet() -> WalletFixture {
    let a = key_mat(&entropy_from_tag(1));
    let b = key_mat(&entropy_from_tag(2));
    let c = key_mat(&entropy_from_tag(3));
    assert_ne!(a.fp, b.fp);
    assert_ne!(b.fp, c.fp);
    assert_ne!(a.fp, c.fp);
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
        c,
        receive: with_checksum(&recv_body),
        change: with_checksum(&chg_body),
    }
}

/// Private `wsh(sortedmulti(2,…))` receive descriptor with exactly one xprv.
fn core_private_receive(wallet: &WalletFixture, private: KeySlot) -> String {
    let expr = |k: &KeyMat, use_xprv: bool| {
        let material = if use_xprv { &k.xprv } else { &k.xpub };
        format!("[{}/48'/1'/0'/2']{}/0/*", k.fp.to_hex(), material)
    };
    let body = format!(
        "wsh(sortedmulti(2,{},{},{}))",
        expr(&wallet.a, private == KeySlot::A),
        expr(&wallet.b, private == KeySlot::B),
        expr(&wallet.c, false)
    );
    with_checksum(&body)
}

fn blob_for(slot: KeySlot, kek: &[u8; 32], entropy: &[u8]) -> Vec<u8> {
    encrypt(kek, slot, WordCount::Words24, 0, entropy, 0).unwrap()
}

fn signer_for(slot: KeySlot, fp: Fingerprint, kek: &[u8; 32], entropy: &[u8]) -> LocalSigner {
    let fake = Arc::new(FakePlatformKeyStore::new());
    LocalSigner::new(
        slot,
        fp,
        fake,
        SecretBytes::from_slice(kek),
        blob_for(slot, kek, entropy),
    )
    .unwrap()
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
        let fp = BtcFingerprint::from(key_expr.fingerprint.to_bytes());
        map.insert(pk, (fp, path));
    }
    map
}

struct BuiltPsbt {
    psbt: Psbt,
    policy: VerifyPolicy,
    label: String,
}

/// Deterministic PSBT variant `i` in `0..D7D8_PSBTS`.
///
/// Varies input / change / recipient indices and amounts. Fabricated
/// `witness_utxo` — Core signs from the PSBT, not the chain.
fn build_psbt(wallet: &WalletFixture, i: u32) -> BuiltPsbt {
    let input_index = i;
    let change_index = i;
    let recipient_index = (i + 1) % D7D8_PSBTS;
    let input_sats = 100_000 + u64::from(i) * 17;
    let fee_sats = 1_000 + u64::from(i % 500);
    let send_sats = 40_000 + (u64::from(i) * 13) % 30_000;
    debug_assert!(input_sats > send_sats + fee_sats);

    let recv = parse(&wallet.receive).unwrap();
    let chg = parse(&wallet.change).unwrap();
    let in_der = derive_at(&recv, input_index).unwrap();
    let ch_der = derive_at(&chg, change_index).unwrap();
    let recip_der = derive_at(&recv, recipient_index).unwrap();
    let recip_addr = recip_der.address(Network::Regtest).to_string();
    let change_sats = input_sats - send_sats - fee_sats;
    let op = OutPoint {
        txid: Txid::from_byte_array([(i as u8).wrapping_add(1).max(1); 32]),
        vout: i % 4,
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
        D7D8_PSBTS,
        known,
        Some(wallet.change.clone()),
        Network::Regtest,
    );
    BuiltPsbt {
        psbt,
        policy,
        label: format!(
            "i={i} in={input_index} chg={change_index} recv={recipient_index} \
             input_sats={input_sats} send_sats={send_sats} fee_sats={fee_sats}"
        ),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn derivation_for_fingerprint(psbt: &Psbt, fp: Fingerprint) -> (PublicKey, DerivationPath) {
    let want = fp.to_bytes();
    let (pk, path) = psbt.inputs[0]
        .bip32_derivation
        .iter()
        .find_map(|(pk, (got, path))| {
            if *got.as_bytes() == want {
                Some((*pk, path.clone()))
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("missing bip32_derivation for fingerprint {}", fp.to_hex()));
    (PublicKey::new(pk), path)
}

fn partial_sig_bytes(psbt: &Psbt, fp: Fingerprint) -> Vec<u8> {
    let (pk, _) = derivation_for_fingerprint(psbt, fp);
    let sig = psbt.inputs[0].partial_sigs.get(&pk).unwrap_or_else(|| {
        panic!(
            "missing partial_sig for fingerprint {} pubkey={pk}",
            fp.to_hex()
        )
    });
    sig.to_vec()
}

fn assert_sigs_bit_identical(id: &str, input: &str, expected_core: &[u8], actual: &[u8]) {
    assert_eq!(
        actual,
        expected_core,
        "{id} signature mismatch\ninput={input}\nexpected (core)={}\nactual={}",
        hex_bytes(expected_core),
        hex_bytes(actual),
    );
}

// ---------------------------------------------------------------------------
// D7 / D8
// ---------------------------------------------------------------------------

#[test]
fn d7_sign_a_against_walletprocesspsbt() {
    let node = connect();
    let (wallet_name, core_wallet) = create_signing_wallet(&node, "a");
    let fixture = d7d8_wallet();
    import_private_descriptor(&core_wallet, &core_private_receive(&fixture, KeySlot::A));
    let signer = signer_for(KeySlot::A, fixture.a.fp, &KEK_A, &fixture.a.entropy);

    let started = Instant::now();
    let mut compared = 0u32;
    for i in 0..D7D8_PSBTS {
        if i > 0 && i % 100 == 0 {
            eprintln!(
                "D7 progress: {i}/{D7D8_PSBTS} PSBTs, {:?}",
                started.elapsed()
            );
        }
        let built = build_psbt(&fixture, i);
        let ours = sign_a(&signer, built.psbt.clone(), &fixture.receive, &built.policy)
            .unwrap_or_else(|e| panic!("D7 sign_a failed at {}\nerror={e:?}", built.label));
        let core = wallet_process_psbt(&core_wallet, &built.psbt);
        assert_sigs_bit_identical(
            "D7",
            &built.label,
            &partial_sig_bytes(&core, fixture.a.fp),
            &partial_sig_bytes(&ours, fixture.a.fp),
        );
        compared += 1;
    }
    unload_wallet(&node, &wallet_name);

    let elapsed = started.elapsed();
    eprintln!(
        "D7: {compared} PSBTs bit-identical to Core walletprocesspsbt (xprv_A) in {elapsed:?}"
    );
    assert_eq!(compared, D7D8_PSBTS);
    assert!(
        elapsed < Duration::from_secs(20 * 60),
        "D7 runtime {elapsed:?} exceeded the 20-minute acceptance cap"
    );
}

#[test]
fn d8_sign_b_against_walletprocesspsbt() {
    let node = connect();
    let (wallet_name, core_wallet) = create_signing_wallet(&node, "b");
    let fixture = d7d8_wallet();
    import_private_descriptor(&core_wallet, &core_private_receive(&fixture, KeySlot::B));
    let signer_a = signer_for(KeySlot::A, fixture.a.fp, &KEK_A, &fixture.a.entropy);
    let signer_b = signer_for(KeySlot::B, fixture.b.fp, &KEK_B, &fixture.b.entropy);

    let started = Instant::now();
    let mut compared = 0u32;
    for i in 0..D7D8_PSBTS {
        if i > 0 && i % 100 == 0 {
            eprintln!(
                "D8 progress: {i}/{D7D8_PSBTS} PSBTs, {:?}",
                started.elapsed()
            );
        }
        let built = build_psbt(&fixture, i);
        let unsigned_txid = built.psbt.unsigned_tx.compute_txid();
        let after_a = sign_a(
            &signer_a,
            built.psbt.clone(),
            &fixture.receive,
            &built.policy,
        )
        .unwrap_or_else(|e| panic!("D8 sign_a (pre-B) failed at {}\nerror={e:?}", built.label));
        let ours = sign_b(
            &signer_b,
            after_a,
            unsigned_txid,
            &fixture.receive,
            &built.policy,
        )
        .unwrap_or_else(|e| panic!("D8 sign_b failed at {}\nerror={e:?}", built.label));
        // Core signs the unsigned PSBT with xprv_B only. Sighash does not
        // include other partial signatures, so A's presence is irrelevant.
        let core = wallet_process_psbt(&core_wallet, &built.psbt);
        assert_sigs_bit_identical(
            "D8",
            &built.label,
            &partial_sig_bytes(&core, fixture.b.fp),
            &partial_sig_bytes(&ours, fixture.b.fp),
        );
        compared += 1;
    }
    unload_wallet(&node, &wallet_name);

    let elapsed = started.elapsed();
    eprintln!(
        "D8: {compared} PSBTs bit-identical to Core walletprocesspsbt (xprv_B) in {elapsed:?}"
    );
    assert_eq!(compared, D7D8_PSBTS);
    assert!(
        elapsed < Duration::from_secs(20 * 60),
        "D8 runtime {elapsed:?} exceeded the 20-minute acceptance cap"
    );
}
