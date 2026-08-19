//! D10 / D11 — `finalize` against Core `finalizepsbt` / `testmempoolaccept`.
//!
//! D10 input PSBTs are built with `WatchWallet::build_psbt_raw_with_aux_rand`
//! and [`trinity_watch::PSBT_BUILD_SEED`] (Spec §3.2 / §5.1).

#![allow(clippy::print_stderr)]

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bdk_wallet::bitcoin::key::rand::{rngs::StdRng, SeedableRng};
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint as BtcFingerprint, KeySource, Xpriv, Xpub};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{PublicKey as SecpPublicKey, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use trinity_differential::rpc::{connect, fund_address};
use trinity_differential::rpc_signer::{finalize_psbt_extract, test_mempool_accept};
use trinity_differential::{D10_PSBTS, D7D8_SEED};
use trinity_keystore::{encrypt, FakePlatformKeyStore};
use trinity_types::{
    FeeTarget, Fingerprint, KeySlot, KeychainKind, SecretBytes, SendRequest, WordCount,
};
use trinity_verify::{derive_at, parse, DerivationBranch, ParsedDescriptor, VerifyPolicy};
use trinity_watch::{WatchWallet, PSBT_BUILD_SEED};

use crate::finalize;
use crate::LocalSigner;

const KEK_A: [u8; 32] = [0x11; 32];
const KEK_B: [u8; 32] = [0x22; 32];

// ---------------------------------------------------------------------------
// BIP-380 checksum (same algorithm as `tests_d7_d8.rs`)
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

struct KeyMat {
    entropy: Vec<u8>,
    fp: Fingerprint,
    xpub: String,
}

struct WalletFixture {
    a: KeyMat,
    b: KeyMat,
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
    KeyMat {
        entropy: entropy.to_vec(),
        fp,
        xpub,
    }
}

fn d10_wallet() -> WalletFixture {
    let a = key_mat(&entropy_from_tag(1));
    let b = key_mat(&entropy_from_tag(2));
    let c = key_mat(&entropy_from_tag(3));
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

fn sign_ab_local(fixture: &WalletFixture, psbt: Psbt) -> Psbt {
    let a = signer_for(KeySlot::A, fixture.a.fp, &KEK_A, &fixture.a.entropy);
    let b = signer_for(KeySlot::B, fixture.b.fp, &KEK_B, &fixture.b.entropy);
    let after_a = crate::Signer::sign(&a, psbt).unwrap();
    crate::Signer::sign(&b, after_a).unwrap()
}

fn policy_from_psbt(
    psbt: &Psbt,
    recipient: String,
    send_sats: u64,
    change: String,
) -> VerifyPolicy {
    let mut known = BTreeMap::new();
    for (input, txin) in psbt.inputs.iter().zip(psbt.unsigned_tx.input.iter()) {
        known.insert(
            txin.previous_output,
            input.witness_utxo.clone().expect("witness_utxo"),
        );
    }
    VerifyPolicy::new(
        vec![recipient],
        send_sats,
        1_000_000,
        10_000,
        None,
        20,
        known,
        Some(change),
        Network::Regtest,
    )
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

#[test]
fn d10_finalize_against_finalizepsbt() {
    let node = connect();
    let fixture = d10_wallet();

    let started = Instant::now();
    let mut compared = 0u32;
    for i in 0..D10_PSBTS {
        if i > 0 && i % 100 == 0 {
            eprintln!(
                "D10 progress: {i}/{D10_PSBTS} PSBTs, {:?}",
                started.elapsed()
            );
        }
        let mut ww = WatchWallet::from_descriptor_strings(
            trinity_types::Network::Regtest,
            &fixture.receive,
            &fixture.change,
        )
        .unwrap();
        ww.inject_confirmed_utxo(200_000 + u64::from(i) * 17, KeychainKind::External)
            .unwrap();
        let recip = ww.peek_address(KeychainKind::External, 5).address;
        let send = 40_000 + (u64::from(i) * 13) % 30_000;
        let fee = 1_000 + u64::from(i % 200);
        let mut rng = StdRng::seed_from_u64(PSBT_BUILD_SEED);
        let psbt = ww
            .build_psbt_raw_with_aux_rand(
                &SendRequest::new(recip.clone(), send, FeeTarget::AbsoluteSats(fee)),
                &mut rng,
            )
            .unwrap_or_else(|e| panic!("D10 build_psbt failed at i={i}: {e}"));
        let policy = policy_from_psbt(&psbt, recip, send, fixture.change.clone());
        let signed = sign_ab_local(&fixture, psbt);
        let ours = finalize(&signed, &fixture.receive, &policy)
            .unwrap_or_else(|e| panic!("D10 finalize failed at i={i}: {e:?}"));
        let core_hex = finalize_psbt_extract(&node, &signed);
        assert_eq!(serialize(&ours), core_hex, "D10 raw-tx mismatch at i={i}");
        compared += 1;
    }

    let elapsed = started.elapsed();
    eprintln!("D10: {compared} PSBTs bit-identical to Core finalizepsbt in {elapsed:?}");
    assert_eq!(compared, D10_PSBTS);
    assert!(
        elapsed < Duration::from_secs(20 * 60),
        "D10 runtime {elapsed:?} exceeded the 20-minute acceptance cap"
    );
}

#[test]
fn d11_testmempoolaccept_allows_finalized() {
    let node = connect();
    let fixture = d10_wallet();
    let recv = parse(&fixture.receive).unwrap();
    let chg = parse(&fixture.change).unwrap();
    let in_der = derive_at(&recv, 0).unwrap();
    let addr = in_der.address(Network::Regtest);
    let fund_sats = 10_000_000u64;
    let (fund_txid, fund_tx) = fund_address(&addr, fund_sats);
    let vout = fund_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == in_der.script_pubkey)
        .expect("funding vout");
    let input_sats = fund_tx.output[vout].value.to_sat();
    let op = OutPoint {
        txid: fund_txid,
        vout: vout as u32,
    };

    let started = Instant::now();
    let mut accepted = 0u32;
    for i in 0..D10_PSBTS {
        if i > 0 && i % 100 == 0 {
            eprintln!("D11 progress: {i}/{D10_PSBTS} txs, {:?}", started.elapsed());
        }
        let send = 3_000_000 + u64::from(i) * 100;
        let fee = 1_000 + u64::from(i % 500);
        let change_sats = input_sats - send - fee;
        let recip = derive_at(&recv, 5).unwrap();
        let ch_der = derive_at(&chg, i % 20).unwrap();
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
                    value: Amount::from_sat(send),
                    script_pubkey: recip.script_pubkey.clone(),
                },
                TxOut {
                    value: Amount::from_sat(change_sats),
                    script_pubkey: ch_der.script_pubkey.clone(),
                },
            ],
        };
        let utxo = TxOut {
            value: Amount::from_sat(input_sats),
            script_pubkey: in_der.script_pubkey.clone(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(utxo.clone());
        psbt.inputs[0].witness_script = Some(in_der.witness_script.clone());
        psbt.inputs[0].bip32_derivation = bip32_derivation_for(&recv, 0);
        psbt.outputs[1].bip32_derivation = bip32_derivation_for(&chg, i % 20);

        let mut known = BTreeMap::new();
        known.insert(op, utxo);
        let policy = VerifyPolicy::new(
            vec![recip.address(Network::Regtest).to_string()],
            send,
            50_000,
            10_000,
            None,
            20,
            known,
            Some(fixture.change.clone()),
            Network::Regtest,
        );
        let signed = sign_ab_local(&fixture, psbt);
        let ours = finalize(&signed, &fixture.receive, &policy)
            .unwrap_or_else(|e| panic!("D11 finalize failed at i={i}: {e:?}"));
        let (allowed, reason) = test_mempool_accept(&node, &ours);
        assert!(allowed, "D11 testmempoolaccept rejected i={i}: {reason:?}");
        accepted += 1;
    }

    let elapsed = started.elapsed();
    eprintln!("D11: {accepted} finalized txs allowed by testmempoolaccept in {elapsed:?}");
    assert_eq!(accepted, D10_PSBTS);
}
