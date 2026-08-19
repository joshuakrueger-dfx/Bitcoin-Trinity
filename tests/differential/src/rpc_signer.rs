//! Bitcoin Core 30.2 JSON-RPC helpers for D7/D8 (`walletprocesspsbt`).
//!
//! Separate from [`crate::rpc`] so D4's watch-only wallet path stays
//! untouched. Wallets created here keep private keys enabled.

use std::str::FromStr;

use bitcoin::psbt::Psbt;
use bitcoincore_rpc::json::{
    ImportDescriptors, ImportMultiResult, Timestamp, WalletProcessPsbtResult,
};
use bitcoincore_rpc::{Client, RpcApi};
use serde_json::json;

use crate::rpc::{auth, is_transport_error, RPC_URL};

/// Fresh descriptor wallet that can hold private keys (`blank`, `descriptors=true`).
///
/// Unlike [`crate::rpc::create_descriptor_wallet`], `disable_private_keys` is
/// **false** — D7/D8 import an `xprv` and call `walletprocesspsbt`.
pub fn create_signing_wallet(node: &Client, label: &str) -> (String, Client) {
    let name = format!("trinity_d78_{}_{label}", std::process::id());
    let args = [
        json!(name),
        json!(false), // disable_private_keys — signing needs the xprv
        json!(true),  // blank
        json!(""),    // passphrase
        json!(false), // avoid_reuse
        json!(true),  // descriptors
    ];
    let mut last_err = None;
    for attempt in 1..=4 {
        match node.call::<bitcoincore_rpc::json::LoadWalletResult>("createwallet", &args) {
            Ok(_) => {
                last_err = None;
                break;
            }
            Err(e) => {
                if e.to_string().contains("already exists") {
                    let _ = node.load_wallet(&name);
                    last_err = None;
                    break;
                }
                let retry = attempt < 4 && is_transport_error(&e);
                last_err = Some(e);
                if retry {
                    std::thread::sleep(std::time::Duration::from_millis(200 * attempt));
                    continue;
                }
                break;
            }
        }
    }
    if let Some(e) = last_err {
        panic!("D7/D8: createwallet({name}, descriptors=true, private keys) failed: {e}");
    }
    let wallet_url = format!("{RPC_URL}/wallet/{name}");
    let wallet = Client::new(&wallet_url, auth()).unwrap_or_else(|e| {
        panic!("D7/D8: cannot open wallet RPC {wallet_url}: {e}");
    });
    (name, wallet)
}

/// Import a ranged private descriptor (`[0, 999]`) without a rescan.
///
/// `active` is false: Core only needs the key material to sign the supplied
/// PSBT, not to generate addresses.
pub fn import_private_descriptor(wallet: &Client, descriptor: &str) -> Vec<ImportMultiResult> {
    let req = ImportDescriptors {
        descriptor: descriptor.to_owned(),
        timestamp: Timestamp::Now,
        active: Some(false),
        range: Some((0, crate::ADDR_END as usize)),
        next_index: None,
        internal: Some(false),
        label: None,
    };
    let mut last_err = None;
    for attempt in 1..=4 {
        match wallet.import_descriptors(req.clone()) {
            Ok(results) => {
                assert!(
                    results.len() == 1 && results[0].success,
                    "D7/D8 importdescriptors unsuccessful\ninput={descriptor}\nresult={results:?}"
                );
                return results;
            }
            Err(e) => {
                let retry = attempt < 4 && is_transport_error(&e);
                last_err = Some(e);
                if retry {
                    std::thread::sleep(std::time::Duration::from_millis(200 * attempt));
                    continue;
                }
                break;
            }
        }
    }
    panic!(
        "D7/D8: importdescriptors (private) failed: {}\ninput={descriptor}",
        last_err.expect("importdescriptors error")
    );
}

/// `walletprocesspsbt` with `sign=true`, `SIGHASH_ALL`, no extra BIP-32
/// derivations, **no finalize** (partial signatures must stay in the PSBT).
pub fn wallet_process_psbt(wallet: &Client, psbt: &Psbt) -> Psbt {
    let b64 = psbt.to_string();
    // bitcoincore-rpc 0.19 omits the Core `finalize` argument. Pass it
    // explicitly so a later 1-of-1 vector cannot swallow `partial_sigs`.
    let args = [
        json!(b64),
        json!(true),  // sign
        json!("ALL"), // sighashtype
        json!(false), // bip32derivs
        json!(false), // finalize
    ];
    let mut last_err = None;
    for attempt in 1..=4 {
        match wallet.call::<WalletProcessPsbtResult>("walletprocesspsbt", &args) {
            Ok(result) => {
                return Psbt::from_str(&result.psbt).unwrap_or_else(|e| {
                    panic!(
                        "D7/D8: Core walletprocesspsbt returned an undecodable PSBT: {e}\ninput={b64}"
                    );
                });
            }
            Err(e) => {
                let retry = attempt < 4 && is_transport_error(&e);
                last_err = Some(e);
                if retry {
                    std::thread::sleep(std::time::Duration::from_millis(200 * attempt));
                    continue;
                }
                break;
            }
        }
    }
    panic!(
        "D7/D8: walletprocesspsbt failed: {}\ninput={b64}",
        last_err.expect("walletprocesspsbt error")
    );
}

/// `finalizepsbt` with `extract=true`. Returns the raw transaction bytes.
pub fn finalize_psbt_extract(client: &Client, psbt: &Psbt) -> Vec<u8> {
    use bitcoincore_rpc::json::FinalizePsbtResult;

    let b64 = psbt.to_string();
    let mut last_err = None;
    for attempt in 1..=4 {
        match client.finalize_psbt(&b64, Some(true)) {
            Ok(FinalizePsbtResult {
                hex: Some(hex),
                complete: true,
                ..
            }) => return hex,
            Ok(other) => panic!(
                "D10: finalizepsbt did not extract a complete tx\nresult={other:?}\ninput={b64}"
            ),
            Err(e) => {
                let retry = attempt < 4 && is_transport_error(&e);
                last_err = Some(e);
                if retry {
                    std::thread::sleep(std::time::Duration::from_millis(200 * attempt));
                    continue;
                }
                break;
            }
        }
    }
    panic!(
        "D10: finalizepsbt failed: {}\ninput={b64}",
        last_err.expect("finalizepsbt error")
    );
}

/// `testmempoolaccept` for one raw transaction. Panics if the node rejects
/// the RPC itself; the caller asserts `allowed`.
pub fn test_mempool_accept(client: &Client, tx: &bitcoin::Transaction) -> (bool, Option<String>) {
    use bitcoincore_rpc::json::TestMempoolAcceptResult;

    let mut last_err = None;
    for attempt in 1..=4 {
        match client.test_mempool_accept(&[tx]) {
            Ok(results) => {
                assert_eq!(
                    results.len(),
                    1,
                    "D11: testmempoolaccept returned {}",
                    results.len()
                );
                let TestMempoolAcceptResult {
                    allowed,
                    reject_reason,
                    ..
                } = results.into_iter().next().expect("one result");
                return (allowed, reject_reason);
            }
            Err(e) => {
                let retry = attempt < 4 && is_transport_error(&e);
                last_err = Some(e);
                if retry {
                    std::thread::sleep(std::time::Duration::from_millis(200 * attempt));
                    continue;
                }
                break;
            }
        }
    }
    panic!(
        "D11: testmempoolaccept failed: {}",
        last_err.expect("testmempoolaccept error")
    );
}
