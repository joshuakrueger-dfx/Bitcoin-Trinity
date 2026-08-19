//! Bitcoin Core 30.2 JSON-RPC helpers for D4 (and later D-tests).
//!
//! Endpoint: `http://127.0.0.1:18443`, user `trinity`, password `regtest`
//! (WP-02 compose stack). Wallet RPCs go to `/wallet/<name>`.

use bitcoincore_rpc::json::{ImportDescriptors, ImportMultiResult, Timestamp};
use bitcoincore_rpc::jsonrpc;
use bitcoincore_rpc::{Auth, Client, Error as RpcError, RpcApi};
use serde_json::json;

/// Host RPC URL of the WP-02 regtest node.
pub const RPC_URL: &str = "http://127.0.0.1:18443";
/// RPC username (compose / `scripts/test-env.sh`).
pub const RPC_USER: &str = "trinity";
/// RPC password (compose / `scripts/test-env.sh`).
pub const RPC_PASS: &str = "regtest";

/// Connect to the node and fail loudly if the environment is not up.
pub fn connect() -> Client {
    let client = Client::new(RPC_URL, auth()).unwrap_or_else(|e| {
        panic!(
            "D4: cannot connect to Core RPC at {RPC_URL}: {e}\n\
             start with `./scripts/test-env.sh up` (user {RPC_USER})"
        );
    });
    if let Err(e) = client.get_blockchain_info() {
        panic!(
            "D4: Core RPC at {RPC_URL} is not answering ({e})\n\
             start with `./scripts/test-env.sh up` (user {RPC_USER})"
        );
    }
    client
}

/// Fresh descriptor wallet (`disable_private_keys`, `blank`, `descriptors=true`).
///
/// `label` distinguishes rotation batches. The process id avoids collisions
/// across local re-runs.
pub fn create_descriptor_wallet(node: &Client, label: &str) -> (String, Client) {
    let name = format!("trinity_d4_{}_{label}", std::process::id());
    // bitcoincore-rpc 0.19 `create_wallet` omits the Core 0.21+ `descriptors`
    // flag. Pass it explicitly — Core 30.2 defaults to true, but the WP asks
    // for `descriptors=true` in the call.
    let args = [
        json!(name),
        json!(true),  // disable_private_keys
        json!(true),  // blank
        json!(""),    // passphrase
        json!(false), // avoid_reuse
        json!(true),  // descriptors
    ];
    // A short transport blip (empty HTTP body) is retried; a real Core
    // rejection is not.
    let mut last_err = None;
    for attempt in 1..=4 {
        match node.call::<bitcoincore_rpc::json::LoadWalletResult>("createwallet", &args) {
            Ok(_) => {
                last_err = None;
                break;
            }
            Err(e) => {
                // "already exists" is a Core RPC string, not a distinct variant.
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
        panic!("D4: createwallet({name}, descriptors=true) failed: {e}");
    }
    let wallet_url = format!("{RPC_URL}/wallet/{name}");
    let wallet = Client::new(&wallet_url, auth()).unwrap_or_else(|e| {
        panic!("D4: cannot open wallet RPC {wallet_url}: {e}");
    });
    (name, wallet)
}

/// Unload a wallet created by [`create_descriptor_wallet`]. Errors are ignored
/// — leftover files live in the ephemeral compose volume.
pub fn unload_wallet(node: &Client, name: &str) {
    let _ = node.unload_wallet(Some(name));
}

/// Import a ranged receive descriptor (`[0, 999]`) without a rescan.
pub fn import_receive_descriptor(wallet: &Client, descriptor: &str) -> Vec<ImportMultiResult> {
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
            Ok(results) => return results,
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
        "D4: importdescriptors failed: {}\ninput={descriptor}",
        last_err.expect("importdescriptors error")
    );
}

/// One `deriveaddresses(desc, [0, 999])` call — 1_000 addresses.
pub fn derive_receive_addresses(client: &Client, descriptor: &str) -> Vec<String> {
    let mut last_err = None;
    for attempt in 1..=4 {
        match client.derive_addresses(descriptor, Some([0, crate::ADDR_END])) {
            Ok(addrs) => {
                return addrs
                    .into_iter()
                    .map(|a| a.assume_checked().to_string())
                    .collect();
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
        "D4: deriveaddresses failed: {}\ninput={descriptor}",
        last_err.expect("deriveaddresses error")
    );
}

pub(crate) fn auth() -> Auth {
    Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned())
}

/// RPC client for the `miner` wallet created by `scripts/test-env.sh`.
pub fn miner_wallet() -> Client {
    let url = format!("{RPC_URL}/wallet/miner");
    Client::new(&url, auth()).unwrap_or_else(|e| {
        panic!(
            "cannot open miner wallet at {url}: {e}\n\
             start with `./scripts/test-env.sh up`"
        );
    })
}

/// Send `sats` from the miner wallet to `address` and mine one confirming block.
///
/// Returns `(txid, raw funding transaction)`.
pub fn fund_address(
    address: &bitcoin::Address,
    sats: u64,
) -> (bitcoin::Txid, bitcoin::Transaction) {
    use bitcoincore_rpc::RpcApi;

    let node = connect();
    let miner = miner_wallet();
    let txid = miner
        .send_to_address(
            address,
            bitcoin::Amount::from_sat(sats),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("fund_address: send_to_address failed: {e}"));
    let sink = miner
        .get_new_address(None, None)
        .unwrap_or_else(|e| panic!("fund_address: miner getnewaddress: {e}"))
        .require_network(bitcoin::Network::Regtest)
        .unwrap_or_else(|e| panic!("fund_address: sink network: {e}"));
    node.generate_to_address(1, &sink)
        .unwrap_or_else(|e| panic!("fund_address: generate_to_address: {e}"));
    let tx = node
        .get_raw_transaction(&txid, None)
        .unwrap_or_else(|e| panic!("fund_address: get_raw_transaction: {e}"));
    (txid, tx)
}

/// Transient HTTP/socket failure (`jsonrpc::Error::Transport`), not a Core RPC
/// rejection. `bitcoincore-rpc` 0.19 re-exports `jsonrpc` (`pub extern crate`)
/// and wraps it as `Error::JsonRpc` — match the variant, not the Display text.
pub(crate) fn is_transport_error(err: &RpcError) -> bool {
    matches!(err, RpcError::JsonRpc(jsonrpc::Error::Transport(_)))
}
