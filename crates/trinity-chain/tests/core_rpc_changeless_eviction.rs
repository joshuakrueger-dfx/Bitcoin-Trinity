//! Incremental Core-RPC sync must not evict a living changeless spend.
//!
//! A payment with no change, spending an output created before the sync
//! start-checkpoint, used to land in `evicted_ats` even while it was still
//! in the mempool (and the confirmed funding tx was evicted with it). That
//! was a false eviction: `known_outpoints` was filled only from the current
//! run. This test now asserts the correct behaviour.
//!
//! A missing node is a failure unless `TRINITY_SKIP_LIVE` is set.

use std::process::Command;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use bitcoin::bip32::Xpriv;
use bitcoin::{Address, FeeRate, Network as BtcNetwork};
use trinity_chain::{ChainBackend, CoreRpcBackend, CoreRpcConfig};

const RPC_URL: &str = "http://127.0.0.1:18443";
const RPC_USER: &str = "trinity";
const RPC_PASS: &str = "regtest";

/// Amount funded to the watch address before the changeless drain.
const FUND_SATS: u64 = 2_500_000;

fn regtest_up() -> bool {
    rpc_call(None, "getblockchaininfo", "[]").is_ok()
}

/// Run against a live node, or fail. Set `TRINITY_SKIP_LIVE=1` to skip
/// explicitly (counts as a pass). A missing node without that variable is a
/// failure, not a silent green.
fn require_live_regtest() -> bool {
    if regtest_up() {
        return true;
    }
    if std::env::var_os("TRINITY_SKIP_LIVE").is_some() {
        eprintln!("skip: regtest RPC not reachable at {RPC_URL} (TRINITY_SKIP_LIVE)");
        return false;
    }
    panic!(
        "regtest RPC not reachable at {RPC_URL}. Run `./scripts/test-env.sh up` \
         or set TRINITY_SKIP_LIVE=1 to skip this live test."
    );
}

fn rpc_call(wallet: Option<&str>, method: &str, params_json: &str) -> Result<String, String> {
    let url = match wallet {
        Some(w) => format!("{RPC_URL}/wallet/{w}"),
        None => RPC_URL.to_string(),
    };
    let body = format!(
        r#"{{"jsonrpc":"1.0","id":"trinity-evict","method":"{method}","params":{params_json}}}"#
    );
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "--user",
            &format!("{RPC_USER}:{RPC_PASS}"),
            "--data-binary",
            &body,
            "-H",
            "content-type: text/plain;",
            &url,
        ])
        .output()
        .map_err(|e| format!("curl spawn: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.is_empty() {
        return Err("empty RPC response".into());
    }
    Ok(text)
}

fn rpc_result(wallet: Option<&str>, method: &str, params_json: &str) -> serde_json::Value {
    let text = rpc_call(wallet, method, params_json).unwrap_or_else(|e| panic!("{method}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!("{method} json: {e}; body={text}");
    });
    assert!(v["error"].is_null(), "{method} error: {text}");
    v["result"].clone()
}

fn ensure_miner_wallet() {
    let _ = rpc_call(
        None,
        "createwallet",
        r#"["miner", false, false, "", false, true, true]"#,
    );
    let _ = rpc_call(None, "loadwallet", r#"["miner"]"#);
}

fn make_wallet() -> Wallet {
    let mut seed = [0u8; 32];
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos()
        .to_le_bytes();
    seed[..16].copy_from_slice(&nanos);
    let pid = std::process::id().to_le_bytes();
    seed[16..20].copy_from_slice(&pid);
    seed[20..28].copy_from_slice(b"NETREPRO");
    seed[28..32].copy_from_slice(&[0x0e, 0x0f, 0x10, 0x11]);

    let xprv = Xpriv::new_master(BtcNetwork::Regtest, &seed).expect("xprv");
    let ext = format!("wpkh({xprv}/84'/1'/0'/0/*)");
    let int = format!("wpkh({xprv}/84'/1'/0'/1/*)");
    Wallet::create(ext, int)
        .network(BtcNetwork::Regtest)
        .create_wallet_no_persist()
        .expect("create wallet")
}

fn connect_backend() -> CoreRpcBackend {
    CoreRpcBackend::connect(CoreRpcConfig::user_pass(RPC_URL, RPC_USER, RPC_PASS))
        .expect("connect Core RPC")
}

fn tx_in_mempool_or_chain(txid: &str) -> bool {
    let mempool = rpc_result(None, "getrawmempool", "[]");
    if mempool
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str() == Some(txid)))
        .unwrap_or(false)
    {
        return true;
    }
    match rpc_call(None, "getrawtransaction", &format!(r#"["{txid}"]"#)) {
        Ok(text) => {
            let v: serde_json::Value =
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
            v["error"].is_null() && v["result"].is_string()
        }
        Err(_) => false,
    }
}

/// A changeless payment whose input was funded in a block before the sync
/// start-checkpoint must stay out of `evicted_ats` while it still lives in
/// the mempool (or chain).
#[test]
fn changeless_spend_from_pre_checkpoint_input_is_not_marked_evicted() {
    if !require_live_regtest() {
        return;
    }
    ensure_miner_wallet();
    let backend = connect_backend();

    let mut wallet = make_wallet();
    let addr_info = wallet.reveal_next_address(KeychainKind::External);
    let receive_spk = addr_info.script_pubkey();
    let addr = addr_info.address.to_string();

    let fund_btc = format!("{:.8}", FUND_SATS as f64 / 100_000_000.0);
    let fund_txid = rpc_result(
        Some("miner"),
        "sendtoaddress",
        &format!(r#"["{addr}", {fund_btc}]"#),
    );
    let fund_txid = fund_txid.as_str().expect("fund txid").to_owned();

    let miner_addr = rpc_result(Some("miner"), "getnewaddress", "[]");
    let miner_addr = miner_addr.as_str().expect("miner addr");
    rpc_result(
        Some("miner"),
        "generatetoaddress",
        &format!(r#"[1, "{miner_addr}"]"#),
    );

    let req = wallet.start_full_scan().build();
    let update = backend.full_scan(req).expect("full_scan after funding");
    wallet.apply_update(update).expect("apply funding");
    assert_eq!(
        wallet.balance().confirmed.to_sat(),
        FUND_SATS,
        "wallet must hold the confirmed funding UTXO before the drain"
    );

    let funding_height = wallet.latest_checkpoint().height();
    eprintln!(
        "funded {FUND_SATS} sats to {addr} via {fund_txid}; wallet checkpoint height={funding_height}"
    );

    // Changeless drain: every input, single output, no change. Spec §3.2
    // prefers this shape (BnB finds changeless solutions).
    let dest = rpc_result(Some("miner"), "getnewaddress", "[]");
    let dest = dest.as_str().expect("drain dest");
    let dest_addr = Address::from_str(dest)
        .expect("dest parse")
        .require_network(BtcNetwork::Regtest)
        .expect("dest network");

    let mut builder = wallet.build_tx();
    builder
        .drain_wallet()
        .drain_to(dest_addr.script_pubkey())
        .fee_rate(FeeRate::from_sat_per_vb(1).expect("1 sat/vb"));
    let mut psbt = builder.finish().expect("drain psbt");
    let signed = wallet
        .sign(&mut psbt, SignOptions::default())
        .expect("sign drain");
    assert!(signed, "descriptor xprv must finalize the drain");
    let spend_tx = psbt.extract_tx().expect("extract drain");
    let spend_txid = spend_tx.compute_txid();

    assert_eq!(
        spend_tx.output.len(),
        1,
        "drain must be changeless (single output); outputs={:?}",
        spend_tx
            .output
            .iter()
            .map(|o| o.script_pubkey.to_string())
            .collect::<Vec<_>>()
    );
    assert_ne!(
        spend_tx.output[0].script_pubkey, receive_spk,
        "drain output must not land on the funded receive script"
    );
    eprintln!(
        "changeless spend {spend_txid} outputs={} value={}",
        spend_tx.output.len(),
        spend_tx.output[0].value
    );

    backend
        .broadcast(&spend_tx)
        .expect("sendrawtransaction of drain");
    let last_seen = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    wallet.apply_unconfirmed_txs([(spend_tx, last_seen)]);

    // Unrelated mempool payment: must stay irrelevant. A mutated relevance
    // check that lets every input-bearing mempool tx through would otherwise
    // still pass on the fixture spend alone.
    let decoy_addr = rpc_result(Some("miner"), "getnewaddress", "[]");
    let decoy_addr = decoy_addr.as_str().expect("decoy addr");
    let decoy = rpc_result(
        Some("miner"),
        "sendtoaddress",
        &format!(r#"["{decoy_addr}", 0.00010000]"#),
    );
    let decoy_txid: bitcoin::Txid = decoy
        .as_str()
        .expect("decoy txid")
        .parse()
        .expect("decoy parse");

    let spend_hex = spend_txid.to_string();
    assert!(
        tx_in_mempool_or_chain(&spend_hex),
        "drain {spend_hex} must still exist in mempool or chain before sync — \
         otherwise this is not a reproduction of a false eviction"
    );

    // Incremental sync starts at the wallet tip (the funding block). FilterIter
    // walks *after* that checkpoint, so the funding outpoint is not re-learned
    // into `known_outpoints` and the changeless spend is not relevant.
    let sync_req = wallet.start_sync_with_revealed_spks().build();
    let sync_update = backend.sync(sync_req).expect("sync after drain");

    let evicted: Vec<_> = sync_update
        .tx_update
        .evicted_ats
        .iter()
        .map(|(t, _)| *t)
        .collect();
    eprintln!(
        "sync evicted_ats={evicted:?}; present txs={:?}",
        sync_update
            .tx_update
            .txs
            .iter()
            .map(|tx| tx.compute_txid())
            .collect::<Vec<_>>()
    );

    assert!(
        tx_in_mempool_or_chain(&spend_hex),
        "drain {spend_hex} is still in mempool/chain after sync"
    );
    assert!(
        sync_update
            .tx_update
            .txs
            .iter()
            .any(|tx| tx.compute_txid() == spend_txid),
        "scan must surface the living changeless spend {spend_txid} as relevant"
    );
    assert!(
        sync_update
            .tx_update
            .txs
            .iter()
            .all(|tx| tx.compute_txid() != decoy_txid),
        "unrelated mempool tx {decoy_txid} must not be treated as relevant"
    );
    assert!(
        !evicted.contains(&spend_txid),
        "living changeless spend {spend_txid} must not be marked evicted; \
         evicted_ats={evicted:?}"
    );
    let fund_parsed: bitcoin::Txid = fund_txid.parse().expect("fund txid");
    assert!(
        !evicted.contains(&fund_parsed),
        "confirmed funding {fund_txid} must not be evicted just because it \
         sits before the incremental checkpoint; evicted_ats={evicted:?}"
    );
}
