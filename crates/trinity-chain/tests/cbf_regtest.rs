//! Integration tests for [`CbfBackend`] against a live BIP-157 peer.
//!
//! Expects the WP-02 environment (`./scripts/test-env.sh up`): Core 30.2
//! regtest with `-blockfilterindex=1 -peerblockfilters=1` on P2P
//! `127.0.0.1:18444` and RPC `127.0.0.1:18443` (user `trinity` / pass
//! `regtest`, wallet `miner`).
//!
//! Parallel WP-14/WP-15 sessions may already hold those ports — tests use the
//! loopback peer as-is (project name collision is handled by whoever started
//! the stack). A missing peer is a failure unless `TRINITY_SKIP_LIVE` is set.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bdk_wallet::bitcoin::{self, Amount, Network};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Address, FeeRate};
use trinity_chain::{
    CbfBackend, CbfConfig, ChainBackend, ChainError, CoreRpcBackend, CoreRpcConfig,
};

/// Amount funded to the watch address before the changeless drain.
const FUND_SATS: u64 = 2_500_000;

/// `cbf.rs` `REORG_WALKBACK` is 7. Incremental CBF resumes that many headers
/// behind the wallet tip, so the funding block must sit strictly older than
/// that window or it is re-indexed and the spend looks relevant.
const CBF_REORG_WALKBACK: u32 = 7;

const RPC_URL: &str = "http://127.0.0.1:18443";
const RPC_USER: &str = "trinity";
const RPC_PASS: &str = "regtest";
const P2P_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18444));

/// Live-peer tests share one bitcoind. Parallel mining (full_scan) while another
/// client is mid-`submit_package` can leave bip157 hanging until the wall
/// timeout — serialize access to the regtest peer for those cases.
static REGTEST_LOCK: Mutex<()> = Mutex::new(());

/// Fixed wpkh descriptors for a regtest watch-only wallet (public only — no
/// key material in this crate). Known-good pair from the BDK cookbook.
const RECEIVE: &str = "wpkh([9122d9e0/84'/1'/0']tpubDCYVtmaSaDzTxcgvoP5AHZNbZKZzrvoNH9KARep88vESc6MxRqAp4LmePc2eeGX6XUxBcdhAmkthWTDqygPz2wLAyHWisD299Lkdrj5egY6/0/*)";
const CHANGE: &str = "wpkh([9122d9e0/84'/1'/0']tpubDCYVtmaSaDzTxcgvoP5AHZNbZKZzrvoNH9KARep88vESc6MxRqAp4LmePc2eeGX6XUxBcdhAmkthWTDqygPz2wLAyHWisD299Lkdrj5egY6/1/*)";

fn regtest_up() -> bool {
    rpc_call(None, "getblockchaininfo", "[]").is_ok()
}

/// Live tests run when RPC is up. A missing node is a failure unless
/// `TRINITY_SKIP_LIVE` is set (explicit skip, not a silent green).
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

fn rpc_result(wallet: Option<&str>, method: &str, params_json: &str) -> serde_json::Value {
    let text = rpc_call(wallet, method, params_json).unwrap_or_else(|e| panic!("{method}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!("{method} json: {e}; body={text}");
    });
    assert!(v["error"].is_null(), "{method} error: {text}");
    v["result"].clone()
}

fn rpc_call(wallet: Option<&str>, method: &str, params_json: &str) -> Result<String, String> {
    let url = match wallet {
        Some(w) => format!("{RPC_URL}/wallet/{w}"),
        None => RPC_URL.to_string(),
    };
    let body = format!(
        r#"{{"jsonrpc":"1.0","id":"trinity-cbf","method":"{method}","params":{params_json}}}"#
    );
    let output = Command::new("curl")
        .args([
            "-sS",
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
    if text.contains("\"error\":null") || text.contains("\"error\": null") {
        Ok(text)
    } else if text.is_empty() {
        Err("empty RPC response".into())
    } else {
        Ok(text)
    }
}

fn ensure_miner_wallet() {
    let _ = rpc_call(
        None,
        "createwallet",
        r#"["miner", false, false, "", false, true, true]"#,
    );
    let _ = rpc_call(None, "loadwallet", r#"["miner"]"#);
}

fn data_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trinity-cbf-it-{}-{}", label, std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn make_backend(label: &str) -> CbfBackend {
    let cfg = CbfConfig::regtest_peer(P2P_ADDR)
        .data_dir(data_dir(label))
        .operation_timeout(Duration::from_secs(90));
    CbfBackend::new(cfg).expect("cbf runtime")
}

fn make_signable_wallet() -> Wallet {
    let mut seed = [0u8; 32];
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos()
        .to_le_bytes();
    seed[..16].copy_from_slice(&nanos);
    let pid = std::process::id().to_le_bytes();
    seed[16..20].copy_from_slice(&pid);
    seed[20..28].copy_from_slice(b"CBFREPRO");
    seed[28..32].copy_from_slice(&[0x1c, 0x1d, 0x1e, 0x1f]);

    let xprv = bitcoin::bip32::Xpriv::new_master(Network::Regtest, &seed).expect("xprv");
    let ext = format!("wpkh({xprv}/84'/1'/0'/0/*)");
    let int = format!("wpkh({xprv}/84'/1'/0'/1/*)");
    Wallet::create(ext, int)
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .expect("create wallet")
}

fn mine_blocks(n: u32) {
    let miner_addr = rpc_result(Some("miner"), "getnewaddress", "[]");
    let miner_addr = miner_addr.as_str().expect("miner addr");
    rpc_result(
        Some("miner"),
        "generatetoaddress",
        &format!(r#"[{n}, "{miner_addr}"]"#),
    );
}

fn tx_exists_on_node(txid: &str) -> bool {
    match rpc_call(None, "getrawtransaction", &format!(r#"["{txid}"]"#)) {
        Ok(text) => {
            let v: serde_json::Value =
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
            v["error"].is_null() && v["result"].is_string()
        }
        Err(_) => false,
    }
}

#[test]
fn cbf_tip_height_matches_regtest_peer() {
    if !require_live_regtest() {
        return;
    }
    let _guard = REGTEST_LOCK.lock().expect("regtest lock");
    let body = rpc_call(None, "getblockcount", "[]").expect("getblockcount");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let rpc_height = v["result"].as_u64().expect("height") as u32;

    let backend = make_backend("tip");
    let cbf_height = backend.tip_height().expect("cbf tip_height");
    assert_eq!(
        cbf_height, rpc_height,
        "CBF tip must match bitcoin-cli getblockcount"
    );
    eprintln!("cbf tip_height={cbf_height} == rpc getblockcount={rpc_height}");
}

#[test]
fn cbf_full_scan_balance_matches_funded_address() {
    if !require_live_regtest() {
        return;
    }
    let _guard = REGTEST_LOCK.lock().expect("regtest lock");
    ensure_miner_wallet();

    let mut wallet = Wallet::create(RECEIVE, CHANGE)
        .network(Network::Regtest)
        .lookahead(20)
        .create_wallet_no_persist()
        .expect("wallet");

    // Unique derivation index so re-runs against a persistent regtest chain
    // do not accumulate prior test fundings on index 0.
    let height_body = rpc_call(None, "getblockcount", "[]").expect("getblockcount");
    let height_v: serde_json::Value = serde_json::from_str(&height_body).expect("json");
    let tip = height_v["result"].as_u64().unwrap_or(0) as u32;
    let index = 10 + (tip % 80); // stay within full_scan_script_limit default (200)
    wallet
        .reveal_addresses_to(KeychainKind::External, index)
        .last()
        .expect("reveal");
    let addr = wallet
        .peek_address(KeychainKind::External, index)
        .address
        .to_string();
    eprintln!("funding address {addr} (index {index})");

    // Send 1 BTC from miner to the watch-only address, then mine 1 block.
    let send_body = rpc_call(
        Some("miner"),
        "sendtoaddress",
        &format!(r#"["{addr}", 1.0]"#),
    )
    .expect("sendtoaddress");
    let send_v: serde_json::Value = serde_json::from_str(&send_body).expect("json");
    assert!(
        send_v["error"].is_null(),
        "sendtoaddress error: {send_body}"
    );
    let txid = send_v["result"].as_str().expect("txid");
    eprintln!("funded via txid {txid}");

    let mine_addr_body = rpc_call(Some("miner"), "getnewaddress", "[]").expect("getnewaddress");
    let mine_v: serde_json::Value = serde_json::from_str(&mine_addr_body).expect("json");
    let mine_addr = mine_v["result"].as_str().expect("mine addr");
    let gen_body = rpc_call(
        Some("miner"),
        "generatetoaddress",
        &format!(r#"[1, "{mine_addr}"]"#),
    )
    .expect("generatetoaddress");
    let gen_v: serde_json::Value = serde_json::from_str(&gen_body).expect("json");
    assert!(gen_v["error"].is_null(), "generate error: {gen_body}");
    let height_body = rpc_call(None, "getblockcount", "[]").expect("getblockcount");
    let height_v: serde_json::Value = serde_json::from_str(&height_body).expect("json");
    eprintln!(
        "mined confirmation; tip={}",
        height_v["result"].as_u64().unwrap_or(0)
    );

    // Primary acceptance (WP-16): CBF sees the UTXO we funded via bitcoin-cli.
    // Full cross-backend balance identity is WP-45. Prior test runs may have
    // left older fundings on the same descriptor — assert this payment, not a
    // global zero-state.
    let expected_sats = Amount::from_btc(1.0).unwrap().to_sat();

    let backend = make_backend("scan");
    eprintln!("starting cbf full_scan …");
    let req = wallet.start_full_scan().build();
    let update = backend.full_scan(req).expect("cbf full_scan");
    eprintln!(
        "full_scan done: txs={} last_active={:?}",
        update.tx_update.txs.len(),
        update.last_active_indices
    );
    assert_eq!(
        update.last_active_indices.get(&KeychainKind::External),
        Some(&index),
        "last_active must include the funded index"
    );
    wallet.apply_update(update).expect("apply_update");

    let bal = wallet.balance();
    let confirmed = bal.confirmed.to_sat();
    eprintln!(
        "cbf wallet balance: confirmed={confirmed} sats; \
         trusted_pending={} untrusted_pending={} immature={}",
        bal.trusted_pending.to_sat(),
        bal.untrusted_pending.to_sat(),
        bal.immature.to_sat()
    );

    // Independent truth: bitcoin-cli scantxoutset for the funded address.
    let scan_body = rpc_call(
        None,
        "scantxoutset",
        &format!(r#"["start", [{{"desc": "addr({addr})"}}]]"#),
    )
    .expect("scantxoutset");
    let scan_v: serde_json::Value = serde_json::from_str(&scan_body).expect("json");
    assert!(scan_v["error"].is_null(), "scantxoutset error: {scan_body}");
    let rpc_total = scan_v["result"]["total_amount"]
        .as_f64()
        .expect("total_amount")
        * 100_000_000.0;
    let rpc_sats = rpc_total.round() as u64;
    eprintln!("scantxoutset addr total = {rpc_sats} sats (cbf confirmed={confirmed})");

    // This address received exactly our 1 BTC funding (unique index).
    assert_eq!(
        rpc_sats, expected_sats,
        "rpc scantxoutset for funded addr must be 1 BTC"
    );

    // CBF must include that UTXO: wallet has at least one unspent of 1 BTC at
    // the funded keychain index, and the funding txid is known.
    let funding_txid: bitcoin::Txid = txid.parse().expect("txid parse");
    let saw_funding_tx = wallet
        .transactions()
        .any(|tx| tx.tx_node.txid == funding_txid);
    assert!(saw_funding_tx, "CBF must surface funding txid {txid}");

    let index_utxo_sats: u64 = wallet
        .list_unspent()
        .filter(|u| u.keychain == KeychainKind::External && u.derivation_index == index)
        .map(|u| u.txout.value.to_sat())
        .sum();
    assert_eq!(
        index_utxo_sats, expected_sats,
        "CBF UTXO at funded index must equal bitcoin-cli amount"
    );
    assert!(
        confirmed >= expected_sats,
        "CBF confirmed balance must include the funded amount"
    );

    // Tip matches RPC after the funding block.
    let tip = backend.tip_height().expect("tip after scan");
    let rpc_tip = rpc_call(None, "getblockcount", "[]").expect("getblockcount");
    let rpc_tip_v: serde_json::Value = serde_json::from_str(&rpc_tip).expect("json");
    let rpc_h = rpc_tip_v["result"].as_u64().unwrap() as u32;
    assert_eq!(tip, rpc_h, "cbf tip must match getblockcount");
}

#[test]
fn cbf_dead_peer_is_clean_error_no_fallback() {
    // Always runs — does not need the live environment.
    let cfg = CbfConfig::regtest_peer(SocketAddr::from(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        1, // nothing listens — immediate connection refused
    )))
    .data_dir(data_dir("dead"))
    .operation_timeout(Duration::from_secs(8));
    let backend = CbfBackend::new(cfg).expect("runtime");

    let err = backend.tip_height().expect_err("must fail");
    assert!(
        matches!(err, ChainError::Network(_) | ChainError::Unavailable(_)),
        "unexpected error variant: {err:?}"
    );
    // Sync path likewise.
    let mut wallet = Wallet::create(RECEIVE, CHANGE)
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .expect("wallet");
    let _ = wallet.reveal_next_address(KeychainKind::External);
    let req = wallet.start_full_scan().build();
    let err = backend.full_scan(req).expect_err("scan must fail");
    assert!(
        matches!(err, ChainError::Network(_) | ChainError::Unavailable(_)),
        "unexpected error variant: {err:?}"
    );
}

#[test]
fn cbf_privacy_profile_matches_spec_table() {
    let backend = make_backend("privacy");
    let p = backend.privacy_profile();
    assert_eq!(p.kind, trinity_chain::BackendKind::Cbf);
    assert!(!p.reveals_full_wallet_graph);
    assert!(p.third_party_counterparty);
    assert!(p.magnitude.to_ascii_lowercase().contains("not zero"));
    assert!(p.counterparty_learns.contains("statistical leak"));
}

#[test]
fn cbf_fee_estimates_and_sync_against_peer() {
    if !require_live_regtest() {
        return;
    }
    let _guard = REGTEST_LOCK.lock().expect("regtest lock");
    let backend = make_backend("fees-sync");

    let fees = backend.fee_estimates().expect("fee_estimates");
    // Regtest peers often advertise a min filter; any non-error result is fine.
    // When present, rates are ≥ 1 sat/vB by construction.
    if let Some(r) = fees.sat_per_vb_for(1) {
        assert!(r >= 1);
    }
    eprintln!("fee_estimates = {fees}");

    let mut wallet = Wallet::create(RECEIVE, CHANGE)
        .network(Network::Regtest)
        .lookahead(5)
        .create_wallet_no_persist()
        .expect("wallet");
    let _ = wallet.reveal_next_address(KeychainKind::External);
    // Incremental sync of revealed scripts (may be empty of txs).
    let req = wallet.start_sync_with_revealed_spks().build();
    let update = backend.sync(req).expect("cbf sync");
    wallet.apply_update(update).expect("apply sync update");
    let tip = backend.tip_height().expect("tip");
    assert!(tip >= 101, "regtest tip after sync: {tip}");
}

#[test]
fn cbf_broadcast_announces_to_peer() {
    if !require_live_regtest() {
        return;
    }
    let _guard = REGTEST_LOCK.lock().expect("regtest lock");
    let backend = make_backend("broadcast");
    // bip157 `submit_package` returns once the inv is sent to a peer — not
    // when the mempool accepts it. Exercise the announce path with a minimal
    // tx; acceptance is a separate concern (wallet signing flow).
    let junk = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: bitcoin::ScriptBuf::new_op_return([0u8]),
        }],
    };
    let txid = backend.broadcast(&junk).expect("announce to peer");
    assert_eq!(txid, junk.compute_txid());
    eprintln!("broadcast announced txid={txid}");
}

/// Lowered from the 120s production default so the hang is bearable. The
/// wait itself is unchanged — do not raise this to "make the test stable".
const CBF_RESUBMIT_TIMEOUT: Duration = Duration::from_secs(25);

/// Re-announcing a transaction the peer already has does not look like a
/// network failure. `submit_package` waits for `getdata` that never comes;
/// the wall-clock deadline surfaces as [`ChainError::DeliveryUnconfirmed`].
#[test]
fn cbf_resubmit_of_already_announced_tx_is_delivery_unconfirmed() {
    if !require_live_regtest() {
        return;
    }
    let _guard = REGTEST_LOCK.lock().expect("regtest lock");
    ensure_miner_wallet();

    // Signed, valid tx that has *not* been sent via RPC. First CBF announce
    // should therefore elicit `getdata`. Second announce of the same tx
    // should not — that is today's hang.
    let dest = rpc_result(Some("miner"), "getnewaddress", "[]");
    let dest = dest.as_str().expect("dest");
    let raw = rpc_result(
        Some("miner"),
        "createrawtransaction",
        &format!(r#"[[], {{"{dest}": 0.01000000}}]"#),
    );
    let raw_hex = raw.as_str().expect("raw hex");
    let funded = rpc_result(
        Some("miner"),
        "fundrawtransaction",
        &format!(r#"["{raw_hex}"]"#),
    );
    let funded_hex = funded["hex"].as_str().expect("funded hex");
    let signed = rpc_result(
        Some("miner"),
        "signrawtransactionwithwallet",
        &format!(r#"["{funded_hex}"]"#),
    );
    assert_eq!(
        signed["complete"].as_bool(),
        Some(true),
        "miner must finalize the package: {signed}"
    );
    let signed_hex = signed["hex"].as_str().expect("signed hex");
    let tx: bitcoin::Transaction = deserialize_hex(signed_hex).expect("decode signed tx");
    let txid = tx.compute_txid();
    eprintln!("resubmit fixture txid={txid}");

    let first = make_backend("resubmit-1");
    let t0 = Instant::now();
    let first_result = first.broadcast(&tx);
    let first_elapsed = t0.elapsed();
    eprintln!("first CBF broadcast {first_result:?} in {first_elapsed:?}");
    let announced = first_result.unwrap_or_else(|e| {
        panic!(
            "first CBF announce of an unknown valid tx must succeed so the \
             resubmit hang is isolated; got {e:?} after {first_elapsed:?}"
        )
    });
    assert_eq!(announced, txid);
    assert!(
        first_elapsed < CBF_RESUBMIT_TIMEOUT,
        "first announce must complete well inside the wall cap; elapsed {first_elapsed:?}"
    );

    let second_cfg = CbfConfig::regtest_peer(P2P_ADDR)
        .data_dir(data_dir("resubmit-2"))
        .operation_timeout(CBF_RESUBMIT_TIMEOUT);
    let second = CbfBackend::new(second_cfg).expect("cbf runtime");
    let t1 = Instant::now();
    let second_result = second.broadcast(&tx);
    eprintln!(
        "second CBF broadcast {second_result:?} in {:?}",
        t1.elapsed()
    );

    match second_result {
        Err(ChainError::DeliveryUnconfirmed) => {
            eprintln!(
                "resubmit DeliveryUnconfirmed after {:?} (cap {}s)",
                t1.elapsed(),
                CBF_RESUBMIT_TIMEOUT.as_secs()
            );
        }
        other => panic!(
            "expected ChainError::DeliveryUnconfirmed on CBF resubmit of \
             {txid}, got {other:?} after {:?}",
            t1.elapsed()
        ),
    }
    // A `submit_package` ClientError mapped onto DeliveryUnconfirmed would
    // return as soon as filters synced (~2s), not after the wall wait.
    assert!(
        t1.elapsed() >= CBF_RESUBMIT_TIMEOUT.saturating_sub(Duration::from_secs(2)),
        "DeliveryUnconfirmed must come from the wall wait after submit_package \
         started, not from an immediate send/recv error; elapsed {:?}",
        t1.elapsed()
    );
}

/// CBF incremental sync must surface a changeless spend whose funding
/// outpoint sits before the scan window.
///
/// Compact filters match the spent script, so the block is fetched.
/// Input-side relevance uses the request's `expected_spk_txids` (and any
/// outpoints) — not a peer lookup of the predecessor. A same-block receive
/// still applies via the output match (unchanged).
#[test]
fn cbf_sync_surfaces_changeless_spend_of_older_output() {
    if !require_live_regtest() {
        return;
    }
    let _guard = REGTEST_LOCK.lock().expect("regtest lock");
    ensure_miner_wallet();

    let mut wallet = make_signable_wallet();
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
    mine_blocks(1);

    // Bootstrap UTXO + chain via Core RPC so the only CBF node in this test
    // is the observation scan. A second short-lived CBF peer against the
    // same bitcoind has been seen to drop before FiltersSynced.
    let rpc_backend =
        CoreRpcBackend::connect(CoreRpcConfig::user_pass(RPC_URL, RPC_USER, RPC_PASS))
            .expect("connect Core RPC");
    let req = wallet.start_full_scan().build();
    let update = rpc_backend
        .full_scan(req)
        .expect("rpc full_scan after funding");
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

    // Push the funding block strictly behind CBF's reorg walk-back so the
    // later incremental scan cannot re-learn the spent outpoint.
    let filler = CBF_REORG_WALKBACK + 1;
    mine_blocks(filler);
    let advance_req = wallet.start_sync_with_revealed_spks().build();
    let advance_update = rpc_backend
        .sync(advance_req)
        .expect("rpc sync to advance checkpoint past funding");
    wallet
        .apply_update(advance_update)
        .expect("apply checkpoint advance");
    let advanced_height = wallet.latest_checkpoint().height();
    eprintln!("advanced wallet checkpoint height={advanced_height} (filler={filler})");
    assert!(
        advanced_height >= funding_height + filler,
        "incremental sync must move the tip past the funding block + walk-back; \
         funding={funding_height} tip={advanced_height}"
    );

    let dest = rpc_result(Some("miner"), "getnewaddress", "[]");
    let dest = dest.as_str().expect("drain dest");
    let dest_addr = Address::from_str(dest)
        .expect("dest parse")
        .require_network(Network::Regtest)
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

    // Same-block receive: proves the filter matched and the block was
    // applied. Without it, a missed block would look like the same gap.
    let probe_info = wallet.reveal_next_address(KeychainKind::External);
    let probe_spk = probe_info.script_pubkey();
    let probe_addr = probe_info.address.to_string();
    let probe = rpc_result(
        Some("miner"),
        "sendtoaddress",
        &format!(r#"["{probe_addr}", 0.00100000]"#),
    );
    let probe_txid: bitcoin::Txid = probe
        .as_str()
        .expect("probe txid")
        .parse()
        .expect("probe parse");

    let spend_hex = serialize_hex(&spend_tx);
    rpc_result(None, "sendrawtransaction", &format!(r#"["{spend_hex}"]"#));
    mine_blocks(1);

    let spend_id = spend_txid.to_string();
    assert!(
        tx_exists_on_node(&spend_id),
        "drain {spend_id} must be in a block before the CBF sync — \
         otherwise this is not a reproduction of a dropped confirmed spend"
    );
    eprintln!(
        "changeless spend {spend_txid} mined; same-block receive {probe_txid} to {probe_addr}"
    );

    let sync_backend = make_backend("changeless-sync");
    let sync_req = wallet.start_sync_with_revealed_spks().build();
    let sync_update = sync_backend
        .sync(sync_req)
        .expect("cbf incremental sync after drain");
    let present: Vec<_> = sync_update
        .tx_update
        .txs
        .iter()
        .map(|tx| tx.compute_txid())
        .collect();
    eprintln!("cbf sync present txs={present:?}");

    assert!(
        present.contains(&probe_txid),
        "same-block receive {probe_txid} must be applied so we know the \
         filter matched and the block was loaded; present={present:?}"
    );
    assert!(
        sync_update
            .tx_update
            .txs
            .iter()
            .any(|tx| tx.output.iter().any(|o| o.script_pubkey == probe_spk)),
        "applied receive must pay the probed script"
    );

    assert!(
        present.contains(&spend_txid),
        "changeless spend {spend_txid} must be in the CBF update even though \
         its funding sits before the scan window; present={present:?}"
    );
    assert!(
        tx_exists_on_node(&spend_id),
        "drain {spend_id} is still on chain after the CBF sync that dropped it"
    );
}
