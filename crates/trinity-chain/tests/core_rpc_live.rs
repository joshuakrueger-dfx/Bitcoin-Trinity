//! Live Core RPC tests — WP-15 / S2 contribution / S13.
//!
//! Requires `./scripts/test-env.sh up` (Bitcoin Core 30.2 regtest on
//! `127.0.0.1:18443`, user/pass `trinity`/`regtest`). When the node is
//! unreachable the tests **skip with a visible message** (not a silent
//! green pass of the balance/error claims).

use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::Network as BtcNetwork;
use trinity_chain::{ChainBackend, ChainError, CoreRpcBackend, CoreRpcConfig, PrivacyProfile};

const RPC_HOST: &str = "127.0.0.1";
const RPC_PORT: &str = "18443";
const RPC_USER: &str = "trinity";
const RPC_PASS: &str = "regtest";
const RPC_URL: &str = "http://127.0.0.1:18443";

/// Amount funded to the watch address (sats) in each S2 run.
const FUND_SATS: u64 = 2_500_000; // 0.025 BTC

fn workspace_root() -> String {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.to_string_lossy().into_owned()
}

fn core_reachable_host() -> bool {
    Command::new("bitcoin-cli")
        .args([
            "-regtest",
            &format!("-rpcconnect={RPC_HOST}"),
            &format!("-rpcport={RPC_PORT}"),
            &format!("-rpcuser={RPC_USER}"),
            &format!("-rpcpassword={RPC_PASS}"),
            "-rpcclienttimeout=2",
            "getblockchaininfo",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Compose project names to try (parallel WP worktrees may set COMPOSE_PROJECT_NAME).
fn compose_project_candidates() -> Vec<String> {
    let mut v = Vec::new();
    if let Ok(p) = std::env::var("COMPOSE_PROJECT_NAME") {
        if !p.is_empty() {
            v.push(p);
        }
    }
    // Default: directory name of the workspace (compose default).
    if let Some(name) = std::path::Path::new(&workspace_root())
        .file_name()
        .and_then(|s| s.to_str())
    {
        v.push(name.to_owned());
    }
    // Explicit WP-15 project used when starting test-env on this Studio box.
    v.push("wp15-corerpc".into());
    v.dedup();
    v
}

/// Prefer standalone `docker-compose` (available here as v5); fall back to the
/// `docker compose` plugin when present (matches `scripts/test-env.sh`).
fn compose_bin() -> (&'static str, bool) {
    // (program, is_plugin): plugin needs `compose` as first arg.
    if Command::new("docker-compose")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return ("docker-compose", false);
    }
    ("docker", true)
}

fn docker_compose_base(project: &str) -> Command {
    let root = workspace_root();
    let (bin, plugin) = compose_bin();
    let mut c = Command::new(bin);
    if plugin {
        c.arg("compose");
    }
    c.args(["-p", project, "-f", &format!("{root}/docker/compose.yml")]);
    c
}

enum RpcMode {
    HostCli,
    DockerExec { project: String },
}

fn detect_rpc() -> Option<RpcMode> {
    if core_reachable_host() {
        return Some(RpcMode::HostCli);
    }
    for project in compose_project_candidates() {
        let mut cmd = docker_compose_base(&project);
        cmd.args([
            "exec",
            "-T",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            &format!("-rpcuser={RPC_USER}"),
            &format!("-rpcpassword={RPC_PASS}"),
            "getblockchaininfo",
        ]);
        let ok = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(RpcMode::DockerExec { project });
        }
    }
    None
}

fn require_core() -> Option<RpcMode> {
    match detect_rpc() {
        Some(m) => Some(m),
        None => {
            eprintln!(
                "SKIP core_rpc_live: Bitcoin Core not reachable at {RPC_URL}. \
                 Run `./scripts/test-env.sh up` first."
            );
            None
        }
    }
}

fn cli(mode: &RpcMode, wallet: Option<&str>, args: &[&str]) -> String {
    cli_allow(mode, wallet, args, &[])
}

/// Like [`cli`], but treat stderr containing any of `ok_err_substrings` as success
/// (used for idempotent `loadwallet` when already loaded).
fn cli_allow(
    mode: &RpcMode,
    wallet: Option<&str>,
    args: &[&str],
    ok_err_substrings: &[&str],
) -> String {
    match mode {
        RpcMode::HostCli => {
            let mut full: Vec<String> = vec![
                "-regtest".into(),
                format!("-rpcconnect={RPC_HOST}"),
                format!("-rpcport={RPC_PORT}"),
                format!("-rpcuser={RPC_USER}"),
                format!("-rpcpassword={RPC_PASS}"),
            ];
            if let Some(w) = wallet {
                full.push(format!("-rpcwallet={w}"));
            }
            for a in args {
                full.push((*a).into());
            }
            let out = Command::new("bitcoin-cli")
                .args(&full)
                .output()
                .expect("spawn bitcoin-cli");
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !out.status.success() && !ok_err_substrings.iter().any(|s| stderr.contains(s)) {
                panic!("bitcoin-cli {args:?} failed: {stderr}");
            }
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        }
        RpcMode::DockerExec { project } => {
            let mut cmd = docker_compose_base(project);
            cmd.args([
                "exec",
                "-T",
                "bitcoind",
                "bitcoin-cli",
                "-regtest",
                &format!("-rpcuser={RPC_USER}"),
                &format!("-rpcpassword={RPC_PASS}"),
            ]);
            if let Some(w) = wallet {
                cmd.arg(format!("-rpcwallet={w}"));
            }
            cmd.args(args);
            let out = cmd.output().expect("spawn docker compose exec");
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !out.status.success() && !ok_err_substrings.iter().any(|s| stderr.contains(s)) {
                panic!("docker bitcoin-cli {args:?} failed: {stderr}");
            }
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        }
    }
}

fn connect_backend() -> CoreRpcBackend {
    CoreRpcBackend::connect(CoreRpcConfig::user_pass(RPC_URL, RPC_USER, RPC_PASS))
        .expect("connect Core RPC")
}

/// Fresh wallet per run so funded addresses do not accumulate across re-tests.
fn make_wallet() -> Wallet {
    use bitcoin::bip32::Xpriv;

    // 32 bytes of process-unique material (pid + nanos + tag).
    let mut seed = [0u8; 32];
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos()
        .to_le_bytes();
    seed[..16].copy_from_slice(&nanos);
    let pid = std::process::id().to_le_bytes();
    seed[16..20].copy_from_slice(&pid);
    seed[20..28].copy_from_slice(b"WP15CORE");
    seed[28..32].copy_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d]);

    let xprv = Xpriv::new_master(BtcNetwork::Regtest, &seed).expect("xprv");
    let ext = format!("wpkh({xprv}/84'/1'/0'/0/*)");
    let int = format!("wpkh({xprv}/84'/1'/0'/1/*)");
    Wallet::create(ext, int)
        .network(BtcNetwork::Regtest)
        .create_wallet_no_persist()
        .expect("create wallet")
}

/// S2 contribution: backend balance matches bitcoin-cli for a funded address.
#[test]
fn s2_balance_matches_bitcoin_cli() {
    let Some(mode) = require_core() else {
        return;
    };

    let backend = connect_backend();
    let tip_before = backend.tip_height().expect("tip");
    assert!(
        tip_before >= 101,
        "expected seeded regtest (≥101 blocks), got {tip_before}"
    );

    // Ensure miner wallet exists (test-env seed creates it). Already-loaded is fine.
    let _ = cli_allow(
        &mode,
        None,
        &["loadwallet", "miner"],
        &["already loaded", "Duplicate -wallet filename"],
    );
    let miner_bal_str = cli(&mode, Some("miner"), &["getbalance"]);
    let miner_bal: f64 = miner_bal_str.parse().expect("miner balance float");
    assert!(
        miner_bal > 0.0,
        "miner wallet must be funded (got {miner_bal_str} BTC)"
    );

    let mut wallet = make_wallet();
    let addr = wallet
        .reveal_next_address(KeychainKind::External)
        .address
        .to_string();

    // Fund watch address from miner, mine one block for confirmation.
    let fund_btc = format!("{:.8}", FUND_SATS as f64 / 100_000_000.0);
    let _txid = cli(&mode, Some("miner"), &["sendtoaddress", &addr, &fund_btc]);
    let miner_addr = cli(&mode, Some("miner"), &["getnewaddress"]);
    cli(
        &mode,
        Some("miner"),
        &["generatetoaddress", "1", &miner_addr],
    );

    // Cross-check against Core's UTXO set for the same script (scantxoutset).
    // `getbalance` on the miner wallet is a different wallet; for a watch-only
    // address Core exposes the matching figure via scantxoutset total_amount.
    // We also record miner getbalance above as the funding source sanity check.
    let scan = cli(
        &mode,
        None,
        &["scantxoutset", "start", &format!("[\"addr({addr})\"]")],
    );
    // scantxoutset JSON contains total_amount in BTC.
    let core_total_sats = parse_scantxoutset_total_sats(&scan);
    assert_eq!(
        core_total_sats, FUND_SATS,
        "scantxoutset total {core_total_sats} != funded {FUND_SATS}; raw={scan}"
    );

    // Also compare against miner getbalance path indirectly: amount left the miner.
    // Primary assertion: CoreRpcBackend full_scan → wallet balance == FUND_SATS
    // and == scantxoutset (Core's own UTXO view of the same script).
    let req = wallet.start_full_scan().build();
    let update = backend.full_scan(req).expect("full_scan");
    wallet.apply_update(update).expect("apply_update");

    let bdk_sats = wallet.balance().total().to_sat();
    assert_eq!(
        bdk_sats, FUND_SATS,
        "BDK balance after CoreRpcBackend full_scan: {bdk_sats} sats, expected {FUND_SATS}"
    );
    assert_eq!(
        bdk_sats, core_total_sats,
        "backend balance {bdk_sats} != bitcoin-cli scantxoutset {core_total_sats}"
    );

    // Incremental sync path also succeeds and keeps the balance.
    let sync_req = wallet.start_sync_with_revealed_spks().build();
    let sync_update = backend.sync(sync_req).expect("sync");
    wallet.apply_update(sync_update).expect("apply sync");
    assert_eq!(wallet.balance().total().to_sat(), FUND_SATS);

    // Tip moved at least one block from funding.
    let tip_after = backend.tip_height().expect("tip after");
    assert!(tip_after >= tip_before);

    // Fee estimates: must not error (regtest may return empty set).
    let fees = backend.fee_estimates().expect("fee_estimates");
    let _ = fees.is_empty(); // regtest often has no estimate data

    // Privacy profile on the live instance.
    assert_eq!(backend.privacy_profile(), PrivacyProfile::core_rpc());

    eprintln!(
        "S2 OK: funded {FUND_SATS} sats to {addr}; \
         CoreRpcBackend balance={bdk_sats}; scantxoutset={core_total_sats}; \
         miner_getbalance_before={miner_bal_str} BTC; tip {tip_before}→{tip_after}"
    );
}

/// S13: unreachable RPC → clean ChainError, no silent fallback.
#[test]
fn s13_unreachable_returns_clean_error() {
    // Does not need a live node — deliberately wrong port.
    let backend = CoreRpcBackend::connect(CoreRpcConfig::user_pass(
        "http://127.0.0.1:1",
        RPC_USER,
        RPC_PASS,
    ))
    .expect("client builds offline");

    let tip = backend.tip_height();
    assert!(
        matches!(tip, Err(ChainError::Network(_)) | Err(ChainError::Other(_))),
        "expected Network/Other, got {tip:?}"
    );

    let fees = backend.fee_estimates();
    assert!(
        matches!(
            fees,
            Err(ChainError::Network(_)) | Err(ChainError::Other(_))
        ),
        "expected Network/Other, got {fees:?}"
    );

    let mut wallet = make_wallet();
    let _ = wallet.reveal_next_address(KeychainKind::External);
    let req = wallet.start_full_scan().build();
    let scan = backend.full_scan(req);
    assert!(
        matches!(
            scan,
            Err(ChainError::Network(_)) | Err(ChainError::Protocol(_)) | Err(ChainError::Other(_))
        ),
        "expected clean error, got {scan:?}"
    );
    // No second backend is constructed — the error is the only outcome.
    // (No Electrum/CBF types are even referenced on this path.)
}

/// Wrong credentials against a live node → clean error (S13 class).
#[test]
fn s13_bad_credentials_return_error() {
    let Some(_) = require_core() else {
        return;
    };
    // Client builds; first RPC call fails auth.
    let backend = CoreRpcBackend::connect(CoreRpcConfig::user_pass(
        RPC_URL,
        "not-trinity",
        "wrong-password",
    ))
    .expect("client builds");
    let err = backend.tip_height().expect_err("bad auth must fail");
    assert!(
        matches!(
            err,
            ChainError::Network(_) | ChainError::Protocol(_) | ChainError::Other(_)
        ),
        "got {err:?}"
    );
    // Brief pause so we do not hammer the node if tests re-run quickly.
    thread::sleep(Duration::from_millis(50));
}

/// Dyn-backend usage with a live tip read.
#[test]
fn live_dyn_backend_tip() {
    let Some(_) = require_core() else {
        return;
    };
    let backend: Arc<dyn ChainBackend> = Arc::new(connect_backend());
    let tip = backend.tip_height().expect("tip");
    assert!(tip >= 101);
    assert_eq!(
        backend.privacy_profile().kind,
        trinity_chain::BackendKind::CoreRpc
    );
}

/// Empty full_scan still returns a chain tip update (tip_checkpoint path).
#[test]
fn live_empty_full_scan_advances_tip() {
    use bdk_wallet::KeychainKind as K;
    use trinity_chain::{FullScanRequest, SyncRequest};

    let Some(_) = require_core() else {
        return;
    };
    let backend = connect_backend();
    let req = FullScanRequest::<K>::builder_at(0).build();
    let update = backend.full_scan(req).expect("empty full_scan");
    assert!(
        update.chain.is_some(),
        "empty full_scan must still report chain tip"
    );
    assert!(update.chain.as_ref().unwrap().height() >= 101);

    // Empty SPK sync (no scripts) still returns a tip.
    let sreq = SyncRequest::<(K, u32)>::builder_at(0).build();
    let sup = backend.sync(sreq).expect("empty sync");
    assert!(sup.chain.is_some());
}

/// Mempool path: fund without mining, full_scan sees unconfirmed balance.
#[test]
fn live_mempool_unconfirmed_balance() {
    let Some(mode) = require_core() else {
        return;
    };
    let backend = connect_backend();
    let _ = cli_allow(
        &mode,
        None,
        &["loadwallet", "miner"],
        &["already loaded", "Duplicate -wallet filename"],
    );

    let mut wallet = make_wallet();
    let addr = wallet
        .reveal_next_address(KeychainKind::External)
        .address
        .to_string();
    let fund_btc = format!("{:.8}", FUND_SATS as f64 / 100_000_000.0);
    let txid_str = cli(&mode, Some("miner"), &["sendtoaddress", &addr, &fund_btc]);
    // Also park an unrelated mempool tx so the "not relevant" filter arm runs.
    let decoy = cli(&mode, Some("miner"), &["getnewaddress"]);
    let _ = cli(
        &mode,
        Some("miner"),
        &["sendtoaddress", &decoy, "0.00010000"],
    );
    // Do NOT mine — leave both in mempool.

    let req = wallet.start_full_scan().build();
    let update = backend.full_scan(req).expect("full_scan mempool");
    // Apply so wallet can see unconfirmed.
    wallet.apply_update(update).expect("apply");
    let total = wallet.balance().total().to_sat();
    let trusted_pending = wallet.balance().trusted_pending.to_sat();
    let untrusted_pending = wallet.balance().untrusted_pending.to_sat();
    let pending = trusted_pending + untrusted_pending;
    assert!(
        total == FUND_SATS || pending == FUND_SATS || total + pending >= FUND_SATS,
        "expected mempool credit of {FUND_SATS}, total={total} pending={pending} \
         (trusted={trusted_pending} untrusted={untrusted_pending}) txid={txid_str}"
    );

    // Mine to clean up mempool for other tests.
    let miner_addr = cli(&mode, Some("miner"), &["getnewaddress"]);
    cli(
        &mode,
        Some("miner"),
        &["generatetoaddress", "1", &miner_addr],
    );

    // Sync with explicit txid + outpoint for confirmed tx paths.
    let txid = bitcoin::Txid::from_str(&txid_str).expect("txid");
    let sync_req = wallet
        .start_sync_with_revealed_spks()
        .txids([txid])
        .outpoints([bitcoin::OutPoint { txid, vout: 0 }])
        .build();
    let sync_up = backend.sync(sync_req).expect("sync with txid/outpoint");
    wallet.apply_update(sync_up).expect("apply sync");
    assert_eq!(
        wallet.balance().total().to_sat(),
        FUND_SATS,
        "after mine+sync balance"
    );
}

/// Sync of a missing txid marks eviction (is_not_found path) without fallback.
#[test]
fn live_sync_missing_txid_evicts() {
    use bitcoin::hashes::Hash;
    use trinity_chain::SyncRequest;

    let Some(_) = require_core() else {
        return;
    };
    let backend = connect_backend();
    let missing = bitcoin::Txid::from_byte_array([0x11; 32]);
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .txids([missing])
        .build();
    let update = backend.sync(req).expect("sync missing txid");
    assert!(
        update
            .tx_update
            .evicted_ats
            .iter()
            .any(|(t, _)| *t == missing),
        "missing txid must be reported as eviction, got {:?}",
        update.tx_update.evicted_ats
    );
}

/// Sync by txid/outpoint only (no SPKs) covers explicit fetch arms.
#[test]
fn live_sync_txid_and_outpoint_only() {
    use trinity_chain::SyncRequest;

    let Some(mode) = require_core() else {
        return;
    };
    let backend = connect_backend();
    let _ = cli_allow(
        &mode,
        None,
        &["loadwallet", "miner"],
        &["already loaded", "Duplicate -wallet filename"],
    );

    // Send to a throwaway address so we have a known confirmed txid that is
    // *not* already in a SPK-driven graph for this backend call.
    let mut wallet = make_wallet();
    let addr = wallet
        .reveal_next_address(KeychainKind::External)
        .address
        .to_string();
    let fund_btc = format!("{:.8}", FUND_SATS as f64 / 100_000_000.0);
    let txid_str = cli(&mode, Some("miner"), &["sendtoaddress", &addr, &fund_btc]);
    let miner_addr = cli(&mode, Some("miner"), &["getnewaddress"]);
    cli(
        &mode,
        Some("miner"),
        &["generatetoaddress", "1", &miner_addr],
    );
    let txid = bitcoin::Txid::from_str(&txid_str).expect("txid");
    let op = bitcoin::OutPoint { txid, vout: 0 };

    // 1) Duplicate txids → second hits `present.contains` continue.
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .txids([txid, txid])
        .build();
    let update = backend.sync(req).expect("sync duplicate txid");
    assert!(
        update
            .tx_update
            .txs
            .iter()
            .any(|tx| tx.compute_txid() == txid),
        "txid fetch must insert the transaction"
    );
    assert!(
        !update.tx_update.anchors.is_empty() || !update.tx_update.seen_ats.is_empty(),
        "confirmed tx should anchor or be seen"
    );

    // 2) Outpoint-only (no txids) → outpoint fetch body.
    let req2 = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .outpoints([op])
        .build();
    let update2 = backend.sync(req2).expect("sync outpoint only");
    assert!(
        update2
            .tx_update
            .txs
            .iter()
            .any(|tx| tx.compute_txid() == txid)
            || update2.tx_update.txouts.contains_key(&op),
        "outpoint fetch must surface the tx or txout"
    );

    // 3) Missing outpoint → silent skip (is_not_found), not a fallback.
    use bitcoin::hashes::Hash;
    let ghost = bitcoin::OutPoint {
        txid: bitcoin::Txid::from_byte_array([0x22; 32]),
        vout: 0,
    };
    let req3 = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .outpoints([ghost])
        .build();
    let update3 = backend.sync(req3).expect("sync ghost outpoint");
    assert!(
        update3.tx_update.txs.is_empty(),
        "ghost outpoint must not invent txs"
    );

    // 4) Out-of-range vout still returns the tx (no panic).
    let op_hi = bitcoin::OutPoint { txid, vout: 9_999 };
    let req4 = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .outpoints([op_hi])
        .build();
    let update4 = backend.sync(req4).expect("sync high vout");
    assert!(update4
        .tx_update
        .txs
        .iter()
        .any(|tx| tx.compute_txid() == txid));
}

/// Unconfirmed txid sync hits the `seen_ats` arm (no blockhash).
#[test]
fn live_sync_unconfirmed_txid_seen_at() {
    use trinity_chain::SyncRequest;

    let Some(mode) = require_core() else {
        return;
    };
    let backend = connect_backend();
    let _ = cli_allow(
        &mode,
        None,
        &["loadwallet", "miner"],
        &["already loaded", "Duplicate -wallet filename"],
    );
    let mut wallet = make_wallet();
    let addr = wallet
        .reveal_next_address(KeychainKind::External)
        .address
        .to_string();
    let fund_btc = format!("{:.8}", FUND_SATS as f64 / 100_000_000.0);
    let txid_str = cli(&mode, Some("miner"), &["sendtoaddress", &addr, &fund_btc]);
    let txid = bitcoin::Txid::from_str(&txid_str).expect("txid");

    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .txids([txid])
        .build();
    let update = backend.sync(req).expect("sync unconfirmed txid");
    assert!(
        update.tx_update.seen_ats.iter().any(|(t, _)| *t == txid)
            || update
                .tx_update
                .txs
                .iter()
                .any(|tx| tx.compute_txid() == txid),
        "unconfirmed txid should be seen or listed"
    );

    // Clean up mempool for subsequent tests.
    let miner_addr = cli(&mode, Some("miner"), &["getnewaddress"]);
    cli(
        &mode,
        Some("miner"),
        &["generatetoaddress", "1", &miner_addr],
    );
}

fn parse_scantxoutset_total_sats(json: &str) -> u64 {
    // Prefer serde_json if available via bitcoin stack — use a tiny manual parse
    // for "total_amount": <float> to avoid adding a dev-dep.
    // Format: ... "total_amount": 0.02500000 ...
    let key = "\"total_amount\"";
    let idx = json
        .find(key)
        .unwrap_or_else(|| panic!("no total_amount in scantxoutset response: {json}"));
    let after = &json[idx + key.len()..];
    let after = after.trim_start_matches([' ', ':', '\t']);
    let num: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    let btc: f64 = f64::from_str(&num).unwrap_or_else(|_| panic!("parse amount {num}"));
    (btc * 100_000_000.0).round() as u64
}
