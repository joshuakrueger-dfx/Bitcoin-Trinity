//! Live electrs integration tests (WP-14).
//!
//! Prerequisites: `./scripts/test-env.sh up` (or any stack publishing
//! electrs on `127.0.0.1:60401` and bitcoind RPC on `127.0.0.1:18443`).
//!
//! ```text
//! rustup run 1.94.1 cargo test -p trinity-chain --locked -- --ignored
//! ```

use std::sync::Arc;
use std::time::Duration;

use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::Network;
use trinity_chain::{
    BackendKind, ChainBackend, ChainError, ElectrumBackend, ElectrumConfig, PrivacyProfile,
};

/// Live electrs: tip height matches bitcoin-cli getblockcount (S2 height half).
#[test]
#[ignore = "requires ./scripts/test-env.sh up (electrs :60401)"]
fn live_tip_height_matches_core() {
    let backend =
        ElectrumBackend::connect(ElectrumConfig::regtest_electrs()).expect("electrs must be up");
    let tip = backend.tip_height().expect("tip");
    let core = core_block_count().expect("bitcoin-cli getblockcount");
    assert_eq!(tip, core, "electrum tip {tip} vs core {core}");
    assert_eq!(
        backend.privacy_profile().kind,
        BackendKind::ElectrumOwnServer
    );
    // fee_estimates may be empty on empty regtest mempool — must not error
    // with a fallback transport.
    let fees = backend.fee_estimates().expect("fees call");
    let _ = fees;

    // Broadcast of a nonsense tx must fail cleanly (covers broadcast path;
    // no Core/CBF fallback).
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
            value: bitcoin::Amount::from_sat(500),
            script_pubkey: bitcoin::ScriptBuf::new_op_return([]),
        }],
    };
    let berr = backend.broadcast(&junk).expect_err("junk tx must fail");
    assert!(
        matches!(
            berr,
            ChainError::Broadcast(_) | ChainError::Network(_) | ChainError::Protocol(_)
        ),
        "got {berr:?}"
    );

    let arc: Arc<dyn ChainBackend> = Arc::new(backend);
    assert!(arc.tip_height().unwrap() >= 101);
    let _ = PrivacyProfile::electrum_own_server();
}

/// Live electrs: balance for a funded SPK matches bitcoin-cli (S2 contribution).
#[test]
#[ignore = "requires ./scripts/test-env.sh up (electrs :60401 + bitcoind)"]
fn live_balance_matches_bitcoin_cli() {
    // Fixed regtest wpkh descriptors (xprv only in this test process —
    // not shipped as product key material).
    const EXT: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
    const INT: &str = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

    let mut wallet = Wallet::create(EXT, INT)
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .expect("wallet");

    let addr = wallet.next_unused_address(KeychainKind::External).address;
    // Unique amount per run (same fixed descriptors re-use index 0 across
    // runs; matching by amount isolates this transfer).
    let fund_sats: u64 = 1_000_000
        + (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() % 800_000)
            .unwrap_or(1) as u64);
    let txid = core_sendtoaddress(&addr.to_string(), fund_sats).expect("sendtoaddress");
    core_generate(1).expect("mine");
    std::thread::sleep(Duration::from_millis(800));

    let backend =
        ElectrumBackend::connect(ElectrumConfig::regtest_electrs()).expect("electrs connect");
    let req = wallet.start_full_scan().build();
    let update = backend.full_scan(req).expect("full_scan");
    wallet.apply_update(update).expect("apply_update");

    let spk = addr.script_pubkey();
    let electrum_has_utxo = wallet
        .list_unspent()
        .any(|u| u.txout.script_pubkey == spk && u.txout.value.to_sat() == fund_sats);
    assert!(
        electrum_has_utxo,
        "Electrum/BDK scan must see the funded UTXO of {fund_sats} sats on {addr}; txid {txid}"
    );
    let core_total = core_getreceivedbyaddress(&addr.to_string()).expect("getreceived");
    assert!(
        core_total >= fund_sats,
        "core scantxoutset total {core_total} must include funded {fund_sats}"
    );
    let electrum_addr_sum: u64 = wallet
        .list_unspent()
        .filter(|u| u.txout.script_pubkey == spk)
        .map(|u| u.txout.value.to_sat())
        .sum();
    assert_eq!(
        electrum_addr_sum, core_total,
        "S2: Electrum address balance {electrum_addr_sum} vs bitcoin-cli {core_total}"
    );

    let sync_req = wallet.start_sync_with_revealed_spks().build();
    let _ = backend.sync(sync_req).expect("sync");

    assert_eq!(backend.config().port, 60401);
    let _ = backend.client();
    let _ = format!("{backend:?}");
}

fn core_cli(args: &[&str]) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let host = Command::new("bitcoin-cli")
        .args([
            "-regtest",
            "-rpcconnect=127.0.0.1",
            "-rpcport=18443",
            "-rpcuser=trinity",
            "-rpcpassword=regtest",
        ])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    if let Ok(out) = host {
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
    }
    let name = bitcoind_container_name()?;
    let mut cmd = Command::new("docker");
    cmd.args([
        "exec",
        &name,
        "bitcoin-cli",
        "-regtest",
        "-rpcuser=trinity",
        "-rpcpassword=regtest",
    ]);
    cmd.args(args);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "bitcoin-cli failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn bitcoind_container_name() -> Result<String, String> {
    use std::process::Command;
    let out = Command::new("docker")
        .args(["ps", "--filter", "publish=18443", "--format", "{{.Names}}"])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let names = String::from_utf8_lossy(&out.stdout);
    names
        .lines()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            "no docker container publishing 18443 — start with ./scripts/test-env.sh up".into()
        })
}

fn core_block_count() -> Result<u32, String> {
    core_cli(&["getblockcount"])?
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())
}

fn core_sendtoaddress(addr: &str, sats: u64) -> Result<String, String> {
    let _ = core_cli(&["loadwallet", "miner"]);
    let btc = format!("{:.8}", sats as f64 / 100_000_000.0);
    core_cli(&["-rpcwallet=miner", "sendtoaddress", addr, &btc])
}

fn core_generate(n: u32) -> Result<(), String> {
    let _ = core_cli(&["loadwallet", "miner"]);
    let addr = core_cli(&["-rpcwallet=miner", "getnewaddress"])?;
    let _ = core_cli(&[
        "-rpcwallet=miner",
        "generatetoaddress",
        &n.to_string(),
        &addr,
    ])?;
    Ok(())
}

fn core_getreceivedbyaddress(addr: &str) -> Result<u64, String> {
    let arg = format!("[\"addr({addr})\"]");
    let json = core_cli(&["scantxoutset", "start", &arg])?;
    let amount = parse_json_f64_field(&json, "total_amount")
        .ok_or_else(|| format!("no total_amount in scantxoutset: {json}"))?;
    Ok((amount * 100_000_000.0).round() as u64)
}

fn parse_json_f64_field(json: &str, key: &str) -> Option<f64> {
    let needle = format!("\"{key}\"");
    let idx = json.find(&needle)?;
    let rest = &json[idx + needle.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}
