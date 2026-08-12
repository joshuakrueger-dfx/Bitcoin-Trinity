//! D2 / D3 (WP-12 Vorgriff) — addresses against Bitcoin Core `deriveaddresses`.
//!
//! Full harness is 500 setups × 1_000 addresses (WP-23). This is a **real
//! smaller** differential run against a live regtest node, same pattern as
//! WP-11 D1.
//!
//! ## Measured case counts (not estimates)
//!
//! | Test | Setups | Addresses / setup | Total address comparisons |
//! |---|---|---|---|
//! | D2 receive (`External`) | 40 | 50 | **2_000** |
//! | D3 change (`Internal`) | 40 | 50 | **2_000** |
//!
//! ## Prerequisites
//!
//! ```text
//! ./scripts/test-env.sh up
//! ```
//!
//! RPC: `http://trinity:regtest@127.0.0.1:18443`.
//!
//! If the environment is not running the test panics with a visible message
//! (not silently green). Run with `-- --ignored`.

use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network as BtcNetwork;
use trinity_types::{Fingerprint, KeySlot, KeychainKind, Network, WordCount, XpubWithOrigin};
use trinity_watch::descriptor::{bip48_origin_path, DescriptorSetup, KeyContribution, KeySource};
use trinity_watch::WatchWallet;

/// WP-12 Vorgriff: 40 random 2-of-3 setups.
const SETUPS: u32 = 40;
/// Addresses derived per setup and keychain (indices 0..ADDRS-1).
const ADDRS: u32 = 50;

const RPC_HOST: &str = "127.0.0.1";
const RPC_PORT: &str = "18443";
const RPC_USER: &str = "trinity";
const RPC_PASS: &str = "regtest";

fn core_reachable() -> bool {
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

fn workspace_root() -> String {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.to_string_lossy().into_owned()
}

/// Compose frontend: prefer `docker compose` (v2 plugin), fall back to
/// hyphenated `docker-compose` (still common when the plugin is missing).
fn compose_frontends() -> Vec<ComposeFrontend> {
    vec![ComposeFrontend::Plugin, ComposeFrontend::Standalone]
}

enum ComposeFrontend {
    Plugin,
    Standalone,
}

impl ComposeFrontend {
    fn probe(&self, root: &str) -> bool {
        let mut cmd = self.base(root);
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
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn base(&self, root: &str) -> Command {
        match self {
            ComposeFrontend::Plugin => {
                let mut c = Command::new("docker");
                c.args(["compose", "-f", &format!("{root}/docker/compose.yml")]);
                c
            }
            ComposeFrontend::Standalone => {
                let mut c = Command::new("docker-compose");
                c.args(["-f", &format!("{root}/docker/compose.yml")]);
                c
            }
        }
    }
}

enum RpcMode {
    HostCli,
    DockerExec(ComposeFrontend),
}

fn detect_rpc() -> Option<RpcMode> {
    if core_reachable() {
        return Some(RpcMode::HostCli);
    }
    let root = workspace_root();
    for front in compose_frontends() {
        if front.probe(&root) {
            return Some(RpcMode::DockerExec(front));
        }
    }
    None
}

fn deriveaddresses(
    mode: &RpcMode,
    descriptor: &str,
    end_inclusive: u32,
) -> Result<Vec<String>, String> {
    let range = format!("[0,{end_inclusive}]");
    let output = match mode {
        RpcMode::HostCli => Command::new("bitcoin-cli")
            .args([
                "-regtest",
                &format!("-rpcconnect={RPC_HOST}"),
                &format!("-rpcport={RPC_PORT}"),
                &format!("-rpcuser={RPC_USER}"),
                &format!("-rpcpassword={RPC_PASS}"),
                "deriveaddresses",
                descriptor,
                &range,
            ])
            .output()
            .map_err(|e| e.to_string())?,
        RpcMode::DockerExec(front) => {
            let root = workspace_root();
            let mut cmd = front.base(&root);
            cmd.args([
                "exec",
                "-T",
                "bitcoind",
                "bitcoin-cli",
                "-regtest",
                &format!("-rpcuser={RPC_USER}"),
                &format!("-rpcpassword={RPC_PASS}"),
                "deriveaddresses",
                descriptor,
                &range,
            ]);
            cmd.output().map_err(|e| e.to_string())?
        }
    };
    if !output.status.success() {
        return Err(format!(
            "bitcoin-cli deriveaddresses failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("json: {e}; body={text}"))?;
    let arr = v
        .as_array()
        .ok_or_else(|| format!("expected address array, got {text}"))?;
    arr.iter()
        .map(|a| {
            a.as_str()
                .map(|s| s.to_owned())
                .ok_or_else(|| format!("non-string address entry: {a}"))
        })
        .collect()
}

fn xpub_from_tag(tag: u32) -> XpubWithOrigin {
    let secp = Secp256k1::new();
    let seed = sha256::Hash::hash(&tag.to_be_bytes());
    let master = Xpriv::new_master(BtcNetwork::Regtest, seed.as_byte_array()).expect("master");
    let fp = master.fingerprint(&secp);
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let account = master.derive_priv(&secp, &path).unwrap();
    let xpub = Xpub::from_priv(&secp, &account);
    XpubWithOrigin::new(
        Fingerprint::new(fp.to_bytes()),
        bip48_origin_path(Network::Regtest),
        xpub.to_string(),
    )
}

fn build_setup(i: u32) -> trinity_watch::descriptor::WalletDescriptors {
    let a = xpub_from_tag(i * 3 + 1);
    let b = xpub_from_tag(i * 3 + 2);
    let c = xpub_from_tag(i * 3 + 3);
    DescriptorSetup {
        network: Network::Regtest,
        created_at_unix: 1_700_000_000 + u64::from(i),
        keys: [
            KeyContribution {
                slot: KeySlot::A,
                xpub: a,
                birthday_height: i,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
            KeyContribution {
                slot: KeySlot::B,
                xpub: b,
                birthday_height: i,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
            KeyContribution {
                slot: KeySlot::C,
                xpub: c,
                birthday_height: i,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
        ],
    }
    .build()
    .expect("build descriptors")
}

fn run_differential(keychain: KeychainKind, label: &str) {
    let mode = match detect_rpc() {
        Some(m) => m,
        None => {
            panic!(
                "skipped: test environment not running \
                 (start with `./scripts/test-env.sh up`; RPC {RPC_USER}@{RPC_HOST}:{RPC_PORT})"
            );
        }
    };

    let started = std::time::Instant::now();
    let mut compared = 0u32;
    let end = ADDRS - 1;

    for i in 0..SETUPS {
        let doc = build_setup(i);
        let wallet = WatchWallet::from_descriptors(&doc).expect("open wallet");
        let desc = match keychain {
            KeychainKind::External => doc.receive(),
            KeychainKind::Internal => doc.change(),
        };
        let ours: Vec<String> = wallet
            .derive_addresses(keychain, ADDRS)
            .into_iter()
            .map(|a| a.address)
            .collect();
        let core = deriveaddresses(&mode, desc, end).unwrap_or_else(|e| {
            panic!("{label}: deriveaddresses failed setup={i}: {e}\ndesc={desc}");
        });
        assert_eq!(
            core.len() as u32,
            ADDRS,
            "{label}: Core returned {} addresses, expected {ADDRS}",
            core.len()
        );
        for idx in 0..ADDRS as usize {
            assert_eq!(
                ours[idx], core[idx],
                "{label} mismatch setup={i} index={idx}\nours={}\ncore={}",
                ours[idx], core[idx]
            );
            compared += 1;
        }
    }

    let elapsed = started.elapsed();
    eprintln!(
        "{label} WP-12 Vorgriff: {compared} addresses \
         (={SETUPS} setups × {ADDRS} indices) matched Core deriveaddresses in {elapsed:?}"
    );
    assert_eq!(compared, SETUPS * ADDRS);
    assert!(elapsed < Duration::from_secs(600));
}

/// D2 — receive addresses (`KeychainKind::External` / `/0/*`).
#[test]
#[ignore = "D2 WP-12 Vorgriff: requires ./scripts/test-env.sh up; run with -- --ignored"]
fn d2_receive_addresses_against_core() {
    run_differential(KeychainKind::External, "D2");
}

/// D3 — change addresses (`KeychainKind::Internal` / `/1/*`).
#[test]
#[ignore = "D3 WP-12 Vorgriff: requires ./scripts/test-env.sh up; run with -- --ignored"]
fn d3_change_addresses_against_core() {
    run_differential(KeychainKind::Internal, "D3");
}
