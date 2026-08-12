//! D1 (WP-11 Vorgriff) — checksum vs Bitcoin Core `getdescriptorinfo`.
//!
//! Full 10_000-case differential harness is WP-23 (`tests/differential/`,
//! feature `differential`). This test is a **WP-11 preview**: a few hundred
//! generated descriptors checked against a live regtest node.
//!
//! ## Prerequisites
//!
//! ```text
//! ./scripts/test-env.sh up
//! ```
//!
//! RPC: `http://trinity:regtest@127.0.0.1:18443` (see `scripts/test-env.sh`).
//!
//! If the environment is not running the test is **skipped** with a visible
//! message (not silently green).

use std::io::Write;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network as BtcNetwork;
use trinity_types::{Fingerprint, KeySlot, Network, WordCount, XpubWithOrigin};
use trinity_watch::descriptor::{bip48_origin_path, DescriptorSetup, KeyContribution, KeySource};

/// Number of random 2-of-3 setups × 2 descriptors (receive+change) ≈ 2× this.
const SETUPS: u32 = 250;

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

/// Fallback: docker compose exec when host has no bitcoin-cli.
fn core_reachable_docker() -> bool {
    let root = workspace_root();
    Command::new("docker")
        .args([
            "compose",
            "-f",
            &format!("{root}/docker/compose.yml"),
            "exec",
            "-T",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            &format!("-rpcuser={RPC_USER}"),
            &format!("-rpcpassword={RPC_PASS}"),
            "getblockchaininfo",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn workspace_root() -> String {
    // CARGO_MANIFEST_DIR = crates/trinity-watch
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.to_string_lossy().into_owned()
}

enum RpcMode {
    HostCli,
    DockerExec,
}

fn detect_rpc() -> Option<RpcMode> {
    if core_reachable() {
        Some(RpcMode::HostCli)
    } else if core_reachable_docker() {
        Some(RpcMode::DockerExec)
    } else {
        None
    }
}

fn getdescriptorinfo(mode: &RpcMode, descriptor: &str) -> Result<String, String> {
    // Core returns JSON; we need the "checksum" field (without applying it
    // to the input — getdescriptorinfo always reports the correct checksum).
    let output = match mode {
        RpcMode::HostCli => Command::new("bitcoin-cli")
            .args([
                "-regtest",
                &format!("-rpcconnect={RPC_HOST}"),
                &format!("-rpcport={RPC_PORT}"),
                &format!("-rpcuser={RPC_USER}"),
                &format!("-rpcpassword={RPC_PASS}"),
                "getdescriptorinfo",
                descriptor,
            ])
            .output()
            .map_err(|e| e.to_string())?,
        RpcMode::DockerExec => {
            let root = workspace_root();
            Command::new("docker")
                .args([
                    "compose",
                    "-f",
                    &format!("{root}/docker/compose.yml"),
                    "exec",
                    "-T",
                    "bitcoind",
                    "bitcoin-cli",
                    "-regtest",
                    &format!("-rpcuser={RPC_USER}"),
                    &format!("-rpcpassword={RPC_PASS}"),
                    "getdescriptorinfo",
                    descriptor,
                ])
                .output()
                .map_err(|e| e.to_string())?
        }
    };
    if !output.status.success() {
        return Err(format!(
            "bitcoin-cli failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // Minimal JSON field extract without adding serde_json requirement on the
    // shape — we already depend on serde_json via the crate.
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("json: {e}; body={text}"))?;
    v.get("checksum")
        .and_then(|c| c.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| format!("no checksum field in {text}"))
}

fn our_checksum(descriptor_with_cs: &str) -> &str {
    descriptor_with_cs
        .rsplit_once('#')
        .map(|(_, cs)| cs)
        .expect("descriptor must carry checksum")
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
    // Three distinct seeds per setup.
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

/// Run with: `./scripts/test-env.sh up` then
/// `cargo test -p trinity-watch --locked -- --ignored d1_checksum`
#[test]
#[ignore = "D1 WP-11 Vorgriff: requires ./scripts/test-env.sh up; run with -- --ignored"]
fn d1_checksum_against_core_getdescriptorinfo() {
    let mode = match detect_rpc() {
        Some(m) => m,
        None => {
            // Forced run without environment: fail loudly (not silent green).
            panic!(
                "skipped: test environment not running \
                 (start with `./scripts/test-env.sh up`; RPC {RPC_USER}@{RPC_HOST}:{RPC_PORT})"
            );
        }
    };

    let started = std::time::Instant::now();
    let mut checked = 0u32;
    for i in 0..SETUPS {
        let doc = build_setup(i);
        for desc in [doc.receive(), doc.change()] {
            let ours = our_checksum(desc);
            // Core wants the descriptor *without* requiring a correct checksum
            // on input — pass with our checksum; Core recomputes.
            let core_cs = getdescriptorinfo(&mode, desc).unwrap_or_else(|e| {
                panic!("getdescriptorinfo failed on setup {i}: {e}\ndesc={desc}");
            });
            assert_eq!(
                ours, core_cs,
                "checksum mismatch setup={i} desc={desc} ours={ours} core={core_cs}"
            );
            checked += 1;
        }
        if i % 50 == 0 {
            let _ = std::io::stderr().flush();
        }
    }

    let elapsed = started.elapsed();
    eprintln!(
        "D1 WP-11 Vorgriff: {checked} descriptors (={SETUPS} setups × 2) matched Core checksums in {elapsed:?}"
    );
    assert_eq!(checked, SETUPS * 2);
    // Bound so a hung RPC cannot hang CI forever when env is up.
    assert!(elapsed < Duration::from_secs(600));
}
