//! Shared setup generation and derivation helpers for the differential harness.
//!
//! Spec §5.1 D4/D5 (WP-23): 500 deterministic 2-of-3 setups, 1_000 receive
//! addresses each. D4 compares `trinity-verify` to Core `deriveaddresses`;
//! D5 compares `trinity-verify` to `trinity-watch`. Both tests consume the
//! same generator so they never drift onto a second vector set.
//!
//! Key generation follows the WP-12 D2/D3 pattern (`xpub_from_tag` via
//! SHA-256 → BIP-32 master → `m/48'/1'/0'/2'`), mixed with a fixed seed so
//! the 500 setups are reproducible without a new RNG crate.

#![forbid(unsafe_code)]

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network as BtcNetwork;
use trinity_types::{Fingerprint, KeySlot, KeychainKind, Network, WordCount, XpubWithOrigin};
use trinity_watch::descriptor::{bip48_origin_path, DescriptorSetup, KeyContribution, KeySource};
use trinity_watch::{WalletDescriptors, WatchWallet};

/// Spec §5.1: 500 random 2-of-3 setups.
pub const SETUPS: u32 = 500;
/// Spec §5.1: `deriveaddresses(desc, [0, 999])` — 1_000 receive addresses.
pub const ADDRS: u32 = 1_000;
/// Inclusive end index for Core `deriveaddresses` range `[0, ADDR_END]`.
pub const ADDR_END: u32 = ADDRS - 1;

/// Fixed seed mixed into each setup tag (TESTING.md §2.4).
///
/// ASCII `TRINITY#` — same family as [`trinity_watch::PSBT_BUILD_SEED`].
pub const SETUP_SEED: u64 = 0x5452_494e_4954_5923;

/// Fixed seed for D7/D8 PSBT variants (TESTING.md §2.4).
///
/// ASCII `D7D8PSBT`. Distinct from [`SETUP_SEED`] so the signature-vector
/// set cannot be confused with the D4/D5 address setups.
pub const D7D8_SEED: u64 = 0x4437_4438_5053_4254;
/// Spec §5.1: 1_000 PSBTs each for D7 (`sign_a`) and D8 (`sign_b`).
pub const D7D8_PSBTS: u32 = 1_000;

/// One deterministic 2-of-3 descriptor document (receive + change).
#[derive(Clone, Debug)]
pub struct Setup {
    /// Setup ordinal in `0..SETUPS`.
    pub index: u32,
    /// Built receive/change descriptors and key metadata.
    pub descriptors: WalletDescriptors,
}

impl Setup {
    /// Receive descriptor string (`wsh(sortedmulti(2,…/0/*))#checksum`).
    #[must_use]
    pub fn receive(&self) -> &str {
        self.descriptors.receive()
    }

    /// Change descriptor string (`wsh(sortedmulti(2,…/1/*))#checksum`).
    #[must_use]
    pub fn change(&self) -> &str {
        self.descriptors.change()
    }
}

/// Build the `i`-th deterministic 2-of-3 setup (`i` in `0..SETUPS`).
#[must_use]
pub fn setup_at(i: u32) -> Setup {
    let a = xpub_from_tag(i * 3 + 1);
    let b = xpub_from_tag(i * 3 + 2);
    let c = xpub_from_tag(i * 3 + 3);
    let descriptors = DescriptorSetup {
        network: Network::Regtest,
        created_at_unix: 1_700_000_000 + u64::from(i),
        keys: [
            contribution(KeySlot::A, a, i),
            contribution(KeySlot::B, b, i),
            contribution(KeySlot::C, c, i),
        ],
    }
    .build()
    .expect("build 2-of-3 descriptors");
    Setup {
        index: i,
        descriptors,
    }
}

/// All 500 setups in order. Shared by D4 and D5 — do not re-generate.
pub fn all_setups() -> impl Iterator<Item = Setup> {
    (0..SETUPS).map(setup_at)
}

/// 1_000 receive addresses from `trinity-verify` (own parser + own BIP-32).
pub fn verify_receive_addresses(receive_desc: &str) -> Vec<String> {
    let parsed = trinity_verify::parse(receive_desc).unwrap_or_else(|e| {
        panic!("trinity-verify parse failed: {e}\ninput={receive_desc}");
    });
    (0..ADDRS)
        .map(|i| {
            let out = trinity_verify::derive_at(&parsed, i).unwrap_or_else(|e| {
                panic!("trinity-verify derive_at({i}) failed: {e}\ninput={receive_desc}");
            });
            out.address(BtcNetwork::Regtest).to_string()
        })
        .collect()
}

/// 1_000 receive addresses from `trinity-watch` (BDK / miniscript builder).
///
/// Uses [`WatchWallet::reveal_next_address`] (public API) in a fresh wallet so
/// each index is derived once. [`WatchWallet::derive_addresses`] peeks via
/// BDK `Iterator::nth`, which re-walks `0..=i` per call — O(n²) and too slow
/// for 500 × 1_000 in debug.
pub fn watch_receive_addresses(descriptors: &WalletDescriptors) -> Vec<String> {
    let mut wallet = WatchWallet::from_descriptors(descriptors).unwrap_or_else(|e| {
        panic!(
            "WatchWallet::from_descriptors failed: {e}\nreceive={}",
            descriptors.receive()
        );
    });
    (0..ADDRS)
        .map(|i| {
            let info = wallet.reveal_next_address(KeychainKind::External);
            assert_eq!(
                info.index,
                i,
                "WatchWallet reveal_next_address order broke at {i} (got index {})\nreceive={}",
                info.index,
                descriptors.receive()
            );
            info.address
        })
        .collect()
}

fn contribution(slot: KeySlot, xpub: XpubWithOrigin, i: u32) -> KeyContribution {
    KeyContribution {
        slot,
        xpub,
        birthday_height: i,
        word_count: WordCount::Words24,
        source: KeySource::InApp,
        policy_id: None,
    }
}

/// Deterministic account xpub: SHA-256(seed || tag) → master → BIP-48.
///
/// Same construction as `crates/trinity-watch/tests/d2_d3_addresses.rs`
/// (`xpub_from_tag`), with [`SETUP_SEED`] mixed in so the 500-case set is a
/// documented, fixed vector rather than an implicit hash of the tag alone.
fn xpub_from_tag(tag: u32) -> XpubWithOrigin {
    let secp = Secp256k1::new();
    let mut material = [0u8; 12];
    material[..8].copy_from_slice(&SETUP_SEED.to_be_bytes());
    material[8..].copy_from_slice(&tag.to_be_bytes());
    let seed = sha256::Hash::hash(&material);
    let master = Xpriv::new_master(BtcNetwork::Regtest, seed.as_byte_array()).expect("master");
    let fp = master.fingerprint(&secp);
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").expect("bip48 path");
    let account = master.derive_priv(&secp, &path).expect("account");
    let xpub = Xpub::from_priv(&secp, &account);
    XpubWithOrigin::new(
        Fingerprint::new(fp.to_bytes()),
        bip48_origin_path(Network::Regtest),
        xpub.to_string(),
    )
}

#[cfg(feature = "differential")]
pub mod rpc;
#[cfg(feature = "differential")]
pub mod rpc_signer;
