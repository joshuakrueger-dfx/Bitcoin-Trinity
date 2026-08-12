//! D6 — BIP-67 via `WatchWallet` (WP-12).
//!
//! Spec already documents that `sortedmulti` is order-invariant (measured).
//! Here we verify that **wallet construction** (BDK `Wallet::create` from
//! Trinity descriptors) preserves that property: all 6 key-order permutations
//! yield identical receive and change addresses at the same indices.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network as BtcNetwork;
use trinity_types::{Fingerprint, KeychainKind, Network, XpubWithOrigin};
use trinity_watch::descriptor::build::{address_at, build_sortedmulti_permutation};
use trinity_watch::WatchWallet;

fn master_at(seed_tag: u8) -> XpubWithOrigin {
    let secp = Secp256k1::new();
    let mut seed = [seed_tag; 64];
    seed[0] = seed_tag;
    seed[1] = seed_tag.wrapping_add(7);
    let master = Xpriv::new_master(BtcNetwork::Regtest, &seed).expect("master");
    let master_fp = master.fingerprint(&secp);
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let account = master.derive_priv(&secp, &path).unwrap();
    let xpub = Xpub::from_priv(&secp, &account);
    XpubWithOrigin::new(
        Fingerprint::new(master_fp.to_bytes()),
        "48'/1'/0'/2'",
        xpub.to_string(),
    )
}

#[test]
fn d6_six_permutations_same_wallet_addresses() {
    let a = master_at(21);
    let b = master_at(22);
    let c = master_at(23);
    let keys = [&a, &b, &c];

    let perms: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    let mut ref_recv: Option<Vec<String>> = None;
    let mut ref_change: Option<Vec<String>> = None;

    for (pi, perm) in perms.iter().enumerate() {
        let ordered = [keys[perm[0]], keys[perm[1]], keys[perm[2]]];
        let receive = build_sortedmulti_permutation(ordered, "0/*").expect("recv");
        let change = build_sortedmulti_permutation(ordered, "1/*").expect("chg");

        let wallet = WatchWallet::from_descriptor_strings(Network::Regtest, &receive, &change)
            .unwrap_or_else(|e| panic!("perm {pi}: open wallet: {e}"));

        let recv_addrs: Vec<String> = (0..8)
            .map(|i| wallet.peek_address(KeychainKind::External, i).address)
            .collect();
        let chg_addrs: Vec<String> = (0..8)
            .map(|i| wallet.peek_address(KeychainKind::Internal, i).address)
            .collect();

        // Cross-check wallet peek against descriptor-level derive (same sortedmulti).
        for i in 0..8u32 {
            let from_desc = address_at(&receive, i, BtcNetwork::Regtest).expect("addr_at receive");
            assert_eq!(
                recv_addrs[i as usize], from_desc,
                "perm {pi} receive index {i}: wallet vs descriptor diverge"
            );
        }

        match &ref_recv {
            None => {
                ref_recv = Some(recv_addrs);
                ref_change = Some(chg_addrs);
            }
            Some(r) => {
                assert_eq!(&recv_addrs, r, "D6 receive perm {pi} diverged");
                assert_eq!(
                    &chg_addrs,
                    ref_change.as_ref().unwrap(),
                    "D6 change perm {pi} diverged"
                );
            }
        }
    }
}
