//! P5 — sortedmulti is permutation-invariant for addresses (Spec §5.2 / WP-11).
//!
//! All 6 key orders in the multisig yield identical addresses at the same index.
//! Counter-check with plain `multi` is left to differential harness notes;
//! here we lock the sortedmulti property used by Trinity.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network as BtcNetwork;
use miniscript::{Descriptor, DescriptorPublicKey};
use trinity_types::{Fingerprint, XpubWithOrigin};
use trinity_watch::descriptor::build::{address_at, build_sortedmulti_permutation};

fn master_at(seed_tag: u8) -> (Fingerprint, XpubWithOrigin) {
    let secp = Secp256k1::new();
    let mut seed = [seed_tag; 64];
    seed[0] = seed_tag;
    seed[1] = seed_tag.wrapping_add(1);
    let master = Xpriv::new_master(BtcNetwork::Testnet, &seed).expect("master");
    let master_fp = master.fingerprint(&secp);
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let account = master.derive_priv(&secp, &path).unwrap();
    let xpub = Xpub::from_priv(&secp, &account);
    let origin = XpubWithOrigin::new(
        Fingerprint::new(master_fp.to_bytes()),
        "48'/1'/0'/2'",
        xpub.to_string(),
    );
    (Fingerprint::new(master_fp.to_bytes()), origin)
}

#[test]
fn p5_six_permutations_same_addresses() {
    let (_, a) = master_at(1);
    let (_, b) = master_at(2);
    let (_, c) = master_at(3);
    let keys = [&a, &b, &c];

    // All 6 orders of the three keys.
    let perms: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    let mut reference_addrs: Option<Vec<String>> = None;
    for (pi, perm) in perms.iter().enumerate() {
        let ordered = [keys[perm[0]], keys[perm[1]], keys[perm[2]]];
        let desc = build_sortedmulti_permutation(ordered, "0/*").expect("build");
        assert!(desc.starts_with("wsh(sortedmulti(2,"), "perm {pi}: {desc}");

        let addrs: Vec<String> = (0..5)
            .map(|i| address_at(&desc, i, BtcNetwork::Testnet).expect("addr"))
            .collect();

        match &reference_addrs {
            None => reference_addrs = Some(addrs),
            Some(r) => assert_eq!(&addrs, r, "permutation {pi} diverged"),
        }
    }
}

#[test]
fn p5_multi_countercheck_diverges() {
    // Sanity: plain multi (NOT what Trinity uses) changes addresses under reorder.
    // Locks that our P5 test is not a vacuous truth (Spec §2.3 counter-check).
    let (_, a) = master_at(10);
    let (_, b) = master_at(11);
    let (_, c) = master_at(12);

    fn multi_desc(order: [&XpubWithOrigin; 3]) -> String {
        let pks: Vec<DescriptorPublicKey> = order
            .iter()
            .map(|x| {
                let s = format!("[{}/{}]{}/0/*", x.fingerprint, x.origin_path, x.xpub);
                DescriptorPublicKey::from_str(&s).unwrap()
            })
            .collect();
        // multi via miniscript string parse
        let body = format!("wsh(multi(2,{},{},{}))", pks[0], pks[1], pks[2]);
        Descriptor::<DescriptorPublicKey>::from_str(&body)
            .unwrap()
            .to_string()
    }

    let d1 = multi_desc([&a, &b, &c]);
    let d2 = multi_desc([&c, &b, &a]);
    let addr1 = address_at(&d1, 0, BtcNetwork::Testnet).unwrap();
    let addr2 = address_at(&d2, 0, BtcNetwork::Testnet).unwrap();
    assert_ne!(
        addr1, addr2,
        "multi must diverge under reorder — otherwise P5 is vacuous"
    );
}
