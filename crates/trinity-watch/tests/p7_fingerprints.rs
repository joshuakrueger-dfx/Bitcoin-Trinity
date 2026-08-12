//! P7 — identical master fingerprints rejected (Spec §2.3 / §5.2).

use trinity_types::{Fingerprint, KeySlot, Network, WordCount, XpubWithOrigin};
use trinity_watch::descriptor::{
    bip48_origin_path, DescriptorError, DescriptorSetup, KeyContribution, KeySource,
};

const XPUB_A: &str = "tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3";
const XPUB_B: &str = "tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4";
const XPUB_C: &str = "tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a";

fn key(slot: KeySlot, fp: [u8; 4], xpub: &str) -> KeyContribution {
    KeyContribution {
        slot,
        xpub: XpubWithOrigin::new(
            Fingerprint::new(fp),
            bip48_origin_path(Network::Regtest),
            xpub,
        ),
        birthday_height: 1,
        word_count: WordCount::Words24,
        source: KeySource::InApp,
        policy_id: None,
    }
}

#[test]
fn p7_rejects_a_equals_b() {
    let setup = DescriptorSetup {
        network: Network::Regtest,
        created_at_unix: 0,
        keys: [
            key(KeySlot::A, [1, 2, 3, 4], XPUB_A),
            key(KeySlot::B, [1, 2, 3, 4], XPUB_B), // same fp as A
            key(KeySlot::C, [5, 6, 7, 8], XPUB_C),
        ],
    };
    match setup.build() {
        Err(DescriptorError::DuplicateFingerprint(hex)) => {
            assert_eq!(hex, "01020304");
        }
        other => panic!("expected DuplicateFingerprint, got {other:?}"),
    }
}

#[test]
fn p7_rejects_b_equals_c() {
    let setup = DescriptorSetup {
        network: Network::Regtest,
        created_at_unix: 0,
        keys: [
            key(KeySlot::A, [1, 0, 0, 1], XPUB_A),
            key(KeySlot::B, [2, 0, 0, 2], XPUB_B),
            key(KeySlot::C, [2, 0, 0, 2], XPUB_C),
        ],
    };
    assert!(matches!(
        setup.build(),
        Err(DescriptorError::DuplicateFingerprint(_))
    ));
}

#[test]
fn p7_accepts_three_distinct() {
    let setup = DescriptorSetup {
        network: Network::Regtest,
        created_at_unix: 0,
        keys: [
            key(KeySlot::A, [0x73, 0x75, 0x6c, 0x7f], XPUB_A),
            key(KeySlot::B, [0xf9, 0xf6, 0x21, 0x94], XPUB_B),
            key(KeySlot::C, [0xc9, 0x8b, 0x15, 0x35], XPUB_C),
        ],
    };
    assert!(setup.build().is_ok());
}
