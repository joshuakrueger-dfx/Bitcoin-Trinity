//! `descriptor.json` lossless round-trip, including mixed word lengths (WP-11).

use trinity_types::{Fingerprint, KeySlot, Network, WordCount, XpubWithOrigin};
use trinity_watch::descriptor::{
    bip48_origin_path, DescriptorSetup, KeyContribution, KeySource, WalletDescriptors,
};

const FP_A: &str = "73756c7f";
const FP_B: &str = "f9f62194";
const FP_C: &str = "c98b1535";
const XPUB_A: &str = "tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3";
const XPUB_B: &str = "tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4";
const XPUB_C: &str = "tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a";

fn mixed_setup() -> WalletDescriptors {
    let path = bip48_origin_path(Network::Regtest);
    DescriptorSetup {
        network: Network::Regtest,
        created_at_unix: 1_720_000_000,
        keys: [
            KeyContribution {
                slot: KeySlot::A,
                xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_A).unwrap(), &path, XPUB_A),
                birthday_height: 800_000,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
            KeyContribution {
                slot: KeySlot::B,
                xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_B).unwrap(), &path, XPUB_B),
                birthday_height: 800_001,
                word_count: WordCount::Words12,
                source: KeySource::Hardware {
                    model: "bitbox02".into(),
                },
                policy_id: Some("aabbccddeeff0011".into()),
            },
            KeyContribution {
                slot: KeySlot::C,
                xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_C).unwrap(), &path, XPUB_C),
                birthday_height: 800_002,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
        ],
    }
    .build()
    .expect("build")
}

#[test]
fn roundtrip_mixed_word_lengths_lossless() {
    let original = mixed_setup();
    assert_eq!(original.key(KeySlot::A).word_count, WordCount::Words24);
    assert_eq!(original.key(KeySlot::B).word_count, WordCount::Words12);
    assert_eq!(original.key(KeySlot::C).word_count, WordCount::Words24);

    let json = original.to_json().unwrap();
    // Spec map shape with integer word counts.
    assert!(json.contains("\"word_count\""));
    assert!(json.contains("\"A\""));
    assert!(json.contains("12"));
    assert!(json.contains("24"));
    assert!(json.contains("bitbox02"));
    assert!(json.contains("aabbccddeeff0011"));
    // O8: two descriptors, no multipath.
    assert!(json.contains("/0/*"));
    assert!(json.contains("/1/*"));
    assert!(!json.contains("<0;1>"));

    let restored = WalletDescriptors::from_json(&json).unwrap();
    assert_eq!(restored, original);
    assert_eq!(restored.receive(), original.receive());
    assert_eq!(restored.change(), original.change());
}

#[test]
fn input_key_order_does_not_change_slot_order() {
    let path = bip48_origin_path(Network::Regtest);
    // Pass keys as C, A, B — document must still order A, B, C.
    let d = DescriptorSetup {
        network: Network::Regtest,
        created_at_unix: 1,
        keys: [
            KeyContribution {
                slot: KeySlot::C,
                xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_C).unwrap(), &path, XPUB_C),
                birthday_height: 1,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
            KeyContribution {
                slot: KeySlot::A,
                xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_A).unwrap(), &path, XPUB_A),
                birthday_height: 1,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
            KeyContribution {
                slot: KeySlot::B,
                xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_B).unwrap(), &path, XPUB_B),
                birthday_height: 1,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
        ],
    }
    .build()
    .unwrap();

    assert_eq!(d.keys[0].slot, KeySlot::A);
    assert_eq!(d.keys[1].slot, KeySlot::B);
    assert_eq!(d.keys[2].slot, KeySlot::C);
    // Descriptor string lists A then B then C fingerprints.
    let recv = d.receive();
    let pos_a = recv.find(FP_A).unwrap();
    let pos_b = recv.find(FP_B).unwrap();
    let pos_c = recv.find(FP_C).unwrap();
    assert!(pos_a < pos_b && pos_b < pos_c);
}
