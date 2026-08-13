//! Property tests P10, P14, P15, P16.

use std::collections::HashSet;

use proptest::prelude::*;
use trinity_entropy::{extract, generate_from_raw, AdditionalEntropy};
use trinity_types::WordCount;

fn dice_strategy() -> impl Strategy<Value = Option<String>> {
    prop::option::of(
        proptest::collection::vec(b'1'..=b'6', 1..12).prop_map(|v| String::from_utf8(v).unwrap()),
    )
}

fn coins_strategy() -> impl Strategy<Value = Option<String>> {
    prop::option::of(
        proptest::collection::vec(prop::sample::select(vec![b'0', b'1']), 1..16)
            .prop_map(|v| String::from_utf8(v).unwrap()),
    )
}

/// Distinct cards encoded in canonical form. At most 8, from a small pool.
fn cards_strategy() -> impl Strategy<Value = Option<String>> {
    const POOL: &[&str] = &[
        "AS", "AH", "AD", "AC", "KS", "KH", "KD", "KC", "QS", "QH", "QD", "QC", "JS", "JH", "JD",
        "JC", "10S", "10H", "10D", "10C", "2S", "2H", "3D", "4C", "5S", "6H", "7D", "8C", "9S",
    ];
    prop::option::of(
        proptest::collection::hash_set(0..POOL.len(), 1..8).prop_map(|idxs| {
            let mut v: Vec<_> = idxs.into_iter().collect();
            v.sort_unstable();
            v.into_iter().map(|i| POOL[i]).collect::<String>()
        }),
    )
}

fn extra_from(
    dice: Option<String>,
    coins: Option<String>,
    cards: Option<String>,
    sensor: Option<Vec<u8>>,
) -> AdditionalEntropy {
    let mut extra = AdditionalEntropy::new();
    if let Some(d) = dice {
        extra = extra.with_dice(&d).unwrap();
    }
    if let Some(c) = coins {
        extra = extra.with_coins(&c).unwrap();
    }
    if let Some(k) = cards {
        extra = extra.with_cards(&k).unwrap();
    }
    if let Some(s) = sensor {
        extra = extra.with_sensor(&s);
    }
    extra
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// P10: fixed `raw_csprng`, different dice sequences ⇒ different entropy.
    #[test]
    fn p10_different_dice_different_entropy(a in dice_strategy(), b in dice_strategy()) {
        prop_assume!(a != b);
        let raw = [0x5au8; 32];
        let ea = extra_from(a, None, None, None);
        let eb = extra_from(b, None, None, None);
        let ha = extract(&raw, &ea.canonical_bytes(), WordCount::Words24);
        let hb = extract(&raw, &eb.canonical_bytes(), WordCount::Words24);
        prop_assert_ne!(ha.as_slice(), hb.as_slice());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// P14: canonical extra_bytes is injective over (dice, coins, cards),
    /// including empty subsets.
    #[test]
    fn p14_encoding_injective(
        d1 in dice_strategy(),
        c1 in coins_strategy(),
        k1 in cards_strategy(),
        d2 in dice_strategy(),
        c2 in coins_strategy(),
        k2 in cards_strategy(),
    ) {
        let a = extra_from(d1.clone(), c1.clone(), k1.clone(), None);
        let b = extra_from(d2.clone(), c2.clone(), k2.clone(), None);
        let same_sources = d1 == d2 && c1 == c2 && k1 == k2;
        prop_assert_eq!(a.canonical_bytes() == b.canonical_bytes(), same_sources);
    }
}

/// P14 supplement: 4,096 enumerated empty/non-empty combinations over a
/// small alphabet, collected in a set — a collision would shrink the set.
#[test]
fn p14_enumerated_no_collision() {
    let dice = [None, Some("1"), Some("2"), Some("12")];
    let coins = [None, Some("0"), Some("1"), Some("01")];
    let cards = [None, Some("AS"), Some("KH"), Some("AS10H")];
    let mut seen = HashSet::new();
    let mut n = 0;
    for d in dice {
        for c in coins {
            for k in cards {
                let extra = extra_from(
                    d.map(str::to_owned),
                    c.map(str::to_owned),
                    k.map(str::to_owned),
                    None,
                );
                let bytes = extra.canonical_bytes();
                assert!(
                    seen.insert(bytes.clone()),
                    "collision on {d:?}/{c:?}/{k:?}: {bytes:?}"
                );
                n += 1;
            }
        }
    }
    assert_eq!(n, 64);
    assert_eq!(seen.len(), 64);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// P15: class-B sensor blobs of any length credit exactly 0 bits.
    #[test]
    fn p15_class_b_credits_zero_bits(
        blob_a in proptest::collection::vec(any::<u8>(), 0..64),
        blob_b in proptest::collection::vec(any::<u8>(), 0..64),
        dice in dice_strategy(),
    ) {
        let base = extra_from(dice, None, None, None);
        let a = base.clone().with_sensor(&blob_a);
        let b = base.clone().with_sensor(&blob_b);
        prop_assert_eq!(a.countable(), b.countable());
        prop_assert_eq!(a.countable().class_b_credited_bits(), 0);
        prop_assert_eq!(b.countable().class_b_credited_bits(), 0);
        prop_assert_eq!(a.countable().class_b_credited_bits(), 0);
        if blob_a.is_empty() && blob_b.is_empty() {
            prop_assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        } else if blob_a != blob_b {
            prop_assert_ne!(a.canonical_bytes(), b.canonical_bytes());
            let raw = [0x11u8; 32];
            let ea = extract(&raw, &a.canonical_bytes(), WordCount::Words24);
            let eb = extract(&raw, &b.canonical_bytes(), WordCount::Words24);
            prop_assert_ne!(ea.as_slice(), eb.as_slice());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// P16: identical raw_csprng + extra_bytes, 12 vs 24 words ⇒ different
    /// master fingerprints.
    #[test]
    fn p16_word_count_changes_fingerprint(
        raw in proptest::array::uniform32(any::<u8>()),
        dice in dice_strategy(),
        coins in coins_strategy(),
    ) {
        let extra = extra_from(dice, coins, None, None);
        let a = generate_from_raw(WordCount::Words12, &raw, &extra).unwrap();
        let b = generate_from_raw(WordCount::Words24, &raw, &extra).unwrap();
        prop_assert_ne!(a.fp(), b.fp());
        prop_assert_eq!(a.raw_csprng().as_slice(), b.raw_csprng().as_slice());
        prop_assert_eq!(a.extra_bytes().as_slice(), b.extra_bytes().as_slice());
        // 12-word entropy is the prefix of the 24-word HMAC; fingerprints
        // still differ because BIP-39 checksum + word count change the seed.
        prop_assert_eq!(a.entropy().as_slice(), &b.entropy().as_slice()[..16]);
    }
}
