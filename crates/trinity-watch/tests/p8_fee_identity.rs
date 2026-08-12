//! P8 — fee identity and overflow edge cases (WP-12 / Spec §5.2).
//!
//! `fee = Σin − Σout` holds for every built PSBT; no overflow, no negative fee.
//! Builds use `finish_with_aux_rand` with [`trinity_watch::PSBT_BUILD_SEED`].

use bdk_wallet::bitcoin::key::rand::{rngs::StdRng, SeedableRng};
use proptest::prelude::*;
use trinity_types::{
    FeeTarget, Fingerprint, KeySlot, KeychainKind, Network, SendRequest, WordCount, XpubWithOrigin,
};
use trinity_watch::descriptor::{
    bip48_origin_path, build_wallet_descriptors, KeyContribution, KeySource,
};
use trinity_watch::{WatchWallet, PSBT_BUILD_SEED};

const FP_A: &str = "73756c7f";
const FP_B: &str = "f9f62194";
const FP_C: &str = "c98b1535";
const XPUB_A: &str = "tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3";
const XPUB_B: &str = "tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4";
const XPUB_C: &str = "tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a";

fn open_wallet() -> WatchWallet {
    let path = bip48_origin_path(Network::Regtest);
    let keys = [
        KeyContribution {
            slot: KeySlot::A,
            xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_A).unwrap(), path.clone(), XPUB_A),
            birthday_height: 1,
            word_count: WordCount::Words24,
            source: KeySource::InApp,
            policy_id: None,
        },
        KeyContribution {
            slot: KeySlot::B,
            xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_B).unwrap(), path.clone(), XPUB_B),
            birthday_height: 1,
            word_count: WordCount::Words24,
            source: KeySource::InApp,
            policy_id: None,
        },
        KeyContribution {
            slot: KeySlot::C,
            xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_C).unwrap(), path, XPUB_C),
            birthday_height: 1,
            word_count: WordCount::Words24,
            source: KeySource::InApp,
            policy_id: None,
        },
    ];
    let d = build_wallet_descriptors(Network::Regtest, keys, 1_700_000_000).unwrap();
    WatchWallet::from_descriptors(&d).unwrap()
}

fn funded_wallet(amount_sats: u64) -> WatchWallet {
    let mut w = open_wallet();
    w.inject_confirmed_utxo(amount_sats, KeychainKind::External)
        .unwrap();
    w.ensure_tip_at_least(1).unwrap();
    w
}

#[test]
fn p8_fee_equals_sum_in_minus_sum_out_absolute() {
    let mut w = funded_wallet(250_000);
    let recipient = w.peek_address(KeychainKind::External, 7).address;
    let req = SendRequest::new(recipient, 40_000, FeeTarget::AbsoluteSats(3_000));
    let mut rng = StdRng::seed_from_u64(PSBT_BUILD_SEED);
    let psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
    let (fee, sum_in, sum_out) = WatchWallet::fee_identity(&psbt).unwrap();
    assert_eq!(fee.checked_add(sum_out), Some(sum_in));
    assert_eq!(fee, 3_000);
}

#[test]
fn p8_fee_equals_sum_in_minus_sum_out_feerate() {
    let mut w = funded_wallet(300_000);
    let recipient = w.peek_address(KeychainKind::External, 8).address;
    let req = SendRequest::new(recipient, 50_000, FeeTarget::FeerateSatVb(5));
    let mut rng = StdRng::seed_from_u64(PSBT_BUILD_SEED);
    let psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
    let (fee, sum_in, sum_out) = WatchWallet::fee_identity(&psbt).unwrap();
    assert_eq!(fee.checked_add(sum_out), Some(sum_in));
    assert!(fee > 0);
}

#[test]
fn p8_dust_bound_change_still_fee_identity() {
    // Leave a dust-sized remainder after fee so change is dropped into fee.
    let mut w = funded_wallet(100_000);
    let recipient = w.peek_address(KeychainKind::External, 2).address;
    let req = SendRequest::new(recipient, 98_500, FeeTarget::AbsoluteSats(1_400));
    // remaining would be 100 sats if fee were exactly 1_400 → dust → absorbed.
    let mut rng = StdRng::seed_from_u64(PSBT_BUILD_SEED);
    let psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
    let (fee, sum_in, sum_out) = WatchWallet::fee_identity(&psbt).unwrap();
    assert_eq!(fee.checked_add(sum_out), Some(sum_in));
    assert_eq!(sum_in, 100_000);
    assert_eq!(sum_out, 98_500);
    assert!(fee >= 1_400);
}

/// Property: for varied fund / send / fee triples that BDK accepts, fee
/// identity holds under a fixed build seed.
fn p8_strategy() -> impl Strategy<Value = (u64, u64, u64)> {
    // fund in [50_000, 5_000_000], send < fund - fee floor, fee in [200, 50_000]
    (50_000u64..5_000_000, 200u64..50_000).prop_flat_map(|(fund, fee)| {
        let max_send = fund.saturating_sub(fee).saturating_sub(1_000);
        let send_range = 1_000u64..=max_send.max(1_000);
        send_range.prop_map(move |send| (fund, send, fee))
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn p8_property_fee_identity( (fund, send, fee) in p8_strategy() ) {
        let mut w = funded_wallet(fund);
        let recipient = w.peek_address(KeychainKind::External, 3).address;
        let req = SendRequest::new(recipient, send, FeeTarget::AbsoluteSats(fee));
        let mut rng = StdRng::seed_from_u64(PSBT_BUILD_SEED);
        match w.build_psbt_raw_with_aux_rand(&req, &mut rng) {
            Ok(psbt) => {
                let (got_fee, sum_in, sum_out) = WatchWallet::fee_identity(&psbt).unwrap();
                prop_assert_eq!(got_fee.checked_add(sum_out), Some(sum_in));
                prop_assert!(got_fee >= fee || psbt.unsigned_tx.output.len() == 1,
                    "fee {got_fee} < requested {fee} without dust absorption");
            }
            Err(_) => {
                // Insufficient funds / dust recipient: builder correctly rejects.
                // Not a fee-identity violation.
            }
        }
    }
}

#[test]
fn p8_overflow_path_on_stripped_inputs_is_not_negative() {
    // fee_identity refuses missing UTXO data rather than returning a negative fee.
    let mut w = funded_wallet(80_000);
    let recipient = w.peek_address(KeychainKind::External, 1).address;
    let req = SendRequest::new(recipient, 10_000, FeeTarget::AbsoluteSats(500));
    let mut rng = StdRng::seed_from_u64(PSBT_BUILD_SEED);
    let mut psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
    for input in &mut psbt.inputs {
        input.witness_utxo = None;
        input.non_witness_utxo = None;
    }
    assert!(WatchWallet::fee_identity(&psbt).is_err());
}
