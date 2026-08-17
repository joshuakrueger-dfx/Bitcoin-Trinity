//! S28, S29, S29b, S29f, S29h, S29i, S29j, S29k — Spec §5.3 / WP-34.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    WPubkeyHash, Witness,
};
use trinity_types::{Balance, SecretBytes};
use trinity_verify::{derive_at, parse, VerifyPolicy};

use crate::tests_wp33::{
    bip32_derivation_for, build_psbt, default_wallet, outpoint, pair_signers, BuiltPsbt,
    WalletFixture,
};
use crate::{
    allowance, set_spend_policy, sign_ab, FakeBlockHeightSource, FakeClock, SignError,
    SpendApproval, SpendPolicy, SpendSession, WindowCounter,
};

const CORE_KEK: [u8; 32] = [0x3C; 32];

fn foreign_spk() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x42; 20]))
}

fn foreign_addr() -> String {
    Address::from_script(&foreign_spk(), Network::Regtest)
        .unwrap()
        .to_string()
}

fn build_foreign_send(
    wallet: &WalletFixture,
    op: OutPoint,
    input_index: u32,
    change_index: u32,
    input_sats: u64,
    send_sats: u64,
    fee_sats: u64,
) -> BuiltPsbt {
    let recv = parse(&wallet.receive).unwrap();
    let chg = parse(&wallet.change).unwrap();
    let in_der = derive_at(&recv, input_index).unwrap();
    let ch_der = derive_at(&chg, change_index).unwrap();
    let change_sats = input_sats - send_sats - fee_sats;
    let recip = foreign_spk();
    let recip_addr = foreign_addr();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(send_sats),
                script_pubkey: recip,
            },
            TxOut {
                value: Amount::from_sat(change_sats),
                script_pubkey: ch_der.script_pubkey.clone(),
            },
        ],
    };
    let witness_utxo = TxOut {
        value: Amount::from_sat(input_sats),
        script_pubkey: in_der.script_pubkey.clone(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(witness_utxo.clone());
    psbt.inputs[0].witness_script = Some(in_der.witness_script.clone());
    psbt.inputs[0].bip32_derivation = bip32_derivation_for(&recv, input_index);
    psbt.outputs[1].bip32_derivation = bip32_derivation_for(&chg, change_index);

    let mut known = BTreeMap::new();
    known.insert(op, witness_utxo);
    let policy = VerifyPolicy::new(
        vec![recip_addr],
        send_sats,
        fee_sats.saturating_mul(10).max(50_000),
        5_000,
        None,
        20,
        known,
        Some(wallet.change.clone()),
        Network::Regtest,
    );
    BuiltPsbt { psbt, policy }
}

fn ready_counter() -> WindowCounter {
    let mut c = WindowCounter::new(SecretBytes::from_slice(&CORE_KEK)).unwrap();
    c.set_passphrase_used_since_install(true);
    c
}

fn session<'a>(
    policy: &'a SpendPolicy,
    counter: &'a mut WindowCounter,
    clock: &'a FakeClock,
    blocks: &'a FakeBlockHeightSource,
    confirmed: u64,
    wall: Option<u64>,
) -> SpendSession<'a> {
    SpendSession {
        policy,
        counter,
        clock,
        blocks,
        balance: Balance {
            confirmed_sats: confirmed,
            trusted_pending_sats: 0,
            untrusted_pending_sats: 0,
            immature_sats: 0,
        },
        wall_unix_ns: wall,
    }
}

#[test]
fn s28_spend_above_share_does_not_unwrap_kek() {
    let wallet = default_wallet();
    let (a, fake_a, b, fake_b) = pair_signers(&wallet);
    // 20 % of 1_000 = 200; send 300 + fee 10 = 310 > 200.
    let built = build_foreign_send(&wallet, outpoint(1), 0, 0, 10_000, 300, 10);
    let mut counter = ready_counter();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(100));
    let policy = SpendPolicy::standard();
    fake_a.reset_calls();
    fake_b.reset_calls();
    let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
    let err = sign_ab(
        &a,
        &b,
        built.psbt,
        &wallet.receive,
        &built.policy,
        &mut spend,
    )
    .unwrap_err();
    assert_eq!(err, SignError::SpendLimitExceeded);
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);
}

#[test]
fn s29_splitting_does_not_help_and_counter_survives_restart() {
    let wallet = default_wallet();
    let (a, _, b, _) = pair_signers(&wallet);
    let policy = SpendPolicy::standard();
    let mut counter = ready_counter();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(200));
    // allowance at 1_000 = 200. Four × 50 = 200; fifth is over.
    for i in 1u8..=4 {
        let built = build_foreign_send(&wallet, outpoint(i), 0, 0, 10_000, 45, 5);
        let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
        sign_ab(
            &a,
            &b,
            built.psbt,
            &wallet.receive,
            &built.policy,
            &mut spend,
        )
        .unwrap();
    }
    assert_eq!(counter.booked_sat(), 200);

    let blob = counter.seal().unwrap();
    // "Not resettable by deleting JS-readable files" is not testable here:
    // the core never opens a path. The app-layer WP that persists the blob
    // must prove a JS-visible sidecar cannot reset it.

    clock.reboot();
    let mut restored = WindowCounter::open(SecretBytes::from_slice(&CORE_KEK), &blob).unwrap();
    assert_eq!(restored.booked_sat(), 200);
    assert!(restored.passphrase_used_since_install());

    let built = build_foreign_send(&wallet, outpoint(9), 0, 0, 10_000, 45, 5);
    let mut spend = session(&policy, &mut restored, &clock, &blocks, 1_000, None);
    let err = sign_ab(
        &a,
        &b,
        built.psbt,
        &wallet.receive,
        &built.policy,
        &mut spend,
    )
    .unwrap_err();
    assert_eq!(err, SignError::SpendLimitExceeded);
}

#[test]
fn s29_full_booking_table_rejects_without_unwrap() {
    let wallet = default_wallet();
    let (a, fake_a, b, fake_b) = pair_signers(&wallet);
    let policy = SpendPolicy::off();
    let mut counter = ready_counter();
    for i in 0..crate::core_state::MAX_BOOKINGS {
        let set: BTreeSet<OutPoint> = [OutPoint {
            txid: Txid::from_byte_array([(i % 256) as u8; 32]),
            vout: i as u32,
        }]
        .into_iter()
        .collect();
        counter.commit(SpendApproval::new(set, 1));
    }
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(50));
    let built = build_foreign_send(&wallet, outpoint(40), 0, 0, 10_000, 40, 10);
    fake_a.reset_calls();
    fake_b.reset_calls();
    let mut spend = session(&policy, &mut counter, &clock, &blocks, 10_000, None);
    let err = sign_ab(
        &a,
        &b,
        built.psbt,
        &wallet.receive,
        &built.policy,
        &mut spend,
    )
    .unwrap_err();
    assert_eq!(err, SignError::SpendLimitExceeded);
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);
}

#[test]
fn s29b_clamp_via_authorize_matches_allowance() {
    let p = SpendPolicy::standard();
    let expected: &[(u64, u64)] = &[
        (0, 0),
        (100, 100),
        (199, 199),
        (200, 200),
        (999, 200),
        (1000, 200),
        (1500, 300),
        (2500, 500),
        (2501, 500),
        (10_000, 500),
    ];
    for &(bal, want) in expected {
        assert_eq!(allowance(&p, bal), want, "balance {bal}");
    }

    let wallet = default_wallet();
    let (a, _, b, _) = pair_signers(&wallet);
    let mut counter = ready_counter();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(50));
    // allowance at 1_000 = 200; 150 is under, 250 is over.
    let under = build_foreign_send(&wallet, outpoint(30), 0, 0, 10_000, 140, 10);
    {
        let mut spend = session(&p, &mut counter, &clock, &blocks, 1_000, None);
        sign_ab(
            &a,
            &b,
            under.psbt,
            &wallet.receive,
            &under.policy,
            &mut spend,
        )
        .unwrap();
    }
    let over = build_foreign_send(&wallet, outpoint(31), 0, 0, 10_000, 240, 10);
    let mut spend = session(&p, &mut counter, &clock, &blocks, 1_000, None);
    assert_eq!(
        sign_ab(&a, &b, over.psbt, &wallet.receive, &over.policy, &mut spend,).unwrap_err(),
        SignError::SpendLimitExceeded
    );
}

#[test]
fn s29f_floor_above_cap_rejected_not_reshaped() {
    let mut p = SpendPolicy::standard();
    p.window_floor_sat = Some(800);
    p.window_cap_sat = Some(200);
    assert_eq!(set_spend_policy(p), Err(SignError::FloorAboveCap));
    p.window_floor_sat = Some(200);
    p.window_cap_sat = Some(100);
    assert_eq!(set_spend_policy(p), Err(SignError::FloorAboveCap));
    let ok = SpendPolicy::standard();
    assert_eq!(set_spend_policy(ok).unwrap().window_floor_sat, Some(200));
}

#[test]
fn s29h_accounting_change_fee_self_rbf_dropped() {
    let wallet = default_wallet();

    // Change + foreign: charge = send + fee, not change.
    let with_change = build_foreign_send(&wallet, outpoint(1), 0, 0, 10_000, 100, 25);
    let charge =
        crate::window::spend_charge(&with_change.psbt, &wallet.receive, &with_change.policy)
            .unwrap();
    assert_eq!(charge, 125);

    // Absurd fee.
    let high_fee = build_foreign_send(&wallet, outpoint(2), 0, 0, 10_000, 100, 3_000);
    let charge =
        crate::window::spend_charge(&high_fee.psbt, &wallet.receive, &high_fee.policy).unwrap();
    assert_eq!(charge, 3_100);

    // Self-transfer to own receive: only the fee.
    let self_xfer = build_psbt(&wallet, 0, 0, 5, 10_000, 100, 25);
    let charge =
        crate::window::spend_charge(&self_xfer.psbt, &wallet.receive, &self_xfer.policy).unwrap();
    assert_eq!(charge, 25);

    // RBF: same input set, fee +10, extra = 10. Dropped tx stays booked.
    let mut counter = ready_counter();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(10));
    let policy = SpendPolicy::standard();
    let first = build_foreign_send(&wallet, outpoint(3), 0, 0, 10_000, 40, 10);
    {
        let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
        // authorize+commit via the counter (no need to sign for accounting).
        let approval = spend
            .authorize(&first.psbt, &wallet.receive, &first.policy)
            .unwrap();
        assert_eq!(approval.charge_sat(), 50);
        spend.commit(approval);
    }
    assert_eq!(counter.booked_sat(), 50);
    let bumped = build_foreign_send(&wallet, outpoint(3), 0, 0, 10_000, 40, 20);
    {
        let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
        let approval = spend
            .authorize(&bumped.psbt, &wallet.receive, &bumped.policy)
            .unwrap();
        assert_eq!(approval.charge_sat(), 60);
        spend.commit(approval);
    }
    assert_eq!(counter.booked_sat(), 60);

    // Never confirmed: still booked after an hour inside the 24 h window.
    clock.advance(Duration::from_secs(3_600));
    blocks.set(Some(16));
    {
        let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
        let probe = build_foreign_send(&wallet, outpoint(32), 0, 0, 10_000, 1, 1);
        // Probe is tiny; authorize prunes then accepts. The dropped first
        // spend must still occupy 60 sat.
        spend
            .authorize(&probe.psbt, &wallet.receive, &probe.policy)
            .unwrap();
        assert_eq!(counter.booked_sat(), 60);
    }
}

#[test]
fn s29i_unconfirmed_foreign_payment_does_not_raise_reference() {
    let p = SpendPolicy::standard();
    let manipulated = Balance {
        confirmed_sats: 200,
        trusted_pending_sats: 0,
        untrusted_pending_sats: 50_000,
        immature_sats: 0,
    };
    assert_eq!(
        allowance(&p, manipulated.spend_policy_reference_sats()),
        200
    );
    let honest = Balance {
        confirmed_sats: 200,
        trusted_pending_sats: 0,
        untrusted_pending_sats: 0,
        immature_sats: 0,
    };
    assert_eq!(
        allowance(&p, honest.spend_policy_reference_sats()),
        allowance(&p, manipulated.spend_policy_reference_sats())
    );
}

#[test]
fn s29j_sliding_window_across_calendar_boundary() {
    let wallet = default_wallet();
    let (a, _, b, _) = pair_signers(&wallet);
    let policy = SpendPolicy::standard();
    let mut counter = ready_counter();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(50));
    // 23:59 → 00:01 is +120 s on the wall; mono also +120 s.
    const T_2359: u64 = 1_700_000_000_000_000_000;
    const TWO_MIN_NS: u64 = 120 * 1_000_000_000;
    let first = build_foreign_send(&wallet, outpoint(4), 0, 0, 10_000, 145, 5);
    {
        let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, Some(T_2359));
        sign_ab(
            &a,
            &b,
            first.psbt,
            &wallet.receive,
            &first.policy,
            &mut spend,
        )
        .unwrap();
    }
    clock.advance(Duration::from_secs(120));
    let second = build_foreign_send(&wallet, outpoint(5), 0, 0, 10_000, 145, 5);
    let mut spend = session(
        &policy,
        &mut counter,
        &clock,
        &blocks,
        1_000,
        Some(T_2359 + TWO_MIN_NS),
    );
    let err = sign_ab(
        &a,
        &b,
        second.psbt,
        &wallet.receive,
        &second.policy,
        &mut spend,
    )
    .unwrap_err();
    // 150 + 150 = 300 > allowance 200. A calendar reset would have allowed it.
    assert_eq!(err, SignError::SpendLimitExceeded);
}

#[test]
fn s29k_device_clock_jump_never_resets_window() {
    let wallet = default_wallet();
    let (a, fake_a, b, fake_b) = pair_signers(&wallet);
    let policy = SpendPolicy::standard();
    let mut counter = ready_counter();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(50));
    const WALL0: u64 = 5_000;
    let first = build_foreign_send(&wallet, outpoint(6), 0, 0, 10_000, 195, 5);
    {
        let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, Some(WALL0));
        sign_ab(
            &a,
            &b,
            first.psbt,
            &wallet.receive,
            &first.policy,
            &mut spend,
        )
        .unwrap();
    }
    assert_eq!(counter.booked_sat(), 200);

    // +24 h on the wall only. Mono and tip stay put.
    fake_a.reset_calls();
    fake_b.reset_calls();
    let plus_day = build_foreign_send(&wallet, outpoint(7), 0, 0, 10_000, 45, 5);
    {
        let mut spend = session(
            &policy,
            &mut counter,
            &clock,
            &blocks,
            1_000,
            Some(WALL0 + 86_400 * 1_000_000_000),
        );
        let err = sign_ab(
            &a,
            &b,
            plus_day.psbt,
            &wallet.receive,
            &plus_day.policy,
            &mut spend,
        )
        .unwrap_err();
        assert_eq!(err, SignError::SpendLimitExceeded);
    }
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);

    // Backward jump.
    fake_a.reset_calls();
    fake_b.reset_calls();
    let back = build_foreign_send(&wallet, outpoint(8), 0, 0, 10_000, 45, 5);
    let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, Some(1));
    let err = sign_ab(&a, &b, back.psbt, &wallet.receive, &back.policy, &mut spend).unwrap_err();
    assert_eq!(err, SignError::SpendLimitExceeded);
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);

    // Automatic time sync off: no wall reading is supplied. Mono and tip
    // stay put — we never invent progress from a missing network clock.
    fake_a.reset_calls();
    fake_b.reset_calls();
    let nosync = build_foreign_send(&wallet, outpoint(41), 0, 0, 10_000, 45, 5);
    let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
    let err = sign_ab(
        &a,
        &b,
        nosync.psbt,
        &wallet.receive,
        &nosync.policy,
        &mut spend,
    )
    .unwrap_err();
    assert_eq!(err, SignError::SpendLimitExceeded);
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);
}

#[test]
fn s29k_block_height_jump_never_resets_window() {
    let wallet = default_wallet();
    let (a, fake_a, b, fake_b) = pair_signers(&wallet);
    let policy = SpendPolicy::standard();
    let mut counter = ready_counter();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(50));
    let first = build_foreign_send(&wallet, outpoint(12), 0, 0, 10_000, 195, 5);
    {
        let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
        sign_ab(
            &a,
            &b,
            first.psbt,
            &wallet.receive,
            &first.policy,
            &mut spend,
        )
        .unwrap();
    }
    assert_eq!(counter.booked_sat(), 200);

    clock.reboot();
    fake_a.reset_calls();
    fake_b.reset_calls();
    blocks.set(Some(50 + 144));
    let plus_day = build_foreign_send(&wallet, outpoint(13), 0, 0, 10_000, 45, 5);
    {
        let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
        let err = sign_ab(
            &a,
            &b,
            plus_day.psbt,
            &wallet.receive,
            &plus_day.policy,
            &mut spend,
        )
        .unwrap_err();
        assert_eq!(err, SignError::SpendLimitExceeded);
    }
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);

    fake_a.reset_calls();
    fake_b.reset_calls();
    blocks.set(Some(50 + 100_000));
    let huge = build_foreign_send(&wallet, outpoint(14), 0, 0, 10_000, 45, 5);
    let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
    let err = sign_ab(&a, &b, huge.psbt, &wallet.receive, &huge.policy, &mut spend).unwrap_err();
    assert_eq!(err, SignError::SpendLimitExceeded);
    assert_eq!(fake_a.unwrap_kek_calls(), 0);
    assert_eq!(fake_b.unwrap_kek_calls(), 0);
}

#[test]
fn under_limit_sign_ab_books_and_unlocks() {
    let wallet = default_wallet();
    let (a, fake_a, b, fake_b) = pair_signers(&wallet);
    let policy = SpendPolicy::standard();
    let mut counter = ready_counter();
    let clock = FakeClock::new();
    let blocks = FakeBlockHeightSource::new(Some(50));
    let built = build_foreign_send(&wallet, outpoint(11), 0, 0, 10_000, 40, 10);
    fake_a.reset_calls();
    fake_b.reset_calls();
    let mut spend = session(&policy, &mut counter, &clock, &blocks, 1_000, None);
    let signed = sign_ab(
        &a,
        &b,
        built.psbt,
        &wallet.receive,
        &built.policy,
        &mut spend,
    )
    .unwrap();
    assert_eq!(signed.inputs[0].partial_sigs.len(), 2);
    assert_eq!(fake_a.unwrap_kek_calls(), 1);
    assert_eq!(fake_b.unwrap_kek_calls(), 1);
    assert_eq!(counter.booked_sat(), 50);
}

#[test]
fn spend_charge_missing_utxo_and_overdraft_and_bad_change() {
    let wallet = default_wallet();
    let mut built = build_foreign_send(&wallet, outpoint(20), 0, 0, 10_000, 40, 10);
    built.psbt.inputs[0].witness_utxo = None;
    assert_eq!(
        crate::window::spend_charge(&built.psbt, &wallet.receive, &built.policy).unwrap_err(),
        SignError::MissingWitnessUtxo { input_index: 0 }
    );

    let mut over = build_foreign_send(&wallet, outpoint(21), 0, 0, 10_000, 40, 10);
    over.psbt.unsigned_tx.output[0].value = Amount::from_sat(20_000);
    assert_eq!(
        crate::window::spend_charge(&over.psbt, &wallet.receive, &over.policy).unwrap_err(),
        SignError::UnbalancedPsbt
    );

    let ok = build_foreign_send(&wallet, outpoint(22), 0, 0, 10_000, 40, 10);
    let mut policy = ok.policy.clone();
    policy.change_descriptor = Some("not-a-descriptor".into());
    assert!(crate::window::spend_charge(&ok.psbt, &wallet.receive, &policy).is_err());

    let mut no_chg = ok.policy.clone();
    no_chg.change_descriptor = None;
    // Change output is no longer classified as own → counts + foreign + fee.
    let charge = crate::window::spend_charge(&ok.psbt, &wallet.receive, &no_chg).unwrap();
    assert_eq!(charge, 10_000);
}
