//! Sliding spend window: accounting, O18 time step, persistable counter.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use bitcoin::psbt::Psbt;
use bitcoin::{OutPoint, ScriptBuf};
use trinity_types::Balance;
use trinity_verify::{derive_at, parse, VerifyPolicy};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::clock::{BlockHeightSource, MonotonicClock};
use crate::core_state::{decrypt, encrypt, BookedSpend, CoreState, MAX_BOOKINGS, MAX_INPUTS};
use crate::error::SignError;
use crate::limits::{allowance, SpendPolicy};
use trinity_types::SecretBytes;

/// Expected seconds per block (Spec §3.6.7: 144 blocks / 24 h).
pub const SECONDS_PER_BLOCK: u64 = 24 * 60 * 60 / 144;

/// Outcome of a successful policy check, applied after `sign_a`/`sign_b`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendApproval {
    input_set: BTreeSet<OutPoint>,
    charge_sat: u64,
}

impl SpendApproval {
    /// Satoshis this transaction charges against the window (full amount,
    /// not the RBF delta).
    #[inline]
    pub fn charge_sat(&self) -> u64 {
        self.charge_sat
    }

    /// Construct an approval for tests and crate-internal commits.
    #[cfg(test)]
    pub(crate) fn new(input_set: BTreeSet<OutPoint>, charge_sat: u64) -> Self {
        Self {
            input_set,
            charge_sat,
        }
    }
}

/// Inputs [`sign_ab`] needs to enforce [`SpendPolicy`] before unlocking A or B.
pub struct SpendSession<'a> {
    /// Policy under test. Must already have passed [`crate::set_spend_policy`]
    /// if it came from user input.
    pub policy: &'a SpendPolicy,
    /// Encrypted counter (in-memory; seal to persist).
    pub counter: &'a mut WindowCounter,
    /// Injected monotonic clock.
    pub clock: &'a dyn MonotonicClock,
    /// Injected chain tip (`None` = offline).
    pub blocks: &'a dyn BlockHeightSource,
    /// Balance **before** the transaction, measured in the Rust core.
    pub balance: Balance,
    /// Wall-clock unix nanoseconds, **display / fail-closed veto only**.
    /// Never a source of `effective_elapsed` (Spec §3.6.7).
    pub wall_unix_ns: Option<u64>,
}

impl SpendSession<'_> {
    /// Advance the window and accept or reject the PSBT. No key unlock.
    pub fn authorize(
        &mut self,
        psbt: &Psbt,
        descriptor: &str,
        verify: &VerifyPolicy,
    ) -> Result<SpendApproval, SignError> {
        self.counter.authorize(
            self.policy,
            psbt,
            descriptor,
            verify,
            self.balance,
            self.clock,
            self.blocks,
            self.wall_unix_ns,
        )
    }

    /// Book a previously authorized spend.
    pub fn commit(&mut self, approval: SpendApproval) {
        self.counter.commit(approval);
    }
}

/// In-memory window counter, sealed with a dedicated 32-byte KEK.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WindowCounter {
    kek: SecretBytes,
    #[zeroize(skip)]
    state: CoreState,
}

impl fmt::Debug for WindowCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowCounter")
            .field("kek", &"[redacted]")
            .field("booked_sat", &self.booked_sat())
            .field(
                "passphrase_used_since_install",
                &self.passphrase_used_since_install(),
            )
            .finish()
    }
}

impl WindowCounter {
    /// Empty counter (first use after install).
    pub fn new(kek: SecretBytes) -> Result<Self, SignError> {
        if kek.len() != 32 {
            return Err(SignError::InvalidKekLength);
        }
        Ok(Self {
            kek,
            state: CoreState::empty(),
        })
    }

    /// Open a previously sealed blob.
    pub fn open(kek: SecretBytes, blob: &[u8]) -> Result<Self, SignError> {
        if kek.len() != 32 {
            return Err(SignError::InvalidKekLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(kek.as_slice());
        let state = decrypt(&arr, blob);
        arr.zeroize();
        Ok(Self { kek, state: state? })
    }

    /// Seal the current state (fresh nonce).
    ///
    /// Persist this blob **before** releasing a signed PSBT to the next
    /// layer. [`crate::sign_ab`] returns the signatures first; a crash or
    /// a skipped write leaves the spend uncounted.
    pub fn seal(&self) -> Result<Vec<u8>, SignError> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(self.kek.as_slice());
        let out = encrypt(&arr, &self.state);
        arr.zeroize();
        Ok(out?)
    }

    /// Mark that a passphrase was accepted (WP-35 writes this; tests seed it).
    pub fn set_passphrase_used_since_install(&mut self, used: bool) {
        self.state.passphrase_used_since_install = used;
    }

    /// Whether a passphrase has been accepted since install.
    #[inline]
    pub fn passphrase_used_since_install(&self) -> bool {
        self.state.passphrase_used_since_install
    }

    /// Sum of bookings still inside the window.
    #[inline]
    pub fn booked_sat(&self) -> u64 {
        self.state
            .bookings
            .iter()
            .map(|b| b.amount_sat)
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// Current effective elapsed since the first initialized observation.
    #[inline]
    pub fn window_elapsed(&self) -> Duration {
        Duration::from_nanos(self.state.window_elapsed_ns)
    }

    /// Check the PSBT against the policy. A rejected policy `validate`
    /// returns before the clock advances; every later rejection still
    /// updates the clock anchor (fail-closed on a time jump).
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &mut self,
        policy: &SpendPolicy,
        psbt: &Psbt,
        descriptor: &str,
        verify: &VerifyPolicy,
        balance: Balance,
        clock: &dyn MonotonicClock,
        blocks: &dyn BlockHeightSource,
        wall_unix_ns: Option<u64>,
    ) -> Result<SpendApproval, SignError> {
        policy.validate()?;
        self.advance(clock, blocks, wall_unix_ns);
        self.prune(policy.window);

        if !self.state.passphrase_used_since_install {
            return Err(SignError::SpendLimitExceeded);
        }

        let reference = balance.spend_policy_reference_sats();
        let allowed = allowance(policy, reference);
        let charge = spend_charge(psbt, descriptor, verify)?;
        let input_set = input_set(psbt)?;
        let known = self
            .state
            .bookings
            .iter()
            .any(|b| same_inputs(&b.inputs, &input_set));
        let extra = extra_against_bookings(&self.state.bookings, &input_set, charge);
        let used = self.booked_sat();
        let remaining = allowed.saturating_sub(used);
        if extra > remaining {
            return Err(SignError::SpendLimitExceeded);
        }
        if !known && self.state.bookings.len() >= MAX_BOOKINGS {
            return Err(SignError::WindowLedgerFull);
        }
        Ok(SpendApproval {
            input_set,
            charge_sat: charge,
        })
    }

    /// Record `approval` in the current window.
    pub fn commit(&mut self, approval: SpendApproval) {
        if let Some(existing) = self
            .state
            .bookings
            .iter_mut()
            .find(|b| same_inputs(&b.inputs, &approval.input_set))
        {
            if approval.charge_sat > existing.amount_sat {
                existing.amount_sat = approval.charge_sat;
                existing.elapsed_at_ns = self.state.window_elapsed_ns;
            }
        } else if self.state.bookings.len() < MAX_BOOKINGS {
            let mut inputs: Vec<OutPoint> = approval.input_set.into_iter().collect();
            inputs.sort();
            self.state.bookings.push(BookedSpend {
                inputs,
                amount_sat: approval.charge_sat,
                elapsed_at_ns: self.state.window_elapsed_ns,
            });
        }
    }

    fn advance(
        &mut self,
        clock: &dyn MonotonicClock,
        blocks: &dyn BlockHeightSource,
        wall_unix_ns: Option<u64>,
    ) {
        let now_mono_ns = duration_as_ns(clock.now());
        let now_boot = clock.boot_id();
        let now_height = blocks.tip_height();

        if !self.state.initialized {
            self.state.initialized = true;
            self.state.monotonic_ns_at_anchor = now_mono_ns;
            self.state.block_height_at_anchor = now_height;
            self.state.boot_id_at_anchor = now_boot;
            self.state.wall_unix_ns_at_anchor = wall_unix_ns;
            self.state.window_elapsed_ns = 0;
            self.state.window_start_elapsed_ns = 0;
            return;
        }

        let step = step_elapsed(&self.state, now_mono_ns, now_boot, now_height, wall_unix_ns);
        self.state.window_elapsed_ns = self
            .state
            .window_elapsed_ns
            .saturating_add(duration_as_ns(step));

        self.state.monotonic_ns_at_anchor = now_mono_ns;
        if now_height.is_some() {
            self.state.block_height_at_anchor = now_height;
        }
        if now_boot.is_some() {
            self.state.boot_id_at_anchor = now_boot;
        }
        if wall_unix_ns.is_some() {
            self.state.wall_unix_ns_at_anchor = wall_unix_ns;
        }
    }

    fn prune(&mut self, window: Duration) {
        let window_ns = duration_as_ns(window);
        let now = self.state.window_elapsed_ns;
        let start = now.saturating_sub(window_ns);
        self.state.window_start_elapsed_ns = start;
        self.state.bookings.retain(|b| b.elapsed_at_ns >= start);
    }
}

/// O18 (c): combine monotonic and block-height; wall is a veto only.
fn step_elapsed(
    prev: &CoreState,
    now_mono_ns: u64,
    now_boot: Option<u64>,
    now_height: Option<u32>,
    now_wall: Option<u64>,
) -> Duration {
    let same_boot = match (prev.boot_id_at_anchor, now_boot) {
        (Some(a), Some(b)) => a == b,
        _ => now_mono_ns >= prev.monotonic_ns_at_anchor,
    };
    let mono_regressed = now_mono_ns < prev.monotonic_ns_at_anchor;
    let mono_trusted = same_boot && !mono_regressed;
    let mono = if mono_trusted {
        Some(Duration::from_nanos(
            now_mono_ns - prev.monotonic_ns_at_anchor,
        ))
    } else {
        None
    };

    let blocks = match (prev.block_height_at_anchor, now_height) {
        (Some(prev_h), Some(now_h)) if now_h >= prev_h => Some(Duration::from_secs(
            u64::from(now_h - prev_h).saturating_mul(SECONDS_PER_BLOCK),
        )),
        (Some(_), Some(_)) => Some(Duration::ZERO),
        _ => None,
    };

    // Wall is **not** a source. Block height is a brake via `min` only
    // while mono is trusted — never a standalone source (a claimed tip
    // is not proven elapsed time).
    let from_sources = match (mono, blocks) {
        (Some(m), Some(b)) => m.min(b),
        (Some(m), None) => m,
        (None, Some(_)) => Duration::ZERO,
        (None, None) => Duration::ZERO,
    };

    apply_wall_veto(
        from_sources,
        mono_trusted,
        mono,
        prev.wall_unix_ns_at_anchor,
        now_wall,
    )
}

/// Spec §3.6.7 fail-closed: a wall-clock jump never loosens the limit.
///
/// On the same boot, a backward jump or a forward jump larger than the
/// monotonic delta zeroes this step. After a reboot the wall is expected
/// to have moved; the veto does not run, because there is no progress
/// anyway (`step_elapsed` yields `Duration::ZERO`).
fn apply_wall_veto(
    from_sources: Duration,
    mono_trusted: bool,
    mono: Option<Duration>,
    prev_wall: Option<u64>,
    now_wall: Option<u64>,
) -> Duration {
    if !mono_trusted {
        return from_sources;
    }
    let (Some(prev_w), Some(now_w)) = (prev_wall, now_wall) else {
        return from_sources;
    };
    if now_w < prev_w {
        return Duration::ZERO;
    }
    let wall_delta = now_w - prev_w;
    let mono_ns = mono.map(duration_as_ns).unwrap_or(0);
    if wall_delta > mono_ns {
        Duration::ZERO
    } else {
        from_sources
    }
}

fn duration_as_ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

fn extra_against_bookings(
    bookings: &[BookedSpend],
    input_set: &BTreeSet<OutPoint>,
    charge: u64,
) -> u64 {
    match bookings.iter().find(|b| same_inputs(&b.inputs, input_set)) {
        Some(existing) => charge.saturating_sub(existing.amount_sat),
        None => charge,
    }
}

fn same_inputs(stored: &[OutPoint], set: &BTreeSet<OutPoint>) -> bool {
    if stored.len() != set.len() {
        return false;
    }
    stored.iter().all(|o| set.contains(o))
}

fn input_set(psbt: &Psbt) -> Result<BTreeSet<OutPoint>, SignError> {
    if psbt.unsigned_tx.input.is_empty() {
        return Err(SignError::EmptyPsbt);
    }
    if psbt.unsigned_tx.input.len() > MAX_INPUTS {
        return Err(SignError::TooManyInputs);
    }
    Ok(psbt
        .unsigned_tx
        .input
        .iter()
        .map(|i| i.previous_output)
        .collect())
}

/// Foreign outputs + fee. Change and self-transfer to the own descriptor
/// do not count (Spec §3.6.7). Membership via `trinity-verify` derivation,
/// not the builder.
pub(crate) fn spend_charge(
    psbt: &Psbt,
    descriptor: &str,
    verify: &VerifyPolicy,
) -> Result<u64, SignError> {
    let receive = parse(descriptor).map_err(trinity_verify::VerifyError::from)?;
    let change = match verify.change_descriptor.as_deref() {
        Some(s) => Some(parse(s).map_err(trinity_verify::VerifyError::from)?),
        None => None,
    };
    let gap = verify.gap_limit;

    let mut sum_in = 0u64;
    for (i, input) in psbt.inputs.iter().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or(SignError::MissingWitnessUtxo { input_index: i })?;
        sum_in = sum_in
            .checked_add(utxo.value.to_sat())
            .ok_or(SignError::UnbalancedPsbt)?;
    }
    let mut sum_out = 0u64;
    let mut foreign = 0u64;
    for txout in &psbt.unsigned_tx.output {
        let v = txout.value.to_sat();
        sum_out = sum_out.checked_add(v).ok_or(SignError::UnbalancedPsbt)?;
        if !belongs_to_wallet(&txout.script_pubkey, &receive, change.as_ref(), gap)? {
            foreign = foreign.saturating_add(v);
        }
    }
    let fee = sum_in
        .checked_sub(sum_out)
        .ok_or(SignError::UnbalancedPsbt)?;
    Ok(foreign.saturating_add(fee))
}

fn belongs_to_wallet(
    script: &ScriptBuf,
    receive: &trinity_verify::ParsedDescriptor,
    change: Option<&trinity_verify::ParsedDescriptor>,
    gap: u32,
) -> Result<bool, SignError> {
    if matches_descriptor(script, receive, gap)? {
        return Ok(true);
    }
    match change {
        Some(chg) => matches_descriptor(script, chg, gap),
        None => Ok(false),
    }
}

fn matches_descriptor(
    script: &ScriptBuf,
    desc: &trinity_verify::ParsedDescriptor,
    gap: u32,
) -> Result<bool, SignError> {
    for i in 0..gap {
        let derived = derive_at(desc, i).map_err(trinity_verify::VerifyError::from)?;
        if derived.script_pubkey == *script {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{FakeBlockHeightSource, FakeClock};
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    fn kek() -> SecretBytes {
        SecretBytes::from_slice(&[0x42u8; 32])
    }

    fn empty_counter() -> WindowCounter {
        WindowCounter::new(kek()).unwrap()
    }

    fn policy_cap(cap: u64) -> SpendPolicy {
        SpendPolicy {
            window_fraction: None,
            window_floor_sat: Some(0),
            window_cap_sat: Some(cap),
            window: Duration::from_secs(24 * 60 * 60),
            passphrase_on_first_use: true,
        }
    }

    fn bare_psbt(outpoint: u8, in_sats: u64, out_sats: u64) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([outpoint; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_sats),
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [0xAA; 20],
                )),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(in_sats),
            script_pubkey: ScriptBuf::new(),
        });
        psbt
    }

    fn book_for_test(counter: &mut WindowCounter, tag: u8, charge: u64) {
        counter.set_passphrase_used_since_install(true);
        let set: BTreeSet<OutPoint> = [OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout: 0,
        }]
        .into_iter()
        .collect();
        counter.commit(SpendApproval {
            input_set: set,
            charge_sat: charge,
        });
    }

    fn wallet_desc() -> String {
        crate::tests_wp33::default_wallet().receive
    }

    fn charge_verify() -> VerifyPolicy {
        VerifyPolicy::new(
            vec![],
            0,
            50_000,
            5_000,
            None,
            20,
            Default::default(),
            None,
            bitcoin::Network::Regtest,
        )
    }

    #[test]
    fn debug_redacts_kek() {
        let c = empty_counter();
        let rendered = format!("{c:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("booked_sat"));
    }

    #[test]
    fn new_rejects_short_kek() {
        assert_eq!(
            WindowCounter::new(SecretBytes::from_slice(&[1, 2, 3])).unwrap_err(),
            SignError::InvalidKekLength
        );
        assert_eq!(
            WindowCounter::open(SecretBytes::from_slice(&[1]), &[]).unwrap_err(),
            SignError::InvalidKekLength
        );
    }

    #[test]
    fn seal_open_roundtrip() {
        let mut c = empty_counter();
        c.set_passphrase_used_since_install(true);
        let blob = c.seal().unwrap();
        let opened = WindowCounter::open(kek(), &blob).unwrap();
        assert!(opened.passphrase_used_since_install());
        assert_eq!(opened.booked_sat(), 0);
    }

    #[test]
    fn first_use_blocks_before_any_booking() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(Some(10));
        let psbt = bare_psbt(1, 100, 90);
        let policy = policy_cap(10_000);
        let verify = VerifyPolicy::new(
            vec!["bcrt1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()],
            90,
            50_000,
            5_000,
            None,
            0,
            Default::default(),
            None,
            bitcoin::Network::Regtest,
        );
        // gap 0 ⇒ nothing is "own" ⇒ charge = 90 + 10 = 100, but first-use fires first.
        let err = c
            .authorize(
                &policy,
                &psbt,
                "not-parsed-because-first-use",
                &verify,
                Balance {
                    confirmed_sats: 1_000,
                    trusted_pending_sats: 0,
                    untrusted_pending_sats: 0,
                    immature_sats: 0,
                },
                &clock,
                &blocks,
                None,
            )
            .unwrap_err();
        assert_eq!(err, SignError::SpendLimitExceeded);
        assert!(c.state.initialized);
    }

    #[test]
    fn authorize_invalid_policy_does_not_advance_clock() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        let mut policy = SpendPolicy::standard();
        policy.window_floor_sat = Some(800);
        policy.window_cap_sat = Some(200);
        let psbt = bare_psbt(1, 100, 50);
        let desc = wallet_desc();
        let err = c
            .authorize(
                &policy,
                &psbt,
                &desc,
                &charge_verify(),
                Balance {
                    confirmed_sats: 1_000,
                    trusted_pending_sats: 0,
                    untrusted_pending_sats: 0,
                    immature_sats: 0,
                },
                &clock,
                &blocks,
                None,
            )
            .unwrap_err();
        assert_eq!(err, SignError::FloorAboveCap);
        assert!(!c.state.initialized);
        assert_eq!(c.window_elapsed(), Duration::ZERO);
    }

    #[test]
    fn reboot_without_blocks_does_not_advance() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        // Offline: monotonic is the only source.
        let blocks = FakeBlockHeightSource::new(None);
        c.advance(&clock, &blocks, None);
        clock.advance(Duration::from_secs(3_600));
        c.advance(&clock, &blocks, None);
        assert_eq!(c.window_elapsed(), Duration::from_secs(3_600));
        let before = c.window_elapsed();
        clock.reboot();
        c.advance(&clock, &blocks, None);
        assert_eq!(c.window_elapsed(), before);
    }

    #[test]
    fn reboot_does_not_advance_from_blocks_alone() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(Some(100));
        c.advance(&clock, &blocks, None);
        clock.reboot();
        blocks.set(Some(100 + 144));
        c.advance(&clock, &blocks, None);
        assert_eq!(c.window_elapsed(), Duration::ZERO);
    }

    #[test]
    fn min_of_mono_and_blocks() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(Some(10));
        c.advance(&clock, &blocks, None);
        clock.advance(Duration::from_secs(6_000));
        blocks.set(Some(11)); // +600 s
        c.advance(&clock, &blocks, None);
        assert_eq!(c.window_elapsed(), Duration::from_secs(600));
    }

    #[test]
    fn offline_same_boot_uses_monotonic() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        c.advance(&clock, &blocks, None);
        clock.advance(Duration::from_secs(90));
        c.advance(&clock, &blocks, None);
        assert_eq!(c.window_elapsed(), Duration::from_secs(90));
    }

    #[test]
    fn height_reorg_is_zero_block_progress() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(Some(50));
        c.advance(&clock, &blocks, None);
        blocks.set(Some(40));
        clock.advance(Duration::from_secs(10));
        // both present: min(10s, 0) = 0
        c.advance(&clock, &blocks, None);
        assert_eq!(c.window_elapsed(), Duration::ZERO);
    }

    #[test]
    fn wall_jump_forward_does_not_advance() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(Some(1));
        c.advance(&clock, &blocks, Some(1_000));
        c.advance(&clock, &blocks, Some(1_000 + 86_400 * 1_000_000_000));
        assert_eq!(c.window_elapsed(), Duration::ZERO);
    }

    #[test]
    fn wall_jump_backward_does_not_advance() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(Some(1));
        c.advance(&clock, &blocks, Some(5_000));
        clock.advance(Duration::from_secs(10));
        c.advance(&clock, &blocks, Some(1));
        assert_eq!(c.window_elapsed(), Duration::ZERO);
    }

    #[test]
    fn mono_regression_is_untrusted() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        clock.set(Duration::from_secs(50));
        c.advance(&clock, &blocks, None);
        clock.set(Duration::from_secs(10));
        c.advance(&clock, &blocks, None);
        assert_eq!(c.window_elapsed(), Duration::ZERO);
    }

    #[test]
    fn prune_drops_old_bookings() {
        let mut c = empty_counter();
        let policy = SpendPolicy {
            window_fraction: None,
            window_floor_sat: Some(0),
            window_cap_sat: Some(10_000),
            window: Duration::from_secs(60),
            passphrase_on_first_use: true,
        };
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        c.advance(&clock, &blocks, None);
        book_for_test(&mut c, 1, 5);
        assert_eq!(c.booked_sat(), 5);
        clock.set(Duration::from_secs(120));
        c.advance(&clock, &blocks, None);
        c.prune(policy.window);
        assert_eq!(c.booked_sat(), 0);
    }

    #[test]
    fn prune_keeps_only_booking_inside_window() {
        let mut c = empty_counter();
        let window = Duration::from_secs(60);
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        c.advance(&clock, &blocks, None);
        book_for_test(&mut c, 1, 5);
        clock.advance(Duration::from_secs(1));
        c.advance(&clock, &blocks, None);
        book_for_test(&mut c, 2, 7);
        clock.advance(Duration::from_secs(60));
        c.advance(&clock, &blocks, None);
        c.prune(window);
        assert_eq!(c.state.bookings.len(), 1);
        assert_eq!(c.state.bookings[0].amount_sat, 7);
        assert_eq!(c.booked_sat(), 7);
    }

    #[test]
    fn rbf_tracks_input_set_not_txid() {
        let set: BTreeSet<OutPoint> = [OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        }]
        .into_iter()
        .collect();
        let bookings = vec![BookedSpend {
            inputs: vec![OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            }],
            amount_sat: 100,
            elapsed_at_ns: 0,
        }];
        assert_eq!(extra_against_bookings(&bookings, &set, 130), 30);
        assert_eq!(extra_against_bookings(&bookings, &set, 80), 0);
        let other: BTreeSet<OutPoint> = [OutPoint {
            txid: Txid::from_byte_array([2; 32]),
            vout: 0,
        }]
        .into_iter()
        .collect();
        assert_eq!(extra_against_bookings(&bookings, &other, 50), 50);
    }

    #[test]
    fn commit_updates_existing_and_inserts_new() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        c.advance(&clock, &blocks, None);
        let set: BTreeSet<OutPoint> = [OutPoint {
            txid: Txid::from_byte_array([9; 32]),
            vout: 0,
        }]
        .into_iter()
        .collect();
        c.commit(SpendApproval {
            input_set: set.clone(),
            charge_sat: 10,
        });
        clock.advance(Duration::from_secs(5));
        c.advance(&clock, &blocks, None);
        c.commit(SpendApproval {
            input_set: set.clone(),
            charge_sat: 15,
        });
        assert_eq!(c.state.bookings[0].elapsed_at_ns, 5_000_000_000);
        clock.advance(Duration::from_secs(5));
        c.advance(&clock, &blocks, None);
        c.commit(SpendApproval {
            input_set: set,
            charge_sat: 15,
        });
        assert_eq!(c.state.bookings[0].amount_sat, 15);
        assert_eq!(c.state.bookings[0].elapsed_at_ns, 5_000_000_000);
        let other: BTreeSet<OutPoint> = [OutPoint {
            txid: Txid::from_byte_array([8; 32]),
            vout: 0,
        }]
        .into_iter()
        .collect();
        c.commit(SpendApproval {
            input_set: other,
            charge_sat: 7,
        });
        assert_eq!(c.booked_sat(), 22);
        assert_eq!(c.state.bookings.len(), 2);
    }

    #[test]
    fn same_inputs_length_mismatch() {
        let stored = vec![OutPoint::null(), OutPoint::null()];
        let set = BTreeSet::new();
        assert!(!same_inputs(&stored, &set));
    }

    #[test]
    fn input_set_empty_psbt() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert_eq!(input_set(&psbt).unwrap_err(), SignError::EmptyPsbt);
    }

    #[test]
    fn spend_charge_rejects_missing_witness_utxo() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![],
        };
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let desc = wallet_desc();
        assert_eq!(
            spend_charge(&psbt, &desc, &charge_verify()).unwrap_err(),
            SignError::MissingWitnessUtxo { input_index: 0 }
        );
    }

    #[test]
    fn untrusted_pending_does_not_raise_allowance() {
        let p = SpendPolicy::standard();
        let low = Balance {
            confirmed_sats: 200,
            trusted_pending_sats: 0,
            untrusted_pending_sats: 10_000,
            immature_sats: 0,
        };
        assert_eq!(allowance(&p, low.spend_policy_reference_sats()), 200);
        let with_change = Balance {
            confirmed_sats: 200,
            trusted_pending_sats: 800,
            untrusted_pending_sats: 10_000,
            immature_sats: 0,
        };
        assert_eq!(
            allowance(&p, with_change.spend_policy_reference_sats()),
            200
        );
    }

    #[test]
    fn seconds_per_block_is_ten_minutes() {
        assert_eq!(SECONDS_PER_BLOCK, 600);
    }

    #[test]
    fn authorize_rejects_when_remaining_exhausted() {
        let mut c = empty_counter();
        c.set_passphrase_used_since_install(true);
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        let policy = policy_cap(10);
        let psbt = bare_psbt(1, 100, 50);
        let desc = wallet_desc();
        let err = c
            .authorize(
                &policy,
                &psbt,
                &desc,
                &charge_verify(),
                Balance {
                    confirmed_sats: 10_000,
                    trusted_pending_sats: 0,
                    untrusted_pending_sats: 0,
                    immature_sats: 0,
                },
                &clock,
                &blocks,
                None,
            )
            .unwrap_err();
        assert_eq!(err, SignError::SpendLimitExceeded);
    }

    #[test]
    fn spend_charge_rejects_unparseable_descriptor() {
        let psbt = bare_psbt(1, 100, 50);
        assert!(matches!(
            spend_charge(&psbt, "not-a-descriptor", &charge_verify()).unwrap_err(),
            SignError::Verify(_)
        ));
    }

    #[test]
    fn charge_rejects_outputs_exceeding_inputs() {
        let psbt = bare_psbt(1, 10, 50);
        let desc = wallet_desc();
        assert_eq!(
            spend_charge(&psbt, &desc, &charge_verify()).unwrap_err(),
            SignError::UnbalancedPsbt
        );
    }

    #[test]
    fn input_set_too_many_is_rejected() {
        let inputs = (0..=MAX_INPUTS)
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([i as u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: vec![],
        };
        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert_eq!(input_set(&psbt).unwrap_err(), SignError::TooManyInputs);
    }

    #[test]
    fn commit_stops_at_max_bookings() {
        let mut c = empty_counter();
        c.set_passphrase_used_since_install(true);
        for i in 0..MAX_BOOKINGS {
            let set: BTreeSet<OutPoint> = [OutPoint {
                txid: Txid::from_byte_array([(i % 256) as u8; 32]),
                vout: i as u32,
            }]
            .into_iter()
            .collect();
            c.commit(SpendApproval {
                input_set: set,
                charge_sat: 1,
            });
        }
        assert_eq!(c.state.bookings.len(), MAX_BOOKINGS);
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        let policy = SpendPolicy::off();
        let psbt = bare_psbt(0xFE, 100, 50);
        let desc = wallet_desc();
        let err = c
            .authorize(
                &policy,
                &psbt,
                &desc,
                &charge_verify(),
                Balance {
                    confirmed_sats: 10_000,
                    trusted_pending_sats: 0,
                    untrusted_pending_sats: 0,
                    immature_sats: 0,
                },
                &clock,
                &blocks,
                None,
            )
            .unwrap_err();
        assert_eq!(err, SignError::WindowLedgerFull);
        assert_eq!(c.state.bookings.len(), MAX_BOOKINGS);
        let extra: BTreeSet<OutPoint> = [OutPoint {
            txid: Txid::from_byte_array([0xFD; 32]),
            vout: 99,
        }]
        .into_iter()
        .collect();
        c.commit(SpendApproval {
            input_set: extra,
            charge_sat: 9,
        });
        assert_eq!(c.state.bookings.len(), MAX_BOOKINGS);
    }

    #[test]
    fn wall_veto_forward_beyond_mono_zeroes_progress() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(Some(100));
        c.advance(&clock, &blocks, Some(1_000));
        clock.advance(Duration::from_secs(3_600));
        blocks.set(Some(106));
        c.advance(&clock, &blocks, Some(1_000 + 7_200 * 1_000_000_000));
        assert_eq!(c.window_elapsed(), Duration::ZERO);
    }

    #[test]
    fn wall_veto_backward_zeroes_progress() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(Some(100));
        c.advance(&clock, &blocks, Some(10_000));
        clock.advance(Duration::from_secs(3_600));
        blocks.set(Some(106));
        c.advance(&clock, &blocks, Some(1));
        assert_eq!(c.window_elapsed(), Duration::ZERO);
    }

    #[test]
    fn rbf_bump_refreshes_elapsed_so_row_does_not_expire_early() {
        let mut c = empty_counter();
        c.set_passphrase_used_since_install(true);
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        c.advance(&clock, &blocks, None);
        let set: BTreeSet<OutPoint> = [OutPoint {
            txid: Txid::from_byte_array([3; 32]),
            vout: 0,
        }]
        .into_iter()
        .collect();
        c.commit(SpendApproval {
            input_set: set.clone(),
            charge_sat: 100,
        });
        clock.advance(Duration::from_secs(23 * 3600 + 59 * 60));
        c.advance(&clock, &blocks, None);
        c.commit(SpendApproval {
            input_set: set,
            charge_sat: 500,
        });
        clock.advance(Duration::from_secs(120));
        c.advance(&clock, &blocks, None);
        c.prune(Duration::from_secs(24 * 3600));
        assert_eq!(c.booked_sat(), 500);
    }

    #[test]
    fn wall_absent_does_not_veto() {
        let mut c = empty_counter();
        let clock = FakeClock::new();
        let blocks = FakeBlockHeightSource::new(None);
        c.advance(&clock, &blocks, None);
        clock.advance(Duration::from_secs(5));
        c.advance(&clock, &blocks, None);
        assert_eq!(c.window_elapsed(), Duration::from_secs(5));
        clock.advance(Duration::from_secs(5));
        c.advance(&clock, &blocks, Some(99));
        assert_eq!(c.window_elapsed(), Duration::from_secs(10));
    }

    #[test]
    fn same_boot_without_boot_id_uses_mono() {
        struct NoBoot(std::sync::atomic::AtomicU64);
        impl MonotonicClock for NoBoot {
            fn now(&self) -> Duration {
                Duration::from_nanos(self.0.load(std::sync::atomic::Ordering::SeqCst))
            }
        }
        let clock = NoBoot(std::sync::atomic::AtomicU64::new(0));
        let blocks = FakeBlockHeightSource::new(None);
        let mut c = empty_counter();
        c.advance(&clock, &blocks, None);
        clock
            .0
            .store(2_000_000_000, std::sync::atomic::Ordering::SeqCst);
        c.advance(&clock, &blocks, None);
        assert_eq!(c.window_elapsed(), Duration::from_secs(2));
    }
}
