//! [`SpendPolicy`] and the clamp that yields the window allowance.
//!
//! Spec §3.6.3 / §3.6.5. Enforcement uses stored sat values only — no
//! rate fetch (WP-35).

use std::time::Duration;

use crate::error::SignError;

/// Non-negative rational used as `window_fraction` (Spec §3.6.3).
///
/// No workspace type existed (`trinity-types` has none). A two-integer
/// fraction avoids an extra crate. `denom == 0` is unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ratio {
    numer: u64,
    denom: u64,
}

impl Ratio {
    /// `numer / denom`. `None` when `denom == 0`.
    #[inline]
    pub const fn new(numer: u64, denom: u64) -> Option<Self> {
        if denom == 0 {
            None
        } else {
            Some(Self { numer, denom })
        }
    }

    /// Default share: 20 % = 1/5 (O15).
    pub const PERCENT_20: Self = Self { numer: 1, denom: 5 };

    /// Numerator.
    #[inline]
    pub const fn numer(self) -> u64 {
        self.numer
    }

    /// Denominator (never zero).
    #[inline]
    pub const fn denom(self) -> u64 {
        self.denom
    }

    /// `floor(value * numer / denom)` with a `u128` intermediate.
    #[inline]
    pub const fn of(self, value: u64) -> u64 {
        let n = (value as u128).saturating_mul(self.numer as u128) / self.denom as u128;
        if n > u64::MAX as u128 {
            u64::MAX
        } else {
            n as u64
        }
    }
}

impl core::ops::Mul<u64> for Ratio {
    type Output = u64;

    #[inline]
    fn mul(self, rhs: u64) -> u64 {
        self.of(rhs)
    }
}

/// Sliding-window spend limit (Spec §3.6.3, §3.6.5).
///
/// Fields are `pub` to match the spec snippet. The only supported
/// construction paths are [`SpendPolicy::standard`], [`SpendPolicy::off`],
/// and [`set_spend_policy`] — the last rejects `floor > cap` and a
/// disabled first-use flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendPolicy {
    /// Share of the balance reference. `None` = no share (unlimited
    /// before floor/cap). Default 20 %.
    pub window_fraction: Option<Ratio>,
    /// Floor in sats. `None` = 0. Default sat-stand-in for €200.
    pub window_floor_sat: Option<u64>,
    /// Cap in sats. `None` = `u64::MAX`. Default sat-stand-in for €500.
    pub window_cap_sat: Option<u64>,
    /// Sliding window length. Default 24 h.
    pub window: Duration,
    /// First signature after install needs the passphrase. Default
    /// `true`; [`set_spend_policy`] refuses `false`.
    pub passphrase_on_first_use: bool,
}

impl SpendPolicy {
    /// Spec defaults: `clamp(20 %, 200, 500)` per 24 h, first-use on.
    ///
    /// Floor/cap are sat numbers. Fiat anchoring is WP-35; tests treat
    /// these units as the € amounts of the spec table (S29b).
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            window_fraction: Some(Ratio::PERCENT_20),
            window_floor_sat: Some(200),
            window_cap_sat: Some(500),
            window: Duration::from_secs(24 * 60 * 60),
            passphrase_on_first_use: true,
        }
    }

    /// Window "off" (3.6.5): no share/floor/cap. First-use stays on.
    #[must_use]
    pub const fn off() -> Self {
        Self {
            window_fraction: None,
            window_floor_sat: None,
            window_cap_sat: None,
            window: Duration::from_secs(24 * 60 * 60),
            passphrase_on_first_use: true,
        }
    }

    /// `floor ≤ cap`, first-use stays enabled, share 1 %–100 %, window 1 h–7 d
    /// (Spec §3.6.5). `None` share is "off" and is allowed.
    pub(crate) fn validate(self) -> Result<Self, SignError> {
        let floor = self.window_floor_sat.unwrap_or(0);
        let cap = self.window_cap_sat.unwrap_or(u64::MAX);
        if floor > cap {
            return Err(SignError::FloorAboveCap);
        }
        if !self.passphrase_on_first_use {
            return Err(SignError::InvalidSpendPolicy);
        }
        if let Some(f) = self.window_fraction {
            // 1 % ≤ share ≤ 100 %.
            if f.numer() == 0 || f.numer() > f.denom() || f.numer().saturating_mul(100) < f.denom()
            {
                return Err(SignError::PolicyOutOfRange);
            }
        }
        if self.window < Duration::from_secs(60 * 60)
            || self.window > Duration::from_secs(7 * 24 * 60 * 60)
        {
            return Err(SignError::PolicyOutOfRange);
        }
        Ok(self)
    }
}

impl Default for SpendPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

/// Setter for a user-supplied [`SpendPolicy`] (S29f). Rejects `floor > cap`
/// and out-of-range share/window instead of reshaping. FFI export is a later WP.
pub fn set_spend_policy(policy: SpendPolicy) -> Result<SpendPolicy, SignError> {
    policy.validate()
}

/// What may be spent in the window without passphrase (Spec §3.6.3).
///
/// Also capped by the balance itself (S29b: balance smaller than the
/// floor). `floor > cap` (possible via the public fields) yields 0 —
/// fail-closed, never a panic on the signature path.
pub fn allowance(p: &SpendPolicy, balance_sat: u64) -> u64 {
    let by_fraction = p
        .window_fraction
        .map(|f| f * balance_sat)
        .unwrap_or(u64::MAX);
    let floor = p.window_floor_sat.unwrap_or(0);
    let cap = p.window_cap_sat.unwrap_or(u64::MAX);
    if floor > cap {
        return 0;
    }
    by_fraction.clamp(floor, cap).min(balance_sat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_rejects_zero_denominator() {
        assert!(Ratio::new(1, 0).is_none());
        assert_eq!(Ratio::new(1, 5), Some(Ratio::PERCENT_20));
        assert_eq!(Ratio::PERCENT_20.numer(), 1);
        assert_eq!(Ratio::PERCENT_20.denom(), 5);
    }

    #[test]
    fn ratio_of_and_mul() {
        let r = Ratio::PERCENT_20;
        assert_eq!(r.of(1000), 200);
        assert_eq!(r * 1000, 200);
        assert_eq!(r.of(999), 199);
        assert_eq!(r.of(0), 0);
        assert_eq!(Ratio::new(0, 5).unwrap().of(100), 0);
    }

    #[test]
    fn ratio_saturating_mul() {
        let r = Ratio::new(u64::MAX, 1).unwrap();
        assert_eq!(r.of(2), u64::MAX);
        let half = Ratio::new(1, 2).unwrap();
        assert_eq!(half.of(u64::MAX), u64::MAX / 2);
    }

    #[test]
    fn s29b_clamp_three_ranges_and_edges() {
        let p = SpendPolicy::standard();
        // < 1000: floor. 999 * 20 % = 199 → clamp to 200.
        assert_eq!(allowance(&p, 0), 0);
        assert_eq!(allowance(&p, 100), 100);
        assert_eq!(allowance(&p, 199), 199);
        assert_eq!(allowance(&p, 200), 200);
        assert_eq!(allowance(&p, 999), 200);
        // exactly 1000: share meets floor.
        assert_eq!(allowance(&p, 1000), 200);
        // 1000–2500: the 20 % share.
        assert_eq!(allowance(&p, 1500), 300);
        // exactly 2500: share meets cap.
        assert_eq!(allowance(&p, 2500), 500);
        // > 2500: cap.
        assert_eq!(allowance(&p, 2501), 500);
        assert_eq!(allowance(&p, 10_000), 500);
    }

    #[test]
    fn s29b_floor_equals_cap() {
        let p = SpendPolicy {
            window_fraction: Some(Ratio::PERCENT_20),
            window_floor_sat: Some(300),
            window_cap_sat: Some(300),
            window: Duration::from_secs(60 * 60),
            passphrase_on_first_use: true,
        };
        assert_eq!(allowance(&p, 100), 100);
        assert_eq!(allowance(&p, 300), 300);
        assert_eq!(allowance(&p, 10_000), 300);
    }

    #[test]
    fn allowance_no_fraction_uses_cap() {
        let p = SpendPolicy {
            window_fraction: None,
            window_floor_sat: Some(10),
            window_cap_sat: Some(50),
            window: Duration::from_secs(60 * 60),
            passphrase_on_first_use: true,
        };
        assert_eq!(allowance(&p, 10_000), 50);
        assert_eq!(allowance(&p, 5), 5);
    }

    #[test]
    fn allowance_off_is_the_balance() {
        let p = SpendPolicy::off();
        assert_eq!(allowance(&p, 42), 42);
        assert_eq!(allowance(&p, 0), 0);
    }

    #[test]
    fn allowance_floor_above_cap_is_zero() {
        let p = SpendPolicy {
            window_fraction: Some(Ratio::PERCENT_20),
            window_floor_sat: Some(500),
            window_cap_sat: Some(200),
            window: Duration::from_secs(60 * 60),
            passphrase_on_first_use: true,
        };
        assert_eq!(allowance(&p, 10_000), 0);
    }

    #[test]
    fn s29f_setter_rejects_floor_above_cap() {
        let mut p = SpendPolicy::standard();
        p.window_floor_sat = Some(600);
        p.window_cap_sat = Some(500);
        assert_eq!(set_spend_policy(p).unwrap_err(), SignError::FloorAboveCap);
        p.window_floor_sat = Some(100);
        p.window_cap_sat = Some(50);
        assert_eq!(set_spend_policy(p).unwrap_err(), SignError::FloorAboveCap);
        p.window_floor_sat = Some(200);
        p.window_cap_sat = Some(500);
        assert_eq!(set_spend_policy(p).unwrap(), SpendPolicy::standard());
    }

    #[test]
    fn setter_rejects_disabled_first_use() {
        let mut p = SpendPolicy::standard();
        p.passphrase_on_first_use = false;
        assert_eq!(
            set_spend_policy(p).unwrap_err(),
            SignError::InvalidSpendPolicy
        );
    }

    #[test]
    fn setter_accepts_equal_floor_and_cap() {
        let p = SpendPolicy {
            window_fraction: None,
            window_floor_sat: Some(7),
            window_cap_sat: Some(7),
            window: Duration::from_secs(60 * 60),
            passphrase_on_first_use: true,
        };
        assert_eq!(set_spend_policy(p).unwrap(), p);
    }

    #[test]
    fn setter_rejects_zero_and_out_of_range_window() {
        let mut p = SpendPolicy::standard();
        p.window = Duration::ZERO;
        assert_eq!(
            set_spend_policy(p).unwrap_err(),
            SignError::PolicyOutOfRange
        );
        p.window = Duration::from_secs(60 * 60 - 1);
        assert_eq!(
            set_spend_policy(p).unwrap_err(),
            SignError::PolicyOutOfRange
        );
        p.window = Duration::from_secs(7 * 24 * 60 * 60 + 1);
        assert_eq!(
            set_spend_policy(p).unwrap_err(),
            SignError::PolicyOutOfRange
        );
        p.window = Duration::from_secs(60 * 60);
        assert!(set_spend_policy(p).is_ok());
        p.window = Duration::from_secs(7 * 24 * 60 * 60);
        assert!(set_spend_policy(p).is_ok());
    }

    #[test]
    fn setter_rejects_share_outside_one_to_hundred_percent() {
        let mut p = SpendPolicy::standard();
        p.window_fraction = Some(Ratio::new(0, 5).unwrap());
        assert_eq!(
            set_spend_policy(p).unwrap_err(),
            SignError::PolicyOutOfRange
        );
        p.window_fraction = Some(Ratio::new(1, 200).unwrap());
        assert_eq!(
            set_spend_policy(p).unwrap_err(),
            SignError::PolicyOutOfRange
        );
        p.window_fraction = Some(Ratio::new(2, 1).unwrap());
        assert_eq!(
            set_spend_policy(p).unwrap_err(),
            SignError::PolicyOutOfRange
        );
        p.window_fraction = Some(Ratio::new(1, 100).unwrap());
        assert!(set_spend_policy(p).is_ok());
        p.window_fraction = Some(Ratio::new(1, 1).unwrap());
        assert!(set_spend_policy(p).is_ok());
        p.window_fraction = None;
        assert!(set_spend_policy(p).is_ok());
    }

    #[test]
    fn default_is_standard() {
        assert_eq!(SpendPolicy::default(), SpendPolicy::standard());
        assert_eq!(SpendPolicy::standard().window, Duration::from_secs(86_400));
    }
}
