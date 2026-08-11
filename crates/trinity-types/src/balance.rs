//! Wallet balance breakdown — SPECIFICATION.md §1.3, §3.6.7.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Spendable and pending balances in satoshi.
///
/// Spec §1.3 facade: `pub fn balance(&self) -> Balance`.
/// Spec §3.6.7 **Balance reference** for SpendPolicy:
/// "confirmed UTXOs **plus** unconfirmed own change". Foreign unconfirmed
/// money must **not** raise the reference (attack: unconfirmed payment to
/// artificially widen the 20 % share).
///
/// Field split follows that rule and the BDK `Balance` shape the facade will
/// map from (confirmed / trusted_pending / untrusted_pending / immature).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Balance {
    /// Confirmed, immediately spendable UTXOs (sats). Spec §3.6.7.
    pub confirmed_sats: u64,
    /// Unconfirmed UTXOs produced by this wallet (own change). Spec §3.6.7
    /// "unconfirmed own change" — **counts** toward the SpendPolicy reference.
    pub trusted_pending_sats: u64,
    /// Unconfirmed UTXOs received from outside. Spec §3.6.7: foreign
    /// unconfirmed money does **not** count toward the SpendPolicy reference.
    pub untrusted_pending_sats: u64,
    /// Immature coinbase outputs (sats). Not spendable until matured.
    pub immature_sats: u64,
}

impl Balance {
    /// Empty balance.
    #[inline]
    pub const fn zero() -> Self {
        Self {
            confirmed_sats: 0,
            trusted_pending_sats: 0,
            untrusted_pending_sats: 0,
            immature_sats: 0,
        }
    }

    /// Balance used as SpendPolicy reference (Spec §3.6.7):
    /// confirmed + unconfirmed own change.
    #[inline]
    pub const fn spend_policy_reference_sats(self) -> u64 {
        self.confirmed_sats
            .saturating_add(self.trusted_pending_sats)
    }

    /// Trusted coins spendable now without depending on a third party
    /// (confirmed + own unconfirmed change). Same sum as the policy reference.
    #[inline]
    pub const fn trusted_spendable_sats(self) -> u64 {
        self.spend_policy_reference_sats()
    }

    /// All coins visible to the wallet, including untrusted and immature.
    #[inline]
    pub const fn total_sats(self) -> u64 {
        self.confirmed_sats
            .saturating_add(self.trusted_pending_sats)
            .saturating_add(self.untrusted_pending_sats)
            .saturating_add(self.immature_sats)
    }
}

impl fmt::Display for Balance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ confirmed: {}, trusted_pending: {}, untrusted_pending: {}, immature: {} }}",
            self.confirmed_sats,
            self.trusted_pending_sats,
            self.untrusted_pending_sats,
            self.immature_sats
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_policy_excludes_untrusted_and_immature() {
        let b = Balance {
            confirmed_sats: 100,
            trusted_pending_sats: 20,
            untrusted_pending_sats: 999,
            immature_sats: 50,
        };
        // Spec §3.6.7: confirmed + unconfirmed own change only.
        assert_eq!(b.spend_policy_reference_sats(), 120);
        assert_eq!(b.trusted_spendable_sats(), 120);
        assert_eq!(b.total_sats(), 100 + 20 + 999 + 50);
    }

    #[test]
    fn zero_and_default() {
        assert_eq!(Balance::zero(), Balance::default());
        assert_eq!(Balance::zero().total_sats(), 0);
        assert_eq!(Balance::zero().spend_policy_reference_sats(), 0);
    }

    #[test]
    fn saturating_on_overflow() {
        let b = Balance {
            confirmed_sats: u64::MAX,
            trusted_pending_sats: 1,
            untrusted_pending_sats: 0,
            immature_sats: 0,
        };
        assert_eq!(b.spend_policy_reference_sats(), u64::MAX);
    }

    #[test]
    fn display_lists_components() {
        let b = Balance {
            confirmed_sats: 1,
            trusted_pending_sats: 2,
            untrusted_pending_sats: 3,
            immature_sats: 4,
        };
        let s = format!("{b}");
        assert!(s.contains("confirmed: 1"));
        assert!(s.contains("trusted_pending: 2"));
        assert!(s.contains("untrusted_pending: 3"));
        assert!(s.contains("immature: 4"));
    }

    #[test]
    fn serde_roundtrip() {
        let b = Balance {
            confirmed_sats: 10,
            trusted_pending_sats: 0,
            untrusted_pending_sats: 1,
            immature_sats: 0,
        };
        let j = serde_json::to_string(&b).unwrap();
        assert_eq!(serde_json::from_str::<Balance>(&j).unwrap(), b);
    }
}
