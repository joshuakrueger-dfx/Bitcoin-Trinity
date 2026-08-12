//! PSBT construction request — SPECIFICATION.md §1.3, §3.1.

use core::fmt;
use serde::{Deserialize, Serialize};

/// How the user targets fees when building a send.
///
/// Spec §3.1: user supplies "recipient + amount + **fee target**" before
/// `build_psbt(SendRequest)`. Confirmation later shows absolute fee and
/// sat/vB (from the verdict); construction needs a target going in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeTarget {
    /// Target fee rate in satoshi per virtual byte (dialog unit "sat/vB").
    FeerateSatVb(u64),
    /// Absolute fee budget in satoshi.
    AbsoluteSats(u64),
}

impl FeeTarget {
    /// `true` when this is a feerate target.
    #[inline]
    pub const fn is_feerate(self) -> bool {
        matches!(self, FeeTarget::FeerateSatVb(_))
    }

    /// `true` when this is an absolute-fee target.
    #[inline]
    pub const fn is_absolute(self) -> bool {
        matches!(self, FeeTarget::AbsoluteSats(_))
    }
}

impl fmt::Display for FeeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeeTarget::FeerateSatVb(v) => write!(f, "{v} sat/vB"),
            FeeTarget::AbsoluteSats(v) => write!(f, "{v} sat"),
        }
    }
}

/// User intent for `build_psbt` — Spec §1.3 / §3.1.
///
/// Spec §1.3 facade: `pub fn build_psbt(&self, req: SendRequest) -> Result<String, TxError>`.
/// Spec §3.1: `JS->>FFI: build_psbt(SendRequest)` after the user chose
/// recipient, amount, and fee target.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SendRequest {
    /// Destination address string (public). Spec §1.3 allows address `String`.
    pub recipient: String,
    /// Amount to send in satoshi (non-change output). Spec §1.3 `u64` satoshi.
    pub amount_sats: u64,
    /// Fee targeting for coin selection / TxBuilder (Spec §3.1 "fee target").
    pub fee_target: FeeTarget,
}

impl SendRequest {
    /// Construct a send request.
    #[inline]
    pub fn new(recipient: impl Into<String>, amount_sats: u64, fee_target: FeeTarget) -> Self {
        Self {
            recipient: recipient.into(),
            amount_sats,
            fee_target,
        }
    }
}

impl fmt::Debug for SendRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Recipient address and amounts are public intent, not secrets.
        f.debug_struct("SendRequest")
            .field("recipient", &self.recipient)
            .field("amount_sats", &self.amount_sats)
            .field("fee_target", &self.fee_target)
            .finish()
    }
}

impl fmt::Display for SendRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} sat to {} ({})",
            self.amount_sats, self.recipient, self.fee_target
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct() {
        let r = SendRequest::new("bc1qto", 10_000, FeeTarget::FeerateSatVb(2));
        assert_eq!(r.recipient, "bc1qto");
        assert_eq!(r.amount_sats, 10_000);
        assert_eq!(r.fee_target, FeeTarget::FeerateSatVb(2));
    }

    #[test]
    fn fee_target_flags_and_display() {
        let fr = FeeTarget::FeerateSatVb(5);
        let ab = FeeTarget::AbsoluteSats(300);
        assert!(fr.is_feerate());
        assert!(!fr.is_absolute());
        assert!(ab.is_absolute());
        assert!(!ab.is_feerate());
        assert_eq!(format!("{fr}"), "5 sat/vB");
        assert_eq!(format!("{ab}"), "300 sat");
    }

    #[test]
    fn display_and_debug() {
        let r = SendRequest::new("tb1q", 1, FeeTarget::AbsoluteSats(100));
        assert!(format!("{r}").contains("tb1q"));
        assert!(format!("{r:?}").contains("SendRequest"));
    }

    #[test]
    fn serde_roundtrip_both_fee_variants() {
        for fee in [FeeTarget::FeerateSatVb(1), FeeTarget::AbsoluteSats(42)] {
            let r = SendRequest::new("bc1q", 9, fee);
            let j = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<SendRequest>(&j).unwrap(), r);
        }
    }
}
