//! Independent PSBT verification result — SPECIFICATION.md §1.3, §3.1, §6.2.

use core::fmt;
use serde::{Deserialize, Serialize};

/// What the verifier read out of a PSBT for the native confirmation dialog.
///
/// Spec §3.1 sequence diagram:
/// `PsbtVerdict{ok, recipient, amount, change, fee, feerate}`.
/// Spec §6.2: dialog is rendered **from this verdict**, not from JS state —
/// "address in groups of 4 · amount · fee · sat/vB · change".
/// Spec §1.3 facade: `verify_psbt(...) -> Result<PsbtVerdict, VerifyError>`.
///
/// Amounts are satoshi (`u64` allowed across the boundary, Spec §1.3).
/// Feerate is sat/vB because the confirmation copy shows "Z sat/vB".
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PsbtVerdict {
    /// Overall pass/fail of checks V1–V9 (hard rejections become `VerifyError`
    /// at the facade; `ok` remains for structured display of soft state).
    pub ok: bool,
    /// Recipient address as present in the PSBT (Spec §6.2 / T7).
    pub recipient: String,
    /// Non-change output amount in sats (Spec §3.1 `amount`, V6).
    pub amount_sats: u64,
    /// Change output amount in sats (Spec §3.1 `change`; 0 if changeless).
    pub change_sats: u64,
    /// Absolute fee in sats: `Σ inputs − Σ outputs` (Spec §1.5 V5, §3.1 `fee`).
    pub fee_sats: u64,
    /// Effective fee rate in satoshi per virtual byte (Spec §3.1 `feerate`,
    /// dialog "Z sat/vB"). Integer ceil is fine for display; fractional rates
    /// are rounded up by the verifier when mapping from kvB.
    pub feerate_sat_vb: u64,
}

impl PsbtVerdict {
    /// Construct a full verdict record.
    #[allow(clippy::too_many_arguments)] // mirrors Spec §3.1 field list exactly
    pub fn new(
        ok: bool,
        recipient: impl Into<String>,
        amount_sats: u64,
        change_sats: u64,
        fee_sats: u64,
        feerate_sat_vb: u64,
    ) -> Self {
        Self {
            ok,
            recipient: recipient.into(),
            amount_sats,
            change_sats,
            fee_sats,
            feerate_sat_vb,
        }
    }
}

impl fmt::Debug for PsbtVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // All fields are public transaction metadata (Spec §1.3) — no secrets.
        f.debug_struct("PsbtVerdict")
            .field("ok", &self.ok)
            .field("recipient", &self.recipient)
            .field("amount_sats", &self.amount_sats)
            .field("change_sats", &self.change_sats)
            .field("fee_sats", &self.fee_sats)
            .field("feerate_sat_vb", &self.feerate_sat_vb)
            .finish()
    }
}

impl fmt::Display for PsbtVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mirrors Spec §3.1 confirmation line:
        // "X sat to bc1q… · fee Y sat (Z sat/vB)"
        write!(
            f,
            "{} sat to {} · fee {} sat ({} sat/vB) · change {} sat · ok={}",
            self.amount_sats,
            self.recipient,
            self.fee_sats,
            self.feerate_sat_vb,
            self.change_sats,
            self.ok
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ok: bool) -> PsbtVerdict {
        PsbtVerdict::new(ok, "bc1qrecv", 50_000, 12_000, 250, 3)
    }

    #[test]
    fn fields_match_spec_shape() {
        let v = sample(true);
        assert!(v.ok);
        assert_eq!(v.recipient, "bc1qrecv");
        assert_eq!(v.amount_sats, 50_000);
        assert_eq!(v.change_sats, 12_000);
        assert_eq!(v.fee_sats, 250);
        assert_eq!(v.feerate_sat_vb, 3);
    }

    #[test]
    fn display_confirmation_line() {
        let s = format!("{}", sample(true));
        assert!(s.contains("50000 sat to bc1qrecv"));
        assert!(s.contains("fee 250 sat"));
        assert!(s.contains("3 sat/vB"));
        assert!(s.contains("change 12000 sat"));
        assert!(s.contains("ok=true"));
    }

    #[test]
    fn debug_and_not_ok() {
        let v = sample(false);
        assert!(!v.ok);
        let d = format!("{v:?}");
        assert!(d.contains("PsbtVerdict"));
        assert!(d.contains("bc1qrecv"));
    }

    #[test]
    fn serde_roundtrip() {
        let v = sample(true);
        let j = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<PsbtVerdict>(&j).unwrap(), v);
    }
}
