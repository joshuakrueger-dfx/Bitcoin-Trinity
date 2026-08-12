//! Verification policy — pure value type for checks V3/V5/V6/V7 (Spec §1.5).
//!
//! Lives in `trinity-verify` (not `trinity-types`) because it is an input to
//! [`crate::verify`], not an FFI display type like [`trinity_types::PsbtVerdict`].
//! No secrets, no I/O — same discipline as `PsbtVerdict` / `SendRequest`.
//!
//! **Gap window:** Spec §1.5 V3 refers to "the current gap window" but does not
//! pin a numeric bound. This crate has no wallet/UTXO state (that is
//! `trinity-watch`). The caller supplies [`VerifyPolicy::gap_limit`] as the
//! exclusive upper bound of address indices searched (`0..gap_limit`) on the
//! receive descriptor and, when set, the change descriptor. Wallet state
//! (highest used index + lookahead) is assembled by the signer/UI layers
//! (WP-33+) before calling [`crate::verify`].

use std::collections::BTreeMap;

use bitcoin::{Network, OutPoint, TxOut};

/// Policy bounds and declared user intent for independent PSBT verification.
///
/// Spec §1.5 V3/V5/V6/V7; fee caps also referenced in §3.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyPolicy {
    /// Destination addresses the user confirmed (V3 `declared_recipients`).
    ///
    /// Compared as network-encoded address strings (bech32) against each
    /// non-change output. Empty is allowed only for pathologically empty
    /// transactions (which V5/V8 still reject).
    pub declared_recipients: Vec<String>,

    /// Bit-exact sum of non-change output amounts the user confirmed (V6).
    pub declared_amount_sats: u64,

    /// Absolute fee cap in satoshi (V5 `max_absolute_fee`).
    pub max_absolute_fee: u64,

    /// Feerate cap in satoshi per virtual byte (V5; same unit as
    /// [`trinity_types::PsbtVerdict::feerate_sat_vb`]).
    pub max_feerate: u64,

    /// Optional exact fee from a prior display-run verdict (Spec §3.3 / P2).
    ///
    /// When `Some(expected)`, V5 requires `fee_sats == expected` in addition to
    /// the absolute/feerate caps. Callers populate this from the first
    /// `verify()` result (`PsbtVerdict::fee_sats`) so later pre-sign runs catch
    /// fee/change mutations between confirmation and signature. `None` on the
    /// initial display run (nothing to pin yet) — only the caps apply.
    pub declared_fee_sats: Option<u64>,

    /// Exclusive upper bound of address indices searched for V2/V3/V4:
    /// indices `0..gap_limit` on each available chain (receive + optional
    /// change descriptor). Caller supplies the window from wallet state.
    pub gap_limit: u32,

    /// Watch-only UTXOs allowed as PSBT inputs (V7): outpoint → full
    /// `TxOut` (value + script_pubkey). Being “in the list” means the
    /// outpoint is known **and** the PSBT’s `witness_utxo` matches that
    /// record byte-for-byte — not merely that the outpoint coordinate is
    /// recognized.
    pub known_utxos: BTreeMap<OutPoint, TxOut>,

    /// Internal-chain (`/1/*`) descriptor string for change reconstruction.
    ///
    /// Required whenever the PSBT may contain change outputs or spend
    /// change-chain UTXOs. The grammar parser rejects multipath, so receive
    /// and change are separate strings (Spec O8). `None` means no change
    /// outputs are accepted (every output must be in `declared_recipients`)
    /// and V2 only matches the receive descriptor.
    pub change_descriptor: Option<String>,

    /// Network used to encode addresses when classifying outputs (V3).
    pub network: Network,
}

impl VerifyPolicy {
    /// Construct a full policy record.
    #[allow(clippy::too_many_arguments)] // mirrors Spec §1.5 check inputs
    pub fn new(
        declared_recipients: Vec<String>,
        declared_amount_sats: u64,
        max_absolute_fee: u64,
        max_feerate: u64,
        declared_fee_sats: Option<u64>,
        gap_limit: u32,
        known_utxos: BTreeMap<OutPoint, TxOut>,
        change_descriptor: Option<String>,
        network: Network,
    ) -> Self {
        Self {
            declared_recipients,
            declared_amount_sats,
            max_absolute_fee,
            max_feerate,
            declared_fee_sats,
            gap_limit,
            known_utxos,
            change_descriptor,
            network,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, ScriptBuf, Txid};

    #[test]
    fn construct_policy() {
        let op = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };
        let mut known = BTreeMap::new();
        known.insert(
            op,
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            },
        );
        let p = VerifyPolicy::new(
            vec!["bcrt1qrecv".into()],
            10_000,
            1_000,
            50,
            None,
            20,
            known,
            Some("wsh(...)#xxxx".into()),
            Network::Regtest,
        );
        assert_eq!(p.declared_amount_sats, 10_000);
        assert_eq!(p.declared_fee_sats, None);
        assert_eq!(p.gap_limit, 20);
        assert_eq!(p.known_utxos.len(), 1);
        assert!(p.change_descriptor.is_some());
        assert_eq!(p.network, Network::Regtest);
    }
}
