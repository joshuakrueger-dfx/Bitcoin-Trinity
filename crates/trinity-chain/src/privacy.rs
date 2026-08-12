//! Privacy disclosure of a chain backend — Spec §1.6 table + T16.

use core::fmt;

/// Backend family for the Spec §1.6 privacy table (and the in-memory test double).
///
/// Concrete network backends (WP-14 Electrum, WP-15 Core RPC, WP-16 CBF)
/// return a matching [`PrivacyProfile`]. There is **no vendor default server**
/// (Spec §1.6): whoever wants Electrum enters a host themselves; default
/// connectivity is CBF once WP-16 lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BackendKind {
    /// Electrum against a server the user operates.
    ElectrumOwnServer,
    /// Electrum against a third-party server — full wallet graph exposed.
    ElectrumThirdParty,
    /// Bitcoin Core JSON-RPC against the user's own node.
    CoreRpc,
    /// Compact Block Filters (BIP-157/158).
    Cbf,
    /// In-process test double — no network counterparty (WP-13 fake).
    InMemory,
}

impl BackendKind {
    /// Stable UI / log label (ASCII, no trailing punctuation).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ElectrumOwnServer => "electrum_own_server",
            Self::ElectrumThirdParty => "electrum_third_party",
            Self::CoreRpc => "core_rpc",
            Self::Cbf => "cbf",
            Self::InMemory => "in_memory",
        }
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a chain backend reveals to its counterparty in the standard case.
///
/// Derived from Spec §1.6 **"What a backend sees in the standard case"**
/// (columns *The counterparty learns* / *Magnitude*) and T16 (UI must show
/// third-party Electrum risk at selection, not only on a help page).
///
/// Field split mirrors WP-10 `Balance`: table meaning becomes named fields
/// the UI can render without re-deriving policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivacyProfile {
    /// Which Spec §1.6 table row this profile describes.
    pub kind: BackendKind,

    /// Spec §1.6 column "The counterparty learns" — UI body copy.
    pub counterparty_learns: &'static str,

    /// Spec §1.6 column "Magnitude" — residual exposure / who is exposed.
    pub magnitude: &'static str,

    /// `true` when the counterparty sees the full wallet graph (all
    /// scriptPubKeys, balances, every sync time) — Electrum rows.
    pub reveals_full_wallet_graph: bool,

    /// `true` when the counterparty is not solely the user's own host/node
    /// (third-party Electrum; CBF peers on the public network).
    pub third_party_counterparty: bool,

    /// T16 / Spec §1.6: must stand unmistakeably in the UI at backend
    /// selection (third-party Electrum). Not a help-page footnote.
    pub requires_selection_warning: bool,
}

impl PrivacyProfile {
    /// Electrum, own server — Spec §1.6 table row 1.
    pub const fn electrum_own_server() -> Self {
        Self {
            kind: BackendKind::ElectrumOwnServer,
            counterparty_learns: "All scriptPubKeys, the full wallet graph, every \
                 balance, every sync time, the IP.",
            magnitude: "Only own hoster/VPS provider — when run at home: nobody outside.",
            reveals_full_wallet_graph: true,
            third_party_counterparty: false,
            requires_selection_warning: false,
        }
    }

    /// Electrum, third-party server — Spec §1.6 table row 2 / T16.
    pub const fn electrum_third_party() -> Self {
        Self {
            kind: BackendKind::ElectrumThirdParty,
            counterparty_learns: "All scriptPubKeys, the full wallet graph, every \
                 balance, every sync time, the IP. The wallet is fully \
                 deanonymized toward this server.",
            magnitude: "Must stand unmistakeably in the UI, not on a help page.",
            reveals_full_wallet_graph: true,
            third_party_counterparty: true,
            requires_selection_warning: true,
        }
    }

    /// Bitcoin Core RPC, own node — Spec §1.6 table row 3.
    pub const fn core_rpc() -> Self {
        Self {
            kind: BackendKind::CoreRpc,
            counterparty_learns: "Nothing beyond the node. The node itself leaks no \
                 wallet information on P2P traffic (no bloom filter).",
            magnitude: "Best option when a node exists.",
            reveals_full_wallet_graph: false,
            third_party_counterparty: false,
            requires_selection_warning: false,
        }
    }

    /// CBF (BIP-157/158) — Spec §1.6 table row 4.
    ///
    /// Label discipline (resolved B.3 / O3): more private than a third-party
    /// Electrum server, **not** anonymous / unqualified "private".
    pub const fn cbf() -> Self {
        Self {
            kind: BackendKind::Cbf,
            counterparty_learns: "Peers learn: an IP loads headers and filters \
                 (reveals nothing about the wallet) and then loads certain \
                 blocks fully (reveals: in this block there is likely a \
                 transaction relevant to me). Across many blocks that is a \
                 statistical leak.",
            magnitude: "Clearly better than Electrum, not zero.",
            reveals_full_wallet_graph: false,
            third_party_counterparty: true,
            requires_selection_warning: false,
        }
    }

    /// In-memory test double — no network counterparty (WP-13).
    pub const fn in_memory() -> Self {
        Self {
            kind: BackendKind::InMemory,
            counterparty_learns: "Nothing — no network peer. Test-only double.",
            magnitude: "No external observer.",
            reveals_full_wallet_graph: false,
            third_party_counterparty: false,
            requires_selection_warning: false,
        }
    }
}

impl fmt::Display for PrivacyProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: graph={} third_party={} warn={}",
            self.kind,
            self.reveals_full_wallet_graph,
            self.third_party_counterparty,
            self.requires_selection_warning
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_rows_match_spec_flags() {
        let own = PrivacyProfile::electrum_own_server();
        assert!(own.reveals_full_wallet_graph);
        assert!(!own.third_party_counterparty);
        assert!(!own.requires_selection_warning);

        let third = PrivacyProfile::electrum_third_party();
        assert!(third.reveals_full_wallet_graph);
        assert!(third.third_party_counterparty);
        assert!(third.requires_selection_warning);

        let core = PrivacyProfile::core_rpc();
        assert!(!core.reveals_full_wallet_graph);
        assert!(!core.third_party_counterparty);

        let cbf = PrivacyProfile::cbf();
        assert!(!cbf.reveals_full_wallet_graph);
        assert!(cbf.third_party_counterparty);
        assert!(!cbf.requires_selection_warning);
    }

    #[test]
    fn kind_labels_stable() {
        assert_eq!(
            BackendKind::ElectrumOwnServer.as_str(),
            "electrum_own_server"
        );
        assert_eq!(
            BackendKind::ElectrumThirdParty.as_str(),
            "electrum_third_party"
        );
        assert_eq!(BackendKind::CoreRpc.as_str(), "core_rpc");
        assert_eq!(BackendKind::Cbf.as_str(), "cbf");
        assert_eq!(BackendKind::InMemory.as_str(), "in_memory");
        assert_eq!(format!("{}", BackendKind::CoreRpc), "core_rpc");
        assert!(format!("{}", PrivacyProfile::in_memory()).contains("in_memory"));
    }

    #[test]
    fn copy_strings_are_nonempty() {
        for p in [
            PrivacyProfile::electrum_own_server(),
            PrivacyProfile::electrum_third_party(),
            PrivacyProfile::core_rpc(),
            PrivacyProfile::cbf(),
            PrivacyProfile::in_memory(),
        ] {
            assert!(!p.counterparty_learns.is_empty());
            assert!(!p.magnitude.is_empty());
        }
    }
}
