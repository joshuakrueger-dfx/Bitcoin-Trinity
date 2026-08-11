//! Bitcoin network — SPECIFICATION.md §2.3 (network separation).

use core::fmt;
use serde::{Deserialize, Serialize};

/// Network identity for descriptors, address encoding, and store separation.
///
/// Spec §2.3: "Signet/Testnet use coin type `1'` and a separate descriptor
/// store. No shared state with mainnet." Spec §5.3 also runs regtest in CI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    /// Bitcoin mainnet — coin type `0'` (Spec §2.3 path diagram).
    Bitcoin,
    /// Bitcoin testnet3 — coin type `1'` (Spec §2.3).
    Testnet,
    /// Signet — coin type `1'` (Spec §2.3, §5.3).
    Signet,
    /// Local regtest — CI and differential harness (Spec §5.3).
    Regtest,
}

impl Network {
    /// BIP-44/48 coin type for this network.
    ///
    /// Spec §2.3: mainnet `0'`, Signet/Testnet `1'`. Regtest follows testnet
    /// coin type in practice (same as rust-bitcoin / Core regtest descriptors).
    #[inline]
    pub const fn coin_type(self) -> u32 {
        match self {
            Network::Bitcoin => 0,
            Network::Testnet | Network::Signet | Network::Regtest => 1,
        }
    }

    /// `true` when this network must not share descriptor state with mainnet.
    ///
    /// Spec §2.3 network separation rule.
    #[inline]
    pub const fn is_test_network(self) -> bool {
        !matches!(self, Network::Bitcoin)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Bitcoin => f.write_str("bitcoin"),
            Network::Testnet => f.write_str("testnet"),
            Network::Signet => f.write_str("signet"),
            Network::Regtest => f.write_str("regtest"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_types() {
        assert_eq!(Network::Bitcoin.coin_type(), 0);
        assert_eq!(Network::Testnet.coin_type(), 1);
        assert_eq!(Network::Signet.coin_type(), 1);
        assert_eq!(Network::Regtest.coin_type(), 1);
    }

    #[test]
    fn test_network_flag() {
        assert!(!Network::Bitcoin.is_test_network());
        assert!(Network::Testnet.is_test_network());
        assert!(Network::Signet.is_test_network());
        assert!(Network::Regtest.is_test_network());
    }

    #[test]
    fn display_labels() {
        assert_eq!(format!("{}", Network::Bitcoin), "bitcoin");
        assert_eq!(format!("{}", Network::Testnet), "testnet");
        assert_eq!(format!("{}", Network::Signet), "signet");
        assert_eq!(format!("{}", Network::Regtest), "regtest");
    }

    #[test]
    fn serde_snake_case() {
        let j = serde_json::to_string(&Network::Signet).unwrap();
        assert_eq!(j, "\"signet\"");
        assert_eq!(
            serde_json::from_str::<Network>("\"regtest\"").unwrap(),
            Network::Regtest
        );
    }
}
