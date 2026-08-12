//! BIP-48 path helpers — Spec §2.3.

use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath};
use trinity_types::Network;

use super::error::DescriptorError;

/// BIP-48 purpose (multisig).
pub const BIP48_PURPOSE: u32 = 48;
/// BIP-48 script type 2 = P2WSH nested in multisig.
pub const BIP48_SCRIPT_P2WSH: u32 = 2;
/// Account index fixed at 0 for v1.
pub const BIP48_ACCOUNT: u32 = 0;

/// Absolute origin path without leading `m/` for the network's coin type.
///
/// Spec §2.3: `m/48'/0'/0'/2'` on mainnet; Signet/Testnet/Regtest use `1'`.
/// Format uses `'` (not `h`) to match miniscript/bitcoin `Display` defaults
/// and BDK Caravan export examples (`vendor/bdk_wallet/src/wallet/export.rs`).
pub fn bip48_origin_path(network: Network) -> String {
    format!(
        "{}'/{}'/{}'/{}'",
        BIP48_PURPOSE,
        network.coin_type(),
        BIP48_ACCOUNT,
        BIP48_SCRIPT_P2WSH
    )
}

/// Validate that `path` is exactly BIP-48 `48'/coin'/0'/2'` for `network`.
///
/// Accepts both `'` and `h` hardened markers (BIP-380 / rust-bitcoin).
pub fn validate_bip48_origin(path: &str, network: Network) -> Result<(), DescriptorError> {
    if path.contains('<') || path.contains(';') || path.contains('*') {
        return Err(DescriptorError::MultipathForbidden);
    }
    let trimmed = path.strip_prefix("m/").unwrap_or(path);
    let deriv = DerivationPath::from_str(trimmed)
        .map_err(|e| DescriptorError::InvalidOriginPath(format!("{path} ({e})")))?;
    let expected = expected_bip48_children(network);
    let actual: Vec<ChildNumber> = deriv.into_iter().copied().collect();
    if actual != expected {
        return Err(DescriptorError::InvalidOriginPath(path.to_owned()));
    }
    Ok(())
}

fn expected_bip48_children(network: Network) -> Vec<ChildNumber> {
    vec![
        ChildNumber::from_hardened_idx(BIP48_PURPOSE).expect("48 fits hardened"),
        ChildNumber::from_hardened_idx(network.coin_type()).expect("coin type fits"),
        ChildNumber::from_hardened_idx(BIP48_ACCOUNT).expect("0 fits"),
        ChildNumber::from_hardened_idx(BIP48_SCRIPT_P2WSH).expect("2 fits"),
    ]
}

/// Reject private extended key prefixes and multipath markers in an xpub string.
pub fn validate_public_xpub(xpub: &str) -> Result<(), DescriptorError> {
    let lower = xpub.to_ascii_lowercase();
    if lower.starts_with("xprv") || lower.starts_with("tprv") {
        return Err(DescriptorError::PrivateKeyForbidden);
    }
    if xpub.contains('<') || xpub.contains(';') {
        return Err(DescriptorError::MultipathForbidden);
    }
    // Public prefixes: xpub (mainnet), tpub (test networks), and rare vpub/upub
    // SLIP-132 variants — we only accept standard BIP-32 base58 xpub/tpub here.
    if !(xpub.starts_with("xpub") || xpub.starts_with("tpub")) {
        return Err(DescriptorError::InvalidKeyExpression(format!(
            "expected xpub or tpub, got prefix from {xpub}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_path() {
        assert_eq!(bip48_origin_path(Network::Bitcoin), "48'/0'/0'/2'");
    }

    #[test]
    fn test_network_paths() {
        for n in [Network::Testnet, Network::Signet, Network::Regtest] {
            assert_eq!(bip48_origin_path(n), "48'/1'/0'/2'");
            validate_bip48_origin(&bip48_origin_path(n), n).unwrap();
            // `h` form accepted
            validate_bip48_origin("48h/1h/0h/2h", n).unwrap();
        }
    }

    #[test]
    fn rejects_wrong_coin_type() {
        assert!(matches!(
            validate_bip48_origin("48'/1'/0'/2'", Network::Bitcoin),
            Err(DescriptorError::InvalidOriginPath(_))
        ));
    }

    #[test]
    fn rejects_private_and_multipath() {
        assert_eq!(
            validate_public_xpub("xprv123"),
            Err(DescriptorError::PrivateKeyForbidden)
        );
        assert_eq!(
            validate_public_xpub("tprv123"),
            Err(DescriptorError::PrivateKeyForbidden)
        );
        assert_eq!(
            validate_public_xpub("xpubA/<0;1>/*"),
            Err(DescriptorError::MultipathForbidden)
        );
        assert_eq!(
            validate_public_xpub("xpubA;evil"),
            Err(DescriptorError::MultipathForbidden)
        );
    }

    #[test]
    fn origin_and_xpub_edge_errors() {
        // Each multipath marker arm of the origin guard.
        assert_eq!(
            validate_bip48_origin("48'/1'/<0;1>", Network::Regtest),
            Err(DescriptorError::MultipathForbidden)
        );
        assert_eq!(
            validate_bip48_origin("48'/1';only", Network::Regtest),
            Err(DescriptorError::MultipathForbidden)
        );
        assert_eq!(
            validate_bip48_origin("48'/1'/*", Network::Regtest),
            Err(DescriptorError::MultipathForbidden)
        );
        assert!(matches!(
            validate_bip48_origin("not-a-path", Network::Regtest),
            Err(DescriptorError::InvalidOriginPath(_))
        ));
        validate_bip48_origin("m/48'/1'/0'/2'", Network::Regtest).unwrap();
        assert!(validate_bip48_origin("m/48h/1h/0h/2h", Network::Bitcoin).is_err());

        // Prefix arms: tpub accepted, xpub accepted, neither → error.
        assert!(validate_public_xpub(
            "tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3"
        )
        .is_ok());
        assert!(validate_public_xpub(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        )
        .is_ok());
        assert!(matches!(
            validate_public_xpub("vpub1234"),
            Err(DescriptorError::InvalidKeyExpression(_))
        ));
        assert!(matches!(
            validate_public_xpub("upub1234"),
            Err(DescriptorError::InvalidKeyExpression(_))
        ));
        assert!(matches!(
            validate_public_xpub("notanextendedkey"),
            Err(DescriptorError::InvalidKeyExpression(_))
        ));
        assert!(matches!(
            validate_public_xpub(""),
            Err(DescriptorError::InvalidKeyExpression(_))
        ));
    }
}
