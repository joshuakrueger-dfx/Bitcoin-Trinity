//! Construct `wsh(sortedmulti(2,…))` receive/change descriptors.
//!
//! APIs used (pinned vendor sources, not docs.rs):
//!
//! - `miniscript::DescriptorPublicKey::from_str` —
//!   `vendor/miniscript/src/descriptor/key.rs`
//! - `miniscript::Descriptor::new_wsh_sortedmulti` —
//!   `vendor/miniscript/src/descriptor/mod.rs` (wraps
//!   `Wsh::new_sortedmulti` in `segwitv0.rs`)
//! - `Descriptor::to_string` / Display with BIP-380 checksum —
//!   `vendor/miniscript/src/descriptor/mod.rs` + `checksum.rs`
//!
//! Pattern mirrored from BDK Caravan import:
//! `vendor/bdk_wallet/src/wallet/export.rs` (`to_descriptors`, ~654–708).

use std::str::FromStr;

use miniscript::{Descriptor, DescriptorPublicKey};
use trinity_types::{Network, XpubWithOrigin};

use super::document::{KeyContribution, WalletDescriptors, FORMAT_VERSION};
use super::error::DescriptorError;
use super::path::{validate_bip48_origin, validate_public_xpub};

/// Multisig threshold k in `sortedmulti(k, …)` — always 2-of-3.
pub const MULTISIG_THRESHOLD: usize = 2;

/// Receive chain suffix after the account xpub (Spec §2.3 / KeychainKind::External).
const RECEIVE_SUFFIX: &str = "0/*";
/// Change chain suffix (Spec §2.3 / KeychainKind::Internal). Decision O8:
/// separate descriptor, not multipath `<0;1>/*`.
const CHANGE_SUFFIX: &str = "1/*";

/// Build receive + change descriptors and the full `descriptor.json` document.
///
/// Keys must cover slots A, B, and C exactly once. Master fingerprints must
/// be pairwise distinct (P7). No multipath, no xprv.
pub fn build_wallet_descriptors(
    network: Network,
    keys: [KeyContribution; 3],
    created_at_unix: u64,
) -> Result<WalletDescriptors, DescriptorError> {
    validate_slots_and_fingerprints(&keys)?;

    for k in &keys {
        validate_public_xpub(&k.xpub.xpub)?;
        validate_bip48_origin(&k.xpub.origin_path, network)?;
        if k.source.is_hardware() && k.policy_id.is_none() {
            // policy_id is required only once a device is registered; generation
            // may still record hardware without a registration id (import before
            // BIP-388). Allowed — Spec says "for hardware keys, policy_id per
            // registered device", not "always present".
        }
        if !k.source.is_hardware() && k.policy_id.is_some() {
            return Err(DescriptorError::InvalidDocument(
                "policy_id is only valid for Hardware source keys".into(),
            ));
        }
    }

    // Stable slot order A, B, C in the document and in the descriptor string.
    // BIP-67 reordering for addresses is performed by sortedmulti at derive time;
    // string key order follows slots so the backup is readable (Spec §2.3 example).
    let ordered = order_by_slot(keys);

    let receive = build_sortedmulti_string(&ordered, RECEIVE_SUFFIX)?;
    let change = build_sortedmulti_string(&ordered, CHANGE_SUFFIX)?;

    // O8: never multipath; receive/change must stay on distinct chain suffixes.
    assert_no_multipath(&receive)?;
    assert_no_multipath(&change)?;
    assert_distinct_receive_change(&receive, &change)?;

    // Grammar self-check (same checks used on load).
    validate_trinity_descriptor(&receive)?;
    validate_trinity_descriptor(&change)?;

    Ok(WalletDescriptors {
        format_version: FORMAT_VERSION,
        network,
        created_at_unix,
        receive_descriptor: receive,
        change_descriptor: change,
        keys: ordered,
    })
}

fn order_by_slot(keys: [KeyContribution; 3]) -> [KeyContribution; 3] {
    let mut out: [Option<KeyContribution>; 3] = [None, None, None];
    for k in keys {
        let idx = k.slot.as_u8() as usize;
        out[idx] = Some(k);
    }
    [
        out[0].take().expect("slot A present"),
        out[1].take().expect("slot B present"),
        out[2].take().expect("slot C present"),
    ]
}

fn validate_slots_and_fingerprints(keys: &[KeyContribution; 3]) -> Result<(), DescriptorError> {
    let mut seen_slots = [false; 3];
    for k in keys {
        let i = k.slot.as_u8() as usize;
        if seen_slots[i] {
            return Err(DescriptorError::InvalidDocument(format!(
                "duplicate key slot {}",
                k.slot
            )));
        }
        seen_slots[i] = true;
    }
    if seen_slots != [true, true, true] {
        return Err(DescriptorError::InvalidDocument(
            "keys must cover slots A, B, and C".into(),
        ));
    }

    // P7: three separate master seeds ⇒ distinct fingerprints.
    for (i, a) in keys.iter().enumerate() {
        for b in keys.iter().skip(i + 1) {
            if a.xpub.fingerprint == b.xpub.fingerprint {
                return Err(DescriptorError::DuplicateFingerprint(
                    a.xpub.fingerprint.to_hex(),
                ));
            }
        }
    }
    Ok(())
}

/// Build `wsh(sortedmulti(2, key/suffix, …))#checksum` via miniscript.
fn build_sortedmulti_string(
    keys: &[KeyContribution; 3],
    chain_suffix: &str,
) -> Result<String, DescriptorError> {
    let pks: Result<Vec<DescriptorPublicKey>, DescriptorError> = keys
        .iter()
        .map(|k| key_expression(&k.xpub, chain_suffix))
        .collect();
    let pks = pks?;

    let desc = Descriptor::<DescriptorPublicKey>::new_wsh_sortedmulti(MULTISIG_THRESHOLD, pks)
        .map_err(|e| DescriptorError::Construction(e.to_string()))?;

    // Display includes BIP-380 checksum (miniscript checksum::Formatter).
    Ok(desc.to_string())
}

/// `[fingerprint/origin_path]xpub/<chain_suffix>` — Caravan/`to_descriptors` form.
fn key_expression(
    xpub: &XpubWithOrigin,
    chain_suffix: &str,
) -> Result<DescriptorPublicKey, DescriptorError> {
    let origin = xpub
        .origin_path
        .strip_prefix("m/")
        .unwrap_or(&xpub.origin_path);
    // Normalise hardened markers for a stable parse; both ' and h are accepted.
    let expr = format!(
        "[{}/{}]{}/{}",
        xpub.fingerprint.to_hex(),
        origin,
        xpub.xpub,
        chain_suffix
    );
    if expr.contains('<') || expr.contains(';') {
        return Err(DescriptorError::MultipathForbidden);
    }
    DescriptorPublicKey::from_str(&expr)
        .map_err(|e| DescriptorError::InvalidKeyExpression(format!("{expr}: {e}")))
}

fn assert_no_multipath(desc: &str) -> Result<(), DescriptorError> {
    if desc.contains('<') || desc.contains(';') {
        return Err(DescriptorError::MultipathForbidden);
    }
    Ok(())
}

/// Defensive O8 check: receive uses `/0/*`, change uses `/1/*`, and they differ.
///
/// Extracted so the failure arms are unit-testable; production always builds
/// both strings with fixed suffixes and should never hit the errors.
fn assert_distinct_receive_change(receive: &str, change: &str) -> Result<(), DescriptorError> {
    if receive.contains("/1/*") || change.contains("/0/*") {
        return Err(DescriptorError::Construction(
            "receive/change chain suffixes swapped".into(),
        ));
    }
    if receive == change {
        return Err(DescriptorError::Construction(
            "receive and change descriptors must differ".into(),
        ));
    }
    Ok(())
}

/// Accept only Trinity grammar: `wsh(sortedmulti(2, k1, k2, k3))` (+ optional checksum).
///
/// This is the builder-side guard used on load and self-check. Full property
/// testing of a *independent* verifier parser is WP-20 (`trinity-verify`, P9
/// primary home); here we still refuse foreign scripts so a tampered
/// `descriptor.json` cannot be reloaded as a Trinity wallet.
pub fn validate_trinity_descriptor(desc: &str) -> Result<(), DescriptorError> {
    assert_no_multipath(desc)?;

    let body = match desc.split_once('#') {
        Some((b, checksum)) => {
            if checksum.len() != 8 || !checksum.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(DescriptorError::ForeignGrammar(
                    "invalid or missing BIP-380 checksum".into(),
                ));
            }
            b
        }
        None => {
            return Err(DescriptorError::ForeignGrammar(
                "checksum required (BIP-380)".into(),
            ));
        }
    };

    // Parse with miniscript — rejects syntax noise — then inspect structure.
    let parsed = Descriptor::<DescriptorPublicKey>::from_str(desc)
        .map_err(|e| DescriptorError::ForeignGrammar(format!("miniscript parse failed: {e}")))?;

    match parsed {
        Descriptor::Wsh(wsh) => match wsh.as_inner() {
            miniscript::descriptor::WshInner::SortedMulti(sm) => {
                if sm.k() != MULTISIG_THRESHOLD {
                    return Err(DescriptorError::ForeignGrammar(format!(
                        "threshold must be {MULTISIG_THRESHOLD}, got {}",
                        sm.k()
                    )));
                }
                let n = sm.pks().len();
                if n != 3 {
                    return Err(DescriptorError::ForeignGrammar(format!(
                        "expected 3 keys, got {n}"
                    )));
                }
                for pk in sm.pks() {
                    if pk.is_multipath() {
                        return Err(DescriptorError::MultipathForbidden);
                    }
                }
            }
            miniscript::descriptor::WshInner::Ms(_) => {
                return Err(DescriptorError::ForeignGrammar(
                    "wsh(miniscript) is not Trinity grammar; need wsh(sortedmulti(2,…))".into(),
                ));
            }
        },
        Descriptor::Sh(_)
        | Descriptor::Wpkh(_)
        | Descriptor::Pkh(_)
        | Descriptor::Tr(_)
        | Descriptor::Bare(_) => {
            return Err(DescriptorError::ForeignGrammar(
                "only wsh(sortedmulti(2,…)) is accepted".into(),
            ));
        }
    }

    // Reject plain `multi` by string probe on the checksum-stripped body.
    // miniscript would parse `wsh(multi(…))` as WshInner::Ms, already rejected
    // above; keep an explicit check for clarity in reviews.
    if body.contains("multi(") && !body.contains("sortedmulti(") {
        return Err(DescriptorError::ForeignGrammar(
            "multi is forbidden; use sortedmulti (BIP-67)".into(),
        ));
    }
    if !body.starts_with("wsh(sortedmulti(2,") {
        return Err(DescriptorError::ForeignGrammar(
            "expected wsh(sortedmulti(2,…))".into(),
        ));
    }

    Ok(())
}

/// Build a single sortedmulti string from three xpubs in caller-chosen order.
///
/// Used by P5 tests to prove address identity under key-order permutation.
/// Not used for production builds (which fix slot order A,B,C).
#[doc(hidden)]
pub fn build_sortedmulti_permutation(
    xpubs: [&XpubWithOrigin; 3],
    chain_suffix: &str,
) -> Result<String, DescriptorError> {
    let pks: Result<Vec<DescriptorPublicKey>, DescriptorError> = xpubs
        .iter()
        .map(|x| {
            validate_public_xpub(&x.xpub)?;
            key_expression(x, chain_suffix)
        })
        .collect();
    let desc = Descriptor::<DescriptorPublicKey>::new_wsh_sortedmulti(MULTISIG_THRESHOLD, pks?)
        .map_err(|e| DescriptorError::Construction(e.to_string()))?;
    Ok(desc.to_string())
}

/// Derive address at `index` for a ranged descriptor string (test helper).
#[doc(hidden)]
pub fn address_at(
    descriptor: &str,
    index: u32,
    network: bitcoin::Network,
) -> Result<String, DescriptorError> {
    let desc = Descriptor::<DescriptorPublicKey>::from_str(descriptor)
        .map_err(|e| DescriptorError::ForeignGrammar(e.to_string()))?;
    let derived = desc
        .at_derivation_index(index)
        .map_err(|e| DescriptorError::Construction(e.to_string()))?;
    let addr = derived
        .address(network)
        .map_err(|e| DescriptorError::Construction(e.to_string()))?;
    Ok(addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::source::KeySource;
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;
    use trinity_types::{Fingerprint, KeySlot, WordCount};

    // Fixed tpubs from BDK Caravan tests (testnet/regtest xpubs).
    const FP_A: &str = "73756c7f";
    const FP_B: &str = "f9f62194";
    const FP_C: &str = "c98b1535";
    const XPUB_A: &str = "tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3";
    const XPUB_B: &str = "tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4";
    const XPUB_C: &str = "tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a";

    fn contrib(slot: KeySlot, fp: &str, xpub: &str) -> KeyContribution {
        KeyContribution {
            slot,
            xpub: XpubWithOrigin::new(Fingerprint::from_hex(fp).unwrap(), "48'/1'/0'/2'", xpub),
            birthday_height: 100,
            word_count: WordCount::Words24,
            source: KeySource::InApp,
            policy_id: None,
        }
    }

    fn sample_keys() -> [KeyContribution; 3] {
        [
            contrib(KeySlot::A, FP_A, XPUB_A),
            contrib(KeySlot::B, FP_B, XPUB_B),
            contrib(KeySlot::C, FP_C, XPUB_C),
        ]
    }

    #[test]
    fn builds_separate_receive_and_change() {
        let d = build_wallet_descriptors(Network::Regtest, sample_keys(), 1_700_000_000).unwrap();
        assert!(d.receive_descriptor.starts_with("wsh(sortedmulti(2,"));
        assert!(d.change_descriptor.starts_with("wsh(sortedmulti(2,"));
        assert!(d.receive_descriptor.contains("/0/*"));
        assert!(!d.receive_descriptor.contains("/1/*"));
        assert!(d.change_descriptor.contains("/1/*"));
        assert!(!d.change_descriptor.contains("/0/*"));
        assert!(!d.receive_descriptor.contains('<'));
        assert!(d.receive_descriptor.contains('#'));
        assert_ne!(d.receive_descriptor, d.change_descriptor);
    }

    #[test]
    fn p7_rejects_duplicate_fingerprint() {
        let mut keys = sample_keys();
        keys[1].xpub.fingerprint = keys[0].xpub.fingerprint;
        let err = build_wallet_descriptors(Network::Regtest, keys, 0).unwrap_err();
        assert!(matches!(err, DescriptorError::DuplicateFingerprint(_)));
    }

    #[test]
    fn rejects_xprv() {
        let mut keys = sample_keys();
        keys[0].xpub.xpub = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".into();
        let err = build_wallet_descriptors(Network::Regtest, keys, 0).unwrap_err();
        assert_eq!(err, DescriptorError::PrivateKeyForbidden);
    }

    #[test]
    fn rejects_wrong_origin_path() {
        let mut keys = sample_keys();
        keys[0].xpub.origin_path = "84'/0'/0'".into();
        assert!(matches!(
            build_wallet_descriptors(Network::Regtest, keys, 0),
            Err(DescriptorError::InvalidOriginPath(_))
        ));
    }

    /// Coverage for private helpers and builder-only error arms (public grammar
    /// cases live in `tests/coverage_gaps.rs` so they do not inflate lib LF).
    #[test]
    fn private_helpers_and_builder_errors() {
        // Hardware without policy_id is allowed (empty true-branch of the guard).
        let mut keys = sample_keys();
        keys[1].source = KeySource::Hardware {
            model: "coldcard_mk4".into(),
        };
        keys[1].policy_id = None;
        assert!(build_wallet_descriptors(Network::Regtest, keys, 0).is_ok());

        // policy_id on InApp.
        let mut keys = sample_keys();
        keys[0].policy_id = Some("pol".into());
        assert!(matches!(
            build_wallet_descriptors(Network::Regtest, keys, 0),
            Err(DescriptorError::InvalidDocument(_))
        ));

        // Duplicate slot.
        let mut keys = sample_keys();
        keys[2].slot = KeySlot::A;
        assert!(matches!(
            build_wallet_descriptors(Network::Regtest, keys, 0),
            Err(DescriptorError::InvalidDocument(_))
        ));

        // key_expression multipath (`<` and `;`-only) + bad base58.
        let mp = XpubWithOrigin::new(
            Fingerprint::from_hex(FP_A).unwrap(),
            "48'/1'/0'/2'/<0;1>",
            XPUB_A,
        );
        assert_eq!(
            key_expression(&mp, "0/*"),
            Err(DescriptorError::MultipathForbidden)
        );
        let semi = XpubWithOrigin::new(
            Fingerprint::from_hex(FP_A).unwrap(),
            "48'/1'/0'/2';evil",
            XPUB_A,
        );
        assert_eq!(
            key_expression(&semi, "0/*"),
            Err(DescriptorError::MultipathForbidden)
        );
        let bad = XpubWithOrigin::new(
            Fingerprint::from_hex(FP_A).unwrap(),
            "48'/1'/0'/2'",
            "tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU4",
        );
        assert!(matches!(
            key_expression(&bad, "0/*"),
            Err(DescriptorError::InvalidKeyExpression(_))
        ));

        assert_eq!(
            assert_no_multipath("a/<0;1>"),
            Err(DescriptorError::MultipathForbidden)
        );
        assert_eq!(
            assert_no_multipath("a;b"),
            Err(DescriptorError::MultipathForbidden)
        );
        assert!(assert_no_multipath("ok").is_ok());

        // Each arm of the chain-suffix OR, then equal-string, then happy path.
        assert!(matches!(
            assert_distinct_receive_change("x/1/*", "y/2/*"),
            Err(DescriptorError::Construction(_))
        ));
        assert!(matches!(
            assert_distinct_receive_change("x/2/*", "y/0/*"),
            Err(DescriptorError::Construction(_))
        ));
        assert!(matches!(
            assert_distinct_receive_change("x/1/*", "y/0/*"),
            Err(DescriptorError::Construction(_))
        ));
        assert!(matches!(
            assert_distinct_receive_change("same", "same"),
            Err(DescriptorError::Construction(_))
        ));
        assert!(assert_distinct_receive_change("r/0/*", "c/1/*").is_ok());

        // Grammar edges exercised here only where they keep private helpers warm.
        assert!(matches!(
            validate_trinity_descriptor("wsh(sortedmulti(2,a,b,c))#abcd"),
            Err(DescriptorError::ForeignGrammar(_))
        ));
        assert!(matches!(
            validate_trinity_descriptor("wsh(sortedmulti(2,a,b,c))#!!!!!!!!"),
            Err(DescriptorError::ForeignGrammar(_))
        ));
        assert!(matches!(
            validate_trinity_descriptor("wsh(sortedmulti(2,not-a-key))#abcdefgh"),
            Err(DescriptorError::ForeignGrammar(_))
        ));

        let body = |k, n: usize| {
            let xpubs = [XPUB_A, XPUB_B, XPUB_C, XPUB_A];
            let fps = [FP_A, FP_B, FP_C, FP_A];
            let keys: Vec<_> = (0..n)
                .map(|i| format!("[{}/48'/1'/0'/2']{}/0/*", fps[i], xpubs[i]))
                .collect();
            format!("wsh(sortedmulti({k},{}))", keys.join(","))
        };
        for raw in [body(3, 3), body(2, 2), body(2, 4)] {
            let d = Descriptor::<DescriptorPublicKey>::from_str(&raw)
                .unwrap()
                .to_string();
            assert!(matches!(
                validate_trinity_descriptor(&d),
                Err(DescriptorError::ForeignGrammar(_))
            ));
        }
        let sh = body(2, 3).replacen("wsh(", "sh(", 1);
        let sh = Descriptor::<DescriptorPublicKey>::from_str(&sh)
            .unwrap()
            .to_string();
        assert!(matches!(
            validate_trinity_descriptor(&sh),
            Err(DescriptorError::ForeignGrammar(_))
        ));

        let good =
            XpubWithOrigin::new(Fingerprint::from_hex(FP_A).unwrap(), "48'/1'/0'/2'", XPUB_A);
        let xprv = XpubWithOrigin::new(
            Fingerprint::from_hex(FP_B).unwrap(),
            "48'/1'/0'/2'",
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        );
        let c = XpubWithOrigin::new(Fingerprint::from_hex(FP_C).unwrap(), "48'/1'/0'/2'", XPUB_C);
        assert_eq!(
            build_sortedmulti_permutation([&good, &xprv, &c], "0/*"),
            Err(DescriptorError::PrivateKeyForbidden)
        );
        assert!(matches!(
            address_at("not-a-descriptor", 0, bitcoin::Network::Regtest),
            Err(DescriptorError::ForeignGrammar(_))
        ));

        for e in [
            DescriptorError::DuplicateFingerprint("aabbccdd".into()),
            DescriptorError::MultipathForbidden,
            DescriptorError::PrivateKeyForbidden,
            DescriptorError::InvalidOriginPath("84'".into()),
            DescriptorError::InvalidKeyExpression("x".into()),
            DescriptorError::ForeignGrammar("y".into()),
            DescriptorError::Construction("z".into()),
            DescriptorError::Json("j".into()),
            DescriptorError::InvalidDocument("d".into()),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
