//! Positive parses — real 2-of-3 `wsh(sortedmulti(2,…))` descriptor strings.
//!
//! Fixture strings reuse the WP-11 test key material (tpubs / fingerprints)
//! as data only — no code dependency on `trinity-watch`.

use trinity_types::Fingerprint;
use trinity_verify::{parse, parse_trinity_descriptor, DerivationBranch, ParseError};

/// WP-11 / p9_grammar receive fixture (regtest coin type 1) with BIP-380 checksum.
const RECEIVE_REGTEST: &str = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*\
))#ttrgvxfp";

/// Same keys, change chain `/1/*`.
const CHANGE_REGTEST: &str = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/1/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/1/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/1/*\
))#w7gjjqef";

/// Mainnet coin type 0, three account xpubs at `m/48'/0'/0'/2'`.
const RECEIVE_MAINNET: &str = "wsh(sortedmulti(2,\
[4ba43603/48'/0'/0'/2']xpub6DknhdAsmeDQc7uaCcTBvPM5HJ2sN2gaBmNiJJtpczK3hMQWdKeodaBUSgi9qJrMKqPLqPuNFa7egPzCn8oJ7uU1zzhgAeHvzgYpxqchsQS/0/*,\
[8dfc9b34/48'/0'/0'/2']xpub6FAQRNJPfe8DZextv3BwkyE9GovxWr6NPx5DFosrY4WDdAeu96gcry37PJrV9agkn2pRsLieS487vaom77nSinfuerwfz926ZaNwkjUbhdt/0/*,\
[56c4fac3/48'/0'/0'/2']xpub6Ewx2N9hNSArJyF35CUGhaZLuZxQPNmJzWVwmpoV9U7Xu5wqka93nd3zEzokew9MzkNV4u6TCVDkHHR6QHQuYEFaasKzWkrkncXHMXGNdZP/0/*\
))#pm2ejlkz";

const CHANGE_MAINNET: &str = "wsh(sortedmulti(2,\
[4ba43603/48'/0'/0'/2']xpub6DknhdAsmeDQc7uaCcTBvPM5HJ2sN2gaBmNiJJtpczK3hMQWdKeodaBUSgi9qJrMKqPLqPuNFa7egPzCn8oJ7uU1zzhgAeHvzgYpxqchsQS/1/*,\
[8dfc9b34/48'/0'/0'/2']xpub6FAQRNJPfe8DZextv3BwkyE9GovxWr6NPx5DFosrY4WDdAeu96gcry37PJrV9agkn2pRsLieS487vaom77nSinfuerwfz926ZaNwkjUbhdt/1/*,\
[56c4fac3/48'/0'/0'/2']xpub6Ewx2N9hNSArJyF35CUGhaZLuZxQPNmJzWVwmpoV9U7Xu5wqka93nd3zEzokew9MzkNV4u6TCVDkHHR6QHQuYEFaasKzWkrkncXHMXGNdZP/1/*\
))#ywprvex2";

/// Hardened marker `h` form on first origin (still valid BIP-48).
const H_FORM: &str = "wsh(sortedmulti(2,\
[73756c7f/48h/1h/0h/2h]tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*\
))#mr6k8fyh";

#[test]
fn parses_regtest_receive() {
    let d = parse(RECEIVE_REGTEST).expect("receive regtest");
    assert_eq!(d.k, 2);
    assert_eq!(d.keys.len(), 3);
    assert_eq!(
        d.keys[0].fingerprint,
        Fingerprint::from_hex("73756c7f").unwrap()
    );
    assert_eq!(d.keys[0].origin_path, "48'/1'/0'/2'");
    assert!(d.keys[0].xpub.starts_with("tpub"));
    assert_eq!(d.keys[0].derivation, DerivationBranch::External);
    assert_eq!(d.uniform_derivation(), Some(DerivationBranch::External));
}

#[test]
fn parses_regtest_change() {
    let d = parse(CHANGE_REGTEST).expect("change regtest");
    assert_eq!(d.uniform_derivation(), Some(DerivationBranch::Internal));
    for k in &d.keys {
        assert_eq!(k.derivation, DerivationBranch::Internal);
    }
}

#[test]
fn parses_mainnet_receive_and_change() {
    let r = parse(RECEIVE_MAINNET).expect("mainnet receive");
    assert_eq!(r.keys[0].origin_path, "48'/0'/0'/2'");
    assert!(r.keys[0].xpub.starts_with("xpub"));
    assert_eq!(r.uniform_derivation(), Some(DerivationBranch::External));

    let c = parse(CHANGE_MAINNET).expect("mainnet change");
    assert_eq!(c.uniform_derivation(), Some(DerivationBranch::Internal));
}

#[test]
fn parses_h_hardened_origin() {
    let d = parse(H_FORM).expect("h-form");
    assert_eq!(d.keys[0].origin_path, "48h/1h/0h/2h");
    assert_eq!(d.keys[1].origin_path, "48'/1'/0'/2'");
}

#[test]
fn parse_trinity_descriptor_alias() {
    let a = parse(RECEIVE_REGTEST).unwrap();
    let b = parse_trinity_descriptor(RECEIVE_REGTEST).unwrap();
    assert_eq!(a, b);
}

#[test]
fn error_display_is_nonempty() {
    // Touch Display arms for a representative set (coverage of thiserror msgs).
    let samples = [
        ParseError::MissingChecksum,
        ParseError::MalformedChecksum,
        ParseError::InvalidChecksum,
        ParseError::InvalidCharset,
        ParseError::WrongTopLevel,
        ParseError::ExpectedSortedMulti,
        ParseError::WrongThreshold("3".into()),
        ParseError::WrongKeyCount(4),
        ParseError::MalformedFingerprint,
        ParseError::MalformedOriginPath("x".into()),
        ParseError::InvalidOriginPath("x".into()),
        ParseError::MultipathForbidden,
        ParseError::MalformedXpub,
        ParseError::PrivateKeyForbidden,
        ParseError::MalformedDerivation,
        ParseError::MalformedKeyExpression,
        ParseError::TrailingGarbage,
        ParseError::UnexpectedEof,
    ];
    for e in samples {
        assert!(!e.to_string().is_empty(), "{e:?}");
    }
}
