//! P9 — foreign grammar rejected on load / validation (builder-side guard).
//!
//! Spec §5.2 P9 is defined for the **verifier** (`trinity-verify`, WP-20): an
//! independent parser must reject anything outside `wsh(sortedmulti(2,·,·,·))`.
//! This crate still validates descriptors when loading `descriptor.json` and
//! after generation, so a tampered file cannot be reloaded. Full negative
//! property testing over random miniscript stays with WP-20.

use trinity_watch::descriptor::build::validate_trinity_descriptor;
use trinity_watch::descriptor::DescriptorError;

#[test]
fn p9_accepts_valid_sortedmulti() {
    // Built offline with miniscript; checksum verified by from_str.
    let desc = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*\
))";
    // Parse via builder path that attaches checksum first.
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;
    let with_cs = Descriptor::<DescriptorPublicKey>::from_str(desc)
        .unwrap()
        .to_string();
    validate_trinity_descriptor(&with_cs).expect("valid Trinity descriptor");
}

#[test]
fn p9_rejects_wpkh() {
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;
    let raw = "wpkh([73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)";
    let d = Descriptor::<DescriptorPublicKey>::from_str(raw)
        .unwrap()
        .to_string();
    assert!(matches!(
        validate_trinity_descriptor(&d),
        Err(DescriptorError::ForeignGrammar(_))
    ));
}

#[test]
fn p9_rejects_multi_not_sortedmulti() {
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;
    let raw = "wsh(multi(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*\
))";
    let d = Descriptor::<DescriptorPublicKey>::from_str(raw)
        .unwrap()
        .to_string();
    assert!(matches!(
        validate_trinity_descriptor(&d),
        Err(DescriptorError::ForeignGrammar(_))
    ));
}

#[test]
fn p9_rejects_multipath() {
    let raw = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/<0;1>/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/<0;1>/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/<0;1>/*\
))#aaaaaaaa";
    // May fail as MultipathForbidden before parse, or ForeignGrammar on checksum.
    let err = validate_trinity_descriptor(raw).unwrap_err();
    assert!(
        matches!(
            err,
            DescriptorError::MultipathForbidden | DescriptorError::ForeignGrammar(_)
        ),
        "got {err:?}"
    );
}

#[test]
fn p9_rejects_missing_checksum() {
    let raw = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*\
))";
    assert!(matches!(
        validate_trinity_descriptor(raw),
        Err(DescriptorError::ForeignGrammar(_))
    ));
}
