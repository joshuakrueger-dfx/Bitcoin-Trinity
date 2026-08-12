//! P9 — foreign grammar rejected with specific [`ParseError`] variants.
//!
//! Spec §5.2 P9 / IMPLEMENTATION_PLAN WP-20: random-valid Miniscript shapes
//! outside `wsh(sortedmulti(2,·,·,·))` must hard-fail. Checksums on negative
//! bodies are minted with the same BIP-380 algorithm (test helper), never via
//! miniscript.

use trinity_verify::{parse, ParseError};

/// BIP-380 `descsum_create` transcribed for test fixtures only.
fn with_checksum(body: &str) -> String {
    const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GENERATOR: [u64; 5] = [
        0xf5dee51989,
        0xa9fdca3312,
        0x1bab10e32d,
        0x3706b1677a,
        0x644d626ffd,
    ];
    fn polymod(symbols: &[u64]) -> u64 {
        let mut chk = 1u64;
        for &value in symbols {
            let top = chk >> 35;
            chk = ((chk & 0x7ffffffff) << 5) ^ value;
            for (i, g) in GENERATOR.iter().enumerate() {
                if ((top >> i) & 1) == 1 {
                    chk ^= g;
                }
            }
        }
        chk
    }
    fn expand(s: &str) -> Vec<u64> {
        let mut groups = Vec::new();
        let mut symbols = Vec::new();
        for c in s.chars() {
            let v = INPUT_CHARSET.find(c).expect("charset") as u64;
            symbols.push(v & 31);
            groups.push(v >> 5);
            if groups.len() == 3 {
                symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
                groups.clear();
            }
        }
        if groups.len() == 1 {
            symbols.push(groups[0]);
        } else if groups.len() == 2 {
            symbols.push(groups[0] * 3 + groups[1]);
        }
        symbols
    }
    let mut symbols = expand(body);
    symbols.extend(std::iter::repeat_n(0u64, 8));
    let checksum = polymod(&symbols) ^ 1;
    let mut out = String::from(body);
    out.push('#');
    for i in 0..8 {
        let idx = ((checksum >> (5 * (7 - i))) & 31) as usize;
        out.push(CHECKSUM_CHARSET[idx] as char);
    }
    out
}

const K1: &str = "[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*";
const K2: &str = "[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*";
const K3: &str = "[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*";

fn good_body() -> String {
    format!("wsh(sortedmulti(2,{K1},{K2},{K3}))")
}

#[test]
fn rejects_wpkh() {
    let body = "wpkh([73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)";
    assert_eq!(parse(&with_checksum(body)), Err(ParseError::WrongTopLevel));
}

#[test]
fn rejects_sh_wsh() {
    let body = format!("sh(wsh(sortedmulti(2,{K1},{K2},{K3})))");
    assert_eq!(parse(&with_checksum(&body)), Err(ParseError::WrongTopLevel));
}

#[test]
fn rejects_tr() {
    // Valid-looking tr() shape; rejected before any tr semantics.
    let body = "tr([73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)";
    assert_eq!(parse(&with_checksum(body)), Err(ParseError::WrongTopLevel));
}

#[test]
fn rejects_multi_not_sortedmulti() {
    let body = format!("wsh(multi(2,{K1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::ExpectedSortedMulti)
    );
}

#[test]
fn rejects_wrong_k() {
    let body = format!("wsh(sortedmulti(3,{K1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::WrongThreshold("3".into()))
    );
    let body = format!("wsh(sortedmulti(1,{K1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::WrongThreshold("1".into()))
    );
}

#[test]
fn rejects_wrong_key_count_two() {
    let body = format!("wsh(sortedmulti(2,{K1},{K2}))");
    // After two keys, `)` where a third key/` ,` is expected.
    let err = parse(&with_checksum(&body)).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::TrailingGarbage
                | ParseError::MalformedKeyExpression
                | ParseError::UnexpectedEof
        ),
        "got {err:?}"
    );
}

#[test]
fn rejects_wrong_key_count_four() {
    let body = format!("wsh(sortedmulti(2,{K1},{K2},{K3},{K1}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::WrongKeyCount(4))
    );
}

#[test]
fn rejects_missing_checksum() {
    assert_eq!(parse(&good_body()), Err(ParseError::MissingChecksum));
}

#[test]
fn rejects_multipath_derivation() {
    let k1 = K1.replace("/0/*", "/<0;1>/*");
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MultipathForbidden)
    );
}

#[test]
fn rejects_bad_fingerprint() {
    let k1 = K1.replacen("73756c7f", "73756c7", 1); // 7 hex chars
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MalformedFingerprint)
    );
}

#[test]
fn rejects_bad_origin_path() {
    let k1 = K1.replace("48'/1'/0'/2'", "48'/1'/0'/3'");
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert!(matches!(
        parse(&with_checksum(&body)),
        Err(ParseError::InvalidOriginPath(_))
    ));
}

#[test]
fn rejects_private_key() {
    // Valid-length-ish xprv prefix will fail PrivateKeyForbidden before base58.
    // Use a real xprv from BIP-32 test vectors so base58 would pass if we allowed it.
    let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    let k1 = format!("[73756c7f/48'/0'/0'/2']{xprv}/0/*");
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    // Checksum may fail charset if any — xprv uses same charset. Parse rejects private.
    let err = parse(&with_checksum(&body)).unwrap_err();
    assert_eq!(err, ParseError::PrivateKeyForbidden);
}

#[test]
fn rejects_malformed_derivation() {
    let k1 = K1.replace("/0/*", "/0/1");
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MalformedDerivation)
    );
}

#[test]
fn rejects_malformed_xpub() {
    let k1 = "[73756c7f/48'/1'/0'/2']tpubINVALIDKEYMATERIAL0000000000000000000000000000000000000000000000000000000000000000000000/0/*";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(parse(&with_checksum(&body)), Err(ParseError::MalformedXpub));
}

#[test]
fn rejects_trailing_garbage_after_body() {
    let body = format!("wsh(sortedmulti(2,{K1},{K2},{K3}))extra");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::TrailingGarbage)
    );
}

#[test]
fn rejects_pkh_and_combo() {
    let pkh = "pkh([73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)";
    assert_eq!(parse(&with_checksum(pkh)), Err(ParseError::WrongTopLevel));
    let combo = "combo([73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)";
    assert_eq!(parse(&with_checksum(combo)), Err(ParseError::WrongTopLevel));
}

#[test]
fn rejects_wsh_sortedmulti_without_closing() {
    // Checksummed truncated body — grammar fails after V1.
    let body = format!("wsh(sortedmulti(2,{K1},{K2},{K3}");
    let err = parse(&with_checksum(&body)).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::UnexpectedEof | ParseError::TrailingGarbage | ParseError::WrongKeyCount(_)
        ),
        "got {err:?}"
    );
}

#[test]
fn rejects_empty_origin_path() {
    let k1 = "[73756c7f/]tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert!(matches!(
        parse(&with_checksum(&body)),
        Err(ParseError::MalformedOriginPath(_))
    ));
}

#[test]
fn rejects_non_xpub_prefix() {
    // ypub is not accepted (only xpub/tpub).
    let k1 = "[73756c7f/48'/1'/0'/2']ypubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(parse(&with_checksum(&body)), Err(ParseError::MalformedXpub));
}

#[test]
fn rejects_multipath_markers_inside_xpub_field() {
    let k1 = "[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3<evil/0/*";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MultipathForbidden)
    );
}

#[test]
fn rejects_empty_xpub_before_derivation() {
    let k1 = "[73756c7f/48'/1'/0'/2']/0/*";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(parse(&with_checksum(&body)), Err(ParseError::MalformedXpub));
}

#[test]
fn rejects_short_key_token() {
    let k1 = "[73756c7f/48'/1'/0'/2']ab";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MalformedKeyExpression)
    );
}

#[test]
fn rejects_missing_origin_bracket() {
    let k1 = "73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MalformedKeyExpression)
    );
}

#[test]
fn rejects_missing_slash_after_fingerprint() {
    // Exactly 8 hex chars then `]` — no `/origin`.
    let k1 = "[73756c7f]tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MalformedKeyExpression)
    );
}

#[test]
fn rejects_unclosed_origin_bracket() {
    // No `]` after a would-be origin — fail before xpub scan.
    let k1 = "[73756c7f/48'/1'/0'/2'tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MalformedKeyExpression)
    );
}

#[test]
fn rejects_non_hex_fingerprint() {
    let k1 = K1.replacen("73756c7f", "73756c7g", 1);
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MalformedFingerprint)
    );
}

#[test]
fn rejects_threshold_without_comma() {
    let body = "wsh(sortedmulti(2)";
    assert_eq!(parse(&with_checksum(body)), Err(ParseError::UnexpectedEof));
}

#[test]
fn rejects_five_keys() {
    let body = format!("wsh(sortedmulti(2,{K1},{K2},{K3},{K1},{K2}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::WrongKeyCount(5))
    );
}

#[test]
fn rejects_empty_fourth_key_slot() {
    // Exercises the take_while terminator branch on immediate `)`.
    let body = format!("wsh(sortedmulti(2,{K1},{K2},{K3},))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::WrongKeyCount(4))
    );
}

#[test]
fn rejects_tprv_prefix() {
    let tprv = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK";
    let k1 = format!("[73756c7f/48'/1'/0'/2']{tprv}/0/*");
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::PrivateKeyForbidden)
    );
}

#[test]
fn mixed_derivation_branches_parse_but_not_uniform() {
    // Grammar allows per-key branch; uniform_derivation reports None.
    // Case A: key0 != key1 (short-circuit on first compare).
    let k1 = K1; // /0/*
    let k2 = K2.replace("/0/*", "/1/*");
    let k3 = K3;
    let body = format!("wsh(sortedmulti(2,{k1},{k2},{k3}))");
    let d = parse(&with_checksum(&body)).expect("mixed branches still parse");
    assert_eq!(d.uniform_derivation(), None);

    // Case B: key0 == key1 != key2 (second compare is the failing arm).
    let k2b = K2; // /0/* same as k1
    let k3b = K3.replace("/0/*", "/1/*");
    let body_b = format!("wsh(sortedmulti(2,{k1},{k2b},{k3b}))");
    let d_b = parse(&with_checksum(&body_b)).expect("mixed branches still parse");
    assert_eq!(d_b.uniform_derivation(), None);
}

#[test]
fn rejects_semicolon_and_star_in_xpub_field() {
    let k_semi = "[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3;evil/0/*";
    let body = format!("wsh(sortedmulti(2,{k_semi},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MultipathForbidden)
    );
    let k_star = "[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3*evil/0/*";
    let body = format!("wsh(sortedmulti(2,{k_star},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MultipathForbidden)
    );
}

#[test]
fn rejects_semicolon_only_in_derivation_token() {
    // Does not end with /0/* or /1/*; contains `;` multipath marker.
    let k1 = K1.replace("/0/*", "/0;1/*");
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    assert_eq!(
        parse(&with_checksum(&body)),
        Err(ParseError::MultipathForbidden)
    );
}

#[test]
fn rejects_semicolon_only_in_origin_path() {
    assert_eq!(
        parse(&with_checksum(&{
            let k1 = K1.replace("48'/1'/0'/2'", "48';1'/0'/2'");
            format!("wsh(sortedmulti(2,{k1},{K2},{K3}))")
        })),
        Err(ParseError::MultipathForbidden)
    );
}

#[test]
fn rejects_missing_closing_bracket_on_origin() {
    let k1 = "[73756c7f/48'/1'/0'/2'tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*";
    let body = format!("wsh(sortedmulti(2,{k1},{K2},{K3}))");
    let err = parse(&with_checksum(&body)).unwrap_err();
    // Without `]`, the origin scanner swallows the rest (including `*`) and
    // fail-closes on multipath / path / key shape — any hard error is fine.
    assert!(
        matches!(
            err,
            ParseError::MalformedKeyExpression
                | ParseError::MalformedOriginPath(_)
                | ParseError::InvalidOriginPath(_)
                | ParseError::MalformedDerivation
                | ParseError::MalformedXpub
                | ParseError::MultipathForbidden
        ),
        "got {err:?}"
    );
}
