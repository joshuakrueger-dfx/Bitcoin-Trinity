//! Checksum mutation probes — prove V1 actually runs (not vacuously green).

use trinity_verify::{parse, ParseError};

const VALID: &str = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*\
))#ttrgvxfp";

#[test]
fn single_checksum_char_flip_rejected() {
    assert!(parse(VALID).is_ok());
    let bytes = VALID.as_bytes();
    let mut mutated = VALID.to_owned();
    // Last char of checksum is 'p'; flip within CHECKSUM_CHARSET to 'q'.
    let last = mutated.len() - 1;
    assert_eq!(bytes[last], b'p');
    mutated.replace_range(last..last + 1, "q");
    assert_ne!(mutated, VALID);
    assert_eq!(parse(&mutated), Err(ParseError::InvalidChecksum));
}

#[test]
fn payload_typo_with_original_checksum_rejected() {
    // Flip one char in the fingerprint; keep the original checksum.
    let mutated = VALID.replacen("73756c7f", "73756c7e", 1);
    assert_eq!(parse(&mutated), Err(ParseError::InvalidChecksum));
}

#[test]
fn missing_checksum_rejected() {
    let body = VALID.rsplit_once('#').unwrap().0;
    assert_eq!(parse(body), Err(ParseError::MissingChecksum));
}

#[test]
fn bip380_reference_vector() {
    // Direct vector from BIP-380 (not a Trinity descriptor — WrongTopLevel
    // after checksum). Proves checksum path accepts the published vector.
    use trinity_verify::parse;
    // raw(deadbeef)#89f8spxm — checksum OK, grammar not Trinity.
    assert_eq!(
        parse("raw(deadbeef)#89f8spxm"),
        Err(ParseError::WrongTopLevel)
    );
}
