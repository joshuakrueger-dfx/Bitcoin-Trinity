//! Grammar-only parser for Trinity `wsh(sortedmulti(2,·,·,·))` descriptors.
//!
//! Spec §1.5:
//! ```text
//! descriptor  := "wsh(" sortedmulti ")" "#" checksum
//! sortedmulti := "sortedmulti(" k "," keyexpr ("," keyexpr){2} ")"
//! keyexpr     := "[" fingerprint "/" origin_path "]" xpub "/" derivation
//! ```
//!
//! Exactly k = 2 and n = 3. No BIP-32 derivation, no BIP-67, no scripts.

use std::str::FromStr;

use bitcoin::bip32::Xpub;
use trinity_types::Fingerprint;

use crate::checksum;
use crate::error::ParseError;
use crate::types::{DerivationBranch, KeyExpr, ParsedDescriptor};

/// Parse a Trinity descriptor string.
///
/// Validates the BIP-380 checksum (V1) and the single accepted grammar.
/// Everything else is a hard [`ParseError`].
pub fn parse(descriptor: &str) -> Result<ParsedDescriptor, ParseError> {
    // V1 first: wrong/missing checksum never proceeds to grammar acceptance.
    checksum::verify_checksum(descriptor)?;

    let hash_pos = descriptor
        .rfind('#')
        .expect("verify_checksum requires trailing #checksum");
    let body = &descriptor[..hash_pos];

    let mut p = Cursor::new(body);

    if !p.starts_with("wsh(") {
        return Err(ParseError::WrongTopLevel);
    }
    p.advance("wsh(".len());

    if !p.starts_with("sortedmulti(") {
        return Err(ParseError::ExpectedSortedMulti);
    }
    p.advance("sortedmulti(".len());

    let k_token = p.take_until_char(',')?;
    if k_token != "2" {
        return Err(ParseError::WrongThreshold(k_token.to_owned()));
    }
    p.expect_char(',')?;

    let key0 = parse_keyexpr(&mut p)?;
    p.expect_char(',')?;
    let key1 = parse_keyexpr(&mut p)?;
    p.expect_char(',')?;
    let key2 = parse_keyexpr(&mut p)?;

    // Reject a fourth (or further) key expression before the closers.
    if p.starts_with(",") {
        let mut extra = 0usize;
        while p.starts_with(",") {
            p.advance(1);
            let _ = p.take_while(|c| c != ',' && c != ')');
            extra += 1;
        }
        return Err(ParseError::WrongKeyCount(3 + extra));
    }

    p.expect_char(')')?; // closes sortedmulti
    p.expect_char(')')?; // closes wsh

    if !p.is_empty() {
        return Err(ParseError::TrailingGarbage);
    }

    Ok(ParsedDescriptor {
        k: 2,
        keys: [key0, key1, key2],
    })
}

/// Spec alias used in §1.5 sketch (`parse_trinity_descriptor`).
#[inline]
pub fn parse_trinity_descriptor(descriptor: &str) -> Result<ParsedDescriptor, ParseError> {
    parse(descriptor)
}

fn parse_keyexpr(p: &mut Cursor<'_>) -> Result<KeyExpr, ParseError> {
    if p.expect_char('[').is_err() {
        return Err(ParseError::MalformedKeyExpression);
    }

    let fp_str = p.take_while(|c| c != '/' && c != ']')?;
    if fp_str.len() != 8 {
        return Err(ParseError::MalformedFingerprint);
    }
    let fingerprint = match Fingerprint::from_hex(fp_str) {
        Ok(fp) => fp,
        Err(_) => return Err(ParseError::MalformedFingerprint),
    };

    // Fingerprint must be followed by `/origin…]`.
    if !p.starts_with("/") {
        return Err(ParseError::MalformedKeyExpression);
    }
    p.advance(1);

    // Origin ends at `]`. Also stop at `,`/`)` so a missing `]` cannot swallow
    // subsequent key expressions.
    let origin_path = p.take_while(|c| c != ']' && c != ',' && c != ')')?;
    if !p.starts_with("]") {
        return Err(ParseError::MalformedKeyExpression);
    }
    if origin_path.is_empty() {
        return Err(ParseError::MalformedOriginPath("empty".into()));
    }
    validate_origin_path(origin_path)?;
    p.advance(1);

    // xpub runs until the derivation suffix `/0/*` or `/1/*`.
    let rest = p.rest();
    let (xpub, branch, consumed) = split_xpub_and_derivation(rest)?;
    p.advance(consumed);

    if xpub.starts_with("xprv") || xpub.starts_with("tprv") {
        return Err(ParseError::PrivateKeyForbidden);
    }
    if !(xpub.starts_with("xpub") || xpub.starts_with("tpub")) {
        return Err(ParseError::MalformedXpub);
    }
    for b in xpub.bytes() {
        if matches!(b, b'<' | b';' | b'*') {
            return Err(ParseError::MultipathForbidden);
        }
    }
    if Xpub::from_str(xpub).is_err() {
        return Err(ParseError::MalformedXpub);
    }

    Ok(KeyExpr {
        fingerprint,
        origin_path: origin_path.to_owned(),
        xpub: xpub.to_owned(),
        derivation: branch,
    })
}

/// Split `xpub/0/*` or `xpub/1/*` from the head of `rest`.
///
/// Returns `(xpub, branch, bytes_consumed)`.
fn split_xpub_and_derivation(rest: &str) -> Result<(&str, DerivationBranch, usize), ParseError> {
    let end = rest.find([',', ')']).unwrap_or(rest.len());
    let token = &rest[..end];
    if token.len() < 4 {
        return Err(ParseError::MalformedKeyExpression);
    }
    let branch = if token.ends_with("/0/*") {
        DerivationBranch::External
    } else if token.ends_with("/1/*") {
        DerivationBranch::Internal
    } else {
        for b in token.bytes() {
            if matches!(b, b'<' | b';') {
                return Err(ParseError::MultipathForbidden);
            }
        }
        return Err(ParseError::MalformedDerivation);
    };
    let xpub = &token[..token.len() - 4];
    if xpub.is_empty() {
        return Err(ParseError::MalformedXpub);
    }
    Ok((xpub, branch, token.len()))
}

/// Accept exactly BIP-48 `48'/coin'/0'/2'` with coin ∈ {0, 1}.
///
/// Both `'` and `h` hardened markers are accepted (BIP-380 / rust-bitcoin).
/// Optional leading `m/` is stripped. Pattern mirrors
/// `trinity-watch::descriptor::path::validate_bip48_origin` without importing
/// that crate.
fn validate_origin_path(path: &str) -> Result<(), ParseError> {
    for b in path.bytes() {
        if matches!(b, b'<' | b';' | b'*') {
            return Err(ParseError::MultipathForbidden);
        }
    }
    let trimmed = path.strip_prefix("m/").unwrap_or(path);
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.len() != 4 {
        // Too few segments → incomplete path syntax; too many → non-BIP-48.
        if segments.len() < 4 {
            return Err(ParseError::MalformedOriginPath(path.to_owned()));
        }
        return Err(ParseError::InvalidOriginPath(path.to_owned()));
    }

    let mut indices = [0u32; 4];
    for (i, part) in segments.iter().enumerate() {
        if part.is_empty() {
            return Err(ParseError::MalformedOriginPath(path.to_owned()));
        }
        let num_str = match part.as_bytes().last().copied() {
            Some(b'\'') | Some(b'h') => &part[..part.len() - 1],
            _ => return Err(ParseError::MalformedOriginPath(path.to_owned())),
        };
        if num_str.is_empty() {
            return Err(ParseError::MalformedOriginPath(path.to_owned()));
        }
        for c in num_str.bytes() {
            if !c.is_ascii_digit() {
                return Err(ParseError::MalformedOriginPath(path.to_owned()));
            }
        }
        if num_str.len() > 1 && num_str.as_bytes()[0] == b'0' {
            return Err(ParseError::MalformedOriginPath(path.to_owned()));
        }
        let n: u64 = match num_str.parse() {
            Ok(v) => v,
            Err(_) => return Err(ParseError::MalformedOriginPath(path.to_owned())),
        };
        if n >= 0x8000_0000 {
            return Err(ParseError::MalformedOriginPath(path.to_owned()));
        }
        indices[i] = n as u32;
    }

    // 48' / coin' / 0' / 2' with coin ∈ {0, 1}.
    let purpose_ok = indices[0] == 48;
    let account_ok = indices[2] == 0;
    let script_ok = indices[3] == 2;
    let coin_ok = indices[1] <= 1;
    if purpose_ok && account_ok && script_ok && coin_ok {
        Ok(())
    } else {
        Err(ParseError::InvalidOriginPath(path.to_owned()))
    }
}

/// Minimal cursor over a `&str` body (no `#checksum`).
struct Cursor<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(s: &'a str) -> Self {
        Self { s, pos: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.s.len()
    }

    fn starts_with(&self, lit: &str) -> bool {
        self.rest().starts_with(lit)
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn expect_char(&mut self, c: char) -> Result<(), ParseError> {
        let rest = self.rest();
        if rest.starts_with(c) {
            self.pos += c.len_utf8();
            Ok(())
        } else if rest.is_empty() {
            Err(ParseError::UnexpectedEof)
        } else {
            Err(ParseError::TrailingGarbage)
        }
    }

    fn take_until_char(&mut self, c: char) -> Result<&'a str, ParseError> {
        let rest = self.rest();
        match rest.find(c) {
            Some(i) => {
                let out = &rest[..i];
                self.pos += i;
                Ok(out)
            }
            None => Err(ParseError::UnexpectedEof),
        }
    }

    fn take_while(&mut self, mut pred: impl FnMut(char) -> bool) -> Result<&'a str, ParseError> {
        let rest = self.rest();
        let end = rest
            .char_indices()
            .find(|&(_, ch)| !pred(ch))
            .map(|(i, _)| i)
            .unwrap_or(rest.len());
        let out = &rest[..end];
        self.pos += end;
        Ok(out)
    }
}

#[cfg(test)]
mod origin_tests {
    use super::validate_origin_path;
    use crate::error::ParseError;

    #[test]
    fn accepts_mainnet_and_testnet_forms() {
        validate_origin_path("48'/0'/0'/2'").unwrap();
        validate_origin_path("48'/1'/0'/2'").unwrap();
        validate_origin_path("48h/0h/0h/2h").unwrap();
        validate_origin_path("48h/1h/0h/2h").unwrap();
        validate_origin_path("m/48'/1'/0'/2'").unwrap();
        // Mixed hardened markers.
        validate_origin_path("48'/1h/0'/2h").unwrap();
    }

    #[test]
    fn rejects_wrong_purpose_account_script_coin() {
        assert!(matches!(
            validate_origin_path("44'/0'/0'/2'"),
            Err(ParseError::InvalidOriginPath(_))
        ));
        assert!(matches!(
            validate_origin_path("48'/2'/0'/2'"),
            Err(ParseError::InvalidOriginPath(_))
        ));
        assert!(matches!(
            validate_origin_path("48'/0'/1'/2'"),
            Err(ParseError::InvalidOriginPath(_))
        ));
        assert!(matches!(
            validate_origin_path("48'/0'/0'/1'"),
            Err(ParseError::InvalidOriginPath(_))
        ));
        assert!(matches!(
            validate_origin_path("48'/0'/0'/2'/0'"),
            Err(ParseError::InvalidOriginPath(_))
        ));
    }

    #[test]
    fn rejects_malformed_and_multipath() {
        assert_eq!(
            validate_origin_path("48'/<0;1>/0'/2'"),
            Err(ParseError::MultipathForbidden)
        );
        assert_eq!(
            validate_origin_path("48'/*"),
            Err(ParseError::MultipathForbidden)
        );
        assert!(matches!(
            validate_origin_path("48'/0'/0'"),
            Err(ParseError::MalformedOriginPath(_))
        ));
        assert!(matches!(
            validate_origin_path("48'/0'/0'/2"),
            Err(ParseError::MalformedOriginPath(_))
        ));
        assert!(matches!(
            validate_origin_path("48H/0H/0H/2H"),
            Err(ParseError::MalformedOriginPath(_))
        ));
        assert!(matches!(
            validate_origin_path("48'/0a'/0'/2'"),
            Err(ParseError::MalformedOriginPath(_))
        ));
        assert!(matches!(
            validate_origin_path("48'/00'/0'/2'"),
            Err(ParseError::MalformedOriginPath(_))
        ));
        // Leading slash → five segments (empty first) → InvalidOriginPath.
        assert!(matches!(
            validate_origin_path("/48'/0'/0'/2'"),
            Err(ParseError::InvalidOriginPath(_))
        ));
        // Empty middle segment among four parts.
        assert!(matches!(
            validate_origin_path("48''/0'/0'/2'"),
            Err(ParseError::MalformedOriginPath(_))
        ));
        assert!(matches!(
            validate_origin_path("48'//0'/2'"),
            Err(ParseError::MalformedOriginPath(_))
        ));
        // Index ≥ 2^31.
        assert!(matches!(
            validate_origin_path("2147483648'/0'/0'/2'"),
            Err(ParseError::MalformedOriginPath(_))
        ));
        // Non-numeric overflow-ish garbage.
        assert!(matches!(
            validate_origin_path("99999999999999999999'/0'/0'/2'"),
            Err(ParseError::MalformedOriginPath(_))
        ));
        // Empty hardened marker body: `'/0'/0'/2'`.
        assert!(matches!(
            validate_origin_path("'/0'/0'/2'"),
            Err(ParseError::MalformedOriginPath(_))
        ));
    }
}
