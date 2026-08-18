//! BIP-380 descriptor checksum — implemented from the BIP text, not miniscript.
//!
//! Source: <https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>
//! (Character Set + Checksum sections). Shared with Core / miniscript only at
//! the algorithm level; this module is an independent transcription.

use crate::error::ParseError;

/// BIP-380 input character set (three groups of 32, in this exact order).
const INPUT_CHARSET: &[u8] = b"0123456789()[],'/*abcdefgh@:$%{}\
IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~\
ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/// Bech32-style charset used for the eight checksum characters.
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BCH generators from BIP-380.
const GENERATOR: [u64; 5] = [
    0x00_00_f5_de_e5_19_89,
    0x00_00_a9_fd_ca_33_12,
    0x00_00_1b_ab_10_e3_2d,
    0x00_00_37_06_b1_67_7a,
    0x00_00_64_4d_62_6f_fd,
];

/// Verify that `s` is `SCRIPT#CHECKSUM` with a correct BIP-380 checksum.
///
/// Corresponds to BIP-380 `descsum_check`. Missing or malformed checksum
/// forms are reported as specific [`ParseError`] variants before the polymod
/// result is examined.
pub fn verify_checksum(s: &str) -> Result<(), ParseError> {
    let bytes = s.as_bytes();
    if bytes.len() < 10 {
        // Need at least one payload char + '#' + 8 checksum chars.
        return Err(ParseError::MissingChecksum);
    }
    let hash_pos = bytes.len() - 9;
    if bytes[hash_pos] != b'#' {
        return Err(ParseError::MissingChecksum);
    }
    let checksum = &bytes[hash_pos + 1..];
    debug_assert_eq!(checksum.len(), 8);
    for &c in checksum {
        if !CHECKSUM_CHARSET.contains(&c) {
            return Err(ParseError::MalformedChecksum);
        }
    }

    let payload = &s[..hash_pos];
    let mut symbols = expand(payload)?;
    for &c in checksum {
        // Checked membership above; find is infallible for those bytes.
        let idx = CHECKSUM_CHARSET
            .iter()
            .position(|&x| x == c)
            .expect("checksum char in charset");
        symbols.push(idx as u64);
    }
    if polymod(&symbols) != 1 {
        return Err(ParseError::InvalidChecksum);
    }
    Ok(())
}

/// Append a correct BIP-380 checksum to a script expression (no `#…` yet).
///
/// Corresponds to BIP-380 `descsum_create`. Available for unit tests so
/// fixtures never need miniscript to mint checksums.
#[cfg(test)]
pub(crate) fn create_checksum(script: &str) -> Result<String, ParseError> {
    let mut symbols = expand(script)?;
    symbols.extend(std::iter::repeat_n(0u64, 8));
    let checksum_val = polymod(&symbols) ^ 1;
    let mut out = String::with_capacity(script.len() + 9);
    out.push_str(script);
    out.push('#');
    for i in 0..8 {
        let shift = 5 * (7 - i);
        let idx = ((checksum_val >> shift) & 31) as usize;
        out.push(CHECKSUM_CHARSET[idx] as char);
    }
    Ok(out)
}

/// BIP-380 `descsum_expand`.
fn expand(s: &str) -> Result<Vec<u64>, ParseError> {
    let mut groups: Vec<u64> = Vec::with_capacity(3);
    let mut symbols: Vec<u64> = Vec::with_capacity(s.len() + s.len() / 3 + 1);
    for c in s.bytes() {
        let v = match INPUT_CHARSET.iter().position(|&x| x == c) {
            Some(i) => i as u64,
            None => return Err(ParseError::InvalidCharset),
        };
        symbols.push(v & 31);
        groups.push(v >> 5);
        if groups.len() == 3 {
            symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
            groups.clear();
        }
    }
    // groups is flushed whenever it reaches 3, so only 0..=2 remain.
    if groups.len() == 1 {
        symbols.push(groups[0]);
    } else if groups.len() == 2 {
        symbols.push(groups[0] * 3 + groups[1]);
    }
    Ok(symbols)
}

/// BIP-380 `descsum_polymod`.
fn polymod(symbols: &[u64]) -> u64 {
    let mut chk: u64 = 1;
    for &value in symbols {
        let top = chk >> 35;
        chk = ((chk & 0x7_ff_ff_ff_ff) << 5) ^ value;
        for (i, gen) in GENERATOR.iter().enumerate() {
            if ((top >> i) & 1) == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip380_vector_valid() {
        verify_checksum("raw(deadbeef)#89f8spxm").unwrap();
    }

    #[test]
    fn bip380_vector_create_roundtrip() {
        let s = create_checksum("raw(deadbeef)").unwrap();
        assert_eq!(s, "raw(deadbeef)#89f8spxm");
        verify_checksum(&s).unwrap();
    }

    #[test]
    fn bip380_vector_error_in_payload() {
        assert_eq!(
            verify_checksum("raw(deedbeef)#89f8spxm"),
            Err(ParseError::InvalidChecksum)
        );
    }

    #[test]
    fn bip380_vector_error_in_checksum() {
        // BIP lists `raw(deedbeef)##9f8spxm` — second char of checksum is `#`,
        // which is outside CHECKSUM_CHARSET → MalformedChecksum.
        assert_eq!(
            verify_checksum("raw(deedbeef)##9f8spxm"),
            Err(ParseError::MalformedChecksum)
        );
    }

    #[test]
    fn bip380_missing_and_short() {
        assert_eq!(
            verify_checksum("raw(deadbeef)"),
            Err(ParseError::MissingChecksum)
        );
        assert_eq!(
            verify_checksum("raw(deadbeef)#"),
            Err(ParseError::MissingChecksum)
        );
        assert_eq!(
            verify_checksum("raw(deadbeef)#89f8spx"),
            Err(ParseError::MissingChecksum)
        );
        // Form `#` + 8 bech32 chars but wrong polymod → InvalidChecksum.
        assert_eq!(
            verify_checksum("a#qpzry9x8"),
            Err(ParseError::InvalidChecksum)
        );
        // Nine trailing checksum chars → `#` is not at position len-9.
        assert_eq!(
            verify_checksum("raw(deadbeef)#89f8spxmx"),
            Err(ParseError::MissingChecksum)
        );
        // Too short overall.
        assert_eq!(verify_checksum(""), Err(ParseError::MissingChecksum));
        assert_eq!(verify_checksum("#"), Err(ParseError::MissingChecksum));
    }

    #[test]
    fn bip380_invalid_charset_in_payload() {
        // Ü is outside INPUT_CHARSET.
        assert_eq!(
            verify_checksum("raw(Ü)#00000000"),
            Err(ParseError::InvalidCharset)
        );
    }

    #[test]
    fn expand_group_remainders() {
        // Length 0 mod 3, 1 mod 3, 2 mod 3 all exercise remainder arms.
        assert!(expand("").unwrap().is_empty());
        assert_eq!(expand("0").unwrap().len(), 2); // symbol + 1 group remainder
        assert_eq!(expand("01").unwrap().len(), 3); // two symbols + combined group
        assert_eq!(expand("012").unwrap().len(), 4); // three symbols + group symbol

        // Two-char remainder: groups[0] * 3 + groups[1], both groups non-zero.
        // 'I' is charset[32] (group 1), 'i' is charset[64] (group 2).
        assert_eq!(expand("Ii").unwrap(), [0, 0, 5]);
    }

    #[test]
    fn known_checksums_cover_remainder_classes() {
        // Each checksum is from Bitcoin Core `getdescriptorinfo` (regtest 30.2):
        //   bitcoin-cli -regtest getdescriptorinfo '<payload>'
        // → field `checksum`. Not minted by this crate's `create_checksum`.
        // Lengths hit every expand remainder class (len mod 3).
        assert_eq!("raw(dead)".len() % 3, 0);
        assert_eq!("raw(deadbeef)".len() % 3, 1);
        assert_eq!("raw(deadbe)".len() % 3, 2);
        verify_checksum("raw(dead)#j7p6x6xf").unwrap(); // 9 ≡ 0; Core
        verify_checksum("raw(deadbeef)#89f8spxm").unwrap(); // 13 ≡ 1; BIP-380 + Core
        verify_checksum("raw(deadbe)#vwtc7tfv").unwrap(); // 11 ≡ 2; Core
    }

    #[test]
    fn create_rejects_invalid_charset() {
        assert_eq!(create_checksum("raw(Ü)"), Err(ParseError::InvalidCharset));
    }

    #[test]
    fn polymod_generator_bits() {
        // Force several generator XORs by feeding a non-trivial symbol stream.
        let s = create_checksum("0123456789()[],'/*abcdefgh@:$%{}").unwrap();
        verify_checksum(&s).unwrap();
    }
}
