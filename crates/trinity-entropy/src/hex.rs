//! Lowercase hex encode / decode. No extra crate — same discipline as
//! `trinity-types::Fingerprint`.

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Encode `bytes` as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode a lowercase or uppercase hex string. Odd length is an error.
#[cfg(test)]
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    if !s.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i]).ok_or(HexError::InvalidChar)?;
        let lo = nibble(bytes[i + 1]).ok_or(HexError::InvalidChar)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// Decode exactly `N` bytes of hex.
#[cfg(test)]
pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    let v = decode(s)?;
    v.try_into().map_err(|_| HexError::WrongLength)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexError {
    OddLength,
    InvalidChar,
    WrongLength,
}

#[cfg(test)]
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty_and_bytes() {
        assert_eq!(encode(&[]), "");
        assert_eq!(encode(&[0x00, 0xff, 0x1e]), "00ff1e");
    }

    #[test]
    fn decode_roundtrip_and_uppercase() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("00FF1E").unwrap(), vec![0x00, 0xff, 0x1e]);
        assert_eq!(decode("00ff1e").unwrap(), vec![0x00, 0xff, 0x1e]);
        assert_eq!(decode_array::<2>("1e1e").unwrap(), [0x1e, 0x1e]);
    }

    #[test]
    fn decode_errors() {
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(decode("zz"), Err(HexError::InvalidChar));
        assert_eq!(decode("0g"), Err(HexError::InvalidChar));
        assert_eq!(decode_array::<2>("aa"), Err(HexError::WrongLength));
        assert_eq!(decode_array::<1>("zzzz"), Err(HexError::InvalidChar));
    }
}
