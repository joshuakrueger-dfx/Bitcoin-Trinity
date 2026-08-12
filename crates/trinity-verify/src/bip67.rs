//! Own BIP-67 public-key sorting — independent of the builder.
//!
//! Source: <https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki>
//! (Specification: lexicographic sort of compressed public keys by their
//! binary representation before building the multisig redeem/witness script).
//!
//! Spec §1.5: verifier sorting must not be `miniscript`'s. Shared remain only
//! the byte comparison of already-compressed SEC1 keys.

/// Sort compressed SEC1 public keys lexicographically ascending (BIP-67).
///
/// Operates in place. Byte-for-byte comparison of the 33-byte encodings —
/// identical to sorting the hex strings when each key is lowercase hex of
/// the compressed form.
///
/// Does not validate that the bytes are valid curve points; callers that need
/// that check (script construction) do so separately. Sorting is pure order.
pub fn sort_pubkeys(keys: &mut [[u8; 33]]) {
    keys.sort_unstable();
}

/// Return a BIP-67-sorted copy of three compressed pubkeys (Trinity 2-of-3).
///
/// Convenience for the fixed `n = 3` case used by
/// [`crate::derive::derive_at`]. The input order is descriptor order; the
/// output is sorted for witnessScript construction. WP-22 check V4 needs both
/// (descriptor-order children for fingerprint mapping, sorted for script).
#[must_use]
pub fn sort_three(keys: [[u8; 33]; 3]) -> [[u8; 33]; 3] {
    let mut out = keys;
    sort_pubkeys(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_sorted_is_stable() {
        let mut a = [0x02; 33];
        a[32] = 0x01;
        let mut b = [0x02; 33];
        b[32] = 0x02;
        let c = [0x03; 33];
        let mut keys = [a, b, c];
        // a < b < c: same 0x02 prefix, a[32]=1 < b[32]=2; c starts with 0x03.
        sort_pubkeys(&mut keys);
        assert_eq!(keys, [a, b, c]);
    }

    #[test]
    fn reverses_and_permutes() {
        let k0 = {
            let mut k = [0u8; 33];
            k[0] = 0x02;
            k[32] = 0x10;
            k
        };
        let k1 = {
            let mut k = [0u8; 33];
            k[0] = 0x02;
            k[32] = 0x20;
            k
        };
        let k2 = {
            let mut k = [0u8; 33];
            k[0] = 0x03;
            k[32] = 0x01;
            k
        };
        assert_eq!(sort_three([k2, k0, k1]), [k0, k1, k2]);
        assert_eq!(sort_three([k1, k2, k0]), [k0, k1, k2]);
    }

    #[test]
    fn empty_and_singleton() {
        let mut empty: [[u8; 33]; 0] = [];
        sort_pubkeys(&mut empty);
        let mut one = [[0x02; 33]];
        sort_pubkeys(&mut one);
        assert_eq!(one[0][0], 0x02);
    }
}
