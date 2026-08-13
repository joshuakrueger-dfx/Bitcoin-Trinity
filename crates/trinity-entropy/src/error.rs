//! Hard-rejection errors for entropy generation (fail-closed).

use thiserror::Error;

/// Hard failure during additional-source validation or key generation.
///
/// Every rejection is a specific variant — never a generic "invalid" and
/// never a silent fallback (Spec §2.1: a weak seed is permanent).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum EntropyError {
    /// Dice ASCII was empty. Inactive dice is expressed by omitting the source.
    #[error("dice sequence must not be empty")]
    EmptyDice,

    /// A dice character was not ASCII `1`–`6`.
    #[error("dice byte at index {index} is not ASCII 1-6 (got 0x{byte:02x})")]
    InvalidDice {
        /// Byte offset in the supplied dice string.
        index: usize,
        /// Offending byte.
        byte: u8,
    },

    /// Coin ASCII was empty. Inactive coins are expressed by omitting the source.
    #[error("coin sequence must not be empty")]
    EmptyCoins,

    /// A coin character was not ASCII `0` or `1`.
    #[error("coin byte at index {index} is not ASCII 0 or 1 (got 0x{byte:02x})")]
    InvalidCoin {
        /// Byte offset in the supplied coin string.
        index: usize,
        /// Offending byte.
        byte: u8,
    },

    /// Playing-card encoding was empty.
    #[error("card sequence must not be empty")]
    EmptyCards,

    /// Playing-card encoding failed to parse or contained a duplicate.
    #[error("card sequence is invalid: {0}")]
    InvalidCard(#[from] CardError),

    /// OS CSPRNG (`getrandom`) failed. There is no software fallback.
    #[error("operating-system CSPRNG failed")]
    CsRng,

    /// Entropy passed to BIP-39 was not 16 or 32 bytes.
    #[error("entropy length must be 16 or 32 bytes, got {got}")]
    BadEntropyLength {
        /// Length that was supplied.
        got: usize,
    },

    /// BIP-39 rejected the entropy (should not occur for 16/32-byte input).
    #[error("BIP-39 derivation rejected the entropy")]
    Bip39,

    /// BIP-32 master-key derivation rejected the seed.
    #[error("BIP-32 master key derivation failed")]
    MasterKey,
}

/// Playing-card parse failure (Spec §2.2.1 rank+suit encoding).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CardError {
    /// Byte is not a valid rank or suit at this position.
    #[error("unexpected byte 0x{byte:02x} at index {index}")]
    UnexpectedByte {
        /// Byte offset in the supplied card string.
        index: usize,
        /// Offending byte.
        byte: u8,
    },

    /// Input ended in the middle of a rank+suit pair (e.g. `"A"` or `"10"`).
    #[error("card sequence ended before a complete rank+suit pair")]
    Incomplete,

    /// The same card appeared twice. A physical deck has one of each.
    #[error("duplicate card {card}")]
    Duplicate {
        /// Canonical rank+suit of the duplicate (e.g. `"AS"`).
        card: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_covers_every_variant() {
        let cases: &[EntropyError] = &[
            EntropyError::EmptyDice,
            EntropyError::InvalidDice {
                index: 1,
                byte: b'7',
            },
            EntropyError::EmptyCoins,
            EntropyError::InvalidCoin {
                index: 0,
                byte: b'2',
            },
            EntropyError::EmptyCards,
            EntropyError::InvalidCard(CardError::Incomplete),
            EntropyError::InvalidCard(CardError::UnexpectedByte {
                index: 2,
                byte: b'X',
            }),
            EntropyError::InvalidCard(CardError::Duplicate { card: "AS".into() }),
            EntropyError::CsRng,
            EntropyError::BadEntropyLength { got: 15 },
            EntropyError::Bip39,
            EntropyError::MasterKey,
        ];
        for e in cases {
            assert!(!e.to_string().is_empty(), "{e:?}");
        }
    }
}
