//! Parse errors — one variant per hard-rejection reason (Spec §1.5, fail-closed).

use thiserror::Error;

/// Hard parse failure for a Trinity descriptor string.
///
/// Every rejection path is distinguishable: Spec §1.5 and the fail-closed
/// principle require specific errors, not a single catch-all string.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    /// No trailing `#checksum` (BIP-380 requires eight checksum characters).
    #[error("descriptor is missing BIP-380 checksum")]
    MissingChecksum,

    /// Checksum present but not exactly eight characters of the bech32 set.
    #[error("descriptor checksum has invalid length or charset")]
    MalformedChecksum,

    /// BIP-380 polymod check failed (wrong checksum for the payload).
    #[error("descriptor BIP-380 checksum is invalid")]
    InvalidChecksum,

    /// Payload contains a character outside the BIP-380 input charset.
    #[error("descriptor contains a character outside the BIP-380 charset")]
    InvalidCharset,

    /// Top-level expression is not `wsh(...)`.
    #[error("descriptor top-level must be wsh(...), got foreign wrapper")]
    WrongTopLevel,

    /// Inner script is not `sortedmulti(...)` (`multi`, `tr`, bare keys, …).
    #[error("descriptor must wrap sortedmulti(...), got foreign script expression")]
    ExpectedSortedMulti,

    /// Threshold `k` is not the literal `2` required for a 2-of-3 wallet.
    #[error("sortedmulti threshold must be 2 (2-of-3 only), got {0}")]
    WrongThreshold(String),

    /// Key expression count is not exactly three.
    #[error("sortedmulti must have exactly 3 key expressions, found {0}")]
    WrongKeyCount(usize),

    /// Fingerprint is not exactly eight hex characters.
    #[error("key origin fingerprint must be 8 hex characters")]
    MalformedFingerprint,

    /// Origin path is syntactically invalid (markers, empty segments, …).
    #[error("key origin path is malformed: {0}")]
    MalformedOriginPath(String),

    /// Origin path is not BIP-48 `48'/coin'/0'/2'` with coin ∈ {{0, 1}}.
    #[error("key origin path must be BIP-48 48'/{{0|1}}'/0'/2' (got {0})")]
    InvalidOriginPath(String),

    /// Multipath markers (`<`, `;`, `*`) appeared where only a fixed path is allowed.
    #[error("multipath markers are forbidden in Trinity descriptors")]
    MultipathForbidden,

    /// Extended key failed base58check / BIP-32 decode, or wrong prefix.
    #[error("invalid extended public key")]
    MalformedXpub,

    /// An xprv/tprv appeared where only public keys are allowed.
    #[error("private extended keys are forbidden in descriptors")]
    PrivateKeyForbidden,

    /// Trailing derivation after the xpub is not `/0/*` or `/1/*`.
    #[error("key derivation must be /0/* or /1/*")]
    MalformedDerivation,

    /// Key expression missing `[…]` origin brackets or otherwise incomplete.
    #[error("malformed key expression")]
    MalformedKeyExpression,

    /// Unexpected characters after `wsh(sortedmulti(...))` (before `#checksum`).
    #[error("trailing garbage after descriptor body")]
    TrailingGarbage,

    /// Input ended before a required token.
    #[error("unexpected end of descriptor")]
    UnexpectedEof,
}
