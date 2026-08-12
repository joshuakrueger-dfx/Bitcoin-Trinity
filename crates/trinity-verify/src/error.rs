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

/// Hard failure during independent BIP-32 / BIP-67 / witnessScript derivation.
///
/// Fail-closed: every rejection path is a specific variant (Spec §1.5). Used by
/// WP-21 derivation and later by WP-22 checks that re-derive outputs.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DeriveError {
    /// Child index is hardened (`i ≥ 2³¹`). Public CKD cannot derive it.
    #[error("hardened child index is not derivable from xpub (got {0})")]
    HardenedIndex(u32),

    /// Parent compressed pubkey bytes are not a valid SEC1 secp256k1 point.
    #[error("invalid compressed public key")]
    InvalidPublicKey,

    /// BIP-32 tweak invalid: `I_L` not a valid secret key, or point addition
    /// yielded the point at infinity (BIP-32 §"Public parent key → public
    /// child key", rare; caller should try the next index).
    #[error("BIP-32 child key derivation produced an invalid tweak")]
    InvalidTweak,

    /// Extended public key string failed base58check / BIP-32 decode.
    #[error("invalid extended public key")]
    MalformedXpub,

    /// Multisig parameters out of range (`k`/`n` not in 1..=16, or `k > n`).
    #[error("invalid multisig parameters: k={k}, n={n}")]
    InvalidMultisigParams {
        /// Required signatures.
        k: u32,
        /// Total keys.
        n: u32,
    },

    /// A compressed pubkey in a set for BIP-67 / script build is malformed.
    #[error("compressed pubkey at index {0} is not a valid 33-byte SEC1 key")]
    InvalidCompressedPubkey(usize),
}
