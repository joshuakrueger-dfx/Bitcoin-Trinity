//! Errors for descriptor generation and persistence.

use thiserror::Error;

/// Failure building, validating, or (de)serialising a Trinity descriptor set.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DescriptorError {
    /// Two or more keys share the same master fingerprint (Spec §2.3 / P7).
    #[error("duplicate master fingerprint {0}: setup requires three separate seeds")]
    DuplicateFingerprint(String),

    /// A key expression or origin path uses BIP-389 multipath (decision O8).
    #[error("multipath descriptor expressions are not allowed (O8)")]
    MultipathForbidden,

    /// Key material (xprv/tprv) appeared where only xpubs are allowed.
    #[error("private extended keys are forbidden in trinity-watch")]
    PrivateKeyForbidden,

    /// Origin path is not the BIP-48 multisig path for the given network.
    #[error("origin path must be BIP-48 m/48'/{{coin}}'/0'/2' for this network (got {0})")]
    InvalidOriginPath(String),

    /// xpub / fingerprint / path failed to parse via miniscript or bitcoin.
    #[error("invalid key expression: {0}")]
    InvalidKeyExpression(String),

    /// Descriptor string is outside Trinity grammar `wsh(sortedmulti(2,·,·,·))`.
    #[error("descriptor is outside Trinity grammar: {0}")]
    ForeignGrammar(String),

    /// miniscript/BDK rejected the constructed descriptor.
    #[error("descriptor construction failed: {0}")]
    Construction(String),

    /// JSON (de)serialisation failed.
    #[error("descriptor.json error: {0}")]
    Json(String),

    /// A required field is missing or inconsistent after load.
    #[error("invalid descriptor document: {0}")]
    InvalidDocument(String),
}
