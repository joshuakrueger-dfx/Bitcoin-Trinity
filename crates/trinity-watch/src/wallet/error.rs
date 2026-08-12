//! Errors for BDK wallet construction, address derivation, and PSBT build.

use thiserror::Error;

/// Failure constructing, funding, or spending with a [`super::WatchWallet`].
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum WalletError {
    /// Descriptor parse / BDK wallet create failed.
    #[error("wallet create failed: {0}")]
    Create(String),

    /// Recipient address failed to parse or mismatched network.
    #[error("invalid recipient address: {0}")]
    InvalidAddress(String),

    /// Fee rate / absolute fee target rejected by the builder.
    #[error("invalid fee target: {0}")]
    InvalidFee(String),

    /// BDK transaction builder error (coin selection, dust, locktime, …).
    #[error("transaction build failed: {0}")]
    Build(String),

    /// Chain update could not be applied (disconnected tip, …).
    #[error("apply update failed: {0}")]
    ApplyUpdate(String),

    /// Descriptor document failed Trinity validation before wallet open.
    #[error("descriptor: {0}")]
    Descriptor(#[from] crate::descriptor::DescriptorError),

    /// Arithmetic overflow while checking fee identity (P8).
    #[error("amount overflow: {0}")]
    Overflow(String),
}
