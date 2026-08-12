//! Chain connectivity errors — Spec §1.6 / facade `ChainError`.

use thiserror::Error;

/// Failure talking to a chain data source or broadcast path.
///
/// Spec §1.3 / §1.6: sync and broadcast return `Result<…, ChainError>`.
/// Concrete backends (WP-14–16) map their transport errors into these
/// variants; the in-memory fake uses the same surface so tests exercise
/// the real call shape without network.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ChainError {
    /// Transport / connection failure (TLS drop, RPC down, peer gone).
    #[error("chain network error: {0}")]
    Network(String),

    /// Peer or server returned an unusable response.
    #[error("chain protocol error: {0}")]
    Protocol(String),

    /// Transaction was rejected or could not be announced.
    #[error("broadcast failed: {0}")]
    Broadcast(String),

    /// Backend is not ready (not connected, still IBD, …).
    #[error("chain backend unavailable: {0}")]
    Unavailable(String),

    /// Catch-all for backend-specific failures that do not fit above.
    #[error("chain error: {0}")]
    Other(String),
}
