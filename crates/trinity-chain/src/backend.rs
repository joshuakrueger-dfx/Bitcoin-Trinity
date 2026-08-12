//! `ChainBackend` trait — Spec §1.6, WP-13.
//!
//! ## BDK type paths (vendored source, not docs.rs)
//!
//! | Spec name | Exact path | Fundstelle |
//! |---|---|---|
//! | `FullScanRequest<K>` | `bdk_core::spk_client::FullScanRequest` (re-export `bdk_chain::spk_client::FullScanRequest`) | `vendor/bdk_core/src/spk_client.rs` (`struct FullScanRequest`) |
//! | `SyncRequest<I>` | `bdk_core::spk_client::SyncRequest` (re-export `bdk_chain::spk_client::SyncRequest`) | `vendor/bdk_core/src/spk_client.rs` (`struct SyncRequest`) |
//! | `Update` | `bdk_wallet::Update` | `vendor/bdk_wallet/src/wallet/mod.rs` (`pub struct Update`) |
//! | `KeychainKind` | **`bdk_wallet::KeychainKind`** (not `trinity_types::KeychainKind`) | `vendor/bdk_wallet/src/types.rs` |
//!
//! ### Why BDK's `KeychainKind`, not Trinity's
//!
//! Spec §1.6 documents the BDK 3.1.0 flow:
//! `Wallet::start_full_scan() -> FullScanRequestBuilder<KeychainKind>` and
//! `start_sync_with_revealed_spks() -> SyncRequestBuilder<(KeychainKind, u32)>`
//! (`vendor/bdk_wallet/src/wallet/mod.rs`). Those methods use BDK's own
//! `KeychainKind` (`External` / `Internal` in `types.rs`). The wallet still
//! builds the request and applies the returned `Update`; this trait is only
//! the network half. `trinity_types::KeychainKind` is the FFI/facade twin
//! (WP-10); `trinity-watch` already maps between the two.
//!
//! ## No vendor default server
//!
//! There is no Electrum/Esplora endpoint operated by Trinity. Default
//! connectivity is CBF (once WP-16 lands); whoever wants a server enters it
//! themselves. Backend selection is WP-14–16; this trait only defines the
//! swappable surface.
//!
//! ## Broadcast is separately configurable
//!
//! Spec §1.6 requirement 1: whoever syncs via Electrum and broadcasts via the
//! same server delivers the strongest linkage. Callers may hold two
//! [`ChainBackend`]s (one for scan/sync, one for broadcast), or compose them
//! with [`crate::SplitBackend`]. The trait **allows** a split; it does not
//! force every impl to split.

use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_wallet::{KeychainKind, Update};
use bitcoin::{Transaction, Txid};

use crate::error::ChainError;
use crate::fee::FeeEstimates;
use crate::privacy::PrivacyProfile;

/// Swappable chain connectivity — Spec §1.6.
///
/// Implementations: Electrum (WP-14), Core RPC (WP-15), CBF (WP-16), and the
/// in-memory fake ([`crate::MemoryBackend`]) for offline tests.
pub trait ChainBackend: Send + Sync {
    /// Full wallet scan (import / restore). Consumes a BDK
    /// [`FullScanRequest`] built by `Wallet::start_full_scan()`.
    fn full_scan(&self, req: FullScanRequest<KeychainKind>) -> Result<Update, ChainError>;

    /// Incremental sync of revealed script pubkeys. Consumes a BDK
    /// [`SyncRequest`] from `Wallet::start_sync_with_revealed_spks()`.
    fn sync(&self, req: SyncRequest<(KeychainKind, u32)>) -> Result<Update, ChainError>;

    /// Announce a finalized transaction. May use a **different** backend
    /// instance than scan/sync (Spec §1.6 separate broadcast path).
    fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError>;

    /// Feerate estimates in sat/vB by confirmation target.
    fn fee_estimates(&self) -> Result<FeeEstimates, ChainError>;

    /// Best-known chain tip height (for anti-fee-sniping locktime, UI, …).
    fn tip_height(&self) -> Result<u32, ChainError>;

    /// What this backend reveals to its counterparty (Spec §1.6 table / T16).
    fn privacy_profile(&self) -> PrivacyProfile;
}
