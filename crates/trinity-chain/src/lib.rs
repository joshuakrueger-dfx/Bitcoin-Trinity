//! `trinity-chain` — swappable chain connectivity.
//!
//! Spec: docs/SPECIFICATION.md §1.6. Work packages: WP-13 (trait + in-memory
//! fake), WP-14 Electrum; Core RPC (WP-15) and CBF (WP-16) follow.
//!
//! ## Surface
//!
//! - [`ChainBackend`] — trait matching Spec §1.6 (including `privacy_profile`)
//! - [`ElectrumBackend`] / [`ElectrumConfig`] — Electrum via `bdk_electrum`
//! - [`MemoryBackend`] — offline test double
//! - [`SplitBackend`] — scan/sync on one backend, broadcast on another
//! - [`PrivacyProfile`] / [`BackendKind`] — Spec §1.6 disclosure table
//! - [`FeeEstimates`] — sat/vB by confirmation target
//! - [`ChainError`]
//!
//! ## BDK types (exact paths)
//!
//! See module docs on [`backend`] for fundstellen. Summary:
//!
//! - `FullScanRequest` / `SyncRequest` → `bdk_chain::spk_client` (defined in
//!   `bdk_core::spk_client`)
//! - `Update` / `KeychainKind` → `bdk_wallet` (BDK's keychain, not
//!   `trinity_types::KeychainKind`)
//!
//! ## No vendor default server
//!
//! Trinity operates no Electrum/Esplora endpoint. Default is CBF; a server
//! host is user-supplied (Spec §1.6). Electrum failures never fall back to
//! Core RPC or CBF (S13).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod backend;
mod electrum;
mod error;
mod fee;
mod memory;
mod privacy;
mod split;

pub use backend::ChainBackend;
pub use electrum::{
    ElectrumBackend, ElectrumConfig, Socks5Proxy, DEFAULT_BATCH_SIZE, DEFAULT_STOP_GAP,
};
pub use error::ChainError;
pub use fee::FeeEstimates;
pub use memory::MemoryBackend;
pub use privacy::{BackendKind, PrivacyProfile};
pub use split::SplitBackend;

// Re-export the BDK types the trait uses so callers need not dig for paths.
pub use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
pub use bdk_wallet::{KeychainKind, Update};
pub use bitcoin::{Transaction, Txid};

#[cfg(test)]
mod trait_surface_tests {
    use super::*;
    use std::sync::Arc;

    /// Compile-time + runtime proof that the Spec §1.6 method set exists on
    /// `dyn ChainBackend` and that broadcast can be split from sync.
    #[test]
    fn dyn_chain_backend_method_set() {
        let sync = MemoryBackend::shared();
        sync.set_tip_height(42);
        let broadcast = MemoryBackend::shared();
        let split: Arc<dyn ChainBackend> =
            Arc::new(SplitBackend::new(sync.clone(), broadcast.clone()));

        let full = FullScanRequest::<KeychainKind>::builder_at(1).build();
        assert!(split.full_scan(full).is_ok());

        let partial = SyncRequest::<(KeychainKind, u32)>::builder_at(1).build();
        assert!(split.sync(partial).is_ok());

        assert_eq!(split.tip_height().unwrap(), 42);
        assert!(split.fee_estimates().unwrap().is_empty());
        assert_eq!(split.privacy_profile().kind, BackendKind::InMemory);
    }

    #[test]
    fn chain_error_display() {
        let e = ChainError::Network("down".into());
        assert!(e.to_string().contains("network"));
        let e = ChainError::Protocol("bad header".into());
        assert!(e.to_string().contains("protocol"));
        let e = ChainError::Broadcast("reject".into());
        assert!(e.to_string().contains("broadcast"));
        let e = ChainError::Unavailable("ibd".into());
        assert!(e.to_string().contains("unavailable"));
        let e = ChainError::Other("x".into());
        assert!(e.to_string().contains("chain error"));
    }
}
