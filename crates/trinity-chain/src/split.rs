//! Compose distinct sync and broadcast backends — Spec §1.6 requirement 1.

use std::sync::Arc;

use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_wallet::{KeychainKind, Update};
use bitcoin::{Transaction, Txid};

use crate::backend::ChainBackend;
use crate::error::ChainError;
use crate::fee::FeeEstimates;
use crate::privacy::PrivacyProfile;

/// Routes scan/sync/fees/tip to one backend and `broadcast` to another.
///
/// Spec §1.6: "The `broadcast` call must be allowed to use its own
/// independently configurable backend (default: CBF peers or Tor)." This
/// type **allows** that split without forcing every backend impl to carry
/// two transports. Example: Electrum for sync + CBF (or the memory fake)
/// for broadcast so the Electrum operator never sees the spend IP linkage.
///
/// `privacy_profile()` reports the **sync** backend's profile (wallet-graph
/// disclosure). Broadcast linkage is a separate concern (Spec §1.6 broadcast
/// row); the UI composes both when a split is configured.
#[derive(Clone)]
pub struct SplitBackend {
    sync: Arc<dyn ChainBackend>,
    broadcast: Arc<dyn ChainBackend>,
}

impl core::fmt::Debug for SplitBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SplitBackend")
            .field("sync", &"Arc<dyn ChainBackend>")
            .field("broadcast", &"Arc<dyn ChainBackend>")
            .finish()
    }
}

impl SplitBackend {
    /// Scan/sync on `sync`, announce transactions on `broadcast`.
    pub fn new(sync: Arc<dyn ChainBackend>, broadcast: Arc<dyn ChainBackend>) -> Self {
        Self { sync, broadcast }
    }

    /// The backend used for full scan, sync, fees, and tip.
    pub fn sync_backend(&self) -> &Arc<dyn ChainBackend> {
        &self.sync
    }

    /// The backend used solely for [`ChainBackend::broadcast`].
    pub fn broadcast_backend(&self) -> &Arc<dyn ChainBackend> {
        &self.broadcast
    }
}

impl ChainBackend for SplitBackend {
    fn full_scan(&self, req: FullScanRequest<KeychainKind>) -> Result<Update, ChainError> {
        self.sync.full_scan(req)
    }

    fn sync(&self, req: SyncRequest<(KeychainKind, u32)>) -> Result<Update, ChainError> {
        self.sync.sync(req)
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
        self.broadcast.broadcast(tx)
    }

    fn fee_estimates(&self) -> Result<FeeEstimates, ChainError> {
        self.sync.fee_estimates()
    }

    fn tip_height(&self) -> Result<u32, ChainError> {
        self.sync.tip_height()
    }

    fn privacy_profile(&self) -> PrivacyProfile {
        self.sync.privacy_profile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryBackend;
    use crate::privacy::{BackendKind, PrivacyProfile};
    use bitcoin::absolute::LockTime;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    /// Sync double whose privacy profile pretends to be third-party Electrum
    /// (so the split's `privacy_profile` is distinguishable from broadcast).
    struct ProfiledBackend {
        inner: MemoryBackend,
        profile: PrivacyProfile,
    }

    impl ChainBackend for ProfiledBackend {
        fn full_scan(&self, req: FullScanRequest<KeychainKind>) -> Result<Update, ChainError> {
            self.inner.full_scan(req)
        }

        fn sync(&self, req: SyncRequest<(KeychainKind, u32)>) -> Result<Update, ChainError> {
            self.inner.sync(req)
        }

        fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
            self.inner.broadcast(tx)
        }

        fn fee_estimates(&self) -> Result<FeeEstimates, ChainError> {
            self.inner.fee_estimates()
        }

        fn tip_height(&self) -> Result<u32, ChainError> {
            self.inner.tip_height()
        }

        fn privacy_profile(&self) -> PrivacyProfile {
            self.profile.clone()
        }
    }

    fn empty_tx() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(500),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn broadcast_uses_broadcast_backend_only() {
        let sync_mem = Arc::new(MemoryBackend::new());
        sync_mem.set_tip_height(100);
        let broadcast_mem = Arc::new(MemoryBackend::new());
        let sync: Arc<dyn ChainBackend> = sync_mem.clone();
        let broadcast: Arc<dyn ChainBackend> = broadcast_mem.clone();
        let split = SplitBackend::new(sync.clone(), broadcast.clone());

        let tx = empty_tx();
        let txid = split.broadcast(&tx).unwrap();
        assert_eq!(txid, tx.compute_txid());

        // Sync path never saw the transaction.
        assert!(sync_mem.broadcasted().is_empty());
        assert_eq!(broadcast_mem.broadcasted().len(), 1);

        // Tip and fees come from sync.
        assert_eq!(split.tip_height().unwrap(), 100);
        assert!(split.fee_estimates().unwrap().is_empty());
        assert!(Arc::ptr_eq(split.sync_backend(), &sync));
        assert!(Arc::ptr_eq(split.broadcast_backend(), &broadcast));
    }

    #[test]
    fn privacy_profile_follows_sync_backend() {
        let sync = Arc::new(ProfiledBackend {
            inner: MemoryBackend::new(),
            profile: PrivacyProfile::electrum_third_party(),
        });
        sync.inner.set_tip_height(7);
        let broadcast = Arc::new(ProfiledBackend {
            inner: MemoryBackend::new(),
            profile: PrivacyProfile::cbf(),
        });
        let split = SplitBackend::new(sync, broadcast);
        let p = split.privacy_profile();
        assert_eq!(p.kind, BackendKind::ElectrumThirdParty);
        assert!(p.requires_selection_warning);
        // Drive ProfiledBackend through the split surface (all methods).
        assert_eq!(split.tip_height().unwrap(), 7);
        assert!(split.fee_estimates().unwrap().is_empty());
        let full = FullScanRequest::<KeychainKind>::builder_at(0).build();
        assert!(split.full_scan(full).is_ok());
        let partial = SyncRequest::<(KeychainKind, u32)>::builder_at(0).build();
        assert!(split.sync(partial).is_ok());
        assert!(split.broadcast(&empty_tx()).is_ok());
    }

    #[test]
    fn scan_and_sync_delegate_to_sync_backend() {
        let sync = Arc::new(MemoryBackend::new());
        sync.fail_next_full_scan("only sync");
        let broadcast = Arc::new(MemoryBackend::new());
        let split = SplitBackend::new(sync, broadcast);

        let req = FullScanRequest::<KeychainKind>::builder_at(0).build();
        assert!(matches!(split.full_scan(req), Err(ChainError::Network(_))));

        let sreq = SyncRequest::<(KeychainKind, u32)>::builder_at(0).build();
        assert!(split.sync(sreq).is_ok());
    }

    #[test]
    fn debug_impl_does_not_panic() {
        let split = SplitBackend::new(MemoryBackend::shared(), MemoryBackend::shared());
        let s = format!("{split:?}");
        assert!(s.contains("SplitBackend"));
        // Clone is used by Arc consumers.
        let _ = split.clone();
    }
}
