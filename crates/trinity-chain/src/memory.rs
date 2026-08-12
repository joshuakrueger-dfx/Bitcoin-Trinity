//! In-memory [`ChainBackend`] for tests — no network (WP-13).

use std::sync::{Arc, Mutex};

use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_wallet::{KeychainKind, Update};
use bitcoin::{Transaction, Txid};

use crate::backend::ChainBackend;
use crate::error::ChainError;
use crate::fee::FeeEstimates;
use crate::privacy::PrivacyProfile;

/// Test double for [`ChainBackend`] that never opens a socket.
///
/// Holds configurable tip height, fee estimates, privacy profile, and the
/// `Update` values returned from `full_scan` / `sync`. Broadcasted
/// transactions are retained for assertions. Optional failure injection
/// covers error paths without real network error simulation (the
/// TESTING.md §3.2 exception for "network error paths per backend" applies
/// to Electrum/Core/CBF, not this fake).
#[derive(Debug)]
pub struct MemoryBackend {
    tip_height: Mutex<u32>,
    fees: Mutex<FeeEstimates>,
    privacy: PrivacyProfile,
    full_scan_update: Mutex<Update>,
    sync_update: Mutex<Update>,
    broadcasted: Mutex<Vec<Transaction>>,
    /// When set, `full_scan` returns [`ChainError::Network`].
    full_scan_fail: Mutex<Option<String>>,
    /// When set, `sync` returns [`ChainError::Network`].
    sync_fail: Mutex<Option<String>>,
    /// When set, `broadcast` returns [`ChainError::Broadcast`].
    broadcast_fail: Mutex<Option<String>>,
    /// When set, `fee_estimates` returns [`ChainError::Unavailable`].
    fees_fail: Mutex<Option<String>>,
    /// When set, `tip_height` returns [`ChainError::Unavailable`].
    tip_fail: Mutex<Option<String>>,
}

impl MemoryBackend {
    /// Empty backend at height 0 with the in-memory privacy profile.
    pub fn new() -> Self {
        Self {
            tip_height: Mutex::new(0),
            fees: Mutex::new(FeeEstimates::empty()),
            privacy: PrivacyProfile::in_memory(),
            full_scan_update: Mutex::new(Update::default()),
            sync_update: Mutex::new(Update::default()),
            broadcasted: Mutex::new(Vec::new()),
            full_scan_fail: Mutex::new(None),
            sync_fail: Mutex::new(None),
            broadcast_fail: Mutex::new(None),
            fees_fail: Mutex::new(None),
            tip_fail: Mutex::new(None),
        }
    }

    /// Convenience: wrap in [`Arc`] for use as `Arc<dyn ChainBackend>`.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Set the tip height returned by [`ChainBackend::tip_height`].
    pub fn set_tip_height(&self, height: u32) {
        *self.tip_height.lock().expect("tip mutex") = height;
    }

    /// Replace fee estimates.
    pub fn set_fee_estimates(&self, fees: FeeEstimates) {
        *self.fees.lock().expect("fees mutex") = fees;
    }

    /// Replace the update returned from `full_scan`.
    pub fn set_full_scan_update(&self, update: Update) {
        *self.full_scan_update.lock().expect("full_scan mutex") = update;
    }

    /// Replace the update returned from `sync`.
    pub fn set_sync_update(&self, update: Update) {
        *self.sync_update.lock().expect("sync mutex") = update;
    }

    /// Transactions successfully accepted by [`ChainBackend::broadcast`].
    pub fn broadcasted(&self) -> Vec<Transaction> {
        self.broadcasted.lock().expect("broadcast mutex").clone()
    }

    /// Next `full_scan` fails with this message (cleared after one use).
    pub fn fail_next_full_scan(&self, msg: impl Into<String>) {
        *self.full_scan_fail.lock().expect("full_scan_fail") = Some(msg.into());
    }

    /// Next `sync` fails with this message (cleared after one use).
    pub fn fail_next_sync(&self, msg: impl Into<String>) {
        *self.sync_fail.lock().expect("sync_fail") = Some(msg.into());
    }

    /// Next `broadcast` fails with this message (cleared after one use).
    pub fn fail_next_broadcast(&self, msg: impl Into<String>) {
        *self.broadcast_fail.lock().expect("broadcast_fail") = Some(msg.into());
    }

    /// Next `fee_estimates` fails with this message (cleared after one use).
    pub fn fail_next_fee_estimates(&self, msg: impl Into<String>) {
        *self.fees_fail.lock().expect("fees_fail") = Some(msg.into());
    }

    /// Next `tip_height` fails with this message (cleared after one use).
    pub fn fail_next_tip_height(&self, msg: impl Into<String>) {
        *self.tip_fail.lock().expect("tip_fail") = Some(msg.into());
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainBackend for MemoryBackend {
    fn full_scan(&self, req: FullScanRequest<KeychainKind>) -> Result<Update, ChainError> {
        // Consume request iterators without network I/O.
        drop(req);
        if let Some(msg) = self.full_scan_fail.lock().expect("full_scan_fail").take() {
            return Err(ChainError::Network(msg));
        }
        Ok(self
            .full_scan_update
            .lock()
            .expect("full_scan mutex")
            .clone())
    }

    fn sync(&self, req: SyncRequest<(KeychainKind, u32)>) -> Result<Update, ChainError> {
        drop(req);
        if let Some(msg) = self.sync_fail.lock().expect("sync_fail").take() {
            return Err(ChainError::Network(msg));
        }
        Ok(self.sync_update.lock().expect("sync mutex").clone())
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
        if let Some(msg) = self.broadcast_fail.lock().expect("broadcast_fail").take() {
            return Err(ChainError::Broadcast(msg));
        }
        let txid = tx.compute_txid();
        self.broadcasted
            .lock()
            .expect("broadcast mutex")
            .push(tx.clone());
        Ok(txid)
    }

    fn fee_estimates(&self) -> Result<FeeEstimates, ChainError> {
        if let Some(msg) = self.fees_fail.lock().expect("fees_fail").take() {
            return Err(ChainError::Unavailable(msg));
        }
        Ok(self.fees.lock().expect("fees mutex").clone())
    }

    fn tip_height(&self) -> Result<u32, ChainError> {
        if let Some(msg) = self.tip_fail.lock().expect("tip_fail").take() {
            return Err(ChainError::Unavailable(msg));
        }
        Ok(*self.tip_height.lock().expect("tip mutex"))
    }

    fn privacy_profile(&self) -> PrivacyProfile {
        self.privacy.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

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
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn empty_full_scan() -> FullScanRequest<KeychainKind> {
        FullScanRequest::<KeychainKind>::builder_at(0).build()
    }

    fn empty_sync() -> SyncRequest<(KeychainKind, u32)> {
        SyncRequest::<(KeychainKind, u32)>::builder_at(0).build()
    }

    #[test]
    fn happy_path_no_network() {
        let m = MemoryBackend::new();
        m.set_tip_height(840_000);
        m.set_fee_estimates(FeeEstimates::from_targets([(1, 12), (6, 4)]));
        // Configurable updates — exercised so the setters stay covered.
        m.set_full_scan_update(Update::default());
        m.set_sync_update(Update::default());

        let update = m.full_scan(empty_full_scan()).unwrap();
        assert!(update.chain.is_none());
        let _ = m.sync(empty_sync()).unwrap();

        let tx = empty_tx();
        let txid = m.broadcast(&tx).unwrap();
        assert_eq!(txid, tx.compute_txid());
        assert_eq!(m.broadcasted().len(), 1);

        assert_eq!(m.tip_height().unwrap(), 840_000);
        assert_eq!(m.fee_estimates().unwrap().sat_per_vb_for(1), Some(12));
        assert_eq!(m.privacy_profile().kind, crate::BackendKind::InMemory);
    }

    #[test]
    fn failure_injection_covers_error_variants() {
        let m = MemoryBackend::default();
        m.fail_next_full_scan("scan down");
        assert!(matches!(
            m.full_scan(empty_full_scan()),
            Err(ChainError::Network(_))
        ));
        // Cleared after one use — next call succeeds.
        assert!(m.full_scan(empty_full_scan()).is_ok());

        m.fail_next_sync("sync down");
        assert!(matches!(m.sync(empty_sync()), Err(ChainError::Network(_))));

        m.fail_next_broadcast("reject");
        assert!(matches!(
            m.broadcast(&empty_tx()),
            Err(ChainError::Broadcast(_))
        ));
        assert!(m.broadcasted().is_empty());

        m.fail_next_fee_estimates("no fees");
        assert!(matches!(m.fee_estimates(), Err(ChainError::Unavailable(_))));

        m.fail_next_tip_height("no tip");
        assert!(matches!(m.tip_height(), Err(ChainError::Unavailable(_))));
    }

    #[test]
    fn shared_is_object_safe() {
        let backend: Arc<dyn ChainBackend> = MemoryBackend::shared();
        assert_eq!(backend.tip_height().unwrap(), 0);
        assert!(!backend.privacy_profile().reveals_full_wallet_graph);
    }
}
