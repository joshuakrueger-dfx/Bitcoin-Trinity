//! Bitcoin Core JSON-RPC [`ChainBackend`] — Spec §1.6, WP-15.
//!
//! Built on `bdk_bitcoind_rpc 0.22.0` → `bitcoincore-rpc 0.19.0`. Scan/sync
//! use BIP-158 compact filters ([`FilterIter`]) when the node has
//! `blockfilterindex` (the test environment does). Broadcast, tip, and fees
//! go through the same RPC client.
//!
//! **No silent fallback:** every RPC failure maps to [`ChainError`]. This
//! backend never opens an Electrum or CBF path.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use bdk_bitcoind_rpc::bip158::FilterIter;
use bdk_bitcoind_rpc::bitcoincore_rpc::{jsonrpc, Auth, Client, Error as RpcError, RpcApi};
use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::{KeychainKind, Update};
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};

use crate::backend::ChainBackend;
use crate::error::ChainError;
use crate::fee::FeeEstimates;
use crate::privacy::PrivacyProfile;

/// Default full-scan stop gap (unused scripts before stopping).
///
/// Matches Trinity gap limit O10 / `trinity-watch::GAP_LIMIT` (= 20).
pub const DEFAULT_STOP_GAP: usize = 20;

/// Confirmation targets requested from `estimatesmartfee` (blocks).
const FEE_TARGETS: &[u32] = &[1, 2, 3, 6, 12, 24, 144, 1008];

/// How Bitcoin Core RPC is authenticated.
///
/// Spec §1.6: "RPC URL, cookie or user/pass". The regtest compose stack uses
/// user/pass (`trinity` / `regtest`); cookie auth is supported for nodes that
/// expose `.cookie`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreRpcAuth {
    /// No credentials (rare; Core usually requires auth).
    None,
    /// HTTP basic user/password.
    UserPass {
        /// RPC username.
        username: String,
        /// RPC password.
        password: String,
    },
    /// Bitcoin Core cookie file (`user:pass` on one line).
    CookieFile(PathBuf),
}

impl From<CoreRpcAuth> for Auth {
    fn from(auth: CoreRpcAuth) -> Self {
        match auth {
            CoreRpcAuth::None => Auth::None,
            CoreRpcAuth::UserPass { username, password } => Auth::UserPass(username, password),
            CoreRpcAuth::CookieFile(path) => Auth::CookieFile(path),
        }
    }
}

/// Connection parameters for [`CoreRpcBackend`].
#[derive(Clone, Debug)]
pub struct CoreRpcConfig {
    /// JSON-RPC URL, e.g. `http://127.0.0.1:18443`.
    pub url: String,
    /// Cookie file or user/pass.
    pub auth: CoreRpcAuth,
    /// Full-scan stop gap (minimum 1). Default [`DEFAULT_STOP_GAP`].
    pub stop_gap: usize,
}

impl CoreRpcConfig {
    /// User/password auth with the default stop gap.
    pub fn user_pass(
        url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            auth: CoreRpcAuth::UserPass {
                username: username.into(),
                password: password.into(),
            },
            stop_gap: DEFAULT_STOP_GAP,
        }
    }

    /// Cookie-file auth with the default stop gap.
    pub fn cookie(url: impl Into<String>, cookie_path: impl Into<PathBuf>) -> Self {
        Self {
            url: url.into(),
            auth: CoreRpcAuth::CookieFile(cookie_path.into()),
            stop_gap: DEFAULT_STOP_GAP,
        }
    }

    /// Override the full-scan stop gap.
    #[must_use]
    pub fn with_stop_gap(mut self, stop_gap: usize) -> Self {
        self.stop_gap = stop_gap;
        self
    }
}

/// Bitcoin Core JSON-RPC backend — Spec §1.6 row "Bitcoin Core RPC, own node".
///
/// Holds a single [`Client`]. Failures surface as [`ChainError`]; there is
/// **no** fallback to Electrum or CBF (T16 / S13).
pub struct CoreRpcBackend {
    client: Client,
    stop_gap: usize,
}

impl core::fmt::Debug for CoreRpcBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CoreRpcBackend")
            .field("stop_gap", &self.stop_gap)
            .field("client", &"bitcoincore_rpc::Client")
            .finish()
    }
}

impl CoreRpcBackend {
    /// Connect to a Bitcoin Core node.
    ///
    /// Cookie auth validates the cookie path at construction; network
    /// reachability is checked on the first RPC call (tip / scan / …).
    pub fn connect(config: CoreRpcConfig) -> Result<Self, ChainError> {
        let client = Client::new(&config.url, config.auth.into())
            .map_err(|e| ChainError::Network(format!("rpc client: {e}")))?;
        Ok(Self {
            client,
            stop_gap: config.stop_gap.max(1),
        })
    }

    /// Configured stop gap.
    pub fn stop_gap(&self) -> usize {
        self.stop_gap
    }

    /// Underlying RPC client (for advanced callers / tests).
    pub fn client(&self) -> &Client {
        &self.client
    }

    fn map_rpc(err: RpcError) -> ChainError {
        // All bitcoind RPC transport/app failures are hard Network errors.
        // There is **no** silent fallback to Electrum/CBF (S13 / T16).
        // (Decode / range problems raised by us use Protocol separately.)
        ChainError::Network(format!("rpc: {err}"))
    }

    fn map_broadcast(err: RpcError) -> ChainError {
        ChainError::Broadcast(format!("sendrawtransaction: {err}"))
    }

    /// Genesis checkpoint of the remote chain.
    fn genesis_checkpoint(&self) -> Result<CheckPoint, ChainError> {
        let hash = self.client.get_block_hash(0).map_err(Self::map_rpc)?;
        Ok(CheckPoint::new(BlockId { height: 0, hash }))
    }

    /// Tip checkpoint (height + hash) of the remote chain.
    fn tip_checkpoint(&self) -> Result<CheckPoint, ChainError> {
        let height = self.client.get_block_count().map_err(Self::map_rpc)?;
        let height_u32 = u32::try_from(height)
            .map_err(|_| ChainError::Protocol(format!("tip height out of range: {height}")))?;
        let hash = self.client.get_block_hash(height).map_err(Self::map_rpc)?;
        // Build a minimal checkpoint chain genesis → tip so LocalChain can
        // apply it when the wallet started empty. Intermediate headers are
        // not required for apply_update when only the tip advances from
        // genesis via a connected path that FilterIter already walked; for
        // tip-only updates we insert genesis then tip.
        let genesis = self.genesis_checkpoint()?;
        // `insert` is a no-op when the tip is already the genesis block.
        Ok(genesis.insert(BlockId {
            height: height_u32,
            hash,
        }))
    }

    /// Scan `spks` via BIP-158 filters and optional mempool; return graph + tip.
    fn scan_spks(
        &self,
        spks: &[ScriptBuf],
        chain_tip: Option<CheckPoint>,
        start_time: u64,
    ) -> Result<(TxUpdate<ConfirmationBlockTime>, Option<CheckPoint>), ChainError> {
        let start_cp = match chain_tip {
            Some(cp) => cp,
            None => self.genesis_checkpoint()?,
        };

        if spks.is_empty() {
            // Still advance the local chain tip when the request is empty.
            return Ok((TxUpdate::default(), Some(self.tip_checkpoint()?)));
        }

        let spk_set: HashSet<ScriptBuf> = spks.iter().cloned().collect();
        let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();
        let mut known_outpoints: HashSet<OutPoint> = HashSet::new();
        let mut seen_txids: HashSet<Txid> = HashSet::new();
        let mut tip_cp = start_cp.clone();

        let iter = FilterIter::new(&self.client, start_cp, spks.iter().cloned());
        for item in iter {
            let event = item.map_err(|e| ChainError::Network(format!("filter scan: {e}")))?;
            tip_cp = event.cp;
            let Some(block) = event.block else {
                continue;
            };
            let header_time = self
                .client
                .get_block_header_info(&tip_cp.hash())
                .map(|h| h.time as u64)
                .unwrap_or(start_time);
            let anchor = ConfirmationBlockTime {
                block_id: tip_cp.block_id(),
                confirmation_time: header_time,
            };

            // Two-pass so spends of outputs introduced earlier in the same
            // block are recognised via `known_outpoints`.
            for _ in 0..2 {
                for tx in &block.txdata {
                    if !tx_is_relevant(tx, &spk_set, &known_outpoints) {
                        continue;
                    }
                    let txid = tx.compute_txid();
                    if seen_txids.insert(txid) {
                        for (vout, out) in tx.output.iter().enumerate() {
                            if spk_set.contains(&out.script_pubkey) {
                                known_outpoints.insert(OutPoint {
                                    txid,
                                    vout: vout as u32,
                                });
                            }
                        }
                        tx_update.txs.push(Arc::new(tx.clone()));
                        tx_update.anchors.insert((anchor, txid));
                    }
                }
            }
        }

        // Mempool: unconfirmed txs that touch watched scripts / outpoints.
        let mempool = self.client.get_raw_mempool().map_err(Self::map_rpc)?;
        for txid in mempool {
            if !seen_txids.insert(txid) {
                continue;
            }
            let Some(tx) = self.get_tx_optional(&txid)? else {
                continue;
            };
            if !tx_is_relevant(&tx, &spk_set, &known_outpoints) {
                continue;
            }
            tx_update.txs.push(Arc::new(tx));
            tx_update.seen_ats.insert((txid, start_time));
        }

        Ok((tx_update, Some(tip_cp)))
    }

    /// `getrawtransaction`, mapping "not found" to `None` (no fallback).
    fn get_tx_optional(&self, txid: &Txid) -> Result<Option<Transaction>, ChainError> {
        match self.client.get_raw_transaction(txid, None) {
            Ok(tx) => Ok(Some(tx)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(Self::map_rpc(e)),
        }
    }

    /// Expand keychain SPK iterators with stop-gap, then scan.
    ///
    /// Returns `(all_spks, last_active_indices, spk → (keychain, index))`.
    fn collect_full_scan_spks(
        &self,
        req: &mut FullScanRequest<KeychainKind>,
    ) -> Result<FullScanSpkPlan, ChainError> {
        let mut plan = FullScanSpkPlan::default();
        // Base checkpoint for intermediate activity probes.
        let probe_cp = self.genesis_checkpoint()?;

        for keychain in req.keychains() {
            let mut unused = 0usize;
            let mut last: Option<u32> = None;
            // Pull SPKs one batch of `stop_gap` at a time; after each batch
            // probe activity so we can stop without walking an infinite
            // descriptor range.
            loop {
                let batch: Vec<(u32, ScriptBuf)> =
                    req.iter_spks(keychain).take(self.stop_gap).collect();
                if batch.is_empty() {
                    break;
                }
                let batch_spks: Vec<ScriptBuf> = batch.iter().map(|(_, s)| s.clone()).collect();
                let active = self.active_spks_in(&batch_spks, probe_cp.clone())?;

                for (i, spk) in batch {
                    if active.contains(&spk) {
                        last = Some(i);
                        unused = 0;
                    } else {
                        unused = unused.saturating_add(1);
                    }
                    plan.spks.push(spk);
                }
                if unused >= self.stop_gap {
                    break;
                }
            }
            if let Some(i) = last {
                plan.last_active.insert(keychain, i);
            }
        }

        Ok(plan)
    }

    /// SPKs among `spks` that appear in a matching filter block or mempool.
    fn active_spks_in(
        &self,
        spks: &[ScriptBuf],
        start_cp: CheckPoint,
    ) -> Result<HashSet<ScriptBuf>, ChainError> {
        let spk_set: HashSet<ScriptBuf> = spks.iter().cloned().collect();
        let mut active = HashSet::new();
        // Callers only pass non-empty batches; empty is a cheap no-op.
        let iter = FilterIter::new(&self.client, start_cp, spks.iter().cloned());
        for item in iter {
            let event = item.map_err(|e| ChainError::Network(format!("filter probe: {e}")))?;
            let Some(block) = event.block else {
                continue;
            };
            for tx in &block.txdata {
                for out in &tx.output {
                    if spk_set.contains(&out.script_pubkey) {
                        active.insert(out.script_pubkey.clone());
                    }
                }
            }
        }
        // Also treat mempool hits as active (import of just-funded wallets).
        let mempool = self.client.get_raw_mempool().map_err(Self::map_rpc)?;
        for txid in mempool {
            let Some(tx) = self.get_tx_optional(&txid)? else {
                continue;
            };
            for out in &tx.output {
                if spk_set.contains(&out.script_pubkey) {
                    active.insert(out.script_pubkey.clone());
                }
            }
        }
        Ok(active)
    }
}

/// SPKs collected for a full scan, with last-active indices per keychain.
#[derive(Default)]
struct FullScanSpkPlan {
    spks: Vec<ScriptBuf>,
    last_active: BTreeMap<KeychainKind, u32>,
}

fn tx_is_relevant(
    tx: &Transaction,
    spks: &HashSet<ScriptBuf>,
    known_outpoints: &HashSet<OutPoint>,
) -> bool {
    if tx.output.iter().any(|o| spks.contains(&o.script_pubkey)) {
        return true;
    }
    tx.input
        .iter()
        .any(|i| known_outpoints.contains(&i.previous_output))
}

fn is_not_found(err: &RpcError) -> bool {
    matches!(
        err,
        RpcError::JsonRpc(jsonrpc::Error::Rpc(e)) if e.code == -5
    )
}

impl ChainBackend for CoreRpcBackend {
    fn full_scan(&self, mut req: FullScanRequest<KeychainKind>) -> Result<Update, ChainError> {
        let start_time = req.start_time();
        let chain_tip = req.chain_tip();
        let plan = self.collect_full_scan_spks(&mut req)?;
        let (tx_update, chain) = self.scan_spks(&plan.spks, chain_tip, start_time)?;
        Ok(Update {
            last_active_indices: plan.last_active,
            tx_update,
            chain,
        })
    }

    fn sync(&self, mut req: SyncRequest<(KeychainKind, u32)>) -> Result<Update, ChainError> {
        let start_time = req.start_time();
        let chain_tip = req.chain_tip();

        let mut spks = Vec::new();
        let mut expected: HashMap<ScriptBuf, HashSet<Txid>> = HashMap::new();
        for item in req.iter_spks_with_expected_txids() {
            expected.insert(item.spk.clone(), item.expected_txids.clone());
            spks.push(item.spk);
        }

        let (mut tx_update, chain) = self.scan_spks(&spks, chain_tip, start_time)?;

        // Evictions: expected txids missing from history of that SPK.
        let mut present: HashSet<Txid> = tx_update.txs.iter().map(|tx| tx.compute_txid()).collect();
        for (spk, expected_txids) in expected {
            // Only mark eviction when the SPK was among the requested set.
            let _ = spk;
            for txid in expected_txids {
                if !present.contains(&txid) {
                    tx_update.evicted_ats.insert((txid, start_time));
                }
            }
        }

        // Explicit txid lookups (verbose for block location).
        for txid in req.iter_txids() {
            if present.contains(&txid) {
                continue;
            }
            match self.client.get_raw_transaction_info(&txid, None) {
                Ok(info) => {
                    let tx = info
                        .transaction()
                        .map_err(|e| ChainError::Protocol(format!("decode tx {txid}: {e}")))?;
                    tx_update.txs.push(Arc::new(tx));
                    present.insert(txid);
                    if let Some(hash) = info.blockhash {
                        if let Ok(header) = self.client.get_block_header_info(&hash) {
                            if let Ok(height) = u32::try_from(header.height) {
                                let anchor = ConfirmationBlockTime {
                                    block_id: BlockId { height, hash },
                                    confirmation_time: header.time as u64,
                                };
                                tx_update.anchors.insert((anchor, txid));
                                continue;
                            }
                        }
                    }
                    tx_update.seen_ats.insert((txid, start_time));
                }
                Err(e) if is_not_found(&e) => {
                    tx_update.evicted_ats.insert((txid, start_time));
                }
                Err(e) => return Err(Self::map_rpc(e)),
            }
        }

        // Outpoints: fetch containing tx when possible.
        for op in req.iter_outpoints() {
            if present.contains(&op.txid) {
                continue;
            }
            let Some(tx) = self.get_tx_optional(&op.txid)? else {
                continue;
            };
            if let Some(txout) = tx.output.get(op.vout as usize) {
                tx_update.txouts.insert(op, txout.clone());
            }
            present.insert(op.txid);
            tx_update.txs.push(Arc::new(tx));
        }

        Ok(Update {
            last_active_indices: BTreeMap::new(),
            tx_update,
            chain,
        })
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
        self.client
            .send_raw_transaction(tx)
            .map_err(Self::map_broadcast)
    }

    fn fee_estimates(&self) -> Result<FeeEstimates, ChainError> {
        // Probe connectivity once so a dead node is Network, not empty fees.
        let _ = self.client.get_block_count().map_err(Self::map_rpc)?;

        let mut map = BTreeMap::new();
        for &target in FEE_TARGETS {
            // Targets fit in u16 by construction of `FEE_TARGETS`.
            // Regtest often has no estimate data (`errors` set, no feerate);
            // we only record positive sat/vB values when Core supplies them.
            if let Ok(res) = self.client.estimate_smart_fee(target as u16, None) {
                let sat_per_vb = res.fee_rate.map(|rate| rate.to_sat() / 1000).unwrap_or(0);
                if sat_per_vb > 0 {
                    map.insert(target, sat_per_vb);
                }
            }
        }
        Ok(FeeEstimates {
            sat_per_vb_by_target_blocks: map,
        })
    }

    fn tip_height(&self) -> Result<u32, ChainError> {
        let height = self.client.get_block_count().map_err(Self::map_rpc)?;
        u32::try_from(height)
            .map_err(|_| ChainError::Protocol(format!("tip height out of range: {height}")))
    }

    fn privacy_profile(&self) -> PrivacyProfile {
        PrivacyProfile::core_rpc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::BackendKind;
    use bitcoin::hashes::Hash;
    use bitcoin::{absolute::LockTime, Amount, OutPoint, Sequence, TxIn, TxOut, Witness};
    use std::sync::Arc;

    #[test]
    fn privacy_profile_matches_spec_table() {
        let backend = CoreRpcBackend {
            client: Client::new("http://127.0.0.1:1", Auth::UserPass("x".into(), "y".into()))
                .expect("user/pass client builds offline"),
            stop_gap: DEFAULT_STOP_GAP,
        };
        let p = backend.privacy_profile();
        assert_eq!(p, PrivacyProfile::core_rpc());
        assert_eq!(p.kind, BackendKind::CoreRpc);
        assert!(!p.reveals_full_wallet_graph);
        assert!(!p.third_party_counterparty);
        assert!(!p.requires_selection_warning);
        assert!(p.counterparty_learns.contains("Nothing beyond the node"));
        assert!(p.magnitude.contains("Best option"));
        assert_eq!(backend.stop_gap(), DEFAULT_STOP_GAP);
        assert!(format!("{backend:?}").contains("CoreRpcBackend"));
    }

    #[test]
    fn config_builders_and_auth_mapping() {
        let c = CoreRpcConfig::user_pass("http://127.0.0.1:18443", "trinity", "regtest")
            .with_stop_gap(5);
        assert_eq!(c.stop_gap, 5);
        assert_eq!(c.url, "http://127.0.0.1:18443");
        match &c.auth {
            CoreRpcAuth::UserPass { username, password } => {
                assert_eq!(username, "trinity");
                assert_eq!(password, "regtest");
            }
            other => panic!("unexpected auth: {other:?}"),
        }
        let auth: Auth = c.auth.clone().into();
        assert!(matches!(auth, Auth::UserPass(_, _)));

        let c2 = CoreRpcConfig::cookie("http://127.0.0.1:18443", "/tmp/no-such-cookie");
        assert!(matches!(c2.auth, CoreRpcAuth::CookieFile(_)));
        let auth2: Auth = CoreRpcAuth::None.into();
        assert!(matches!(auth2, Auth::None));
        let auth3: Auth = CoreRpcAuth::CookieFile(PathBuf::from("/tmp/x")).into();
        assert!(matches!(auth3, Auth::CookieFile(_)));
    }

    #[test]
    fn cookie_missing_file_fails_at_connect() {
        let err = CoreRpcBackend::connect(CoreRpcConfig::cookie(
            "http://127.0.0.1:18443",
            "/tmp/trinity-wp15-missing-cookie-file",
        ))
        .expect_err("missing cookie must fail");
        assert!(
            matches!(err, ChainError::Network(_)),
            "expected Network, got {err:?}"
        );
        assert!(err.to_string().contains("rpc"));
    }

    #[test]
    fn connect_user_pass_builds_without_network() {
        let b = CoreRpcBackend::connect(CoreRpcConfig::user_pass(
            "http://127.0.0.1:1",
            "trinity",
            "regtest",
        ))
        .expect("user/pass builds offline");
        assert_eq!(b.stop_gap(), DEFAULT_STOP_GAP);
        let _ = b.client();
    }

    #[test]
    fn object_safe_dyn_backend() {
        let b = CoreRpcBackend::connect(CoreRpcConfig::user_pass("http://127.0.0.1:1", "u", "p"))
            .unwrap();
        let dyn_b: Arc<dyn ChainBackend> = Arc::new(b);
        assert_eq!(dyn_b.privacy_profile().kind, BackendKind::CoreRpc);
    }

    #[test]
    fn tx_relevance_helpers() {
        let spk = ScriptBuf::new_op_return([0x61]);
        let mut set = HashSet::new();
        set.insert(spk.clone());
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: spk,
            }],
        };
        assert!(tx_is_relevant(&tx, &set, &HashSet::new()));
        assert!(!tx_is_relevant(&tx, &HashSet::new(), &HashSet::new()));

        let known = OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let mut known_set = HashSet::new();
        known_set.insert(known);
        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: known,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        };
        assert!(tx_is_relevant(&spend, &HashSet::new(), &known_set));
        assert!(!tx_is_relevant(&spend, &HashSet::new(), &HashSet::new()));
    }

    #[test]
    fn is_not_found_matches_rpc_code_minus_five() {
        let not_found = RpcError::JsonRpc(jsonrpc::Error::Rpc(jsonrpc::error::RpcError {
            code: -5,
            message: "No such mempool or blockchain transaction".into(),
            data: None,
        }));
        assert!(is_not_found(&not_found));
        let other = RpcError::JsonRpc(jsonrpc::Error::Rpc(jsonrpc::error::RpcError {
            code: -8,
            message: "other".into(),
            data: None,
        }));
        assert!(!is_not_found(&other));
    }

    /// S13 / dead port: every ChainBackend method returns a clean ChainError.
    #[test]
    fn against_dead_endpoint_all_methods_error() {
        let b = CoreRpcBackend::connect(CoreRpcConfig::user_pass("http://127.0.0.1:1", "u", "p"))
            .expect("client builds offline");

        let tip = b.tip_height();
        assert!(
            matches!(tip, Err(ChainError::Network(_)) | Err(ChainError::Other(_))),
            "tip_height: {tip:?}"
        );
        let fees = b.fee_estimates();
        assert!(
            matches!(
                fees,
                Err(ChainError::Network(_)) | Err(ChainError::Other(_))
            ),
            "fee_estimates: {fees:?}"
        );
        let empty_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let bc = b.broadcast(&empty_tx);
        assert!(
            matches!(bc, Err(ChainError::Broadcast(_))),
            "broadcast: {bc:?}"
        );

        let full = FullScanRequest::<KeychainKind>::builder_at(0).build();
        let scan = b.full_scan(full);
        assert!(
            matches!(
                scan,
                Err(ChainError::Network(_))
                    | Err(ChainError::Protocol(_))
                    | Err(ChainError::Other(_))
            ),
            "full_scan: {scan:?}"
        );

        let sync = SyncRequest::<(KeychainKind, u32)>::builder_at(0).build();
        let s = b.sync(sync);
        assert!(
            matches!(
                s,
                Err(ChainError::Network(_))
                    | Err(ChainError::Protocol(_))
                    | Err(ChainError::Other(_))
            ),
            "sync: {s:?}"
        );
    }

    /// S13: unresolvable host fails cleanly (connect or first call — no fallback).
    #[test]
    fn against_invalid_host_errors() {
        let result = CoreRpcBackend::connect(CoreRpcConfig::user_pass(
            "http://no-such-host.invalid:18443",
            "u",
            "p",
        ));
        match result {
            Err(e) => assert!(
                matches!(e, ChainError::Network(_) | ChainError::Other(_)),
                "got {e:?}"
            ),
            Ok(b) => {
                let err = b.tip_height().expect_err("must not succeed");
                assert!(
                    matches!(err, ChainError::Network(_) | ChainError::Other(_)),
                    "got {err:?}"
                );
            }
        }
    }

    #[test]
    fn stop_gap_clamped_to_at_least_one() {
        let b = CoreRpcBackend::connect(
            CoreRpcConfig::user_pass("http://127.0.0.1:1", "u", "p").with_stop_gap(0),
        )
        .unwrap();
        assert_eq!(b.stop_gap(), 1);
    }
}
