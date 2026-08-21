//! Compact Block Filters backend (BIP-157/158) — Spec §1.6, WP-16.
//!
//! Built on `bdk_kyoto 0.17.0` → `bip157 0.6.3`. The light client is reactive
//! (long-running node + filter events); this module bridges that model to the
//! synchronous, request/response [`ChainBackend`] trait used by Electrum and
//! Core RPC.
//!
//! ## Privacy (Appendix B.3 / O3)
//!
//! Block-fetch after a filter match is routed to a **uniformly random**
//! connected peer (`bip157` `node.rs::get_blocks` → `peer_map.rs::send_random`),
//! not deliberately away from the filter peer and not with netgroup diversity.
//! [`privacy_profile`](CbfBackend::privacy_profile) therefore uses
//! [`PrivacyProfile::cbf`] — "more private than a third-party server, not
//! anonymous" / "clearly better than Electrum, not zero". No unqualified
//! "private" claim.
//!
//! ## No silent fallback
//!
//! Transport failures map to [`ChainError`]. There is no path to Electrum or
//! Core RPC from this type.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bdk_chain::spk_client::{FullScanRequest, SyncRequest};
use bdk_chain::spk_txout::SpkTxOutIndex;
use bdk_chain::{BlockId, CheckPoint, ConfirmationBlockTime, IndexedTxGraph, Indexer};
use bdk_wallet::{KeychainKind, Update};
use bitcoin::{Network, OutPoint, ScriptBuf, Transaction, Txid};

use bdk_kyoto::bip157::chain::{BlockHeaderChanges, ChainState};
use bdk_kyoto::bip157::tokio;
use bdk_kyoto::bip157::{
    Builder, Client, Event, HashCheckpoint, IndexedFilter, Node, Requester, Socks5Proxy,
    TrustedPeer,
};

use crate::backend::ChainBackend;
use crate::error::ChainError;
use crate::fee::FeeEstimates;
use crate::privacy::PrivacyProfile;

/// Default maximum time to wait for a single CBF operation (header/filter sync
/// + optional block fetch) before returning [`ChainError::Network`].
const DEFAULT_OP_TIMEOUT: Duration = Duration::from_secs(120);

/// Default recovery depth: scripts per keychain taken from a full-scan request.
const DEFAULT_FULL_SCAN_SCRIPT_LIMIT: usize = 200;

/// Walk-back depth for reorg safety when resuming from a local tip (matches
/// `bdk_kyoto` `IMPOSSIBLE_REORG_DEPTH`).
const REORG_WALKBACK: usize = 7;

/// Configuration for a BIP-157/158 compact-filter peer set.
///
/// Spec §1.6: peer list or DNS seeds, optional fixed peers, optional Tor
/// (`socks5_proxy`). When [`whitelist_only`](CbfConfig::whitelist_only) is set,
/// the node does not DNS-seed and only connects to the configured peers.
#[derive(Clone, Debug)]
pub struct CbfConfig {
    /// Bitcoin network the peers are expected to serve.
    pub network: Network,
    /// Preferred / fixed peers (IP or hostname). Empty ⇒ DNS seeds only
    /// (mainnet/signet/testnet; useless on regtest without seeds).
    pub peers: Vec<TrustedPeer>,
    /// When `true`, never discover peers beyond [`peers`](Self::peers).
    pub whitelist_only: bool,
    /// Minimum peer connections to maintain (clamped by bip157 to 1..=15).
    pub required_peers: u8,
    /// Directory for bip157 header/filter state. When `None`, the process CWD
    /// is used (prefer a dedicated path in production and tests).
    pub data_dir: Option<PathBuf>,
    /// Optional Socks5 proxy (typically a local Tor daemon).
    pub socks5_proxy: Option<Socks5Proxy>,
    /// Peer TCP handshake timeout. `None` ⇒ bip157 default (2 s).
    pub handshake_timeout: Option<Duration>,
    /// Peer response timeout. `None` ⇒ bip157 default (5 s).
    pub response_timeout: Option<Duration>,
    /// Wall-clock cap for one scan/broadcast/tip/fee call.
    pub operation_timeout: Duration,
    /// Max script pubkeys consumed per keychain from a [`FullScanRequest`].
    ///
    /// BDK's `Wallet::start_full_scan()` yields an **unbounded** SPK iterator;
    /// Electrum applies a stop-gap while querying. CBF must materialise scripts
    /// before matching filters, so this hard cap is the recovery depth
    /// (default 200). Raise for deep-gap restores.
    pub full_scan_script_limit: usize,
}

impl CbfConfig {
    /// Regtest config aimed at a single local Core peer (WP-02 P2P port).
    ///
    /// `whitelist_only` is set so the node does not try public DNS seeds.
    pub fn regtest_peer(addr: SocketAddr) -> Self {
        Self {
            network: Network::Regtest,
            peers: vec![TrustedPeer::from_socket_addr(addr)],
            whitelist_only: true,
            required_peers: 1,
            data_dir: None,
            socks5_proxy: None,
            handshake_timeout: Some(Duration::from_secs(5)),
            response_timeout: Some(Duration::from_secs(10)),
            operation_timeout: DEFAULT_OP_TIMEOUT,
            full_scan_script_limit: DEFAULT_FULL_SCAN_SCRIPT_LIMIT,
        }
    }

    /// Builder starting point for `network` with empty peer list.
    pub fn new(network: Network) -> Self {
        Self {
            network,
            peers: Vec::new(),
            whitelist_only: false,
            required_peers: 1,
            data_dir: None,
            socks5_proxy: None,
            handshake_timeout: None,
            response_timeout: None,
            operation_timeout: DEFAULT_OP_TIMEOUT,
            full_scan_script_limit: DEFAULT_FULL_SCAN_SCRIPT_LIMIT,
        }
    }

    /// Add a preferred peer.
    pub fn peer(mut self, peer: impl Into<TrustedPeer>) -> Self {
        self.peers.push(peer.into());
        self
    }

    /// Add a peer from host IP and port.
    pub fn peer_ip(mut self, ip: impl Into<IpAddr>, port: u16) -> Self {
        self.peers.push(TrustedPeer::from((ip.into(), Some(port))));
        self
    }

    /// Only connect to configured peers (no DNS / addr gossip).
    pub fn whitelist_only(mut self) -> Self {
        self.whitelist_only = true;
        self
    }

    /// Persist bip157 state under `path`.
    pub fn data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(path.into());
        self
    }

    /// Route traffic through a Socks5 proxy (Tor).
    pub fn socks5_proxy(mut self, proxy: impl Into<Socks5Proxy>) -> Self {
        self.socks5_proxy = Some(proxy.into());
        self
    }

    /// How many peers to maintain.
    pub fn required_peers(mut self, n: u8) -> Self {
        self.required_peers = n;
        self
    }

    /// Cap for one backend method call.
    pub fn operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout;
        self
    }

    /// Max scripts per keychain for full scan (recovery depth).
    pub fn full_scan_script_limit(mut self, limit: usize) -> Self {
        self.full_scan_script_limit = limit.max(1);
        self
    }
}

/// What a short-lived node should do once filters are synced.
enum ReadyOp {
    Tip,
    Fees,
    Broadcast(Transaction),
}

enum ReadyResult {
    Tip(u32),
    Fees(FeeEstimates),
    Broadcast(Txid),
}

/// Compact Block Filters implementation of [`ChainBackend`].
///
/// Each method starts a bip157 node against the configured peers, performs the
/// work, and shuts the node down. State under [`CbfConfig::data_dir`] is reused
/// across calls when set. Failures surface as [`ChainError`]; there is **no**
/// fallback to Electrum or Core RPC.
pub struct CbfBackend {
    config: CbfConfig,
    /// Dedicated multi-thread runtime driving bip157 (async).
    runtime: tokio::runtime::Runtime,
    /// Last known tip height, updated after successful scan / tip query.
    tip_cache: Mutex<Option<u32>>,
}

impl core::fmt::Debug for CbfBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CbfBackend")
            .field("network", &self.config.network)
            .field("peers", &self.config.peers.len())
            .field("whitelist_only", &self.config.whitelist_only)
            .field("required_peers", &self.config.required_peers)
            .finish()
    }
}

impl CbfBackend {
    /// Construct a backend from `config`.
    ///
    /// Builds a multi-thread tokio runtime for bip157. Fails only if the
    /// runtime cannot be created (rare host misconfiguration).
    pub fn new(config: CbfConfig) -> Result<Self, ChainError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("trinity-cbf")
            .build()
            .map_err(|e| ChainError::Other(format!("tokio runtime: {e}")))?;
        Ok(Self {
            config,
            runtime,
            tip_cache: Mutex::new(None),
        })
    }

    /// Shared configuration (peers, network, Tor, …).
    pub fn config(&self) -> &CbfConfig {
        &self.config
    }

    fn build_node(&self, chain_state: ChainState) -> (Node, Client) {
        let mut builder = Builder::new(self.config.network)
            .required_peers(self.config.required_peers)
            .chain_state(chain_state)
            .fetch_witness_data();

        if self.config.whitelist_only {
            builder = builder.whitelist_only();
        }
        if !self.config.peers.is_empty() {
            builder = builder.add_peers(self.config.peers.clone());
        }
        if let Some(ref dir) = self.config.data_dir {
            builder = builder.data_dir(dir.clone());
        }
        if let Some(proxy) = self.config.socks5_proxy.clone() {
            builder = builder.socks5_proxy(proxy);
        }
        if let Some(t) = self.config.handshake_timeout {
            builder = builder.handshake_timeout(t);
        }
        if let Some(t) = self.config.response_timeout {
            builder = builder.response_timeout(t);
        }

        builder.build()
    }

    fn chain_state_for_network(network: Network, tip: Option<CheckPoint>) -> ChainState {
        match tip {
            Some(cp) => ChainState::Checkpoint(walk_back_reorg(cp)),
            None => {
                let params = bitcoin::params::Params::from(network);
                ChainState::Checkpoint(HashCheckpoint::from_genesis(params))
            }
        }
    }

    fn genesis_checkpoint(network: Network) -> CheckPoint {
        let genesis = bitcoin::constants::genesis_block(network);
        CheckPoint::new(BlockId {
            height: 0,
            hash: genesis.block_hash(),
        })
    }

    /// Run a filter scan for the given scripts and produce a wallet [`Update`].
    fn scan_indexed(
        &self,
        index: RelevantSpkIndex,
        chain_tip: Option<CheckPoint>,
    ) -> Result<Update, ChainError> {
        let network = self.config.network;
        let spk_cache: HashSet<ScriptBuf> = index.all_spks().values().cloned().collect();
        let chain_state = Self::chain_state_for_network(network, chain_tip.clone());
        let (node, client) = self.build_node(chain_state);
        let Client {
            requester,
            info_rx: _,
            warn_rx: _,
            mut event_rx,
        } = client;

        let timeout = self.config.operation_timeout;
        let initial_cp = chain_tip.unwrap_or_else(|| Self::genesis_checkpoint(network));
        let shutdown = requester.clone();
        let handle = self.runtime.handle().clone();

        // Wall-clock timeout on a helper thread: bip157 may park OS threads on
        // a dead peer such that a pure `tokio::time::timeout` is never polled.
        let result = run_with_wall_timeout(timeout, move || {
            handle.block_on(async move {
                tokio::spawn(async move {
                    let _ = node.run().await;
                });

                let mut graph = IndexedTxGraph::<ConfirmationBlockTime, _>::new(index);
                let mut cp = initial_cp;
                let mut queued: Vec<bitcoin::BlockHash> = Vec::new();

                loop {
                    let event = event_rx.recv().await.ok_or_else(|| {
                        ChainError::Network("cbf node stopped before filters synced".into())
                    })?;

                    match event {
                        Event::IndexedFilter(filter) => {
                            if filter_matches(&filter, &spk_cache) {
                                queued.push(filter.block_hash());
                            }
                        }
                        Event::ChainUpdate(changeset) => {
                            apply_chain_event(&mut cp, &changeset);
                        }
                        Event::FiltersSynced(update) => {
                            for hash in core::mem::take(&mut queued) {
                                let block = requester.get_block(hash).await.map_err(|e| {
                                    ChainError::Network(format!("cbf get_block: {e}"))
                                })?;
                                let _ = graph.apply_block_relevant(&block.block, block.height);
                            }

                            let tip = update.tip();
                            cp = cp.insert(BlockId {
                                height: tip.height,
                                hash: tip.hash,
                            });

                            let last_active = last_active_indices(&graph.index.inner);
                            let tx_update = graph.graph().clone().into();
                            return Ok(Update {
                                last_active_indices: last_active,
                                tx_update,
                                chain: Some(cp),
                            });
                        }
                    }
                }
            })
        });

        let _ = shutdown.shutdown();

        if let Ok(ref update) = result {
            if let Some(ref chain) = update.chain {
                *self.tip_cache.lock().expect("tip mutex") = Some(chain.height());
            }
        }
        result
    }

    /// Spin up a node, wait until filters are synced, then run `op`.
    fn with_synced(&self, op: ReadyOp) -> Result<ReadyResult, ChainError> {
        let chain_state = Self::chain_state_for_network(self.config.network, None);
        let (node, client) = self.build_node(chain_state);
        let Client {
            requester,
            info_rx: _,
            warn_rx: _,
            mut event_rx,
        } = client;
        let timeout = self.config.operation_timeout;
        let shutdown = requester.clone();
        let handle = self.runtime.handle().clone();
        let is_broadcast = matches!(op, ReadyOp::Broadcast(_));
        let reached_submit = Arc::new(AtomicBool::new(false));
        let reached_for_wait = Arc::clone(&reached_submit);
        let reached_for_work = Arc::clone(&reached_submit);
        let timeout_secs = timeout.as_secs();

        // Timeout before `submit_package` (dead peer, filter sync) → Network.
        // Timeout after `submit_package` started (peer never sent `getdata`) →
        // DeliveryUnconfirmed. `submit_package` Err → Broadcast. Disconnected
        // worker → Network. The wall deadline is unchanged.
        let result = run_with_wall_timeout_or(
            timeout,
            move || {
                map_operation_timeout(
                    is_broadcast,
                    reached_for_wait.load(Ordering::SeqCst),
                    timeout_secs,
                )
            },
            move || {
                handle.block_on(async move {
                    tokio::spawn(async move {
                        let _ = node.run().await;
                    });

                    loop {
                        match event_rx.recv().await {
                            Some(Event::FiltersSynced(_)) => break,
                            Some(_) => continue,
                            None => {
                                return Err(ChainError::Network(
                                    "cbf node stopped before ready".into(),
                                ));
                            }
                        }
                    }
                    run_ready_op(&requester, op, &reached_for_work).await
                })
            },
        );

        let _ = shutdown.shutdown();
        result
    }
}

/// Run `f` on a detached thread and enforce a wall-clock deadline.
///
/// Returns [`ChainError::Network`] if `f` has not completed when `timeout`
/// elapses. The worker thread is abandoned (the bip157 node is shut down by
/// the caller via [`Requester::shutdown`]).
fn run_with_wall_timeout<T, F>(timeout: Duration, f: F) -> Result<T, ChainError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ChainError> + Send + 'static,
{
    let secs = timeout.as_secs();
    run_with_wall_timeout_or(
        timeout,
        move || ChainError::Network(format!("cbf operation timed out after {secs}s")),
        f,
    )
}

/// Wall-clock deadline → error. Broadcast that has started `submit_package`
/// (`reached_submit`) is [`ChainError::DeliveryUnconfirmed`]; anything else
/// is [`ChainError::Network`]. Isolated so the four combinations are testable
/// without a peer or a wait.
fn map_operation_timeout(
    is_broadcast: bool,
    reached_submit: bool,
    timeout_secs: u64,
) -> ChainError {
    if is_broadcast && reached_submit {
        ChainError::DeliveryUnconfirmed
    } else {
        ChainError::Network(format!("cbf operation timed out after {timeout_secs}s"))
    }
}

/// Like [`run_with_wall_timeout`], but the timeout error is supplied by the
/// caller so broadcast can map a hang after `submit_package` to
/// [`ChainError::DeliveryUnconfirmed`] without changing scan/tip/fee timeouts.
fn run_with_wall_timeout_or<T, F, E>(
    timeout: Duration,
    on_timeout: E,
    f: F,
) -> Result<T, ChainError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ChainError> + Send + 'static,
    E: FnOnce() -> ChainError,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("trinity-cbf-op".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .map_err(|e| ChainError::Other(format!("cbf worker spawn: {e}")))?;

    match rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(on_timeout()),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(ChainError::Network(
            "cbf worker ended without a result".into(),
        )),
    }
}

async fn run_ready_op(
    requester: &Requester,
    op: ReadyOp,
    reached_submit: &AtomicBool,
) -> Result<ReadyResult, ChainError> {
    match op {
        ReadyOp::Tip => {
            let tip = requester
                .chain_tip()
                .await
                .map_err(|e| ChainError::Unavailable(format!("cbf chain tip: {e}")))?;
            Ok(ReadyResult::Tip(tip.height))
        }
        ReadyOp::Fees => {
            // Peer mempool minimum (BIP133) — the only feerate bip157 exposes
            // without scanning an arbitrary block. Map to short-horizon targets;
            // CBF does not provide estimatesmartfee-style multi-horizon curves.
            let rate = requester
                .broadcast_min_feerate()
                .await
                .map_err(|e| ChainError::Unavailable(format!("cbf fee filter: {e}")))?;
            let sat_vb = rate.to_sat_per_vb_ceil().max(1);
            Ok(ReadyResult::Fees(FeeEstimates::from_targets([
                (1, sat_vb),
                (6, sat_vb),
            ])))
        }
        ReadyOp::Broadcast(tx) => {
            // Earliest honest point: we are about to call submit_package.
            // Setting the flag at FiltersSynced would claim an announcement
            // that has not started (timeout between sync and send).
            reached_submit.store(true, Ordering::SeqCst);
            let txid = tx.compute_txid();
            requester
                .submit_package(tx)
                .await
                .map_err(|e| ChainError::Broadcast(format!("cbf broadcast: {e}")))?;
            Ok(ReadyResult::Broadcast(txid))
        }
    }
}

fn filter_matches(filter: &IndexedFilter, spks: &HashSet<ScriptBuf>) -> bool {
    filter.contains_any(spks.iter())
}

fn apply_chain_event(cp: &mut CheckPoint, event: &BlockHeaderChanges) {
    match event {
        BlockHeaderChanges::Connected(at) => {
            let block_id = BlockId {
                hash: at.block_hash(),
                height: at.height,
            };
            *cp = cp.clone().insert(block_id);
        }
        BlockHeaderChanges::Reorganized {
            accepted,
            reorganized: _,
        } => {
            for header in accepted {
                let block_id = BlockId {
                    hash: header.block_hash(),
                    height: header.height,
                };
                *cp = cp.clone().insert(block_id);
            }
        }
        BlockHeaderChanges::ForkAdded(_) => {}
    }
}

fn walk_back_reorg(checkpoint: CheckPoint) -> HashCheckpoint {
    let mut ret = HashCheckpoint::new(checkpoint.height(), checkpoint.hash());
    for (index, next) in checkpoint.iter().enumerate() {
        if index > REORG_WALKBACK {
            return ret;
        }
        ret = HashCheckpoint::new(next.height(), next.hash());
    }
    ret
}

/// Scripts plus request-carried predecessors, so a changeless spend of an
/// already-known output is relevant without fetching that output from a peer.
///
/// `SpkTxOutIndex::is_relevant` only treats an input as ours when the spent
/// outpoint is already in `txouts`. That map is filled by `scan_txout`, which
/// needs a [`bitcoin::TxOut`]. [`SyncRequest`] does not carry TxOuts: wallet
/// `start_sync_with_revealed_spks` puts canonical txs in `expected_spk_txids`
/// and (optionally) raw [`OutPoint`]s in `outpoints`. Matching those locally
/// is the input-side of relevance; the output-side (pay-to-watched-script)
/// stays `inner.is_relevant`.
#[derive(Debug)]
struct RelevantSpkIndex {
    inner: SpkTxOutIndex<(KeychainKind, u32)>,
    known_outpoints: HashSet<OutPoint>,
    known_txids: HashSet<Txid>,
}

impl RelevantSpkIndex {
    fn scripts_only(inner: SpkTxOutIndex<(KeychainKind, u32)>) -> Self {
        Self {
            inner,
            known_outpoints: HashSet::new(),
            known_txids: HashSet::new(),
        }
    }

    fn all_spks(&self) -> &BTreeMap<(KeychainKind, u32), ScriptBuf> {
        self.inner.all_spks()
    }
}

impl Indexer for RelevantSpkIndex {
    type ChangeSet = ();

    fn index_txout(&mut self, outpoint: OutPoint, txout: &bitcoin::TxOut) -> Self::ChangeSet {
        self.inner.index_txout(outpoint, txout)
    }

    fn index_tx(&mut self, tx: &Transaction) -> Self::ChangeSet {
        self.inner.index_tx(tx)
    }

    fn apply_changeset(&mut self, changeset: Self::ChangeSet) {
        self.inner.apply_changeset(changeset)
    }

    fn initial_changeset(&self) -> Self::ChangeSet {
        self.inner.initial_changeset()
    }

    fn is_tx_relevant(&self, tx: &Transaction) -> bool {
        if self.inner.is_relevant(tx) {
            return true;
        }
        tx.input.iter().any(|input| {
            self.known_outpoints.contains(&input.previous_output)
                || self.known_txids.contains(&input.previous_output.txid)
        })
    }
}

fn last_active_indices(index: &SpkTxOutIndex<(KeychainKind, u32)>) -> BTreeMap<KeychainKind, u32> {
    let mut out: BTreeMap<KeychainKind, u32> = BTreeMap::new();
    for ((keychain, idx), _op) in index.outpoints() {
        out.entry(*keychain)
            .and_modify(|cur| *cur = (*cur).max(*idx))
            .or_insert(*idx);
    }
    out
}

fn collect_full_scan_spks(
    mut req: FullScanRequest<KeychainKind>,
    script_limit: usize,
) -> (SpkTxOutIndex<(KeychainKind, u32)>, Option<CheckPoint>) {
    let chain_tip = req.chain_tip();
    let mut index = SpkTxOutIndex::default();
    let limit = script_limit.max(1);
    for keychain in req.keychains() {
        for (i, spk) in req.iter_spks(keychain).take(limit) {
            index.insert_spk((keychain, i), spk);
        }
    }
    (index, chain_tip)
}

/// Collect sync SPKs and the predecessor ids the request already carries.
///
/// `SyncRequest` does not re-expose the index type `I` once drained via the
/// public iterators (only the script). For sync, [`Update::last_active_indices`]
/// is empty anyway (`From<SyncResponse> for Update`); filter matching only
/// needs the script set. Indices are filled with a monotone counter under
/// [`KeychainKind::External`] so `SpkTxOutIndex` stays populated.
///
/// Wallet `start_sync_with_revealed_spks` puts canonical txs in
/// `expected_spk_txids`, not in `outpoints`. Those txids (and any explicit
/// outpoints / loose txids) seed input-side relevance so a changeless spend
/// of a pre-checkpoint output is not dropped. No peer lookup.
fn collect_sync_spks(
    mut req: SyncRequest<(KeychainKind, u32)>,
) -> (RelevantSpkIndex, Option<CheckPoint>) {
    let chain_tip = req.chain_tip();
    let mut inner = SpkTxOutIndex::default();
    let mut known_txids = HashSet::new();
    let mut n = 0u32;
    while let Some(item) = req.next_spk_with_expected_txids() {
        known_txids.extend(item.expected_txids);
        inner.insert_spk((KeychainKind::External, n), item.spk);
        n = n.saturating_add(1);
    }
    while let Some(txid) = req.next_txid() {
        known_txids.insert(txid);
    }
    let mut known_outpoints = HashSet::new();
    while let Some(op) = req.next_outpoint() {
        known_outpoints.insert(op);
    }
    (
        RelevantSpkIndex {
            inner,
            known_outpoints,
            known_txids,
        },
        chain_tip,
    )
}

impl ChainBackend for CbfBackend {
    fn full_scan(&self, req: FullScanRequest<KeychainKind>) -> Result<Update, ChainError> {
        let (index, tip) = collect_full_scan_spks(req, self.config.full_scan_script_limit);
        self.scan_indexed(RelevantSpkIndex::scripts_only(index), tip)
    }

    fn sync(&self, req: SyncRequest<(KeychainKind, u32)>) -> Result<Update, ChainError> {
        let (index, tip) = collect_sync_spks(req);
        self.scan_indexed(index, tip)
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
        match self.with_synced(ReadyOp::Broadcast(tx.clone()))? {
            ReadyResult::Broadcast(txid) => Ok(txid),
            _ => Err(ChainError::Other(
                "cbf broadcast: internal result mismatch".into(),
            )),
        }
    }

    fn fee_estimates(&self) -> Result<FeeEstimates, ChainError> {
        match self.with_synced(ReadyOp::Fees)? {
            ReadyResult::Fees(fees) => Ok(fees),
            _ => Err(ChainError::Other(
                "cbf fees: internal result mismatch".into(),
            )),
        }
    }

    fn tip_height(&self) -> Result<u32, ChainError> {
        let height = match self.with_synced(ReadyOp::Tip)? {
            ReadyResult::Tip(h) => h,
            _ => {
                return Err(ChainError::Other(
                    "cbf tip: internal result mismatch".into(),
                ))
            }
        };
        *self.tip_cache.lock().expect("tip mutex") = Some(height);
        Ok(height)
    }

    fn privacy_profile(&self) -> PrivacyProfile {
        // Spec §1.6 table row 4 + B.3/O3 label discipline (random-peer block
        // fetch — more private than third-party Electrum, not anonymous).
        PrivacyProfile::cbf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::BackendKind;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn map_operation_timeout_four_cases() {
        // Broadcast after submit_package started: announcement may be in flight.
        assert_eq!(
            map_operation_timeout(true, true, 25),
            ChainError::DeliveryUnconfirmed
        );
        // Broadcast before submit_package: the old FiltersSynced merker lied here.
        assert!(
            matches!(
                map_operation_timeout(true, false, 25),
                ChainError::Network(_)
            ),
            "broadcast timeout with merker unset must stay Network"
        );
        // Non-broadcast (scan/tip/fees) never claims an announcement, even if
        // the merker were spuriously set.
        assert!(
            matches!(
                map_operation_timeout(false, true, 25),
                ChainError::Network(_)
            ),
            "non-broadcast timeout with merker set must stay Network"
        );
        assert!(
            matches!(
                map_operation_timeout(false, false, 25),
                ChainError::Network(_)
            ),
            "non-broadcast timeout with merker unset must stay Network"
        );
    }

    #[test]
    fn privacy_profile_is_cbf_table_row() {
        let cfg = CbfConfig::regtest_peer(SocketAddr::from(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            18444,
        )));
        let backend = CbfBackend::new(cfg).expect("runtime");
        let p = backend.privacy_profile();
        assert_eq!(p.kind, BackendKind::Cbf);
        assert!(!p.reveals_full_wallet_graph);
        assert!(p.third_party_counterparty);
        assert!(!p.requires_selection_warning);
        // B.3 / O3: no unqualified privacy claim.
        assert!(p.magnitude.to_ascii_lowercase().contains("not zero"));
        assert!(p.counterparty_learns.contains("statistical leak"));
        assert!(!p.magnitude.to_ascii_lowercase().contains("anonymous"));
    }

    #[test]
    fn config_builder_sets_peers_and_tor() {
        let cfg = CbfConfig::new(Network::Signet)
            .peer_ip(Ipv4Addr::new(1, 2, 3, 4), 38333)
            .peer(TrustedPeer::from_socket_addr(SocketAddr::from(
                SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 8333),
            )))
            .whitelist_only()
            .required_peers(2)
            .data_dir("/tmp/trinity-cbf-test")
            .socks5_proxy(Socks5Proxy::local())
            .operation_timeout(Duration::from_secs(30))
            .full_scan_script_limit(0); // clamped to 1
        assert_eq!(cfg.network, Network::Signet);
        assert_eq!(cfg.peers.len(), 2);
        assert!(cfg.whitelist_only);
        assert_eq!(cfg.required_peers, 2);
        assert!(cfg.data_dir.is_some());
        assert!(cfg.socks5_proxy.is_some());
        assert_eq!(cfg.operation_timeout, Duration::from_secs(30));
        assert_eq!(cfg.full_scan_script_limit, 1);
    }

    #[test]
    fn wall_timeout_fires() {
        let err = run_with_wall_timeout(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(2));
            Ok::<(), ChainError>(())
        })
        .expect_err("must time out");
        assert!(matches!(err, ChainError::Network(_)));
        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn wall_timeout_disconnected_worker() {
        // Worker panics → channel disconnect.
        let err = run_with_wall_timeout(Duration::from_secs(2), || -> Result<(), ChainError> {
            panic!("forced worker abort");
        })
        .expect_err("must surface disconnect");
        assert!(matches!(err, ChainError::Network(_)));
    }

    #[test]
    fn apply_chain_event_connected_and_fork() {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut cp = CheckPoint::new(BlockId {
            height: 0,
            hash: genesis.block_hash(),
        });
        // Connected: insert a synthetic second block id via ForkAdded (no-op)
        // then Connected path needs a real IndexedHeader — exercise ForkAdded.
        apply_chain_event(
            &mut cp,
            &BlockHeaderChanges::ForkAdded(bdk_kyoto::bip157::chain::IndexedHeader {
                height: 1,
                header: genesis.header,
            }),
        );
        assert_eq!(cp.height(), 0);

        // Reorganized with empty accepted is a no-op on height.
        apply_chain_event(
            &mut cp,
            &BlockHeaderChanges::Reorganized {
                accepted: vec![],
                reorganized: vec![],
            },
        );
        assert_eq!(cp.height(), 0);
    }

    #[test]
    fn apply_chain_event_connected_inserts_tip() {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut cp = CheckPoint::new(BlockId {
            height: 0,
            hash: genesis.block_hash(),
        });
        // Distinct header bytes → distinct block hash at height 1.
        let mut header = genesis.header;
        header.time = genesis.header.time.wrapping_add(600);
        header.nonce = genesis.header.nonce.wrapping_add(1);
        apply_chain_event(
            &mut cp,
            &BlockHeaderChanges::Connected(bdk_kyoto::bip157::chain::IndexedHeader {
                height: 1,
                header,
            }),
        );
        assert_eq!(cp.height(), 1);
        assert_eq!(cp.hash(), header.block_hash());
    }

    #[test]
    fn apply_chain_event_reorg_accepted_inserts() {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut cp = CheckPoint::new(BlockId {
            height: 0,
            hash: genesis.block_hash(),
        });
        // Two accepted headers — exercises the non-empty `accepted` loop body
        // in `Reorganized` (empty accepted is covered elsewhere).
        let mut accepted = Vec::new();
        for h in 1..=2u32 {
            let mut header = genesis.header;
            header.time = genesis.header.time.wrapping_add(h * 600);
            header.nonce = h;
            accepted.push(bdk_kyoto::bip157::chain::IndexedHeader { height: h, header });
        }
        apply_chain_event(
            &mut cp,
            &BlockHeaderChanges::Reorganized {
                accepted,
                reorganized: vec![],
            },
        );
        assert_eq!(cp.height(), 2);
    }

    #[test]
    fn walk_back_stops_at_reorg_depth() {
        use bitcoin::hashes::Hash;
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut cp = CheckPoint::new(BlockId {
            height: 0,
            hash: genesis.block_hash(),
        });
        // Build a chain of 12 block ids (hashes fake but heights ascending).
        for h in 1..=12u32 {
            let mut bytes = [0u8; 32];
            bytes[0] = h as u8;
            bytes[1] = (h >> 8) as u8;
            let hash = bitcoin::BlockHash::from_byte_array(bytes);
            cp = cp
                .push(BlockId { height: h, hash })
                .expect("ascending heights");
        }
        let hc = walk_back_reorg(cp);
        // iter is tip-first: index 0 = tip (12). Loop keeps updating while
        // index <= REORG_WALKBACK (7), so final height is 12 - 7 = 5.
        assert_eq!(hc.height, 12 - REORG_WALKBACK as u32);
    }

    #[test]
    fn debug_impl_is_stable() {
        let cfg = CbfConfig::regtest_peer(SocketAddr::from(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            18444,
        )));
        let backend = CbfBackend::new(cfg).expect("runtime");
        let s = format!("{backend:?}");
        assert!(s.contains("CbfBackend"));
        assert!(s.contains("peers"));
        assert!(backend.config().whitelist_only);
    }

    #[test]
    fn unreachable_peer_returns_network_error_not_ok() {
        // Port nobody listens on — must fail cleanly (S13 analogue).
        let dir = std::env::temp_dir().join(format!("trinity-cbf-err-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg =
            CbfConfig::regtest_peer(SocketAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)))
                .data_dir(dir)
                .operation_timeout(Duration::from_secs(8));
        let backend = CbfBackend::new(cfg).expect("runtime");
        let err = backend
            .tip_height()
            .expect_err("unreachable peer must not succeed");
        match err {
            ChainError::Network(_) | ChainError::Unavailable(_) => {}
            other => panic!("expected Network/Unavailable, got {other:?}"),
        }
        assert!(backend.tip_cache.lock().unwrap().is_none());
    }

    #[test]
    fn empty_full_scan_against_dead_peer_errors() {
        let dir = std::env::temp_dir().join(format!("trinity-cbf-scan-err-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg =
            CbfConfig::regtest_peer(SocketAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2)))
                .data_dir(dir)
                .operation_timeout(Duration::from_secs(8));
        let backend = CbfBackend::new(cfg).expect("runtime");
        let req = FullScanRequest::<KeychainKind>::builder_at(0).build();
        let err = backend.full_scan(req).expect_err("must not succeed");
        assert!(matches!(
            err,
            ChainError::Network(_) | ChainError::Unavailable(_)
        ));
    }

    #[test]
    fn last_active_indices_empty_without_outpoints() {
        let mut index = SpkTxOutIndex::default();
        assert!(last_active_indices(&index).is_empty());
        index.insert_spk((KeychainKind::External, 3), ScriptBuf::new_op_return([1u8]));
        assert!(last_active_indices(&index).is_empty());
    }

    #[test]
    fn walk_back_from_genesis_stays_genesis() {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let cp = CheckPoint::new(BlockId {
            height: 0,
            hash: genesis.block_hash(),
        });
        let hc = walk_back_reorg(cp);
        assert_eq!(hc.height, 0);
        assert_eq!(hc.hash, genesis.block_hash());
    }

    #[test]
    fn collect_full_scan_registers_spks() {
        let spk = ScriptBuf::new_op_return([9u8]);
        let req = FullScanRequest::<KeychainKind>::builder_at(0)
            .spks_for_keychain(KeychainKind::External, vec![(0, spk.clone())])
            .build();
        let (index, tip) = collect_full_scan_spks(req, 200);
        assert!(tip.is_none());
        assert_eq!(index.all_spks().len(), 1);
        assert_eq!(
            index.all_spks().get(&(KeychainKind::External, 0)),
            Some(&spk)
        );
    }

    #[test]
    fn collect_full_scan_respects_limit() {
        let spks: Vec<_> = (0..50u32)
            .map(|i| (i, ScriptBuf::new_op_return([i as u8])))
            .collect();
        let req = FullScanRequest::<KeychainKind>::builder_at(0)
            .spks_for_keychain(KeychainKind::External, spks)
            .build();
        let (index, _) = collect_full_scan_spks(req, 10);
        assert_eq!(index.all_spks().len(), 10);
    }

    #[test]
    fn collect_sync_registers_spks() {
        let spk = ScriptBuf::new_op_return([7u8]);
        let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
            .spks_with_indexes(vec![((KeychainKind::External, 1), spk.clone())])
            .build();
        let (index, tip) = collect_sync_spks(req);
        assert!(tip.is_none());
        assert_eq!(index.all_spks().len(), 1);
        assert!(index.all_spks().values().any(|s| s == &spk));
    }

    #[test]
    fn collect_sync_drains_txids_and_outpoints() {
        use bitcoin::hashes::Hash;
        use bitcoin::OutPoint;

        let spk = ScriptBuf::new_op_return([3u8]);
        let txid = bitcoin::Txid::from_byte_array([9u8; 32]);
        let op = OutPoint {
            txid: bitcoin::Txid::from_byte_array([8u8; 32]),
            vout: 1,
        };
        let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
            .spks_with_indexes(vec![((KeychainKind::External, 0), spk)])
            .txids(vec![txid])
            .outpoints(vec![op])
            .build();
        let (index, tip) = collect_sync_spks(req);
        assert!(tip.is_none());
        assert_eq!(index.all_spks().len(), 1);
        assert!(index.known_txids.contains(&txid));
        assert!(index.known_outpoints.contains(&op));
    }

    #[test]
    fn collect_sync_keeps_expected_spk_txids() {
        use bitcoin::hashes::Hash;

        let spk = ScriptBuf::new_op_return([4u8]);
        let txid = bitcoin::Txid::from_byte_array([7u8; 32]);
        let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
            .spks_with_indexes(vec![((KeychainKind::External, 0), spk.clone())])
            .expected_spk_txids(vec![(spk, txid)])
            .build();
        let (index, _) = collect_sync_spks(req);
        assert!(index.known_txids.contains(&txid));
        assert!(index.known_outpoints.is_empty());
    }

    #[test]
    fn relevant_spk_index_input_side_from_request_ids() {
        use bitcoin::hashes::Hash;
        use bitcoin::{Amount, Sequence, TxIn, TxOut, Witness};

        let spend_spk = ScriptBuf::new_op_return([1u8]);
        let foreign_spk = ScriptBuf::new_op_return([2u8]);
        let mut inner = SpkTxOutIndex::default();
        inner.insert_spk((KeychainKind::External, 0), spend_spk.clone());

        let funding_txid = bitcoin::Txid::from_byte_array([0x11; 32]);
        let known_op = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
            vout: 1,
        };
        let index = RelevantSpkIndex {
            inner,
            known_outpoints: HashSet::from([known_op]),
            known_txids: HashSet::from([funding_txid]),
        };

        let changeless = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: funding_txid,
                    vout: 3,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: foreign_spk.clone(),
            }],
        };
        assert!(
            index.is_tx_relevant(&changeless),
            "spend of an expected-spk txid must be relevant without scanning that TxOut"
        );

        let by_outpoint = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: known_op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: foreign_spk.clone(),
            }],
        };
        assert!(index.is_tx_relevant(&by_outpoint));

        let receive = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: spend_spk,
            }],
        };
        assert!(
            index.is_tx_relevant(&receive),
            "pay-to-watched-script must stay relevant (receive path)"
        );

        let foreign = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x33; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: foreign_spk,
            }],
        };
        assert!(!index.is_tx_relevant(&foreign));
    }

    #[test]
    fn relevant_spk_index_index_tx_records_matching_outpoint() {
        use bitcoin::{Amount, TxOut};

        let spk = ScriptBuf::new_op_return([6u8]);
        let foreign_spk = ScriptBuf::new_op_return([7u8]);
        let mut inner = SpkTxOutIndex::default();
        inner.insert_spk((KeychainKind::External, 0), spk.clone());
        let mut index = RelevantSpkIndex::scripts_only(inner);
        assert!(
            index.inner.outpoints().is_empty(),
            "watching a script does not record an outpoint until a matching tx is indexed"
        );

        let pay = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: spk,
            }],
        };
        index.index_tx(&pay);
        assert_eq!(
            index.inner.outpoints().len(),
            1,
            "index_tx must scan matching outputs into the inner index"
        );
        let last = last_active_indices(&index.inner);
        assert_eq!(last.get(&KeychainKind::External), Some(&0));

        let foreign = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: foreign_spk,
            }],
        };
        index.index_tx(&foreign);
        assert_eq!(
            index.inner.outpoints().len(),
            1,
            "a foreign output must not be recorded"
        );
    }

    #[test]
    fn last_active_indices_tracks_max_per_keychain() {
        use bitcoin::hashes::Hash;
        use bitcoin::{Amount, OutPoint, TxOut};

        // Unique scripts per derivation index so scan_txout can bind each.
        let spk_e1 = ScriptBuf::new_op_return([10u8]);
        let spk_e4 = ScriptBuf::new_op_return([11u8]);
        let spk_i2 = ScriptBuf::new_op_return([12u8]);
        let mut index = SpkTxOutIndex::default();
        index.insert_spk((KeychainKind::External, 1), spk_e1.clone());
        index.insert_spk((KeychainKind::External, 4), spk_e4.clone());
        index.insert_spk((KeychainKind::Internal, 2), spk_i2.clone());

        let txout = |spk: ScriptBuf| TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: spk,
        };
        index.scan_txout(
            OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            &txout(spk_e1),
        );
        index.scan_txout(
            OutPoint {
                txid: Txid::from_byte_array([2u8; 32]),
                vout: 0,
            },
            &txout(spk_e4),
        );
        index.scan_txout(
            OutPoint {
                txid: Txid::from_byte_array([3u8; 32]),
                vout: 0,
            },
            &txout(spk_i2),
        );

        let last = last_active_indices(&index);
        assert_eq!(last.get(&KeychainKind::External), Some(&4));
        assert_eq!(last.get(&KeychainKind::Internal), Some(&2));
    }

    #[test]
    fn build_node_optional_builder_arms_against_dead_endpoint() {
        // Hit the *false* / *Some* arms of build_node that regtest_peer never
        // takes: whitelist_only=false, empty peers, no data_dir, Socks5 set,
        // handshake/response timeouts left as None (bip157 defaults).
        let cfg = CbfConfig::new(Network::Regtest)
            .socks5_proxy(Socks5Proxy::local())
            .operation_timeout(Duration::from_secs(4));
        assert!(!cfg.whitelist_only);
        assert!(cfg.peers.is_empty());
        assert!(cfg.data_dir.is_none());
        assert!(cfg.socks5_proxy.is_some());
        assert!(cfg.handshake_timeout.is_none());
        assert!(cfg.response_timeout.is_none());

        let backend = CbfBackend::new(cfg).expect("runtime");
        let err = backend
            .tip_height()
            .expect_err("no tor/proxy and no peers → must fail");
        assert!(matches!(
            err,
            ChainError::Network(_) | ChainError::Unavailable(_)
        ));
    }

    #[test]
    fn full_scan_with_chain_tip_against_dead_peer() {
        // Exercises chain_state_for_network(Some(cp)) + walk_back_reorg on the
        // scan path (with_synced always uses None).
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let cp = CheckPoint::new(BlockId {
            height: 0,
            hash: genesis.block_hash(),
        });
        let dir = std::env::temp_dir().join(format!("trinity-cbf-tip-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg =
            CbfConfig::regtest_peer(SocketAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3)))
                .data_dir(dir)
                .operation_timeout(Duration::from_secs(6));
        let backend = CbfBackend::new(cfg).expect("runtime");
        let req = FullScanRequest::<KeychainKind>::builder_at(0)
            .chain_tip(cp)
            .spks_for_keychain(
                KeychainKind::External,
                vec![(0, ScriptBuf::new_op_return([42u8]))],
            )
            .build();
        let err = backend.full_scan(req).expect_err("dead peer");
        assert!(matches!(
            err,
            ChainError::Network(_) | ChainError::Unavailable(_)
        ));
    }

    #[test]
    fn sync_against_dead_peer_errors() {
        let dir = std::env::temp_dir().join(format!("trinity-cbf-sync-err-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg =
            CbfConfig::regtest_peer(SocketAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4)))
                .data_dir(dir)
                .operation_timeout(Duration::from_secs(6));
        let backend = CbfBackend::new(cfg).expect("runtime");
        let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
            .spks_with_indexes(vec![(
                (KeychainKind::External, 0),
                ScriptBuf::new_op_return([5u8]),
            )])
            .build();
        let err = backend.sync(req).expect_err("dead peer");
        assert!(matches!(
            err,
            ChainError::Network(_) | ChainError::Unavailable(_)
        ));
    }

    #[test]
    fn fee_and_broadcast_against_dead_peer_error() {
        let dir = std::env::temp_dir().join(format!("trinity-cbf-ops-err-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg =
            CbfConfig::regtest_peer(SocketAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5)))
                .data_dir(dir)
                .operation_timeout(Duration::from_secs(6));
        let backend = CbfBackend::new(cfg).expect("runtime");
        let fee_err = backend.fee_estimates().expect_err("dead peer fees");
        assert!(matches!(
            fee_err,
            ChainError::Network(_) | ChainError::Unavailable(_)
        ));

        let junk = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: ScriptBuf::new_op_return([0u8]),
            }],
        };
        let bcast_err = backend.broadcast(&junk).expect_err("dead peer broadcast");
        assert!(
            matches!(
                bcast_err,
                ChainError::Network(_) | ChainError::Unavailable(_)
            ),
            "dead peer never reaches submit_package, so must stay Network/Unavailable, got {bcast_err:?}"
        );
        assert!(
            !matches!(bcast_err, ChainError::DeliveryUnconfirmed),
            "unconfirmed delivery is only the hang after announcement, not a refused connection"
        );
    }

    #[test]
    fn dead_peer_broadcast_is_network_not_unconfirmed() {
        // Real transport failure: nothing listens. Distinct from the
        // already-known-tx hang, which is DeliveryUnconfirmed.
        let dir =
            std::env::temp_dir().join(format!("trinity-cbf-bcast-net-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg =
            CbfConfig::regtest_peer(SocketAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)))
                .data_dir(dir)
                .operation_timeout(Duration::from_secs(6));
        let backend = CbfBackend::new(cfg).expect("runtime");
        let junk = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: ScriptBuf::new_op_return([0u8]),
            }],
        };
        let err = backend.broadcast(&junk).expect_err("dead peer");
        assert!(
            matches!(err, ChainError::Network(_) | ChainError::Unavailable(_)),
            "got {err:?}"
        );
        assert_ne!(err, ChainError::DeliveryUnconfirmed);
    }
}
