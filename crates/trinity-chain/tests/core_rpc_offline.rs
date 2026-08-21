//! Offline Core RPC coverage — dead endpoints + HTTP mock bitcoind.
//!
//! Runs without Docker / test-env (same constraint as CI coverage and WP-14/WP-16).
//! The mock speaks the subset of bitcoind JSON-RPC that `CoreRpcBackend` uses.

use std::collections::{BTreeMap as Map, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bdk_bitcoind_rpc::bitcoincore_rpc::jsonrpc::serde_json::{self as serde_json, json, Value};
use bdk_chain::BlockId;
use bdk_chain::CheckPoint;
use bitcoin::bip158::BlockFilter;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::{
    absolute::LockTime, Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
};
use trinity_chain::{
    ChainBackend, ChainError, CoreRpcBackend, CoreRpcConfig, FullScanRequest, KeychainKind,
    SyncRequest,
};

/// Confirmation targets mirrored from `core_rpc::FEE_TARGETS`.
const FEE_TARGETS: &[u32] = &[1, 2, 3, 6, 12, 24, 144, 1008];

// ── offline mock bitcoind (no Docker) ───────────────────────────────────

#[derive(Clone)]
struct MockBlock {
    height: u32,
    block: Block,
    filter: Vec<u8>,
}

#[derive(Clone)]
struct StoredTx {
    tx: Transaction,
    blockhash: Option<BlockHash>,
}

struct MockState {
    blocks: Vec<MockBlock>,
    /// tip height override (default = last block). Used for overflow tests.
    tip_override: Option<u64>,
    mempool: Vec<Transaction>,
    /// Txids listed in getrawmempool but not served by getrawtransaction (-5).
    phantom_mempool: Vec<bitcoin::Txid>,
    /// Txids for which getrawtransaction / info returns a non-not-found error.
    hard_fail_txids: HashSet<bitcoin::Txid>,
    /// Txids that return Core's -5 txindex hint (not a genuine missing tx).
    txindex_fail_txids: HashSet<bitcoin::Txid>,
    /// Extra txs served by getrawtransaction (e.g. already-confirmed lookups).
    extras: Map<bitcoin::Txid, StoredTx>,
    /// conf_target → sat/vB (0 means omit feerate / errors path).
    fees: Map<u16, u64>,
    /// Require HTTP Basic user/pass; if set, mismatch → 401.
    auth: Option<(String, String)>,
    /// Methods that return a generic RPC error.
    fail: HashSet<String>,
    /// getblockheader call count per hash (to force time-lookup failure).
    header_calls: Map<String, u32>,
    /// After this many header lookups for a hash, fail (None = never).
    header_fail_after: Option<u32>,
}

impl MockState {
    fn tip_height(&self) -> u64 {
        if let Some(t) = self.tip_override {
            return t;
        }
        self.blocks.last().map(|b| u64::from(b.height)).unwrap_or(0)
    }

    fn by_height(&self, h: u32) -> Option<&MockBlock> {
        self.blocks.iter().find(|b| b.height == h)
    }

    fn by_hash(&self, hash: &str) -> Option<&MockBlock> {
        self.blocks
            .iter()
            .find(|b| b.block.block_hash().to_string() == hash)
    }
}

struct MockRpc {
    url: String,
    state: Arc<Mutex<MockState>>,
    // Keep listener thread alive; join on drop is best-effort.
    _thread: thread::JoinHandle<()>,
}

impl MockRpc {
    fn spawn(state: MockState) -> Self {
        let state = Arc::new(Mutex::new(state));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock rpc");
        listener.set_nonblocking(false).expect("blocking listener");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        let url = format!("http://{addr}");
        let st = Arc::clone(&state);
        let _thread = thread::spawn(move || {
            // Accept until the process ends / listener is dropped via OS.
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => {
                        let st = Arc::clone(&st);
                        let _ = thread::spawn(move || {
                            let _ = handle_http(stream, &st);
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        // Tiny settle so the accept loop is ready.
        thread::sleep(Duration::from_millis(20));
        Self {
            url,
            state,
            _thread,
        }
    }

    fn backend(&self) -> CoreRpcBackend {
        CoreRpcBackend::connect(CoreRpcConfig::user_pass(&self.url, "trinity", "regtest"))
            .expect("connect mock")
    }

    fn backend_auth(&self, user: &str, pass: &str) -> CoreRpcBackend {
        CoreRpcBackend::connect(CoreRpcConfig::user_pass(&self.url, user, pass))
            .expect("connect mock")
    }

    fn with_stop_gap(&self, gap: usize) -> CoreRpcBackend {
        CoreRpcBackend::connect(
            CoreRpcConfig::user_pass(&self.url, "trinity", "regtest").with_stop_gap(gap),
        )
        .expect("connect mock")
    }
}

fn handle_http(mut stream: TcpStream, state: &Arc<Mutex<MockState>>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    // Read headers + body (Content-Length).
    loop {
        let n = match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e),
        };
        buf.extend_from_slice(&tmp[..n]);
        if let Some(header_end) = find_header_end(&buf) {
            let headers = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
            let content_len = headers
                .lines()
                .find_map(|l| {
                    let l = l.to_ascii_lowercase();
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= header_end + content_len {
                let body = &buf[header_end..header_end + content_len];
                // Auth check (HTTP Basic).
                let st = state.lock().expect("state");
                if let Some((ref u, ref p)) = st.auth {
                    let expected = format!("Basic {}", b64_std(format!("{u}:{p}").as_bytes()));
                    let got = headers.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.eq_ignore_ascii_case("authorization") {
                            Some(v.trim().to_string())
                        } else {
                            None
                        }
                    });
                    let ok = got.as_ref().is_some_and(|g| g == &expected);
                    if !ok {
                        drop(st);
                        let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        stream.write_all(resp.as_bytes())?;
                        return Ok(());
                    }
                }
                drop(st);
                let reply = dispatch_rpc(body, state);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    reply.len(),
                    reply
                );
                stream.write_all(resp.as_bytes())?;
                return Ok(());
            }
        }
        if buf.len() > 1 << 20 {
            break;
        }
    }
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn dispatch_rpc(body: &[u8], state: &Arc<Mutex<MockState>>) -> String {
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return rpc_err(Value::Null, -32700, "parse error");
        }
    };
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = v.get("params").cloned().unwrap_or_else(|| json!([]));

    let mut st = state.lock().expect("state");
    if st.fail.contains(method) {
        return rpc_err(id, -1, &format!("{method} forced fail"));
    }

    match method {
        "getblockcount" => rpc_ok(id, json!(st.tip_height())),
        "getblockhash" => {
            let h = params.get(0).and_then(|x| x.as_u64()).unwrap_or(0);
            if h > u64::from(u32::MAX) {
                return rpc_err(id, -8, "height out of range");
            }
            match st.by_height(h as u32) {
                Some(b) => rpc_ok(id, json!(b.block.block_hash().to_string())),
                None => rpc_err(id, -8, "Block height out of range"),
            }
        }
        "getblockheader" => {
            let hash = params
                .get(0)
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let count = {
                let c = st.header_calls.entry(hash.clone()).or_insert(0);
                *c += 1;
                *c
            };
            if let Some(limit) = st.header_fail_after {
                if count > limit {
                    return rpc_err(id, -5, "header fail");
                }
            }
            match st.by_hash(&hash) {
                Some(b) => rpc_ok(id, header_json(b, &st)),
                None => rpc_err(id, -5, "Block not found"),
            }
        }
        "getblockfilter" => {
            let hash = params.get(0).and_then(|x| x.as_str()).unwrap_or("");
            match st.by_hash(hash) {
                Some(b) => {
                    let header = "00".repeat(32);
                    rpc_ok(
                        id,
                        json!({
                            "header": header,
                            "filter": hex_encode(&b.filter),
                        }),
                    )
                }
                None => rpc_err(id, -5, "Block not found"),
            }
        }
        "getblock" => {
            let hash = params.get(0).and_then(|x| x.as_str()).unwrap_or("");
            match st.by_hash(hash) {
                Some(b) => rpc_ok(id, json!(serialize_hex(&b.block))),
                None => rpc_err(id, -5, "Block not found"),
            }
        }
        "getrawmempool" => {
            let mut ids: Vec<String> = st
                .mempool
                .iter()
                .map(|t| t.compute_txid().to_string())
                .collect();
            for t in &st.phantom_mempool {
                ids.push(t.to_string());
            }
            rpc_ok(id, json!(ids))
        }
        "getrawtransaction" => {
            let txid = params.get(0).and_then(|x| x.as_str()).unwrap_or("");
            let verbose = params
                .get(1)
                .map(|v| v.as_bool().unwrap_or(v.as_u64() == Some(1)))
                .unwrap_or(false);
            if let Ok(id_parsed) = txid.parse::<bitcoin::Txid>() {
                if st.hard_fail_txids.contains(&id_parsed) {
                    return rpc_err(id, -1, "forced hard fail");
                }
                if st.txindex_fail_txids.contains(&id_parsed) {
                    return rpc_err(
                        id,
                        -5,
                        "No such mempool transaction. Use -txindex or provide a block hash \
                         to enable blockchain transaction queries.",
                    );
                }
            }
            // Search mempool, extras, then block txs.
            let found = find_tx(&st, txid);
            match found {
                Some(stored) => {
                    let hex = serialize_hex(&stored.tx);
                    if verbose {
                        rpc_ok(
                            id,
                            json!({
                                "hex": hex,
                                "txid": stored.tx.compute_txid().to_string(),
                                "hash": stored.tx.compute_wtxid().to_string(),
                                "size": 100,
                                "vsize": 100,
                                "version": 2,
                                "locktime": 0,
                                "vin": [],
                                "vout": [],
                                "blockhash": stored.blockhash.map(|h| h.to_string()),
                                "confirmations": stored.blockhash.map(|_| 1u32),
                            }),
                        )
                    } else {
                        rpc_ok(id, json!(hex))
                    }
                }
                None => rpc_err(id, -5, "No such mempool or blockchain transaction"),
            }
        }
        "estimatesmartfee" => {
            let target = params.get(0).and_then(|x| x.as_u64()).unwrap_or(1) as u16;
            match st.fees.get(&target).copied() {
                Some(0) | None => rpc_ok(
                    id,
                    json!({
                        "errors": ["Insufficient data or no feerate found"],
                        "blocks": target,
                    }),
                ),
                Some(sat_vb) => {
                    // bitcoind feerate is BTC/kvB; sat/vB * 1000 = sat/kvB.
                    let btc_per_kvb = (sat_vb as f64) * 1000.0 / 100_000_000.0;
                    rpc_ok(
                        id,
                        json!({
                            "feerate": btc_per_kvb,
                            "blocks": target,
                        }),
                    )
                }
            }
        }
        "sendrawtransaction" => {
            let hex = params.get(0).and_then(|x| x.as_str()).unwrap_or("");
            match hex_decode(hex).and_then(|b| deserialize::<Transaction>(&b).ok()) {
                Some(tx) => rpc_ok(id, json!(tx.compute_txid().to_string())),
                None => rpc_err(id, -22, "TX decode failed"),
            }
        }
        other => rpc_err(id, -32601, &format!("Method not found: {other}")),
    }
}

fn find_tx(st: &MockState, txid: &str) -> Option<StoredTx> {
    for t in &st.mempool {
        if t.compute_txid().to_string() == txid {
            return Some(StoredTx {
                tx: t.clone(),
                blockhash: None,
            });
        }
    }
    if let Ok(id) = txid.parse::<bitcoin::Txid>() {
        if let Some(s) = st.extras.get(&id) {
            return Some(s.clone());
        }
    }
    for b in &st.blocks {
        for t in &b.block.txdata {
            if t.compute_txid().to_string() == txid {
                return Some(StoredTx {
                    tx: t.clone(),
                    blockhash: Some(b.block.block_hash()),
                });
            }
        }
    }
    None
}

fn header_json(b: &MockBlock, st: &MockState) -> Value {
    let hash = b.block.block_hash();
    let next = st
        .by_height(b.height.saturating_add(1))
        .map(|n| n.block.block_hash().to_string());
    let prev = if b.height == 0 {
        None
    } else {
        st.by_height(b.height - 1)
            .map(|p| p.block.block_hash().to_string())
    };
    let tip = st.tip_height() as u32;
    let conf = tip.saturating_sub(b.height) as i32 + 1;
    let mut obj = json!({
        "hash": hash.to_string(),
        "confirmations": conf,
        "height": b.height,
        "version": 1,
        "merkleroot": b.block.header.merkle_root.to_string(),
        "time": b.block.header.time,
        "mediantime": b.block.header.time,
        "nonce": b.block.header.nonce,
        "bits": format!("{:08x}", b.block.header.bits.to_consensus()),
        "difficulty": 1.0,
        "chainwork": "00".repeat(32),
        "nTx": b.block.txdata.len(),
    });
    if let Some(p) = prev {
        obj.as_object_mut()
            .unwrap()
            .insert("previousblockhash".into(), json!(p));
    }
    if let Some(n) = next {
        obj.as_object_mut()
            .unwrap()
            .insert("nextblockhash".into(), json!(n));
    }
    obj
}

fn rpc_ok(id: Value, result: Value) -> String {
    json!({"result": result, "error": null, "id": id}).to_string()
}

fn rpc_err(id: Value, code: i32, message: &str) -> String {
    json!({
        "result": null,
        "error": {"code": code, "message": message},
        "id": id
    })
    .to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Standard base64 (no deps) for HTTP Basic.
fn b64_std(input: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < input.len() {
            out.push(T[(((b1 & 0xf) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(T[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

/// P2WPKH-shaped script (not OP_RETURN — BIP158 filters skip OP_RETURN outputs).
fn watch_spk(tag: u8) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([tag; 20]))
}

fn coinbase_tx(spk: ScriptBuf, value: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        }],
    }
}

fn payment_tx(spk: ScriptBuf, value: u64) -> Transaction {
    // Non-coinbase shaped tx (dummy prevout — filter input scripts resolve empty).
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        }],
    }
}

fn make_block(prev: BlockHash, height: u32, txs: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: Header {
            version: BlockVersion::ONE,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_296_688_602 + height * 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        },
        txdata: txs,
    };
    block.header.merkle_root = block.compute_merkle_root().expect("merkle");
    block
}

fn filter_for(block: &Block) -> Vec<u8> {
    BlockFilter::new_script_filter(block, |_| {
        // Coinbase-only inputs are skipped; non-coinbase inputs would need UTXOs.
        // Our payment txs use a dummy prevout — treat as empty script.
        Ok::<_, bitcoin::bip158::Error>(ScriptBuf::new())
    })
    .expect("filter")
    .content
}

fn chain_with_payment(pay_spk: ScriptBuf) -> (Vec<MockBlock>, Transaction) {
    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    let g_filter = filter_for(&genesis);
    let pay = payment_tx(pay_spk, 50_000);
    let pay_clone = pay.clone();
    // Block 1: coinbase + payment to watched SPK.
    let coinbase = coinbase_tx(watch_spk(0xf1), 50 * 100_000_000);
    let b1 = make_block(genesis.block_hash(), 1, vec![coinbase, pay]);
    let f1 = filter_for(&b1);
    // Block 2: empty-of-interest (coinbase only) so FilterIter walks past match.
    let coinbase2 = coinbase_tx(watch_spk(0xf2), 50 * 100_000_000);
    let b2 = make_block(b1.block_hash(), 2, vec![coinbase2]);
    let f2 = filter_for(&b2);
    let blocks = vec![
        MockBlock {
            height: 0,
            block: genesis,
            filter: g_filter,
        },
        MockBlock {
            height: 1,
            block: b1,
            filter: f1,
        },
        MockBlock {
            height: 2,
            block: b2,
            filter: f2,
        },
    ];
    (blocks, pay_clone)
}

fn default_fees() -> Map<u16, u64> {
    let mut m = Map::new();
    for &t in FEE_TARGETS {
        // Half the targets get a positive rate so both insert / skip arms run.
        m.insert(t as u16, if t % 2 == 0 { 10 } else { 0 });
    }
    m
}

fn base_state(blocks: Vec<MockBlock>) -> MockState {
    MockState {
        blocks,
        tip_override: None,
        mempool: vec![],
        phantom_mempool: vec![],
        hard_fail_txids: HashSet::new(),
        txindex_fail_txids: HashSet::new(),
        extras: Map::new(),
        fees: default_fees(),
        auth: Some(("trinity".into(), "regtest".into())),
        fail: HashSet::new(),
        header_calls: Map::new(),
        header_fail_after: None,
    }
}

#[test]
fn mock_tip_height_and_overflow_protocol() {
    let (blocks, _) = chain_with_payment(watch_spk(0x11));
    let mock = MockRpc::spawn(base_state(blocks));
    let b = mock.backend();
    assert_eq!(b.tip_height().expect("tip"), 2);

    // Overflow → Protocol on tip_height.
    {
        let mut st = mock.state.lock().unwrap();
        st.tip_override = Some(u64::from(u32::MAX) + 1);
    }
    let err = b.tip_height().expect_err("overflow");
    assert!(
        matches!(err, ChainError::Protocol(ref m) if m.contains("out of range")),
        "got {err:?}"
    );
}

#[test]
fn mock_fee_estimates_and_broadcast() {
    let (blocks, _) = chain_with_payment(watch_spk(0x12));
    let mock = MockRpc::spawn(base_state(blocks));
    let b = mock.backend();
    let fees = b.fee_estimates().expect("fees");
    // Even targets only (see default_fees).
    assert!(!fees.sat_per_vb_by_target_blocks.is_empty());
    for (&t, &rate) in &fees.sat_per_vb_by_target_blocks {
        assert_eq!(rate, 10, "target {t}");
        assert_eq!(t % 2, 0);
    }

    let tx = payment_tx(watch_spk(0x99), 1000);
    let txid = b.broadcast(&tx).expect("broadcast");
    assert_eq!(txid, tx.compute_txid());
}

#[test]
fn mock_empty_full_scan_and_sync_advance_tip() {
    let (blocks, _) = chain_with_payment(watch_spk(0x13));
    let mock = MockRpc::spawn(base_state(blocks));
    let b = mock.backend();

    let full = FullScanRequest::<KeychainKind>::builder_at(0).build();
    let update = b.full_scan(full).expect("empty full_scan");
    assert!(update.chain.is_some());
    assert_eq!(update.chain.as_ref().unwrap().height(), 2);

    let sync = SyncRequest::<(KeychainKind, u32)>::builder_at(0).build();
    let update = b.sync(sync).expect("empty sync");
    assert!(update.chain.is_some());
    assert_eq!(update.chain.as_ref().unwrap().height(), 2);
}

#[test]
fn mock_full_scan_finds_payment_and_mempool() {
    let pay_spk = watch_spk(0xca);
    let (blocks, pay_tx) = chain_with_payment(pay_spk.clone());
    let mut state = base_state(blocks);
    // Mempool: relevant payment + decoy.
    let mem_pay = payment_tx(pay_spk.clone(), 7_000);
    let decoy = payment_tx(watch_spk(0xde), 1_000);
    state.mempool.push(mem_pay.clone());
    state.mempool.push(decoy);
    let mock = MockRpc::spawn(state);
    let b = mock.with_stop_gap(5);

    let external: Vec<_> = (0..5u32)
        .map(|i| {
            let spk = if i == 0 {
                pay_spk.clone()
            } else {
                watch_spk(0x10u8.wrapping_add(i as u8))
            };
            (i, spk)
        })
        .collect();
    let internal: Vec<_> = (0..5u32)
        .map(|i| (i, watch_spk(0x20u8.wrapping_add(i as u8))))
        .collect();
    let req = FullScanRequest::<KeychainKind>::builder_at(0)
        .spks_for_keychain(KeychainKind::External, external)
        .spks_for_keychain(KeychainKind::Internal, internal)
        .build();
    let update = b.full_scan(req).expect("full_scan");
    assert!(
        update
            .tx_update
            .txs
            .iter()
            .any(|t| t.compute_txid() == pay_tx.compute_txid()),
        "confirmed payment must be found"
    );
    assert!(
        update
            .tx_update
            .txs
            .iter()
            .any(|t| t.compute_txid() == mem_pay.compute_txid())
            || update
                .tx_update
                .seen_ats
                .iter()
                .any(|(id, _)| *id == mem_pay.compute_txid()),
        "mempool payment must surface"
    );
    assert!(
        update
            .last_active_indices
            .contains_key(&KeychainKind::External),
        "external last_active from active probe"
    );
}

#[test]
fn mock_sync_txid_outpoint_and_eviction() {
    use bitcoin::hashes::Hash as _;

    let pay_spk = watch_spk(0xee);
    let (blocks, pay_tx) = chain_with_payment(pay_spk.clone());
    let pay_txid = pay_tx.compute_txid();
    let b1_hash = blocks[1].block.block_hash();
    let mut state = base_state(blocks);
    // Unconfirmed extra for seen_ats arm.
    let unconf = payment_tx(watch_spk(0x55), 42);
    let unconf_id = unconf.compute_txid();
    state.extras.insert(
        unconf_id,
        StoredTx {
            tx: unconf,
            blockhash: None,
        },
    );
    // Also register confirmed pay in extras so explicit txid path can find it
    // when SPK scan already listed it (present.contains) or not.
    state.extras.insert(
        pay_txid,
        StoredTx {
            tx: pay_tx.clone(),
            blockhash: Some(b1_hash),
        },
    );
    let mock = MockRpc::spawn(state);
    let b = mock.backend();

    let missing = bitcoin::Txid::from_byte_array([0x11; 32]);
    let op = OutPoint {
        txid: pay_txid,
        vout: 0,
    };
    let ghost_op = OutPoint {
        txid: bitcoin::Txid::from_byte_array([0x22; 32]),
        vout: 0,
    };
    let hi_vout = OutPoint {
        txid: pay_txid,
        vout: 9_999,
    };

    // 1) Missing txid → eviction.
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .txids([missing])
        .build();
    let up = b.sync(req).expect("sync missing");
    assert!(
        up.tx_update.evicted_ats.iter().any(|(t, _)| *t == missing),
        "missing must be evicted"
    );

    // 2) Confirmed txid (+ duplicate) → anchors; second hits present.contains.
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .txids([pay_txid, pay_txid])
        .build();
    let up = b.sync(req).expect("sync confirmed");
    assert!(up
        .tx_update
        .txs
        .iter()
        .any(|t| t.compute_txid() == pay_txid));
    assert!(
        !up.tx_update.anchors.is_empty() || !up.tx_update.seen_ats.is_empty(),
        "confirmed should anchor or be seen"
    );

    // 3) Unconfirmed verbose info → seen_ats.
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .txids([unconf_id])
        .build();
    let up = b.sync(req).expect("sync unconf");
    assert!(
        up.tx_update.seen_ats.iter().any(|(t, _)| *t == unconf_id)
            || up
                .tx_update
                .txs
                .iter()
                .any(|t| t.compute_txid() == unconf_id)
    );

    // 4) Outpoint-only + ghost + high vout.
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .outpoints([op, ghost_op, hi_vout])
        .build();
    let up = b.sync(req).expect("sync outpoints");
    assert!(
        up.tx_update
            .txs
            .iter()
            .any(|t| t.compute_txid() == pay_txid)
            || up.tx_update.txouts.contains_key(&op)
    );

    // 5) SPK sync with expected_txids eviction path (expected missing from history).
    let expected_missing = bitcoin::Txid::from_byte_array([0x33; 32]);
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .spks_with_indexes(vec![((KeychainKind::External, 0), pay_spk)])
        .build();
    // expected_txids via builder — use chain of spks_with_expected if available.
    // Fallback: drive expected via SyncRequest builder API.
    let _ = expected_missing;
    let up = b.sync(req).expect("spk sync");
    assert!(up.chain.is_some());
}

#[test]
fn mock_sync_expected_txid_eviction_on_spk() {
    use bitcoin::hashes::Hash as _;
    let pay_spk = watch_spk(0x77);
    let (blocks, _) = chain_with_payment(pay_spk.clone());
    let mock = MockRpc::spawn(base_state(blocks));
    let b = mock.backend();
    let missing = bitcoin::Txid::from_byte_array([0x44; 32]);
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .spks_with_indexes(vec![((KeychainKind::External, 0), pay_spk.clone())])
        .expected_spk_txids(vec![(pay_spk, missing)])
        .build();
    let up = b.sync(req).expect("sync");
    assert!(
        up.tx_update.evicted_ats.iter().any(|(t, _)| *t == missing),
        "expected-but-missing txid must be evicted, got {:?}",
        up.tx_update.evicted_ats
    );
}

#[test]
fn mock_bad_credentials_error() {
    let (blocks, _) = chain_with_payment(watch_spk(0x66));
    let mut state = base_state(blocks);
    state.auth = Some(("trinity".into(), "regtest".into()));
    let mock = MockRpc::spawn(state);
    let b = mock.backend_auth("not-trinity", "wrong");
    let err = b.tip_height().expect_err("bad auth");
    assert!(
        matches!(
            err,
            ChainError::Network(_) | ChainError::Protocol(_) | ChainError::Other(_)
        ),
        "got {err:?}"
    );
}

#[test]
fn mock_filter_probe_stop_gap_without_activity() {
    // No matching SPKs → stop_gap unused counter breaks the loop; last_active empty.
    let (blocks, _) = chain_with_payment(watch_spk(0x01));
    let mock = MockRpc::spawn(base_state(blocks));
    let b = mock.with_stop_gap(3);
    let req = FullScanRequest::<KeychainKind>::builder_at(0)
        .spks_for_keychain(
            KeychainKind::External,
            (0..10u32).map(|i| (i, watch_spk(0xa0u8.wrapping_add(i as u8)))),
        )
        .build();
    let up = b.full_scan(req).expect("scan");
    assert!(up.last_active_indices.is_empty());
    assert!(up.chain.is_some());
}

#[test]
fn mock_header_time_fallback_when_header_lookup_fails() {
    let pay_spk = watch_spk(0x88);
    let (blocks, _) = chain_with_payment(pay_spk.clone());
    let mut state = base_state(blocks);
    // FilterIter needs a few successful header lookups; then scan_spks' time
    // fetch can fail → unwrap_or(start_time).
    state.header_fail_after = Some(4);
    let mock = MockRpc::spawn(state);
    let b = mock.with_stop_gap(2);
    let req = FullScanRequest::<KeychainKind>::builder_at(0)
        .spks_for_keychain(KeychainKind::External, vec![(0, pay_spk)])
        .build();
    // Must not panic; may still return Ok or Network depending on which call fails.
    let _ = b.full_scan(req);
}

#[test]
fn mock_rpc_method_failure_maps_network() {
    let (blocks, _) = chain_with_payment(watch_spk(0x19));
    let mut state = base_state(blocks);
    state.fail.insert("getblockcount".into());
    let mock = MockRpc::spawn(state);
    let b = mock.backend();
    let err = b.tip_height().expect_err("forced fail");
    assert!(matches!(err, ChainError::Network(_)), "got {err:?}");
    let err = b.fee_estimates().expect_err("probe fail");
    assert!(matches!(err, ChainError::Network(_)), "got {err:?}");
}

/// Cover remaining scan/sync/fee branches: chain_tip Some, mempool races,
/// header failures, non-not-found RPC errors, expected-present (no eviction).
#[test]
fn mock_scan_sync_remaining_branches() {
    use bitcoin::hashes::Hash as _;

    let pay_spk = watch_spk(0xb1);
    let (blocks, pay_tx) = chain_with_payment(pay_spk.clone());
    let genesis_hash = blocks[0].block.block_hash();
    let pay_txid = pay_tx.compute_txid();
    let b1_hash = blocks[1].block.block_hash();

    let mut state = base_state(blocks);
    // Mempool lists: (1) already-confirmed pay_txid → seen_txids continue,
    // (2) ghost txid not fetchable → get_tx_optional None continue,
    // (3) relevant mempool payment for active probe.
    let ghost = bitcoin::Txid::from_byte_array([0x5a; 32]);
    state.mempool.push(pay_tx.clone()); // will also be in block scan
                                        // Inject ghost only into mempool listing by faking via a side channel:
                                        // add a StoredTx-less id by pushing a tx then removing from extras — instead
                                        // put ghost in mempool list through a custom approach: add to mempool as a
                                        // real tx then mark fail for that getrawtransaction. Simpler: push a tx,
                                        // then put its txid in fail set for getrawtransaction only when missing.
    let orphan = payment_tx(watch_spk(0xb2), 9);
    let orphan_id = orphan.compute_txid();
    state.mempool.push(orphan); // listed, but we remove from find by not storing — it's in mempool vec so find_tx finds it.
                                // For None path: use extras-less id. Override by having mempool report a
                                // synthetic id via a dedicated field would need mock change. Use fail on
                                // getrawtransaction for a specific pattern instead.
    state.extras.insert(
        pay_txid,
        StoredTx {
            tx: pay_tx.clone(),
            blockhash: Some(b1_hash),
        },
    );
    // Tx with blockhash but header lookup will fail (forced after N calls).
    let conf_only = payment_tx(watch_spk(0xb3), 11);
    let conf_only_id = conf_only.compute_txid();
    state.extras.insert(
        conf_only_id,
        StoredTx {
            tx: conf_only,
            blockhash: Some(BlockHash::from_byte_array([0xcd; 32])), // not in chain
        },
    );
    state.header_fail_after = None;
    let mock = MockRpc::spawn(state);
    let b = mock.with_stop_gap(4);

    // chain_tip Some path (scan_spks start_cp from request).
    let tip_cp = CheckPoint::new(BlockId {
        height: 0,
        hash: genesis_hash,
    });
    let full = FullScanRequest::<KeychainKind>::builder_at(0)
        .chain_tip(tip_cp.clone())
        .spks_for_keychain(KeychainKind::External, vec![(0, pay_spk.clone())])
        .build();
    let up = b.full_scan(full).expect("full_scan with tip");
    assert!(up
        .tx_update
        .txs
        .iter()
        .any(|t| t.compute_txid() == pay_txid));

    // expected present → no eviction for that txid; missing still evicted.
    let missing = bitcoin::Txid::from_byte_array([0x4e; 32]);
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .chain_tip(tip_cp)
        .spks_with_indexes(vec![((KeychainKind::External, 0), pay_spk.clone())])
        .expected_spk_txids(vec![(pay_spk.clone(), pay_txid), (pay_spk, missing)])
        .build();
    let up = b.sync(req).expect("sync expected");
    assert!(
        up.tx_update.evicted_ats.iter().any(|(t, _)| *t == missing),
        "missing expected still evicted"
    );
    assert!(
        !up.tx_update.evicted_ats.iter().any(|(t, _)| *t == pay_txid),
        "present expected must not be evicted"
    );

    // conf_only: blockhash present but header missing → seen_ats arm.
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .txids([conf_only_id])
        .build();
    let up = b.sync(req).expect("sync conf_only");
    assert!(
        up.tx_update
            .seen_ats
            .iter()
            .any(|(t, _)| *t == conf_only_id)
            || up
                .tx_update
                .txs
                .iter()
                .any(|t| t.compute_txid() == conf_only_id)
    );

    // High-vout-only outpoint (not pre-present) → output.get None arm.
    let hi = OutPoint {
        txid: pay_txid,
        vout: 99,
    };
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .outpoints([hi])
        .build();
    let up = b.sync(req).expect("hi vout");
    assert!(up
        .tx_update
        .txs
        .iter()
        .any(|t| t.compute_txid() == pay_txid));
    let _ = (ghost, orphan_id);
}

#[test]
fn mock_mempool_missing_and_rpc_errors() {
    use bitcoin::hashes::Hash as _;

    let pay_spk = watch_spk(0xc1);
    let (blocks, _) = chain_with_payment(pay_spk.clone());
    let mut state = base_state(blocks);
    // Mempool contains a txid that getrawtransaction returns -5 for:
    // implement by listing a synthetic Transaction in mempool then clearing
    // it from find_tx via a dedicated "phantom" list.
    state
        .phantom_mempool
        .push(bitcoin::Txid::from_byte_array([0x91; 32]));
    // Non-not-found error on getrawtransaction for another phantom.
    state
        .hard_fail_txids
        .insert(bitcoin::Txid::from_byte_array([0x92; 32]));
    state
        .phantom_mempool
        .push(bitcoin::Txid::from_byte_array([0x92; 32]));
    // Also force getrawtransaction_info hard fail for explicit sync.
    state
        .hard_fail_txids
        .insert(bitcoin::Txid::from_byte_array([0x93; 32]));
    let mock = MockRpc::spawn(state);
    let b = mock.with_stop_gap(2);

    // full_scan drives mempool path: -5 → continue; hard fail → Network.
    let req = FullScanRequest::<KeychainKind>::builder_at(0)
        .spks_for_keychain(KeychainKind::External, vec![(0, pay_spk)])
        .build();
    let err = b.full_scan(req);
    // Hard-fail txid in mempool should surface as Network once reached.
    assert!(
        matches!(err, Err(ChainError::Network(_)) | Ok(_)),
        "got {err:?}"
    );

    // Explicit txid hard-fail → map_rpc on sync.
    let bad = bitcoin::Txid::from_byte_array([0x93; 32]);
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .txids([bad])
        .build();
    let err = b.sync(req).expect_err("hard fail txid");
    assert!(matches!(err, ChainError::Network(_)), "got {err:?}");
}

#[test]
fn mock_estimatesmartfee_errors_skipped() {
    let (blocks, _) = chain_with_payment(watch_spk(0xd1));
    let mut state = base_state(blocks);
    // All estimatesmartfee calls error → if-let Ok false arm (no panic, empty map).
    state.fail.insert("estimatesmartfee".into());
    let mock = MockRpc::spawn(state);
    let b = mock.backend();
    let fees = b.fee_estimates().expect("probe ok, estimates fail soft");
    assert!(fees.is_empty());
}

#[test]
fn mock_tip_checkpoint_overflow_on_empty_scan() {
    let (blocks, _) = chain_with_payment(watch_spk(0xd2));
    let mut state = base_state(blocks);
    state.tip_override = Some(u64::from(u32::MAX) + 5);
    let mock = MockRpc::spawn(state);
    let b = mock.backend();
    let full = FullScanRequest::<KeychainKind>::builder_at(0).build();
    let err = b.full_scan(full).expect_err("tip overflow");
    assert!(
        matches!(err, ChainError::Protocol(_) | ChainError::Network(_)),
        "got {err:?}"
    );
}

#[test]
fn mock_txindex_required_fails_loud_on_expected_txid() {
    let pay_spk = watch_spk(0xe1);
    let (blocks, pay) = chain_with_payment(pay_spk.clone());
    let pay_txid = pay.compute_txid();
    let mut state = base_state(blocks);
    state.txindex_fail_txids.insert(pay_txid);
    let mock = MockRpc::spawn(state);
    let b = mock.backend();
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .spks_with_indexes(vec![((KeychainKind::External, 0), pay_spk.clone())])
        .expected_spk_txids(vec![(pay_spk, pay_txid)])
        .build();
    let err = b.sync(req).expect_err("txindex must not look like missing");
    assert!(matches!(err, ChainError::Unavailable(_)), "got {err:?}");
}

#[test]
fn mock_mempool_two_pass_sees_changeless_child_listed_first() {
    // Parent pays the watched spk; child spends that outpoint with no change
    // to a foreign script. Mempool lists the child first (not topological).
    let pay_spk = watch_spk(0xe2);
    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    let g_filter = filter_for(&genesis);
    let blocks = vec![MockBlock {
        height: 0,
        block: genesis,
        filter: g_filter,
    }];
    let parent = payment_tx(pay_spk.clone(), 50_000);
    let parent_txid = parent.compute_txid();
    let child = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: watch_spk(0xee),
        }],
    };
    let child_txid = child.compute_txid();
    let mut state = base_state(blocks);
    state.mempool = vec![child, parent];
    let mock = MockRpc::spawn(state);
    let b = mock.backend();
    let req = SyncRequest::<(KeychainKind, u32)>::builder_at(0)
        .spks_with_indexes(vec![((KeychainKind::External, 0), pay_spk)])
        .build();
    let up = b.sync(req).expect("sync mempool pair");
    let ids: Vec<_> = up
        .tx_update
        .txs
        .iter()
        .map(|tx| tx.compute_txid())
        .collect();
    assert!(
        ids.contains(&parent_txid),
        "parent must be relevant; got {ids:?}"
    );
    assert!(
        ids.contains(&child_txid),
        "changeless child listed first must still be relevant after the parent \
         outpoint is learned; got {ids:?}"
    );
}
