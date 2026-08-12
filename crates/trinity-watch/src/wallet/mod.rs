//! BDK watch-only wallet — Spec §1.1, §3.2, WP-12.
//!
//! Builds a BDK 3.1.0 [`Wallet`] from Trinity receive/change descriptors,
//! derives addresses (`KeychainKind::External` = receive, `::Internal` =
//! change), manages UTXOs via `apply_update` / `list_unspent`, and constructs
//! PSBTs with anti-fee-sniping locktime/sequence and default coin selection
//! (`BranchAndBoundCoinSelection<SingleRandomDraw>`).
//!
//! ## Vendored API sources (not docs.rs)
//!
//! | API | Location |
//! |---|---|
//! | `Wallet::create` | `vendor/bdk_wallet/src/wallet/mod.rs` |
//! | `reveal_next_address` | `wallet/mod.rs:651` |
//! | `peek_address` | `wallet/mod.rs:605` |
//! | `build_tx` → `DefaultCoinSelectionAlgorithm` | `wallet/mod.rs:1220` |
//! | `DefaultCoinSelectionAlgorithm` | `coin_selection.rs:121` |
//! | `BranchAndBoundCoinSelection<SingleRandomDraw>` | `coin_selection.rs:404` |
//! | `TxBuilder::finish` / `finish_with_aux_rand` | `tx_builder.rs:748,762` |
//! | `set_exact_sequence` / `current_height` | `tx_builder.rs:632,648` |
//! | `decide_change` dust → fee | `coin_selection.rs:300–311` |
//! | `DEFAULT_LOOKAHEAD` (BDK default 25) | `vendor/bdk_chain/.../keychain_txout.rs:26` |
//!
//! Gap limit **20** (decision O10) is applied as BDK `lookahead(20)`.

mod encode;
mod error;

use std::str::FromStr;
use std::sync::Arc;

use bdk_chain::{BlockId, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::bitcoin::key::rand::RngCore;
use bdk_wallet::coin_selection::{
    BranchAndBoundCoinSelection, DefaultCoinSelectionAlgorithm, SingleRandomDraw,
};
use bdk_wallet::{KeychainKind as BdkKeychain, Update, Wallet};
use bitcoin::hashes::Hash;
use bitcoin::{
    absolute, transaction, Address, Amount, BlockHash, FeeRate, Network as BtcNetwork, OutPoint,
    Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
};
use trinity_types::{AddressInfo, Balance, FeeTarget, KeychainKind, Network, PsbtB64, SendRequest};

use crate::descriptor::{validate_trinity_descriptor, WalletDescriptors};

pub use error::WalletError;

/// Gap limit (decision O10) — unused-address scan depth.
///
/// Applied as BDK `CreateParams::lookahead`. BDK's library default is
/// [`bdk_chain::keychain_txout::DEFAULT_LOOKAHEAD`] (= 25); Trinity pins 20.
pub const GAP_LIMIT: u32 = 20;

/// Built-transaction `nSequence` (Spec §3.2 / WP-12 acceptance).
///
/// `0xFFFFFFFD` = [`Sequence::ENABLE_RBF_NO_LOCKTIME`]: enables absolute
/// `nLockTime` (anti-fee-sniping when combined with `nLockTime = tip height`)
/// **and** signals BIP-125 RBF replaceability (required for fee-bump flows).
/// Matches the BDK default when no explicit sequence is set.
pub const ANTI_FEE_SNIPING_SEQUENCE: u32 = 0xFFFF_FFFD;

/// Fixed seed for `finish_with_aux_rand` in tests (TESTING.md §2.4 / Spec §3.2).
///
/// Production may call [`WatchWallet::build_psbt`] → `finish()` (thread RNG).
/// Every bit-comparable PSBT test path must use
/// [`WatchWallet::build_psbt_with_aux_rand`] with this seed (or another fixed
/// seed declared at the call site).
pub const PSBT_BUILD_SEED: u64 = 0x5452_494e_4954_5901; // "TRINITY\x01"

/// Compile-time lock that the default coin-selection alias is BnB + SRD.
///
/// If BDK renames the default, this fails to compile rather than silently
/// changing selection behaviour.
const _: () = {
    fn _assert_default_cs() {
        fn same<T>(_: T, _: T) {}
        same(
            DefaultCoinSelectionAlgorithm::default(),
            BranchAndBoundCoinSelection::<SingleRandomDraw>::default(),
        );
    }
};

/// A spendable UTXO owned by the wallet (iterator collected for FFI).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoInfo {
    /// Outpoint of the UTXO.
    pub outpoint: OutPoint,
    /// Value in satoshi.
    pub amount_sats: u64,
    /// Receive vs change keychain.
    pub keychain: KeychainKind,
    /// BIP-32 child index on that keychain.
    pub derivation_index: u32,
    /// Script pubkey of the output.
    pub script_pubkey: ScriptBuf,
}

/// Watch-only wallet wrapping BDK 3.1.0 [`Wallet`].
///
/// No key material — descriptors are public only. Signing lives in
/// `trinity-signer` (denied as a dependency of this crate via `deny.toml`).
#[derive(Debug)]
pub struct WatchWallet {
    inner: Wallet,
    network: Network,
}

impl WatchWallet {
    /// Open a non-persisted wallet from a validated [`WalletDescriptors`] document.
    ///
    /// Uses separate receive/change descriptors (O8 — no multipath). Lookahead
    /// is set to [`GAP_LIMIT`] (20).
    pub fn from_descriptors(descriptors: &WalletDescriptors) -> Result<Self, WalletError> {
        Self::from_descriptor_strings(
            descriptors.network,
            descriptors.receive(),
            descriptors.change(),
        )
    }

    /// Open from raw receive/change descriptor strings (already Trinity grammar).
    ///
    /// Used by D6 (key-order permutations) and recovery paths that rebuild
    /// descriptors outside the document model.
    pub fn from_descriptor_strings(
        network: Network,
        receive: &str,
        change: &str,
    ) -> Result<Self, WalletError> {
        validate_trinity_descriptor(receive)?;
        validate_trinity_descriptor(change)?;
        let btc_net = to_bitcoin_network(network);
        let wallet = Wallet::create(receive.to_owned(), change.to_owned())
            .network(btc_net)
            .lookahead(GAP_LIMIT)
            .create_wallet_no_persist()
            .map_err(|e| WalletError::Create(e.to_string()))?;
        Ok(Self {
            inner: wallet,
            network,
        })
    }

    /// Trinity network this wallet was opened for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Current local-chain tip height (anti-fee-sniping / maturity).
    pub fn tip_height(&self) -> u32 {
        self.inner.latest_checkpoint().height()
    }

    /// Gap limit applied at create time (O10).
    pub fn gap_limit(&self) -> u32 {
        GAP_LIMIT
    }

    // ── Address derivation ──────────────────────────────────────────────

    /// Reveal the next address on `keychain` and stage the index advance.
    ///
    /// BDK: `Wallet::reveal_next_address(&mut self, KeychainKind) -> AddressInfo`
    /// (`wallet/mod.rs:651`).
    pub fn reveal_next_address(&mut self, keychain: KeychainKind) -> AddressInfo {
        let info = self.inner.reveal_next_address(to_bdk_keychain(keychain));
        from_bdk_address_info(info)
    }

    /// Peek at derivation `index` without advancing the revealed cursor.
    pub fn peek_address(&self, keychain: KeychainKind, index: u32) -> AddressInfo {
        let info = self.inner.peek_address(to_bdk_keychain(keychain), index);
        from_bdk_address_info(info)
    }

    /// Next unused address (reveals one if all prior are used).
    pub fn next_unused_address(&mut self, keychain: KeychainKind) -> AddressInfo {
        let info = self.inner.next_unused_address(to_bdk_keychain(keychain));
        from_bdk_address_info(info)
    }

    /// Collect addresses at indices `0..count` without revealing (for D2/D3).
    pub fn derive_addresses(&self, keychain: KeychainKind, count: u32) -> Vec<AddressInfo> {
        (0..count).map(|i| self.peek_address(keychain, i)).collect()
    }

    // ── Balance / UTXOs ─────────────────────────────────────────────────

    /// Balance breakdown mapped to [`trinity_types::Balance`].
    pub fn balance(&self) -> Balance {
        let b = self.inner.balance();
        Balance {
            confirmed_sats: b.confirmed.to_sat(),
            trusted_pending_sats: b.trusted_pending.to_sat(),
            untrusted_pending_sats: b.untrusted_pending.to_sat(),
            immature_sats: b.immature.to_sat(),
        }
    }

    /// Collect unspent outputs (BDK returns a lifetime-bound iterator).
    pub fn list_unspent(&self) -> Vec<UtxoInfo> {
        self.inner
            .list_unspent()
            .map(|o| UtxoInfo {
                outpoint: o.outpoint,
                amount_sats: o.txout.value.to_sat(),
                keychain: from_bdk_keychain(o.keychain),
                derivation_index: o.derivation_index,
                script_pubkey: o.txout.script_pubkey,
            })
            .collect()
    }

    // ── Persistence / chain updates ─────────────────────────────────────

    /// Apply a BDK [`Update`] (chain tip, txs, anchors) — entry for WP-13+.
    pub fn apply_update(&mut self, update: Update) -> Result<(), WalletError> {
        self.inner
            .apply_update(update)
            .map_err(|e| WalletError::ApplyUpdate(e.to_string()))
    }

    /// Take staged [`bdk_wallet::ChangeSet`] for external persistence, if any.
    pub fn take_staged(&mut self) -> Option<bdk_wallet::ChangeSet> {
        self.inner.take_staged()
    }

    /// Whether any staged changes await persistence.
    pub fn has_staged(&self) -> bool {
        self.inner.staged().is_some()
    }

    /// Extend the local chain to `height` (creates a synthetic block id).
    ///
    /// Used by tests and offline inject paths; production sync uses
    /// [`Self::apply_update`] with real checkpoints from a chain backend.
    pub fn ensure_tip_at_least(&mut self, height: u32) -> Result<(), WalletError> {
        let tip = self.inner.latest_checkpoint();
        let tip_h = tip.height();
        if tip_h >= height {
            return Ok(());
        }
        let mut cp = tip;
        for h in (tip_h + 1)..=height {
            // Distinct synthetic hashes so the chain oracle accepts the tip walk.
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&h.to_le_bytes());
            bytes[4] = 0x74; // 't' — test/synthetic marker
            let block = BlockId {
                height: h,
                hash: BlockHash::from_byte_array(bytes),
            };
            cp = cp.insert(block);
        }
        self.apply_update(Update {
            chain: Some(cp),
            ..Default::default()
        })
    }

    /// Inject a confirmed UTXO to the next unused address on `keychain`.
    ///
    /// Convenience for unit/property tests (no network). Production funds
    /// arrive through chain-backend `apply_update` (WP-13+).
    pub fn inject_confirmed_utxo(
        &mut self,
        amount_sats: u64,
        keychain: KeychainKind,
    ) -> Result<(OutPoint, AddressInfo), WalletError> {
        self.ensure_tip_at_least(1)?;
        let addr_info = self.next_unused_address(keychain);
        let spk = Address::from_str(&addr_info.address)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
            .require_network(to_bitcoin_network(self.network))
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
            .script_pubkey();

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(amount_sats),
                script_pubkey: spk,
            }],
        };
        let txid = tx.compute_txid();
        let tip = self.inner.latest_checkpoint();
        let anchor = ConfirmationBlockTime {
            block_id: tip.block_id(),
            confirmation_time: 1_700_000_000,
        };
        let mut tx_update = TxUpdate::default();
        tx_update.txs = vec![Arc::new(tx)];
        tx_update.anchors.insert((anchor, txid));
        self.apply_update(Update {
            tx_update,
            ..Default::default()
        })?;
        Ok((OutPoint { txid, vout: 0 }, addr_info))
    }

    // ── PSBT construction ───────────────────────────────────────────────

    /// Build a PSBT for `req` (production path: `finish()` → thread RNG).
    ///
    /// Sets:
    /// - `nLockTime = tip height` via `current_height` (BDK anti-fee-sniping)
    /// - `nSequence = 0xFFFFFFFD` via `set_exact_sequence` /
    ///   [`Sequence::ENABLE_RBF_NO_LOCKTIME`] (Spec §3.2: locktime + RBF)
    /// - coin selection: BDK default `BranchAndBoundCoinSelection<SingleRandomDraw>`
    /// - `add_global_xpubs` for hardware/multisig interop
    ///
    /// Dust change is absorbed into the fee by BDK `decide_change`
    /// (`coin_selection.rs:300–311`).
    pub fn build_psbt(&mut self, req: &SendRequest) -> Result<PsbtB64, WalletError> {
        let builder = self.tx_builder_for(req)?;
        let psbt = builder
            .finish()
            .map_err(|e| WalletError::Build(e.to_string()))?;
        Ok(psbt_to_b64(&psbt))
    }

    /// Build a PSBT with a caller-supplied RNG (tests: fixed seed).
    ///
    /// Spec §3.2 / TESTING.md §2.4: every test that bit-compares a built PSBT
    /// must use this path (not [`Self::build_psbt`]).
    pub fn build_psbt_with_aux_rand(
        &mut self,
        req: &SendRequest,
        rng: &mut impl RngCore,
    ) -> Result<PsbtB64, WalletError> {
        let builder = self.tx_builder_for(req)?;
        let psbt = builder
            .finish_with_aux_rand(rng)
            .map_err(|e| WalletError::Build(e.to_string()))?;
        Ok(psbt_to_b64(&psbt))
    }

    /// Build and return the raw [`Psbt`] (tests that inspect locktime/sequence).
    pub fn build_psbt_raw_with_aux_rand(
        &mut self,
        req: &SendRequest,
        rng: &mut impl RngCore,
    ) -> Result<Psbt, WalletError> {
        let builder = self.tx_builder_for(req)?;
        builder
            .finish_with_aux_rand(rng)
            .map_err(|e| WalletError::Build(e.to_string()))
    }

    /// Fee identity: `fee = Σin − Σout` for a built PSBT (P8 helper).
    ///
    /// Returns `(fee_sats, sum_in, sum_out)`. Errors on overflow or missing UTXO
    /// data on a PSBT input.
    pub fn fee_identity(psbt: &Psbt) -> Result<(u64, u64, u64), WalletError> {
        let mut sum_in: u64 = 0;
        for (idx, input) in psbt.inputs.iter().enumerate() {
            let value = if let Some(o) = input.witness_utxo.as_ref() {
                o.value.to_sat()
            } else if let Some(tx) = input.non_witness_utxo.as_ref() {
                let vout = psbt.unsigned_tx.input[idx].previous_output.vout as usize;
                tx.output
                    .get(vout)
                    .map(|o| o.value.to_sat())
                    .ok_or_else(|| WalletError::Build("vout OOB on non_witness_utxo".into()))?
            } else {
                return Err(WalletError::Build("missing utxo on psbt input".into()));
            };
            sum_in = sum_in
                .checked_add(value)
                .ok_or_else(|| WalletError::Overflow("input sum".into()))?;
        }

        let mut sum_out: u64 = 0;
        for o in &psbt.unsigned_tx.output {
            sum_out = sum_out
                .checked_add(o.value.to_sat())
                .ok_or_else(|| WalletError::Overflow("output sum".into()))?;
        }
        let fee = sum_in
            .checked_sub(sum_out)
            .ok_or_else(|| WalletError::Overflow("fee negative (out > in)".into()))?;
        Ok((fee, sum_in, sum_out))
    }

    fn tx_builder_for(
        &mut self,
        req: &SendRequest,
    ) -> Result<bdk_wallet::TxBuilder<'_, DefaultCoinSelectionAlgorithm>, WalletError> {
        let btc_net = to_bitcoin_network(self.network);
        let address = Address::from_str(&req.recipient)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
            .require_network(btc_net)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;

        let tip = self.inner.latest_checkpoint().height();
        // Default coin selection is already DefaultCoinSelectionAlgorithm =
        // BranchAndBoundCoinSelection<SingleRandomDraw> (coin_selection.rs:121).
        // Explicit re-set documents the acceptance criterion in the call path.
        let mut builder = self
            .inner
            .build_tx()
            .coin_selection(DefaultCoinSelectionAlgorithm::default());
        builder
            .add_recipient(address.script_pubkey(), Amount::from_sat(req.amount_sats))
            .current_height(tip)
            .set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME)
            .add_global_xpubs();

        match req.fee_target {
            FeeTarget::FeerateSatVb(vb) => {
                let rate = FeeRate::from_sat_per_vb(vb).ok_or_else(|| {
                    WalletError::InvalidFee(format!("feerate {vb} sat/vB out of range"))
                })?;
                builder.fee_rate(rate);
            }
            FeeTarget::AbsoluteSats(sats) => {
                builder.fee_absolute(Amount::from_sat(sats));
            }
        }
        Ok(builder)
    }
}

// ── Mapping helpers ─────────────────────────────────────────────────────

fn to_bitcoin_network(n: Network) -> BtcNetwork {
    match n {
        Network::Bitcoin => BtcNetwork::Bitcoin,
        Network::Testnet => BtcNetwork::Testnet,
        Network::Signet => BtcNetwork::Signet,
        Network::Regtest => BtcNetwork::Regtest,
    }
}

fn to_bdk_keychain(k: KeychainKind) -> BdkKeychain {
    match k {
        KeychainKind::External => BdkKeychain::External,
        KeychainKind::Internal => BdkKeychain::Internal,
    }
}

fn from_bdk_keychain(k: BdkKeychain) -> KeychainKind {
    match k {
        BdkKeychain::External => KeychainKind::External,
        BdkKeychain::Internal => KeychainKind::Internal,
    }
}

fn from_bdk_address_info(info: bdk_wallet::AddressInfo) -> AddressInfo {
    AddressInfo::new(
        info.address.to_string(),
        info.index,
        from_bdk_keychain(info.keychain),
    )
}

fn psbt_to_b64(psbt: &Psbt) -> PsbtB64 {
    PsbtB64::new(encode::encode_base64(&psbt.serialize()))
}

/// Decode a base64 PSBT (integration / unit tests).
pub fn decode_psbt_b64(b64: &str) -> Result<Psbt, WalletError> {
    // bitcoin 0.32 without base64 feature: decode manually then deserialize.
    let bytes = decode_base64(b64).map_err(WalletError::Build)?;
    bitcoin::psbt::Psbt::deserialize(&bytes).map_err(|e| WalletError::Build(e.to_string()))
}

fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 byte {c}")),
        }
    }
    let s = s.trim().as_bytes();
    if !s.len().is_multiple_of(4) {
        return Err("base64 length not multiple of 4".into());
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut i = 0;
    while i < s.len() {
        let a = val(s[i])?;
        let b = val(s[i + 1])?;
        let pad_c = s[i + 2] == b'=';
        let pad_d = s[i + 3] == b'=';
        let c = if pad_c { 0 } else { val(s[i + 2])? };
        let d = if pad_d { 0 } else { val(s[i + 3])? };
        let n = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        out.push(((n >> 16) & 0xff) as u8);
        if !pad_c {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if !pad_d {
            out.push((n & 0xff) as u8);
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{
        bip48_origin_path, build_wallet_descriptors, KeyContribution, KeySource,
    };
    use bdk_wallet::bitcoin::key::rand::{rngs::StdRng, SeedableRng};
    use trinity_types::{Fingerprint, KeySlot, WordCount, XpubWithOrigin};

    // Fixed tpubs from BDK Caravan tests (regtest/testnet).
    const FP_A: &str = "73756c7f";
    const FP_B: &str = "f9f62194";
    const FP_C: &str = "c98b1535";
    const XPUB_A: &str = "tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3";
    const XPUB_B: &str = "tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4";
    const XPUB_C: &str = "tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a";

    fn sample_descriptors() -> WalletDescriptors {
        let path = bip48_origin_path(Network::Regtest);
        let keys = [
            KeyContribution {
                slot: KeySlot::A,
                xpub: XpubWithOrigin::new(
                    Fingerprint::from_hex(FP_A).unwrap(),
                    path.clone(),
                    XPUB_A,
                ),
                birthday_height: 1,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
            KeyContribution {
                slot: KeySlot::B,
                xpub: XpubWithOrigin::new(
                    Fingerprint::from_hex(FP_B).unwrap(),
                    path.clone(),
                    XPUB_B,
                ),
                birthday_height: 1,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
            KeyContribution {
                slot: KeySlot::C,
                xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_C).unwrap(), path, XPUB_C),
                birthday_height: 1,
                word_count: WordCount::Words24,
                source: KeySource::InApp,
                policy_id: None,
            },
        ];
        build_wallet_descriptors(Network::Regtest, keys, 1_700_000_000).unwrap()
    }

    fn open_funded(amount_sats: u64) -> WatchWallet {
        let d = sample_descriptors();
        let mut w = WatchWallet::from_descriptors(&d).unwrap();
        w.inject_confirmed_utxo(amount_sats, KeychainKind::External)
            .unwrap();
        w
    }

    fn fixed_rng() -> StdRng {
        StdRng::seed_from_u64(PSBT_BUILD_SEED)
    }

    #[test]
    fn create_and_derive_receive_change() {
        let d = sample_descriptors();
        let mut w = WatchWallet::from_descriptors(&d).unwrap();
        assert_eq!(w.network(), Network::Regtest);
        assert_eq!(w.gap_limit(), 20);
        assert_eq!(w.tip_height(), 0);

        let r0 = w.reveal_next_address(KeychainKind::External);
        assert_eq!(r0.index, 0);
        assert_eq!(r0.keychain, KeychainKind::External);
        assert!(r0.address.starts_with("bcrt1"));

        let r1 = w.reveal_next_address(KeychainKind::External);
        assert_eq!(r1.index, 1);
        assert_ne!(r0.address, r1.address);

        let c0 = w.reveal_next_address(KeychainKind::Internal);
        assert_eq!(c0.keychain, KeychainKind::Internal);
        assert_ne!(c0.address, r0.address);

        let peek = w.peek_address(KeychainKind::External, 0);
        assert_eq!(peek.address, r0.address);

        let batch = w.derive_addresses(KeychainKind::External, 3);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].address, r0.address);
        assert!(w.has_staged());
        assert!(w.take_staged().is_some());
    }

    #[test]
    fn balance_and_list_unspent_after_inject() {
        let w = open_funded(100_000);
        let bal = w.balance();
        assert_eq!(bal.confirmed_sats, 100_000);
        assert_eq!(bal.spend_policy_reference_sats(), 100_000);
        let utxos = w.list_unspent();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].amount_sats, 100_000);
        assert_eq!(utxos[0].keychain, KeychainKind::External);
    }

    #[test]
    fn anti_fee_sniping_locktime_and_sequence() {
        let mut w = open_funded(200_000);
        // Raise tip so locktime is non-zero and distinguishable from default 0.
        w.ensure_tip_at_least(42).unwrap();
        assert_eq!(w.tip_height(), 42);

        let recipient = w.peek_address(KeychainKind::External, 5).address;
        let req = SendRequest::new(recipient, 10_000, FeeTarget::AbsoluteSats(1_000));
        let mut rng = fixed_rng();
        let psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
        let tx = &psbt.unsigned_tx;
        assert_eq!(
            tx.lock_time,
            absolute::LockTime::from_height(42).unwrap(),
            "nLockTime must equal tip height"
        );
        for tin in &tx.input {
            assert_eq!(
                tin.sequence,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                "nSequence must be 0xFFFFFFFD (ENABLE_RBF_NO_LOCKTIME)"
            );
            assert_eq!(
                tin.sequence.to_consensus_u32(),
                ANTI_FEE_SNIPING_SEQUENCE,
                "exported sequence constant must match built nSequence"
            );
            assert!(
                tin.sequence.is_rbf(),
                "BIP-125: nSequence must signal replaceability"
            );
        }
        assert!(
            tx.is_explicitly_rbf(),
            "BIP-125: built transaction must be explicitly replaceable"
        );
    }

    #[test]
    fn p8_fee_identity_holds() {
        let mut w = open_funded(150_000);
        w.ensure_tip_at_least(1).unwrap();
        let recipient = w.peek_address(KeychainKind::External, 3).address;
        let req = SendRequest::new(recipient, 20_000, FeeTarget::AbsoluteSats(2_000));
        let mut rng = fixed_rng();
        let psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
        let (fee, sum_in, sum_out) = WatchWallet::fee_identity(&psbt).unwrap();
        assert_eq!(fee, sum_in - sum_out);
        assert_eq!(fee, 2_000);
        assert_eq!(sum_in, 150_000);
    }

    #[test]
    fn dust_change_goes_into_fee() {
        // Fund just enough that change would be dust after a large absolute fee.
        // P2WSH dust is higher than P2WPKH; use a tight remaining amount.
        let mut w = open_funded(50_000);
        w.ensure_tip_at_least(1).unwrap();
        let recipient = w.peek_address(KeychainKind::External, 2).address;
        // Send most of it; leave a remainder that is dust after fee for change.
        // amount 49_000 + fee 900 = 49_900 → remaining 100 sats change → dust.
        let req = SendRequest::new(recipient, 49_000, FeeTarget::AbsoluteSats(900));
        let mut rng = fixed_rng();
        let psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
        // Only recipient output — no change output.
        assert_eq!(
            psbt.unsigned_tx.output.len(),
            1,
            "dust change must not produce a change output"
        );
        let (fee, sum_in, sum_out) = WatchWallet::fee_identity(&psbt).unwrap();
        assert_eq!(sum_in, 50_000);
        assert_eq!(sum_out, 49_000);
        // Fee absorbs the 100 sat dust remainder (900 requested + 100 dust).
        assert_eq!(fee, 1_000);
        assert!(fee > 900, "dust remainder must fold into fee");
    }

    #[test]
    fn changeless_preferred_when_exact() {
        let mut w = open_funded(100_000);
        w.ensure_tip_at_least(1).unwrap();
        let recipient = w.peek_address(KeychainKind::External, 4).address;
        // Exact: 100_000 in = 99_000 out + 1_000 fee → no change needed.
        let req = SendRequest::new(recipient, 99_000, FeeTarget::AbsoluteSats(1_000));
        let mut rng = fixed_rng();
        let psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
        let (fee, _, _) = WatchWallet::fee_identity(&psbt).unwrap();
        assert_eq!(fee, 1_000);
    }

    #[test]
    fn finish_with_aux_rand_is_deterministic() {
        let d = sample_descriptors();
        let mut w1 = WatchWallet::from_descriptors(&d).unwrap();
        w1.inject_confirmed_utxo(80_000, KeychainKind::External)
            .unwrap();
        w1.ensure_tip_at_least(1).unwrap();
        let recipient = w1.peek_address(KeychainKind::External, 1).address.clone();
        let req = SendRequest::new(&recipient, 10_000, FeeTarget::AbsoluteSats(500));

        let mut rng_a = StdRng::seed_from_u64(PSBT_BUILD_SEED);
        let b64_a = w1.build_psbt_with_aux_rand(&req, &mut rng_a).unwrap();

        let mut w2 = WatchWallet::from_descriptors(&d).unwrap();
        w2.inject_confirmed_utxo(80_000, KeychainKind::External)
            .unwrap();
        w2.ensure_tip_at_least(1).unwrap();
        let mut rng_b = StdRng::seed_from_u64(PSBT_BUILD_SEED);
        let b64_b = w2.build_psbt_with_aux_rand(&req, &mut rng_b).unwrap();

        assert_eq!(
            b64_a.as_str(),
            b64_b.as_str(),
            "same seed must yield identical PSBT base64"
        );
    }

    #[test]
    fn build_psbt_production_path_succeeds() {
        let mut w = open_funded(60_000);
        w.ensure_tip_at_least(1).unwrap();
        let recipient = w.peek_address(KeychainKind::External, 6).address;
        let req = SendRequest::new(recipient, 5_000, FeeTarget::FeerateSatVb(2));
        let b64 = w.build_psbt(&req).unwrap();
        assert!(!b64.as_str().is_empty());
        // Round-trip decode.
        let psbt = decode_psbt_b64(b64.as_str()).unwrap();
        assert!(!psbt.unsigned_tx.input.is_empty());
    }

    #[test]
    fn rejects_bad_recipient_and_feerate() {
        let mut w = open_funded(50_000);
        w.ensure_tip_at_least(1).unwrap();
        let err = w
            .build_psbt(&SendRequest::new(
                "not-an-address",
                1_000,
                FeeTarget::AbsoluteSats(100),
            ))
            .unwrap_err();
        assert!(matches!(err, WalletError::InvalidAddress(_)));

        // Network mismatch: mainnet address on regtest wallet.
        let err = w
            .build_psbt(&SendRequest::new(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                1_000,
                FeeTarget::AbsoluteSats(100),
            ))
            .unwrap_err();
        assert!(matches!(err, WalletError::InvalidAddress(_)));

        let recipient = w.peek_address(KeychainKind::External, 0).address;
        // from_sat_per_vb rejects values that overflow internal scale.
        let err = w
            .build_psbt(&SendRequest::new(
                recipient,
                1_000,
                FeeTarget::FeerateSatVb(u64::MAX),
            ))
            .unwrap_err();
        assert!(matches!(err, WalletError::InvalidFee(_)));
    }

    #[test]
    fn insufficient_funds_is_build_error() {
        let mut w = open_funded(1_000);
        w.ensure_tip_at_least(1).unwrap();
        let recipient = w.peek_address(KeychainKind::External, 0).address;
        let err = w
            .build_psbt(&SendRequest::new(
                recipient,
                500_000,
                FeeTarget::AbsoluteSats(100),
            ))
            .unwrap_err();
        assert!(matches!(err, WalletError::Build(_)));
    }

    #[test]
    fn next_unused_and_ensure_tip_idempotent() {
        let d = sample_descriptors();
        let mut w = WatchWallet::from_descriptors(&d).unwrap();
        let a = w.next_unused_address(KeychainKind::External);
        let b = w.next_unused_address(KeychainKind::External);
        // Without marking used, next_unused stays at the same index.
        assert_eq!(a.index, b.index);
        w.ensure_tip_at_least(5).unwrap();
        assert_eq!(w.tip_height(), 5);
        w.ensure_tip_at_least(3).unwrap();
        assert_eq!(w.tip_height(), 5);
    }

    #[test]
    fn fee_identity_missing_utxo_errors() {
        // Empty PSBT-like structure via a real build then strip witness_utxo.
        let mut w = open_funded(40_000);
        w.ensure_tip_at_least(1).unwrap();
        let recipient = w.peek_address(KeychainKind::External, 0).address;
        let req = SendRequest::new(recipient, 5_000, FeeTarget::AbsoluteSats(500));
        let mut rng = fixed_rng();
        let mut psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
        for input in &mut psbt.inputs {
            input.witness_utxo = None;
            input.non_witness_utxo = None;
        }
        assert!(matches!(
            WatchWallet::fee_identity(&psbt),
            Err(WalletError::Build(_))
        ));
    }

    #[test]
    fn error_display_covers_variants() {
        for e in [
            WalletError::Create("c".into()),
            WalletError::InvalidAddress("a".into()),
            WalletError::InvalidFee("f".into()),
            WalletError::Build("b".into()),
            WalletError::ApplyUpdate("u".into()),
            WalletError::Overflow("o".into()),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn base64_roundtrip_psbt_bytes() {
        let raw = b"hello psbt";
        let enc = encode::encode_base64(raw);
        let dec = decode_base64(&enc).unwrap();
        assert_eq!(dec, raw);
        assert!(decode_base64("abc").is_err()); // bad length
        assert!(decode_base64("!!!!").is_err());
    }

    #[test]
    fn default_coin_selection_type_is_bnb_srd() {
        // Runtime twin of the const _: () type equality above.
        let a = DefaultCoinSelectionAlgorithm::default();
        let b = BranchAndBoundCoinSelection::<SingleRandomDraw>::default();
        // Both are unit-like / default-constructible the same way; sizes match.
        assert_eq!(
            std::mem::size_of_val(&a),
            std::mem::size_of_val(&b),
            "DefaultCoinSelectionAlgorithm must stay BnB+SRD sized"
        );
    }

    #[test]
    fn foreign_descriptor_rejected() {
        let err = WatchWallet::from_descriptor_strings(
            Network::Regtest,
            "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/0/*)#checksum",
            "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/1/*)#checksum",
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::Descriptor(_)));
    }

    #[test]
    fn network_mapping_all_variants() {
        assert_eq!(to_bitcoin_network(Network::Bitcoin), BtcNetwork::Bitcoin);
        assert_eq!(to_bitcoin_network(Network::Testnet), BtcNetwork::Testnet);
        assert_eq!(to_bitcoin_network(Network::Signet), BtcNetwork::Signet);
        assert_eq!(to_bitcoin_network(Network::Regtest), BtcNetwork::Regtest);
        assert_eq!(
            from_bdk_keychain(BdkKeychain::External),
            KeychainKind::External
        );
        assert_eq!(
            from_bdk_keychain(BdkKeychain::Internal),
            KeychainKind::Internal
        );
        assert_eq!(
            to_bdk_keychain(KeychainKind::External),
            BdkKeychain::External
        );
        assert_eq!(
            to_bdk_keychain(KeychainKind::Internal),
            BdkKeychain::Internal
        );
    }

    #[test]
    fn fee_identity_via_non_witness_utxo() {
        // Build a real PSBT (witness_utxo filled), then move value data onto
        // non_witness_utxo only so the fallback arm of fee_identity runs.
        let mut w = open_funded(55_000);
        w.ensure_tip_at_least(1).unwrap();
        let recipient = w.peek_address(KeychainKind::External, 0).address;
        let req = SendRequest::new(recipient, 8_000, FeeTarget::AbsoluteSats(600));
        let mut rng = fixed_rng();
        let mut psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();

        for (idx, input) in psbt.inputs.iter_mut().enumerate() {
            let wit = input.witness_utxo.take().expect("witness_utxo present");
            let vout = psbt.unsigned_tx.input[idx].previous_output.vout;
            // Minimal parent tx carrying the spent output at the right vout.
            let mut outputs = vec![
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::new(),
                };
                vout as usize + 1
            ];
            outputs[vout as usize] = wit;
            let parent = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: outputs,
            };
            input.non_witness_utxo = Some(parent);
        }

        let (fee, sum_in, sum_out) = WatchWallet::fee_identity(&psbt).unwrap();
        assert_eq!(fee.checked_add(sum_out), Some(sum_in));
        assert_eq!(sum_in, 55_000);
    }

    #[test]
    fn fee_identity_non_witness_vout_oob() {
        let mut w = open_funded(40_000);
        w.ensure_tip_at_least(1).unwrap();
        let recipient = w.peek_address(KeychainKind::External, 0).address;
        let req = SendRequest::new(recipient, 5_000, FeeTarget::AbsoluteSats(400));
        let mut rng = fixed_rng();
        let mut psbt = w.build_psbt_raw_with_aux_rand(&req, &mut rng).unwrap();
        for input in &mut psbt.inputs {
            input.witness_utxo = None;
            // Parent with empty outputs → vout OOB.
            input.non_witness_utxo = Some(Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            });
        }
        assert!(matches!(
            WatchWallet::fee_identity(&psbt),
            Err(WalletError::Build(_))
        ));
    }
}
