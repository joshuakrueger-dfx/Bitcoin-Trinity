//! `trinity-watch` — watch-only wallet core.
//!
//! Spec: docs/SPECIFICATION.md §1.1, §2.3, §3.2.
//! Work packages: WP-11 (descriptor generation and persistence),
//! WP-12 (BDK wallet, address derivation, UTXO management, TxBuilder).
//!
//! **No key material** — only xpubs and descriptors. No access to
//! `trinity-keystore` or `trinity-signer` (enforced via `deny.toml` bans).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod descriptor;
pub mod wallet;

pub use descriptor::{
    bip48_origin_path, DescriptorError, DescriptorSetup, KeyContribution, KeySource,
    WalletDescriptors, FORMAT_VERSION, MULTISIG_THRESHOLD,
};
pub use wallet::{
    decode_psbt_b64, UtxoInfo, WalletError, WatchWallet, ANTI_FEE_SNIPING_SEQUENCE, GAP_LIMIT,
    PSBT_BUILD_SEED,
};
