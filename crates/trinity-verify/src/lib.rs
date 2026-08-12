//! `trinity-verify` — independent descriptor parser and key derivation (WP-20 / WP-21).
//!
//! Spec: `docs/SPECIFICATION.md` §1.5, Decision E2.
//!
//! This crate parses **exactly** one grammar:
//!
//! ```text
//! descriptor  := "wsh(" sortedmulti ")" "#" checksum
//! sortedmulti := "sortedmulti(" k "," keyexpr ("," keyexpr){2} ")"
//! keyexpr     := "[" fingerprint "/" origin_path "]" xpub "/" derivation
//! ```
//!
//! with `k = 2` and exactly three `keyexpr`s. Everything else is a hard
//! [`ParseError`]. BIP-380 checksum validation is included (check V1).
//!
//! It also derives independently of the builder (WP-21):
//!
//! - own BIP-32 CKDpub ([`ckd_pub`], [`derive_child`], [`derive_at`])
//! - own BIP-67 sorting ([`sort_pubkeys`], [`sort_three`])
//! - own witnessScript construction ([`witness_script_2of3`],
//!   [`build_checkmultisig_script`])
//!
//! **Not in scope (WP-22):** checks V2–V10, or `verify()` on a PSBT.
//!
//! **Prohibited dependency:** `miniscript` (direct or transitive). Enforced
//! by `deny.toml` `[bans]` wrappers and CI `cargo deny check`.
//!
//! **Independence boundary (Spec §1.5):** derivation and sorting here must not
//! call `bitcoin::bip32::Xpub::derive_pub` / `ckd_pub` / `derive_priv`. Shared
//! remain only `bitcoin::hashes` (HMAC-SHA512 / SHA-256) and
//! `bitcoin::secp256k1` (EC point arithmetic). `Xpub::from_str` is used only
//! to base58check-decode an xpub into raw fields.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

mod bip67;
mod checksum;
mod ckd;
mod derive;
mod error;
mod parse;
mod types;
mod witness;

pub use bip67::{sort_pubkeys, sort_three};
pub use ckd::{ckd_pub, ChildKey, MAX_NON_HARDENED_INDEX};
pub use derive::{decode_xpub, derive_at, derive_child, DerivedChild, DerivedOutput};
pub use error::{DeriveError, ParseError};
pub use parse::{parse, parse_trinity_descriptor};
pub use types::{DerivationBranch, KeyExpr, ParsedDescriptor};
pub use witness::{
    build_checkmultisig_script, p2wsh_address, p2wsh_script_pubkey, witness_script_2of3,
};
