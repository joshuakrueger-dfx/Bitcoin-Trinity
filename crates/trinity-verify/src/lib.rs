//! `trinity-verify` — independent descriptor parser (WP-20).
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
//! **Not in scope (WP-21 / WP-22):** BIP-32 CKDpub, BIP-67 sorting,
//! witnessScript construction, checks V2–V10, or `verify()` on a PSBT.
//!
//! **Prohibited dependency:** `miniscript` (direct or transitive). Enforced
//! by `deny.toml` `[bans]` wrappers and CI `cargo deny check`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

mod checksum;
mod error;
mod parse;
mod types;

pub use error::ParseError;
pub use parse::{parse, parse_trinity_descriptor};
pub use types::{DerivationBranch, KeyExpr, ParsedDescriptor};
