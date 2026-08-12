//! `trinity-watch` — watch-only wallet core.
//!
//! Spec: docs/SPECIFICATION.md §1.1, §2.3, §3.2.
//! Work package: WP-11 (descriptor generation and persistence); WP-12 follows.
//!
//! **No key material** — only xpubs and descriptors. No access to
//! `trinity-keystore` or `trinity-signer`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod descriptor;

pub use descriptor::{
    bip48_origin_path, DescriptorError, DescriptorSetup, KeyContribution, KeySource,
    WalletDescriptors, FORMAT_VERSION, MULTISIG_THRESHOLD,
};
