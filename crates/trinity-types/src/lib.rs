//! `trinity-types` — pure value types for the Trinity workspace.
//!
//! Spec: docs/SPECIFICATION.md §1.1, §1.3. Work package: WP-10.
//!
//! No I/O, no keystore/signer access, no secrets in `Debug`/`Display`
//! (except the fixed `"[redacted]"` for [`SecretBytes`]). `SecretBytes` is
//! part of the Rust API for core crates but is **not** a uniffi export.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod address;
mod balance;
mod fingerprint;
mod key_slot;
mod network;
mod psbt;
mod secret;
mod send;
mod verdict;
mod word_count;
mod xpub;

pub use address::{AddressInfo, KeychainKind};
pub use balance::Balance;
pub use fingerprint::{Fingerprint, FingerprintParseError};
pub use key_slot::KeySlot;
pub use network::Network;
pub use psbt::PsbtB64;
pub use secret::SecretBytes;
pub use send::{FeeTarget, SendRequest};
pub use verdict::PsbtVerdict;
pub use word_count::WordCount;
pub use xpub::XpubWithOrigin;
