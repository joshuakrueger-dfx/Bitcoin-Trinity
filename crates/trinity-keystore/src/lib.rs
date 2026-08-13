//! `trinity-keystore` — encrypted on-device blobs for keys A and B (Spec §2.4).
//!
//! Blob encode/decode is [`encrypt`] / [`decrypt`]. Access-class policy
//! ([`SlotPolicy`], [`POLICY_A`], [`POLICY_B`]) and the platform callback
//! ([`PlatformKeyStore`]) are the WP-32 layer around that format. Argon2id
//! *computation* is WP-35; this crate only names [`ArgonProfile`]. Real
//! Secure Enclave / Android Keystore implementations are WP-41 / WP-42.
//!
//! The blob *format* is identical for A and B. Two sealed blobs that differ
//! only in `slot` also differ in the Poly1305 tag, because `slot` is AAD.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

mod blob;
mod platform;
mod policy;

pub use blob::{
    decrypt, encrypt, BlobError, DecodedBlob, HEADER_LEN, MAGIC, NONCE_LEN, SLOT_OFFSET, TAG_LEN,
    VERSION, WORD_COUNT_OFFSET,
};
pub use platform::{PlatformError, PlatformKeyStore};
pub use policy::{ArgonProfile, HwBinding, SlotPolicy, UnlockFactor, POLICY_A, POLICY_B};

#[cfg(any(test, feature = "test-util"))]
pub use blob::encrypt_with_nonce;

#[cfg(any(test, feature = "test-util"))]
mod fake;
#[cfg(any(test, feature = "test-util"))]
pub use fake::FakePlatformKeyStore;

#[cfg(test)]
mod p6_p13;
#[cfg(test)]
mod zeroize_proof;
