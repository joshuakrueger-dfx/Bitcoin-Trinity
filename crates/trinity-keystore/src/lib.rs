//! `trinity-keystore` — encrypted on-device blobs for keys A and B (Spec §2.4).
//!
//! This crate currently implements only the blob encode/decode container
//! (WP-31). KEK derivation, Argon2id, `SlotPolicy`, and `PlatformKeyStore`
//! are WP-32 and are not present here.
//!
//! The blob *format* is identical for A and B. Two sealed blobs that differ
//! only in `slot` also differ in the Poly1305 tag, because `slot` is AAD.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

mod blob;

pub use blob::{
    decrypt, encrypt, BlobError, DecodedBlob, HEADER_LEN, MAGIC, NONCE_LEN, SLOT_OFFSET, TAG_LEN,
    VERSION, WORD_COUNT_OFFSET,
};

#[cfg(any(test, feature = "test-util"))]
pub use blob::encrypt_with_nonce;

#[cfg(test)]
mod p6_p13;
