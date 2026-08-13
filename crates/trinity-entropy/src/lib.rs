//! `trinity-entropy` — seed generation (Spec §2.1–§2.2.5).
//!
//! A weak seed from this crate is **permanent**. Every rejection is a hard
//! error; nothing here silently degrades (the Coldcard July 2026 lesson).
//!
//! Construction (Spec §2.2):
//!
//! ```text
//! L           := 32 (24 words) or 16 (12 words)
//! raw_csprng  := getrandom(32)
//! extra_bytes := canonical encoding of the additional source
//! extract     := HMAC-SHA512(key = raw_csprng, msg = extra_bytes)
//! entropy     := extract[0..L]
//! mnemonic    := BIP-39(entropy)
//! seed        := PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64)
//! xprv        := BIP-32-Master(seed)
//! ```
//!
//! This is an **OR combiner**: security is `max` of the two sources. Additional
//! entropy is optional. Key C is generated only via [`generate_c`] /
//! [`generate_c_from_raw`], which hardcode 24 words (S15b).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

mod entropy;
mod error;
mod evidence;
mod hex;
mod sources;

pub use entropy::{
    bip39_from_entropy, extract, generate, generate_c, generate_c_from_raw, generate_from_raw,
    Bip39Material, GeneratedKey,
};
pub use error::{CardError, EntropyError};
pub use evidence::{bytes_to_hex, VerificationSheet};
pub use sources::{
    encode_slots, AdditionalEntropy, Card, CountableEntropy, Rank, Suit, SLOT_SEPARATOR,
};

#[cfg(test)]
mod zeroize_proof;
