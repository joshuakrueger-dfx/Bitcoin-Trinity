//! Descriptor generation and `descriptor.json` persistence — Spec §2.3, WP-11.
//!
//! Builds separate receive (`/0/*`) and change (`/1/*`) `wsh(sortedmulti(2,…))`
//! descriptors with BIP-48 origin info and BIP-380 checksum. Multipath
//! (BIP-389) is never produced (decision O8).

pub mod build;
mod document;
mod error;
mod path;
mod source;

pub use build::{build_wallet_descriptors, validate_trinity_descriptor, MULTISIG_THRESHOLD};
pub use document::{DescriptorSetup, KeyContribution, WalletDescriptors, FORMAT_VERSION};
pub use error::DescriptorError;
pub use path::bip48_origin_path;
pub use source::KeySource;
