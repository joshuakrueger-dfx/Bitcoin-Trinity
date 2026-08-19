//! `trinity-signer` — RFC-6979 signatures behind a swappable [`Signer`] (Spec §3.4, §6.6).
//!
//! [`LocalSigner`] unlocks one on-device slot (A or B) and signs a PSBT.
//! Crate-internal `sign_a` / `sign_b` (composed by [`sign_ab`]) run the
//! independent verifier **before** any `unwrap_kek` (S9) and bind the
//! unsigned txid between the two signatures (S10). FFI export is WP-40.
//!
//! [`sign_ab`] evaluates [`SpendPolicy`] against the encrypted window
//! counter **before** either slot is unlocked (S28 / S29k). That check
//! is on [`sign_ab`] only — [`LocalSigner::sign`] is the WP-33 primitive
//! and does not apply the limit.
//!
//! [`finalize`] turns a twice-signed PSBT into a transaction: BIP-67
//! witness order, `bitcoinconsensus` (O7), then exact vsize against
//! `max_feerate`. Nothing is sent here; broadcast belongs on the facade,
//! with a separately configurable backend (Spec §1.6).
//!
//! External signer kinds exist on [`SignerKind`] so the trait is complete;
//! `ExternalSigner` itself lives in `trinity-transport` (WP-50+).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

mod clock;
mod core_state;
mod error;
mod finalize;
mod kind;
mod limits;
mod local;
mod sign;
mod window;

pub use clock::{BlockHeightSource, MonotonicClock};
#[cfg(any(test, feature = "test-util"))]
pub use clock::{FakeBlockHeightSource, FakeClock};
pub use core_state::CoreStateError;
pub use error::SignError;
pub use finalize::finalize;
pub use kind::SignerKind;
pub use limits::{allowance, set_spend_policy, Ratio, SpendPolicy};
pub use local::LocalSigner;
pub use sign::sign_ab;
pub use window::{SpendApproval, SpendSession, WindowCounter};

use bitcoin::psbt::Psbt;
use trinity_types::Fingerprint;

/// One signature contributor (Spec §6.6).
///
/// `sign_b` later calls only this trait — swapping software-B for hardware-B
/// is a configuration change (E5). Implementations must not draw a nonce
/// from an RNG.
pub trait Signer: Send + Sync {
    /// BIP-32 master fingerprint of the key this signer holds.
    fn fingerprint(&self) -> Fingerprint;

    /// Add this signer's `SIGHASH_ALL` partial signature to `psbt`.
    fn sign(&self, psbt: Psbt) -> Result<Psbt, SignError>;

    /// Local vs. external transport.
    fn kind(&self) -> SignerKind;
}

#[cfg(all(test, feature = "differential"))]
mod tests_d10_d11;
#[cfg(all(test, feature = "differential"))]
mod tests_d7_d8;
#[cfg(test)]
mod tests_wp33;
#[cfg(test)]
mod tests_wp34;
#[cfg(test)]
mod tests_wp36;
#[cfg(test)]
mod zeroize_proof;
