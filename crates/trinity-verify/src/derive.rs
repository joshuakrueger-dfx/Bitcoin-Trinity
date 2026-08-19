//! Combine ParsedDescriptor + address index → child keys, BIP-67 sort, scripts.
//!
//! WP-22 will call this path for checks V2–V4 (reconstruct witnessScript /
//! scriptPubKey from the stored descriptor and compare). Public surface keeps
//! descriptor-order children, sorted children, and scripts separate so V4 can
//! re-check `bip32_derivation` fingerprints against the unsorted set.

use std::str::FromStr;

use bitcoin::bip32::Xpub;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, ScriptBuf};

use crate::bip67;
use crate::ckd;
use crate::error::DeriveError;
use crate::types::{DerivationBranch, KeyExpr, ParsedDescriptor};
use crate::witness;

/// Compressed public key produced for one `KeyExpr` at address index `i`.
///
/// Descriptor order is preserved: `fingerprint` / `xpub` identify which of the
/// three keys this child belongs to (needed for V4 fingerprint mapping).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedChild {
    /// Master fingerprint from the key expression (not re-derived).
    pub fingerprint: trinity_types::Fingerprint,
    /// Branch used for the first CKD step (`/0` or `/1`).
    pub branch: DerivationBranch,
    /// Address index `i` (second CKD step).
    pub address_index: u32,
    /// Child compressed SEC1 pubkey at `xpub / branch / i`.
    pub public_key: [u8; 33],
    /// Child chain code after the second CKD step (rarely needed; exposed for
    /// further non-hardened derivation if a later WP requires it).
    pub chain_code: [u8; 32],
}

/// Full independent derivation of a Trinity receive/change output at index `i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedOutput {
    /// Child pubkeys in **descriptor key order** (before BIP-67 sort).
    pub children: [DerivedChild; 3],
    /// The three child pubkeys after BIP-67 sort (witnessScript order).
    pub sorted_pubkeys: [[u8; 33]; 3],
    /// `OP_2 <sorted pk1> <sorted pk2> <sorted pk3> OP_3 OP_CHECKMULTISIG`.
    pub witness_script: ScriptBuf,
    /// P2WSH `scriptPubKey`: `OP_0 <sha256(witnessScript)>`.
    pub script_pubkey: ScriptBuf,
}

impl DerivedOutput {
    /// Bech32 P2WSH address for this output on `network`.
    #[must_use]
    pub fn address(&self, network: Network) -> Address {
        witness::p2wsh_address(self.witness_script.as_script(), network)
    }

    /// Sorted pubkeys as a flat list (convenience for callers that want a slice).
    #[must_use]
    pub fn sorted_pubkeys_slice(&self) -> &[[u8; 33]; 3] {
        &self.sorted_pubkeys
    }
}

/// Decode an xpub/tpub string to chain code + compressed pubkey only.
///
/// Uses `Xpub::from_str` solely for base58check field extraction — the same
/// approved boundary as the WP-20 parser. No child derivation is performed.
pub fn decode_xpub(xpub: &str) -> Result<([u8; 32], [u8; 33]), DeriveError> {
    let xp = Xpub::from_str(xpub).map_err(|_| DeriveError::MalformedXpub)?;
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(xp.chain_code.as_ref());
    Ok((chain_code, xp.public_key.serialize()))
}

/// Derive one child compressed pubkey for a `KeyExpr` at address index `i`.
///
/// Performs two non-hardened CKDpub steps: `xpub / branch / i` where `branch`
/// is `0` (external) or `1` (internal). Origin path (`48'/…/2'`) is already
/// baked into the account xpub and is not re-derived.
pub fn derive_child(key: &KeyExpr, address_index: u32) -> Result<DerivedChild, DeriveError> {
    if address_index > ckd::MAX_NON_HARDENED_INDEX {
        return Err(DeriveError::HardenedIndex(address_index));
    }

    let (chain0, pk0) = decode_xpub(&key.xpub)?;
    let branch_index = match key.derivation {
        DerivationBranch::External => 0u32,
        DerivationBranch::Internal => 1u32,
    };

    let mid = ckd::ckd_pub(&chain0, &pk0, branch_index)?;
    let child = ckd::ckd_pub(&mid.chain_code, &mid.public_key, address_index)?;

    // Defensive: ensure SEC1 bytes still parse (ckd_pub already serializes a valid key).
    let _ = PublicKey::from_slice(&child.public_key).map_err(|_| DeriveError::InvalidPublicKey)?;

    Ok(DerivedChild {
        fingerprint: key.fingerprint,
        branch: key.derivation,
        address_index,
        public_key: child.public_key,
        chain_code: child.chain_code,
    })
}

/// Derive all three children, BIP-67-sort, and build witnessScript / scriptPubKey.
///
/// Does not encode a network-specific address; call [`DerivedOutput::address`]
/// with the intended [`Network`] (regtest vs testnet share tpub but differ in HRP).
pub fn derive_at(
    descriptor: &ParsedDescriptor,
    address_index: u32,
) -> Result<DerivedOutput, DeriveError> {
    let c0 = derive_child(&descriptor.keys[0], address_index)?;
    let c1 = derive_child(&descriptor.keys[1], address_index)?;
    let c2 = derive_child(&descriptor.keys[2], address_index)?;
    let children = [c0, c1, c2];

    let unsorted = [
        children[0].public_key,
        children[1].public_key,
        children[2].public_key,
    ];
    let sorted_pubkeys = bip67::sort_three(unsorted);
    let witness_script = witness::witness_script_2of3(&sorted_pubkeys)?;
    let script_pubkey = witness::p2wsh_script_pubkey(witness_script.as_script());

    Ok(DerivedOutput {
        children,
        sorted_pubkeys,
        witness_script,
        script_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    const RECEIVE: &str = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/0/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/0/*\
))#ttrgvxfp";

    #[test]
    fn decode_xpub_rejects_garbage() {
        assert_eq!(decode_xpub("not-an-xpub"), Err(DeriveError::MalformedXpub));
        assert_eq!(decode_xpub(""), Err(DeriveError::MalformedXpub));
    }

    #[test]
    fn decode_xpub_roundtrip_fields() {
        // Prefix 0x02 (even y).
        let s02 = "tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3";
        let (cc, pk) = decode_xpub(s02).unwrap();
        assert_eq!(cc.len(), 32);
        assert_eq!(pk[0], 0x02);
        // Re-parse with bitcoin for field identity (decode only, not CKD).
        let xp = Xpub::from_str(s02).unwrap();
        assert_eq!(&cc[..], &xp.chain_code[..]);
        assert_eq!(pk, xp.public_key.serialize());

        // Prefix 0x03 (odd y) — second key from RECEIVE; covers the other SEC1 arm.
        let s03 = "tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4";
        let (cc3, pk3) = decode_xpub(s03).unwrap();
        assert_eq!(cc3.len(), 32);
        assert_eq!(pk3[0], 0x03);
    }

    #[test]
    fn derive_at_produces_p2wsh_and_sorted_keys() {
        let d = parse(RECEIVE).unwrap();
        let out = derive_at(&d, 0).unwrap();
        assert!(out.script_pubkey.is_p2wsh());
        assert_eq!(out.witness_script.as_bytes()[0], 0x52); // OP_2
                                                            // Sorted order is non-decreasing.
        assert!(out.sorted_pubkeys[0] <= out.sorted_pubkeys[1]);
        assert!(out.sorted_pubkeys[1] <= out.sorted_pubkeys[2]);
        // Descriptor-order children retain fingerprints.
        assert_eq!(out.children[0].fingerprint.to_hex(), "73756c7f");
        let addr = out.address(Network::Regtest);
        assert!(addr.to_string().starts_with("bcrt1"));
        let descriptor_order = [
            out.children[0].public_key,
            out.children[1].public_key,
            out.children[2].public_key,
        ];
        // Fixture keys at i=0 are not already BIP-67-sorted; a constant
        // `[[0;33];3]` / `[[1;33];3]` return from `sorted_pubkeys_slice` fails.
        assert_ne!(
            descriptor_order, out.sorted_pubkeys,
            "BIP-67 must reorder these fixture keys"
        );
        let mut expected = descriptor_order;
        expected.sort_unstable();
        assert_eq!(out.sorted_pubkeys_slice(), &expected);
        assert_ne!(*out.sorted_pubkeys_slice(), [[0u8; 33]; 3]);
        assert_ne!(*out.sorted_pubkeys_slice(), [[1u8; 33]; 3]);
    }

    #[test]
    fn derive_child_rejects_hardened_index() {
        let d = parse(RECEIVE).unwrap();
        assert_eq!(
            derive_child(&d.keys[0], 0x8000_0000),
            Err(DeriveError::HardenedIndex(0x8000_0000))
        );
        // Exclusive: `>` not `>=` / `==`. The max non-hardened index is legal.
        let max = derive_child(&d.keys[0], ckd::MAX_NON_HARDENED_INDEX).unwrap();
        assert_eq!(max.address_index, ckd::MAX_NON_HARDENED_INDEX);
    }

    #[test]
    fn change_branch_differs_from_receive() {
        let recv = parse(RECEIVE).unwrap();
        let change_s = "wsh(sortedmulti(2,\
[73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/1/*,\
[f9f62194/48'/1'/0'/2']tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4/1/*,\
[c98b1535/48'/1'/0'/2']tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a/1/*\
))#w7gjjqef";
        let chg = parse(change_s).unwrap();
        let a = derive_at(&recv, 0).unwrap();
        let b = derive_at(&chg, 0).unwrap();
        assert_ne!(a.script_pubkey, b.script_pubkey);
        assert_eq!(a.children[0].branch, DerivationBranch::External);
        assert_eq!(b.children[0].branch, DerivationBranch::Internal);
    }

    #[test]
    fn different_indices_differ() {
        let d = parse(RECEIVE).unwrap();
        let a = derive_at(&d, 0).unwrap();
        let b = derive_at(&d, 1).unwrap();
        assert_ne!(a.script_pubkey, b.script_pubkey);
        assert_eq!(a.children[0].address_index, 0);
        assert_eq!(b.children[0].address_index, 1);
    }
}
