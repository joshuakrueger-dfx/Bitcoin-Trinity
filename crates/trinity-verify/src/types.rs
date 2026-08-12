//! Parsed form of a Trinity `wsh(sortedmulti(2,…))` descriptor.

use trinity_types::Fingerprint;

/// Which BIP-32 chain the key expression's trailing `/*` selects.
///
/// Spec §2.3 / O8: external (`/0/*`) and internal (`/1/*`) are separate
/// descriptors, not multipath. The parser records the branch; it does not
/// resolve `*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DerivationBranch {
    /// Receive / external chain: `/0/*`.
    External,
    /// Change / internal chain: `/1/*`.
    Internal,
}

/// One of the three key expressions in the grammar:
/// `keyexpr := "[" fingerprint "/" origin_path "]" xpub "/" derivation`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyExpr {
    /// Master fingerprint (8 hex chars in the descriptor string).
    pub fingerprint: Fingerprint,
    /// BIP-48 origin path as written (e.g. `48'/0'/0'/2'` or `48h/0h/0h/2h`).
    pub origin_path: String,
    /// Validated extended public key string (`xpub…` / `tpub…`).
    pub xpub: String,
    /// Trailing derivation branch (`/0/*` or `/1/*`).
    pub derivation: DerivationBranch,
}

/// Result of parsing a Trinity descriptor string (WP-20 grammar only).
///
/// No PSBT types, no `verify()` — those are WP-22.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedDescriptor {
    /// Multisig threshold; always `2` after a successful parse.
    pub k: u32,
    /// Exactly three key expressions in descriptor order.
    pub keys: [KeyExpr; 3],
}

impl ParsedDescriptor {
    /// Convenience: all three key expressions share this derivation branch
    /// when the input is a well-formed Trinity receive or change descriptor.
    ///
    /// Returns `None` if the three branches differ (still a legal parse of the
    /// grammar; callers that need uniform chains can reject separately).
    pub fn uniform_derivation(&self) -> Option<DerivationBranch> {
        let b0 = self.keys[0].derivation;
        if self.keys[1].derivation == b0 && self.keys[2].derivation == b0 {
            Some(b0)
        } else {
            None
        }
    }
}
