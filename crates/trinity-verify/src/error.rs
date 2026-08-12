//! Parse errors — one variant per hard-rejection reason (Spec §1.5, fail-closed).

use thiserror::Error;

/// Hard parse failure for a Trinity descriptor string.
///
/// Every rejection path is distinguishable: Spec §1.5 and the fail-closed
/// principle require specific errors, not a single catch-all string.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    /// No trailing `#checksum` (BIP-380 requires eight checksum characters).
    #[error("descriptor is missing BIP-380 checksum")]
    MissingChecksum,

    /// Checksum present but not exactly eight characters of the bech32 set.
    #[error("descriptor checksum has invalid length or charset")]
    MalformedChecksum,

    /// BIP-380 polymod check failed (wrong checksum for the payload).
    #[error("descriptor BIP-380 checksum is invalid")]
    InvalidChecksum,

    /// Payload contains a character outside the BIP-380 input charset.
    #[error("descriptor contains a character outside the BIP-380 charset")]
    InvalidCharset,

    /// Top-level expression is not `wsh(...)`.
    #[error("descriptor top-level must be wsh(...), got foreign wrapper")]
    WrongTopLevel,

    /// Inner script is not `sortedmulti(...)` (`multi`, `tr`, bare keys, …).
    #[error("descriptor must wrap sortedmulti(...), got foreign script expression")]
    ExpectedSortedMulti,

    /// Threshold `k` is not the literal `2` required for a 2-of-3 wallet.
    #[error("sortedmulti threshold must be 2 (2-of-3 only), got {0}")]
    WrongThreshold(String),

    /// Key expression count is not exactly three.
    #[error("sortedmulti must have exactly 3 key expressions, found {0}")]
    WrongKeyCount(usize),

    /// Fingerprint is not exactly eight hex characters.
    #[error("key origin fingerprint must be 8 hex characters")]
    MalformedFingerprint,

    /// Origin path is syntactically invalid (markers, empty segments, …).
    #[error("key origin path is malformed: {0}")]
    MalformedOriginPath(String),

    /// Origin path is not BIP-48 `48'/coin'/0'/2'` with coin ∈ {{0, 1}}.
    #[error("key origin path must be BIP-48 48'/{{0|1}}'/0'/2' (got {0})")]
    InvalidOriginPath(String),

    /// Multipath markers (`<`, `;`, `*`) appeared where only a fixed path is allowed.
    #[error("multipath markers are forbidden in Trinity descriptors")]
    MultipathForbidden,

    /// Extended key failed base58check / BIP-32 decode, or wrong prefix.
    #[error("invalid extended public key")]
    MalformedXpub,

    /// An xprv/tprv appeared where only public keys are allowed.
    #[error("private extended keys are forbidden in descriptors")]
    PrivateKeyForbidden,

    /// Trailing derivation after the xpub is not `/0/*` or `/1/*`.
    #[error("key derivation must be /0/* or /1/*")]
    MalformedDerivation,

    /// Key expression missing `[…]` origin brackets or otherwise incomplete.
    #[error("malformed key expression")]
    MalformedKeyExpression,

    /// Unexpected characters after `wsh(sortedmulti(...))` (before `#checksum`).
    #[error("trailing garbage after descriptor body")]
    TrailingGarbage,

    /// Input ended before a required token.
    #[error("unexpected end of descriptor")]
    UnexpectedEof,
}

/// Hard failure during independent BIP-32 / BIP-67 / witnessScript derivation.
///
/// Fail-closed: every rejection path is a specific variant (Spec §1.5). Used by
/// WP-21 derivation and later by WP-22 checks that re-derive outputs.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DeriveError {
    /// Child index is hardened (`i ≥ 2³¹`). Public CKD cannot derive it.
    #[error("hardened child index is not derivable from xpub (got {0})")]
    HardenedIndex(u32),

    /// Parent compressed pubkey bytes are not a valid SEC1 secp256k1 point.
    #[error("invalid compressed public key")]
    InvalidPublicKey,

    /// BIP-32 tweak invalid: `I_L` not a valid secret key, or point addition
    /// yielded the point at infinity (BIP-32 §"Public parent key → public
    /// child key", rare; caller should try the next index).
    #[error("BIP-32 child key derivation produced an invalid tweak")]
    InvalidTweak,

    /// Extended public key string failed base58check / BIP-32 decode.
    #[error("invalid extended public key")]
    MalformedXpub,

    /// Multisig parameters out of range (`k`/`n` not in 1..=16, or `k > n`).
    #[error("invalid multisig parameters: k={k}, n={n}")]
    InvalidMultisigParams {
        /// Required signatures.
        k: u32,
        /// Total keys.
        n: u32,
    },

    /// A compressed pubkey in a set for BIP-67 / script build is malformed.
    #[error("compressed pubkey at index {0} is not a valid 33-byte SEC1 key")]
    InvalidCompressedPubkey(usize),
}

/// Hard rejection reason from independent PSBT verification (Spec §1.5 V1–V10).
///
/// Every path is a concrete variant — never a generic "invalid" string
/// (fail-closed acceptance criterion for WP-22).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// V1: descriptor string failed the independent parser / BIP-380 checksum.
    #[error("descriptor rejected: {0}")]
    Descriptor(#[from] ParseError),

    /// Independent derivation failed while reconstructing scripts / keys.
    #[error("derivation failed: {0}")]
    Derive(#[from] DeriveError),

    /// V2: input `script_pubkey` is not a P2WSH program independently
    /// reconstructed from the descriptor in the search window.
    #[error("input {input_index}: foreign or non-reconstructible script_pubkey (V2)")]
    ForeignInput {
        /// PSBT input index.
        input_index: usize,
    },

    /// V3: output is neither a declared recipient nor a derived change address
    /// (forged change — the central attack). Spec S9 names this variant.
    #[error("output {output_index}: forged or undeclared change address (V3)")]
    ForeignChangeOutput {
        /// Transaction output index.
        output_index: usize,
    },

    /// V4: change output `bip32_derivation` missing fingerprints, wrong path,
    /// or pubkeys do not reconstruct the output's witnessScript.
    #[error("output {output_index}: mismatched change bip32_derivation (V4)")]
    MismatchedDerivation {
        /// Transaction output index.
        output_index: usize,
    },

    /// V5: fee is zero or would underflow (outputs ≥ inputs).
    #[error("fee is not strictly positive (V5)")]
    FeeNonPositive,

    /// V5: absolute fee exceeds `policy.max_absolute_fee`.
    #[error("fee {fee_sats} sat exceeds max_absolute_fee {max_sats} (V5)")]
    FeeTooHigh {
        /// Computed fee in satoshi.
        fee_sats: u64,
        /// Policy cap in satoshi.
        max_sats: u64,
    },

    /// V5: feerate exceeds `policy.max_feerate`.
    #[error("feerate {feerate_sat_vb} sat/vB exceeds max_feerate {max_sat_vb} (V5)")]
    FeerateTooHigh {
        /// Computed feerate (ceil sat/vB).
        feerate_sat_vb: u64,
        /// Policy cap (sat/vB).
        max_sat_vb: u64,
    },

    /// V5: fee does not match `policy.declared_fee_sats` from a prior display run.
    #[error("fee {actual_sats} sat ≠ declared fee {expected_sats} (V5/P2)")]
    FeeMismatch {
        /// Computed fee in satoshi.
        actual_sats: u64,
        /// `policy.declared_fee_sats`.
        expected_sats: u64,
    },

    /// V6: sum of non-change outputs ≠ user-confirmed amount.
    #[error("non-change amount {actual_sats} ≠ declared {expected_sats} (V6)")]
    AmountMismatch {
        /// Sum of non-change outputs.
        actual_sats: u64,
        /// `policy.declared_amount_sats`.
        expected_sats: u64,
    },

    /// V7: input outpoint is not in the watch-only UTXO list.
    #[error("input {input_index}: outpoint not in known UTXO list (V7)")]
    UnknownInput {
        /// PSBT input index.
        input_index: usize,
    },

    /// V7: outpoint is known, but `witness_utxo` value/script does not match
    /// the watch-only record for that outpoint.
    #[error("input {input_index}: witness_utxo does not match known UTXO (V7)")]
    MismatchedUtxo {
        /// PSBT input index.
        input_index: usize,
    },

    /// V8: input/output map lengths disagree with `unsigned_tx`, or the
    /// unsigned transaction still carries scriptSig/witness data.
    #[error("PSBT structure inconsistent with unsigned_tx (V8): {detail}")]
    InconsistentPsbt {
        /// Short reason for the structural mismatch.
        detail: &'static str,
    },

    /// V8: input or output count exceeds the pre-derivation resource bound.
    #[error("PSBT has too many inputs or outputs (V8): {detail}")]
    TooManyInputsOutputs {
        /// Short reason (which side and the count).
        detail: &'static str,
    },

    /// V8: proprietary PSBT fields present (field-confusion surface).
    #[error("PSBT contains proprietary fields (V8)")]
    ProprietaryField,

    /// V9: input lacks `witness_utxo`.
    #[error("input {input_index}: missing witness_utxo (V9)")]
    MissingWitnessUtxo {
        /// PSBT input index.
        input_index: usize,
    },

    /// V9: input has `non_witness_utxo` without `witness_utxo`.
    #[error("input {input_index}: non_witness_utxo without witness_utxo (V9)")]
    NonWitnessUtxoOnly {
        /// PSBT input index.
        input_index: usize,
    },

    /// V10: a present partial signature is high-s (BIP-62), not valid DER, or
    /// otherwise not a low-s ECDSA signature.
    #[error("input {input_index}: bad or high-s signature (V10)")]
    BadSignature {
        /// PSBT input index.
        input_index: usize,
    },

    /// P11 / V10: sighash type is not `SIGHASH_ALL` (0x01).
    #[error("input {input_index}: sighash is not SIGHASH_ALL (P11)")]
    NonSighashAll {
        /// PSBT input index.
        input_index: usize,
    },

    /// Base64 PSBT string failed to deserialize (exported `verify_psbt` path).
    #[error("PSBT base64/deserialize failed")]
    PsbtDecode,

    /// Output `script_pubkey` cannot be encoded as an address on the policy network.
    #[error("output {output_index}: script_pubkey is not a valid address on policy network")]
    InvalidOutputAddress {
        /// Transaction output index.
        output_index: usize,
    },
}
