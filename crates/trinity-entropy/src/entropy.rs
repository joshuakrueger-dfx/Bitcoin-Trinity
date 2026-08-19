//! The §2.2 construction: extract → BIP-39 → seed → BIP-32 master.
//!
//! ```text
//! extract := HMAC-SHA512(key = raw_csprng, msg = extra_bytes)
//! entropy := extract[0..L]
//! mnemonic := BIP-39(entropy)
//! seed     := PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64)
//! xprv     := BIP-32-Master(seed)
//! ```

use bip39::Mnemonic;
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::{sha512, Hash as _, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use trinity_types::{Fingerprint, SecretBytes, WordCount};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::EntropyError;
use crate::hex;
use crate::sources::AdditionalEntropy;

/// BIP-39 mnemonic + seed (empty passphrase) from already-extracted entropy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Bip39Material {
    /// Space-separated English words (UTF-8).
    pub mnemonic: SecretBytes,
    /// 64-byte BIP-39 seed (PBKDF2, salt `"mnemonic"`, 2048 rounds).
    pub seed: SecretBytes,
}

impl core::fmt::Debug for Bip39Material {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bip39Material")
            .field("mnemonic", &"[redacted]")
            .field("seed", &"[redacted]")
            .finish()
    }
}

/// One generated key: every intermediate of the §2.2 pipeline.
///
/// Secrets (`raw_csprng`, `extra_bytes`, `entropy`, mnemonic, seed, xprv)
/// live in [`SecretBytes`]. [`Debug`] prints only `"[redacted]"` for those
/// fields. Hex and the word list are exposed through named accessors and
/// [`crate::VerificationSheet`] — never through `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GeneratedKey {
    #[zeroize(skip)]
    word_count: WordCount,
    raw_csprng: SecretBytes,
    extra_bytes: SecretBytes,
    entropy: SecretBytes,
    mnemonic: SecretBytes,
    seed: SecretBytes,
    xprv: SecretBytes,
    #[zeroize(skip)]
    fingerprint: Fingerprint,
    #[zeroize(skip)]
    sources: AdditionalEntropy,
}

impl core::fmt::Debug for GeneratedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GeneratedKey")
            .field("word_count", &self.word_count)
            .field("raw_csprng", &"[redacted]")
            .field("extra_bytes", &"[redacted]")
            .field("entropy", &"[redacted]")
            .field("mnemonic", &"[redacted]")
            .field("seed", &"[redacted]")
            .field("xprv", &"[redacted]")
            .field("fingerprint", &self.fingerprint)
            .field("sources", &self.sources)
            .finish()
    }
}

impl GeneratedKey {
    /// Word length used for this key (`L` = 16 or 32).
    #[inline]
    pub fn word_count(&self) -> WordCount {
        self.word_count
    }

    /// 32-byte OS-CSPRNG draw (`raw_csprng`).
    #[inline]
    pub fn raw_csprng(&self) -> &SecretBytes {
        &self.raw_csprng
    }

    /// Canonical `extra_bytes` (possibly empty).
    #[inline]
    pub fn extra_bytes(&self) -> &SecretBytes {
        &self.extra_bytes
    }

    /// Extracted entropy, `L` bytes.
    #[inline]
    pub fn entropy(&self) -> &SecretBytes {
        &self.entropy
    }

    /// BIP-39 word list as UTF-8 bytes (space-separated).
    #[inline]
    pub fn mnemonic(&self) -> &SecretBytes {
        &self.mnemonic
    }

    /// BIP-39 word list as a string. The buffer is UTF-8 by construction.
    pub fn mnemonic_phrase(&self) -> &str {
        core::str::from_utf8(self.mnemonic.as_slice())
            .expect("mnemonic buffer is UTF-8 by construction")
    }

    /// 64-byte BIP-39 seed (no passphrase).
    #[inline]
    pub fn seed(&self) -> &SecretBytes {
        &self.seed
    }

    /// Serialized BIP-32 master `xprv` (base58check).
    ///
    /// The string always uses **mainnet** version bytes (`xprv…`). This crate
    /// does not take a network argument: `finish` calls
    /// `Xpriv::new_master(Network::Bitcoin, …)` unconditionally. Callers that
    /// need a testnet / signet / regtest serialization must re-derive from
    /// [`Self::seed()`] (the 64-byte BIP-39 seed is network-agnostic) via
    /// `Xpriv::new_master` for that network. Do not export this string as-is
    /// for a non-mainnet wallet.
    #[inline]
    pub fn xprv(&self) -> &SecretBytes {
        &self.xprv
    }

    /// BIP-32 master fingerprint (public metadata).
    #[inline]
    pub fn fp(&self) -> Fingerprint {
        self.fingerprint
    }

    /// The additional sources that produced `extra_bytes`.
    #[inline]
    pub fn sources(&self) -> &AdditionalEntropy {
        &self.sources
    }

    /// `raw_csprng` as 64 lowercase hex characters.
    pub fn raw_csprng_hex(&self) -> String {
        hex::encode(self.raw_csprng.as_slice())
    }

    /// `extra_bytes` as lowercase hex (empty when no sources are active).
    pub fn extra_bytes_hex(&self) -> String {
        hex::encode(self.extra_bytes.as_slice())
    }

    /// `entropy` as 32 or 64 lowercase hex characters.
    pub fn entropy_hex(&self) -> String {
        hex::encode(self.entropy.as_slice())
    }
}

/// HMAC-SHA512 extract stage, truncated to `L` bytes.
///
/// ```text
/// extract := HMAC-SHA512(key = raw_csprng, msg = extra_bytes)
/// entropy := extract[0..L]
/// ```
///
/// This is the construction that D13/S20 recompute with `openssl`.
pub fn extract(raw_csprng: &[u8; 32], extra_bytes: &[u8], word_count: WordCount) -> SecretBytes {
    let mut engine: HmacEngine<sha512::Hash> = HmacEngine::new(raw_csprng);
    engine.input(extra_bytes);
    let mac: Hmac<sha512::Hash> = Hmac::from_engine(engine);
    let l = usize::from(word_count.entropy_bytes());
    SecretBytes::from_slice(&mac[..l])
}

/// BIP-39 mnemonic + empty-passphrase seed from extracted entropy.
///
/// `entropy` must be 16 bytes (12 words) or 32 bytes (24 words).
pub fn bip39_from_entropy(entropy: &[u8]) -> Result<Bip39Material, EntropyError> {
    if entropy.len() != 16 && entropy.len() != 32 {
        return Err(EntropyError::BadEntropyLength { got: entropy.len() });
    }
    let mnemonic = mnemonic_from_entropy(entropy)?;
    let mut phrase = mnemonic.to_string();
    let seed = mnemonic.to_seed("");
    // `phrase` is a second heap copy of the mnemonic words. `SecretBytes`
    // takes its own copy; zeroize this buffer before it is freed so the
    // words do not linger until the allocator reuses the slot. No `?`
    // or early return sits between the copy and this call.
    let material = Bip39Material {
        mnemonic: SecretBytes::from_slice(phrase.as_bytes()),
        seed: SecretBytes::from_slice(&seed),
    };
    phrase.zeroize();
    Ok(material)
}

fn mnemonic_from_entropy(entropy: &[u8]) -> Result<Mnemonic, EntropyError> {
    Mnemonic::from_entropy(entropy).map_err(map_bip39)
}

fn map_bip39(_err: bip39::Error) -> EntropyError {
    EntropyError::Bip39
}

/// Generate a key for A or B: `word_count` is choosable (default is the
/// caller's choice; this crate does not impose one).
pub fn generate(
    word_count: WordCount,
    extra: &AdditionalEntropy,
) -> Result<GeneratedKey, EntropyError> {
    let raw = read_raw_csprng()?;
    generate_from_raw(word_count, &raw, extra)
}

/// Generate key C. Word length is fixed at 24 — a 12-word C cannot be
/// expressed (S15b, Spec §2.2.3).
pub fn generate_c(extra: &AdditionalEntropy) -> Result<GeneratedKey, EntropyError> {
    generate_c_from_raw(&read_raw_csprng()?, extra)
}

/// Deterministic A/B generation from a supplied `raw_csprng`.
///
/// Used by tests (D13, P10, P16) and by callers that already drew the
/// CSPRNG (so intermediates can be displayed before the rest of the
/// pipeline runs).
pub fn generate_from_raw(
    word_count: WordCount,
    raw_csprng: &[u8; 32],
    extra: &AdditionalEntropy,
) -> Result<GeneratedKey, EntropyError> {
    finish(word_count, raw_csprng, extra)
}

/// Deterministic C generation. Hardcodes [`WordCount::Words24`].
pub fn generate_c_from_raw(
    raw_csprng: &[u8; 32],
    extra: &AdditionalEntropy,
) -> Result<GeneratedKey, EntropyError> {
    finish(WordCount::Words24, raw_csprng, extra)
}

fn finish(
    word_count: WordCount,
    raw_csprng: &[u8; 32],
    extra: &AdditionalEntropy,
) -> Result<GeneratedKey, EntropyError> {
    let extra_bytes = extra.canonical_bytes();
    let entropy = extract(raw_csprng, &extra_bytes, word_count);
    let mut bip39 = bip39_from_entropy(entropy.as_slice())?;
    let xpriv =
        xpriv_from_master_result(Xpriv::new_master(Network::Bitcoin, bip39.seed.as_slice()))?;
    let secp = Secp256k1::signing_only();
    let get_fp = Xpriv::fingerprint;
    let btc_fp = get_fp(&xpriv, &secp);
    let mut fp_bytes = [0u8; 4];
    fp_bytes.copy_from_slice(btc_fp.as_ref());
    let mut xprv_str = xpriv.to_string();
    // `xprv_str` is a second heap copy of the serialized master key.
    // `SecretBytes` takes its own copy; zeroize this buffer before it is
    // freed. No `?` or early return sits between the copy and this call.
    // `Bip39Material` implements `Drop` (`ZeroizeOnDrop`); fields cannot be
    // moved out, so ownership is transferred via replace with an empty buffer.
    let key = GeneratedKey {
        word_count,
        raw_csprng: SecretBytes::from_slice(raw_csprng),
        extra_bytes: SecretBytes::from(extra_bytes),
        entropy,
        mnemonic: core::mem::replace(&mut bip39.mnemonic, SecretBytes::new(Vec::new())),
        seed: core::mem::replace(&mut bip39.seed, SecretBytes::new(Vec::new())),
        xprv: SecretBytes::from_slice(xprv_str.as_bytes()),
        fingerprint: Fingerprint::new(fp_bytes),
        sources: extra.clone(),
    };
    xprv_str.zeroize();
    Ok(key)
}

fn read_raw_csprng() -> Result<[u8; 32], EntropyError> {
    read_raw_csprng_with(getrandom::fill)
}

fn read_raw_csprng_with<F>(fill: F) -> Result<[u8; 32], EntropyError>
where
    F: FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
{
    let mut raw = [0u8; 32];
    fill(&mut raw).map_err(|_| EntropyError::CsRng)?;
    Ok(raw)
}

fn xpriv_from_master_result(
    result: Result<Xpriv, bitcoin::bip32::Error>,
) -> Result<Xpriv, EntropyError> {
    result.map_err(|_| EntropyError::MasterKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_empty_extra_matches_openssl_zero_key() {
        // Computed with:
        //   printf '' | openssl dgst -sha512 -mac HMAC \
        //     -macopt hexkey:000…000 -binary | xxd -p
        let raw = [0u8; 32];
        let got = extract(&raw, b"", WordCount::Words24);
        assert_eq!(
            hex::encode(got.as_slice()),
            "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac673"
        );
        let got16 = extract(&raw, b"", WordCount::Words12);
        assert_eq!(
            hex::encode(got16.as_slice()),
            "b936cee86c9f87aa5d3c6f2e84cb5a42"
        );
    }

    #[test]
    fn extract_dice_example_matches_openssl() {
        let raw = [0u8; 32];
        let got = extract(&raw, b"31662", WordCount::Words24);
        assert_eq!(
            hex::encode(got.as_slice()),
            "d330786003d48a011e6cc1433948dc9f53362384a8fe13db110a11af618534cc"
        );
    }

    #[test]
    fn bip39_rejects_wrong_length() {
        assert_eq!(
            bip39_from_entropy(&[0u8; 15]).unwrap_err(),
            EntropyError::BadEntropyLength { got: 15 }
        );
        assert_eq!(
            bip39_from_entropy(&[0u8; 0]).unwrap_err(),
            EntropyError::BadEntropyLength { got: 0 }
        );
        assert_eq!(
            bip39_from_entropy(&[0u8; 31]).unwrap_err(),
            EntropyError::BadEntropyLength { got: 31 }
        );
    }

    #[test]
    fn bip39_debug_is_redacted() {
        let m = bip39_from_entropy(&[0u8; 16]).unwrap();
        let d = format!("{m:?}");
        assert!(d.contains("[redacted]"));
        assert!(!d.contains("abandon"));
    }

    #[test]
    fn master_error_maps() {
        use core::str::FromStr;
        let err = Xpriv::from_str("not-an-xprv").expect_err("malformed xprv");
        assert_eq!(
            xpriv_from_master_result(Err(err)).unwrap_err(),
            EntropyError::MasterKey
        );
    }

    #[test]
    fn bip39_error_maps() {
        assert_eq!(
            map_bip39(bip39::Error::InvalidChecksum),
            EntropyError::Bip39
        );
        assert_eq!(
            map_bip39(bip39::Error::BadWordCount(11)),
            EntropyError::Bip39
        );
        assert_eq!(map_bip39(bip39::Error::UnknownWord(0)), EntropyError::Bip39);
        assert_eq!(
            map_bip39(bip39::Error::BadEntropyBitCount(7)),
            EntropyError::Bip39
        );
        assert_eq!(
            mnemonic_from_entropy(&[0u8; 15]).unwrap_err(),
            EntropyError::Bip39
        );
    }

    #[test]
    fn csrng_error_is_mapped() {
        let err = read_raw_csprng_with(|_| Err(getrandom::Error::UNSUPPORTED)).unwrap_err();
        assert_eq!(err, EntropyError::CsRng);
    }

    #[test]
    fn live_generate_and_generate_c() {
        let extra = AdditionalEntropy::new();
        let a = generate(WordCount::Words12, &extra).unwrap();
        assert_eq!(a.word_count(), WordCount::Words12);
        assert_eq!(a.entropy().len(), 16);
        assert_eq!(a.mnemonic_phrase().split_whitespace().count(), 12);
        assert_eq!(a.raw_csprng().len(), 32);
        assert_eq!(a.seed().len(), 64);
        assert!(a.extra_bytes().is_empty());
        assert!(!a.xprv().is_empty());

        let c = generate_c(&extra).unwrap();
        assert_eq!(c.word_count(), WordCount::Words24);
        assert_eq!(c.entropy().len(), 32);
        assert_eq!(c.mnemonic_phrase().split_whitespace().count(), 24);

        // Two live draws must differ. A stubbed `read_raw_csprng` that
        // returns `[0; 32]` / `[1; 32]` makes both calls collide.
        let b = generate(WordCount::Words12, &extra).unwrap();
        assert_ne!(a.raw_csprng().as_slice(), b.raw_csprng().as_slice());
        assert_ne!(a.raw_csprng().as_slice(), &[0u8; 32]);
        assert_ne!(a.raw_csprng().as_slice(), &[1u8; 32]);
        assert_ne!(c.raw_csprng().as_slice(), a.raw_csprng().as_slice());
    }

    #[test]
    fn generated_key_debug_redacts_secrets() {
        let raw = [0xdeu8; 32];
        let extra = AdditionalEntropy::new().with_dice("31662").unwrap();
        let key = generate_from_raw(WordCount::Words24, &raw, &extra).unwrap();
        let d = format!("{key:?}");
        assert!(d.contains("[redacted]"));
        assert!(!d.contains("dededede"));
        assert!(!d.contains(&key.raw_csprng_hex()));
        assert!(!d.contains(key.mnemonic_phrase().split_whitespace().next().unwrap()));
        assert_eq!(key.sources().dice(), Some("31662"));
        assert_eq!(key.raw_csprng().as_slice(), &raw);
        assert_eq!(key.extra_bytes().as_slice(), extra.canonical_bytes());
        let phrase = core::str::from_utf8(key.mnemonic().as_slice()).unwrap();
        assert_eq!(phrase, key.mnemonic_phrase());
        assert_eq!(key.fp().to_hex().len(), 8);
    }

    #[test]
    fn hex_accessors_have_expected_widths() {
        let raw = [0xabu8; 32];
        let key = generate_from_raw(WordCount::Words12, &raw, &AdditionalEntropy::new()).unwrap();
        assert_eq!(key.raw_csprng_hex().len(), 64);
        assert!(key.extra_bytes_hex().is_empty());
        assert_eq!(key.entropy_hex().len(), 32);
    }
}
