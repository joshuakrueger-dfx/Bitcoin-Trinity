//! XChaCha20-Poly1305 blob encode/decode — Spec §2.4.
//!
//! Layout is identical for A and B. Sealed blobs with the same inputs differ
//! at `slot` and at the Poly1305 tag (`slot` is AAD):
//!
//! ```text
//! Header (AAD, authenticated, unencrypted) — 36 bytes
//!   magic       "TRIN"                        4 B
//!   version     u8 = 1                        1 B
//!   slot        u8 (0=A, 1=B)                 1 B
//!   reserved    u8 = 0                        1 B
//!   word_count  u8 (24 or 12)                 1 B
//!   nonce       24 B (XChaCha20 random)
//!   birthday    u32 LE (block height)         4 B
//! Ciphertext
//!   entropy     L bytes (32 for 24 words, 16 for 12)
//!   created_at  u64 LE                         8 B
//! Tag
//!   Poly1305    16 B
//! ```
//!
//! `word_count` is in the header and therefore in the AAD: a 24→12 flip
//! cannot produce a half-entropy decrypt (P13). There is no KDF field —
//! `kdf_profile` and `pp_salt` sit in the policy record (WP-32).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use thiserror::Error;
use trinity_types::{KeySlot, SecretBytes, WordCount};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Spec §2.4 magic: ASCII `TRIN`.
pub const MAGIC: [u8; 4] = *b"TRIN";

/// Spec §2.4 version byte. Only `1` is defined.
pub const VERSION: u8 = 1;

/// Spec §2.4 header length in bytes (magic through birthday).
pub const HEADER_LEN: usize = 36;

/// XChaCha20 nonce length (192-bit).
pub const NONCE_LEN: usize = 24;

/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// Byte offset of `slot` in the header (`0=A`, `1=B`).
pub const SLOT_OFFSET: usize = 5;

/// Byte offset of `word_count` in the header (`12` or `24`).
pub const WORD_COUNT_OFFSET: usize = 7;

const VERSION_OFFSET: usize = 4;
const RESERVED_OFFSET: usize = 6;
const NONCE_OFFSET: usize = 8;
const BIRTHDAY_OFFSET: usize = 32;
const CREATED_AT_LEN: usize = 8;

/// Failure while encoding or decoding a key blob.
///
/// Every rejection is a specific variant (fail-closed). Structural header
/// checks run before AEAD; tag failure is always [`BlobError::Aead`].
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BlobError {
    /// Input is shorter than a header plus a Poly1305 tag.
    #[error("blob is shorter than the header plus authentication tag")]
    Truncated,

    /// First four bytes are not `TRIN`.
    #[error("blob magic is not TRIN")]
    BadMagic,

    /// `version` is not `1`. Unknown future format.
    #[error("unsupported blob version {0}")]
    UnsupportedVersion(u8),

    /// `reserved` is not `0`. Treated as an unknown-version-like case:
    /// a future meaning for this byte must bump [`VERSION`], not reuse v1.
    #[error("nonzero reserved byte is an unknown blob format")]
    UnsupportedReserved,

    /// `slot` is not A or B (`0` or `1`). C has no on-device blob.
    #[error("blob slot is not A or B")]
    InvalidSlot,

    /// `word_count` is not `12` or `24`.
    #[error("blob word_count is not 12 or 24 (got {0})")]
    InvalidWordCount(u8),

    /// Caller-supplied entropy length does not match `word_count`.
    #[error("entropy length must be {expected} bytes for this word count, got {got}")]
    EntropyLength {
        /// Length required by [`WordCount::entropy_bytes`].
        expected: usize,
        /// Length that was supplied.
        got: usize,
    },

    /// OS CSPRNG (`getrandom`) failed while drawing a nonce.
    #[error("operating-system CSPRNG failed")]
    CsRng,

    /// XChaCha20-Poly1305 tag check failed (ciphertext, tag, or AAD mismatch).
    #[error("XChaCha20-Poly1305 authentication failed")]
    Aead,

    /// AEAD succeeded but the plaintext is not `L + 8` for the header's
    /// `word_count`. Unreachable for an AAD-honest blob; defense in depth.
    #[error("decrypted plaintext length does not match header word_count")]
    PlaintextLength,
}

/// One decrypted key blob (Spec §2.4).
///
/// `entropy` is key material and lives in [`SecretBytes`]. [`Debug`] prints
/// `[redacted]` for that field via `SecretBytes` — never the bytes.
///
/// WP-31 shipped this type without [`ZeroizeOnDrop`] on the parent (the
/// field still zeroed via [`SecretBytes`]). WP-32 adds the parent bound so
/// the compile-time inventory can name this type.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct DecodedBlob {
    #[zeroize(skip)]
    slot: KeySlot,
    #[zeroize(skip)]
    word_count: WordCount,
    #[zeroize(skip)]
    birthday: u32,
    entropy: SecretBytes,
    #[zeroize(skip)]
    created_at: u64,
}

impl DecodedBlob {
    /// Slot encoded in the header (`A` or `B`).
    #[inline]
    pub fn slot(&self) -> KeySlot {
        self.slot
    }

    /// Word count encoded in the header (`12` or `24`).
    #[inline]
    pub fn word_count(&self) -> WordCount {
        self.word_count
    }

    /// Birthday block height from the header.
    #[inline]
    pub fn birthday(&self) -> u32 {
        self.birthday
    }

    /// Recovered entropy (`L` bytes). Key material.
    #[inline]
    pub fn entropy(&self) -> &SecretBytes {
        &self.entropy
    }

    /// Creation timestamp (unix seconds, little-endian in the ciphertext).
    #[inline]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
}

/// Encrypt `entropy` under `kek`, drawing a fresh 24-byte nonce.
///
/// Production entry point: the caller cannot supply (and therefore cannot
/// reuse) a nonce.
pub fn encrypt(
    kek: &[u8; 32],
    slot: KeySlot,
    word_count: WordCount,
    birthday: u32,
    entropy: &[u8],
    created_at: u64,
) -> Result<Vec<u8>, BlobError> {
    let nonce = draw_nonce()?;
    encrypt_at_nonce(kek, slot, word_count, nonce, birthday, entropy, created_at)
}

/// Encrypt `entropy` under `kek` with an explicit nonce.
///
/// Compiled only for this crate's tests or the non-default `test-util`
/// feature. Production callers use [`encrypt`].
#[cfg(any(test, feature = "test-util"))]
pub fn encrypt_with_nonce(
    kek: &[u8; 32],
    slot: KeySlot,
    word_count: WordCount,
    nonce: [u8; NONCE_LEN],
    birthday: u32,
    entropy: &[u8],
    created_at: u64,
) -> Result<Vec<u8>, BlobError> {
    encrypt_at_nonce(kek, slot, word_count, nonce, birthday, entropy, created_at)
}

fn encrypt_at_nonce(
    kek: &[u8; 32],
    slot: KeySlot,
    word_count: WordCount,
    nonce: [u8; NONCE_LEN],
    birthday: u32,
    entropy: &[u8],
    created_at: u64,
) -> Result<Vec<u8>, BlobError> {
    if !slot.has_device_blob() {
        return Err(BlobError::InvalidSlot);
    }
    let expected = usize::from(word_count.entropy_bytes());
    if entropy.len() != expected {
        return Err(BlobError::EntropyLength {
            expected,
            got: entropy.len(),
        });
    }

    let header = encode_header(slot, word_count, &nonce, birthday);
    let mut plaintext = Vec::with_capacity(expected + CREATED_AT_LEN);
    plaintext.extend_from_slice(entropy);
    plaintext.extend_from_slice(&created_at.to_le_bytes());
    let blob = seal(kek, &header, &plaintext)?;
    plaintext.zeroize();
    Ok(blob)
}

/// Decrypt `blob` under `kek`.
///
/// Structural checks (magic, version, reserved, slot, word_count, minimum
/// length) run before AEAD. A well-formed header whose AAD no longer matches
/// the tag — including a `word_count` 24↔12 flip — returns [`BlobError::Aead`].
pub fn decrypt(kek: &[u8; 32], blob: &[u8]) -> Result<DecodedBlob, BlobError> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(BlobError::Truncated);
    }

    let header = &blob[..HEADER_LEN];
    let parsed = parse_header(header)?;
    let body = &blob[HEADER_LEN..];

    let mut plaintext = open(kek, header, body)?;
    let expected = usize::from(parsed.word_count.entropy_bytes()) + CREATED_AT_LEN;
    if plaintext.len() != expected {
        plaintext.zeroize();
        return Err(BlobError::PlaintextLength);
    }

    let entropy = SecretBytes::from_slice(&plaintext[..expected - CREATED_AT_LEN]);
    let mut ts = [0u8; CREATED_AT_LEN];
    ts.copy_from_slice(&plaintext[expected - CREATED_AT_LEN..]);
    plaintext.zeroize();

    Ok(DecodedBlob {
        slot: parsed.slot,
        word_count: parsed.word_count,
        birthday: parsed.birthday,
        entropy,
        created_at: u64::from_le_bytes(ts),
    })
}

struct ParsedHeader {
    slot: KeySlot,
    word_count: WordCount,
    birthday: u32,
}

fn encode_header(
    slot: KeySlot,
    word_count: WordCount,
    nonce: &[u8; NONCE_LEN],
    birthday: u32,
) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[VERSION_OFFSET] = VERSION;
    header[SLOT_OFFSET] = slot.as_u8();
    header[RESERVED_OFFSET] = 0;
    header[WORD_COUNT_OFFSET] = word_count.words();
    header[NONCE_OFFSET..BIRTHDAY_OFFSET].copy_from_slice(nonce);
    header[BIRTHDAY_OFFSET..].copy_from_slice(&birthday.to_le_bytes());
    header
}

fn parse_header(header: &[u8]) -> Result<ParsedHeader, BlobError> {
    debug_assert_eq!(header.len(), HEADER_LEN);

    if header[..4] != MAGIC {
        return Err(BlobError::BadMagic);
    }
    let version = header[VERSION_OFFSET];
    if version != VERSION {
        return Err(BlobError::UnsupportedVersion(version));
    }
    if header[RESERVED_OFFSET] != 0 {
        return Err(BlobError::UnsupportedReserved);
    }
    let slot = match KeySlot::from_u8(header[SLOT_OFFSET]) {
        Some(s) if s.has_device_blob() => s,
        _ => return Err(BlobError::InvalidSlot),
    };
    let word_count_byte = header[WORD_COUNT_OFFSET];
    let word_count = WordCount::from_words(word_count_byte)
        .ok_or(BlobError::InvalidWordCount(word_count_byte))?;

    let mut birthday_bytes = [0u8; 4];
    birthday_bytes.copy_from_slice(&header[BIRTHDAY_OFFSET..]);
    Ok(ParsedHeader {
        slot,
        word_count,
        birthday: u32::from_le_bytes(birthday_bytes),
    })
}

fn seal(kek: &[u8; 32], header: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, BlobError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*kek));
    let nonce = nonce_from_header(header);
    // Encrypt fails only if the message exceeds ChaCha20's 2^32-block
    // limit (~256 GiB). Our plaintext is L+8 bytes (24 or 40).
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: header,
            },
        )
        .expect("XChaCha20-Poly1305 encrypt is infallible for L+8 plaintext");
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open(kek: &[u8; 32], header: &[u8], body: &[u8]) -> Result<Vec<u8>, BlobError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*kek));
    let nonce = nonce_from_header(header);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: body,
                aad: header,
            },
        )
        .map_err(|_| BlobError::Aead)
}

fn nonce_from_header(header: &[u8]) -> XNonce {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&header[NONCE_OFFSET..BIRTHDAY_OFFSET]);
    XNonce::from(nonce)
}

fn draw_nonce() -> Result<[u8; NONCE_LEN], BlobError> {
    draw_nonce_with(getrandom::fill)
}

fn draw_nonce_with<F>(fill: F) -> Result<[u8; NONCE_LEN], BlobError>
where
    F: FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
{
    let mut nonce = [0u8; NONCE_LEN];
    fill(&mut nonce).map_err(|_| BlobError::CsRng)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEK: [u8; 32] = [0x11; 32];
    const NONCE: [u8; 24] = [0x22; 24];
    const ENTROPY24: [u8; 32] = [0x33; 32];
    const ENTROPY12: [u8; 16] = [0x44; 16];

    fn sample_blob(slot: KeySlot, wc: WordCount, entropy: &[u8]) -> Vec<u8> {
        encrypt_with_nonce(&KEK, slot, wc, NONCE, 800_000, entropy, 1_700_000_000).unwrap()
    }

    #[test]
    fn layout_matches_spec() {
        let blob = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        assert_eq!(&blob[..4], &MAGIC);
        assert_eq!(blob[VERSION_OFFSET], VERSION);
        assert_eq!(blob[SLOT_OFFSET], 0);
        assert_eq!(blob[RESERVED_OFFSET], 0);
        assert_eq!(blob[WORD_COUNT_OFFSET], 24);
        assert_eq!(&blob[NONCE_OFFSET..BIRTHDAY_OFFSET], &NONCE);
        assert_eq!(
            &blob[BIRTHDAY_OFFSET..HEADER_LEN],
            &800_000u32.to_le_bytes()
        );
        assert_eq!(blob.len(), HEADER_LEN + 32 + CREATED_AT_LEN + TAG_LEN);
    }

    #[test]
    fn a_and_b_share_format_and_ciphertext() {
        // Slot is AAD, so the Poly1305 tag must differ. The layout and the
        // XChaCha20 ciphertext (entropy || created_at) are identical.
        let a = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        let b = sample_blob(KeySlot::B, WordCount::Words24, &ENTROPY24);
        assert_eq!(a.len(), b.len());
        assert_eq!(&a[..SLOT_OFFSET], &b[..SLOT_OFFSET]);
        assert_eq!(a[SLOT_OFFSET], 0);
        assert_eq!(b[SLOT_OFFSET], 1);
        assert_eq!(
            &a[SLOT_OFFSET + 1..a.len() - TAG_LEN],
            &b[SLOT_OFFSET + 1..b.len() - TAG_LEN]
        );
        assert_ne!(&a[a.len() - TAG_LEN..], &b[b.len() - TAG_LEN..]);
    }

    #[test]
    fn words12_layout_length() {
        let blob = sample_blob(KeySlot::B, WordCount::Words12, &ENTROPY12);
        assert_eq!(blob[SLOT_OFFSET], 1);
        assert_eq!(blob[WORD_COUNT_OFFSET], 12);
        assert_eq!(blob.len(), HEADER_LEN + 16 + CREATED_AT_LEN + TAG_LEN);
    }

    #[test]
    fn encrypt_draws_distinct_nonces() {
        let a = encrypt(&KEK, KeySlot::A, WordCount::Words24, 1, &ENTROPY24, 2).unwrap();
        let b = encrypt(&KEK, KeySlot::A, WordCount::Words24, 1, &ENTROPY24, 2).unwrap();
        assert_ne!(
            &a[NONCE_OFFSET..BIRTHDAY_OFFSET],
            &b[NONCE_OFFSET..BIRTHDAY_OFFSET]
        );
        let da = decrypt(&KEK, &a).unwrap();
        let db = decrypt(&KEK, &b).unwrap();
        assert_eq!(da.entropy().as_slice(), &ENTROPY24);
        assert_eq!(db.entropy().as_slice(), &ENTROPY24);
    }

    #[test]
    fn roundtrip_recovers_all_fields() {
        let blob = sample_blob(KeySlot::B, WordCount::Words12, &ENTROPY12);
        let d = decrypt(&KEK, &blob).unwrap();
        assert_eq!(d.slot(), KeySlot::B);
        assert_eq!(d.word_count(), WordCount::Words12);
        assert_eq!(d.birthday(), 800_000);
        assert_eq!(d.entropy().as_slice(), &ENTROPY12);
        assert_eq!(d.created_at(), 1_700_000_000);
        assert_eq!(d.entropy().len(), 16);
        assert!(!d.entropy().is_empty());
    }

    #[test]
    fn decoded_debug_redacts_entropy() {
        let blob = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        let d = decrypt(&KEK, &blob).unwrap();
        let rendered = format!("{d:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("333333"));
        let hex = ENTROPY24
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(!rendered.contains(&hex));
    }

    #[test]
    fn encrypt_rejects_slot_c() {
        let err = encrypt_with_nonce(
            &KEK,
            KeySlot::C,
            WordCount::Words24,
            NONCE,
            0,
            &ENTROPY24,
            0,
        )
        .unwrap_err();
        assert_eq!(err, BlobError::InvalidSlot);
    }

    #[test]
    fn encrypt_rejects_wrong_entropy_length() {
        let err = encrypt_with_nonce(
            &KEK,
            KeySlot::A,
            WordCount::Words24,
            NONCE,
            0,
            &ENTROPY12,
            0,
        )
        .unwrap_err();
        assert_eq!(
            err,
            BlobError::EntropyLength {
                expected: 32,
                got: 16
            }
        );
        let err = encrypt_with_nonce(
            &KEK,
            KeySlot::A,
            WordCount::Words12,
            NONCE,
            0,
            &ENTROPY24,
            0,
        )
        .unwrap_err();
        assert_eq!(
            err,
            BlobError::EntropyLength {
                expected: 16,
                got: 32
            }
        );
    }

    #[test]
    fn decrypt_rejects_truncated() {
        assert_eq!(decrypt(&KEK, &[]).unwrap_err(), BlobError::Truncated);
        assert_eq!(
            decrypt(&KEK, &[0u8; HEADER_LEN + TAG_LEN - 1]).unwrap_err(),
            BlobError::Truncated
        );
    }

    #[test]
    fn decrypt_rejects_bad_magic() {
        let mut blob = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        blob[0] = b'X';
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), BlobError::BadMagic);
    }

    #[test]
    fn decrypt_rejects_unknown_version() {
        let mut blob = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        blob[VERSION_OFFSET] = 2;
        assert_eq!(
            decrypt(&KEK, &blob).unwrap_err(),
            BlobError::UnsupportedVersion(2)
        );
        blob[VERSION_OFFSET] = 0;
        assert_eq!(
            decrypt(&KEK, &blob).unwrap_err(),
            BlobError::UnsupportedVersion(0)
        );
    }

    #[test]
    fn decrypt_rejects_nonzero_reserved() {
        let mut blob = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        blob[RESERVED_OFFSET] = 1;
        assert_eq!(
            decrypt(&KEK, &blob).unwrap_err(),
            BlobError::UnsupportedReserved
        );
    }

    #[test]
    fn decrypt_rejects_slot_c_and_unknown() {
        let mut blob = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        blob[SLOT_OFFSET] = 2;
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), BlobError::InvalidSlot);
        blob[SLOT_OFFSET] = 255;
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), BlobError::InvalidSlot);
    }

    #[test]
    fn decrypt_rejects_invalid_word_count() {
        let mut blob = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        blob[WORD_COUNT_OFFSET] = 15;
        assert_eq!(
            decrypt(&KEK, &blob).unwrap_err(),
            BlobError::InvalidWordCount(15)
        );
        blob[WORD_COUNT_OFFSET] = 0;
        assert_eq!(
            decrypt(&KEK, &blob).unwrap_err(),
            BlobError::InvalidWordCount(0)
        );
    }

    #[test]
    fn decrypt_rejects_wrong_kek() {
        let blob = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        let other = [0xAAu8; 32];
        assert_eq!(decrypt(&other, &blob).unwrap_err(), BlobError::Aead);
    }

    #[test]
    fn decrypt_rejects_ciphertext_and_tag_mutation() {
        let blob = sample_blob(KeySlot::A, WordCount::Words24, &ENTROPY24);
        let mut ct = blob.clone();
        let last = ct.len() - 1;
        ct[HEADER_LEN] ^= 0x01;
        assert_eq!(decrypt(&KEK, &ct).unwrap_err(), BlobError::Aead);
        let mut tag = blob;
        tag[last] ^= 0x01;
        assert_eq!(decrypt(&KEK, &tag).unwrap_err(), BlobError::Aead);
    }

    #[test]
    fn plaintext_length_is_defense_in_depth() {
        // Honest AEAD over a lying header: word_count=24, plaintext is 16+8.
        let header = encode_header(KeySlot::A, WordCount::Words24, &NONCE, 1);
        let mut plaintext = ENTROPY12.to_vec();
        plaintext.extend_from_slice(&0u64.to_le_bytes());
        let blob = seal(&KEK, &header, &plaintext).unwrap();
        plaintext.zeroize();
        assert_eq!(
            decrypt(&KEK, &blob).unwrap_err(),
            BlobError::PlaintextLength
        );
    }

    #[test]
    fn csrng_error_is_mapped() {
        let err = draw_nonce_with(|_| Err(getrandom::Error::UNSUPPORTED)).unwrap_err();
        assert_eq!(err, BlobError::CsRng);
    }

    #[test]
    fn display_covers_every_variant() {
        let cases: &[BlobError] = &[
            BlobError::Truncated,
            BlobError::BadMagic,
            BlobError::UnsupportedVersion(2),
            BlobError::UnsupportedReserved,
            BlobError::InvalidSlot,
            BlobError::InvalidWordCount(15),
            BlobError::EntropyLength {
                expected: 32,
                got: 16,
            },
            BlobError::CsRng,
            BlobError::Aead,
            BlobError::PlaintextLength,
        ];
        for e in cases {
            assert!(!e.to_string().is_empty(), "{e:?}");
        }
    }

    #[test]
    fn open_maps_tag_failure() {
        let header = encode_header(KeySlot::A, WordCount::Words12, &NONCE, 0);
        assert_eq!(
            open(&KEK, &header, &[0u8; TAG_LEN]).unwrap_err(),
            BlobError::Aead
        );
    }
}
