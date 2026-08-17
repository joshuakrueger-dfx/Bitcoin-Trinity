//! Encrypted core-state blob for the spend-window counter (Spec §3.6.7).
//!
//! # Why a standalone AEAD, not `trinity-keystore::{encrypt,decrypt}`
//!
//! The keystore primitive is slot-specific: header fields `slot` /
//! `word_count` / `birthday` and a plaintext of `entropy || created_at`.
//! Reusing it would either lie about those fields or pull the A/B blob
//! type into a third role. Same construction (XChaCha20-Poly1305, 24-byte
//! nonce, header as AAD, `chacha20poly1305` already on the signature
//! path) lives here with its own magic/`version` and a dedicated KEK.
//!
//! # KEK
//!
//! The counter is read and written on every `sign_ab` check, including
//! the reject path, and must not call `unwrap_kek(A|B)` (S28). A/B KEKs
//! are presence-gated. The core-state KEK is therefore a **separate**
//! 32-byte key supplied by the caller — not JS-readable once sealed.
//! The app layer (later WP) stores that KEK in the platform keystore
//! under a non-presence policy; this crate only seals/opens.
//!
//! # Anti-rollback
//!
//! AEAD authenticates the bytes; it does **not** stop an older sealed
//! copy from being replayed, which would reset the counter. The app
//! layer must prevent rollback (a platform counter or non-replayable
//! store). A failure from [`crate::WindowCounter::open`] must **never**
//! fall back silently to [`crate::WindowCounter::new`]: that is the
//! same hole via the delete path.

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use thiserror::Error;
use zeroize::Zeroize;

/// ASCII `TRCS` (TRinity Core State). Distinct from keystore `TRIN`.
pub const MAGIC: [u8; 4] = *b"TRCS";

/// Only version `1` is defined.
pub const VERSION: u8 = 1;

/// Header length (magic through nonce).
pub const HEADER_LEN: usize = 32;

/// XChaCha20 nonce length.
pub const NONCE_LEN: usize = 24;

/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

const VERSION_OFFSET: usize = 4;
const RESERVED_OFFSET: usize = 5;
const NONCE_OFFSET: usize = 8;
const RESERVED_LEN: usize = 3;

/// Sentinel: block height / boot id / wall time not known.
pub(crate) const UNKNOWN_U32: u32 = u32::MAX;
pub(crate) const UNKNOWN_U64: u64 = u64::MAX;

/// Hard cap on booked rows (personal wallet, 24 h window).
pub(crate) const MAX_BOOKINGS: usize = 256;
/// Matches `trinity_verify::MAX_PSBT_INS_OR_OUTS`.
pub(crate) const MAX_INPUTS: usize = 100;

/// Failure while encoding or decoding the core-state blob.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CoreStateError {
    /// Shorter than a header plus a tag.
    #[error("core-state blob is shorter than the header plus authentication tag")]
    Truncated,
    /// First four bytes are not `TRCS`.
    #[error("core-state blob magic is not TRCS")]
    BadMagic,
    /// `version` is not `1`.
    #[error("unsupported core-state blob version {0}")]
    UnsupportedVersion(u8),
    /// Non-zero reserved bytes.
    #[error("nonzero reserved bytes are an unknown core-state format")]
    UnsupportedReserved,
    /// OS CSPRNG failed while drawing a nonce.
    #[error("operating-system CSPRNG failed")]
    CsRng,
    /// Tag / ciphertext / AAD mismatch.
    #[error("XChaCha20-Poly1305 authentication failed")]
    Aead,
    /// AEAD succeeded but the plaintext is not a well-formed state.
    #[error("decrypted core-state plaintext is malformed")]
    Plaintext,
}

/// One booked spend, keyed by **input set** (Spec §3.6.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BookedSpend {
    pub(crate) inputs: Vec<OutPoint>,
    pub(crate) amount_sat: u64,
    pub(crate) elapsed_at_ns: u64,
}

/// Decrypted window counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreState {
    pub(crate) initialized: bool,
    pub(crate) monotonic_ns_at_anchor: u64,
    pub(crate) block_height_at_anchor: Option<u32>,
    pub(crate) boot_id_at_anchor: Option<u64>,
    pub(crate) wall_unix_ns_at_anchor: Option<u64>,
    pub(crate) window_elapsed_ns: u64,
    /// Inclusive live-window start: `window_elapsed_ns` minus the configured
    /// window length, saturating at 0. Written by `prune` and, on first
    /// initialization, by `advance`. Serialized in the TRCS v1 blob. Can
    /// run backward if the user lengthens the window. No reader today —
    /// kept so the blob layout stays at `VERSION` 1.
    pub(crate) window_start_elapsed_ns: u64,
    pub(crate) passphrase_used_since_install: bool,
    pub(crate) bookings: Vec<BookedSpend>,
}

impl CoreState {
    pub(crate) fn empty() -> Self {
        Self {
            initialized: false,
            monotonic_ns_at_anchor: 0,
            block_height_at_anchor: None,
            boot_id_at_anchor: None,
            wall_unix_ns_at_anchor: None,
            window_elapsed_ns: 0,
            window_start_elapsed_ns: 0,
            passphrase_used_since_install: false,
            bookings: Vec::new(),
        }
    }
}

/// Encrypt `state` under `kek`, drawing a fresh nonce.
pub(crate) fn encrypt(kek: &[u8; 32], state: &CoreState) -> Result<Vec<u8>, CoreStateError> {
    let nonce = draw_nonce()?;
    encrypt_at_nonce(kek, nonce, state)
}

/// Encrypt with an explicit nonce (tests).
#[cfg(test)]
pub(crate) fn encrypt_with_nonce(
    kek: &[u8; 32],
    nonce: [u8; NONCE_LEN],
    state: &CoreState,
) -> Result<Vec<u8>, CoreStateError> {
    encrypt_at_nonce(kek, nonce, state)
}

fn encrypt_at_nonce(
    kek: &[u8; 32],
    nonce: [u8; NONCE_LEN],
    state: &CoreState,
) -> Result<Vec<u8>, CoreStateError> {
    if state.bookings.len() > MAX_BOOKINGS {
        return Err(CoreStateError::Plaintext);
    }
    let header = encode_header(&nonce);
    let mut plaintext = encode_plaintext(state)?;
    let blob = seal(kek, &header, &plaintext)?;
    plaintext.zeroize();
    Ok(blob)
}

/// Decrypt `blob` under `kek`.
pub(crate) fn decrypt(kek: &[u8; 32], blob: &[u8]) -> Result<CoreState, CoreStateError> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(CoreStateError::Truncated);
    }
    let header = &blob[..HEADER_LEN];
    parse_header(header)?;
    let body = &blob[HEADER_LEN..];
    let mut plaintext = open(kek, header, body)?;
    let state = decode_plaintext(&plaintext);
    plaintext.zeroize();
    state
}

fn encode_header(nonce: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&MAGIC);
    header[VERSION_OFFSET] = VERSION;
    header[NONCE_OFFSET..].copy_from_slice(nonce);
    header
}

fn parse_header(header: &[u8]) -> Result<(), CoreStateError> {
    debug_assert_eq!(header.len(), HEADER_LEN);
    if header[..4] != MAGIC {
        return Err(CoreStateError::BadMagic);
    }
    let version = header[VERSION_OFFSET];
    if version != VERSION {
        return Err(CoreStateError::UnsupportedVersion(version));
    }
    if header[RESERVED_OFFSET..NONCE_OFFSET] != [0u8; RESERVED_LEN] {
        return Err(CoreStateError::UnsupportedReserved);
    }
    Ok(())
}

fn encode_plaintext(state: &CoreState) -> Result<Vec<u8>, CoreStateError> {
    let mut flags = 0u8;
    if state.initialized {
        flags |= 1;
    }
    if state.passphrase_used_since_install {
        flags |= 2;
    }
    let n = u16::try_from(state.bookings.len()).map_err(|_| CoreStateError::Plaintext)?;
    let mut out = Vec::new();
    out.extend_from_slice(&state.monotonic_ns_at_anchor.to_le_bytes());
    out.extend_from_slice(&opt_u32(state.block_height_at_anchor).to_le_bytes());
    out.extend_from_slice(&opt_u64(state.boot_id_at_anchor).to_le_bytes());
    out.extend_from_slice(&opt_u64(state.wall_unix_ns_at_anchor).to_le_bytes());
    out.extend_from_slice(&state.window_elapsed_ns.to_le_bytes());
    out.extend_from_slice(&state.window_start_elapsed_ns.to_le_bytes());
    out.push(flags);
    out.push(0);
    out.extend_from_slice(&n.to_le_bytes());
    for b in &state.bookings {
        if b.inputs.len() > MAX_INPUTS || b.inputs.is_empty() {
            return Err(CoreStateError::Plaintext);
        }
        let ni = u16::try_from(b.inputs.len()).map_err(|_| CoreStateError::Plaintext)?;
        out.extend_from_slice(&b.elapsed_at_ns.to_le_bytes());
        out.extend_from_slice(&b.amount_sat.to_le_bytes());
        out.extend_from_slice(&ni.to_le_bytes());
        for op in &b.inputs {
            out.extend_from_slice(op.txid.as_ref());
            out.extend_from_slice(&op.vout.to_le_bytes());
        }
    }
    Ok(out)
}

fn decode_plaintext(buf: &[u8]) -> Result<CoreState, CoreStateError> {
    // anchors (8+4+8+8) + elapsed (8+8) + flags/res (1+1) + n (2) = 48
    const MIN: usize = 48;
    if buf.len() < MIN {
        return Err(CoreStateError::Plaintext);
    }
    let monotonic_ns_at_anchor = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let block_raw = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let boot_raw = u64::from_le_bytes(buf[12..20].try_into().unwrap());
    let wall_raw = u64::from_le_bytes(buf[20..28].try_into().unwrap());
    let window_elapsed_ns = u64::from_le_bytes(buf[28..36].try_into().unwrap());
    let window_start_elapsed_ns = u64::from_le_bytes(buf[36..44].try_into().unwrap());
    let flags = buf[44];
    let reserved = buf[45];
    if reserved != 0 || flags & !3 != 0 {
        return Err(CoreStateError::Plaintext);
    }
    let n = u16::from_le_bytes(buf[46..48].try_into().unwrap()) as usize;
    if n > MAX_BOOKINGS {
        return Err(CoreStateError::Plaintext);
    }
    let mut off = 48;
    let mut bookings = Vec::with_capacity(n);
    for _ in 0..n {
        if off + 18 > buf.len() {
            return Err(CoreStateError::Plaintext);
        }
        let elapsed_at_ns = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        let amount_sat = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap());
        let ni = u16::from_le_bytes(buf[off + 16..off + 18].try_into().unwrap()) as usize;
        off += 18;
        if ni == 0 || ni > MAX_INPUTS {
            return Err(CoreStateError::Plaintext);
        }
        let need = ni.saturating_mul(36);
        if off + need > buf.len() {
            return Err(CoreStateError::Plaintext);
        }
        let mut inputs = Vec::with_capacity(ni);
        for _ in 0..ni {
            let txid = Txid::from_byte_array(buf[off..off + 32].try_into().unwrap());
            let vout = u32::from_le_bytes(buf[off + 32..off + 36].try_into().unwrap());
            inputs.push(OutPoint { txid, vout });
            off += 36;
        }
        bookings.push(BookedSpend {
            inputs,
            amount_sat,
            elapsed_at_ns,
        });
    }
    if off != buf.len() {
        return Err(CoreStateError::Plaintext);
    }
    Ok(CoreState {
        initialized: flags & 1 != 0,
        monotonic_ns_at_anchor,
        block_height_at_anchor: from_opt_u32(block_raw),
        boot_id_at_anchor: from_opt_u64(boot_raw),
        wall_unix_ns_at_anchor: from_opt_u64(wall_raw),
        window_elapsed_ns,
        window_start_elapsed_ns,
        passphrase_used_since_install: flags & 2 != 0,
        bookings,
    })
}

fn opt_u32(v: Option<u32>) -> u32 {
    v.unwrap_or(UNKNOWN_U32)
}
fn opt_u64(v: Option<u64>) -> u64 {
    v.unwrap_or(UNKNOWN_U64)
}
fn from_opt_u32(v: u32) -> Option<u32> {
    if v == UNKNOWN_U32 {
        None
    } else {
        Some(v)
    }
}
fn from_opt_u64(v: u64) -> Option<u64> {
    if v == UNKNOWN_U64 {
        None
    } else {
        Some(v)
    }
}

fn seal(kek: &[u8; 32], header: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CoreStateError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*kek));
    let nonce = nonce_from_header(header);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: header,
            },
        )
        .expect("XChaCha20-Poly1305 encrypt is infallible for core-state plaintext");
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open(kek: &[u8; 32], header: &[u8], body: &[u8]) -> Result<Vec<u8>, CoreStateError> {
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
        .map_err(|_| CoreStateError::Aead)
}

fn nonce_from_header(header: &[u8]) -> XNonce {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&header[NONCE_OFFSET..]);
    XNonce::from(nonce)
}

fn draw_nonce() -> Result<[u8; NONCE_LEN], CoreStateError> {
    draw_nonce_with(getrandom::fill)
}

fn draw_nonce_with<F>(fill: F) -> Result<[u8; NONCE_LEN], CoreStateError>
where
    F: FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
{
    let mut nonce = [0u8; NONCE_LEN];
    fill(&mut nonce).map_err(|_| CoreStateError::CsRng)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    const KEK: [u8; 32] = [0x5A; 32];
    const NONCE: [u8; 24] = [0x11; 24];

    fn sample_state() -> CoreState {
        let mut s = CoreState::empty();
        s.initialized = true;
        s.monotonic_ns_at_anchor = 1_000;
        s.block_height_at_anchor = Some(800_000);
        s.boot_id_at_anchor = Some(3);
        s.wall_unix_ns_at_anchor = Some(1_700_000_000_000_000_000);
        s.window_elapsed_ns = 5_000;
        s.window_start_elapsed_ns = 0;
        s.passphrase_used_since_install = true;
        s.bookings.push(BookedSpend {
            inputs: vec![OutPoint {
                txid: Txid::from_byte_array([7u8; 32]),
                vout: 1,
            }],
            amount_sat: 42,
            elapsed_at_ns: 10,
        });
        s
    }

    fn sample_blob() -> Vec<u8> {
        encrypt_with_nonce(&KEK, NONCE, &sample_state()).unwrap()
    }

    #[test]
    fn layout_and_roundtrip() {
        let blob = sample_blob();
        assert_eq!(&blob[..4], &MAGIC);
        assert_eq!(blob[VERSION_OFFSET], VERSION);
        assert_eq!(&blob[RESERVED_OFFSET..NONCE_OFFSET], &[0, 0, 0]);
        assert_eq!(&blob[NONCE_OFFSET..HEADER_LEN], &NONCE);
        let d = decrypt(&KEK, &blob).unwrap();
        assert_eq!(d, sample_state());
    }

    #[test]
    fn encrypt_draws_distinct_nonces() {
        let s = sample_state();
        let a = encrypt(&KEK, &s).unwrap();
        let b = encrypt(&KEK, &s).unwrap();
        assert_ne!(&a[NONCE_OFFSET..HEADER_LEN], &b[NONCE_OFFSET..HEADER_LEN]);
        assert_eq!(decrypt(&KEK, &a).unwrap(), s);
        assert_eq!(decrypt(&KEK, &b).unwrap(), s);
    }

    #[test]
    fn empty_roundtrip() {
        let s = CoreState::empty();
        let blob = encrypt_with_nonce(&KEK, NONCE, &s).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap(), s);
    }

    #[test]
    fn unknown_sentinels_roundtrip_as_none() {
        let mut s = CoreState::empty();
        s.initialized = true;
        let blob = encrypt_with_nonce(&KEK, NONCE, &s).unwrap();
        let d = decrypt(&KEK, &blob).unwrap();
        assert_eq!(d.block_height_at_anchor, None);
        assert_eq!(d.boot_id_at_anchor, None);
        assert_eq!(d.wall_unix_ns_at_anchor, None);
    }

    #[test]
    fn decrypt_rejects_truncated_magic_version_reserved() {
        assert_eq!(decrypt(&KEK, &[]).unwrap_err(), CoreStateError::Truncated);
        assert_eq!(
            decrypt(&KEK, &[0u8; HEADER_LEN + TAG_LEN - 1]).unwrap_err(),
            CoreStateError::Truncated
        );
        let mut blob = sample_blob();
        blob[0] = b'X';
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::BadMagic);
        let mut blob = sample_blob();
        blob[VERSION_OFFSET] = 2;
        assert_eq!(
            decrypt(&KEK, &blob).unwrap_err(),
            CoreStateError::UnsupportedVersion(2)
        );
        let mut blob = sample_blob();
        blob[RESERVED_OFFSET] = 1;
        assert_eq!(
            decrypt(&KEK, &blob).unwrap_err(),
            CoreStateError::UnsupportedReserved
        );
    }

    #[test]
    fn decrypt_rejects_wrong_kek_and_bit_flips() {
        let blob = sample_blob();
        assert_eq!(
            decrypt(&[0x00; 32], &blob).unwrap_err(),
            CoreStateError::Aead
        );
        let mut ct = blob.clone();
        ct[HEADER_LEN] ^= 1;
        assert_eq!(decrypt(&KEK, &ct).unwrap_err(), CoreStateError::Aead);
        let mut tag = blob;
        let last = tag.len() - 1;
        tag[last] ^= 1;
        assert_eq!(decrypt(&KEK, &tag).unwrap_err(), CoreStateError::Aead);
    }

    #[test]
    fn plaintext_malformed_paths() {
        let header = encode_header(&NONCE);
        // Too short.
        let blob = seal(&KEK, &header, &[0u8; 10]).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::Plaintext);
        // Non-zero inner reserved / bad flags.
        let mut s = sample_state();
        let mut raw = encode_plaintext(&s).unwrap();
        raw[45] = 1;
        let blob = seal(&KEK, &header, &raw).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::Plaintext);
        raw[45] = 0;
        raw[44] = 4;
        let blob = seal(&KEK, &header, &raw).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::Plaintext);
        // Trailing garbage.
        raw = encode_plaintext(&s).unwrap();
        raw.push(0);
        let blob = seal(&KEK, &header, &raw).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::Plaintext);
        // Claimed booking count past the buffer.
        raw = encode_plaintext(&s).unwrap();
        raw[46..48].copy_from_slice(&2u16.to_le_bytes());
        let blob = seal(&KEK, &header, &raw).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::Plaintext);
        // n_inputs = 0.
        s.bookings[0].inputs.clear();
        assert_eq!(
            encrypt_with_nonce(&KEK, NONCE, &s).unwrap_err(),
            CoreStateError::Plaintext
        );
        // Too many inputs on one booking (the other arm of the ||).
        s.bookings[0].inputs = (0..=MAX_INPUTS)
            .map(|i| OutPoint {
                txid: Txid::from_byte_array([i as u8; 32]),
                vout: 0,
            })
            .collect();
        assert_eq!(
            encrypt_with_nonce(&KEK, NONCE, &s).unwrap_err(),
            CoreStateError::Plaintext
        );
    }

    #[test]
    fn too_many_bookings_rejected() {
        let mut s = CoreState::empty();
        s.initialized = true;
        s.bookings = (0..MAX_BOOKINGS + 1)
            .map(|i| BookedSpend {
                inputs: vec![OutPoint {
                    txid: Txid::from_byte_array([i as u8; 32]),
                    vout: 0,
                }],
                amount_sat: 1,
                elapsed_at_ns: 0,
            })
            .collect();
        assert_eq!(
            encrypt_with_nonce(&KEK, NONCE, &s).unwrap_err(),
            CoreStateError::Plaintext
        );
    }

    #[test]
    fn decode_rejects_too_many_bookings_in_header() {
        let header = encode_header(&NONCE);
        let mut raw = vec![0u8; 48];
        raw[46..48].copy_from_slice(&(MAX_BOOKINGS as u16 + 1).to_le_bytes());
        let blob = seal(&KEK, &header, &raw).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::Plaintext);
    }

    #[test]
    fn decode_rejects_bad_input_count_and_short_inputs() {
        let header = encode_header(&NONCE);
        let mut raw = vec![0u8; 48 + 18];
        raw[46..48].copy_from_slice(&1u16.to_le_bytes());
        // ni = 0
        let blob = seal(&KEK, &header, &raw).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::Plaintext);
        raw[48 + 16..48 + 18].copy_from_slice(&(MAX_INPUTS as u16 + 1).to_le_bytes());
        let blob = seal(&KEK, &header, &raw).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::Plaintext);
        // ni = 1 but no outpoint bytes
        raw[48 + 16..48 + 18].copy_from_slice(&1u16.to_le_bytes());
        let blob = seal(&KEK, &header, &raw).unwrap();
        assert_eq!(decrypt(&KEK, &blob).unwrap_err(), CoreStateError::Plaintext);
    }

    #[test]
    fn csrng_error_is_mapped() {
        let err = draw_nonce_with(|_| Err(getrandom::Error::UNSUPPORTED)).unwrap_err();
        assert_eq!(err, CoreStateError::CsRng);
    }

    #[test]
    fn display_covers_every_variant() {
        let cases: &[CoreStateError] = &[
            CoreStateError::Truncated,
            CoreStateError::BadMagic,
            CoreStateError::UnsupportedVersion(2),
            CoreStateError::UnsupportedReserved,
            CoreStateError::CsRng,
            CoreStateError::Aead,
            CoreStateError::Plaintext,
        ];
        for e in cases {
            assert!(!e.to_string().is_empty(), "{e:?}");
        }
    }

    #[test]
    fn open_maps_tag_failure() {
        let header = encode_header(&NONCE);
        assert_eq!(
            open(&KEK, &header, &[0u8; TAG_LEN]).unwrap_err(),
            CoreStateError::Aead
        );
    }
}
