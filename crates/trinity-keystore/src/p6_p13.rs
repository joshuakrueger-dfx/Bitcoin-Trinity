//! P6 (blob round-trip + header mutations) and P13 (`word_count` AAD).

use proptest::prelude::*;
use trinity_types::{KeySlot, WordCount};

use crate::{
    decrypt, encrypt_with_nonce, BlobError, HEADER_LEN, SLOT_OFFSET, TAG_LEN, WORD_COUNT_OFFSET,
};

const KEK: [u8; 32] = [0x5a; 32];
const NONCE: [u8; 24] = [0xa5; 24];

fn fixture(
    slot: KeySlot,
    wc: WordCount,
    entropy: &[u8],
    nonce: [u8; 24],
    birthday: u32,
    created_at: u64,
) -> Vec<u8> {
    encrypt_with_nonce(&KEK, slot, wc, nonce, birthday, entropy, created_at)
        .expect("fixture encrypt")
}

/// P6: `decrypt(encrypt(e, kek), kek) == e` for both word counts and slots.
#[test]
fn p6_roundtrip_identity_both_profiles() {
    for wc in [WordCount::Words12, WordCount::Words24] {
        let mut entropy = vec![0u8; usize::from(wc.entropy_bytes())];
        for (i, b) in entropy.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        for slot in [KeySlot::A, KeySlot::B] {
            let blob = fixture(slot, wc, &entropy, NONCE, 42, 99);
            let d = decrypt(&KEK, &blob).expect("round-trip");
            assert_eq!(d.slot(), slot);
            assert_eq!(d.word_count(), wc);
            assert_eq!(d.birthday(), 42);
            assert_eq!(d.created_at(), 99);
            assert_eq!(d.entropy().as_slice(), entropy.as_slice());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// P6: random entropy / KEK / nonce / birthday / created_at round-trip.
    #[test]
    fn p6_random_roundtrip(
        wc12 in proptest::bool::ANY,
        slot_b in proptest::bool::ANY,
        kek in any::<[u8; 32]>(),
        nonce in any::<[u8; 24]>(),
        birthday in any::<u32>(),
        created_at in any::<u64>(),
        e12 in any::<[u8; 16]>(),
        e24 in any::<[u8; 32]>(),
    ) {
        let wc = if wc12 { WordCount::Words12 } else { WordCount::Words24 };
        let slot = if slot_b { KeySlot::B } else { KeySlot::A };
        let entropy: &[u8] = if wc12 { &e12 } else { &e24 };
        let blob = encrypt_with_nonce(&kek, slot, wc, nonce, birthday, entropy, created_at)
            .expect("encrypt");
        let d = decrypt(&kek, &blob).expect("decrypt");
        prop_assert_eq!(d.slot(), slot);
        prop_assert_eq!(d.word_count(), wc);
        prop_assert_eq!(d.birthday(), birthday);
        prop_assert_eq!(d.created_at(), created_at);
        prop_assert_eq!(d.entropy().as_slice(), entropy);
    }
}

/// P6: every header bit-flip is a decrypt error (never a plausible success).
#[test]
fn p6_every_header_mutation_is_decrypt_error() {
    let entropy = [0x77u8; 32];
    let blob = fixture(KeySlot::A, WordCount::Words24, &entropy, NONCE, 1, 2);
    assert!(decrypt(&KEK, &blob).is_ok());

    for offset in 0..HEADER_LEN {
        for bit in 0..8 {
            let mut mutated = blob.clone();
            mutated[offset] ^= 1 << bit;
            assert!(
                decrypt(&KEK, &mutated).is_err(),
                "header byte {offset} bit {bit} decrypted"
            );
        }
    }
}

/// P13: `word_count` 24→12 is an AEAD error, never a 16-byte half-read.
#[test]
fn p13_word_count_24_to_12_is_aead() {
    let entropy = [0xABu8; 32];
    let blob = fixture(KeySlot::A, WordCount::Words24, &entropy, NONCE, 100, 200);
    let mut mutated = blob;
    mutated[WORD_COUNT_OFFSET] = 12;

    let err = decrypt(&KEK, &mutated).unwrap_err();
    assert_eq!(
        err,
        BlobError::Aead,
        "24→12 must fail the AEAD tag check, not return Ok with a 16-byte prefix"
    );
}

/// P13: `word_count` 12→24 is also an AEAD error (AAD mismatch).
///
/// The ciphertext is still the original 16+8 bytes plus tag. Decrypt does
/// not slice the body by the claimed `L` before AEAD, so this is not a
/// structural length check — it is the same AAD-protected tag failure.
#[test]
fn p13_word_count_12_to_24_is_aead() {
    let entropy = [0xCDu8; 16];
    let blob = fixture(KeySlot::B, WordCount::Words12, &entropy, NONCE, 3, 4);
    let mut mutated = blob;
    mutated[WORD_COUNT_OFFSET] = 24;

    let err = decrypt(&KEK, &mutated).unwrap_err();
    assert_eq!(
        err,
        BlobError::Aead,
        "12→24 must fail AEAD (AAD), not succeed with a padded/short read"
    );
}

/// A-blob and B-blob share layout and ciphertext; only `slot` and the tag differ.
///
/// Slot is AAD, so a one-offset-only identity cannot hold: the Poly1305 tag
/// authenticates the header. Spec §2.4's own phrase is bit-identical *in format*.
#[test]
fn a_b_layout_identical_except_slot_and_tag() {
    let entropy = [0x10u8; 32];
    let a = fixture(KeySlot::A, WordCount::Words24, &entropy, NONCE, 9, 8);
    let b = fixture(KeySlot::B, WordCount::Words24, &entropy, NONCE, 9, 8);
    assert_eq!(a.len(), b.len());
    assert_eq!(&a[..SLOT_OFFSET], &b[..SLOT_OFFSET]);
    assert_eq!(a[SLOT_OFFSET], 0);
    assert_eq!(b[SLOT_OFFSET], 1);
    let tag_at = a.len() - TAG_LEN;
    assert_eq!(&a[SLOT_OFFSET + 1..tag_at], &b[SLOT_OFFSET + 1..tag_at]);
    assert_ne!(&a[tag_at..], &b[tag_at..]);
}
