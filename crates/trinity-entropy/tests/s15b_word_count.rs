//! S15b — a 12-word C is unrepresentable at the type level.
//!
//! `generate_c` / `generate_c_from_raw` take no `WordCount` argument and
//! hardcode `Words24`. There is no `generate_for_slot(C, Words12, …)` path.

use trinity_entropy::{generate_c_from_raw, AdditionalEntropy};
use trinity_types::WordCount;

#[test]
fn s15b_generate_c_is_always_24_words() {
    let extra = AdditionalEntropy::new();
    let key = generate_c_from_raw(&[0x7fu8; 32], &extra).unwrap();
    assert_eq!(key.word_count(), WordCount::Words24);
    assert_eq!(key.entropy().len(), 32);
    assert_eq!(key.mnemonic_phrase().split_whitespace().count(), 24);
    assert_eq!(key.entropy_hex().len(), 64);
}

#[test]
fn s15b_compile_fail_word_count_argument() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
