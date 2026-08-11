//! BIP-39 word length per key — SPECIFICATION.md §2.2.3 (Decision E3b).

use core::fmt;
use serde::{Deserialize, Serialize};

/// BIP-39 mnemonic length allowed by Trinity.
///
/// Spec §2.2.3 / E3b: only **12** or **24** words. A and B are choosable
/// (default 24); C is fixed 24 at setup time (enforced in WP-30 / SetupConfig,
/// not by deleting the 12-word variant of this type).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WordCount {
    /// 12 words → 128 bit / 16 bytes entropy (Spec §2.2.3 table).
    Words12,
    /// 24 words → 256 bit / 32 bytes entropy (Spec §2.2.3 table).
    Words24,
}

impl WordCount {
    /// Number of BIP-39 words.
    #[inline]
    pub const fn words(self) -> u8 {
        match self {
            WordCount::Words12 => 12,
            WordCount::Words24 => 24,
        }
    }

    /// Entropy length `L` in bytes (Spec §2.2.3: 16 for 12 words, 32 for 24).
    #[inline]
    pub const fn entropy_bytes(self) -> u8 {
        match self {
            WordCount::Words12 => 16,
            WordCount::Words24 => 32,
        }
    }

    /// Quiz sample size (Spec §2.2.3 table: 3 of 12, 4 of 24).
    #[inline]
    pub const fn quiz_sample_size(self) -> u8 {
        match self {
            WordCount::Words12 => 3,
            WordCount::Words24 => 4,
        }
    }

    /// Parse from the word count integer used in blob headers / JSON
    /// (`word_count u8 (24 or 12)`, Spec §2.4).
    pub const fn from_words(n: u8) -> Option<Self> {
        match n {
            12 => Some(WordCount::Words12),
            24 => Some(WordCount::Words24),
            _ => None,
        }
    }
}

impl fmt::Display for WordCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.words())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_and_entropy() {
        assert_eq!(WordCount::Words12.words(), 12);
        assert_eq!(WordCount::Words12.entropy_bytes(), 16);
        assert_eq!(WordCount::Words12.quiz_sample_size(), 3);
        assert_eq!(WordCount::Words24.words(), 24);
        assert_eq!(WordCount::Words24.entropy_bytes(), 32);
        assert_eq!(WordCount::Words24.quiz_sample_size(), 4);
    }

    #[test]
    fn from_words_accepts_only_12_and_24() {
        assert_eq!(WordCount::from_words(12), Some(WordCount::Words12));
        assert_eq!(WordCount::from_words(24), Some(WordCount::Words24));
        assert_eq!(WordCount::from_words(15), None);
        assert_eq!(WordCount::from_words(0), None);
        assert_eq!(WordCount::from_words(21), None);
    }

    #[test]
    fn display_is_count() {
        assert_eq!(format!("{}", WordCount::Words12), "12");
        assert_eq!(format!("{}", WordCount::Words24), "24");
    }

    #[test]
    fn serde_snake_case() {
        let j = serde_json::to_string(&WordCount::Words24).unwrap();
        assert_eq!(j, "\"words24\"");
        assert_eq!(
            serde_json::from_str::<WordCount>("\"words12\"").unwrap(),
            WordCount::Words12
        );
    }
}
