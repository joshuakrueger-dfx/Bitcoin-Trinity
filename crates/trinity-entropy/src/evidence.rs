//! Verification sheet — Spec §2.2.4 point 5.
//!
//! Secrets appear here only through [`fmt::Display`] / [`VerificationSheet::render`].
//! [`fmt::Debug`] prints `[redacted]` for hex fields and the mnemonic.

use core::fmt;

use trinity_types::WordCount;

use crate::entropy::GeneratedKey;
use crate::hex;
use crate::sources::{AdditionalEntropy, SLOT_SEPARATOR};

/// Exportable evidence for one generation.
///
/// Built from a [`GeneratedKey`]. Displaying this type is the deliberate
/// path that reveals `raw_csprng`, `extra_bytes`, `entropy`, and the
/// BIP-39 words so a third party can recompute the derivation offline.
pub struct VerificationSheet {
    l: u8,
    word_count: WordCount,
    raw_csprng_hex: String,
    extra_bytes_hex: String,
    entropy_hex: String,
    mnemonic: String,
    dice: Option<String>,
    coins: Option<String>,
    cards: Option<String>,
    sensor_len: Option<usize>,
}

impl VerificationSheet {
    /// Build a sheet from a completed generation.
    pub fn from_key(key: &GeneratedKey) -> Self {
        Self::from_parts(
            key.word_count(),
            key.raw_csprng_hex(),
            key.extra_bytes_hex(),
            key.entropy_hex(),
            key.mnemonic_phrase().to_owned(),
            key.sources(),
        )
    }

    fn from_parts(
        word_count: WordCount,
        raw_csprng_hex: String,
        extra_bytes_hex: String,
        entropy_hex: String,
        mnemonic: String,
        sources: &AdditionalEntropy,
    ) -> Self {
        Self {
            l: word_count.entropy_bytes(),
            word_count,
            raw_csprng_hex,
            extra_bytes_hex,
            entropy_hex,
            mnemonic,
            dice: sources.dice().map(str::to_owned),
            coins: sources.coins().map(str::to_owned),
            cards: sources.cards_display(),
            sensor_len: sources.sensor().map(<[u8]>::len),
        }
    }

    /// `L` in bytes (16 or 32).
    #[inline]
    pub fn l(&self) -> u8 {
        self.l
    }

    /// Word length that selected `L`.
    #[inline]
    pub fn word_count(&self) -> WordCount {
        self.word_count
    }

    /// `raw_csprng` as 64 hex characters.
    #[inline]
    pub fn raw_csprng_hex(&self) -> &str {
        &self.raw_csprng_hex
    }

    /// `extra_bytes` as hex (empty when no sources were active).
    #[inline]
    pub fn extra_bytes_hex(&self) -> &str {
        &self.extra_bytes_hex
    }

    /// `entropy` as 32 or 64 hex characters.
    #[inline]
    pub fn entropy_hex(&self) -> &str {
        &self.entropy_hex
    }

    /// The 12 or 24 BIP-39 words.
    #[inline]
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Dice digit sequence, if that source was active.
    #[inline]
    pub fn dice(&self) -> Option<&str> {
        self.dice.as_deref()
    }

    /// Coin bit sequence, if that source was active.
    #[inline]
    pub fn coins(&self) -> Option<&str> {
        self.coins.as_deref()
    }

    /// Card list (`AS 10H KD`), if that source was active.
    #[inline]
    pub fn cards(&self) -> Option<&str> {
        self.cards.as_deref()
    }

    /// Sensor blob length in bytes, if that class-B source was active.
    #[inline]
    pub fn sensor_len(&self) -> Option<usize> {
        self.sensor_len
    }

    /// Render the sheet. Equivalent to [`ToString::to_string`].
    pub fn render(&self) -> String {
        self.body()
    }

    fn body(&self) -> String {
        let extra_line = if self.extra_bytes_hex.is_empty() {
            "  extra_bytes = (empty)".to_owned()
        } else {
            format!("  extra_bytes = {}", self.extra_bytes_hex)
        };
        let sensor_line = match self.sensor_len {
            Some(n) => format!("  sensor = {n} bytes (class B; credited bits = 0)"),
            None => "  sensor = (inactive)".to_owned(),
        };
        format!(
            "\
Trinity entropy verification sheet
==================================

Construction (SPECIFICATION.md §2.2):

  L           := 32 (24 words) or 16 (12 words)
  raw_csprng  := getrandom(32)
  extra_bytes := canonical encoding of the additional source
  extract     := HMAC-SHA512(key = raw_csprng, msg = extra_bytes)
  entropy     := extract[0..L]
  mnemonic    := BIP-39(entropy)
  seed        := PBKDF2-HMAC-SHA512(mnemonic, \"mnemonic\", 2048, 64)
  xprv        := BIP-32-Master(seed)

This instance:
  L           = {} ({} words)
  raw_csprng  = {}
{extra_line}
  entropy     = {}

Separator rule (SPECIFICATION.md §2.2.2):
  extra_bytes = [dice_ascii] 0x{SLOT_SEPARATOR:02X} [coin_ascii] 0x{SLOT_SEPARATOR:02X} [cards_ascii] 0x{SLOT_SEPARATOR:02X} [sensor_blob]
  Order is Dice < Coin < Cards < SensorNoise, not activation order.
  Inactive trailing sources omit their separator. An empty slot
  between two active sources keeps its 0x{SLOT_SEPARATOR:02X} so the encoding
  is injective (dice=\"12\" ≠ dice=\"1\" + coin=\"2\"; dice=\"1\" ≠ coin=\"1\").
  If no sources are active, extra_bytes is empty and
  extract = HMAC-SHA512(raw_csprng, \"\").

Sources:
  dice   = {}
  coins  = {}
  cards  = {}
{sensor_line}

BIP-39 words ({}):
  {}

Recompute extract offline:
  scripts/recompute_entropy.sh <raw_csprng_hex> <extra_bytes_hex> <L>
  # openssl dgst -sha512 -mac HMAC -macopt hexkey:<raw_csprng_hex>
",
            self.l,
            self.word_count,
            self.raw_csprng_hex,
            self.entropy_hex,
            self.dice.as_deref().unwrap_or("(inactive)"),
            self.coins.as_deref().unwrap_or("(inactive)"),
            self.cards.as_deref().unwrap_or("(inactive)"),
            self.word_count,
            self.mnemonic,
        )
    }
}

impl fmt::Debug for VerificationSheet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationSheet")
            .field("l", &self.l)
            .field("word_count", &self.word_count)
            .field("raw_csprng_hex", &"[redacted]")
            .field("extra_bytes_hex", &"[redacted]")
            .field("entropy_hex", &"[redacted]")
            .field("mnemonic", &"[redacted]")
            .field("dice", &self.dice)
            .field("coins", &self.coins)
            .field("cards", &self.cards)
            .field("sensor_len", &self.sensor_len)
            .finish()
    }
}

impl fmt::Display for VerificationSheet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.body())
    }
}

/// Convenience: hex of a byte slice (used by callers assembling evidence).
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::generate_from_raw;
    use crate::sources::AdditionalEntropy;
    use trinity_types::WordCount;

    fn sample_key() -> crate::GeneratedKey {
        let extra = AdditionalEntropy::new()
            .with_dice("31662")
            .unwrap()
            .with_coins("01")
            .unwrap()
            .with_cards("AS10H")
            .unwrap()
            .with_sensor(&[0x01, 0x02]);
        generate_from_raw(WordCount::Words24, &[0x11u8; 32], &extra).unwrap()
    }

    #[test]
    fn sheet_contains_formula_l_and_separator_rule() {
        let key = sample_key();
        let sheet = VerificationSheet::from_key(&key);
        assert_eq!(sheet.l(), 32);
        assert_eq!(sheet.word_count(), WordCount::Words24);
        assert_eq!(sheet.raw_csprng_hex(), key.raw_csprng_hex());
        assert_eq!(sheet.extra_bytes_hex(), key.extra_bytes_hex());
        assert_eq!(sheet.entropy_hex(), key.entropy_hex());
        assert_eq!(sheet.mnemonic(), key.mnemonic_phrase());
        assert_eq!(sheet.dice(), Some("31662"));
        assert_eq!(sheet.coins(), Some("01"));
        assert_eq!(sheet.cards(), Some("AS 10H"));
        assert_eq!(sheet.sensor_len(), Some(2));

        let text = sheet.render();
        assert!(text.contains("HMAC-SHA512(key = raw_csprng, msg = extra_bytes)"));
        assert!(text.contains("L           = 32 (24 words)"));
        assert!(text.contains("0x1E"));
        assert!(text.contains("Dice < Coin < Cards < SensorNoise"));
        assert!(text.contains("extract = HMAC-SHA512(raw_csprng, \"\")"));
        assert!(text.contains(&key.raw_csprng_hex()));
        assert!(text.contains(&key.entropy_hex()));
        assert!(text.contains("31662"));
        assert!(text.contains("AS 10H"));
        assert!(text.contains("class B; credited bits = 0"));
        assert!(text.contains(key.mnemonic_phrase()));
        assert!(text.contains("openssl dgst -sha512 -mac HMAC"));
        assert_eq!(text, sheet.to_string());
    }

    #[test]
    fn sheet_empty_sources() {
        let key =
            generate_from_raw(WordCount::Words12, &[0u8; 32], &AdditionalEntropy::new()).unwrap();
        let sheet = VerificationSheet::from_key(&key);
        assert_eq!(sheet.l(), 16);
        let text = sheet.render();
        assert!(text.contains("extra_bytes = (empty)"));
        assert!(text.contains("L           = 16 (12 words)"));
        assert!(text.contains("dice   = (inactive)"));
        assert!(text.contains("sensor = (inactive)"));
    }

    #[test]
    fn debug_does_not_print_hex_or_words() {
        let key = sample_key();
        let sheet = VerificationSheet::from_key(&key);
        let d = format!("{sheet:?}");
        assert!(d.contains("[redacted]"));
        assert!(!d.contains(&key.raw_csprng_hex()));
        assert!(!d.contains(&key.entropy_hex()));
        let first = key.mnemonic_phrase().split_whitespace().next().unwrap();
        assert!(!d.contains(first));
    }

    #[test]
    fn bytes_to_hex_wrapper() {
        assert_eq!(bytes_to_hex(&[0x1e, 0xff]), "1eff");
    }

    #[test]
    fn display_propagates_fmt_error() {
        struct Fail;
        impl fmt::Write for Fail {
            fn write_str(&mut self, _: &str) -> fmt::Result {
                Err(fmt::Error)
            }
        }
        let sheet = VerificationSheet::from_key(&sample_key());
        let mut fail = Fail;
        assert!(fmt::write(&mut fail, format_args!("{sheet}")).is_err());
    }
}
