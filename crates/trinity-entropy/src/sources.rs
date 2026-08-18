//! Class A / Class B additional-entropy sources and canonical `extra_bytes`.
//!
//! Spec §2.2.1–§2.2.2. Encoding is injective: trailing inactive sources omit
//! their `0x1E` separator; an empty slot *between* two active sources keeps
//! its separator so dice=`"12"` and (dice=`"1"`, coin=`"2"`) cannot collide,
//! and dice=`"1"` cannot collide with coin=`"1"`.

use crate::error::{CardError, EntropyError};

/// ASCII Record Separator. Spec §2.2.2.
pub const SLOT_SEPARATOR: u8 = 0x1E;

/// Countable (class A) contribution of a source combination.
///
/// Class B (sensor) is deliberately absent: it is never represented as
/// countable entropy in this crate (Spec §2.2.1, P15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CountableEntropy {
    /// Number of d6 rolls (ASCII `1`–`6`).
    pub dice_rolls: usize,
    /// Number of coin flips (ASCII `0`/`1`).
    pub coin_flips: usize,
    /// Number of distinct playing cards.
    pub cards: usize,
}

impl CountableEntropy {
    /// Bits credited to any class-B source. Always `0`, independent of volume.
    #[inline]
    pub const fn class_b_credited_bits(self) -> u64 {
        0
    }
}

/// Playing-card rank (Spec §2.2.1 examples: `A`, `10`, `K`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rank {
    /// Ace.
    Ace,
    /// Two.
    Two,
    /// Three.
    Three,
    /// Four.
    Four,
    /// Five.
    Five,
    /// Six.
    Six,
    /// Seven.
    Seven,
    /// Eight.
    Eight,
    /// Nine.
    Nine,
    /// Ten (`10`, two ASCII characters).
    Ten,
    /// Jack.
    Jack,
    /// Queen.
    Queen,
    /// King.
    King,
}

impl Rank {
    fn from_start(bytes: &[u8]) -> Option<(Self, usize)> {
        match bytes {
            [b'1', b'0', ..] => Some((Rank::Ten, 2)),
            [b'A', ..] => Some((Rank::Ace, 1)),
            [b'2', ..] => Some((Rank::Two, 1)),
            [b'3', ..] => Some((Rank::Three, 1)),
            [b'4', ..] => Some((Rank::Four, 1)),
            [b'5', ..] => Some((Rank::Five, 1)),
            [b'6', ..] => Some((Rank::Six, 1)),
            [b'7', ..] => Some((Rank::Seven, 1)),
            [b'8', ..] => Some((Rank::Eight, 1)),
            [b'9', ..] => Some((Rank::Nine, 1)),
            [b'J', ..] => Some((Rank::Jack, 1)),
            [b'Q', ..] => Some((Rank::Queen, 1)),
            [b'K', ..] => Some((Rank::King, 1)),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Rank::Ace => "A",
            Rank::Two => "2",
            Rank::Three => "3",
            Rank::Four => "4",
            Rank::Five => "5",
            Rank::Six => "6",
            Rank::Seven => "7",
            Rank::Eight => "8",
            Rank::Nine => "9",
            Rank::Ten => "10",
            Rank::Jack => "J",
            Rank::Queen => "Q",
            Rank::King => "K",
        }
    }

    fn index(self) -> u8 {
        match self {
            Rank::Ace => 0,
            Rank::Two => 1,
            Rank::Three => 2,
            Rank::Four => 3,
            Rank::Five => 4,
            Rank::Six => 5,
            Rank::Seven => 6,
            Rank::Eight => 7,
            Rank::Nine => 8,
            Rank::Ten => 9,
            Rank::Jack => 10,
            Rank::Queen => 11,
            Rank::King => 12,
        }
    }
}

/// Playing-card suit (Spec §2.2.1 examples: `S`, `H`, `D`, `C`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Suit {
    /// Spades (`S`).
    Spades,
    /// Hearts (`H`).
    Hearts,
    /// Diamonds (`D`).
    Diamonds,
    /// Clubs (`C`).
    Clubs,
}

impl Suit {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'S' => Some(Suit::Spades),
            b'H' => Some(Suit::Hearts),
            b'D' => Some(Suit::Diamonds),
            b'C' => Some(Suit::Clubs),
            _ => None,
        }
    }

    fn as_char(self) -> char {
        match self {
            Suit::Spades => 'S',
            Suit::Hearts => 'H',
            Suit::Diamonds => 'D',
            Suit::Clubs => 'C',
        }
    }

    fn index(self) -> u8 {
        match self {
            Suit::Spades => 0,
            Suit::Hearts => 1,
            Suit::Diamonds => 2,
            Suit::Clubs => 3,
        }
    }
}

/// One card: rank + suit, canonical ASCII e.g. `AS`, `10H`, `KD`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Card {
    rank: Rank,
    suit: Suit,
}

impl Card {
    /// Rank of this card.
    #[inline]
    pub const fn rank(self) -> Rank {
        self.rank
    }

    /// Suit of this card.
    #[inline]
    pub const fn suit(self) -> Suit {
        self.suit
    }

    /// Canonical encoding (`AS`, `10H`, `KD`).
    pub fn encode(self) -> String {
        let mut s = String::with_capacity(3);
        s.push_str(self.rank.as_str());
        s.push(self.suit.as_char());
        s
    }

    fn deck_index(self) -> u8 {
        self.rank.index() * 4 + self.suit.index()
    }
}

/// Additional entropy fed into the OR combiner.
///
/// Every source is optional. Omitting all of them yields empty `extra_bytes`
/// (Spec §2.2.1: additional entropy is never mandatory).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AdditionalEntropy {
    dice: Option<String>,
    coins: Option<String>,
    cards: Option<Vec<Card>>,
    sensor: Option<Vec<u8>>,
}

impl core::fmt::Debug for AdditionalEntropy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdditionalEntropy")
            .field(
                "dice",
                &self.dice.as_ref().map(|s| format!("[{} chars]", s.len())),
            )
            .field(
                "coins",
                &self.coins.as_ref().map(|s| format!("[{} chars]", s.len())),
            )
            .field(
                "cards",
                &self.cards.as_ref().map(|c| format!("[{} cards]", c.len())),
            )
            .field(
                "sensor",
                &self.sensor.as_ref().map(|s| format!("[{} bytes]", s.len())),
            )
            .finish()
    }
}

impl AdditionalEntropy {
    /// No additional sources. `canonical_bytes()` is empty.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Activate dice (ASCII `1`–`6`, no separators).
    pub fn with_dice(mut self, ascii: &str) -> Result<Self, EntropyError> {
        self.dice = Some(parse_dice(ascii)?);
        Ok(self)
    }

    /// Activate coin flips (ASCII `0`/`1`, no separators).
    pub fn with_coins(mut self, ascii: &str) -> Result<Self, EntropyError> {
        self.coins = Some(parse_coins(ascii)?);
        Ok(self)
    }

    /// Activate playing cards (concatenated rank+suit, e.g. `AS10HKD`).
    pub fn with_cards(mut self, ascii: &str) -> Result<Self, EntropyError> {
        self.cards = Some(parse_cards(ascii)?);
        Ok(self)
    }

    /// Activate a class-B sensor blob. Empty blob is treated as inactive.
    ///
    /// The blob is fed into `extra_bytes` but is never countable (P15).
    pub fn with_sensor(mut self, blob: &[u8]) -> Self {
        if blob.is_empty() {
            self.sensor = None;
        } else {
            self.sensor = Some(blob.to_vec());
        }
        self
    }

    /// Dice digit sequence, if that source is active.
    #[inline]
    pub fn dice(&self) -> Option<&str> {
        self.dice.as_deref()
    }

    /// Coin bit sequence, if that source is active.
    #[inline]
    pub fn coins(&self) -> Option<&str> {
        self.coins.as_deref()
    }

    /// Parsed cards, if that source is active.
    #[inline]
    pub fn cards(&self) -> Option<&[Card]> {
        self.cards.as_deref()
    }

    /// Canonical concatenated card encoding (`AS10HKD`), if cards are active.
    pub fn cards_ascii(&self) -> Option<String> {
        self.cards.as_ref().map(|cards| encode_cards(cards))
    }

    /// Space-separated card list for the verification sheet (`AS 10H KD`).
    pub fn cards_display(&self) -> Option<String> {
        self.cards.as_ref().map(|cards| {
            cards
                .iter()
                .map(|c| c.encode())
                .collect::<Vec<_>>()
                .join(" ")
        })
    }

    /// Sensor blob, if that class-B source is active.
    #[inline]
    pub fn sensor(&self) -> Option<&[u8]> {
        self.sensor.as_deref()
    }

    /// Class-A unit counts. Sensor length does not appear.
    pub fn countable(&self) -> CountableEntropy {
        CountableEntropy {
            dice_rolls: self.dice.as_ref().map(String::len).unwrap_or(0),
            coin_flips: self.coins.as_ref().map(String::len).unwrap_or(0),
            cards: self.cards.as_ref().map(Vec::len).unwrap_or(0),
        }
    }

    /// Canonical `extra_bytes` (Spec §2.2.2).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let cards = self.cards_ascii().unwrap_or_default();
        encode_slots(&[
            self.dice.as_deref().unwrap_or("").as_bytes(),
            self.coins.as_deref().unwrap_or("").as_bytes(),
            cards.as_bytes(),
            self.sensor.as_deref().unwrap_or(&[]),
        ])
    }
}

/// Concatenate the four slots in Dice < Coin < Cards < SensorNoise order.
///
/// Trailing empty slots (and their separators) are omitted. Internal empty
/// slots keep their separator so the encoding stays injective.
pub fn encode_slots(slots: &[&[u8]; 4]) -> Vec<u8> {
    let last = match slots.iter().rposition(|s| !s.is_empty()) {
        Some(i) => i,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (i, slot) in slots.iter().enumerate().take(last + 1) {
        if i > 0 {
            out.push(SLOT_SEPARATOR);
        }
        out.extend_from_slice(slot);
    }
    out
}

fn parse_dice(ascii: &str) -> Result<String, EntropyError> {
    if ascii.is_empty() {
        return Err(EntropyError::EmptyDice);
    }
    for (index, &byte) in ascii.as_bytes().iter().enumerate() {
        if !matches!(byte, b'1'..=b'6') {
            return Err(EntropyError::InvalidDice { index, byte });
        }
    }
    Ok(ascii.to_owned())
}

fn parse_coins(ascii: &str) -> Result<String, EntropyError> {
    if ascii.is_empty() {
        return Err(EntropyError::EmptyCoins);
    }
    for (index, &byte) in ascii.as_bytes().iter().enumerate() {
        if !matches!(byte, b'0' | b'1') {
            return Err(EntropyError::InvalidCoin { index, byte });
        }
    }
    Ok(ascii.to_owned())
}

fn parse_cards(ascii: &str) -> Result<Vec<Card>, EntropyError> {
    if ascii.is_empty() {
        return Err(EntropyError::EmptyCards);
    }
    let bytes = ascii.as_bytes();
    let mut cards = Vec::new();
    let mut seen: u64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let (rank, n) = Rank::from_start(&bytes[i..]).ok_or(CardError::UnexpectedByte {
            index: i,
            byte: bytes[i],
        })?;
        i += n;
        if i >= bytes.len() {
            return Err(CardError::Incomplete.into());
        }
        let suit = Suit::from_byte(bytes[i]).ok_or(CardError::UnexpectedByte {
            index: i,
            byte: bytes[i],
        })?;
        i += 1;
        let card = Card { rank, suit };
        let bit = 1u64 << card.deck_index();
        if seen & bit != 0 {
            return Err(CardError::Duplicate {
                card: card.encode(),
            }
            .into());
        }
        seen |= bit;
        cards.push(card);
    }
    Ok(cards)
}

fn encode_cards(cards: &[Card]) -> String {
    let mut s = String::new();
    for card in cards {
        s.push_str(card.rank.as_str());
        s.push(card.suit.as_char());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dice_only_example_from_spec() {
        let extra = AdditionalEntropy::new().with_dice("31662").unwrap();
        assert_eq!(extra.canonical_bytes(), b"31662");
        assert_eq!(extra.dice(), Some("31662"));
        assert_eq!(extra.countable().dice_rolls, 5);
    }

    #[test]
    fn empty_sources_yield_empty_bytes() {
        assert!(AdditionalEntropy::new().canonical_bytes().is_empty());
        assert_eq!(
            AdditionalEntropy::new().with_sensor(&[]).canonical_bytes(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn trailing_omit_keeps_internal_empty_slot() {
        // dice + cards, coin inactive → dice 0x1E 0x1E cards
        let extra = AdditionalEntropy::new()
            .with_dice("12")
            .unwrap()
            .with_cards("AS")
            .unwrap();
        assert_eq!(extra.canonical_bytes(), b"12\x1e\x1eAS");
    }

    #[test]
    fn only_coin_has_leading_separator() {
        let extra = AdditionalEntropy::new().with_coins("10").unwrap();
        assert_eq!(extra.canonical_bytes(), b"\x1e10");
    }

    #[test]
    fn only_sensor_has_three_separators() {
        let extra = AdditionalEntropy::new().with_sensor(&[0xaa]);
        assert_eq!(extra.canonical_bytes(), [0x1e, 0x1e, 0x1e, 0xaa]);
    }

    #[test]
    fn dice_one_does_not_collide_with_coin_one() {
        let d = AdditionalEntropy::new().with_dice("1").unwrap();
        let c = AdditionalEntropy::new().with_coins("1").unwrap();
        assert_ne!(d.canonical_bytes(), c.canonical_bytes());
    }

    #[test]
    fn dice_11_does_not_collide_with_dice_1_coin_1() {
        // The boundary case the auftrag names (dice="12" vs dice="1"+coin="2")
        // cannot arise: coin ASCII is only 0/1. The isomorphic valid pair is
        // dice="11" vs dice="1"+coin="1" — join-without-placeholder would
        // still be distinguishable via 0x1E, but a join-active-only rule
        // that dropped the empty-slot mark would *not* be the worry here;
        // the trailing-omit rule still produces different byte strings.
        let a = AdditionalEntropy::new().with_dice("11").unwrap();
        let b = AdditionalEntropy::new()
            .with_dice("1")
            .unwrap()
            .with_coins("1")
            .unwrap();
        assert_eq!(a.canonical_bytes(), b"11");
        assert_eq!(b.canonical_bytes(), b"1\x1e1");
    }

    #[test]
    fn cards_parse_ten_and_faces() {
        let extra = AdditionalEntropy::new().with_cards("AS10HKDQC2C").unwrap();
        let cards = extra.cards().unwrap();
        assert_eq!(cards.len(), 5);
        assert_eq!(cards[0].encode(), "AS");
        assert_eq!(cards[1].encode(), "10H");
        assert_eq!(cards[2].encode(), "KD");
        assert_eq!(cards[3].encode(), "QC");
        assert_eq!(cards[4].encode(), "2C");
        assert_eq!(extra.cards_ascii().unwrap(), "AS10HKDQC2C");
        assert_eq!(extra.cards_display().unwrap(), "AS 10H KD QC 2C");
        assert_eq!(cards[0].rank(), Rank::Ace);
        assert_eq!(cards[0].suit(), Suit::Spades);
    }

    #[test]
    fn full_deck_all_ranks_and_suits() {
        let mut s = String::new();
        for rank in [
            Rank::Ace,
            Rank::Two,
            Rank::Three,
            Rank::Four,
            Rank::Five,
            Rank::Six,
            Rank::Seven,
            Rank::Eight,
            Rank::Nine,
            Rank::Ten,
            Rank::Jack,
            Rank::Queen,
            Rank::King,
        ] {
            for suit in [Suit::Spades, Suit::Hearts, Suit::Diamonds, Suit::Clubs] {
                s.push_str(Card { rank, suit }.encode().as_str());
            }
        }
        let extra = AdditionalEntropy::new().with_cards(&s).unwrap();
        assert_eq!(extra.countable().cards, 52);
    }

    #[test]
    fn rejects_bad_dice_coins_cards() {
        assert_eq!(
            AdditionalEntropy::new().with_dice("").unwrap_err(),
            EntropyError::EmptyDice
        );
        assert_eq!(
            AdditionalEntropy::new().with_dice("17").unwrap_err(),
            EntropyError::InvalidDice {
                index: 1,
                byte: b'7'
            }
        );
        assert_eq!(
            AdditionalEntropy::new().with_coins("").unwrap_err(),
            EntropyError::EmptyCoins
        );
        assert_eq!(
            AdditionalEntropy::new().with_coins("02").unwrap_err(),
            EntropyError::InvalidCoin {
                index: 1,
                byte: b'2'
            }
        );
        assert_eq!(
            AdditionalEntropy::new().with_cards("").unwrap_err(),
            EntropyError::EmptyCards
        );
        assert_eq!(
            AdditionalEntropy::new().with_cards("A").unwrap_err(),
            EntropyError::InvalidCard(CardError::Incomplete)
        );
        assert_eq!(
            AdditionalEntropy::new().with_cards("10").unwrap_err(),
            EntropyError::InvalidCard(CardError::Incomplete)
        );
        assert_eq!(
            AdditionalEntropy::new().with_cards("1H").unwrap_err(),
            EntropyError::InvalidCard(CardError::UnexpectedByte {
                index: 0,
                byte: b'1'
            })
        );
        assert_eq!(
            AdditionalEntropy::new().with_cards("AX").unwrap_err(),
            EntropyError::InvalidCard(CardError::UnexpectedByte {
                index: 1,
                byte: b'X'
            })
        );
        assert_eq!(
            AdditionalEntropy::new().with_cards("ASAS").unwrap_err(),
            EntropyError::InvalidCard(CardError::Duplicate { card: "AS".into() })
        );
        // AS is deck_index 0, where `1 << 0` equals `1 >> 0`. A non-zero
        // index makes the shift direction observable.
        assert_eq!(
            AdditionalEntropy::new().with_cards("2H2H").unwrap_err(),
            EntropyError::InvalidCard(CardError::Duplicate { card: "2H".into() })
        );
        assert_eq!(
            AdditionalEntropy::new().with_cards("KDKD").unwrap_err(),
            EntropyError::InvalidCard(CardError::Duplicate { card: "KD".into() })
        );
    }

    #[test]
    fn cards_known_sequence_roundtrip() {
        let extra = AdditionalEntropy::new().with_cards("2HKDAS").unwrap();
        assert_eq!(extra.cards_ascii().unwrap(), "2HKDAS");
        assert_eq!(extra.countable().cards, 3);
        let cards = extra.cards().unwrap();
        assert_eq!(cards[0].encode(), "2H");
        assert_eq!(cards[1].encode(), "KD");
        assert_eq!(cards[2].encode(), "AS");
    }

    #[test]
    fn countable_ignores_sensor() {
        let a = AdditionalEntropy::new().with_dice("123").unwrap();
        let b = a.clone().with_sensor(&[0u8; 10_000]);
        assert_eq!(a.countable(), b.countable());
        assert_eq!(b.countable().class_b_credited_bits(), 0);
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(b.sensor().unwrap().len(), 10_000);
    }

    #[test]
    fn debug_redacts_sensor_payload() {
        let extra = AdditionalEntropy::new().with_sensor(&[0xde, 0xad]);
        let d = format!("{extra:?}");
        assert!(d.contains("2 bytes"));
        assert!(!d.contains("dead"));
        assert!(!d.contains("de, ad"));
    }

    #[test]
    fn debug_redacts_class_a_sources() {
        let extra = AdditionalEntropy::new()
            .with_dice("31662")
            .unwrap()
            .with_coins("0110")
            .unwrap()
            .with_cards("AS10HKD")
            .unwrap()
            .with_sensor(&[0xaa, 0xbb]);
        let d = format!("{extra:?}");
        assert!(d.contains("[5 chars]"));
        assert!(d.contains("[4 chars]"));
        assert!(d.contains("[3 cards]"));
        assert!(d.contains("[2 bytes]"));
        assert!(!d.contains("31662"));
        assert!(!d.contains("0110"));
        assert!(!d.contains("AS"));
        assert!(!d.contains("10H"));
        assert!(!d.contains("KD"));
        assert!(!d.contains("Ace"));
        assert!(!d.contains("Spades"));
        assert!(!d.contains("aabb"));
    }

    #[test]
    fn accessors_none_when_inactive() {
        let extra = AdditionalEntropy::new();
        assert!(extra.dice().is_none());
        assert!(extra.coins().is_none());
        assert!(extra.cards().is_none());
        assert!(extra.cards_ascii().is_none());
        assert!(extra.cards_display().is_none());
        assert!(extra.sensor().is_none());
        assert_eq!(extra.countable(), CountableEntropy::default());
    }
}
