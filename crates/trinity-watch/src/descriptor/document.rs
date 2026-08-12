//! `descriptor.json` document model — Spec §2.3.

use serde::{Deserialize, Serialize};
use trinity_types::{Fingerprint, KeySlot, Network, WordCount, XpubWithOrigin};

use super::build::{build_wallet_descriptors, validate_trinity_descriptor};
use super::error::DescriptorError;
use super::source::KeySource;

/// Current `descriptor.json` format version.
pub const FORMAT_VERSION: u32 = 1;

/// One key's public contribution to the wallet (setup input and persisted form).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyContribution {
    /// Slot A, B, or C.
    pub slot: KeySlot,
    /// Account-level xpub with BIP-32 origin (Spec §2.3).
    pub xpub: XpubWithOrigin,
    /// Block height at which this key first existed (rescan birthday).
    pub birthday_height: u32,
    /// BIP-39 word length for this key (E3b; Spec §2.3 `word_count` per key).
    pub word_count: WordCount,
    /// Generation / import source.
    pub source: KeySource,
    /// BIP-388 policy id when the key is registered on a hardware device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

/// Inputs required to build a [`WalletDescriptors`] document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorSetup {
    /// Network the descriptors encode for.
    pub network: Network,
    /// Exactly the three keys A, B, C (order irrelevant; slots must be unique).
    pub keys: [KeyContribution; 3],
    /// Unix creation timestamp (seconds).
    pub created_at_unix: u64,
}

impl DescriptorSetup {
    /// Build the wallet descriptor document (receive + change + metadata).
    pub fn build(self) -> Result<WalletDescriptors, DescriptorError> {
        build_wallet_descriptors(self.network, self.keys, self.created_at_unix)
    }
}

/// Full `descriptor.json` payload (Spec §2.3).
///
/// Holds plaintext receive/change descriptors, all three xpubs with origin,
/// per-key birthday / word_count / source / optional policy_id, network,
/// creation timestamp, and format version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletDescriptors {
    /// Format version (currently [`FORMAT_VERSION`]).
    pub format_version: u32,
    /// Network (mainnet / testnet / signet / regtest).
    pub network: Network,
    /// Creation time as Unix seconds.
    pub created_at_unix: u64,
    /// Receive descriptor `wsh(sortedmulti(2,…/0/*))#checksum`.
    pub receive_descriptor: String,
    /// Change descriptor `wsh(sortedmulti(2,…/1/*))#checksum`.
    pub change_descriptor: String,
    /// Keys in slot order A, B, C.
    pub keys: [KeyContribution; 3],
}

impl WalletDescriptors {
    /// Serialise to pretty JSON (`descriptor.json` body).
    pub fn to_json(&self) -> Result<String, DescriptorError> {
        // Wire form uses numeric word_count map as in Spec §2.3 example
        // `{"A":24,"B":24,"C":24}` alongside the full key records.
        let wire = WireDocument::from_wallet(self);
        serde_json::to_string_pretty(&wire).map_err(|e| DescriptorError::Json(e.to_string()))
    }

    /// Parse and validate a `descriptor.json` body.
    pub fn from_json(json: &str) -> Result<Self, DescriptorError> {
        let wire: WireDocument =
            serde_json::from_str(json).map_err(|e| DescriptorError::Json(e.to_string()))?;
        wire.into_wallet()
    }

    /// Receive descriptor string (with checksum).
    pub fn receive(&self) -> &str {
        &self.receive_descriptor
    }

    /// Change descriptor string (with checksum).
    pub fn change(&self) -> &str {
        &self.change_descriptor
    }

    /// Word counts per slot as Spec map shape `{"A":24,"B":12,"C":24}`.
    pub fn word_count_map(&self) -> WordCountMap {
        WordCountMap {
            a: self.keys[0].word_count.words(),
            b: self.keys[1].word_count.words(),
            c: self.keys[2].word_count.words(),
        }
    }

    /// Key record for a slot.
    pub fn key(&self, slot: KeySlot) -> &KeyContribution {
        &self.keys[slot.as_u8() as usize]
    }
}

/// Spec §2.3 `word_count` map serialised with integer values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WordCountMap {
    /// Slot A word count (12 or 24).
    #[serde(rename = "A")]
    pub a: u8,
    /// Slot B word count (12 or 24).
    #[serde(rename = "B")]
    pub b: u8,
    /// Slot C word count (12 or 24).
    #[serde(rename = "C")]
    pub c: u8,
}

/// Wire format for `descriptor.json`.
///
/// Separates the Spec-facing `word_count` map (integers) from full key
/// records so the backup printout and recovery UI can read either view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WireDocument {
    format_version: u32,
    network: Network,
    created_at_unix: u64,
    receive_descriptor: String,
    change_descriptor: String,
    /// Spec §2.3: `{"A":24,"B":24,"C":24}` (integers, not enum tags).
    word_count: WordCountMap,
    keys: [WireKey; 3],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WireKey {
    slot: KeySlot,
    /// Hex fingerprint (Spec origin form), not raw byte array.
    fingerprint: String,
    origin_path: String,
    xpub: String,
    birthday_height: u32,
    source: KeySource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_id: Option<String>,
}

impl WireDocument {
    fn from_wallet(w: &WalletDescriptors) -> Self {
        let keys = [
            WireKey::from_contrib(&w.keys[0]),
            WireKey::from_contrib(&w.keys[1]),
            WireKey::from_contrib(&w.keys[2]),
        ];
        Self {
            format_version: w.format_version,
            network: w.network,
            created_at_unix: w.created_at_unix,
            receive_descriptor: w.receive_descriptor.clone(),
            change_descriptor: w.change_descriptor.clone(),
            word_count: w.word_count_map(),
            keys,
        }
    }

    fn into_wallet(self) -> Result<WalletDescriptors, DescriptorError> {
        if self.format_version != FORMAT_VERSION {
            return Err(DescriptorError::InvalidDocument(format!(
                "unsupported format_version {}",
                self.format_version
            )));
        }

        validate_trinity_descriptor(&self.receive_descriptor)?;
        validate_trinity_descriptor(&self.change_descriptor)?;

        if self.receive_descriptor.contains("/1/*")
            || !self.receive_descriptor.contains("/0/*")
            || self.change_descriptor.contains("/0/*")
            || !self.change_descriptor.contains("/1/*")
        {
            return Err(DescriptorError::InvalidDocument(
                "receive must use /0/* and change /1/* (O8, no multipath)".into(),
            ));
        }
        if self.receive_descriptor.contains('<') || self.change_descriptor.contains('<') {
            return Err(DescriptorError::MultipathForbidden);
        }

        let mut keys = [
            self.keys[0].to_contrib(self.word_count.a)?,
            self.keys[1].to_contrib(self.word_count.b)?,
            self.keys[2].to_contrib(self.word_count.c)?,
        ];
        // Re-order into A,B,C if needed and check word_count map consistency.
        keys.sort_by_key(|k| k.slot.as_u8());
        if keys[0].slot != KeySlot::A || keys[1].slot != KeySlot::B || keys[2].slot != KeySlot::C {
            return Err(DescriptorError::InvalidDocument(
                "keys must be slots A, B, C".into(),
            ));
        }
        if keys[0].word_count.words() != self.word_count.a
            || keys[1].word_count.words() != self.word_count.b
            || keys[2].word_count.words() != self.word_count.c
        {
            return Err(DescriptorError::InvalidDocument(
                "word_count map inconsistent with key records".into(),
            ));
        }

        // Rebuild to enforce P7 and path rules, then ensure descriptors match.
        let rebuilt = build_wallet_descriptors(self.network, keys.clone(), self.created_at_unix)?;
        if rebuilt.receive_descriptor != self.receive_descriptor
            || rebuilt.change_descriptor != self.change_descriptor
        {
            return Err(DescriptorError::InvalidDocument(
                "stored descriptors do not match keys (possible tampering)".into(),
            ));
        }

        Ok(WalletDescriptors {
            format_version: self.format_version,
            network: self.network,
            created_at_unix: self.created_at_unix,
            receive_descriptor: self.receive_descriptor,
            change_descriptor: self.change_descriptor,
            keys,
        })
    }
}

impl WireKey {
    fn from_contrib(k: &KeyContribution) -> Self {
        Self {
            slot: k.slot,
            fingerprint: k.xpub.fingerprint.to_hex(),
            origin_path: k.xpub.origin_path.clone(),
            xpub: k.xpub.xpub.clone(),
            birthday_height: k.birthday_height,
            source: k.source.clone(),
            policy_id: k.policy_id.clone(),
        }
    }

    fn to_contrib(&self, word_count_words: u8) -> Result<KeyContribution, DescriptorError> {
        let word_count = WordCount::from_words(word_count_words).ok_or_else(|| {
            DescriptorError::InvalidDocument(format!(
                "word_count must be 12 or 24, got {word_count_words}"
            ))
        })?;
        let fingerprint = Fingerprint::from_hex(&self.fingerprint)
            .map_err(|e| DescriptorError::InvalidKeyExpression(format!("fingerprint: {e}")))?;
        if !self.source.is_hardware() && self.policy_id.is_some() {
            return Err(DescriptorError::InvalidDocument(
                "policy_id is only valid for Hardware source keys".into(),
            ));
        }
        Ok(KeyContribution {
            slot: self.slot,
            xpub: XpubWithOrigin::new(fingerprint, self.origin_path.clone(), self.xpub.clone()),
            birthday_height: self.birthday_height,
            word_count,
            source: self.source.clone(),
            policy_id: self.policy_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::path::bip48_origin_path;

    const FP_A: &str = "73756c7f";
    const FP_B: &str = "f9f62194";
    const FP_C: &str = "c98b1535";
    const XPUB_A: &str = "tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3";
    const XPUB_B: &str = "tpubDDp3ZSH1yCwusRppH7zgSxq2t1VEUyXSeEp8E5aFS8m43MknUjiF1bSLo3CGWAxbDyhF1XowA5ukPzyJZjznYk3kYi6oe7QxtX2euvKWsk4";
    const XPUB_C: &str = "tpubDCDi5W4sP6zSnzJeowy8rQDVhBdRARaPhK1axABi8V1661wEPeanpEXj4ZLAUEoikVtoWcyK26TKKJSecSfeKxwHCcRrge9k1ybuiL71z4a";

    fn sample(mixed_words: bool) -> WalletDescriptors {
        let path = bip48_origin_path(Network::Regtest);
        let wc_b = if mixed_words {
            WordCount::Words12
        } else {
            WordCount::Words24
        };
        DescriptorSetup {
            network: Network::Regtest,
            created_at_unix: 1_700_000_000,
            keys: [
                KeyContribution {
                    slot: KeySlot::A,
                    xpub: XpubWithOrigin::new(
                        Fingerprint::from_hex(FP_A).unwrap(),
                        path.clone(),
                        XPUB_A,
                    ),
                    birthday_height: 101,
                    word_count: WordCount::Words24,
                    source: KeySource::InApp,
                    policy_id: None,
                },
                KeyContribution {
                    slot: KeySlot::B,
                    xpub: XpubWithOrigin::new(
                        Fingerprint::from_hex(FP_B).unwrap(),
                        path.clone(),
                        XPUB_B,
                    ),
                    birthday_height: 102,
                    word_count: wc_b,
                    source: KeySource::Hardware {
                        model: "coldcard_mk4".into(),
                    },
                    policy_id: Some("pol-deadbeef".into()),
                },
                KeyContribution {
                    slot: KeySlot::C,
                    xpub: XpubWithOrigin::new(Fingerprint::from_hex(FP_C).unwrap(), path, XPUB_C),
                    birthday_height: 103,
                    word_count: WordCount::Words24,
                    source: KeySource::InApp,
                    policy_id: None,
                },
            ],
        }
        .build()
        .unwrap()
    }

    #[test]
    fn json_roundtrip_mixed_word_lengths() {
        let original = sample(true);
        assert_eq!(original.word_count_map().a, 24);
        assert_eq!(original.word_count_map().b, 12);
        assert_eq!(original.word_count_map().c, 24);

        let json = original.to_json().unwrap();
        // Pretty JSON always inserts a space after `:`; evaluate both needles so
        // coverage does not leave short-circuit `||` arms as unevaluated (`-`).
        let a_pretty = json.contains(r#""A": 24"#);
        let a_compact = json.contains(r#""A":24"#);
        assert!(a_pretty | a_compact);
        let b_pretty = json.contains(r#""B": 12"#);
        let b_compact = json.contains(r#""B":12"#);
        assert!(b_pretty | b_compact);
        assert!(json.contains("coldcard_mk4"));
        assert!(json.contains("pol-deadbeef"));

        let restored = WalletDescriptors::from_json(&json).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn load_rejects_foreign_grammar() {
        // Force wire with tampered receive (wpkh instead of sortedmulti).
        let mut wire = WireDocument::from_wallet(&sample(false));
        use miniscript::{Descriptor, DescriptorPublicKey};
        use std::str::FromStr;
        let foreign = Descriptor::<DescriptorPublicKey>::from_str(
            "wpkh([73756c7f/48'/1'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)",
        )
        .unwrap()
        .to_string();
        wire.receive_descriptor = foreign;
        let json = serde_json::to_string(&wire).unwrap();
        let err = WalletDescriptors::from_json(&json).unwrap_err();
        assert!(
            matches!(
                err,
                DescriptorError::ForeignGrammar(_) | DescriptorError::InvalidDocument(_)
            ),
            "got {err:?}"
        );
    }

    /// Load-path error arms that need `WireDocument` (crate-private).
    #[test]
    fn load_error_arms() {
        let base = sample(false);

        let mut wire = WireDocument::from_wallet(&base);
        wire.format_version = 99;
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        // Full swap hits receive.contains("/1/*") first.
        let mut wire = WireDocument::from_wallet(&base);
        std::mem::swap(&mut wire.receive_descriptor, &mut wire.change_descriptor);
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        // O8 chain-check arms with descriptors that still pass Trinity grammar.
        use miniscript::{Descriptor, DescriptorPublicKey};
        use std::str::FromStr;
        let reparse = |s: &str| -> String {
            Descriptor::<DescriptorPublicKey>::from_str(s)
                .unwrap()
                .to_string()
        };

        // Receive without /0/* and without /1/* (fixed index), change ok.
        let mut wire = WireDocument::from_wallet(&base);
        let recv_fixed = wire.receive_descriptor.replace("/0/*", "/0/0");
        // Drop checksum then reparse so grammar validates with fixed child.
        let recv_body = recv_fixed.split('#').next().unwrap();
        wire.receive_descriptor = reparse(recv_body);
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        // Change carries /0/* while receive stays external-only.
        let mut wire = WireDocument::from_wallet(&base);
        wire.change_descriptor = wire.receive_descriptor.clone();
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        // Change missing /1/* (fixed /1/0), receive ok with /0/*.
        let mut wire = WireDocument::from_wallet(&base);
        let ch_body = wire
            .change_descriptor
            .replace("/1/*", "/1/0")
            .split('#')
            .next()
            .unwrap()
            .to_owned();
        wire.change_descriptor = reparse(&ch_body);
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        // Slot sets that fail different arms of the A/B/C check after sort.
        let mut wire = WireDocument::from_wallet(&base);
        wire.keys[2].slot = KeySlot::A; // A,B,A → after sort A,A,B (fails B)
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));
        let mut wire = WireDocument::from_wallet(&base);
        wire.keys[2].slot = KeySlot::B; // A,B,B → after sort A,B,B (fails C)
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));
        let mut wire = WireDocument::from_wallet(&base);
        wire.keys[0].slot = KeySlot::B;
        wire.keys[1].slot = KeySlot::B;
        wire.keys[2].slot = KeySlot::C; // B,B,C
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        let mut wire = WireDocument::from_wallet(&base);
        wire.receive_descriptor = wire.receive_descriptor.replacen(FP_A, "00000000", 1);
        assert!(WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()).is_err());

        // Tamper keys so rebuild diverges on both descriptors.
        let mut wire = WireDocument::from_wallet(&base);
        let x0 = wire.keys[0].xpub.clone();
        let f0 = wire.keys[0].fingerprint.clone();
        wire.keys[0].xpub = wire.keys[1].xpub.clone();
        wire.keys[0].fingerprint = wire.keys[1].fingerprint.clone();
        wire.keys[1].xpub = x0;
        wire.keys[1].fingerprint = f0;
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        // Change-only mismatch: keep keys + receive, reorder keys inside change
        // string (valid sortedmulti + /1/*) so rebuild receive matches but change does not.
        let mut wire = WireDocument::from_wallet(&base);
        let ch = &wire.change_descriptor;
        // Swap first two key expressions between commas inside sortedmulti.
        // Pattern: wsh(sortedmulti(2, KEY0, KEY1, KEY2))#cs
        let body = ch.split('#').next().unwrap();
        let inner = body
            .strip_prefix("wsh(sortedmulti(2,")
            .and_then(|s| s.strip_suffix("))"))
            .expect("change descriptor shape");
        let parts: Vec<&str> = inner.splitn(3, ',').collect();
        assert_eq!(parts.len(), 3);
        let reordered = format!("wsh(sortedmulti(2,{},{},{}))", parts[1], parts[0], parts[2]);
        wire.change_descriptor = reparse(&reordered);
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        let mut wire = WireDocument::from_wallet(&base);
        wire.word_count.a = 18;
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        let mut wire = WireDocument::from_wallet(&base);
        wire.keys[0].policy_id = Some("nope".into());
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidDocument(_))
        ));

        let mut wire = WireDocument::from_wallet(&base);
        wire.keys[0].fingerprint = "zzzzzzzz".into();
        assert!(matches!(
            WalletDescriptors::from_json(&serde_json::to_string(&wire).unwrap()),
            Err(DescriptorError::InvalidKeyExpression(_))
        ));

        assert!(matches!(
            WalletDescriptors::from_json("not-json{"),
            Err(DescriptorError::Json(_))
        ));

        let d = sample(true);
        assert_eq!(d.receive(), d.receive_descriptor.as_str());
        assert_eq!(d.change(), d.change_descriptor.as_str());
        assert_eq!(d.key(KeySlot::B).word_count, WordCount::Words12);
    }
}
