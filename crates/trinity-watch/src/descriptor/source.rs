//! Per-key source metadata for `descriptor.json` — Spec §2.3.

use serde::{Deserialize, Serialize};

/// Where a key was generated or imported (Spec §2.3 `source` per key).
///
/// `InApp` — generated inside Trinity. `Hardware { model }` — xpub imported
/// from a registered device (Coldcard, BitBox, …); may carry a BIP-388
/// `policy_id` on the key contribution.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeySource {
    /// Generated in-app (phone / SE / keystore path).
    InApp,
    /// Imported from a hardware signer; `model` is a free-form product label.
    Hardware {
        /// Device model string (e.g. `"coldcard_mk4"`, `"bitbox02"`).
        model: String,
    },
}

impl KeySource {
    /// `true` when this source is a hardware device.
    #[inline]
    pub const fn is_hardware(&self) -> bool {
        matches!(self, KeySource::Hardware { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_in_app() {
        let s = KeySource::InApp;
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"{"type":"in_app"}"#);
        assert_eq!(serde_json::from_str::<KeySource>(&j).unwrap(), s);
    }

    #[test]
    fn serde_hardware() {
        let s = KeySource::Hardware {
            model: "coldcard_mk4".into(),
        };
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("hardware"));
        assert!(j.contains("coldcard_mk4"));
        assert_eq!(serde_json::from_str::<KeySource>(&j).unwrap(), s);
        assert!(s.is_hardware());
        assert!(!KeySource::InApp.is_hardware());
    }
}
