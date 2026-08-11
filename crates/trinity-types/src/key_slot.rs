//! Key slot identifiers A / B / C — SPECIFICATION.md §1.1, §2.4.

use core::fmt;
use serde::{Deserialize, Serialize};

/// One of the three independent keys in the 2-of-3 quorum.
///
/// Spec §1.1 (`KeySlot{A,B,C}`), §2.4 (`SlotPolicy.slot`), facade §1.3
/// (`sign_with_recovery_key`, `quiz_*`, `hw_import_xpub`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeySlot {
    /// Device key A — biometric unlock, no paper backup (Spec §1.4, §2.4).
    A,
    /// Device key B — user-presence unlock, paper backup mandatory (Spec §1.4, §2.4).
    B,
    /// Paper/steel key C — never on device after setup (Spec §1.4, §2.2.5).
    C,
}

impl KeySlot {
    /// All slots in descriptor order A, B, C.
    pub const ALL: [KeySlot; 3] = [KeySlot::A, KeySlot::B, KeySlot::C];

    /// Wire / blob encoding: A = 0, B = 1, C = 2.
    ///
    /// Spec §2.4 blob header: `slot u8 (0=A, 1=B)`. C is not stored in a blob
    /// but needs a stable ordinal for `descriptor.json` key maps.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        match self {
            KeySlot::A => 0,
            KeySlot::B => 1,
            KeySlot::C => 2,
        }
    }

    /// Inverse of [`KeySlot::as_u8`]. Returns `None` for values outside `0..=2`.
    #[inline]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(KeySlot::A),
            1 => Some(KeySlot::B),
            2 => Some(KeySlot::C),
            _ => None,
        }
    }

    /// `true` for slots that may hold an on-device encrypted blob (A and B).
    #[inline]
    pub const fn has_device_blob(self) -> bool {
        matches!(self, KeySlot::A | KeySlot::B)
    }
}

impl fmt::Display for KeySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySlot::A => f.write_str("A"),
            KeySlot::B => f.write_str("B"),
            KeySlot::C => f.write_str("C"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u8() {
        for slot in KeySlot::ALL {
            assert_eq!(KeySlot::from_u8(slot.as_u8()), Some(slot));
        }
        assert_eq!(KeySlot::from_u8(3), None);
        assert_eq!(KeySlot::from_u8(255), None);
    }

    #[test]
    fn device_blob_slots() {
        assert!(KeySlot::A.has_device_blob());
        assert!(KeySlot::B.has_device_blob());
        assert!(!KeySlot::C.has_device_blob());
    }

    #[test]
    fn display_and_debug_are_labels_not_secrets() {
        assert_eq!(format!("{}", KeySlot::A), "A");
        assert_eq!(format!("{}", KeySlot::B), "B");
        assert_eq!(format!("{}", KeySlot::C), "C");
        assert_eq!(format!("{:?}", KeySlot::A), "A");
    }

    #[test]
    fn serde_uppercase() {
        let j = serde_json::to_string(&KeySlot::B).unwrap();
        assert_eq!(j, "\"B\"");
        assert_eq!(
            serde_json::from_str::<KeySlot>("\"C\"").unwrap(),
            KeySlot::C
        );
    }
}
