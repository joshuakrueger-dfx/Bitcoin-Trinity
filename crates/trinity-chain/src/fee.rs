//! Fee-rate estimates from a chain backend — Spec §1.6 `fee_estimates()`.

use core::fmt;
use std::collections::BTreeMap;

/// Feerate estimates keyed by confirmation target (blocks).
///
/// Spec §1.6 names `FeeEstimates` but does not prescribe fields. Units match
/// Spec §3.1 / `FeeTarget::FeerateSatVb`: **satoshi per virtual byte**.
/// Backends fill whatever targets their source provides (Electrum / Core
/// `estimatesmartfee` targets differ); the UI maps these into a fee target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeeEstimates {
    /// Confirmation target in blocks → feerate in sat/vB.
    ///
    /// Typical keys when available: `1`, `3`, `6`, `144`. Missing keys mean
    /// the backend did not estimate that horizon.
    pub sat_per_vb_by_target_blocks: BTreeMap<u32, u64>,
}

impl FeeEstimates {
    /// Empty estimate set (no targets known).
    #[inline]
    pub const fn empty() -> Self {
        Self {
            sat_per_vb_by_target_blocks: BTreeMap::new(),
        }
    }

    /// Build from `(target_blocks, sat_per_vb)` pairs.
    pub fn from_targets(targets: impl IntoIterator<Item = (u32, u64)>) -> Self {
        Self {
            sat_per_vb_by_target_blocks: targets.into_iter().collect(),
        }
    }

    /// Feerate for a confirmation target, if present.
    #[inline]
    pub fn sat_per_vb_for(&self, target_blocks: u32) -> Option<u64> {
        self.sat_per_vb_by_target_blocks
            .get(&target_blocks)
            .copied()
    }

    /// Whether any target was estimated.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.sat_per_vb_by_target_blocks.is_empty()
    }
}

impl fmt::Display for FeeEstimates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sat_per_vb_by_target_blocks.is_empty() {
            return f.write_str("{}");
        }
        write!(f, "{{")?;
        let mut first = true;
        for (blocks, rate) in &self.sat_per_vb_by_target_blocks {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "{blocks}bl→{rate} sat/vB")?;
        }
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_targets_and_lookup() {
        let e = FeeEstimates::from_targets([(1, 10), (6, 3)]);
        assert_eq!(e.sat_per_vb_for(1), Some(10));
        assert_eq!(e.sat_per_vb_for(6), Some(3));
        assert_eq!(e.sat_per_vb_for(144), None);
        assert!(!e.is_empty());
    }

    #[test]
    fn empty_default() {
        assert!(FeeEstimates::empty().is_empty());
        assert_eq!(FeeEstimates::empty(), FeeEstimates::default());
        assert_eq!(format!("{}", FeeEstimates::empty()), "{}");
    }

    #[test]
    fn display_lists_targets() {
        let e = FeeEstimates::from_targets([(1, 8), (6, 2)]);
        let s = format!("{e}");
        assert!(s.contains("1bl→8 sat/vB"));
        assert!(s.contains("6bl→2 sat/vB"));
    }
}
