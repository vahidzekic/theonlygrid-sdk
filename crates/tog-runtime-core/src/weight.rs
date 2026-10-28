//! Two-dimensional weight (TOG-SPEC-0007 §6).
//!
//! A block is bounded both in execution time (`validate_block` must fit the Hub's 2 s budget) and
//! in proof size (the PoV must fit 5 MB, TOG-SPEC-0002 §8). Every call, hook and transaction
//! declares a [`Weight`] in both dimensions; the block builder stops before either sum would pass
//! [`BlockLimits`].

use borsh::{BorshDeserialize, BorshSerialize};

/// Picoseconds per second; `ref_time` is counted in picoseconds of reference-validator time.
pub const PS_PER_SECOND: u64 = 1_000_000_000_000;

/// Execution time (picoseconds of reference-validator time) and proof size (witness bytes): the
/// shared type of `tog-types` (TOG-SPEC-0000 §7.2), so CGMP weight limits and block weights are the
/// same type.
pub use tog_types::cgmp::Weight;

/// Per-block limits (§6 defaults). A chain may lower them, never raise them past the Hub's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BlockLimits {
    /// Most weight one block may use, hooks included.
    pub max_block: Weight,
}

impl BlockLimits {
    /// 1.5 s of reference execution and a 5 MB (5 000 000 byte) PoV.
    pub const DEFAULT: BlockLimits = BlockLimits { max_block: Weight::from_parts(PS_PER_SECOND * 3 / 2, 5_000_000) };
}

impl Default for BlockLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Tracks the weight consumed against a limit while a block or call executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeightMeter {
    limit: Weight,
    consumed: Weight,
}

impl WeightMeter {
    /// A meter with nothing consumed.
    pub const fn new(limit: Weight) -> Self {
        WeightMeter { limit, consumed: Weight::ZERO }
    }

    /// Weight consumed so far.
    pub const fn consumed(&self) -> Weight {
        self.consumed
    }

    /// Weight still available.
    pub const fn remaining(&self) -> Weight {
        self.limit.saturating_sub(self.consumed)
    }

    /// Whether `w` more would still fit.
    pub fn can_consume(&self, w: Weight) -> bool {
        self.consumed.checked_add(w).is_some_and(|t| t.all_lte(self.limit))
    }

    /// Consume `w` if it fits; otherwise consume nothing and return `false`.
    pub fn try_consume(&mut self, w: Weight) -> bool {
        if !self.can_consume(w) {
            return false;
        }
        self.consumed = self.consumed.saturating_add(w);
        true
    }

    /// Give back `w` (the unused part of a worst-case charge, §6).
    pub fn refund(&mut self, w: Weight) {
        self.consumed = self.consumed.saturating_sub(w);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits() {
        assert_eq!(BlockLimits::DEFAULT.max_block, Weight::from_parts(1_500_000_000_000, 5_000_000));
    }

    #[test]
    fn meter_refuses_either_dimension() {
        let mut m = WeightMeter::new(Weight::from_parts(10, 10));
        assert!(m.try_consume(Weight::from_parts(6, 1)));
        assert!(!m.try_consume(Weight::from_parts(5, 1)));
        assert!(!m.try_consume(Weight::from_parts(1, 10)));
        assert_eq!(m.consumed(), Weight::from_parts(6, 1));
        m.refund(Weight::from_parts(2, 0));
        assert!(m.try_consume(Weight::from_parts(6, 9)));
        assert_eq!(m.remaining(), Weight::ZERO);
    }

    #[test]
    fn overflow_does_not_fit() {
        let m = WeightMeter::new(Weight::MAX);
        let mut m2 = m;
        assert!(m2.try_consume(Weight::MAX));
        assert!(!m2.can_consume(Weight::from_parts(1, 0)));
    }
}
