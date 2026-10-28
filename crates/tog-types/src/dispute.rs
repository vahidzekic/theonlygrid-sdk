//! Disputes opened outside sampling (TOG-SPEC-0003 §4.6): fisherman challenges and appeals.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use alloc::collections::BTreeMap;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{Amount, Hash32};

use crate::checkpoint::Sketch;
use crate::worker::WorkerId;

/// `TxBody` variant 17. A fisherman challenge during `W_opt`; opens R1 for that segment.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChallengeTx {
    /// Job.
    pub job_id: Hash32,
    /// Challenged segment.
    pub segment: u32,
    /// The Hub locks exactly `21 · fee_j`; the tx is rejected if that exceeds `max_bond`.
    pub max_bond: Amount,
    /// As `VerifierCommit.output_commitment`, with a salt of the challenger's choice; opened
    /// with a `VerifierReveal` in R1's reveal window.
    pub output_commitment: Option<Hash32>,
}

/// `TxBody` variant 18. The R1 loser (executor, dissenter or challenger) appeals; opens R2.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppealTx {
    /// Job.
    pub job_id: Hash32,
    /// Segment of the R1 verdict.
    pub segment: u32,
    /// The Hub locks exactly `51 · fee_j`; the tx is rejected if that exceeds `max_bond`.
    pub max_bond: Amount,
}

/// `TxBody` variant 83. A juror's derived executor sketch in a derived-sketch round (TOG-SPEC-0003
/// §4.2): valid from the first block past the challenge's `T_keys` deadline to the round's reveal
/// deadline, inclusive; one per juror and round.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AttestSketchTx {
    /// Job.
    pub job_id: Hash32,
    /// Challenged segment `m`.
    pub segment: u32,
    /// `H("TOG/v1/sketch" ‖ borsh(Some(d)))`, the hash `output_commitment` uses
    /// ([`crate::verifier::sketch_hash`] of `Some(d)`).
    pub sketch_hash: Hash32,
    /// The body `d`; required if the round has none recorded for `sketch_hash`.
    pub sketch: Option<Sketch>,
}

/// `TxBody` variant 84. A voter's sketch of the start checkpoint under the segment's seed
/// (TOG-SPEC-0003 §3.3 "Copy test"): `c = sketch_n(ckpt_{n−1})`. Valid from the block that
/// records the executor's sketch of `segment` to the voter's round's reveal deadline, inclusive;
/// one per voter and round.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AttestCopySketchTx {
    /// Job.
    pub job_id: Hash32,
    /// Segment `n ≥ 1`.
    pub segment: u32,
    /// `H("TOG/v1/sketch" ‖ borsh(Some(c)))` ([`crate::verifier::sketch_hash`] of `Some(c)`).
    pub copy_hash: Hash32,
    /// The body `c`; required if the round has none recorded for `copy_hash`.
    pub sketch: Option<Sketch>,
}

/// `compute_market.sketch_attests[(job_id, segment, round)]` (TOG-SPEC-0003 §4.2): the
/// attestations of a derived-sketch round, round 1 for R1 and 2 for R2, removed with the dispute.
/// `compute_market.copy_attests[(job_id, segment, round)]` holds the copy test's the same way,
/// round 0 for the committee (§3.3 "Copy test"). Borsh in field order.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SketchAttests {
    /// Each voter's attested hash (a juror's `sketch_hash`, or a committee member's or juror's
    /// `copy_hash`), one per voter.
    pub by: BTreeMap<WorkerId, Hash32>,
    /// The first body recorded for each attested hash.
    pub bodies: BTreeMap<Hash32, Sketch>,
}

/// `compute_market.disputes[(job_id, segment)]`: the open dispute of a segment (TOG-SPEC-0002
/// §7.2, TOG-SPEC-0003 §4). Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Dispute {
    /// 1 = R1, 2 = R2 (after `AppealTx`).
    pub round: u8,
    /// The executor's opponents: `players[0]` plays the bisection game and its dissent or
    /// challenge bond is locked; then the segment's other dissenters in commit order. At most
    /// `MaxVerifiers`. Jury eligibility rule 5 excludes every entry.
    pub players: Vec<WorkerId>,
    /// Micro-bisection (TOG-SPEC-0003 §4.5), `None` if not played.
    pub bisect: Option<Bisect>,
    /// The job's V3 sample randomness `ρ`.
    pub rho: Hash32,
    /// `fee_j` of TOG-SPEC-0003 §7, fixed when the dispute opens: R1 bond `21 · fee_j`, appeal
    /// bond `51 · fee_j`.
    pub fee_j: Amount,
    /// R1's verdict `(verdict, appeal_until)`, `appeal_until = h_v + T_appeal` being the last
    /// block that accepts an `AppealTx`; `None` before it and from the appeal on.
    pub verdict: Option<(R1Verdict, u64)>,
}

/// R1's verdict in [`Dispute::verdict`] (TOG-SPEC-0002 §7.2). Borsh index = position, so
/// `ExecutorLost` and `ExecutorWon` encode as the former `executor_won` bool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum R1Verdict {
    /// The executor lost R1: it may appeal.
    ExecutorLost,
    /// The executor won R1: the player may appeal.
    ExecutorWon,
    /// The jury disagreed with itself (TOG-SPEC-0003 §5.4): the executor or the player may
    /// appeal.
    Nondeterministic,
}

impl R1Verdict {
    /// Whether the executor won, for a decisive verdict.
    pub fn executor_won(self) -> Option<bool> {
        match self {
            Self::ExecutorLost => Some(false),
            Self::ExecutorWon => Some(true),
            Self::Nondeterministic => None,
        }
    }

    /// Whether `executor` (true) or the player (false) may appeal it (TOG-SPEC-0003 §4.6
    /// "Appeal", §5.4 "Appeal of a nondeterministic R1").
    pub fn appealable_by(self, executor: bool) -> bool {
        self.executor_won() != Some(executor)
    }
}

/// A micro-bisection game in [`Dispute`]. Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Bisect {
    /// Current `[start, end]` of sub-checkpoints.
    pub range: (u16, u16),
    /// The executor's plaintext roots of `start` and `end`.
    pub roots: (Hash32, Hash32),
    /// `midpoint(range)` while the game runs; `j` once it is over.
    pub mid: u16,
    /// `None`: the executor posts next; `Some`: the player answers.
    pub root_mid: Option<Hash32>,
    /// Last block for the move that is due (the sub-checkpoint upload once the game is over).
    pub deadline: u64,
}

impl Bisect {
    /// The agreed sub-step `j` once the game is over: juries re-run `j → j + 1` from the
    /// sub-checkpoint with root `roots.0`.
    pub fn located(&self) -> Option<u16> {
        (self.range.1 == self.range.0 + 1).then_some(self.range.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_game_is_located_once_its_range_is_one_sub_step() {
        let mut b = Bisect { range: (0, 8), roots: ([1; 32], [2; 32]), mid: 4, root_mid: None, deadline: 9 };
        assert_eq!(b.located(), None);
        b.range = (5, 6);
        assert_eq!(b.located(), Some(5));
        let d = Dispute {
            round: 1,
            players: vec![[3; 20]],
            bisect: Some(b),
            rho: [4; 32],
            fee_j: 5,
            verdict: Some((R1Verdict::ExecutorWon, 9)),
        };
        let bytes = borsh::to_vec(&d).unwrap();
        // round, players (u32 len + 20), Some, range, roots, mid, root_mid None, deadline, rho, fee_j,
        // Some, verdict, appeal_until.
        assert_eq!(bytes.len(), 1 + 4 + 20 + 1 + 4 + 64 + 2 + 1 + 8 + 32 + 16 + 1 + 1 + 8);
        assert_eq!(Dispute::try_from_slice(&bytes).unwrap(), d);
    }

    #[test]
    fn an_r1_verdict_reads_like_the_former_bool_and_nondeterministic_is_two() {
        for (old, new) in [(false, R1Verdict::ExecutorLost), (true, R1Verdict::ExecutorWon)] {
            assert_eq!(borsh::to_vec(&(old, 7u64)).unwrap(), borsh::to_vec(&(new, 7u64)).unwrap());
        }
        assert_eq!(borsh::to_vec(&R1Verdict::Nondeterministic).unwrap(), [2]);
        // Either side may appeal a nondeterministic R1, only the loser a decisive one.
        assert!(R1Verdict::Nondeterministic.appealable_by(true) && R1Verdict::Nondeterministic.appealable_by(false));
        assert!(R1Verdict::ExecutorLost.appealable_by(true) && !R1Verdict::ExecutorLost.appealable_by(false));
        assert!(!R1Verdict::ExecutorWon.appealable_by(true) && R1Verdict::ExecutorWon.appealable_by(false));
    }
}
