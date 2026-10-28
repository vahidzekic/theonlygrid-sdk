//! Micro-bisection of a disputed segment (TOG-SPEC-0003 §4.5), as a pure state machine.
//!
//! Sub-checkpoint 0 is `ckpt_{n−1}` (both sides agree) and sub-checkpoint `substeps` is `ckpt_n`
//! (they disagree). Each round the executor posts the plaintext root of the midpoint and the
//! dissenter agrees or disagrees with it, halving the range until one sub-step `j → j + 1` is left.

use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::Hash32;

/// Blocks per move (`T_bisect`).
pub const T_BISECT_BLOCKS: u64 = 150;

/// The executor's root of sub-checkpoint `mid`, `TxBody` variant 14. Signed by the executor's worker key.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BisectPostTx {
    /// Job.
    pub job_id: Hash32,
    /// Disputed segment.
    pub segment: u32,
    /// Must equal the game's current midpoint.
    pub mid: u16,
    /// `plaintext_root` of the executor's sub-checkpoint `mid` (4 KiB chunk tree, as for `ckpt_n`).
    pub root: Hash32,
}

/// Agree or disagree with the posted root, `TxBody` variant 15. Signed by the worker key of the
/// dissenter or challenger that plays the game.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BisectAnswerTx {
    /// Job.
    pub job_id: Hash32,
    /// Disputed segment.
    pub segment: u32,
    /// The midpoint being answered; accepted only after the matching [`BisectPostTx`].
    pub mid: u16,
    /// Whether the player's own sub-checkpoint `mid` has the posted root.
    pub agree: bool,
}

/// The dissenter's answer to a posted midpoint root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Its own sub-checkpoint at `mid` has the same root.
    Agree,
    /// It differs.
    Disagree,
}

/// Whose move it is, or how the game ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Phase {
    /// The executor must post the root of sub-checkpoint `mid`.
    ExecutorPosts {
        /// Midpoint.
        mid: u16,
    },
    /// The dissenter must answer the posted root.
    DissenterAnswers {
        /// Midpoint.
        mid: u16,
        /// Root the executor posted.
        root: Hash32,
    },
    /// Narrowed to sub-step `j → j + 1`: both agree on `j` (with root `agreed_root`) and disagree on `j + 1`.
    Located {
        /// Sub-step index.
        j: u16,
        /// Root of sub-checkpoint `j` both sides agree on; the executor uploads that sub-checkpoint.
        agreed_root: Option<Hash32>,
    },
}

/// Why a move is rejected.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BisectionError {
    /// `substeps` is not a power of two in `2..=64`.
    #[error("substeps must be a power of two in 2..=64")]
    Substeps,
    /// Not this side's turn, or the game is over.
    #[error("move out of turn")]
    OutOfTurn,
    /// The transaction names a different midpoint than the game's current one.
    #[error("wrong midpoint {0}")]
    WrongMid(u16),
}

/// One bisection game between the executor and the first dissenter of a segment.
/// Borsh in field order: the Hub keeps open games in state.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Bisection {
    start: u16,
    end: u16,
    /// Root of sub-checkpoint `start` once it came from an agreed midpoint; `None` while it is
    /// still `ckpt_{n−1}`, whose root is already on-chain.
    start_root: Option<Hash32>,
    phase: Phase,
}

impl Bisection {
    /// A new game over `substeps` sub-steps.
    pub fn new(substeps: u16) -> Result<Self, BisectionError> {
        if !substeps.is_power_of_two() || !(2..=64).contains(&substeps) {
            return Err(BisectionError::Substeps);
        }
        Ok(Self { start: 0, end: substeps, start_root: None, phase: Phase::ExecutorPosts { mid: substeps / 2 } })
    }

    /// Current phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The executor posts the root of sub-checkpoint `mid`.
    pub fn executor_posts(&mut self, root: Hash32) -> Result<Phase, BisectionError> {
        let Phase::ExecutorPosts { mid } = self.phase else { return Err(BisectionError::OutOfTurn) };
        self.phase = Phase::DissenterAnswers { mid, root };
        Ok(self.phase)
    }

    /// The dissenter answers the posted root.
    pub fn dissenter_answers(&mut self, answer: Answer) -> Result<Phase, BisectionError> {
        let Phase::DissenterAnswers { mid, root } = self.phase else { return Err(BisectionError::OutOfTurn) };
        match answer {
            Answer::Agree => {
                self.start = mid;
                self.start_root = Some(root);
            }
            Answer::Disagree => self.end = mid,
        }
        self.phase = if self.end - self.start == 1 {
            Phase::Located { j: self.start, agreed_root: self.start_root }
        } else {
            Phase::ExecutorPosts { mid: self.start + (self.end - self.start) / 2 }
        };
        Ok(self.phase)
    }

    /// Applies a [`BisectPostTx`] whose `job_id`, `segment` and signer the caller already matched.
    pub fn apply_post(&mut self, tx: &BisectPostTx) -> Result<Phase, BisectionError> {
        match self.phase {
            Phase::ExecutorPosts { mid } if mid != tx.mid => Err(BisectionError::WrongMid(tx.mid)),
            _ => self.executor_posts(tx.root),
        }
    }

    /// Applies a [`BisectAnswerTx`] whose `job_id`, `segment` and signer the caller already matched.
    pub fn apply_answer(&mut self, tx: &BisectAnswerTx) -> Result<Phase, BisectionError> {
        match self.phase {
            Phase::DissenterAnswers { mid, .. } if mid != tx.mid => Err(BisectionError::WrongMid(tx.mid)),
            _ => self.dissenter_answers(if tx.agree { Answer::Agree } else { Answer::Disagree }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plays a game where the two runs part between sub-checkpoints `diverge − 1` and `diverge`.
    fn play(substeps: u16, diverge: u16) -> (Phase, usize) {
        let mut g = Bisection::new(substeps).unwrap();
        let mut rounds = 0;
        loop {
            match g.phase() {
                Phase::ExecutorPosts { mid } => {
                    g.executor_posts([mid as u8; 32]).unwrap();
                }
                Phase::DissenterAnswers { mid, .. } => {
                    rounds += 1;
                    let a = if mid < diverge { Answer::Agree } else { Answer::Disagree };
                    g.dissenter_answers(a).unwrap();
                }
                done @ Phase::Located { .. } => return (done, rounds),
            }
        }
    }

    #[test]
    fn locates_every_divergence_in_log2_rounds() {
        for substeps in [2u16, 4, 8, 64] {
            for diverge in 1..=substeps {
                let (phase, rounds) = play(substeps, diverge);
                let j = diverge - 1;
                let agreed_root = (j > 0).then_some([j as u8; 32]);
                assert_eq!(phase, Phase::Located { j, agreed_root });
                assert_eq!(rounds, substeps.trailing_zeros() as usize);
            }
        }
    }

    #[test]
    fn a_game_in_progress_survives_borsh() {
        let mut g = Bisection::new(8).unwrap();
        g.executor_posts([4; 32]).unwrap();
        g.dissenter_answers(Answer::Agree).unwrap();
        let back: Bisection = borsh::from_slice(&borsh::to_vec(&g).unwrap()).unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn rejects_bad_setup_and_out_of_turn_moves() {
        assert_eq!(Bisection::new(0), Err(BisectionError::Substeps));
        assert_eq!(Bisection::new(1), Err(BisectionError::Substeps));
        assert_eq!(Bisection::new(12), Err(BisectionError::Substeps));
        assert_eq!(Bisection::new(128), Err(BisectionError::Substeps));
        let mut g = Bisection::new(4).unwrap();
        assert_eq!(g.dissenter_answers(Answer::Agree), Err(BisectionError::OutOfTurn));
        g.executor_posts([0; 32]).unwrap();
        assert_eq!(g.executor_posts([0; 32]), Err(BisectionError::OutOfTurn));
    }

    #[test]
    fn transactions_drive_the_game() {
        let mut g = Bisection::new(4).unwrap();
        let post = |mid, root| BisectPostTx { job_id: [1; 32], segment: 2, mid, root };
        let answer = |mid, agree| BisectAnswerTx { job_id: [1; 32], segment: 2, mid, agree };
        assert_eq!(g.apply_post(&post(1, [7; 32])), Err(BisectionError::WrongMid(1)));
        g.apply_post(&post(2, [7; 32])).unwrap();
        assert_eq!(g.apply_answer(&answer(1, true)), Err(BisectionError::WrongMid(1)));
        assert_eq!(g.apply_answer(&answer(2, true)), Ok(Phase::ExecutorPosts { mid: 3 }));
        g.apply_post(&post(3, [8; 32])).unwrap();
        assert_eq!(g.apply_answer(&answer(3, false)), Ok(Phase::Located { j: 2, agreed_root: Some([7; 32]) }));
        assert_eq!(g.apply_post(&post(3, [8; 32])), Err(BisectionError::OutOfTurn));
    }

    #[test]
    fn tx_variants_14_and_15() {
        let first = |b: crate::TxBody| borsh::to_vec(&b).unwrap()[0];
        let post = BisectPostTx { job_id: [0; 32], segment: 0, mid: 1, root: [0; 32] };
        assert_eq!(first(crate::TxBody::BisectPost(post)), 14);
        let answer = BisectAnswerTx { job_id: [0; 32], segment: 0, mid: 1, agree: true };
        assert_eq!(first(crate::TxBody::BisectAnswer(answer)), 15);
    }
}
