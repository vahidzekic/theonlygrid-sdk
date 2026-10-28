//! Protocol time constants in Hub blocks (2 s) that both the Hub and `togd` need, and the
//! deterministic heights derived from them.

use tog_primitives::Amount;

use crate::job::JobTx;

/// `N_claim`: blocks after assignment in which `ClaimJob` is valid, `at < h ≤ at + N_claim`
/// (TOG-SPEC-0001 §4.2 step 3, TOG-SPEC-0003 §10).
pub const N_CLAIM: u64 = 10;
/// `R_reveal`: blocks between `CommitResult` and the earliest `RevealResult` (TOG-SPEC-0003 §3.1).
pub const R_REVEAL: u64 = 5;
/// `D_beacon`: a draw ordered in block `h` uses `HubBeacon(h + D_beacon)` (TOG-SPEC-0002 §3.2).
pub const D_BEACON: u64 = 3;
/// `T_keys`: blocks to release a segment's keys (TOG-SPEC-0003 §10).
pub const T_KEYS: u64 = 150;
/// `T_reveal`: blocks for verifier reveals (TOG-SPEC-0003 §10).
pub const T_REVEAL: u64 = 150;
/// `T_audit` (TOG-SPEC-0003 §10).
pub use crate::audit::T_AUDIT;
/// `W_opt`: challenge window after passing, 1 h (TOG-SPEC-0003 §10).
pub const W_OPT: u64 = 1_800;
/// `G_release`: blocks after a job ends before its deals close (TOG-SPEC-0004 §4.7).
pub const G_RELEASE: u64 = 150;
/// `L_fetch`: fixed part of a segment's fetch allowance in blocks (TOG-SPEC-0003 §7.4).
pub const L_FETCH: u64 = 150;
/// `B_fetch`: fetch rate the allowance assumes, in bit/s (TOG-SPEC-0003 §7.4).
pub const B_FETCH: u128 = 800_000_000;

/// `claim_miss_penalty = ⌈B_min / 100⌉`: what a worker that let its claim window lapse pays into
/// the job's escrow, before the cap at its free bond (TOG-SPEC-0001 §4.2 step 3).
pub fn claim_miss_penalty(b_min: Amount) -> Amount {
    b_min.div_ceil(100)
}

/// `max_end` of a job's `ChallengeWindow` deals (TOG-SPEC-0004 §4.7): the height its deals are
/// paid until on the normal path. In `u128` with each `⌈⌉` on its own; saturates at `u64::MAX`.
///
/// ```text
/// F       = L_fetch + ⌈8·(C + I) / (B_fetch·2)⌉
/// V       = R_reveal + D_beacon + 1 + M·(T_keys + F) + ⌈3·max_wall_time_secs / 4⌉ + T_reveal + T_audit + W_opt
/// max_end = claim_deadline_height + ⌈max_wall_time_secs / 2⌉ + V + G_release
/// ```
///
/// `M = max_segments` (1 unsegmented), `I = Σ inputs content.size`, `C = checkpoint_max_bytes`
/// (0 unsegmented).
pub fn max_end(job: &JobTx) -> u64 {
    let spec = &job.spec;
    let (m, c) =
        spec.segmentation.as_ref().map_or((1, 0), |s| (u128::from(s.max_segments), u128::from(s.checkpoint_max_bytes)));
    let i: u128 = spec.inputs.iter().map(|r| u128::from(r.content.payload.size)).sum();
    let wall = u128::from(spec.limits.max_wall_time_secs);
    let f = u128::from(L_FETCH) + (8 * (c + i)).div_ceil(B_FETCH * 2);
    let v = u128::from(R_REVEAL + D_BEACON + 1)
        + m * (u128::from(T_KEYS) + f)
        + (3 * wall).div_ceil(4)
        + u128::from(T_REVEAL + T_AUDIT + W_OPT);
    let end = u128::from(spec.fee.claim_deadline_height) + wall.div_ceil(2) + v + u128::from(G_RELEASE);
    u64::try_from(end).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::sample_job;

    #[test]
    fn max_end_follows_the_formula() {
        let mut job = sample_job();
        job.spec.fee.claim_deadline_height = 1_000;
        job.spec.limits.max_wall_time_secs = 3_601;
        let seg = job.spec.segmentation.as_mut().unwrap();
        seg.max_segments = 4;
        seg.checkpoint_max_bytes = 1_000_000_000;
        let inputs: u128 = job.spec.inputs.iter().map(|r| u128::from(r.content.payload.size)).sum();
        // F = 150 + ⌈8·(1e9 + I) / 1.6e9⌉
        let f = 150 + (8 * (1_000_000_000 + inputs)).div_ceil(1_600_000_000);
        let v = 5 + 3 + 1 + 4 * (150 + f) + 2_701 + 150 + 150 + 1_800;
        assert_eq!(u128::from(max_end(&job)), 1_000 + 1_801 + v + 150);

        // Unsegmented: one segment, no checkpoints.
        job.spec.segmentation = None;
        job.spec.inputs.clear();
        job.spec.limits.max_wall_time_secs = 0;
        assert_eq!(max_end(&job), 1_000 + (5 + 3 + 1 + 150 + 150 + 150 + 150 + 1_800) + 150);
        job.spec.fee.claim_deadline_height = u64::MAX;
        assert_eq!(max_end(&job), u64::MAX);
    }

    #[test]
    fn claim_miss_penalty_rounds_up() {
        assert_eq!(claim_miss_penalty(0), 0);
        assert_eq!(claim_miss_penalty(1), 1);
        assert_eq!(claim_miss_penalty(1_000), 10);
        assert_eq!(claim_miss_penalty(1_001), 11);
    }
}
