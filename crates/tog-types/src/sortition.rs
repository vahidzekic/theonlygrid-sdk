//! Worker weight, verifier sortition and public job assignment in exact integer arithmetic
//! (TOG-SPEC-0003 §3.2, TOG-SPEC-0001 §4.2 step 2).

use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Amount, Domain, Hash32, HubHeight};

use crate::worker::WorkerId;

/// Which draw of a sampled segment (TOG-SPEC-0003 §3.2). Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum DrawKind {
    /// Verifier draw: 0 at V3, 1 for the second draw.
    Verify {
        /// Draw number.
        draw: u8,
    },
    /// Jury draw of round 1 (R1) or 2 (R2).
    Jury {
        /// Round.
        round: u8,
    },
}

impl DrawKind {
    /// The `SignTx.slot` of this draw's `VerifierCommit` and `VerifierReveal` (TOG-SPEC-0001 §1.1):
    /// the draw number, or `0x100 + round` for a juror.
    pub fn signer_slot(self) -> u64 {
        match self {
            DrawKind::Verify { draw } => u64::from(draw),
            DrawKind::Jury { round } => 0x100 + u64::from(round),
        }
    }
}

/// `compute_market.draws[(job_id, segment, kind)]` value (TOG-SPEC-0003 §3.2). Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SortitionDraw {
    /// `ρ` of this draw.
    pub seed: Hash32,
    /// `W`.
    pub total_weight: u128,
    /// `r`, or the jury size.
    pub target: u16,
    /// Snapshot height: eligibility and `weight_w` are read from state at its start.
    pub height: HubHeight,
    /// Last height a selected worker may commit.
    pub commit_deadline: HubHeight,
    /// §4.4's cross-bucket fallback is in force for this job: eligibility rule 3 is dropped.
    /// Decided at the V3 snapshot (`BitwiseSameArch` only) and copied into every later draw.
    pub cross_bucket: bool,
}

/// `compute_market.params` value (TOG-SPEC-0002 §7.2). Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ComputeParams {
    /// `μ_cap` in days.
    pub mu_cap_days: u32,
    /// R2 jury reputation floor (TOG-SPEC-0003 §4.1).
    pub r2_min_reputation: u32,
    /// `B_min`: minimum bucket weight in atto-TOG (TOG-SPEC-0003 §4.4).
    pub bucket_min_weight: u128,
    /// Lowest `challenge_window_blocks` a job may set: [`crate::admission::W_OPT_MIN`] on
    /// testnet and mainnet, a few blocks on devnet (TOG-SPEC-0003 §10).
    pub w_opt_min: u32,
    /// Job locators may use `http://`: `false` on testnet and mainnet, set only in a devnet
    /// genesis (TOG-SPEC-0001 §2.3, §3.4).
    pub http_locators: bool,
    /// `κ` of the worker base bond in hours (TOG-SPEC-0001 §4.2.1 rule 1): 24 at genesis.
    pub kappa_hours: u32,
}

/// `μ_cap`: the weight cap in days of full-capacity revenue (TOG-SPEC-0005 §10).
pub const DEFAULT_MU_CAP_DAYS: u128 = 4;

/// `κ` of the worker base bond in hours at genesis (TOG-SPEC-0001 §4.2.1 rule 1).
pub const DEFAULT_KAPPA_HOURS: u32 = 24;

/// `weight_w = min(bond_w, 24 · μ_cap · verified_wu_per_hour_w · P_ref)`, saturating. A worker
/// without a passed calibration (`verified_wu_per_hour = 0`) has weight 0.
pub fn weight(bond: Amount, verified_wu_per_hour: u64, p_ref: Amount, mu_cap_days: u128) -> Amount {
    let cap = (24 * mu_cap_days).saturating_mul(u128::from(verified_wu_per_hour)).saturating_mul(p_ref);
    bond.min(cap)
}

/// Selection test `y · W < min(r · weight, W) · 2^256`, evaluated exactly. `y` is the first 32
/// bytes of the VRF output β, big-endian. A worker with weight 0, or an empty pool, is never selected.
pub fn is_selected(y: &[u8; 32], weight: Amount, total_weight: Amount, target: u16) -> bool {
    if weight == 0 || total_weight == 0 {
        return false;
    }
    let m = weight.checked_mul(u128::from(target)).map_or(total_weight, |rw| rw.min(total_weight));
    // m · 2^256 has zero low 256 bits, so the comparison is `⌊y · W / 2^256⌋ < m`.
    high_128(y, total_weight) < m
}

/// `⌊y · w / 2^256⌋` for a 256-bit big-endian `y`; the result fits in 128 bits.
fn high_128(y: &[u8; 32], w: u128) -> u128 {
    // Little-endian u64 limbs.
    let a: [u64; 4] = core::array::from_fn(|i| u64::from_be_bytes(y[24 - 8 * i..32 - 8 * i].try_into().unwrap()));
    let b = [w as u64, (w >> 64) as u64];
    let mut p = [0u64; 6];
    for (i, &ai) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &bj) in b.iter().enumerate() {
            let t = u128::from(ai) * u128::from(bj) + u128::from(p[i + j]) + carry;
            p[i + j] = t as u64;
            carry = t >> 64;
        }
        p[i + 2] = carry as u64;
    }
    u128::from(p[4]) | (u128::from(p[5]) << 64)
}

/// `u256_be(bytes) mod m` for `m > 0`.
fn mod_u128(bytes: &[u8; 32], m: u128) -> u128 {
    let mut acc = 0u128;
    for byte in bytes {
        for k in (0..8).rev() {
            // acc < m; compute (2·acc + bit) mod m without overflow.
            let d = m - acc;
            acc = if acc >= d { acc - d } else { acc * 2 };
            if byte >> k & 1 == 1 {
                acc = if acc == m - 1 { 0 } else { acc + 1 };
            }
        }
    }
    acc
}

/// Public assignment draw (TOG-SPEC-0001 §4.2 step 2). `candidates` are `(worker, weight)`; they are
/// sorted by `WorkerId` here, `x = u256_be(H("TOG/v1/assign" ‖ beacon ‖ job_id)) mod W`, and the
/// winner is the candidate whose cumulative interval contains `x`. `None` when `W = 0`.
pub fn assign(beacon: &Hash32, job_id: &Hash32, candidates: &[(WorkerId, Amount)]) -> Option<WorkerId> {
    draw(Domain::Assign, beacon, job_id, candidates)
}

/// A reservation's worker (TOG-SPEC-0015 §3): as [`assign`], with
/// `x = u256_be(H("TOG/v1/reserve" ‖ beacon ‖ u64_le(id))) mod W`.
pub fn reserve(beacon: &Hash32, id: u64, candidates: &[(WorkerId, Amount)]) -> Option<WorkerId> {
    draw(Domain::Reserve, beacon, &id.to_le_bytes(), candidates)
}

fn draw(domain: Domain, beacon: &Hash32, subject: &[u8], candidates: &[(WorkerId, Amount)]) -> Option<WorkerId> {
    let mut sorted = candidates.to_vec();
    sorted.sort_unstable_by_key(|(id, _)| *id);
    let total = sorted.iter().try_fold(0u128, |acc, (_, w)| acc.checked_add(*w))?;
    if total == 0 {
        return None;
    }
    let mut x = mod_u128(&tagged_hash(domain, &[beacon, subject]), total);
    for (id, w) in sorted {
        if x < w {
            return Some(id);
        }
        x -= w;
    }
    unreachable!("x < W")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draw_slots() {
        assert_eq!(DrawKind::Verify { draw: 0 }.signer_slot(), 0);
        assert_eq!(DrawKind::Verify { draw: 1 }.signer_slot(), 1);
        assert_eq!(DrawKind::Jury { round: 2 }.signer_slot(), 0x102);
        assert_eq!(borsh::to_vec(&DrawKind::Jury { round: 1 }).unwrap(), [1, 1]);
    }

    #[test]
    fn appended_fields_are_last() {
        let d = SortitionDraw {
            seed: [0; 32],
            total_weight: 0,
            target: 0,
            height: 0,
            commit_deadline: 0,
            cross_bucket: true,
        };
        let b = borsh::to_vec(&d).unwrap();
        assert_eq!((b.len(), b[b.len() - 1]), (32 + 16 + 2 + 8 + 8 + 1, 1));
        let p = ComputeParams {
            mu_cap_days: 4,
            r2_min_reputation: 60,
            bucket_min_weight: 7,
            w_opt_min: 1_800,
            http_locators: true,
            kappa_hours: 24,
        };
        let b = borsh::to_vec(&p).unwrap();
        assert_eq!(
            (&b[8..24], &b[24..28], &b[28..29], &b[29..]),
            (&7u128.to_le_bytes()[..], &1_800u32.to_le_bytes()[..], &[1u8][..], &24u32.to_le_bytes()[..])
        );
    }

    fn y_from(v: u128, shift_bytes: usize) -> [u8; 32] {
        let mut y = [0u8; 32];
        y[32 - 16 - shift_bytes..32 - shift_bytes].copy_from_slice(&v.to_be_bytes());
        y
    }

    #[test]
    fn weight_is_capped_and_saturates() {
        assert_eq!(weight(1_000, 0, 5, 4), 0);
        assert_eq!(weight(1_000, 2, 5, 4), 24 * 4 * 2 * 5);
        assert_eq!(weight(100, 2, 5, 4), 100);
        assert_eq!(weight(Amount::MAX, u64::MAX, Amount::MAX, 4), Amount::MAX);
    }

    #[test]
    fn high_part_is_exact() {
        // y = 2^255, w = 6 → ⌊2^255 · 6 / 2^256⌋ = 3.
        let mut y = [0u8; 32];
        y[0] = 0x80;
        assert_eq!(high_128(&y, 6), 3);
        // y = 2^256 − 1, w = u128::MAX → ⌊(2^256 − 1)(2^128 − 1) / 2^256⌋ = 2^128 − 2.
        assert_eq!(high_128(&[0xFF; 32], u128::MAX), u128::MAX - 1);
        // Small y: high part is 0.
        assert_eq!(high_128(&y_from(12345, 0), u128::MAX), 0);
    }

    #[test]
    fn selection_threshold() {
        // W = 100, w = 10, r = 3: selected iff y / 2^256 < 30 / 100.
        let (w, total) = (10, 100);
        let mut just_below = [0u8; 32];
        just_below[0] = 0x4C; // 0x4C / 256 = 0.296875 < 0.3
        let mut just_above = [0u8; 32];
        just_above[0] = 0x4D; // 0.30078125 > 0.3
        assert!(is_selected(&just_below, w, total, 3));
        assert!(!is_selected(&just_above, w, total, 3));
        // r · w ≥ W: always selected.
        assert!(is_selected(&[0xFF; 32], 50, 100, 3));
        assert!(!is_selected(&[0; 32], 0, 100, 3));
        assert!(!is_selected(&[0; 32], 10, 0, 3));
        // No overflow at the extremes.
        assert!(is_selected(&[0; 32], Amount::MAX, Amount::MAX, 7));
    }

    #[test]
    fn modulo_matches_small_cases() {
        let b = y_from(1_000_003, 0);
        assert_eq!(mod_u128(&b, 97), 1_000_003 % 97);
        let b = y_from(u128::MAX, 0);
        assert_eq!(mod_u128(&b, u128::MAX), 0);
        assert_eq!(mod_u128(&b, (1 << 127) + 1), u128::MAX % ((1 << 127) + 1));
        // 2^128 mod (2^128 − 1) = 1.
        assert_eq!(mod_u128(&y_from(1, 16), u128::MAX), 1);
    }

    #[test]
    fn assignment_is_order_independent_and_weighted() {
        let cands = [([3u8; 20], 1u128), ([1u8; 20], 0), ([2u8; 20], 5)];
        let mut rev = cands;
        rev.reverse();
        let beacon = [9; 32];
        let mut wins = [0u32; 4];
        for j in 0..600u32 {
            let mut job = [0u8; 32];
            job[..4].copy_from_slice(&j.to_le_bytes());
            let a = assign(&beacon, &job, &cands).unwrap();
            assert_eq!(Some(a), assign(&beacon, &job, &rev));
            wins[a[0] as usize] += 1;
        }
        assert_eq!(wins[1], 0, "weight 0 never wins");
        assert!(wins[2] > 3 * wins[3], "weight 5 beats weight 1: {wins:?}");
        assert_eq!(assign(&beacon, &[0; 32], &[([1; 20], 0)]), None);
    }
}
