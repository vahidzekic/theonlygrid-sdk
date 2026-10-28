//! Verifier transactions (TOG-SPEC-0003 §2, §3.2–3.3), `TxBody` variants 7 and 8.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Domain, Hash32};

use crate::checkpoint::Sketch;
use crate::payload::PayloadCommitment;

/// ECVRF-EDWARDS25519-SHA512-TAI proof (RFC 9381, suite 0x03): Γ (32 B) ‖ c (16 B) ‖ s (32 B)
/// (TOG-SPEC-0001 §3.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VrfProof(pub [u8; 80]);

impl VrfProof {
    /// Proves `alpha` under the VRF secret seed (see [`tog_primitives::ecvrf`], unaudited).
    pub fn prove(seed: &[u8; 32], alpha: &[u8]) -> Self {
        VrfProof(tog_primitives::ecvrf::prove(seed, alpha))
    }

    /// Verifies the proof for `alpha` under a registered `vrf_key` and returns its output.
    pub fn verify(&self, vrf_key: &[u8; 32], alpha: &[u8]) -> Option<VrfOutput> {
        tog_primitives::ecvrf::verify(vrf_key, alpha, &self.0).map(|beta| VrfOutput::from_beta(&beta))
    }
}

/// Sortition VRF input `"TOG/v1/verify" ‖ w ‖ job_id ‖ u32 n ‖ ρ` (TOG-SPEC-0003 §3.2), `w` the
/// evaluating worker's `WorkerId`, so two workers' outputs are independent even under one secret
/// (TOG-SPEC-0001 §3.2 "VRF key uniqueness").
///
/// This is the ECVRF alpha string itself, not a BLAKE3 hash: the tag is a plain prefix.
pub fn sortition_input(worker: &Address, job_id: &Hash32, segment: u32, rho: &Hash32) -> Vec<u8> {
    let tag = Domain::Verify.tag().as_bytes();
    let mut alpha = Vec::with_capacity(tag.len() + 20 + 32 + 4 + 32);
    alpha.extend_from_slice(tag);
    alpha.extend_from_slice(worker);
    alpha.extend_from_slice(job_id);
    alpha.extend_from_slice(&segment.to_le_bytes());
    alpha.extend_from_slice(rho);
    alpha
}

/// The two halves of a VRF output β (64 B).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrfOutput {
    /// `y`: first 32 bytes, read as a big-endian u256 in the selection test.
    pub y: [u8; 32],
    /// `salt_v`: last 32 bytes, salts the vote tree (TOG-SPEC-0003 §3.3).
    pub salt_v: [u8; 32],
}

impl VrfOutput {
    /// Splits β.
    pub fn from_beta(beta: &[u8; 64]) -> Self {
        let mut y = [0; 32];
        let mut salt_v = [0; 32];
        y.copy_from_slice(&beta[..32]);
        salt_v.copy_from_slice(&beta[32..]);
        VrfOutput { y, salt_v }
    }
}

/// `H("TOG/v1/sketch" ‖ borsh(sketch))`; `None` hashes as the single byte `0x00`.
pub fn sketch_hash(sketch: &Option<Sketch>) -> Hash32 {
    tagged_hash(Domain::Sketch, &[&borsh::to_vec(sketch).expect("in-memory borsh cannot fail")])
}

/// `H("TOG/v1/vote-commit" ‖ vote_root ‖ metrics_hash ‖ H(sketch))` (TOG-SPEC-0003 §3.3).
pub fn output_commitment(vote_root: &Hash32, metrics_hash: &Hash32, sketch: &Option<Sketch>) -> Hash32 {
    tagged_hash(Domain::VoteCommit, &[vote_root, metrics_hash, &sketch_hash(sketch)])
}

/// `fault_root(c) = H("TOG/v1/fault" ‖ i32_le c)`: `own_vote_root` and `own_plaintext_root` of a
/// fault vote, cast when the checker's run of a segment fails with exit status `c` (TOG-SPEC-0003
/// §3.6). Its `own_metrics` is `[0; 32]` and it has no sketch.
pub fn fault_root(exit_status: i32) -> Hash32 {
    tagged_hash(Domain::Fault, &[&exit_status.to_le_bytes()])
}

/// Step V5: a selected verifier commits to its own re-run of segment `n`. Signed by the worker key.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VerifierCommit {
    /// Job.
    pub job_id: Hash32,
    /// Verified segment.
    pub segment: u32,
    /// Proves this worker was selected, under its registered `vrf_key`.
    pub sortition_proof: VrfProof,
    /// See [`output_commitment`].
    pub output_commitment: Hash32,
}

/// Step V7: opens the commitment after the executor released `k_n`. Signed by the worker key.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VerifierReveal {
    /// Job.
    pub job_id: Hash32,
    /// Verified segment.
    pub segment: u32,
    /// Root of the salted vote tree.
    pub own_vote_root: Hash32,
    /// BLAKE3 root of the verifier's own `ckpt_n`.
    pub own_plaintext_root: Hash32,
    /// `H("TOG/v1/metrics" ‖ metrics)` of the verifier's run.
    pub own_metrics: Hash32,
    /// Tolerance class only.
    pub own_sketch: Option<Sketch>,
    /// Optional on any vote and never read by the tally or a verdict: a hint for jurors, in an
    /// `Account` deal the verifier pays for (TOG-SPEC-0003 §2, §4.6).
    pub own_output_locator: Option<PayloadCommitment>,
}

impl VerifierReveal {
    /// Whether this reveal opens `commit`; one that doesn't counts as a non-reveal (TOG-SPEC-0003 §3.3).
    pub fn opens(&self, commit: &VerifierCommit) -> bool {
        self.job_id == commit.job_id
            && self.segment == commit.segment
            && output_commitment(&self.own_vote_root, &self.own_metrics, &self.own_sketch) == commit.output_commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::TensorSketch;

    fn reveal(sketch: Option<Sketch>) -> VerifierReveal {
        VerifierReveal {
            job_id: [1; 32],
            segment: 3,
            own_vote_root: [2; 32],
            own_plaintext_root: [3; 32],
            own_metrics: [4; 32],
            own_sketch: sketch,
            own_output_locator: None,
        }
    }

    fn commit_for(r: &VerifierReveal) -> VerifierCommit {
        VerifierCommit {
            job_id: r.job_id,
            segment: r.segment,
            sortition_proof: VrfProof([0; 80]),
            output_commitment: output_commitment(&r.own_vote_root, &r.own_metrics, &r.own_sketch),
        }
    }

    #[test]
    fn reveal_opens_its_commitment() {
        let r = reveal(None);
        let c = commit_for(&r);
        assert!(r.opens(&c));
        // The plaintext root is not in the commitment; the Hub compares it separately.
        assert!(VerifierReveal { own_plaintext_root: [9; 32], ..r.clone() }.opens(&c));
        assert!(!VerifierReveal { own_metrics: [9; 32], ..r.clone() }.opens(&c));
        assert!(!VerifierReveal { segment: 4, ..r }.opens(&c));
    }

    #[test]
    fn sketch_is_bound() {
        let sketch = Sketch { tensors: vec![TensorSketch { name: "w".into(), projection: vec![1], norm: 1 }] };
        let c = commit_for(&reveal(Some(sketch)));
        assert!(!reveal(None).opens(&c));
        assert_eq!(sketch_hash(&None), tagged_hash(Domain::Sketch, &[&[0]]));
    }

    #[test]
    fn vrf_output_halves() {
        let mut beta = [0u8; 64];
        beta[0] = 0xAA;
        beta[63] = 0xBB;
        let out = VrfOutput::from_beta(&beta);
        assert_eq!((out.y[0], out.salt_v[31]), (0xAA, 0xBB));
    }

    #[test]
    fn sortition_input_layout() {
        let alpha = sortition_input(&[4; 20], &[1; 32], 2, &[3; 32]);
        assert_eq!(alpha.len(), "TOG/v1/verify".len() + 88);
        assert!(alpha.starts_with(b"TOG/v1/verify"));
        assert_eq!((&alpha[13..33], &alpha[33..65]), (&[4; 20][..], &[1; 32][..]));
        assert_eq!(&alpha[65..69], &2u32.to_le_bytes());
        assert_ne!(alpha, sortition_input(&[5; 20], &[1; 32], 2, &[3; 32]));
    }

    #[test]
    fn sortition_proof_roundtrip() {
        let seed = [9u8; 32];
        let key = tog_primitives::ecvrf::public_key(&seed);
        let alpha = sortition_input(&[4; 20], &[1; 32], 2, &[3; 32]);
        let proof = VrfProof::prove(&seed, &alpha);
        let out = proof.verify(&key, &alpha).unwrap();
        assert!(proof.verify(&key, &sortition_input(&[4; 20], &[1; 32], 3, &[3; 32])).is_none());
        assert_ne!(out.y, out.salt_v);
    }

    #[test]
    fn fault_root_binds_the_signed_code() {
        assert_eq!(fault_root(-6), tagged_hash(Domain::Fault, &[&(-6i32).to_le_bytes()]));
        assert_ne!(fault_root(-6), fault_root(6));
        assert_ne!(fault_root(0), fault_root(1));
    }

    #[test]
    fn proof_is_80_bytes() {
        assert_eq!(borsh::to_vec(&VrfProof([0; 80])).unwrap().len(), 80);
    }
}
