//! Checkpoint commitments (TOG-SPEC-0001 §4.2 step 6, TOG-SPEC-0003 §2).

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Domain, Hash32};

use crate::payload::{Encryption, PayloadCommitment, PayloadKind};

/// Checkpoints always travel in 4 MiB pieces (TOG-SPEC-0003 §2).
pub const CHECKPOINT_PIECE_LOG2: u8 = 22;

/// Symmetric key `k_n` that encrypts checkpoint `n`. Held by the executor until
/// its release at V4 / V6. Wiped from memory when dropped; a copy of the bytes taken out of it
/// is not.
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CheckpointKey(pub [u8; 32]);

impl CheckpointKey {
    /// `key_commitment = H("TOG/v1/ckpt-key" ‖ k_n)`.
    pub fn commitment(&self) -> Hash32 {
        tagged_hash(Domain::CheckpointKey, &[&self.0])
    }
}

impl Drop for CheckpointKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl core::fmt::Debug for CheckpointKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CheckpointKey(..)")
    }
}

/// Published by the executor with `CommitResult` for every segment.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CheckpointCommitment {
    /// Segment index.
    pub segment: u32,
    /// Payload root of `ckpt_n` (goes into `S_n`).
    pub plaintext_root: Hash32,
    /// Payload root of `Enc(k_n, ckpt_n)`, what storage workers pin.
    pub ciphertext_root: Hash32,
    /// `H("TOG/v1/ckpt-key" ‖ k_n)`.
    pub key_commitment: Hash32,
    /// Ciphertext bytes.
    pub size: u64,
    /// `H("TOG/v1/metrics" ‖ metrics_n)`, the value in `S_n`; the tally compares it for every job.
    pub metrics_hash: Hash32,
    /// `Tolerance` jobs only; `None` at commit, recorded from the V6 key release.
    pub sketch: Option<Sketch>,
    /// `CheckerOnly` jobs only, set at V1 (TOG-SPEC-0003 §5.3); `None` otherwise.
    pub checker: Option<CheckerResult>,
}

/// `S_m` of the segment chain over `checkpoints` (segments `0..=m`, in order), `S_{-1}` when empty:
/// what `ExecutionReceipt.segment_root` must be (TOG-SPEC-0001 §4.2 step 6, §5.3). `None` if a
/// segment is out of order.
pub fn segment_root(job_id: &Hash32, checkpoints: &[CheckpointCommitment]) -> Option<Hash32> {
    let mut head = tog_primitives::segment::segment_genesis(job_id);
    for (n, c) in (0u32..).zip(checkpoints) {
        if c.segment != n {
            return None;
        }
        head = tog_primitives::segment::segment_link(&head, n, &c.plaintext_root, &c.metrics_hash);
    }
    Some(head)
}

/// Job-fault `exit_status` when the checker rejects a segment (TOG-SPEC-0001 §5.3, check 8).
pub const CHECKER_REJECTED: i32 = -7;

/// The executor's own checker run over a segment (TOG-SPEC-0003 §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CheckerResult {
    /// Checker container exit code; 0 = pass, −1 on timeout.
    pub exit: i32,
    /// 4 KiB chunk-tree root of the report archive (TDA of `/out/report`).
    pub report_root: Hash32,
    /// Bytes of that archive.
    pub report_size: u64,
    /// Segment `n` is the job's last (TOG-SPEC-0001 §4.2 step 6): the checker run mounted
    /// `/in/output`, and verifiers and jurors of `n` mount it too (TOG-SPEC-0003 §5.3
    /// "Last-segment flag"). Committed at V1; the Hub allows it on the last entry only.
    pub is_final: bool,
}

impl CheckerResult {
    /// `H("TOG/v1/metrics" ‖ i32_le exit)`: the `own_metrics` of a `CheckerOnly` vote, which the
    /// tally compares with this value.
    pub fn metrics_hash(&self) -> Hash32 {
        tog_primitives::segment::metrics_hash(&self.exit.to_le_bytes())
    }
}

impl CheckpointCommitment {
    /// The stored ciphertext as a verifier or juror mounts it; nothing else is needed. Its deal
    /// is `storage.job_deals[(job_id, Checkpoints)]`.
    pub fn payload(&self) -> PayloadCommitment {
        PayloadCommitment {
            version: 1,
            root: self.ciphertext_root,
            size: self.size,
            piece_log2: CHECKPOINT_PIECE_LOG2,
            kind: PayloadKind::Checkpoint,
            oci_digest: None,
            encryption: Encryption::Checkpoint {
                plaintext_root: self.plaintext_root,
                key_commitment: self.key_commitment,
            },
        }
    }

    /// True if `key` is the key this commitment was made to.
    pub fn opens_with(&self, key: &CheckpointKey) -> bool {
        key.commitment() == self.key_commitment
    }
}

/// Random-projection sketch of a tensor checkpoint (TOG-SPEC-0003 §5.2).
///
/// The spec fixes the math (k = 64 projections per tensor, fixed-point only) but not the
/// number format. This code uses signed Q32.32 for projections and unsigned Q32.32 for norms.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Sketch {
    /// One entry per tensor, in checkpoint manifest order.
    pub tensors: Vec<TensorSketch>,
}

/// Sketch of one tensor.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TensorSketch {
    /// Tensor name in the checkpoint manifest.
    pub name: String,
    /// `s_t = R_t · t / sqrt(k)`, Q32.32, `k` entries.
    pub projection: Vec<i64>,
    /// `‖t‖₂`, Q32.32.
    pub norm: u64,
}

/// Executor releases checkpoint keys at V4 / V6 (TOG-SPEC-0003 §3.1). `TxBody` variant 6.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KeyReleaseTx {
    /// Job.
    pub job_id: Hash32,
    /// Strictly sorted by segment.
    pub keys: Vec<ReleasedKey>,
}

/// One released key.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReleasedKey {
    /// Segment `n`.
    pub segment: u32,
    /// `k_n`.
    pub key: CheckpointKey,
    /// `verify_class` Tolerance only, at V6 or for a challenged unsampled segment's end key
    /// (TOG-SPEC-0003 §4.2): the sketch of `ckpt_n`. `None` otherwise.
    pub sketch: Option<Sketch>,
}

/// Why a key release is invalid.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyReleaseError {
    /// Nothing released.
    #[error("no keys")]
    Empty,
    /// Segments not strictly increasing.
    #[error("keys must be strictly sorted by segment")]
    NotSorted,
    /// Segment past the job's last one.
    #[error("segment {0} has no checkpoint")]
    UnknownSegment(u32),
    /// Key does not open the committed `key_commitment`.
    #[error("key for segment {0} does not match its commitment")]
    WrongKey(u32),
    /// A sketch over the size caps or with a projection of the wrong length (TOG-SPEC-0003 §5.2.1).
    #[error("sketch for segment {0} is malformed")]
    BadSketch(u32),
}

impl KeyReleaseTx {
    /// Check against the job's `CommitResult` checkpoints (segment `n` at index `n`).
    pub fn check(&self, checkpoints: &[CheckpointCommitment]) -> Result<(), KeyReleaseError> {
        if self.keys.is_empty() {
            return Err(KeyReleaseError::Empty);
        }
        if self.keys.windows(2).any(|w| w[0].segment >= w[1].segment) {
            return Err(KeyReleaseError::NotSorted);
        }
        for k in &self.keys {
            let c = checkpoints.get(k.segment as usize).ok_or(KeyReleaseError::UnknownSegment(k.segment))?;
            if !c.opens_with(&k.key) {
                return Err(KeyReleaseError::WrongKey(k.segment));
            }
            if k.sketch.as_ref().is_some_and(|s| !s.well_formed()) {
                return Err(KeyReleaseError::BadSketch(k.segment));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_commitment_opens() {
        let k = CheckpointKey([9; 32]);
        let c = CheckpointCommitment {
            segment: 0,
            plaintext_root: [0; 32],
            ciphertext_root: [0; 32],
            key_commitment: k.commitment(),
            size: 0,
            metrics_hash: [0; 32],
            sketch: None,
            checker: None,
        };
        assert!(c.opens_with(&k));
        assert!(!c.opens_with(&CheckpointKey([8; 32])));
    }

    #[test]
    fn payload_is_determined_by_the_commitment() {
        let c = CheckpointCommitment {
            segment: 3,
            plaintext_root: [1; 32],
            ciphertext_root: [2; 32],
            key_commitment: [3; 32],
            size: 5 << 20,
            metrics_hash: [4; 32],
            sketch: None,
            checker: None,
        };
        let p = c.payload();
        assert_eq!((p.version, p.root, p.size, p.piece_log2), (1, [2; 32], 5 << 20, 22));
        assert_eq!(p.kind, PayloadKind::Checkpoint);
        assert_eq!(p.oci_digest, None);
        assert_eq!(p.encryption, Encryption::Checkpoint { plaintext_root: [1; 32], key_commitment: [3; 32] });
    }

    #[test]
    fn checker_result_is_the_last_field() {
        let mut c = commitments(1).remove(0);
        let without = borsh::to_vec(&c).unwrap();
        assert_eq!(without.last(), Some(&0));
        let r = CheckerResult { exit: CHECKER_REJECTED, report_root: [5; 32], report_size: 7, is_final: true };
        c.checker = Some(r);
        let with = borsh::to_vec(&c).unwrap();
        assert_eq!(&with[..without.len() - 1], &without[..without.len() - 1]);
        // `is_final` is the last byte (0003 §5.3, C-37).
        let tail = [&[1u8][..], &(-7i32).to_le_bytes(), &[5; 32], &7u64.to_le_bytes(), &[1]].concat();
        assert_eq!(&with[without.len() - 1..], &tail[..]);
        assert_eq!(r.metrics_hash(), tagged_hash(Domain::Metrics, &[&(-7i32).to_le_bytes()]));
    }

    #[test]
    fn segment_root_follows_the_chain() {
        use tog_primitives::segment::{metrics_hash, SegmentChain};
        let job = [6; 32];
        assert_eq!(segment_root(&job, &[]), Some(tog_primitives::segment::segment_genesis(&job)));
        let mut cs = commitments(3);
        let mut chain = SegmentChain::genesis(&job);
        for c in &mut cs {
            c.plaintext_root = [c.segment as u8 + 1; 32];
            c.metrics_hash = metrics_hash(&[c.segment as u8]);
            chain.push(c.segment, &c.plaintext_root, &[c.segment as u8]).unwrap();
        }
        assert_eq!(segment_root(&job, &cs), Some(chain.head()));
        cs.swap(1, 2);
        assert_eq!(segment_root(&job, &cs), None);
    }

    fn commitments(n: u8) -> Vec<CheckpointCommitment> {
        (0..n)
            .map(|i| CheckpointCommitment {
                segment: i.into(),
                plaintext_root: [0; 32],
                ciphertext_root: [0; 32],
                key_commitment: CheckpointKey([i; 32]).commitment(),
                size: 0,
                metrics_hash: [0; 32],
                sketch: None,
                checker: None,
            })
            .collect()
    }

    fn release(segs: &[u8]) -> KeyReleaseTx {
        KeyReleaseTx {
            job_id: [0; 32],
            keys: segs
                .iter()
                .map(|&i| ReleasedKey { segment: i.into(), key: CheckpointKey([i; 32]), sketch: None })
                .collect(),
        }
    }

    #[test]
    fn key_release_checks() {
        let c = commitments(4);
        assert_eq!(release(&[0, 2, 3]).check(&c), Ok(()));
        assert_eq!(release(&[]).check(&c), Err(KeyReleaseError::Empty));
        assert_eq!(release(&[2, 1]).check(&c), Err(KeyReleaseError::NotSorted));
        assert_eq!(release(&[1, 1]).check(&c), Err(KeyReleaseError::NotSorted));
        assert_eq!(release(&[4]).check(&c), Err(KeyReleaseError::UnknownSegment(4)));
        let mut bad = release(&[1]);
        bad.keys[0].key = CheckpointKey([9; 32]);
        assert_eq!(bad.check(&c), Err(KeyReleaseError::WrongKey(1)));
    }

    #[test]
    fn key_is_not_printed() {
        assert_eq!(format!("{:?}", CheckpointKey([1; 32])), "CheckpointKey(..)");
    }

    #[test]
    fn a_key_is_wiped_when_dropped() {
        assert!(core::mem::needs_drop::<CheckpointKey>());
    }
}
