//! The segment chain (TOG-SPEC-0001 §4.2 step 6):
//!
//! ```text
//! S_{-1} = H("TOG/v1/segment-genesis" ‖ job_id)
//! S_n    = H("TOG/v1/segment" ‖ S_{n-1} ‖ u32_le(n) ‖ plaintext_root_n ‖ H("TOG/v1/metrics" ‖ metrics_n))
//! ```

use crate::hash::{tagged_hash, Domain, Hash32};

/// `H("TOG/v1/metrics" ‖ metrics_n)`.
pub fn metrics_hash(metrics: &[u8]) -> Hash32 {
    tagged_hash(Domain::Metrics, &[metrics])
}

/// One link: `S_n = H("TOG/v1/segment" ‖ S_{n-1} ‖ u32_le(n) ‖ plaintext_root_n ‖ metrics_hash_n)`.
pub fn segment_link(prev: &Hash32, n: u32, plaintext_root: &Hash32, metrics_hash: &Hash32) -> Hash32 {
    tagged_hash(Domain::Segment, &[prev, &n.to_le_bytes(), plaintext_root, metrics_hash])
}

/// `S_{-1}` of a job.
pub fn segment_genesis(job_id: &Hash32) -> Hash32 {
    tagged_hash(Domain::SegmentGenesis, &[job_id])
}

/// Errors from extending a segment chain.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SegmentError {
    /// Segments must be pushed in order without gaps.
    #[error("expected segment {expected}, got {got}")]
    OutOfOrder {
        /// Next index the chain accepts.
        expected: u32,
        /// Index that was pushed.
        got: u32,
    },
}

/// Running segment chain of one job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentChain {
    head: Hash32,
    next: u32,
}

impl SegmentChain {
    /// Empty chain for `job_id`; the first pushed segment is 0.
    pub fn genesis(job_id: &Hash32) -> Self {
        Self { head: segment_genesis(job_id), next: 0 }
    }

    /// Continue a chain whose head after segment `next - 1` is `head`.
    /// A verifier re-running segment `n` resumes from the executor's `S_{n-1}`.
    pub fn resume(head: Hash32, next: u32) -> Self {
        Self { head, next }
    }

    /// Append segment `n` with its checkpoint root and the raw bytes of its metrics file.
    pub fn push(&mut self, n: u32, ckpt_root: &Hash32, metrics: &[u8]) -> Result<Hash32, SegmentError> {
        if n != self.next {
            return Err(SegmentError::OutOfOrder { expected: self.next, got: n });
        }
        self.head = segment_link(&self.head, n, ckpt_root, &metrics_hash(metrics));
        self.next += 1;
        Ok(self.head)
    }

    /// Current head: `S_last`, or `S_{-1}` if nothing was pushed.
    pub fn head(&self) -> Hash32 {
        self.head
    }

    /// Index of the next segment to push.
    pub fn next_index(&self) -> u32 {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: Hash32 = [7; 32];

    #[test]
    fn deterministic_and_order_sensitive() {
        let mut a = SegmentChain::genesis(&JOB);
        a.push(0, &[1; 32], b"m0").unwrap();
        a.push(1, &[3; 32], b"m1").unwrap();

        let mut b = SegmentChain::genesis(&JOB);
        b.push(0, &[1; 32], b"m0").unwrap();
        b.push(1, &[3; 32], b"m1").unwrap();
        assert_eq!(a.head(), b.head());

        let mut c = SegmentChain::genesis(&JOB);
        c.push(0, &[3; 32], b"m1").unwrap();
        c.push(1, &[1; 32], b"m0").unwrap();
        assert_ne!(a.head(), c.head());
    }

    #[test]
    fn matches_spec_encoding() {
        let job = [7u8; 32];
        let genesis = tagged_hash(Domain::SegmentGenesis, &[&job]);
        let m = tagged_hash(Domain::Metrics, &[b"loss=1"]);
        let s0 = tagged_hash(Domain::Segment, &[&genesis, &0u32.to_le_bytes(), &[1; 32], &m]);
        let mut c = SegmentChain::genesis(&job);
        assert_eq!(c.head(), genesis);
        assert_eq!(c.push(0, &[1; 32], b"loss=1").unwrap(), s0);
    }

    #[test]
    fn genesis_binds_job() {
        assert_ne!(SegmentChain::genesis(&[0; 32]).head(), SegmentChain::genesis(&[1; 32]).head());
    }

    #[test]
    fn rejects_gaps() {
        let mut c = SegmentChain::genesis(&JOB);
        assert_eq!(c.push(1, &[0; 32], b""), Err(SegmentError::OutOfOrder { expected: 0, got: 1 }));
    }

    #[test]
    fn resume_matches_full_chain() {
        let mut full = SegmentChain::genesis(&JOB);
        let s0 = full.push(0, &[1; 32], b"m0").unwrap();
        let s1 = full.push(1, &[3; 32], b"m1").unwrap();

        let mut verifier = SegmentChain::resume(s0, 1);
        assert_eq!(verifier.push(1, &[3; 32], b"m1").unwrap(), s1);
    }
}
