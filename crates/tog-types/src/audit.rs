//! V8 chunk audit of a verifier's vote (TOG-SPEC-0003 §3.3), `TxBody` variant 16.
//!
//! The Hub draws 16 leaves of the verifier's 4 KiB vote tree; the verifier opens each one with
//! the chunk bytes, its `VoteTree` path to `own_vote_root` and its BLAKE3 path to the
//! executor-shaped `plaintext_root`. A verifier that voted without the bytes cannot open them.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::payload::CHUNK_4K;
use tog_primitives::vote::{verify_vote_path, vote_leaf, vote_leaves, vote_path};
use tog_primitives::{Domain, Hash32};

use crate::worker::WorkerId;

/// Openings per audited vote.
pub const AUDIT_OPENINGS: usize = 16;
/// `T_audit`: blocks after `h7 + D_beacon` within which the response must be included.
pub const T_AUDIT: u64 = 150;

/// Indices of the leaves to open: 16 draws, repeats allowed, from the BLAKE3 XOF of
/// `derive_key("TOG/v1/audit", borsh((ρ_a, job_id, u32 segment, w)))`, little-endian `u64` words
/// with rejection sampling. Empty for `m = 0`.
pub fn audit_indices(rho_a: &Hash32, job_id: &Hash32, segment: u32, worker: &WorkerId, m: u64) -> Vec<u64> {
    if m == 0 {
        return Vec::new();
    }
    let material = borsh::to_vec(&(rho_a, job_id, segment, worker)).expect("in-memory borsh cannot fail");
    let mut xof = blake3::Hasher::new_derive_key(Domain::Audit.tag()).update(&material).finalize_xof();
    let limit = u64::MAX / m * m;
    let mut out = Vec::with_capacity(AUDIT_OPENINGS);
    while out.len() < AUDIT_OPENINGS {
        let mut w = [0u8; 8];
        xof.fill(&mut w);
        let w = u64::from_le_bytes(w);
        if w < limit {
            out.push(w % m);
        }
    }
    out
}

/// One opened leaf.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChunkOpening {
    /// Leaf index.
    pub index: u64,
    /// The leaf's bytes: 4096, or fewer for a short last leaf.
    pub chunk: Vec<u8>,
    /// `VoteTree` siblings, bottom-up, to `own_vote_root`.
    pub vote_path: Vec<Hash32>,
    /// BLAKE3 sibling chaining values, bottom-up, to `plaintext_root`.
    pub blake3_path: Vec<[u8; 32]>,
}

/// `TxBody` variant 16, signed by the verifier's worker key.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuditResponseTx {
    /// Job.
    pub job_id: Hash32,
    /// Audited segment.
    pub segment: u32,
    /// One per drawn index, in draw order; at most [`AUDIT_OPENINGS`].
    pub openings: Vec<ChunkOpening>,
}

/// Why an audit response fails.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// Openings do not follow the drawn indices.
    #[error("openings do not match the drawn indices")]
    Indices,
    /// A chunk has the wrong length for its index.
    #[error("chunk {0} has the wrong length")]
    ChunkLength(u64),
    /// A vote path does not lead to `own_vote_root`.
    #[error("vote path of chunk {0} does not verify")]
    VotePath(u64),
    /// A BLAKE3 path does not lead to `plaintext_root`.
    #[error("BLAKE3 path of chunk {0} does not verify")]
    Blake3Path(u64),
}

/// Leaves of a checkpoint of `len` bytes.
pub fn leaf_count(len: u64) -> u64 {
    len.div_ceil(CHUNK_4K as u64)
}

/// Sides of the path to leaf `index` in a BLAKE3 tree over `len` bytes, root first: `true` if
/// the leaf is in the left subtree. Splits follow BLAKE3, which on 4 KiB leaves is the vote tree's
/// shape.
fn sides(len: u64, index: u64) -> Vec<bool> {
    let leaf = CHUNK_4K as u64;
    let (mut lo, mut n) = (0u64, len);
    let mut out = Vec::new();
    let target = index * leaf;
    while n > leaf {
        let left = blake3::hazmat::left_subtree_len(n);
        if target < lo + left {
            out.push(true);
            n = left;
        } else {
            out.push(false);
            lo += left;
            n -= left;
        }
    }
    out
}

/// Chaining value of the subtree holding leaf `index`, whose bytes are `chunk`.
fn leaf_cv(index: u64, chunk: &[u8]) -> [u8; 32] {
    use blake3::hazmat::HasherExt;
    blake3::Hasher::new().set_input_offset(index * CHUNK_4K as u64).update(chunk).finalize_non_root()
}

/// BLAKE3 siblings of leaf `index` of `bytes`, bottom-up; `None` past the end.
pub fn blake3_path(bytes: &[u8], index: u64) -> Option<Vec<[u8; 32]>> {
    use blake3::hazmat::HasherExt;
    if index >= leaf_count(bytes.len() as u64) {
        return None;
    }
    let subtree_cv = |lo: u64, hi: u64| {
        blake3::Hasher::new().set_input_offset(lo).update(&bytes[lo as usize..hi as usize]).finalize_non_root()
    };
    let target = index * CHUNK_4K as u64;
    let (mut lo, mut hi) = (0u64, bytes.len() as u64);
    let mut path = Vec::new();
    while hi - lo > CHUNK_4K as u64 {
        let mid = lo + blake3::hazmat::left_subtree_len(hi - lo);
        if target < mid {
            path.push(subtree_cv(mid, hi));
            hi = mid;
        } else {
            path.push(subtree_cv(lo, mid));
            lo = mid;
        }
    }
    path.reverse();
    Some(path)
}

/// Checks that `chunk` is leaf `index` of the `len` bytes whose BLAKE3 hash is `root`.
pub fn verify_blake3_path(root: &Hash32, len: u64, index: u64, chunk: &[u8], path: &[[u8; 32]]) -> bool {
    use blake3::hazmat::{merge_subtrees_non_root, merge_subtrees_root, Mode};
    if index >= leaf_count(len) {
        return false;
    }
    let sides = sides(len, index);
    if sides.len() != path.len() {
        return false;
    }
    if path.is_empty() {
        return blake3::hash(chunk).as_bytes() == root;
    }
    let mut cv = leaf_cv(index, chunk);
    let last = path.len() - 1;
    for (i, (sib, left)) in path.iter().zip(sides.iter().rev()).enumerate() {
        let (l, r) = if *left { (&cv, sib) } else { (sib, &cv) };
        if i == last {
            return merge_subtrees_root(l, r, Mode::Hash).as_bytes() == root;
        }
        cv = merge_subtrees_non_root(l, r, Mode::Hash);
    }
    unreachable!("path is not empty")
}

/// The openings of `indices` over a verifier's own checkpoint `bytes` under `salt_v`.
pub fn open_chunks(bytes: &[u8], salt_v: &[u8; 32], indices: &[u64]) -> Option<Vec<ChunkOpening>> {
    let leaves = vote_leaves(salt_v, bytes);
    indices
        .iter()
        .map(|&i| {
            let start = usize::try_from(i).ok()?.checked_mul(CHUNK_4K)?;
            let chunk = bytes.get(start..(start + CHUNK_4K).min(bytes.len()))?.to_vec();
            Some(ChunkOpening {
                index: i,
                chunk,
                vote_path: vote_path(&leaves, usize::try_from(i).ok()?)?,
                blake3_path: blake3_path(bytes, i)?,
            })
        })
        .collect()
}

impl AuditResponseTx {
    /// Checks the response against the drawn `indices`, the verifier's revealed
    /// `own_vote_root` under `salt_v`, and the executor's `plaintext_root` over `len` bytes.
    pub fn check(
        &self,
        indices: &[u64],
        salt_v: &[u8; 32],
        own_vote_root: &Hash32,
        plaintext_root: &Hash32,
        len: u64,
    ) -> Result<(), AuditError> {
        if self.openings.len() != indices.len() || self.openings.iter().map(|o| o.index).ne(indices.iter().copied()) {
            return Err(AuditError::Indices);
        }
        let m = leaf_count(len);
        for o in &self.openings {
            let expected = len.saturating_sub(o.index * CHUNK_4K as u64).min(CHUNK_4K as u64);
            if o.chunk.len() as u64 != expected || expected == 0 {
                return Err(AuditError::ChunkLength(o.index));
            }
            let leaf = vote_leaf(salt_v, o.index, &o.chunk);
            let (count, index) = (usize::try_from(m), usize::try_from(o.index));
            let (Ok(count), Ok(index)) = (count, index) else { return Err(AuditError::VotePath(o.index)) };
            if !verify_vote_path(own_vote_root, count, index, &leaf, &o.vote_path) {
                return Err(AuditError::VotePath(o.index));
            }
            if !verify_blake3_path(plaintext_root, len, o.index, &o.chunk, &o.blake3_path) {
                return Err(AuditError::Blake3Path(o.index));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tog_primitives::vote::vote_root;

    use super::*;

    fn bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn indices_are_deterministic_and_in_range() {
        let a = audit_indices(&[1; 32], &[2; 32], 3, &[4; 20], 37);
        assert_eq!(a.len(), AUDIT_OPENINGS);
        assert!(a.iter().all(|&i| i < 37));
        assert_eq!(a, audit_indices(&[1; 32], &[2; 32], 3, &[4; 20], 37));
        assert_ne!(a, audit_indices(&[1; 32], &[2; 32], 3, &[5; 20], 37));
        assert!(audit_indices(&[1; 32], &[2; 32], 3, &[4; 20], 0).is_empty());
        assert_eq!(audit_indices(&[1; 32], &[2; 32], 3, &[4; 20], 1), vec![0; AUDIT_OPENINGS]);
    }

    #[test]
    fn blake3_paths_open_every_leaf() {
        for len in [1, 1024, 4096, 4097, 8192, 3 * 4096 + 5, 5 * 4096, 7 * 4096 + 4095, 9 * 4096] {
            let b = bytes(len);
            let root = *blake3::hash(&b).as_bytes();
            let m = leaf_count(len as u64);
            for i in 0..m {
                let start = i as usize * CHUNK_4K;
                let chunk = &b[start..(start + CHUNK_4K).min(len)];
                let path = blake3_path(&b, i).unwrap();
                assert!(verify_blake3_path(&root, len as u64, i, chunk, &path), "len {len} leaf {i}");
                let mut bad = chunk.to_vec();
                bad[0] ^= 1;
                assert!(!verify_blake3_path(&root, len as u64, i, &bad, &path));
                if m > 1 {
                    assert!(!verify_blake3_path(&root, len as u64, (i + 1) % m, chunk, &path));
                }
            }
            assert_eq!(blake3_path(&b, m), None);
        }
    }

    #[test]
    fn honest_response_passes() {
        let b = bytes(11 * 4096 + 100);
        let salt = [7; 32];
        let len = b.len() as u64;
        let indices = audit_indices(&[1; 32], &[2; 32], 0, &[3; 20], leaf_count(len));
        let tx = AuditResponseTx { job_id: [2; 32], segment: 0, openings: open_chunks(&b, &salt, &indices).unwrap() };
        let vr = vote_root(&salt, &b);
        let pr = *blake3::hash(&b).as_bytes();
        assert_eq!(tx.check(&indices, &salt, &vr, &pr, len), Ok(()));

        // A lazy verifier's tree over other bytes fails.
        let mut lazy = tx.clone();
        lazy.openings[0].chunk[0] ^= 1;
        assert!(matches!(lazy.check(&indices, &salt, &vr, &pr, len), Err(AuditError::VotePath(_))));
        // Wrong order, wrong salt, wrong root.
        let mut swapped = tx.clone();
        swapped.openings.reverse();
        if swapped.openings != tx.openings {
            assert_eq!(swapped.check(&indices, &salt, &vr, &pr, len), Err(AuditError::Indices));
        }
        assert!(tx.check(&indices, &[8; 32], &vr, &pr, len).is_err());
        assert!(matches!(tx.check(&indices, &salt, &vr, &[0; 32], len), Err(AuditError::Blake3Path(_))));
        // The last leaf is short.
        let last = leaf_count(len) - 1;
        let open = open_chunks(&b, &salt, &[last]).unwrap();
        assert_eq!(open[0].chunk.len(), 100);
        let t = AuditResponseTx { job_id: [2; 32], segment: 0, openings: open };
        assert_eq!(t.check(&[last], &salt, &vr, &pr, len), Ok(()));
    }
}
