//! Salted vote tree of a verifier (TOG-SPEC-0003 §3.3).
//!
//! The verifier splits its own `ckpt_n` into 4 KiB chunks and builds
//!
//! ```text
//! leaf_i    = H("TOG/v1/vote" ‖ salt_v ‖ u64_le(i) ‖ chunk_i)
//! vote_root = VoteTree(leaf_0 … leaf_{m-1})
//! ```
//!
//! `VoteTree` has BLAKE3's shape over 4 KiB groups: the left subtree holds the largest
//! power of two of leaves strictly less than `m`, the rest go right; an inner node is
//! `H("TOG/v1/vote-node" ‖ left ‖ right)`; one leaf is its own root; `m = 0` has root
//! `H("TOG/v1/vote-node")`.

use crate::payload::CHUNK_4K;
#[cfg(not(feature = "std"))]
use crate::prelude::*;
use crate::{tagged_hash, Domain, Hash32};

/// `leaf_i` of the vote tree.
pub fn vote_leaf(salt_v: &[u8; 32], index: u64, chunk: &[u8]) -> Hash32 {
    tagged_hash(Domain::Vote, &[salt_v, &index.to_le_bytes(), chunk])
}

fn node(left: &Hash32, right: &Hash32) -> Hash32 {
    tagged_hash(Domain::VoteNode, &[left, right])
}

/// Size of the left subtree of `m > 1` leaves: the largest power of two strictly below `m`.
fn left_len(m: usize) -> usize {
    1 << (usize::BITS - 1 - (m - 1).leading_zeros())
}

/// Leaves of `bytes` under `salt_v`.
pub fn vote_leaves(salt_v: &[u8; 32], bytes: &[u8]) -> Vec<Hash32> {
    bytes.chunks(CHUNK_4K).enumerate().map(|(i, c)| vote_leaf(salt_v, i as u64, c)).collect()
}

/// Root over precomputed leaves.
pub fn vote_tree_root(leaves: &[Hash32]) -> Hash32 {
    match leaves.len() {
        0 => tagged_hash(Domain::VoteNode, &[]),
        1 => leaves[0],
        m => {
            let (l, r) = leaves.split_at(left_len(m));
            node(&vote_tree_root(l), &vote_tree_root(r))
        }
    }
}

/// `vote_root` of a checkpoint.
pub fn vote_root(salt_v: &[u8; 32], bytes: &[u8]) -> Hash32 {
    vote_tree_root(&vote_leaves(salt_v, bytes))
}

/// Sibling hashes from leaf `index` up to the root (nearest sibling first), for the V8 audit.
/// `None` if `index` is out of range.
pub fn vote_path(leaves: &[Hash32], index: usize) -> Option<Vec<Hash32>> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    let (mut lo, mut hi) = (0, leaves.len());
    // Walk down, collecting siblings root-first, then reverse.
    while hi - lo > 1 {
        let mid = lo + left_len(hi - lo);
        if index < mid {
            path.push(vote_tree_root(&leaves[mid..hi]));
            hi = mid;
        } else {
            path.push(vote_tree_root(&leaves[lo..mid]));
            lo = mid;
        }
    }
    path.reverse();
    Some(path)
}

/// Checks that `leaf` sits at `index` of a tree with `count` leaves and root `root`.
pub fn verify_vote_path(root: &Hash32, count: usize, index: usize, leaf: &Hash32, path: &[Hash32]) -> bool {
    if index >= count {
        return false;
    }
    // Rebuild the sequence of (is_left_child) decisions from the root down.
    let mut sides = Vec::new();
    let (mut lo, mut hi) = (0, count);
    while hi - lo > 1 {
        let mid = lo + left_len(hi - lo);
        let left = index < mid;
        sides.push(left);
        if left {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    if sides.len() != path.len() {
        return false;
    }
    let mut acc = *leaf;
    for (sibling, left) in path.iter().zip(sides.iter().rev()) {
        acc = if *left { node(&acc, sibling) } else { node(sibling, &acc) };
    }
    acc == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 32] = [7; 32];

    #[test]
    fn shape_matches_spec() {
        assert_eq!(vote_root(&SALT, b""), tagged_hash(Domain::VoteNode, &[]));
        let one = vote_root(&SALT, b"abc");
        assert_eq!(one, vote_leaf(&SALT, 0, b"abc"));

        // Three leaves: left holds 2 (largest power of two < 3), right holds 1.
        let bytes = vec![1u8; 2 * CHUNK_4K + 10];
        let l = vote_leaves(&SALT, &bytes);
        assert_eq!(l.len(), 3);
        assert_eq!(vote_root(&SALT, &bytes), node(&node(&l[0], &l[1]), &l[2]));

        // Four leaves: 2 + 2 (strictly less than 4).
        let l4 = vote_leaves(&SALT, &vec![2u8; 4 * CHUNK_4K]);
        assert_eq!(vote_tree_root(&l4), node(&node(&l4[0], &l4[1]), &node(&l4[2], &l4[3])));
    }

    #[test]
    fn salt_and_index_are_bound() {
        assert_ne!(vote_root(&SALT, b"x"), vote_root(&[8; 32], b"x"));
        assert_ne!(vote_leaf(&SALT, 0, b"x"), vote_leaf(&SALT, 1, b"x"));
    }

    #[test]
    fn paths_verify_for_every_leaf() {
        for m in 1..=11usize {
            let leaves: Vec<Hash32> = (0..m).map(|i| vote_leaf(&SALT, i as u64, &[i as u8])).collect();
            let root = vote_tree_root(&leaves);
            for i in 0..m {
                let path = vote_path(&leaves, i).unwrap();
                assert!(verify_vote_path(&root, m, i, &leaves[i], &path), "m={m} i={i}");
                if m > 1 {
                    let other = (i + 1) % m;
                    assert!(!verify_vote_path(&root, m, other, &leaves[i], &path) || leaves[i] == leaves[other]);
                }
            }
            assert!(vote_path(&leaves, m).is_none());
            assert!(!verify_vote_path(&root, m, m, &leaves[0], &[]));
        }
    }
}
