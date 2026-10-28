//! Retrievability challenges and their responses (TOG-SPEC-0004 §5.1).
//!
//! A response opens `q` 4 KiB chunks of a deal's set. Each [`ChunkOpening`] proves its payload is
//! in the set ([`MerklePath`]) and its chunk is in the payload ([`Bao4kProof`], BLAKE3 chaining
//! values from the 4 KiB leaf to the payload root).

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::payload::CHUNK_4K;
use tog_primitives::{tagged_hash, Address, Domain, Hash32};

use crate::job::DealId;
use crate::storage::{verify_path, MerklePath, PayloadSetLeaf, PayloadSetRoot};
use crate::worker::WorkerId;

/// Most chunks one challenge opens.
pub const MAX_Q: usize = 16;

/// The address of a storage worker's key (TOG-SPEC-0004 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct StorageWorkerId(pub Address);

/// A challenge, assigned in issue order and never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct ChallengeId(pub u64);

/// `storage.challenges[id]` (TOG-SPEC-0004 §5.1, TOG-SPEC-0002 §7.2): an open challenge, from issue
/// until answered or expired.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RetrievabilityChallenge {
    /// Id.
    pub id: ChallengeId,
    /// What it covers.
    pub target: ChallengeTarget,
    /// `HubBeacon(issued)`.
    pub seed: [u8; 32],
    /// Chunks to open.
    pub q: u8,
    /// Height issued.
    pub issued: u64,
    /// Last height a response is accepted: `issued + D_resp(kind)`.
    pub deadline: u64,
    /// A targeted challenge's challenger and bond.
    pub challenger: Option<(Address, tog_primitives::Amount)>,
    /// The challenged byte space, fixed at issue (TOG-SPEC-0004 §5.1): index derivation and
    /// response checks read the span containing a drawn byte, never the deal's current state.
    pub spans: Vec<Span>,
}

/// One slot's bytes in a challenge's byte space, as they were at issue (TOG-SPEC-0004 §5.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Span {
    /// Deal.
    pub deal: DealId,
    /// Slot; 0 for an `Executor` target.
    pub slot: u16,
    /// The deal's payload set at issue; responses open against its root.
    pub set: PayloadSetRoot,
    /// Offset of this span in the challenge's concatenated byte space.
    pub base: u64,
    /// Bytes drawn from: the sum of `leaves`' sizes for a lazy slot, else `set.total_size`.
    pub len: u64,
    /// A lazy slot's materialized leaves at issue, ascending; empty otherwise.
    pub leaves: Vec<(u32, PayloadSetLeaf)>,
}

impl Span {
    /// Set offset of byte `x` of the slot this span covers, for a slot holding RS shard `shard`
    /// (ignored otherwise): in a lazy slot's `leaves` ([`lazy_offset`]); for an RS shard slot,
    /// whose `len` is one shard of the longer shard set, `shard · len + x`; else `x`. `base` is
    /// the span's place in the challenge's byte space, not in the set.
    pub fn at(&self, x: u64, shard: u16) -> Option<u64> {
        if !self.leaves.is_empty() {
            return lazy_offset(&self.leaves, x).map(|(_, o)| o);
        }
        if x >= self.len {
            return None;
        }
        if self.set.total_size == self.len {
            return Some(x);
        }
        u64::from(shard).checked_mul(self.len)?.checked_add(x)
    }

    /// Where a `RetrievalDispute` offset `x` of the slot's bytes is in the set: `x` itself in a
    /// lazy slot's leaves, else [`Span::at`].
    fn chunk_at(&self, x: u64, shard: u16) -> Option<u64> {
        if self.leaves.is_empty() {
            self.at(x, shard)
        } else {
            self.leaves.iter().any(|(_, l)| l.offset <= x && x - l.offset < l.size).then_some(x)
        }
    }
}

impl RetrievabilityChallenge {
    /// Where chunk `j` lies (TOG-SPEC-0004 §5.1 index derivation): the span holding it and the
    /// set offset of the drawn byte, read from `spans` only, so a set that grew, a leaf
    /// materialized or a slot lost since issue moves nothing. A `Holder` draw walks the spans'
    /// lengths in order; every other target has one span. `shard` gives the RS shard a span's
    /// slot holds (`HolderSlot.shard`; any value for other slots). `None` if nothing can be drawn.
    pub fn locate(&self, j: u32, shard: impl Fn(&Span) -> u16) -> Option<(&Span, u64)> {
        let u = self.target.draw(&self.seed, j);
        let first = self.spans.first();
        match &self.target {
            ChallengeTarget::Holder(_) => {
                let total = self.spans.iter().try_fold(0u64, |a, s| a.checked_add(s.len))?;
                let mut x = u.checked_rem(total)?;
                for s in &self.spans {
                    if x < s.len {
                        return Some((s, s.at(x, shard(s))?));
                    }
                    x -= s.len;
                }
                None
            }
            // A lazy slot's `Ack` range is already in set offsets.
            ChallengeTarget::Ack { .. } if first.is_some_and(|s| !s.leaves.is_empty()) => {
                let s = first?;
                Some((s, self.target.set_offset(&self.seed, j, s.set.total_size)?))
            }
            ChallengeTarget::Ack { .. } => {
                let s = first?;
                Some((s, s.at(self.target.set_offset(&self.seed, j, s.len)?, shard(s))?))
            }
            ChallengeTarget::Chunks { offsets, .. } => {
                let s = first?;
                Some((s, s.chunk_at(*offsets.get(j as usize)?, shard(s))?))
            }
            ChallengeTarget::Slot { .. } | ChallengeTarget::Executor { .. } => {
                let s = first?;
                Some((s, s.at(u.checked_rem(s.len)?, shard(s))?))
            }
        }
    }
}

/// What a challenge covers.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ChallengeTarget {
    /// 0: scheduled, over the holder's whole committed byte space across its slots.
    Holder(StorageWorkerId),
    /// 1: targeted, one slot of one deal.
    Slot {
        /// Deal.
        deal: DealId,
        /// Slot.
        slot: u16,
    },
    /// 2: the executor as custodian of its own checkpoint deal.
    Executor {
        /// Deal.
        deal: DealId,
        /// Executor.
        worker: WorkerId,
    },
    /// 3: custody acknowledgement of one slot, over the set's bytes `[from_offset, to_offset)`:
    /// `to_offset` is the set's `total_size` when issued, or the end of one leaf for a lazy
    /// materialization (TOG-SPEC-0004 §4.8).
    Ack {
        /// Deal.
        deal: DealId,
        /// Slot.
        slot: u16,
        /// First byte the ack covers.
        from_offset: u64,
        /// End of the covered bytes, exclusive.
        to_offset: u64,
    },
    /// 4: a `RetrievalDispute`'s chunks, named by the requester as byte offsets in the deal's set
    /// (the shard for RS); nothing is drawn (TOG-SPEC-0004 §6.6).
    Chunks {
        /// Deal.
        deal: DealId,
        /// Slot.
        slot: u16,
        /// 1 to 16 strictly ascending offsets; chunk `j` is at `offsets[j]`.
        offsets: Vec<u64>,
    },
}

impl ChallengeTarget {
    /// `u_j`: the first 8 bytes, little-endian, of `H("TOG/v1/por" ‖ seed ‖ borsh(target) ‖ u32 j)`.
    pub fn draw(&self, seed: &[u8; 32], j: u32) -> u64 {
        let target = borsh::to_vec(self).expect("in-memory borsh cannot fail");
        let h = tagged_hash(Domain::Por, &[seed, &target, &j.to_le_bytes()]);
        u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
    }

    /// Offset in the deal's set of chunk `j`, for every target but `Holder` (whose offset spans the
    /// holder's slots and needs Hub state), in a set of `total_size` bytes. `None` for `Holder`, an
    /// empty range, an `Ack` range past the set, or a `Chunks` offset missing or past the set. A
    /// `Slot` of a lazy deal draws over its own leaves instead: [`lazy_offset`] of `u mod Σ size`.
    pub fn set_offset(&self, seed: &[u8; 32], j: u32, total_size: u64) -> Option<u64> {
        if let ChallengeTarget::Chunks { offsets, .. } = self {
            return offsets.get(j as usize).copied().filter(|&x| x < total_size);
        }
        let u = self.draw(seed, j);
        match *self {
            ChallengeTarget::Holder(_) | ChallengeTarget::Chunks { .. } => None,
            ChallengeTarget::Slot { .. } | ChallengeTarget::Executor { .. } => u.checked_rem(total_size),
            ChallengeTarget::Ack { from_offset, to_offset, .. } => {
                if to_offset > total_size {
                    return None;
                }
                Some(from_offset + u.checked_rem(to_offset.checked_sub(from_offset)?)?)
            }
        }
    }
}

/// BLAKE3 chaining values that connect one 4 KiB leaf to the payload root, closest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Bao4kProof {
    /// Sibling CV at each level, from the leaf's subtree upward.
    pub siblings: Vec<Hash32>,
}

/// The subtrees BLAKE3 splits `[0, size)` into on the way to the leaf starting at `leaf_lo`:
/// `(sibling_lo, sibling_hi, sibling_is_left)` from the root down.
fn walk(size: u64, leaf_lo: u64) -> Vec<(u64, u64, bool)> {
    use blake3::hazmat::left_subtree_len;
    let (mut lo, mut hi) = (0, size);
    let mut out = Vec::new();
    // Every split of more than four chunks falls on a multiple of 4 KiB, so each leaf is one subtree.
    while hi - lo > CHUNK_4K as u64 {
        let mid = lo + left_subtree_len(hi - lo);
        if leaf_lo < mid {
            out.push((mid, hi, false));
            hi = mid;
        } else {
            out.push((lo, mid, true));
            lo = mid;
        }
    }
    out
}

/// CV of the subtree over `bytes`, which start at `offset` in the payload.
fn subtree_cv(offset: u64, bytes: &[u8]) -> Hash32 {
    use blake3::hazmat::HasherExt;
    blake3::Hasher::new().set_input_offset(offset).update(bytes).finalize_non_root()
}

/// Byte range of leaf `index` in a `size`-byte payload; `None` past the end.
fn leaf_range(size: u64, index: u64) -> Option<(u64, u64)> {
    let lo = index.checked_mul(CHUNK_4K as u64)?;
    (lo < size).then(|| (lo, size.min(lo + CHUNK_4K as u64)))
}

impl Bao4kProof {
    /// The proof for leaf `index` of `bytes`; `None` past the end.
    pub fn prove(bytes: &[u8], index: u64) -> Option<Self> {
        leaf_range(bytes.len() as u64, index)?;
        let walk = walk(bytes.len() as u64, index * CHUNK_4K as u64);
        let siblings = walk.iter().rev().map(|&(lo, hi, _)| subtree_cv(lo, &bytes[lo as usize..hi as usize])).collect();
        Some(Self { siblings })
    }

    /// True if `chunk` is leaf `index` of the `size`-byte payload with BLAKE3 `root`.
    pub fn verify(&self, root: &Hash32, size: u64, index: u64, chunk: &[u8]) -> bool {
        use blake3::hazmat::{merge_subtrees_non_root, merge_subtrees_root, Mode};
        let Some((lo, hi)) = leaf_range(size, index) else { return false };
        if chunk.len() as u64 != hi - lo {
            return false;
        }
        let walk = walk(size, lo);
        if self.siblings.len() != walk.len() {
            return false;
        }
        if walk.is_empty() {
            return blake3::hash(chunk).as_bytes() == root;
        }
        let mut cv = subtree_cv(lo, chunk);
        for (k, (sib, &(_, _, left))) in self.siblings.iter().zip(walk.iter().rev()).enumerate() {
            let (l, r) = if left { (sib, &cv) } else { (&cv, sib) };
            if k + 1 == walk.len() {
                return merge_subtrees_root(l, r, Mode::Hash).as_bytes() == root;
            }
            cv = merge_subtrees_non_root(l, r, Mode::Hash);
        }
        unreachable!("the last merge returns")
    }
}

/// One opened chunk.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChunkOpening {
    /// Deal.
    pub deal: DealId,
    /// Slot; 0 for an `Executor` target.
    pub slot: u16,
    /// Which payload, and its offset in the set.
    pub set_leaf: PayloadSetLeaf,
    /// Leaf to the set root.
    pub set_path: MerklePath,
    /// 4 KiB leaf of the payload.
    pub chunk_index: u64,
    /// The leaf's bytes, at most 4 KiB.
    pub chunk: Vec<u8>,
    /// Leaf to the payload root.
    pub chunk_proof: Bao4kProof,
}

impl ChunkOpening {
    /// The per-chunk part of `verify_response` (TOG-SPEC-0004 §5.1): this opening proves the
    /// byte at `set_off` of the set `set`. The caller has matched `deal` and `slot`.
    pub fn proves(&self, set: &PayloadSetRoot, set_off: u64) -> bool {
        let leaf = &self.set_leaf;
        self.chunk.len() <= CHUNK_4K
            && verify_path(set, leaf, &self.set_path)
            && leaf.offset <= set_off
            && set_off - leaf.offset < leaf.size
            && self.chunk_index == (set_off - leaf.offset) / CHUNK_4K as u64
            && self.chunk_proof.verify(&leaf.root, leaf.size, self.chunk_index, &self.chunk)
    }
}

/// Offset in the deal's set of byte `x` of a lazy slot's `leaves` (ascending leaf index, each
/// with its index), concatenated in leaf order (TOG-SPEC-0004 §5.1): the leaf index and the set
/// offset. `None` if `x ≥ Σ size`.
pub fn lazy_offset(leaves: &[(u32, PayloadSetLeaf)], mut x: u64) -> Option<(u32, u64)> {
    for (i, l) in leaves {
        if x < l.size {
            return Some((*i, l.offset + x));
        }
        x -= l.size;
    }
    None
}

/// The leaf holding byte `set_off` of a set with these `leaves`, and the chunk index within it.
pub fn locate(leaves: &[PayloadSetLeaf], set_off: u64) -> Option<(usize, u64)> {
    let i = leaves.partition_point(|l| l.offset + l.size <= set_off);
    let leaf = leaves.get(i)?;
    (leaf.offset <= set_off).then(|| (i, (set_off - leaf.offset) / CHUNK_4K as u64))
}

/// Answer to a challenge.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChallengeResponse {
    /// Challenge.
    pub challenge: ChallengeId,
    /// Exactly `q` openings (at most [`MAX_Q`]), in draw order.
    pub openings: Vec<ChunkOpening>,
}

/// `TxBody` variant 21. Answers any challenge; a `CustodyAck` is the answer to an `Ack` challenge.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RespondChallengeTx {
    /// The response.
    pub response: ChallengeResponse,
}

#[cfg(test)]
mod tests;
