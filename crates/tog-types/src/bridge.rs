//! Bridge leaves and their Keccak Merkle Mountain Range (TOG-SPEC-0008 §3.2 "Encoding and MMR layout
//! (exact)"), and the message validators sign over a commitment (§3.3).
//!
//! Everything here is Keccak-256 and big-endian, so Solidity can check it without a Borsh parser.
//! The Hub keeps only [`Mmr`] (leaf count and peaks) in `bridge_commitments.mmr`; inclusion and
//! ancestry are proven against those peaks with [`MmrProof`].

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use bls12_381::G1Affine;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{keccak256, Hash32};

/// A leaf every this many Hub blocks.
pub const BRIDGE_INTERVAL: u64 = 4;
/// `BridgeLeaf::version`.
pub const BRIDGE_LEAF_VERSION: u8 = 1;
/// Length of [`BridgeLeaf::encode`].
pub const BRIDGE_LEAF_LEN: usize = 325;
/// Prefix of the signed message.
pub const BRIDGE_TAG: &[u8; 13] = b"TOG/v1/bridge";

/// Whether `h` gets a leaf: `h mod 4 = 3` (the last block of every era is one, since `era_length` is a
/// multiple of 4).
pub fn is_commitment_height(h: u64) -> bool {
    h % BRIDGE_INTERVAL == BRIDGE_INTERVAL - 1
}

/// Index of the leaf of commitment height `h`; the MMR certified at `h` has one more leaf.
pub fn leaf_index(h: u64) -> u64 {
    h / BRIDGE_INTERVAL
}

/// A G1 point in the 128-byte EIP-2537 form: `x ‖ y`, each a 64-byte big-endian field element whose
/// top 16 bytes are zero. The identity is all zeros.
pub fn eip2537_g1(p: &G1Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if bool::from(p.is_identity()) {
        return out;
    }
    // Uncompressed zkcrypto form is x ‖ y, 48 bytes each, with no flag bits set for a finite point.
    let u = p.to_uncompressed();
    out[16..64].copy_from_slice(&u[..48]);
    out[80..128].copy_from_slice(&u[48..]);
    out
}

/// The Gateway head a leaf carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayHeadRef {
    /// Gateway block number of its current final head.
    pub height: u64,
    /// BLAKE3 JMT root.
    pub state_root: Hash32,
    /// Keccak root of the Ethereum outbox.
    pub eth_outbox_root: Hash32,
}

/// The validator set that signs the following commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritySetRef {
    /// Increments every era.
    pub id: u64,
    /// Number of validators.
    pub len: u32,
    /// [`keys_root`] of the BLS keys in validator index order.
    pub keys_root: Hash32,
    /// Aggregate of all `len` keys.
    pub apk: G1Affine,
}

impl AuthoritySetRef {
    /// The reference of a set: `keys` in validator index order.
    pub fn of(id: u64, keys: &[G1Affine]) -> Self {
        let apk = keys.iter().fold(bls12_381::G1Projective::identity(), |a, k| a + k);
        AuthoritySetRef { id, len: keys.len() as u32, keys_root: keys_root(keys), apk: apk.into() }
    }
}

/// One MMR leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeLeaf {
    /// [`BRIDGE_LEAF_VERSION`].
    pub version: u8,
    /// The commitment height.
    pub hub_height: u64,
    /// BFT time, ms.
    pub hub_time: u64,
    /// BLAKE3 header hash of the block.
    pub hub_block_hash: Hash32,
    /// BLAKE3 JMT root after the block.
    pub hub_state_root: Hash32,
    /// Gateway head.
    pub gateway: GatewayHeadRef,
    /// Next authority set.
    pub next_authority: AuthoritySetRef,
}

impl BridgeLeaf {
    /// The 325-byte packed encoding, integers big-endian.
    pub fn encode(&self) -> [u8; BRIDGE_LEAF_LEN] {
        let parts: [&[u8]; 12] = [
            &[self.version],
            &self.hub_height.to_be_bytes(),
            &self.hub_time.to_be_bytes(),
            &self.hub_block_hash,
            &self.hub_state_root,
            &self.gateway.height.to_be_bytes(),
            &self.gateway.state_root,
            &self.gateway.eth_outbox_root,
            &self.next_authority.id.to_be_bytes(),
            &self.next_authority.len.to_be_bytes(),
            &self.next_authority.keys_root,
            &eip2537_g1(&self.next_authority.apk),
        ];
        parts.concat().try_into().expect("fields add up to 325 bytes")
    }

    /// `keccak256(encode())`.
    pub fn hash(&self) -> Hash32 {
        keccak256(&[&self.encode()])
    }
}

fn node(left: &Hash32, right: &Hash32) -> Hash32 {
    keccak256(&[left, right])
}

/// Keccak Merkle root of BLS keys: leaves `keccak256(eip2537(pk))` in order, padded with `[0; 32]`
/// leaves to a power of two, inner nodes `keccak256(left ‖ right)`. One key is its own leaf; no keys
/// give `[0; 32]`.
pub fn keys_root(keys: &[G1Affine]) -> Hash32 {
    if keys.is_empty() {
        return [0; 32];
    }
    let mut level: Vec<Hash32> = keys.iter().map(|k| keccak256(&[&eip2537_g1(k)])).collect();
    level.resize(level.len().next_power_of_two(), [0; 32]);
    while level.len() > 1 {
        level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
    }
    level[0]
}

/// `bridge_commitments.mmr`: leaf count and mountain peaks, left to right.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Mmr {
    /// Leaves appended so far.
    pub leaf_count: u64,
    /// One root per set bit of `leaf_count`, largest mountain first.
    pub peaks: Vec<Hash32>,
}

/// Mountain heights of an MMR with `leaf_count` leaves, left to right.
fn mountains(leaf_count: u64) -> impl Iterator<Item = u8> {
    (0..64u8).rev().filter(move |b| leaf_count >> b & 1 == 1)
}

/// Bags peaks right to left: `R_k = P_k`, `R_j = keccak256(P_j ‖ R_{j+1})`; none give `[0; 32]`.
pub fn bag_peaks(peaks: &[Hash32]) -> Hash32 {
    let mut it = peaks.iter().rev();
    let Some(last) = it.next() else { return [0; 32] };
    it.fold(*last, |r, p| node(p, &r))
}

impl Mmr {
    /// Appends a leaf hash, merging equal-height mountains.
    pub fn append(&mut self, leaf: Hash32) {
        let mut n = leaf;
        let mut c = self.leaf_count;
        while c & 1 == 1 {
            let left = self.peaks.pop().expect("a set bit has a peak");
            n = node(&left, &n);
            c >>= 1;
        }
        self.peaks.push(n);
        self.leaf_count += 1;
    }

    /// `mmr_root`.
    pub fn root(&self) -> Hash32 {
        bag_peaks(&self.peaks)
    }

    /// Whether the peaks match the leaf count.
    pub fn well_formed(&self) -> bool {
        self.peaks.len() == self.leaf_count.count_ones() as usize
    }
}

/// Membership of a leaf (`height = 0`) or an inner node (`height = b`, `index` = its position among
/// all nodes of that height, left to right) in the MMR with `leaf_count` leaves.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MmrProof {
    /// Leaves of the MMR proven into.
    pub leaf_count: u64,
    /// Height of the node.
    pub height: u8,
    /// Position among nodes of that height.
    pub index: u64,
    /// Siblings inside the node's mountain, bottom-up.
    pub path: Vec<Hash32>,
    /// The other peaks, left to right; empty when checked against stored peaks.
    pub peaks: Vec<Hash32>,
}

impl MmrProof {
    /// The peak position the node climbs to, and the peak.
    fn climb(&self, node_hash: &Hash32) -> Option<(usize, Hash32)> {
        let mut first = 0u64; // index of the first node of `height` in the current mountain
        for (pos, k) in mountains(self.leaf_count).enumerate() {
            if k < self.height {
                continue;
            }
            let count = 1u64 << (k - self.height);
            if self.index < first + count {
                if self.path.len() != (k - self.height) as usize {
                    return None;
                }
                let mut j = self.index - first;
                let mut h = *node_hash;
                for s in &self.path {
                    h = if j & 1 == 1 { node(s, &h) } else { node(&h, s) };
                    j >>= 1;
                }
                return Some((pos, h));
            }
            first += count;
        }
        None
    }

    /// Checks `node_hash` against a claimed `mmr_root`, with the other peaks carried in the proof.
    pub fn verify(&self, node_hash: &Hash32, mmr_root: &Hash32) -> bool {
        let Some((pos, peak)) = self.climb(node_hash) else { return false };
        if self.peaks.len() + 1 != self.leaf_count.count_ones() as usize {
            return false;
        }
        let mut peaks = self.peaks.clone();
        peaks.insert(pos, peak);
        bag_peaks(&peaks) == *mmr_root
    }

    /// Checks `node_hash` against stored peaks (the Hub's form): `peaks` must be empty and the
    /// leaf count equal.
    pub fn verify_stored(&self, node_hash: &Hash32, mmr: &Mmr) -> bool {
        self.peaks.is_empty()
            && self.leaf_count == mmr.leaf_count
            && mmr.well_formed()
            && self.climb(node_hash).is_some_and(|(pos, peak)| mmr.peaks[pos] == peak)
    }
}

/// The root certified at an earlier MMR of `old_leaf_count` leaves: its peaks, each with an
/// [`MmrProof`] into `current`, checked against the stored peaks and bagged. Each old peak must sit at
/// its own mountain's height and position.
pub fn ancestry_root(old_leaf_count: u64, old_peaks: &[(Hash32, MmrProof)], current: &Mmr) -> Option<Hash32> {
    if old_leaf_count == 0 || old_leaf_count > current.leaf_count {
        return None;
    }
    let heights: Vec<u8> = mountains(old_leaf_count).collect();
    if heights.len() != old_peaks.len() {
        return None;
    }
    let mut leaves_before = 0u64;
    for (k, (peak, proof)) in heights.iter().zip(old_peaks) {
        let ok = proof.height == *k && proof.index == leaves_before >> k && proof.verify_stored(peak, current);
        if !ok {
            return None;
        }
        leaves_before += 1 << k;
    }
    Some(bag_peaks(&old_peaks.iter().map(|(p, _)| *p).collect::<Vec<_>>()))
}

/// Builds proofs from all leaf hashes; for relayers and tests, since the Hub keeps only peaks.
#[derive(Clone, Debug, Default)]
pub struct MmrLeaves(pub Vec<Hash32>);

impl MmrLeaves {
    /// The MMR of the first `leaf_count` leaves.
    pub fn mmr(&self, leaf_count: u64) -> Mmr {
        let mut m = Mmr::default();
        self.0[..leaf_count as usize].iter().for_each(|l| m.append(*l));
        m
    }

    /// The node of `height` at `index` in the MMR of `leaf_count` leaves, and its proof (other
    /// peaks included). `None` if there is no such node.
    pub fn prove(&self, leaf_count: u64, height: u8, index: u64) -> Option<(Hash32, MmrProof)> {
        let leaves = self.0.get(..leaf_count as usize)?;
        let peaks = self.mmr(leaf_count).peaks;
        let mut start = 0usize; // first leaf of the mountain
        let mut first = 0u64;
        for (pos, k) in mountains(leaf_count).enumerate() {
            let size = 1usize << k;
            if k >= height {
                let count = 1u64 << (k - height);
                if index < first + count {
                    let mountain = &leaves[start..start + size];
                    let mut j = (index - first) as usize;
                    let mut path = vec![];
                    for b in height..k {
                        path.push(mountain_node(mountain, b, j ^ 1));
                        j >>= 1;
                    }
                    let hash = mountain_node(mountain, height, (index - first) as usize);
                    let mut other = peaks.clone();
                    other.remove(pos);
                    return Some((hash, MmrProof { leaf_count, height, index, path, peaks: other }));
                }
                first += count;
            }
            start += size;
        }
        None
    }
}

fn mountain_node(leaves: &[Hash32], height: u8, j: usize) -> Hash32 {
    let mut level = leaves[j << height..(j + 1) << height].to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
    }
    level[0]
}

/// What validators sign over a commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BridgeCommitment {
    /// Root of the MMR whose last leaf is `hub_height`'s.
    pub mmr_root: Hash32,
    /// The commitment height.
    pub hub_height: u64,
    /// The signing set.
    pub authority_set_id: u64,
}

impl BridgeCommitment {
    /// `mmr_root ‖ u64_be(hub_height) ‖ u64_be(authority_set_id)`, 48 bytes.
    pub fn encode(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[..32].copy_from_slice(&self.mmr_root);
        out[32..40].copy_from_slice(&self.hub_height.to_be_bytes());
        out[40..].copy_from_slice(&self.authority_set_id.to_be_bytes());
        out
    }

    /// `keccak256("TOG/v1/bridge" ‖ u64_be(hub_chain_id) ‖ encode())`, signed with BLS keys.
    pub fn message(&self, hub_chain_id: u64) -> Hash32 {
        keccak256(&[BRIDGE_TAG, &hub_chain_id.to_be_bytes(), &self.encode()])
    }
}

#[cfg(test)]
mod tests {
    use bls12_381::{G1Projective, Scalar};

    use super::*;

    fn leaves(n: u64) -> MmrLeaves {
        MmrLeaves((0..n).map(|i| keccak256(&[&i.to_be_bytes()])).collect())
    }

    #[test]
    fn heights_and_indices() {
        assert!(!is_commitment_height(0) && is_commitment_height(3) && is_commitment_height(43_199));
        assert_eq!((leaf_index(3), leaf_index(7)), (0, 1));
    }

    #[test]
    fn mountains_and_bagging() {
        let l = leaves(7);
        let m = l.mmr(7);
        let n = |a: &Hash32, b: &Hash32| keccak256(&[a, b]);
        let p1 = n(&n(&l.0[0], &l.0[1]), &n(&l.0[2], &l.0[3]));
        let p2 = n(&l.0[4], &l.0[5]);
        let p3 = l.0[6];
        assert_eq!(m.peaks, vec![p1, p2, p3]);
        assert_eq!(m.root(), n(&p1, &n(&p2, &p3)));
        assert!(m.well_formed());
        assert_eq!(Mmr::default().root(), [0; 32]);
        assert_eq!(l.mmr(1).root(), l.0[0]);
    }

    #[test]
    fn proofs_of_every_node() {
        let l = leaves(11);
        for count in 1..=11 {
            let m = l.mmr(count);
            for height in 0..4u8 {
                for index in 0..count {
                    let Some((hash, proof)) = l.prove(count, height, index) else { continue };
                    assert!(proof.verify(&hash, &m.root()), "{count} {height} {index}");
                    let stored = MmrProof { peaks: vec![], ..proof.clone() };
                    assert!(stored.verify_stored(&hash, &m));
                    assert!(!proof.verify(&[9; 32], &m.root()));
                    let wrong = MmrProof { index: index + 1, ..proof };
                    assert!(!wrong.verify(&hash, &m.root()));
                }
            }
        }
        // Leaf 0 of 4 leaves has a 2-step path; a node of height 3 doesn't exist in 7 leaves.
        assert_eq!(l.prove(4, 0, 0).unwrap().1.path.len(), 2);
        assert!(l.prove(7, 3, 0).is_none());
    }

    #[test]
    fn ancestry_recovers_old_roots() {
        let l = leaves(13);
        let now = l.mmr(13);
        for old in 1..=13u64 {
            let mut before = 0u64;
            let proofs: Vec<_> = mountains(old)
                .map(|k| {
                    let (h, p) = l.prove(13, k, before >> k).unwrap();
                    before += 1 << k;
                    (h, MmrProof { peaks: vec![], ..p })
                })
                .collect();
            assert_eq!(proofs.iter().map(|p| p.0).collect::<Vec<_>>(), l.mmr(old).peaks);
            assert_eq!(ancestry_root(old, &proofs, &now), Some(l.mmr(old).root()));
        }
    }

    #[test]
    fn leaf_encoding() {
        let keys: Vec<G1Affine> = (1..=3u64).map(|i| (G1Projective::generator() * Scalar::from(i)).into()).collect();
        let leaf = BridgeLeaf {
            version: 1,
            hub_height: 3,
            hub_time: 6_000,
            hub_block_hash: [1; 32],
            hub_state_root: [2; 32],
            gateway: GatewayHeadRef { height: 7, state_root: [3; 32], eth_outbox_root: [4; 32] },
            next_authority: AuthoritySetRef::of(5, &keys),
        };
        let e = leaf.encode();
        assert_eq!(e[0], 1);
        assert_eq!(&e[1..9], &3u64.to_be_bytes());
        assert_eq!(&e[161..165], &3u32.to_be_bytes());
        assert_eq!(e[197..213], [0; 16]);
        // apk = 6·G.
        let six: G1Affine = (G1Projective::generator() * Scalar::from(6u64)).into();
        assert_eq!(&e[197..], &eip2537_g1(&six)[..]);
        assert_eq!(leaf.hash(), keccak256(&[&e]));
        // keys_root pads three leaves to four.
        let h = |k: &G1Affine| keccak256(&[&eip2537_g1(k)]);
        let n = |a: &Hash32, b: &Hash32| keccak256(&[a, b]);
        assert_eq!(leaf.next_authority.keys_root, n(&n(&h(&keys[0]), &h(&keys[1])), &n(&h(&keys[2]), &[0; 32])));
        assert_eq!(keys_root(&keys[..1]), h(&keys[0]));
        // The generator's x starts 0x17f1.
        assert_eq!(&eip2537_g1(&G1Affine::generator())[16..18], &[0x17, 0xf1]);
    }

    #[test]
    fn commitment_message() {
        let c = BridgeCommitment { mmr_root: [7; 32], hub_height: 3, authority_set_id: 2 };
        let msg =
            [&b"TOG/v1/bridge"[..], &9u64.to_be_bytes(), &[7; 32], &3u64.to_be_bytes(), &2u64.to_be_bytes()].concat();
        assert_eq!(c.message(9), keccak256(&[&msg]));
    }
}
