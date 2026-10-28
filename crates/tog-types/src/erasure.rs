//! Availability chunks of an AppChain candidate's PoV (TOG-SPEC-0002 §4.5).
//!
//! The Zstd-compressed PoV `c` is framed as `D = u64_le(len(c)) ‖ c`, cut into `k` data shards
//! and extended with `m` parity shards of the RS code of TOG-SPEC-0004 §5.6.1 (GF(2¹⁶), data at
//! points `0..k`, parity `P(k + p)`), one shard per validator of the inclusion era:
//!
//! ```text
//! n = era set size, k = ⌊(n − 1) / 3⌋ + 1, m = n − k
//! shard_size      = 2 · ⌈len(D) / (2k)⌉
//! chunk_leaf(x)   = H("TOG/v1/chunk-leaf" ‖ x)
//! chunk_node(a,b) = H("TOG/v1/chunk-node" ‖ a ‖ b)
//! erasure_root    = pairs left to right over chunk_leaf(shard 0..n), an unpaired last node moving up
//! ```

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Domain, Hash32};

use crate::rs::{lagrange, mul};

/// Most bytes of a compressed PoV.
pub const MAX_POV_COMPRESSED: usize = 5_000_000;
/// Request/response protocol on the validator plane.
pub const CHUNK_PROTOCOL: &str = "/tog/val/1/chunk";
/// Frame type of a [`ChunkRequest`].
pub const CHUNK_REQUEST_TYPE: u8 = 0x01;
/// Frame type of a `ChunkResponse` ([`ErasureChunk`]).
pub const CHUNK_RESPONSE_TYPE: u8 = 0x81;
/// Frame type of an error: one byte, [`ChunkError`].
pub const CHUNK_ERROR_TYPE: u8 = 0xFF;
/// Bytes of a request frame.
pub const CHUNK_REQUEST_LEN: usize = 37;
/// Requests per second served to one peer.
pub const CHUNK_REQUESTS_PER_SEC: u32 = 50;
/// Hub blocks a chunk is still served after its candidate leaves `appchains.candidates`.
pub const CHUNK_RETENTION_BLOCKS: u64 = 1_800;
/// `T_cgmp_keep`: Hub blocks a chunk is still served after its candidate leaves when its
/// `ValidationResult.outbox` changed the head of a channel to an AppChain (`dest ≠ 0`), so the
/// message bodies stay recoverable (TOG-SPEC-0002 §4.5).
pub const CGMP_KEEP_BLOCKS: u64 = 7_200;

/// Blocks the chunks of a candidate with these `outbox` entries are served after it leaves.
pub fn chunk_window(outbox: &[(tog_primitives::ChainId, Hash32, u64)]) -> u64 {
    if outbox.iter().any(|(dest, _, _)| dest.0 != 0) {
        CGMP_KEEP_BLOCKS
    } else {
        CHUNK_RETENTION_BLOCKS
    }
}

/// `(k, m)` for `n` validators: any `k` chunks recover the PoV.
pub fn params(n: usize) -> (usize, usize) {
    let k = n.saturating_sub(1) / 3 + 1;
    (k, n.saturating_sub(k))
}

/// `2 · ⌈len_d / (2k)⌉`.
pub fn shard_size(len_d: usize, k: usize) -> usize {
    2 * len_d.div_ceil(2 * k.max(1))
}

/// Why chunks don't give back a PoV.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ErasureError {
    /// `n` is 0 or above 65 536, or the data is over [`MAX_POV_COMPRESSED`].
    #[error("bad parameters")]
    Params,
    /// Fewer than `k` distinct chunks of one length with valid proofs.
    #[error("not enough chunks")]
    Missing,
    /// The chunks are not a codeword of `erasure_root` (recovery check 1).
    #[error("chunks re-encode to another root")]
    Root,
    /// The framed length is out of range (recovery check 2).
    #[error("bad framed length")]
    Length,
}

/// All `n` chunks of the compressed PoV `c`, in index order.
pub fn encode(c: &[u8], n: usize) -> Result<Vec<Vec<u8>>, ErasureError> {
    if n == 0 || n > 1 << 16 || c.len() > MAX_POV_COMPRESSED {
        return Err(ErasureError::Params);
    }
    let (k, _) = params(n);
    let mut d = Vec::with_capacity(8 + c.len());
    d.extend_from_slice(&(c.len() as u64).to_le_bytes());
    d.extend_from_slice(c);
    let size = shard_size(d.len(), k);
    let data: Vec<Vec<u8>> = (0..k)
        .map(|s| {
            let lo = (s * size).min(d.len());
            let mut shard = d[lo..((s + 1) * size).min(d.len())].to_vec();
            shard.resize(size, 0);
            shard
        })
        .collect();
    Ok(extend(&data, (0..k).collect(), n))
}

/// The `n` shards of the polynomial through `known` shards at points `xs` (as many as `k`).
fn extend(known: &[Vec<u8>], xs: Vec<usize>, n: usize) -> Vec<Vec<u8>> {
    let size = known.first().map_or(0, Vec::len);
    let points: Vec<u16> = xs.iter().map(|&x| x as u16).collect();
    let coeffs: Vec<Option<Vec<u16>>> =
        (0..n).map(|t| if xs.contains(&t) { None } else { Some(lagrange(&points, t as u16)) }).collect();
    let mut out = vec![Vec::new(); n];
    for (t, slot) in out.iter_mut().enumerate() {
        match xs.iter().position(|&x| x == t) {
            Some(i) => *slot = known[i].clone(),
            None => *slot = vec![0u8; size],
        }
    }
    for p in (0..size).step_by(2) {
        let ys: Vec<u16> = known.iter().map(|s| u16::from_le_bytes([s[p], s[p + 1]])).collect();
        for (shard, c) in out.iter_mut().zip(&coeffs) {
            if let Some(c) = c {
                let v = c.iter().zip(&ys).fold(0u16, |acc, (&c, &y)| acc ^ mul(c, y));
                shard[p..p + 2].copy_from_slice(&v.to_le_bytes());
            }
        }
    }
    out
}

/// `chunk_leaf(x)`.
pub fn chunk_leaf(x: &[u8]) -> Hash32 {
    tagged_hash(Domain::ChunkLeaf, &[x])
}

/// `chunk_node(a, b)`.
pub fn chunk_node(a: &Hash32, b: &Hash32) -> Hash32 {
    tagged_hash(Domain::ChunkNode, &[a, b])
}

/// The tree levels over `chunks`' leaves, leaves first, root last.
fn levels(chunks: &[Vec<u8>]) -> Vec<Vec<Hash32>> {
    let mut levels = vec![chunks.iter().map(|c| chunk_leaf(c)).collect::<Vec<_>>()];
    while levels.last().is_some_and(|l| l.len() > 1) {
        let l = levels.last().expect("non-empty");
        let up = l.chunks(2).map(|p| if let [a, b] = p { chunk_node(a, b) } else { p[0] }).collect();
        levels.push(up);
    }
    levels
}

/// `erasure_root` of `chunks`; `[0; 32]` with none.
pub fn erasure_root(chunks: &[Vec<u8>]) -> Hash32 {
    levels(chunks).last().and_then(|l| l.first()).copied().unwrap_or([0; 32])
}

/// One chunk with its proof against `erasure_root`; the `ChunkResponse` body.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ErasureChunk {
    /// Chunk index `i`, the holder's `ValidatorIndex`.
    pub index: u32,
    /// Shard `i`, `shard_size` bytes.
    pub chunk: Vec<u8>,
    /// Siblings from the leaf up; levels where the node is unpaired are skipped.
    pub proof: Vec<Hash32>,
}

impl ErasureChunk {
    /// Every chunk of `chunks` with its proof.
    pub fn all(chunks: Vec<Vec<u8>>) -> Vec<ErasureChunk> {
        let levels = levels(&chunks);
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| {
                let mut proof = Vec::new();
                let mut index = i;
                for l in &levels[..levels.len() - 1] {
                    if let Some(s) = l.get(index ^ 1) {
                        proof.push(*s);
                    }
                    index /= 2;
                }
                ErasureChunk { index: i as u32, chunk, proof }
            })
            .collect()
    }

    /// The proof check for a candidate with `n` chunks: every entry used, the fold equals `root`.
    pub fn verify(&self, root: &Hash32, n: u32) -> bool {
        if self.index >= n {
            return false;
        }
        let (mut index, mut width) = (self.index, n);
        let mut x = chunk_leaf(&self.chunk);
        let mut next = self.proof.iter();
        while width > 1 {
            if index % 2 == 1 {
                let Some(s) = next.next() else { return false };
                x = chunk_node(s, &x);
            } else if index + 1 < width {
                let Some(s) = next.next() else { return false };
                x = chunk_node(&x, s);
            }
            index /= 2;
            width = width.div_ceil(2);
        }
        next.next().is_none() && x == *root
    }
}

/// Recovery (TOG-SPEC-0002 §4.5): from chunks whose proofs check against `root` with `n` chunks,
/// the compressed PoV `c`, if the first `k` distinct indices of one length re-encode to `root`
/// and the framed length is in range. Decompressing `c` and checking `pov_hash` are the caller's.
pub fn recover(chunks: &[ErasureChunk], root: &Hash32, n: usize) -> Result<Vec<u8>, ErasureError> {
    if n == 0 || n > 1 << 16 {
        return Err(ErasureError::Params);
    }
    let (k, _) = params(n);
    let mut held: Vec<&ErasureChunk> = Vec::with_capacity(k);
    for c in chunks {
        let len_ok = held.first().map_or(true, |h| h.chunk.len() == c.chunk.len()) && c.chunk.len() % 2 == 0;
        if held.len() < k && len_ok && !held.iter().any(|h| h.index == c.index) && c.verify(root, n as u32) {
            held.push(c);
        }
    }
    if held.len() < k {
        return Err(ErasureError::Missing);
    }
    let xs = held.iter().map(|c| c.index as usize).collect();
    let known: Vec<Vec<u8>> = held.iter().map(|c| c.chunk.clone()).collect();
    let all = extend(&known, xs, n);
    if erasure_root(&all) != *root {
        return Err(ErasureError::Root);
    }
    let d: Vec<u8> = all.into_iter().take(k).flatten().collect();
    let len = d.get(..8).map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes"))).ok_or(ErasureError::Length)?;
    if len > MAX_POV_COMPRESSED as u64 || 8 + len > d.len() as u64 {
        return Err(ErasureError::Length);
    }
    Ok(d[8..8 + len as usize].to_vec())
}

/// `0x01 ChunkRequest`: chunk `index` of candidate `candidate` (its `candidate_hash`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChunkRequest {
    /// `candidate_hash`.
    pub candidate: Hash32,
    /// Chunk index.
    pub index: u32,
}

impl ChunkRequest {
    /// `0x01 ‖ borsh(self)`.
    pub fn encode_frame(&self) -> Vec<u8> {
        let mut m = vec![CHUNK_REQUEST_TYPE];
        m.extend_from_slice(&borsh::to_vec(self).expect("in-memory borsh cannot fail"));
        m
    }

    /// A request frame, if it is exactly one.
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        match msg.split_first() {
            Some((&CHUNK_REQUEST_TYPE, body)) if msg.len() == CHUNK_REQUEST_LEN => borsh::from_slice(body).ok(),
            _ => None,
        }
    }
}

/// `0xFF Error` codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkError {
    /// 0.
    BadRequest = 0,
    /// 1.
    NotAvailable = 1,
    /// 2.
    Busy = 2,
}

/// A response frame: a chunk or an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkResponse {
    /// `0x81`.
    Chunk(ErasureChunk),
    /// `0xFF`.
    Error(ChunkError),
}

impl ChunkResponse {
    /// The frame.
    pub fn encode_frame(&self) -> Vec<u8> {
        match self {
            ChunkResponse::Chunk(c) => {
                let mut m = vec![CHUNK_RESPONSE_TYPE];
                m.extend_from_slice(&borsh::to_vec(c).expect("in-memory borsh cannot fail"));
                m
            }
            ChunkResponse::Error(e) => vec![CHUNK_ERROR_TYPE, *e as u8],
        }
    }

    /// A response frame, if it is exactly one.
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        match msg.split_first()? {
            (&CHUNK_RESPONSE_TYPE, body) => borsh::from_slice(body).ok().map(ChunkResponse::Chunk),
            (&CHUNK_ERROR_TYPE, [0]) => Some(ChunkResponse::Error(ChunkError::BadRequest)),
            (&CHUNK_ERROR_TYPE, [1]) => Some(ChunkResponse::Error(ChunkError::NotAvailable)),
            (&CHUNK_ERROR_TYPE, [2]) => Some(ChunkResponse::Error(ChunkError::Busy)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
