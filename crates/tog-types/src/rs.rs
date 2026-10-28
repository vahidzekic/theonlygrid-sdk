//! Reed–Solomon layout of `LongTerm` deals (TOG-SPEC-0004 §5.6.1).
//!
//! Systematic RS(k, m) over GF(2¹⁶), striped by 4 KiB rows. The `k` data symbols at one position
//! of one row are the values `P(0) … P(k − 1)` of a polynomial of degree `< k`; parity symbol `p`
//! is `P(k + p)`. Integers are read as field elements by their bits.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
#[cfg(feature = "std")]
use std::sync::OnceLock;

use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::payload::CHUNK_4K;
use tog_primitives::{tagged_hash, Address, Domain, Hash32};

use crate::job::DealId;
use crate::payload::{Encryption, PayloadCommitment, PayloadKind};
use crate::por::ChunkOpening;
use crate::storage::{PayloadSetLeaf, ReplayGuard, SetFrontier};

/// Field polynomial x¹⁶ + x⁵ + x³ + x² + 1.
const POLY: u32 = 0x1002D;
/// Most shards of one deal.
pub const MAX_SHARDS: usize = 64;

/// `TxBody` variant 22. The beacon-chosen encoder posts the RS shard roots (TOG-SPEC-0004 §5.6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PostEncodingTx {
    /// Deal.
    pub deal: DealId,
    /// Payload set tree root over the `k + m` shard leaves.
    pub shard_roots: Hash32,
    /// Bytes per shard.
    pub shard_size: u64,
}

/// The replica slot (0 or 1) that encodes, from the beacon of the block `h_a` that includes the
/// second replica ack: `u64_le(H("TOG/v1/encoder" ‖ B(h_a) ‖ u64 deal_id)[0..8]) mod 2`, with
/// `B(h_a) = HubBeacon(h_a − 1)` (TOG-SPEC-0002 §3.2).
pub fn encoder_slot(beacon: &[u8; 32], deal: DealId) -> u16 {
    let h = tagged_hash(Domain::Encoder, &[beacon, &deal.0.to_le_bytes()]);
    (u64::from_le_bytes(h[..8].try_into().expect("8 bytes")) % 2) as u16
}

/// `TxBody` variant 24: proof that a deal's encoder posted shards that are not the RS code of the
/// deal's data (TOG-SPEC-0004 §5.6.1). Signed by any account.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EncodingFraudTx {
    /// Submitter; the challenger of the slash split.
    pub submitter: Address,
    /// Deal.
    pub deal: DealId,
    /// The proof.
    pub proof: EncodingFraud,
    /// The submitter's next nonce.
    pub replay: ReplayGuard,
}

/// What an [`EncodingFraudTx`] proves. Shard openings are RS slot openings against `shard_roots`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum EncodingFraud {
    /// 0: row `row` of the `k` data shards (openings with `slot` = shard `0..k`, ascending) and of
    /// parity shard `parity.slot`, where symbol `symbol` (`0..2048`) of the parity row is not
    /// `P(slot)`.
    Parity {
        /// Row.
        row: u64,
        /// Symbol position in the row.
        symbol: u16,
        /// The `k` data rows.
        data: Vec<ChunkOpening>,
        /// The parity row.
        parity: ChunkOpening,
    },
    /// 1: byte `byte` (`0..4096`) of row `shard.chunk_index` of data shard `shard.slot < k`
    /// differs from the deal's data at `o = shard.slot · shard_size + 4096 · row + byte`.
    Data {
        /// The data shard row.
        shard: ChunkOpening,
        /// Byte in the row.
        byte: u16,
        /// The chunk holding `D[o]`, against the payload set root; `None` iff `o ≥ total_size`,
        /// where the shard byte must be 0.
        payload: Option<ChunkOpening>,
    },
}

#[cfg(feature = "std")]
struct Tables {
    exp: Vec<u16>,
    log: Vec<u16>,
}

#[cfg(feature = "std")]
fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut exp = vec![0u16; 2 * 65535];
        let mut log = vec![0u16; 65536];
        let mut x: u32 = 1;
        for (i, e) in exp.iter_mut().take(65535).enumerate() {
            *e = x as u16;
            log[x as usize] = i as u16;
            x <<= 1;
            if x & 0x10000 != 0 {
                x ^= POLY;
            }
        }
        assert_eq!(x, 1, "x generates GF(2^16)*");
        for i in 65535..2 * 65535 {
            exp[i] = exp[i - 65535];
        }
        Tables { exp, log }
    })
}

/// Product in GF(2¹⁶).
#[cfg(feature = "std")]
pub fn mul(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

/// Product in GF(2¹⁶).
#[cfg(not(feature = "std"))]
pub fn mul(a: u16, b: u16) -> u16 {
    mul_slow(a, b)
}

/// Product in GF(2¹⁶) without tables (no `std`: no lazy statics).
#[cfg(any(test, not(feature = "std")))]
fn mul_slow(a: u16, b: u16) -> u16 {
    let (mut a, mut b, mut p) = (a as u32, b, 0u32);
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0x10000 != 0 {
            a ^= POLY;
        }
    }
    p as u16
}

/// Inverse in GF(2¹⁶); `a ≠ 0`.
#[cfg(feature = "std")]
fn inv(a: u16) -> u16 {
    assert_ne!(a, 0, "zero has no inverse");
    let t = tables();
    t.exp[65535 - t.log[a as usize] as usize]
}

/// Inverse in GF(2¹⁶); `a ≠ 0`.
#[cfg(not(feature = "std"))]
fn inv(a: u16) -> u16 {
    inv_slow(a)
}

/// `a^(2¹⁶ − 2)`, the inverse of `a ≠ 0`, without tables.
#[cfg(any(test, not(feature = "std")))]
fn inv_slow(a: u16) -> u16 {
    assert_ne!(a, 0, "zero has no inverse");
    let (mut base, mut e, mut r) = (a, 65534u32, 1u16);
    while e != 0 {
        if e & 1 != 0 {
            r = mul_slow(r, base);
        }
        base = mul_slow(base, base);
        e >>= 1;
    }
    r
}

/// Lagrange coefficients: `P(x) = Σ c_i · y_i` for the polynomial through `(xs[i], y_i)`.
pub(crate) fn lagrange(xs: &[u16], x: u16) -> Vec<u16> {
    xs.iter()
        .enumerate()
        .map(|(i, &xi)| {
            xs.iter().enumerate().filter(|&(j, _)| j != i).fold(1u16, |acc, (_, &xj)| {
                // In characteristic 2, subtraction is XOR.
                mul(acc, mul(x ^ xj, inv(xi ^ xj)))
            })
        })
        .collect()
}

/// Multiplication by one constant `c`, split by byte: `c · x = lo[x & 0xff] ⊕ hi[x >> 8]`, since
/// multiplying by `c` is linear over GF(2).
#[derive(Clone)]
struct MulTable {
    lo: [u16; 256],
    hi: [u16; 256],
}

impl core::fmt::Debug for MulTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MulTable({})", self.lo[1])
    }
}

impl MulTable {
    fn new(c: u16) -> Self {
        let mut t = Self { lo: [0; 256], hi: [0; 256] };
        for b in 0..256u16 {
            t.lo[b as usize] = mul(c, b);
            t.hi[b as usize] = mul(c, b << 8);
        }
        t
    }

    /// `c · x`.
    #[inline(always)]
    fn mul(&self, x: [u8; 2]) -> u16 {
        self.lo[x[0] as usize] ^ self.hi[x[1] as usize]
    }
}

/// Symbols of each row combined at a time: the `m` accumulators stay in L1 across the `k` inputs.
const BLOCK: usize = 512;

/// `out[o] = Σ_i c[o][i] · src[i]` over equal even-length ranges, block by block, each input
/// read once per block into every output's accumulator.
fn combine(tables: &[Vec<MulTable>], src: &[&[u8]], out: &mut [&mut [u8]]) {
    let len = src.first().map_or(0, |s| s.len());
    let mut acc = vec![[0u16; BLOCK]; out.len()];
    let mut lo = 0;
    while lo < len {
        let hi = len.min(lo + 2 * BLOCK);
        let n = (hi - lo) / 2;
        for a in &mut acc {
            a[..n].fill(0);
        }
        for (i, s) in src.iter().enumerate() {
            for (a, ts) in acc.iter_mut().zip(tables) {
                let t = &ts[i];
                for (a, x) in a[..n].iter_mut().zip(s[lo..hi].chunks_exact(2)) {
                    *a ^= t.mul([x[0], x[1]]);
                }
            }
        }
        for (row, a) in out.iter_mut().zip(&acc) {
            for (d, v) in row[lo..hi].chunks_exact_mut(2).zip(&a[..n]) {
                d.copy_from_slice(&v.to_le_bytes());
            }
        }
        lo = hi;
    }
}

/// RS(k, m) parameters with the parity coefficients precomputed.
#[derive(Clone, Debug)]
pub struct RsCode {
    k: usize,
    m: usize,
    /// `parity[p][i]`: multiplication by the weight of data symbol `i` in parity symbol `p`.
    parity: Vec<Vec<MulTable>>,
}

/// Invalid RS parameters or shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RsError {
    /// `k` or `m` is 0, or `k + m > 64`.
    #[error("RS needs 1 <= k, 1 <= m, k + m <= 64")]
    Params,
    /// Rows of the wrong count or length.
    #[error("rows do not match the code")]
    Shape,
}

impl RsCode {
    /// RS(k, m).
    pub fn new(k: u8, m: u8) -> Result<Self, RsError> {
        let (k, m) = (k as usize, m as usize);
        if k == 0 || m == 0 || k + m > MAX_SHARDS {
            return Err(RsError::Params);
        }
        let xs: Vec<u16> = (0..k as u16).collect();
        let parity = (0..m).map(|p| lagrange(&xs, (k + p) as u16).into_iter().map(MulTable::new).collect()).collect();
        Ok(Self { k, m, parity })
    }

    /// Symbol `symbol` (`0..2048`) of parity row `p` (`0..m`) of one stripe of `k` data rows of
    /// 4 KiB, without building the code: the same value as `parity_rows(data)[p][2·symbol..][..2]`
    /// read little-endian, in `O(k²)` field operations for the one Lagrange weight row instead of
    /// all `m` rows of 2 048 symbols. What an `EncodingFraud::Parity` check needs.
    pub fn parity_symbol(k: u8, m: u8, data: &[&[u8]], p: usize, symbol: usize) -> Result<u16, RsError> {
        let (k, m) = (k as usize, m as usize);
        if k == 0 || m == 0 || k + m > MAX_SHARDS {
            return Err(RsError::Params);
        }
        if data.len() != k || data.iter().any(|r| r.len() != CHUNK_4K) || p >= m || symbol >= CHUNK_4K / 2 {
            return Err(RsError::Shape);
        }
        let xs: Vec<u16> = (0..k as u16).collect();
        let t = 2 * symbol;
        Ok(lagrange(&xs, (k + p) as u16)
            .into_iter()
            .zip(data)
            .fold(0u16, |acc, (c, r)| acc ^ mul(c, u16::from_le_bytes([r[t], r[t + 1]]))))
    }

    /// Data shards.
    pub fn k(&self) -> usize {
        self.k
    }

    /// Parity shards.
    pub fn m(&self) -> usize {
        self.m
    }

    /// The `m` parity rows of one stripe of `k` data rows, each 4 KiB.
    pub fn parity_rows(&self, data: &[&[u8]]) -> Result<Vec<Vec<u8>>, RsError> {
        if data.len() != self.k || data.iter().any(|r| r.len() != CHUNK_4K) {
            return Err(RsError::Shape);
        }
        let mut out = vec![vec![0u8; CHUNK_4K]; self.m];
        self.parity_into(data, &mut out.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>())?;
        Ok(out)
    }

    /// The `m` parity ranges of the same byte range of the `k` data shards, written into `out`.
    /// Parity is symbol by symbol, so any range works that starts on a symbol: `parity_rows` of
    /// each 4 KiB row in it, side by side. All ranges have one even length.
    pub fn parity_into(&self, data: &[&[u8]], out: &mut [&mut [u8]]) -> Result<(), RsError> {
        let len = data.first().map_or(0, |r| r.len());
        if data.len() != self.k
            || out.len() != self.m
            || len % 2 != 0
            || data.iter().any(|r| r.len() != len)
            || out.iter().any(|r| r.len() != len)
        {
            return Err(RsError::Shape);
        }
        combine(&self.parity, data, out);
        Ok(())
    }

    /// True if the `k + m` rows at one row index (shard order) are a codeword: the polynomial
    /// through the data symbols gives every parity symbol. A `false` is the bad-encoding proof.
    pub fn is_codeword(&self, rows: &[&[u8]]) -> Result<bool, RsError> {
        if rows.len() != self.k + self.m {
            return Err(RsError::Shape);
        }
        let parity = self.parity_rows(&rows[..self.k])?;
        Ok(parity.iter().zip(&rows[self.k..]).all(|(a, b)| a.as_slice() == *b))
    }

    /// Rebuilds the same byte range of shards `targets` from that range of `k` other shards,
    /// given as `(shard index, bytes)`: every symbol is interpolated through the `k` known ones
    /// (§5.6.1, retrieval §6.1). The ranges must have one even length and start on a symbol.
    pub fn recover(&self, known: &[(usize, &[u8])], targets: &[usize]) -> Result<Vec<Vec<u8>>, RsError> {
        let len = known.first().map_or(0, |(_, b)| b.len());
        let mut out = vec![vec![0u8; len]; targets.len()];
        self.recover_into(known, targets, &mut out.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>())?;
        Ok(out)
    }

    /// [`recover`](Self::recover) into `out`, one range per target, each as long as the known ones.
    pub fn recover_into(
        &self,
        known: &[(usize, &[u8])],
        targets: &[usize],
        out: &mut [&mut [u8]],
    ) -> Result<(), RsError> {
        let n = self.k + self.m;
        let len = known.first().map_or(0, |(_, b)| b.len());
        let mut seen = 0u64;
        for &(i, b) in known {
            if i >= n || seen >> i & 1 == 1 || b.len() != len {
                return Err(RsError::Shape);
            }
            seen |= 1 << i;
        }
        if known.len() != self.k
            || len % 2 != 0
            || targets.iter().any(|&t| t >= n)
            || out.len() != targets.len()
            || out.iter().any(|r| r.len() != len)
        {
            return Err(RsError::Shape);
        }
        let xs: Vec<u16> = known.iter().map(|&(i, _)| i as u16).collect();
        let tables: Vec<Vec<MulTable>> =
            targets.iter().map(|&t| lagrange(&xs, t as u16).into_iter().map(MulTable::new).collect()).collect();
        let src: Vec<&[u8]> = known.iter().map(|&(_, b)| b).collect();
        combine(&tables, &src, out);
        Ok(())
    }

    /// All `k + m` shards of `data` (the deal's payloads concatenated in leaf order).
    pub fn encode(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let shard_size = shard_size(data.len() as u64, self.k as u8) as usize;
        let mut shards: Vec<Vec<u8>> = (0..self.k)
            .map(|s| {
                let lo = (s * shard_size).min(data.len());
                let hi = ((s + 1) * shard_size).min(data.len());
                let mut shard = data[lo..hi].to_vec();
                shard.resize(shard_size, 0);
                shard
            })
            .collect();
        let mut parity = vec![vec![0u8; shard_size]; self.m];
        let data: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
        self.parity_into(&data, &mut parity.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>())
            .expect("k shards of one size");
        shards.extend(parity);
        shards
    }

    /// The set leaves of `shards` and their `shard_roots` (TOG-SPEC-0004 §5.6.1).
    pub fn shard_roots(shards: &[Vec<u8>]) -> (Vec<PayloadSetLeaf>, Hash32) {
        let payloads: Vec<PayloadCommitment> = shards
            .iter()
            .map(|s| PayloadCommitment {
                version: 1,
                root: *blake3::hash(s).as_bytes(),
                size: s.len() as u64,
                piece_log2: 20,
                kind: PayloadKind::Output,
                oci_digest: None,
                encryption: Encryption::None,
            })
            .collect();
        let mut set = SetFrontier::new();
        let leaves = set.append(&payloads).expect("at most 64 shards");
        (leaves, set.set.root)
    }
}

/// `4096 · ⌈total_size / (4096 · k)⌉`.
pub fn shard_size(total_size: u64, k: u8) -> u64 {
    CHUNK_4K as u64 * total_size.div_ceil(CHUNK_4K as u64 * u64::from(k))
}

#[cfg(test)]
mod tests;
