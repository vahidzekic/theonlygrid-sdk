//! Content identity of stored payloads (TOG-SPEC-0004 §2.2).

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Domain, Hash32};

use crate::job::EnclavePolicyId;

/// Content identity. Two payloads with equal `(root, size)` are the same bytes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PayloadCommitment {
    /// Format version, 1.
    pub version: u8,
    /// BLAKE3 root of the stored bytes (the ciphertext if encrypted).
    pub root: Hash32,
    /// Stored size in bytes.
    pub size: u64,
    /// Transfer piece size, `20..=22`; not part of identity.
    pub piece_log2: u8,
    /// What the payload is.
    pub kind: PayloadKind,
    /// sha256 of an OCI blob, if any.
    pub oci_digest: Option<[u8; 32]>,
    /// Encryption layer.
    pub encryption: Encryption,
}

/// Payload kinds, in the order TOG-SPEC-0004 §2.2 lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum PayloadKind {
    /// Image layer, config or manifest.
    Image,
    /// Job input.
    Input,
    /// Encrypted segment checkpoint.
    Checkpoint,
    /// Job output.
    Output,
    /// A dissenting verifier's output (TOG-SPEC-0003 §4).
    VerifierOutput,
}

/// Encryption of the stored bytes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Encryption {
    /// Plaintext.
    None,
    /// TOG-SPEC-0003 temporal encryption; the key is released on-chain at V4/V6.
    Checkpoint {
        /// Root of the plaintext.
        plaintext_root: Hash32,
        /// `H("TOG/v1/ckpt-key" ‖ k)`.
        key_commitment: Hash32,
    },
    /// T3 confidentiality layer under a job key held only by attested enclaves.
    Confidential {
        /// Root of the inner layer.
        inner_root: Hash32,
        /// Enclaves allowed to hold the key.
        policy: EnclavePolicyId,
    },
}

impl PayloadCommitment {
    /// Deal and challenge key `H("TOG/v1/payload" ‖ root ‖ u64 size)`; layout never changes identity.
    pub fn id(&self) -> Hash32 {
        tagged_hash(Domain::Payload, &[&self.root, &self.size.to_le_bytes()])
    }

    /// Version 1, `kind`, and a transfer piece size of 1–4 MiB (TOG-SPEC-0004 §2.2).
    pub fn is_v1(&self, kind: PayloadKind) -> bool {
        self.version == 1 && self.kind == kind && (20..=22).contains(&self.piece_log2)
    }
}

/// Which pieces of a payload are in a partially staged CAS file (TOG-SPEC-0001 §4.5), Borsh in
/// `cas/in/<root>.pieces`. Lets the executor verify a partial payload against its root.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PieceMap {
    /// `PayloadCommitment.size`.
    pub size: u64,
    /// `PayloadCommitment.piece_log2`.
    pub piece_log2: u8,
    /// BLAKE3 chaining value of every piece's subtree, in order; one per piece.
    pub piece_cvs: Vec<Hash32>,
    /// Ascending indices of the pieces written into the file.
    pub present: Vec<u64>,
}

/// Why a [`PieceMap`] does not describe a payload.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PieceMapError {
    /// `piece_log2` outside `20..=22`.
    #[error("piece size out of range")]
    PieceSize,
    /// A payload of one piece is never staged in part; or `piece_cvs` has the wrong count.
    #[error("piece count does not match the size")]
    Count,
    /// `present` not strictly ascending, or past the last piece.
    #[error("present pieces out of order or range")]
    Present,
    /// The pieces do not merge to the payload root.
    #[error("piece chaining values do not merge to the root")]
    Root,
}

impl PieceMap {
    /// Number of pieces of a `size`-byte payload in `2^piece_log2`-byte pieces.
    pub fn piece_count(size: u64, piece_log2: u8) -> u64 {
        size.div_ceil(1 << piece_log2)
    }

    /// The chaining value of piece `index` with content `bytes` (a whole piece, or the short last one).
    pub fn piece_cv(piece_log2: u8, index: u64, bytes: &[u8]) -> Hash32 {
        use blake3::hazmat::HasherExt;
        blake3::Hasher::new().set_input_offset(index << piece_log2).update(bytes).finalize_non_root()
    }

    /// Checks the map's shape and that `piece_cvs` merge to `root` with BLAKE3's parent function.
    /// Each present piece must then hash to its entry with [`PieceMap::piece_cv`] when it is read.
    pub fn check(&self, root: &Hash32) -> Result<(), PieceMapError> {
        if !(20..=22).contains(&self.piece_log2) {
            return Err(PieceMapError::PieceSize);
        }
        let n = Self::piece_count(self.size, self.piece_log2);
        if n < 2 || self.piece_cvs.len() as u64 != n {
            return Err(PieceMapError::Count);
        }
        if self.present.windows(2).any(|w| w[0] >= w[1]) || self.present.last().is_some_and(|&p| p >= n) {
            return Err(PieceMapError::Present);
        }
        if &self.merge(0, self.size, true) != root {
            return Err(PieceMapError::Root);
        }
        Ok(())
    }

    /// CV of the subtree over bytes `lo..hi`, which start on a piece boundary and span at least two pieces
    /// when `hi - lo` exceeds one piece; the root hash if `root`.
    fn merge(&self, lo: u64, hi: u64, root: bool) -> Hash32 {
        use blake3::hazmat::{left_subtree_len, merge_subtrees_non_root, merge_subtrees_root, Mode};
        if hi - lo <= 1 << self.piece_log2 {
            return self.piece_cvs[(lo >> self.piece_log2) as usize];
        }
        // A piece is a whole number of power-of-two chunks, so the split falls on a piece boundary.
        let mid = lo + left_subtree_len(hi - lo);
        let (l, r) = (self.merge(lo, mid, false), self.merge(mid, hi, false));
        if root {
            *merge_subtrees_root(&l, &r, Mode::Hash).as_bytes()
        } else {
            merge_subtrees_non_root(&l, &r, Mode::Hash)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_ignores_layout() {
        let a = PayloadCommitment {
            version: 1,
            root: [1; 32],
            size: 10,
            piece_log2: 20,
            kind: PayloadKind::Output,
            oci_digest: None,
            encryption: Encryption::None,
        };
        let b = PayloadCommitment { piece_log2: 22, kind: PayloadKind::VerifierOutput, ..a.clone() };
        assert_eq!(a.id(), b.id());
        assert_ne!(a.id(), PayloadCommitment { size: 11, ..a }.id());
    }

    fn piece_map(bytes: &[u8], piece_log2: u8) -> PieceMap {
        let piece_cvs = bytes
            .chunks(1 << piece_log2)
            .enumerate()
            .map(|(i, b)| PieceMap::piece_cv(piece_log2, i as u64, b))
            .collect();
        PieceMap { size: bytes.len() as u64, piece_log2, piece_cvs, present: vec![0] }
    }

    #[test]
    fn piece_cvs_merge_to_the_blake3_root() {
        for (len, log2) in [(2 << 20, 20), ((5 << 20) + 7, 20), ((3 << 21) + 1, 21), (9 << 22, 22), ((1 << 20) + 1, 20)]
        {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let root = *blake3::hash(&bytes).as_bytes();
            let map = piece_map(&bytes, log2);
            assert_eq!(map.check(&root), Ok(()), "len {len} log2 {log2}");
            let mut bad = map.clone();
            bad.piece_cvs[1][0] ^= 1;
            assert_eq!(bad.check(&root), Err(PieceMapError::Root));
        }
    }

    #[test]
    fn piece_map_shape() {
        let bytes = vec![7u8; 3 << 20];
        let root = *blake3::hash(&bytes).as_bytes();
        let map = piece_map(&bytes, 20);
        let with = |f: fn(&mut PieceMap)| {
            let mut m = map.clone();
            f(&mut m);
            m.check(&root)
        };
        assert_eq!(with(|m| m.present = vec![0, 2]), Ok(()));
        assert_eq!(with(|m| m.present = vec![2, 0]), Err(PieceMapError::Present));
        assert_eq!(with(|m| m.present = vec![1, 1]), Err(PieceMapError::Present));
        assert_eq!(with(|m| m.present = vec![3]), Err(PieceMapError::Present));
        assert_eq!(with(|m| m.piece_log2 = 19), Err(PieceMapError::PieceSize));
        assert_eq!(with(|m| m.size = 1 << 20), Err(PieceMapError::Count));
        assert_eq!(
            with(|m| {
                m.piece_cvs.pop();
            }),
            Err(PieceMapError::Count)
        );
    }
}
