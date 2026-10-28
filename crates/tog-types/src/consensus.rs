//! Hub consensus messages and system-lane items (TOG-SPEC-0002 §3.1, §5).
//!
//! The Hub's round state machine, signing and validation stay in `tog-hub`; these are the types
//! that blocks and evidence carry, so that `togd` and light clients decode them without it.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::Hash32;

use crate::hub_key::ReleasedKeys;

/// Position of a validator in the era's validator set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct ValidatorIndex(pub u16);

/// Round within a height.
pub type Round = u32;

/// Prevote or precommit; Borsh indices 0, 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub enum VoteKind {
    /// First voting phase.
    Prevote,
    /// Second voting phase; a quorum commits the block.
    Precommit,
}

/// A vote. `value: None` is a vote for nil.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Vote {
    /// Height.
    pub height: u64,
    /// Round.
    pub round: Round,
    /// Phase.
    pub kind: VoteKind,
    /// Header hash, or nil.
    pub value: Option<Hash32>,
    /// Who voted.
    pub validator: ValidatorIndex,
}

/// A block proposal.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proposal {
    /// Height.
    pub height: u64,
    /// Round.
    pub round: Round,
    /// Hash of the proposed header.
    pub value: Hash32,
    /// Round in which `value` got a prevote quorum, if it is re-proposed (`validRound`).
    pub pol_round: Option<Round>,
    /// Who proposed it.
    pub proposer: ValidatorIndex,
    /// Merkle root of the gossip parts of `borsh(FullBlock)` (TOG-SPEC-0006 §2.1).
    pub parts_root: Hash32,
    /// Number of gossip parts, `1..=64`.
    pub parts: u16,
}

/// A vote with its Ed25519 signature over `H("TOG/v1/hub-vote" ‖ borsh((chain_id, vote)))`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SignedVote {
    /// The vote.
    pub vote: Vote,
    /// Ed25519 signature.
    pub sig: [u8; 64],
}

/// A proposal with its Ed25519 signature over `H("TOG/v1/hub-proposal" ‖ borsh((chain_id, proposal)))`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SignedProposal {
    /// The proposal.
    pub proposal: Proposal,
    /// Ed25519 signature.
    pub sig: [u8; 64],
}

/// A dealer's Groth21 resharing dealing, posted in the system lane (TOG-SPEC-0009 §2.2, §2.3).
/// G1 points are 48-byte compressed, scalars 32 bytes big-endian and `< r`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ResharingDealing {
    /// `e`: the dealer's era; receivers are the set of era `e + 1`, in election order.
    pub era: u64,
    /// Epoch of the Hub key being reshared.
    pub ek_epoch: u32,
    /// Index of the dealer in era `e`'s set.
    pub dealer: ValidatorIndex,
    /// Feldman commitments `A_0..A_{t'−1}` in G1, `t'` the threshold of era `e + 1`; `A_0` must
    /// equal the dealer's `EK_i`.
    pub commitments: Vec<[u8; 48]>,
    /// Chunked ElGamal encryptions of the shares.
    pub ciphertexts: ChunkedCiphertexts,
    /// Every chunk is small (Groth21 §6.5).
    pub chunking_proof: ChunkingProof,
    /// The chunks encrypt shares on `commitments` (Groth21 §6.4, commitments in G1).
    pub sharing_proof: SharingProof,
    /// The dealer's consensus key over [`ResharingDealing::signing_hash`].
    pub sig: [u8; 64],
}

/// Which transcript a dealing is for (TOG-SPEC-0009 §2.2): a fresh DKG (the genesis key) or the
/// resharing of a key. The dealer signs it with the dealing, so a dealing of one kind never
/// verifies as the other: a genesis dealing, whose `A_0` is random, can't be posted as an
/// invalid resharing of the same `(era, ek_epoch)`. Borsh indices 0, 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum DealingKind {
    /// A fresh DKG.
    Fresh,
    /// A resharing of the key of `ek_epoch`.
    Reshare,
}

impl ResharingDealing {
    /// `H("TOG/v1/dkg-dealing" ‖ borsh((chain_id, kind, every field before sig)))`.
    pub fn signing_hash(&self, chain_id: u64, kind: DealingKind) -> Hash32 {
        let fields = (
            chain_id,
            kind,
            self.era,
            self.ek_epoch,
            self.dealer,
            &self.commitments,
            &self.ciphertexts,
            &self.chunking_proof,
            &self.sharing_proof,
        );
        tog_primitives::tagged_hash(
            tog_primitives::Domain::DkgDealing,
            &[&borsh::to_vec(&fields).expect("in-memory borsh cannot fail")],
        )
    }
}

/// Chunks per share: 16 chunks of 16 bits, most significant first.
pub const DKG_CHUNKS: usize = 16;

/// Chunked ElGamal in G1 (TOG-SPEC-0009 §2.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChunkedCiphertexts {
    /// `R_j = r_j · g1` per chunk position `j`.
    pub rand_r: [[u8; 48]; DKG_CHUNKS],
    /// Per receiver `i`: `C_ij = r_j · pk_i + m_ij · g1`.
    pub chunks: Vec<[[u8; 48]; DKG_CHUNKS]>,
}

/// Proof of chunking (Groth21 §6.5, ElGamal in G1); lengths follow Groth21 for `n` receivers.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChunkingProof {
    /// `y0`.
    pub y0: [u8; 48],
    /// `bb`.
    pub bb: Vec<[u8; 48]>,
    /// `cc`.
    pub cc: Vec<[u8; 48]>,
    /// `dd`.
    pub dd: Vec<[u8; 48]>,
    /// `yy`.
    pub yy: [u8; 48],
    /// `z_r`.
    pub z_r: Vec<[u8; 32]>,
    /// `z_s`.
    pub z_s: Vec<[u8; 32]>,
    /// `z_β`.
    pub z_beta: [u8; 32],
}

/// Proof of sharing (Groth21 §6.4, commitments in G1, no pairing).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SharingProof {
    /// `ff`.
    pub ff: [u8; 48],
    /// `aa`.
    pub aa: [u8; 48],
    /// `yy`.
    pub yy: [u8; 48],
    /// `z_r`.
    pub z_r: [u8; 32],
    /// `z_α`.
    pub z_alpha: [u8; 32],
}

/// A receiver's proof that one chunk of a dealing is out of range (TOG-SPEC-0009 §2.2 "Complaint
/// against an out-of-range chunk"): `M_ij = C_ij − x_i · R_j` with a Chaum–Pedersen proof that
/// `log_g(pk_i) = log_{R_j}(C_ij − M_ij)`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DealingComplaint {
    /// The dealing's `era`.
    pub era: u64,
    /// The dealing's `ek_epoch`: with `era`, its transcript (1 for a genesis dealing).
    pub ek_epoch: u32,
    /// 0 a genesis dealing (`threshold_key.genesis_dealings`), 1 a resharing dealing
    /// (`threshold_key.dealings`).
    pub kind: u8,
    /// The dealing's dealer.
    pub dealer: u16,
    /// `i`: index into the dealing's receiver keys.
    pub receiver: u16,
    /// `j ∈ 0..m`.
    pub chunk: u8,
    /// `M_ij`, compressed G1.
    pub m: [u8; 48],
    /// Chaum–Pedersen `(c, z)`, scalars big-endian like the other Groth21 proofs.
    pub proof: ([u8; 32], [u8; 32]),
}

/// A payload whose type its section doesn't specify yet. It holds no bytes; a block carrying
/// one is invalid until the type is specified (TOG-SPEC-0002 §5), and the variant only keeps
/// the indices after it in place.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Unspecified;

/// Equivocation and other provable offences (TOG-SPEC-0002 §6.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Evidence {
    /// 0: two votes of the same `(height, round, validator, kind)` with different values.
    DuplicateVote {
        /// One vote.
        a: SignedVote,
        /// The other.
        b: SignedVote,
    },
    /// 1: two proposals of the same `(height, round, proposer)` with different values.
    DuplicateProposal {
        /// One proposal.
        a: SignedProposal,
        /// The other.
        b: SignedProposal,
    },
    /// 2: a conflicting bridge commitment (TOG-SPEC-0008 §3.5); reserved.
    BridgeCommitment(Unspecified),
    /// 3: a signed dealing that fails verification (TOG-SPEC-0009 §2.3).
    InvalidDealing(Box<ResharingDealing>),
    /// 4: a signed vote extension whose beacon or mempool share is wrong (§6.2 "Invalid beacon
    /// share (exact)").
    InvalidBeaconShare(SignedExtension),
    /// 5: two commit certificates for different blocks at one height (§6.3).
    ConflictingCommits {
        /// The height both commit.
        height: u64,
        /// One block hash and its certificate.
        a: (Hash32, CommitCertificate),
        /// The other.
        b: (Hash32, CommitCertificate),
    },
    /// 6: an out-of-range chunk of a dealing (TOG-SPEC-0009 §2.2, §6.2).
    UndecryptableDealing(DealingComplaint),
}

/// A precommit's vote extension as gossiped (TOG-SPEC-0006 §2.1), signed with the validator's
/// Ed25519 consensus key over `H("TOG/v1/hub-vote-ext" ‖ borsh((chain_id, height, round,
/// validator, extension)))` (§3.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SignedExtension {
    /// Height of the precommit.
    pub height: u64,
    /// Round of the precommit.
    pub round: Round,
    /// The signer.
    pub validator: ValidatorIndex,
    /// `borsh(Vec<[u8; 96]>)`, one share per `release_set` entry (TOG-SPEC-0009 §3.1).
    pub extension: Vec<u8>,
    /// Ed25519 signature.
    pub sig: [u8; 64],
}

/// Which validators signed, one bit per [`ValidatorIndex`], least significant bit first.
///
/// Encoded as a `BitVec` (TOG-SPEC-0000 §13): `len` as a `u16` (little-endian), then exactly
/// `⌈len / 8⌉` raw bytes, with no length prefix of their own. Only canonical bitmaps decode
/// ([`SignerBitmap::is_canonical`]): no bit set past `len`, so a bit no validator owns can never
/// count toward a quorum (B41-1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignerBitmap {
    len: u16,
    bits: Vec<u8>,
}

impl SignerBitmap {
    /// A bitmap for a set of `len` validators with no signer.
    pub fn new(len: usize) -> Self {
        Self { len: len as u16, bits: vec![0; len.div_ceil(8)] }
    }

    /// Bitmap with exactly `signers` set.
    pub fn from_signers(len: usize, signers: impl IntoIterator<Item = ValidatorIndex>) -> Self {
        let mut b = Self::new(len);
        for s in signers {
            b.set(s);
        }
        b
    }

    /// Marks `i` as a signer. Panics if `i` is outside the set.
    pub fn set(&mut self, i: ValidatorIndex) {
        assert!(i.0 < self.len, "signer {} outside a set of {}", i.0, self.len);
        self.bits[usize::from(i.0 / 8)] |= 1 << (i.0 % 8);
    }

    /// True if `i` signed.
    pub fn contains(&self, i: ValidatorIndex) -> bool {
        // `get`: a bitmap built in memory may hold fewer bytes than `len` needs.
        i.0 < self.len && self.bits.get(usize::from(i.0 / 8)).is_some_and(|b| b & (1 << (i.0 % 8)) != 0)
    }

    /// Size of the set the bitmap was built for.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// True if the bitmap covers no validators.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of signers: the set bits below `len`, never a padding bit.
    pub fn count(&self) -> usize {
        self.signers().count()
    }

    /// The signers, in index order.
    pub fn signers(&self) -> impl Iterator<Item = ValidatorIndex> + '_ {
        (0..self.len).map(ValidatorIndex).filter(|i| self.contains(*i))
    }

    /// The bitmap's bytes, bit `i` at bit `i mod 8` of byte `⌊i / 8⌋`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// A bitmap of exactly `len` and `bits`, canonical or not, as a forger would send it.
    /// `bits` must be `⌈len / 8⌉` bytes, as on the wire: serialize writes them as held, so a
    /// different count would shift the frame and a test would fail for the wrong reason.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_raw(len: u16, bits: Vec<u8>) -> Self {
        assert_eq!(bits.len(), usize::from(len).div_ceil(8), "a BitVec of len {len} has ⌈len / 8⌉ bytes");
        Self { len, bits }
    }

    /// Well formed: the byte length matches `len` and no bit past `len` is set.
    pub fn is_canonical(&self) -> bool {
        self.bits.len() == self.len().div_ceil(8)
            && match self.len % 8 {
                0 => true,
                r => match self.bits.last() {
                    Some(last) => last >> r == 0,
                    None => true,
                },
            }
    }
}

impl BorshSerialize for SignerBitmap {
    /// `len` and the bytes as held: a canonical bitmap's are exactly `⌈len / 8⌉`.
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.len.serialize(writer)?;
        writer.write_all(&self.bits)
    }
}

impl BorshDeserialize for SignerBitmap {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let len = u16::deserialize_reader(reader)?;
        let mut bits = vec![0; usize::from(len).div_ceil(8)];
        reader.read_exact(&mut bits)?;
        let b = Self { len, bits };
        if !b.is_canonical() {
            return Err(borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, "non-canonical signer bitmap"));
        }
        Ok(b)
    }
}

/// Commit certificate: an aggregate BLS signature by more than 2/3 of the set over the
/// precommits for one block, `H("TOG/v1/hub-commit" ‖ borsh((chain_id, height, round,
/// block_hash)))` (§3.1). Height and block hash are not stored: a certificate is checked against
/// the block it commits.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CommitCertificate {
    /// Round in which the block was committed.
    pub round: Round,
    /// Aggregate BLS12-381 precommit signature (G2, compressed).
    pub signature: [u8; 96],
    /// Who precommitted.
    pub signers: SignerBitmap,
}

impl CommitCertificate {
    /// The certificate in the genesis header, which has no parent to commit.
    pub fn genesis() -> Self {
        Self { round: 0, signature: [0; 96], signers: SignerBitmap::default() }
    }
}

/// Most bytes of `borsh(SystemItem)` in one block's system lane (§5 "System lane bound").
pub const MAX_SYSTEM_WEIGHT: u64 = 1_966_080;

/// One leaf of the system lane: `leaf(borsh(item))` in `tx_root` (TOG-SPEC-0002 §3.1, §5).
/// Items appear in ascending variant index; new kinds are appended.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SystemItem {
    /// 0: keys combined by the proposer (TOG-SPEC-0009 §6); at most one per block.
    ReleasedKeys(ReleasedKeys),
    /// 1: a resharing dealing (TOG-SPEC-0009 §2).
    Dealing(Box<ResharingDealing>),
    /// 2: evidence of an offence (§6.1).
    Evidence(Box<Evidence>),
    /// 3: availability bitfield (TOG-SPEC-0002 §4.6).
    AvailabilityBitfield(crate::appchain::Bitfield),
    /// 4: approval vote (TOG-SPEC-0002 §4.6).
    ApprovalVote(crate::appchain::ApprovalVote),
    /// 5: an L1 candidate dispute (TOG-SPEC-0002 §4.6), not `compute_market`'s `Dispute`.
    Dispute(crate::appchain::CandidateDispute),
    /// 6: a backed L1 candidate (TOG-SPEC-0002 §4.4).
    BackedCandidate(Box<crate::appchain::BackedCandidate>),
    /// 7: a validator's pre-check vote on AppChain code (TOG-SPEC-0007 §8.2).
    PreCheckVote(crate::appchain::PreCheckVote),
    /// 8: a bridge certificate (TOG-SPEC-0008 §3.3); reserved until after v1.
    BridgeCertificate(Unspecified),
    /// 9: precommits for `height` that the next header's `last_commit` omitted (§3.1 "Late
    /// signers"); at most one per block.
    LateSigners(LateCommit),
}

/// Late precommits for block `height`, carried by the block at `height + 2` (TOG-SPEC-0002 §3.1
/// "Late signers").
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LateCommit {
    /// `h`: the including block's height − 2.
    pub height: u64,
    /// Aggregate BLS12-381 precommit signature of `signers` (G2, compressed).
    pub signature: [u8; 96],
    /// By `ValidatorIndex` over the set of `height`; disjoint from header `h + 1`'s
    /// `last_commit.signers`.
    pub signers: SignerBitmap,
}

impl SystemItem {
    /// The Borsh variant index, which orders items in the lane.
    pub fn index(&self) -> u8 {
        match self {
            SystemItem::ReleasedKeys(_) => 0,
            SystemItem::Dealing(_) => 1,
            SystemItem::Evidence(_) => 2,
            SystemItem::AvailabilityBitfield(_) => 3,
            SystemItem::ApprovalVote(_) => 4,
            SystemItem::Dispute(_) => 5,
            SystemItem::BackedCandidate(_) => 6,
            SystemItem::PreCheckVote(_) => 7,
            SystemItem::BridgeCertificate(_) => 8,
            SystemItem::LateSigners(_) => 9,
        }
    }

    /// The item's weight in the system lane: `len(borsh(item))` (§5).
    pub fn weight(&self) -> u64 {
        borsh::object_length(self).expect("in-memory borsh cannot fail") as u64
    }

    /// True if the item's payload type is still reserved, which makes a block carrying it invalid.
    pub fn is_reserved(&self) -> bool {
        match self {
            SystemItem::Evidence(e) => matches!(**e, Evidence::BridgeCommitment(_)),
            SystemItem::BridgeCertificate(_) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn dealing() -> ResharingDealing {
        ResharingDealing {
            era: 3,
            ek_epoch: 0,
            dealer: ValidatorIndex(1),
            commitments: vec![[1; 48]],
            ciphertexts: ChunkedCiphertexts { rand_r: [[2; 48]; DKG_CHUNKS], chunks: vec![[[3; 48]; DKG_CHUNKS]] },
            chunking_proof: ChunkingProof {
                y0: [4; 48],
                bb: vec![],
                cc: vec![],
                dd: vec![],
                yy: [5; 48],
                z_r: vec![],
                z_s: vec![],
                z_beta: [6; 32],
            },
            sharing_proof: SharingProof { ff: [7; 48], aa: [8; 48], yy: [9; 48], z_r: [10; 32], z_alpha: [11; 32] },
            sig: [0; 64],
        }
    }

    #[test]
    fn signer_bitmaps_are_canonical_and_list_their_signers() {
        let b = SignerBitmap::from_signers(10, [ValidatorIndex(1), ValidatorIndex(9)]);
        assert!(b.is_canonical());
        assert_eq!((b.len(), b.count()), (10, 2));
        assert_eq!(b.signers().collect::<Vec<_>>(), [ValidatorIndex(1), ValidatorIndex(9)]);
        // TOG-SPEC-0000 §13 `BitVec`: u16 LE bit length, then ⌈len / 8⌉ raw bytes, LSB first.
        assert_eq!(borsh::to_vec(&b).unwrap(), [10, 0, 0b10, 0b10]);
        assert_eq!(borsh::from_slice::<SignerBitmap>(&[10, 0, 0b10, 0b10]).unwrap(), b);
        assert_eq!(borsh::to_vec(&SignerBitmap::new(0)).unwrap(), [0, 0]);
        assert_eq!(borsh::to_vec(&SignerBitmap::from_signers(16, [ValidatorIndex(8)])).unwrap(), [16, 0, 0, 1]);
        let wide = SignerBitmap::from_signers(300, [ValidatorIndex(0), ValidatorIndex(299)]);
        let enc = borsh::to_vec(&wide).unwrap();
        assert_eq!((&enc[..2], enc.len(), enc[2], enc[39]), (&[44, 1][..], 2 + 38, 1, 0b1000));
        // A bit past `len`, a byte too few: neither decodes, so none counts. A byte too many is
        // left over, which `from_slice` (and every enclosing decode) refuses.
        assert!(borsh::from_slice::<SignerBitmap>(&[10, 0, 0, 0b100]).is_err());
        assert!(borsh::from_slice::<SignerBitmap>(&[10, 0, 0b10]).is_err());
        assert!(borsh::from_slice::<SignerBitmap>(&[10, 0, 0b10, 0b10, 0xff]).is_err());
        assert!(borsh::from_slice::<SignerBitmap>(&[16, 0, 0xff, 0xff]).is_ok_and(|b| b.count() == 16));
        let stray = SignerBitmap { len: 10, bits: vec![0b10, 0b1111_1100] };
        assert!(!stray.is_canonical());
        assert_eq!(stray.count(), 1, "padding bits never count");
        let short = SignerBitmap { len: 10, bits: vec![0b10] };
        assert!(!short.is_canonical() && !short.contains(ValidatorIndex(9)) && short.count() == 1);
        assert!(CommitCertificate::genesis().signers.is_empty());
    }

    #[test]
    fn a_dealing_signs_every_field_but_its_signature_under_its_chain() {
        let d = dealing();
        let h = d.signing_hash(1, DealingKind::Reshare);
        assert_eq!(ResharingDealing { sig: [9; 64], ..d.clone() }.signing_hash(1, DealingKind::Reshare), h);
        assert_ne!(d.signing_hash(2, DealingKind::Reshare), h);
        assert_ne!(d.signing_hash(1, DealingKind::Fresh), h);
        assert_ne!(ResharingDealing { era: 4, ..d }.signing_hash(1, DealingKind::Reshare), h);
    }

    #[test]
    fn variant_indices_match_spec() {
        let vote = |value| SignedVote {
            vote: Vote { height: 5, round: 0, kind: VoteKind::Precommit, value, validator: ValidatorIndex(3) },
            sig: [7; 64],
        };
        let proposal = Proposal {
            height: 5,
            round: 1,
            value: [1; 32],
            pol_round: None,
            proposer: ValidatorIndex(0),
            parts_root: [0; 32],
            parts: 1,
        };
        let items = [
            SystemItem::ReleasedKeys(ReleasedKeys::default()),
            SystemItem::Dealing(Box::new(dealing())),
            SystemItem::Evidence(Box::new(Evidence::DuplicateVote { a: vote(None), b: vote(Some([2; 32])) })),
            SystemItem::AvailabilityBitfield(crate::appchain::tests::bitfield()),
            SystemItem::ApprovalVote(crate::appchain::tests::approval()),
            SystemItem::Dispute(crate::appchain::tests::dispute()),
            SystemItem::BackedCandidate(Box::new(crate::appchain::tests::backed())),
            SystemItem::PreCheckVote(crate::appchain::tests::vote()),
        ];
        for (i, item) in items.iter().enumerate() {
            let bytes = borsh::to_vec(item).unwrap();
            assert_eq!((bytes[0], item.index()), (i as u8, i as u8));
            assert_eq!(&borsh::from_slice::<SystemItem>(&bytes).unwrap(), item);
            assert!(!item.is_reserved());
        }
        let dup = Evidence::DuplicateProposal {
            a: SignedProposal { proposal: proposal.clone(), sig: [0; 64] },
            b: SignedProposal { proposal: Proposal { value: [2; 32], ..proposal }, sig: [0; 64] },
        };
        assert_eq!(borsh::to_vec(&dup).unwrap()[0], 1);
        let bridge = SystemItem::Evidence(Box::new(Evidence::BridgeCommitment(Unspecified)));
        assert_eq!(borsh::to_vec(&bridge).unwrap(), [2, 2]);
        let certificate = SystemItem::BridgeCertificate(Unspecified);
        assert_eq!((borsh::to_vec(&certificate).unwrap(), certificate.is_reserved()), (vec![8], true));
        let late = SystemItem::LateSigners(LateCommit {
            height: 7,
            signature: [1; 96],
            signers: SignerBitmap::from_signers(3, [ValidatorIndex(2)]),
        });
        let bytes = borsh::to_vec(&late).unwrap();
        assert_eq!((bytes[0], late.index(), late.is_reserved()), (9, 9, false));
        assert_eq!(borsh::from_slice::<SystemItem>(&bytes).unwrap(), late);
        let invalid = Evidence::InvalidDealing(Box::new(dealing()));
        assert_eq!(borsh::to_vec(&invalid).unwrap()[0], 3);
        let ext =
            SignedExtension { height: 9, round: 1, validator: ValidatorIndex(2), extension: vec![7], sig: [0; 64] };
        assert_eq!(borsh::to_vec(&Evidence::InvalidBeaconShare(ext)).unwrap()[0], 4);
        let cert = |r| CommitCertificate {
            round: r,
            signature: [0; 96],
            signers: SignerBitmap::from_signers(3, [ValidatorIndex(0)]),
        };
        let conflict = Evidence::ConflictingCommits { height: 9, a: ([1; 32], cert(0)), b: ([2; 32], cert(1)) };
        let bytes = borsh::to_vec(&conflict).unwrap();
        assert_eq!((bytes[0], &bytes[1..9]), (5, &9u64.to_le_bytes()[..]));
        assert_eq!(borsh::from_slice::<Evidence>(&bytes).unwrap(), conflict);
        let complaint = DealingComplaint {
            era: 3,
            ek_epoch: 2,
            kind: 1,
            dealer: 2,
            receiver: 1,
            chunk: 0,
            m: [4; 48],
            proof: ([5; 32], [6; 32]),
        };
        let bytes = borsh::to_vec(&Evidence::UndecryptableDealing(complaint.clone())).unwrap();
        assert_eq!(
            (bytes[0], &bytes[1..9], &bytes[9..13], bytes[13]),
            (6, &3u64.to_le_bytes()[..], &2u32.to_le_bytes()[..], 1)
        );
        assert_eq!(bytes.len(), 1 + 8 + 4 + 1 + 2 + 2 + 1 + 48 + 64);
        assert_eq!(borsh::from_slice::<Evidence>(&bytes).unwrap(), Evidence::UndecryptableDealing(complaint));
        assert!(bridge.is_reserved());
        assert_eq!(bridge.weight(), 2);
        assert_eq!(borsh::to_vec(&VoteKind::Precommit).unwrap(), [1]);
    }
}
