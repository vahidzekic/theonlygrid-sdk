//! Domain-separated BLAKE3 hashing (TOG-SPEC-0000 §13.1).
//!
//! The specs write domain-separated hashes as `H("TOG/v1/<tag>" ‖ x)`. This crate
//! implements every such hash as BLAKE3 in `derive_key` mode with the tag as the
//! context string, which is what TOG-SPEC-0001 §3.2 already uses for `job_id`.
//! Integers inside hashed data are little-endian.
//!
//! The IBE identity tags (`Mempool`, `KeyEscrow`, `ConfKey`) are BLS domain-separation
//! tags, not BLAKE3 contexts (0000 §13.1 exceptions); they live here so every tag has one name.
//! `Verify` and `Probe` are likewise prefixes of ECVRF input strings, not BLAKE3 contexts.

/// A 32-byte BLAKE3 digest.
pub type Hash32 = [u8; 32];

/// Every domain tag used by the node. Keeping them in one enum makes collisions
/// between tags impossible to introduce by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    /// `job_id = H(borsh(JobTx))`, TOG-SPEC-0001 §3.2.
    JobId,
    /// Signing digest of a transaction body, TOG-SPEC-0001 §3.1.
    Tx,
    /// Account address from `scheme ‖ public key`, TOG-SPEC-0000 §13.2.
    Address,
    /// Sovereign account of a chain on the Hub, TOG-SPEC-0000 §13.2.
    Sovereign,
    /// `EscrowRef` from `borsh(EscrowOrigin)`, TOG-SPEC-0000 §13.2.
    Escrow,
    /// Start of a job's segment chain (`S_{-1}`).
    SegmentGenesis,
    /// One link of the segment chain, TOG-SPEC-0001 §4.2 step 6.
    Segment,
    /// Metrics file of one segment, TOG-SPEC-0001 §4.2 step 6.
    Metrics,
    /// `key_commitment = H(k_n)`, TOG-SPEC-0003 §2.
    CheckpointKey,
    /// Result commitment `H(borsh(receipt) ‖ salt)`, TOG-SPEC-0001 §4.2 step 8.
    Result,
    /// Job seed `TOG_SEED = H(job_id ‖ segment)`, TOG-SPEC-0001 §2.6.
    Seed,
    /// Seed of a sketch projection matrix, TOG-SPEC-0003 §5.2.
    SketchProj,
    /// Hub block hash `H(borsh(HubHeader))`, TOG-SPEC-0002 §3.1.
    HubHeader,
    /// `H(borsh(ValidatorSet))`, TOG-SPEC-0002 §3.1.
    ValidatorSet,
    /// Leaf of a lane transaction Merkle tree, TOG-SPEC-0002 §3.1.
    TxLeaf,
    /// Inner node of a lane transaction Merkle tree, TOG-SPEC-0002 §3.1.
    TxNode,
    /// Block `tx_root` over the lane roots, TOG-SPEC-0002 §3.1.
    TxRoot,
    /// IBE identity of encrypted mempool transactions (BLS DST), TOG-SPEC-0009 §1.3.
    Mempool,
    /// IBE identity of escrowed checkpoint keys (BLS DST), TOG-SPEC-0009 §1.3.
    KeyEscrow,
    /// IBE identity of confidential job keys (BLS DST, reserved), TOG-SPEC-0009 §1.3.
    ConfKey,
    /// IBE randomness derivation (Fujisaki–Okamoto), TOG-SPEC-0009 §1.2.
    IbeR,
    /// IBE mask, TOG-SPEC-0009 §1.2.
    IbeMask,
    /// IBE message hash, TOG-SPEC-0009 §1.2.
    IbeMsg,
    /// AAD of an `EncryptedTx` body (TOG-SPEC-0009 §4.2 rule 1).
    EncTx,
    /// Leaf of a verifier's salted vote tree, TOG-SPEC-0003 §3.3.
    Vote,
    /// Inner node of a vote tree, TOG-SPEC-0003 §3.3.
    VoteNode,
    /// Verifier `output_commitment`, TOG-SPEC-0003 §3.3.
    VoteCommit,
    /// `H(borsh(Option<Sketch>))`, TOG-SPEC-0003 §3.3.
    Sketch,
    /// Verifier sortition VRF input (the ECVRF alpha string), TOG-SPEC-0003 §3.2.
    Verify,
    /// Beacon draw for job assignment, TOG-SPEC-0001 §4.2 step 2.
    Assign,
    /// Worker key proof of possession, TOG-SPEC-0001 §3.2.
    WorkerBind,
    /// VRF input of the `vrf_key` proof of possession, TOG-SPEC-0001 §3.2 "VRF key uniqueness".
    VrfBind,
    /// Attestation report nonce, TOG-SPEC-0001 §3.2.
    WorkerAttest,
    /// Payload id `H(root ‖ size)`, TOG-SPEC-0004 §2.2.
    Payload,
    /// CVM report data of an enclave registration, TOG-SPEC-0010 §2.1.
    Enclave,
    /// SPDM nonce of an enclave's GPU reports, TOG-SPEC-0010 §2.1.
    EnclaveGpu,
    /// `EnclavePolicyId = H(borsh(EnclavePolicy))`, TOG-SPEC-0010 §3.
    EnclavePolicy,
    /// Signed digest of a key share request, TOG-SPEC-0010 §4.2.
    ShareReq,
    /// HPKE info of a key share (a prefix, not a BLAKE3 context), TOG-SPEC-0010 §4.2.
    ConfShare,
    /// Keys derived from `K_conf`, TOG-SPEC-0010 §5.
    ConfKdf,
    /// Ed25519-signed Hub consensus vote, TOG-SPEC-0002 §3.1.
    HubVote,
    /// Ed25519-signed Hub block proposal, TOG-SPEC-0002 §3.1.
    HubProposal,
    /// BLS-signed precommit message, TOG-SPEC-0002 §3.1.
    HubCommit,
    /// Ed25519-signed vote extension, TOG-SPEC-0002 §3.1.
    HubVoteExt,
    /// BLS message of the randomness beacon, `("TOG/v1/beacon", h)`, TOG-SPEC-0002 §3.2.
    Beacon,
    /// Beacon output `HubBeacon(h) = H("TOG/v1/rand" ‖ randomness(h + 1))`, TOG-SPEC-0002 §3.2.
    Rand,
    /// Groth21 DKG: proof of possession of a dealer's encryption key, TOG-SPEC-0009.
    DkgPop,
    /// Groth21 DKG: Fiat–Shamir challenge of the chunking proof.
    DkgChunking,
    /// Groth21 DKG: Fiat–Shamir challenge of the sharing proof.
    DkgSharing,
    /// Groth21 DKG: deterministic randomness derivation.
    DkgRng,
    /// Groth21 DKG: the dealer's consensus-key signature on a `ResharingDealing`, TOG-SPEC-0009 §2.2.
    DkgDealing,
    /// Groth21 DKG: Chaum–Pedersen challenge of a complaint against an out-of-range chunk,
    /// TOG-SPEC-0009 §2.2.
    DkgComplaint,
    /// HPKE info of a sealed `ConfKeyRequest` to a `Sender` broker, TOG-SPEC-0010 §4.3.
    ConfKeyReq,
    /// The genesis hash, `H("TOG/v1/genesis" ‖ file bytes)`, TOG-SPEC-0002 §2.3.
    Genesis,
    /// Jellyfish Merkle tree nodes, key hashes and value hashes, TOG-SPEC-0002 §7.1.
    Jmt,
    /// Sample-plan seed (0003 §8.2).
    Sample,
    /// `borsh(EnvDescriptor)`, the receipt's `env_digest` (0001 §4.2 step 7).
    Env,
    /// Inputs of the OCI runtime spec (0001 §4.2 step 7).
    OciSpec,
    /// V8 audit index stream (0003 §3.3).
    Audit,
    /// Leaf of a deal's payload set tree, TOG-SPEC-0004 §4.4.1.
    SetLeaf,
    /// Inner node of a payload set tree, TOG-SPEC-0004 §4.4.1.
    SetNode,
    /// Empty leaf `Z_0` of a payload set tree, TOG-SPEC-0004 §4.4.1.
    SetEmpty,
    /// Chunk draw of a retrievability challenge, TOG-SPEC-0004 §5.1.
    Por,
    /// Holder draw of a deal's placement, TOG-SPEC-0004 §4.3.
    Place,
    /// Scheduled holder challenge draw, TOG-SPEC-0004 §5.1.
    Sched,
    /// Storage key's proof of possession at registration, TOG-SPEC-0004 §3.1.
    StorageBind,
    /// Encoder choice among a Reed–Solomon deal's two replicas, TOG-SPEC-0004 §5.6.1.
    Encoder,
    /// Root of a fault vote on a failed segment, TOG-SPEC-0003 §3.6.
    Fault,
    /// Retrieval payment voucher signed by a channel's payer, TOG-SPEC-0004 §6.6.
    Voucher,
    /// A sender's signature on a `DeliverConfKey` message, TOG-SPEC-0006 §2.4.
    DeliverConfKey,
    /// A worker's `Availability` message, TOG-SPEC-0006 §2.4.
    Availability,
    /// The Grid-DHT key and signature of an `EndpointRecord`, TOG-SPEC-0006 §4.
    Endpoint,
    /// The rows an RS shard holder audits, TOG-SPEC-0004 §5.6.
    RowAudit,
    /// Prefix of a bandwidth prober's ECVRF input, TOG-SPEC-0004 §3.3 (like `Verify`, not a BLAKE3 context).
    Probe,
    /// The pseudo-random bytes of a bandwidth probe, TOG-SPEC-0004 §3.3.
    ProbeBytes,
    /// The Grid-DHT provider key of a payload root, TOG-SPEC-0004 §7.1.
    Provide,
    /// `msg_hash` of a CGMP message, TOG-SPEC-0000 §7.2.
    CgmpMsg,
    /// A CGMP channel's queue head, TOG-SPEC-0000 §7.2.
    CgmpQueue,
    /// A leaf of the CGMP `outbox_root` tree, TOG-SPEC-0000 §7.2.
    CgmpLeaf,
    /// An inner node of the CGMP `outbox_root` tree, TOG-SPEC-0000 §7.2.
    CgmpNode,
    /// The validator-plane DHT key and signature of a `ValidatorAddrRecord`, TOG-SPEC-0006 §2.1.
    ValAddr,
    /// An AppChain head hash over `borsh(Header)`, TOG-SPEC-0007 §3.4.
    AppchainHeader,
    /// `pov_hash` of a candidate's `borsh(Pov)`, TOG-SPEC-0002 §4.4.
    Pov,
    /// `candidate_hash` over `borsh(CandidateReceipt)`, TOG-SPEC-0002 §4.4.
    Candidate,
    /// A backer's statement on a `candidate_hash`, TOG-SPEC-0002 §4.4.
    Backing,
    /// The per-session permutation of validators that forms the backing groups (and, under
    /// backing rule 1, a chain's own draw), TOG-SPEC-0002 §4.4.
    BackingGroup,
    /// A validator's pre-check vote on AppChain code, TOG-SPEC-0007 §8.2.
    PreCheck,
    /// A leaf of a candidate's availability chunk tree, TOG-SPEC-0002 §4.5.
    ChunkLeaf,
    /// An inner node of a candidate's availability chunk tree, TOG-SPEC-0002 §4.5.
    ChunkNode,
    /// A validator's availability bitfield, TOG-SPEC-0002 §4.6.
    Bitfield,
    /// An approval checker's assignment message, TOG-SPEC-0002 §4.6.
    ApprovalVrf,
    /// An approval checker's VRF output, TOG-SPEC-0002 §4.6.
    ApprovalOut,
    /// A validator's vote in an L1 candidate dispute, TOG-SPEC-0002 §4.6.
    DisputeVote,
    /// An execution receipt, `ComputeResult.receipt_root`, TOG-SPEC-0000 §7.2.
    Receipt,
    /// A leaf of the header's `candidates_root` and `approvals_root` trees, TOG-SPEC-0002 §3.1.
    HdrLeaf,
    /// An inner node of those trees, TOG-SPEC-0002 §3.1.
    HdrNode,
    /// `k_out = H("TOG/v1/output-key" ‖ k_{N−1})`, the cipher key of a sealed output archive that isn't
    /// `ckpt_{N−1}`, TOG-SPEC-0004 §9.1.
    OutputKey,
    /// The degraded beacon before the first DKG closes, TOG-SPEC-0002 §3.2.
    BeaconFallback,
    /// The draw of a reservation's worker, TOG-SPEC-0015 §3.
    Reserve,
    /// `key_check = H(K_conf)` of a `Sender`-broker job, TOG-SPEC-0010 §4.3.
    ConfKeyCheck,
    /// The per-session offset of the chain-to-group assignment, TOG-SPEC-0002 §4.4.
    BackingOffset,
    /// Signing digest of the inner transaction of an `EncryptedTx`, bound to its envelope
    /// (TOG-SPEC-0009 §4.2 rule 5).
    EncInner,
    /// The storage tier walk: its accumulator, and the prefix of a walk prober's ECVRF input,
    /// TOG-SPEC-0012 §2.1–§2.2.
    Walk,
    /// The seed of one tier walk, TOG-SPEC-0012 §2.2.
    WalkSeed,
    /// The slot-audit draw with each scheduled holder challenge, TOG-SPEC-0004 §5.1.
    SlotAudit,
}

impl Domain {
    /// Every domain, for exhaustiveness checks.
    pub const ALL: [Domain; 105] = [
        Domain::JobId,
        Domain::Tx,
        Domain::Address,
        Domain::Sovereign,
        Domain::Escrow,
        Domain::SegmentGenesis,
        Domain::Segment,
        Domain::Metrics,
        Domain::CheckpointKey,
        Domain::Result,
        Domain::Seed,
        Domain::SketchProj,
        Domain::HubHeader,
        Domain::ValidatorSet,
        Domain::TxLeaf,
        Domain::TxNode,
        Domain::TxRoot,
        Domain::Mempool,
        Domain::KeyEscrow,
        Domain::ConfKey,
        Domain::IbeR,
        Domain::IbeMask,
        Domain::IbeMsg,
        Domain::EncTx,
        Domain::Vote,
        Domain::VoteNode,
        Domain::VoteCommit,
        Domain::Sketch,
        Domain::Verify,
        Domain::Assign,
        Domain::WorkerBind,
        Domain::VrfBind,
        Domain::WorkerAttest,
        Domain::Payload,
        Domain::Enclave,
        Domain::EnclaveGpu,
        Domain::EnclavePolicy,
        Domain::ShareReq,
        Domain::ConfShare,
        Domain::ConfKdf,
        Domain::HubVote,
        Domain::HubProposal,
        Domain::HubCommit,
        Domain::HubVoteExt,
        Domain::Beacon,
        Domain::Rand,
        Domain::DkgPop,
        Domain::DkgChunking,
        Domain::DkgSharing,
        Domain::DkgRng,
        Domain::DkgDealing,
        Domain::DkgComplaint,
        Domain::ConfKeyReq,
        Domain::Genesis,
        Domain::Jmt,
        Domain::Sample,
        Domain::Env,
        Domain::OciSpec,
        Domain::Audit,
        Domain::SetLeaf,
        Domain::SetNode,
        Domain::SetEmpty,
        Domain::Por,
        Domain::Place,
        Domain::Sched,
        Domain::StorageBind,
        Domain::Encoder,
        Domain::Fault,
        Domain::Voucher,
        Domain::DeliverConfKey,
        Domain::Availability,
        Domain::Endpoint,
        Domain::RowAudit,
        Domain::Probe,
        Domain::ProbeBytes,
        Domain::Provide,
        Domain::CgmpMsg,
        Domain::CgmpQueue,
        Domain::CgmpLeaf,
        Domain::CgmpNode,
        Domain::ValAddr,
        Domain::AppchainHeader,
        Domain::Pov,
        Domain::Candidate,
        Domain::Backing,
        Domain::BackingGroup,
        Domain::PreCheck,
        Domain::ChunkLeaf,
        Domain::ChunkNode,
        Domain::Bitfield,
        Domain::ApprovalVrf,
        Domain::ApprovalOut,
        Domain::DisputeVote,
        Domain::Receipt,
        Domain::HdrLeaf,
        Domain::HdrNode,
        Domain::OutputKey,
        Domain::BeaconFallback,
        Domain::Reserve,
        Domain::ConfKeyCheck,
        Domain::BackingOffset,
        Domain::EncInner,
        Domain::Walk,
        Domain::WalkSeed,
        Domain::SlotAudit,
    ];

    /// The BLAKE3 context string for this domain.
    pub const fn tag(self) -> &'static str {
        match self {
            Domain::JobId => "TOG/v1/job_id",
            Domain::Tx => "TOG/v1/tx",
            Domain::Address => "TOG/v1/address",
            Domain::Sovereign => "TOG/v1/sovereign",
            Domain::Escrow => "TOG/v1/escrow",
            Domain::SegmentGenesis => "TOG/v1/segment-genesis",
            Domain::Segment => "TOG/v1/segment",
            Domain::Metrics => "TOG/v1/metrics",
            Domain::CheckpointKey => "TOG/v1/ckpt-key",
            Domain::Result => "TOG/v1/result",
            Domain::Seed => "TOG/v1/seed",
            Domain::SketchProj => "TOG/v1/sketch-proj",
            Domain::HubHeader => "TOG/v1/hub-header",
            Domain::ValidatorSet => "TOG/v1/validator-set",
            Domain::TxLeaf => "TOG/v1/tx-leaf",
            Domain::TxNode => "TOG/v1/tx-node",
            Domain::TxRoot => "TOG/v1/tx-root",
            Domain::Mempool => "TOG/v1/mempool",
            Domain::KeyEscrow => "TOG/v1/key-escrow",
            Domain::ConfKey => "TOG/v1/conf-key",
            Domain::IbeR => "TOG/v1/ibe-r",
            Domain::IbeMask => "TOG/v1/ibe-mask",
            Domain::IbeMsg => "TOG/v1/ibe-msg",
            Domain::EncTx => "TOG/v1/enc-tx",
            Domain::Vote => "TOG/v1/vote",
            Domain::VoteNode => "TOG/v1/vote-node",
            Domain::VoteCommit => "TOG/v1/vote-commit",
            Domain::Sketch => "TOG/v1/sketch",
            Domain::Verify => "TOG/v1/verify",
            Domain::Assign => "TOG/v1/assign",
            Domain::WorkerBind => "TOG/v1/worker-bind",
            Domain::VrfBind => "TOG/v1/vrf-bind",
            Domain::WorkerAttest => "TOG/v1/worker-attest",
            Domain::Payload => "TOG/v1/payload",
            Domain::Enclave => "TOG/v1/enclave",
            Domain::EnclaveGpu => "TOG/v1/enclave-gpu",
            Domain::EnclavePolicy => "TOG/v1/enclave-policy",
            Domain::ShareReq => "TOG/v1/share-req",
            Domain::ConfShare => "TOG/v1/conf-share",
            Domain::ConfKdf => "TOG/v1/conf-kdf",
            Domain::HubVote => "TOG/v1/hub-vote",
            Domain::HubProposal => "TOG/v1/hub-proposal",
            Domain::HubCommit => "TOG/v1/hub-commit",
            Domain::HubVoteExt => "TOG/v1/hub-vote-ext",
            Domain::Beacon => "TOG/v1/beacon",
            Domain::Rand => "TOG/v1/rand",
            Domain::DkgPop => "TOG/v1/dkg-pop",
            Domain::DkgChunking => "TOG/v1/dkg-chunking",
            Domain::DkgSharing => "TOG/v1/dkg-sharing",
            Domain::DkgRng => "TOG/v1/dkg-rng",
            Domain::DkgDealing => "TOG/v1/dkg-dealing",
            Domain::DkgComplaint => "TOG/v1/dkg-complaint",
            Domain::ConfKeyReq => "TOG/v1/conf-key-req",
            Domain::Genesis => "TOG/v1/genesis",
            Domain::Jmt => "TOG/v1/jmt",
            Domain::Sample => "TOG/v1/sample",
            Domain::Env => "TOG/v1/env",
            Domain::OciSpec => "TOG/v1/oci-spec",
            Domain::Audit => "TOG/v1/audit",
            Domain::SetLeaf => "TOG/v1/set-leaf",
            Domain::SetNode => "TOG/v1/set-node",
            Domain::SetEmpty => "TOG/v1/set-empty",
            Domain::Por => "TOG/v1/por",
            Domain::Place => "TOG/v1/place",
            Domain::Sched => "TOG/v1/sched",
            Domain::StorageBind => "TOG/v1/storage-bind",
            Domain::Encoder => "TOG/v1/encoder",
            Domain::Fault => "TOG/v1/fault",
            Domain::Voucher => "TOG/v1/voucher",
            Domain::DeliverConfKey => "TOG/v1/deliver-conf-key",
            Domain::Availability => "TOG/v1/availability",
            Domain::Endpoint => "TOG/v1/endpoint",
            Domain::RowAudit => "TOG/v1/row-audit",
            Domain::Probe => "TOG/v1/probe",
            Domain::ProbeBytes => "TOG/v1/probe-bytes",
            Domain::Walk => "TOG/v1/walk",
            Domain::WalkSeed => "TOG/v1/walk-seed",
            Domain::SlotAudit => "TOG/v1/slot-audit",
            Domain::Provide => "TOG/v1/provide",
            Domain::CgmpMsg => "TOG/v1/cgmp-msg",
            Domain::CgmpQueue => "TOG/v1/cgmp-queue",
            Domain::CgmpLeaf => "TOG/v1/cgmp-leaf",
            Domain::CgmpNode => "TOG/v1/cgmp-node",
            Domain::ValAddr => "TOG/v1/val-addr",
            Domain::AppchainHeader => "TOG/v1/appchain-header",
            Domain::Pov => "TOG/v1/pov",
            Domain::Candidate => "TOG/v1/candidate",
            Domain::Backing => "TOG/v1/backing",
            Domain::BackingGroup => "TOG/v1/backing-group",
            Domain::PreCheck => "TOG/v1/precheck",
            Domain::ChunkLeaf => "TOG/v1/chunk-leaf",
            Domain::ChunkNode => "TOG/v1/chunk-node",
            Domain::Bitfield => "TOG/v1/bitfield",
            Domain::ApprovalVrf => "TOG/v1/approval-vrf",
            Domain::ApprovalOut => "TOG/v1/approval-out",
            Domain::DisputeVote => "TOG/v1/dispute-vote",
            Domain::Receipt => "TOG/v1/receipt",
            Domain::HdrLeaf => "TOG/v1/hdr-leaf",
            Domain::HdrNode => "TOG/v1/hdr-node",
            Domain::OutputKey => "TOG/v1/output-key",
            Domain::BeaconFallback => "TOG/v1/beacon-fallback",
            Domain::Reserve => "TOG/v1/reserve",
            Domain::ConfKeyCheck => "TOG/v1/conf-key-check",
            Domain::BackingOffset => "TOG/v1/backing-offset",
            Domain::EncInner => "TOG/v1/enc-inner",
        }
    }
}

/// `H(tag ‖ parts[0] ‖ parts[1] ‖ …)`.
///
/// Parts are concatenated without length prefixes, so callers must only pass
/// fixed-size fields or a single variable-length field in the last position.
pub fn tagged_hash(domain: Domain, parts: &[&[u8]]) -> Hash32 {
    let mut h = hasher(domain);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// A BLAKE3 `derive_key` hasher for `domain`. With `std` the context string is hashed once per
/// domain and kept, which takes about a third off a hash of a few dozen bytes (a JMT node);
/// without it, on every call.
fn hasher(domain: Domain) -> blake3::Hasher {
    #[cfg(feature = "std")]
    {
        use blake3::hazmat::{hash_derive_key_context, ContextKey, HasherExt};
        static KEYS: std::sync::OnceLock<[ContextKey; Domain::ALL.len()]> = std::sync::OnceLock::new();
        let keys = KEYS.get_or_init(|| Domain::ALL.map(|d| hash_derive_key_context(d.tag())));
        blake3::Hasher::new_from_context_key(&keys[domain as usize])
    }
    #[cfg(not(feature = "std"))]
    {
        blake3::Hasher::new_derive_key(domain.tag())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_context_keys_hash_as_derive_key() {
        for (i, d) in Domain::ALL.into_iter().enumerate() {
            assert_eq!(d as usize, i, "{d:?} out of place in Domain::ALL");
            for x in [&b""[..], b"x", &[7; 80], &[9; 2000]] {
                assert_eq!(tagged_hash(d, &[x]), blake3::derive_key(d.tag(), x), "{d:?}");
            }
        }
    }

    #[test]
    fn domains_separate() {
        let a = tagged_hash(Domain::JobId, &[b"x"]);
        let b = tagged_hash(Domain::Tx, &[b"x"]);
        assert_ne!(a, b);
    }

    #[test]
    fn tags_are_unique_and_versioned() {
        let mut tags: Vec<&str> = Domain::ALL.iter().map(|d| d.tag()).collect();
        assert!(tags.iter().all(|t| t.starts_with("TOG/v1/")));
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), Domain::ALL.len());
    }

    #[test]
    fn parts_are_concatenated() {
        assert_eq!(tagged_hash(Domain::Result, &[b"ab", b"c"]), tagged_hash(Domain::Result, &[b"abc"]));
    }

    #[test]
    fn matches_blake3_derive_key() {
        let expected = blake3::derive_key("TOG/v1/job_id", b"payload");
        assert_eq!(tagged_hash(Domain::JobId, &[b"payload"]), expected);
    }
}
