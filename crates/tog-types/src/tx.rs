//! Signed transaction envelope (TOG-SPEC-0001 §3.2).
//!
//! `TxBody` variant indices are consensus-critical: new variants are only appended.
//!
//! Worker transactions (variants 2–8, 11 and 14–18) carry no `chain_id` or nonce: each names a
//! `job_id`, which already hashes the replay domain, and the Hub accepts each at most
//! once per job and worker.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{ed25519_address, tagged_hash, Address, Amount, Domain, Hash32};

use crate::appchain::{
    CloseAppChainTx, DeregisterCollatorTx, ExitClaimTx, RegisterAppChainTx, RegisterCollatorTx, SetCollatorKeysTx,
    SetVerificationModuleTx, UploadCodeTx,
};
use crate::audit::AuditResponseTx;
use crate::bisection::{BisectAnswerTx, BisectPostTx};
use crate::cgmp::{DeliverCgmpTx, DepositToChainTx, RefuseInboundTx};
use crate::channel::{CloseChannelTx, OpenChannelTx};
use crate::checkpoint::{CheckpointCommitment, KeyReleaseTx};
use crate::coretime::{FundOnDemandTx, PurchaseRegionTx};
use crate::dispute::{AppealTx, AttestCopySketchTx, AttestSketchTx, ChallengeTx};
use crate::enclave::{DeliverConfKeyTx, RegisterEnclaveTx, TeeCollateralTx};
use crate::hub_key::{EncryptedTx, KeyEscrowTx};
use crate::job::JobTx;
use crate::por::RespondChallengeTx;
use crate::probe::ProbeReportTx;
use crate::receipt::ExecutionReceipt;
use crate::rs::{EncodingFraudTx, PostEncodingTx};
use crate::staking::{BondTx, NominateTx, RegisterValidatorTx, SetCommissionTx, SetDkgKeyTx, UnbondTx, WithdrawTx};
use crate::storage::{
    AppendPayloadTx, FetchStallTx, OpenDealTx, PostExternalLocatorTx, RenewDealTx, RetrievalDisputeTx,
};
use crate::storage_worker::{
    BondStorageWorkerTx, RegisterStorageWorkerTx, UnbondStorageWorkerTx, UpdateStorageWorkerTx,
};
use crate::verifier::{VerifierCommit, VerifierReveal};
use crate::worker::{BondWorkerTx, SetOptInsTx, UnbondWorkerTx, WorkerRegistrationTx};

/// Account signature. Variants 0 and 1 have the index of their address scheme (TOG-SPEC-0000 §13.2);
/// variant 2 is the same key as variant 1 and uses scheme 1.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Signature {
    /// Ed25519; the key travels with the signature because it cannot be recovered.
    Ed25519 {
        /// Public key.
        public_key: [u8; 32],
        /// Signature.
        sig: [u8; 64],
    },
    /// secp256k1, recoverable (r ‖ s ‖ v); the key is recovered from the signature.
    Secp256k1([u8; 65]),
    /// secp256k1 over the EIP-712 digest of the body ([`crate::eip712`]) instead of the TOG digest, so
    /// browser wallets show a typed prompt (TOG-SPEC-0007 §4.5). Same key and address as `Secp256k1`.
    Secp256k1Eip712([u8; 65]),
}

impl Signature {
    /// Signer address for Ed25519. `None` for secp256k1, whose key must first be
    /// recovered from the signature and the digest.
    pub fn ed25519_signer(&self) -> Option<Address> {
        match self {
            Signature::Ed25519 { public_key, .. } => Some(ed25519_address(public_key)),
            Signature::Secp256k1(_) | Signature::Secp256k1Eip712(_) => None,
        }
    }
}

/// Plain $TOG transfer.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TransferTx {
    /// Replay domain, TOG-SPEC-0000 §13.2.
    pub chain_id: u64,
    /// Sender.
    pub from: Address,
    /// Recipient.
    pub to: Address,
    /// Amount in atto-TOG.
    pub amount: Amount,
    /// Sender nonce.
    pub nonce: u64,
}

/// Worker accepts a protocol assignment and posts its bond (TOG-SPEC-0001 §4.2 step 3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ClaimTx {
    /// Assigned job.
    pub job_id: Hash32,
    /// Job bond `B ≥ β · max_budget`; a larger bond lowers the sampling rate.
    pub bond: Amount,
}

/// Worker gives an assignment back before committing (TOG-SPEC-0001 §5.3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReleaseClaimTx {
    /// Claimed job.
    pub job_id: Hash32,
    /// Why (TOG-SPEC-0001 §5.3).
    pub reason: ReleaseReason,
    /// The claim being released, `JobStatus::Running.claimed_at`; any other value is invalid (TOG-SPEC-0001 §3.2).
    pub claim_height: u64,
}

/// Why a worker releases its claim (TOG-SPEC-0001 §5.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ReleaseReason {
    /// 0: a node fault.
    #[default]
    Node,
    /// 1: every locator of a locator-only payload of the job is dead (TOG-SPEC-0001 §2.3).
    LocatorsDead,
    /// 2: a T3 `Sender` broker never delivered `K_conf` (TOG-SPEC-0010 §4.3).
    ConfKeyMissing,
    /// 3: a verified image or input is rejected by content (TOG-SPEC-0001 §5.3).
    BadPayload,
    /// 4: the holders of a deal the claim's run reads don't serve it (TOG-SPEC-0001 §5.3).
    HoldersStalled {
        /// The deal.
        deal: crate::job::DealId,
    },
    /// 5: the resume checkpoint doesn't decrypt to its `plaintext_root` (TOG-SPEC-0001 §5.3).
    BadResume,
}

/// Result commitment (TOG-SPEC-0001 §4.2 step 8).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ResultCommitTx {
    /// Job.
    pub job_id: Hash32,
    /// `H("TOG/v1/result" ‖ borsh(receipt) ‖ salt)`.
    pub commit: Hash32,
    /// One per segment, in order `0..N`; `N = checkpoints.len()` (TOG-SPEC-0003 §2).
    pub checkpoints: Vec<CheckpointCommitment>,
    /// The claim this commit answers, `JobStatus::Running.claimed_at`; the Hub rejects any other value, so an old
    /// commit can't be replayed after the same worker is assigned the job again (TOG-SPEC-0001 §3.2).
    pub claim_height: u64,
}

/// Reveal of a committed result.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ResultRevealTx {
    /// The receipt.
    pub receipt: ExecutionReceipt,
    /// Salt of the commitment.
    pub salt: [u8; 32],
}

/// Transaction kinds, in consensus order. The Borsh index is the discriminant: 0–55 in order,
/// then the ones specified past the unassigned range.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum TxBody {
    /// 0: transfer.
    Transfer(TransferTx),
    /// 1: submit a compute job.
    SubmitJob(Box<JobTx>),
    /// 2: claim an assignment.
    ClaimJob(ClaimTx),
    /// 3: release a claim.
    ReleaseClaim(ReleaseClaimTx),
    /// 4: commit a result.
    CommitResult(ResultCommitTx),
    /// 5: reveal a result.
    RevealResult(Box<ResultRevealTx>),
    /// 6: release checkpoint keys.
    ReleaseKeys(KeyReleaseTx),
    /// 7: verifier commits to its re-run of a segment.
    VerifierCommit(VerifierCommit),
    /// 8: verifier opens its commitment.
    VerifierReveal(Box<VerifierReveal>),
    /// 9: register a worker, signed by the owner.
    RegisterWorker(Box<WorkerRegistrationTx>),
    /// 10: user-lane transaction encrypted to the Hub key.
    SubmitEncrypted(Box<EncryptedTx>),
    /// 11: escrow of `k_n` after a sealed segment.
    EscrowKey(Box<KeyEscrowTx>),
    /// 12: register a T3 enclave key with CVM and GPU attestation (TOG-SPEC-0010 §2).
    RegisterEnclave(Box<RegisterEnclaveTx>),
    /// 13: vendor-signed TEE collateral (TOG-SPEC-0010 §2.4).
    PostTeeCollateral(TeeCollateralTx),
    /// 14: executor's sub-checkpoint root in micro-bisection (TOG-SPEC-0003 §4.5).
    BisectPost(BisectPostTx),
    /// 15: the playing dissenter agrees or disagrees with that root.
    BisectAnswer(BisectAnswerTx),
    /// 16: a verifier's chunk openings at the V8 audit (TOG-SPEC-0003 §3.3).
    AuditResponse(Box<AuditResponseTx>),
    /// 17: a fisherman challenge during `W_opt` (TOG-SPEC-0003 §4.6).
    Challenge(ChallengeTx),
    /// 18: the R1 loser opens R2 (TOG-SPEC-0003 §4.6).
    Appeal(AppealTx),
    /// 19: a storage deal with its first payloads (TOG-SPEC-0004 §4.4.1).
    OpenDeal(Box<OpenDealTx>),
    /// 20: more payloads in an open deal (TOG-SPEC-0004 §4.4.1).
    AppendPayload(AppendPayloadTx),
    /// 21: a custody proof, including `CustodyAck` (TOG-SPEC-0004 §4.4.1, §5.1).
    RespondChallenge(Box<RespondChallengeTx>),
    /// 22: RS shard roots from the beacon-chosen encoder (TOG-SPEC-0004 §5.6.1).
    PostEncoding(PostEncodingTx),
    /// 23: register a storage worker (TOG-SPEC-0004 §3.1).
    RegisterStorageWorker(Box<RegisterStorageWorkerTx>),
    /// 24: proof of a bad Reed–Solomon encoding (TOG-SPEC-0004 §5.6.1).
    EncodingFraud(Box<EncodingFraudTx>),
    /// 25: extend a deal's term (TOG-SPEC-0004 §6.6).
    RenewDeal(RenewDealTx),
    /// 26: bonded on-chain request for named chunks of one slot (TOG-SPEC-0004 §6.6).
    RetrievalDispute(RetrievalDisputeTx),
    /// 27: a selected verifier or juror can't fetch from a deal (TOG-SPEC-0004 §6.5, §6.6).
    FetchStall(Box<FetchStallTx>),
    /// 28: open a retrieval payment channel (TOG-SPEC-0004 §6.6).
    OpenChannel(OpenChannelTx),
    /// 29: close a retrieval payment channel (TOG-SPEC-0004 §6.6).
    CloseChannel(Box<CloseChannelTx>),
    /// 30: register a validator (TOG-SPEC-0002 §2.4).
    RegisterValidator(Box<RegisterValidatorTx>),
    /// 31: bond free balance.
    Bond(BondTx),
    /// 32: start unbonding.
    Unbond(UnbondTx),
    /// 33: withdraw unlocked stake.
    Withdraw(WithdrawTx),
    /// 34: nominate validators.
    Nominate(NominateTx),
    /// 35: change commission from the next era.
    SetCommission(SetCommissionTx),
    /// 36: a DKG encryption key for a coming era (TOG-SPEC-0009 §2.2).
    SetDkgKey(Box<SetDkgKeyTx>),
    /// 37: declared fields of a storage worker (TOG-SPEC-0004 §3.1).
    UpdateStorageWorker(Box<UpdateStorageWorkerTx>),
    /// 38: add to a storage worker's bond.
    BondStorageWorker(BondStorageWorkerTx),
    /// 39: start unbonding a storage worker.
    UnbondStorageWorker(UnbondStorageWorkerTx),
    /// 40: an export agent's external locator (TOG-SPEC-0004 §4.6).
    PostExternalLocator(PostExternalLocatorTx),
    /// 41: a `Sender` broker's on-chain `K_conf` delivery (TOG-SPEC-0010 §4.3).
    DeliverConfKey(Box<DeliverConfKeyTx>),
    /// 42: a bandwidth probe's result, by the prober's worker key (TOG-SPEC-0004 §3.3).
    ProbeReport(Box<ProbeReportTx>),
    /// 43: start unbonding a compute worker (TOG-SPEC-0001 §4.2).
    UnbondWorker(UnbondWorkerTx),
    /// 44: replace a compute worker's worker-set opt-ins (TOG-SPEC-0001 §4.2).
    SetOptIns(SetOptInsTx),
    /// 45: a chunk of AppChain runtime code (TOG-SPEC-0007 §8.1).
    UploadCode(UploadCodeTx),
    /// 46: register an AppChain with pre-checked code (TOG-SPEC-0007 §8.1).
    RegisterAppChain(Box<RegisterAppChainTx>),
    /// 47: buy a bulk coretime region (TOG-SPEC-0005 §6.3).
    PurchaseRegion(PurchaseRegionTx),
    /// 48: prepay on-demand coretime for a chain (TOG-SPEC-0005 §6.3).
    FundOnDemand(FundOnDemandTx),
    /// 49: deliver final L1 → Hub CGMP messages (TOG-SPEC-0002 §4.7).
    DeliverCgmp(Box<DeliverCgmpTx>),
    /// 50: move $TOG from a Hub account to an AppChain (TOG-SPEC-0002 §4.7).
    DepositToChain(DepositToChainTx),
    /// 51: close an AppChain for exits (TOG-SPEC-0007 §8.4).
    CloseAppChain(CloseAppChainTx),
    /// 52: withdraw a balance from a closed AppChain by state proof (TOG-SPEC-0007 §8.4).
    ExitClaim(Box<ExitClaimTx>),
    /// 53: bond a collator and bind its network key (TOG-SPEC-0007 §8.5).
    RegisterCollator(RegisterCollatorTx),
    /// 54: remove a collator record and unreserve its bond (TOG-SPEC-0007 §8.5).
    DeregisterCollator(DeregisterCollatorTx),
    /// 55: bind a verification-module blob to `(chain, id)`, write-once (TOG-SPEC-0007 §7.2, §8.1).
    SetVerificationModule(SetVerificationModuleTx),
    /// 56: a timed walk of a storage worker's media tier (TOG-SPEC-0012 §2.2).
    TierProbeReport(Box<crate::walk::TierProbeReportTx>) = 56,
    /// 57: a storage worker's per-tier capacity split (TOG-SPEC-0012 §1.1).
    DeclareStorageMedia(crate::walk::DeclareStorageMediaTx) = 57,
    /// 60: a storage worker declares slots it lost (TOG-SPEC-0012 §3.2).
    DeclareFaults(crate::fault::DeclareFaultsTx) = 60,
    /// 61: a storage worker asks to prove declared slots again (TOG-SPEC-0012 §3.2).
    DeclareRecovery(crate::fault::DeclareRecoveryTx) = 61,
    /// 68: add to a compute worker's bond (TOG-SPEC-0001 §4.2).
    BondWorker(BondWorkerTx) = 68,
    /// 69: replace a collator's network and session keys (TOG-SPEC-0007 §8.5).
    SetCollatorKeys(SetCollatorKeysTx) = 69,
    /// 70: a chain's manager refuses channels from a source, or lifts that (TOG-SPEC-0002 §4.7).
    RefuseInbound(RefuseInboundTx) = 70,
    /// 72: open a service channel (TOG-SPEC-0011 §2.2).
    OpenServiceChannel(crate::channel::OpenServiceChannelTx) = 72,
    /// 73: add to an open channel's deposit (TOG-SPEC-0011 §2.2).
    TopUpChannel(crate::channel::TopUpChannelTx) = 73,
    /// 75: a payee settles up to 64 channels with their highest vouchers (TOG-SPEC-0011 §2.4).
    /// 74 (a spending allowance) and 76–79 are reserved for TOG-SPEC-0011.
    SettleChannels(crate::channel::SettleChannelsTx) = 75,
    /// 80: ask for a slice of one compute worker (TOG-SPEC-0015 §2).
    RequestReservation(Box<crate::reservation::RequestReservationTx>) = 80,
    /// 81: the offered worker takes a reservation (TOG-SPEC-0015 §3).
    AcceptReservation(crate::reservation::AcceptReservationTx) = 81,
    /// 82: the payer ends its reservation (TOG-SPEC-0015 §5.3).
    CancelReservation(crate::reservation::CancelReservationTx) = 82,
    /// 83: a juror's derived executor sketch (TOG-SPEC-0003 §4.2).
    AttestSketch(AttestSketchTx) = 83,
    /// 84: a voter's sketch of the start checkpoint (TOG-SPEC-0003 §3.3 "Copy test").
    AttestCopySketch(AttestCopySketchTx) = 84,
}

/// The block lane of a `SignedTx` (TOG-SPEC-0002 §5); the system lane carries none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lane {
    /// Compute market: gossiped on `/tog/hub/1/tx/compute`.
    Compute,
    /// User: gossiped on `/tog/hub/1/tx/user`.
    User,
}

impl Lane {
    /// The gossip topic of this lane; a message on it is exactly `borsh(SignedTx)`.
    pub fn topic(self) -> &'static str {
        match self {
            Lane::Compute => "/tog/hub/1/tx/compute",
            Lane::User => "/tog/hub/1/tx/user",
        }
    }

    /// The Grid-plane fast path to validators, `/tog/grid/1/tx`, which carries compute-market
    /// transactions only (TOG-SPEC-0006 §2.4); same message format as [`Lane::topic`].
    pub fn grid_topic(self) -> Option<&'static str> {
        match self {
            Lane::Compute => Some(GRID_TX_TOPIC),
            Lane::User => None,
        }
    }
}

/// Grid-plane transaction topic (TOG-SPEC-0006 §2.4).
pub const GRID_TX_TOPIC: &str = "/tog/grid/1/tx";

impl TxBody {
    /// The lane this variant belongs to (TOG-SPEC-0002 §5).
    pub fn lane(&self) -> Lane {
        match self {
            TxBody::Transfer(_)
            | TxBody::SubmitJob(_)
            | TxBody::RegisterWorker(_)
            | TxBody::SubmitEncrypted(_)
            | TxBody::RegisterEnclave(_)
            | TxBody::PostTeeCollateral(_)
            | TxBody::RegisterStorageWorker(_)
            | TxBody::OpenChannel(_)
            | TxBody::RegisterValidator(_)
            | TxBody::Bond(_)
            | TxBody::Unbond(_)
            | TxBody::Withdraw(_)
            | TxBody::Nominate(_)
            | TxBody::SetCommission(_)
            | TxBody::SetDkgKey(_)
            | TxBody::UpdateStorageWorker(_)
            | TxBody::DeclareStorageMedia(_)
            | TxBody::BondStorageWorker(_)
            | TxBody::UnbondStorageWorker(_)
            | TxBody::DeliverConfKey(_)
            | TxBody::UnbondWorker(_)
            | TxBody::SetOptIns(_)
            | TxBody::UploadCode(_)
            | TxBody::RegisterAppChain(_)
            | TxBody::PurchaseRegion(_)
            | TxBody::FundOnDemand(_)
            | TxBody::DeliverCgmp(_)
            | TxBody::DepositToChain(_)
            | TxBody::CloseAppChain(_)
            | TxBody::ExitClaim(_)
            | TxBody::RegisterCollator(_)
            | TxBody::DeregisterCollator(_)
            | TxBody::SetVerificationModule(_)
            | TxBody::BondWorker(_)
            | TxBody::SetCollatorKeys(_)
            | TxBody::RefuseInbound(_)
            | TxBody::OpenServiceChannel(_)
            | TxBody::TopUpChannel(_)
            | TxBody::RequestReservation(_)
            | TxBody::CancelReservation(_) => Lane::User,
            TxBody::AcceptReservation(_)
            | TxBody::ClaimJob(_)
            | TxBody::ReleaseClaim(_)
            | TxBody::CommitResult(_)
            | TxBody::RevealResult(_)
            | TxBody::ReleaseKeys(_)
            | TxBody::VerifierCommit(_)
            | TxBody::VerifierReveal(_)
            | TxBody::EscrowKey(_)
            | TxBody::BisectPost(_)
            | TxBody::BisectAnswer(_)
            | TxBody::AuditResponse(_)
            | TxBody::Challenge(_)
            | TxBody::Appeal(_)
            | TxBody::OpenDeal(_)
            | TxBody::AppendPayload(_)
            | TxBody::RespondChallenge(_)
            | TxBody::PostEncoding(_)
            | TxBody::EncodingFraud(_)
            | TxBody::RenewDeal(_)
            | TxBody::RetrievalDispute(_)
            | TxBody::FetchStall(_)
            | TxBody::CloseChannel(_)
            | TxBody::PostExternalLocator(_)
            | TxBody::ProbeReport(_)
            | TxBody::TierProbeReport(_)
            | TxBody::DeclareFaults(_)
            | TxBody::DeclareRecovery(_)
            | TxBody::AttestSketch(_)
            | TxBody::AttestCopySketch(_)
            | TxBody::SettleChannels(_) => Lane::Compute,
        }
    }

    /// Digest the account key signs: `H("TOG/v1/tx" ‖ borsh(body))`, variant index included.
    pub fn signing_hash(&self) -> Hash32 {
        tagged_hash(Domain::Tx, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }

    /// Variant name, the EIP-712 `kind` of this body (TOG-SPEC-0007 §4.5).
    pub fn kind(&self) -> &'static str {
        match self {
            TxBody::Transfer(_) => "Transfer",
            TxBody::SubmitJob(_) => "SubmitJob",
            TxBody::ClaimJob(_) => "ClaimJob",
            TxBody::ReleaseClaim(_) => "ReleaseClaim",
            TxBody::CommitResult(_) => "CommitResult",
            TxBody::RevealResult(_) => "RevealResult",
            TxBody::ReleaseKeys(_) => "ReleaseKeys",
            TxBody::VerifierCommit(_) => "VerifierCommit",
            TxBody::VerifierReveal(_) => "VerifierReveal",
            TxBody::RegisterWorker(_) => "RegisterWorker",
            TxBody::SubmitEncrypted(_) => "SubmitEncrypted",
            TxBody::EscrowKey(_) => "EscrowKey",
            TxBody::RegisterEnclave(_) => "RegisterEnclave",
            TxBody::PostTeeCollateral(_) => "PostTeeCollateral",
            TxBody::BisectPost(_) => "BisectPost",
            TxBody::BisectAnswer(_) => "BisectAnswer",
            TxBody::AuditResponse(_) => "AuditResponse",
            TxBody::Challenge(_) => "Challenge",
            TxBody::Appeal(_) => "Appeal",
            TxBody::OpenDeal(_) => "OpenDeal",
            TxBody::AppendPayload(_) => "AppendPayload",
            TxBody::RespondChallenge(_) => "RespondChallenge",
            TxBody::PostEncoding(_) => "PostEncoding",
            TxBody::RegisterStorageWorker(_) => "RegisterStorageWorker",
            TxBody::EncodingFraud(_) => "EncodingFraud",
            TxBody::RenewDeal(_) => "RenewDeal",
            TxBody::RetrievalDispute(_) => "RetrievalDispute",
            TxBody::FetchStall(_) => "FetchStall",
            TxBody::OpenChannel(_) => "OpenChannel",
            TxBody::CloseChannel(_) => "CloseChannel",
            TxBody::RegisterValidator(_) => "RegisterValidator",
            TxBody::Bond(_) => "Bond",
            TxBody::Unbond(_) => "Unbond",
            TxBody::Withdraw(_) => "Withdraw",
            TxBody::Nominate(_) => "Nominate",
            TxBody::SetCommission(_) => "SetCommission",
            TxBody::SetDkgKey(_) => "SetDkgKey",
            TxBody::UpdateStorageWorker(_) => "UpdateStorageWorker",
            TxBody::BondStorageWorker(_) => "BondStorageWorker",
            TxBody::UnbondStorageWorker(_) => "UnbondStorageWorker",
            TxBody::PostExternalLocator(_) => "PostExternalLocator",
            TxBody::DeliverConfKey(_) => "DeliverConfKey",
            TxBody::ProbeReport(_) => "ProbeReport",
            TxBody::TierProbeReport(_) => "TierProbeReport",
            TxBody::DeclareStorageMedia(_) => "DeclareStorageMedia",
            TxBody::DeclareFaults(_) => "DeclareFaults",
            TxBody::DeclareRecovery(_) => "DeclareRecovery",
            TxBody::UnbondWorker(_) => "UnbondWorker",
            TxBody::SetOptIns(_) => "SetOptIns",
            TxBody::UploadCode(_) => "UploadCode",
            TxBody::RegisterAppChain(_) => "RegisterAppChain",
            TxBody::PurchaseRegion(_) => "PurchaseRegion",
            TxBody::FundOnDemand(_) => "FundOnDemand",
            TxBody::DeliverCgmp(_) => "DeliverCgmp",
            TxBody::DepositToChain(_) => "DepositToChain",
            TxBody::CloseAppChain(_) => "CloseAppChain",
            TxBody::ExitClaim(_) => "ExitClaim",
            TxBody::RegisterCollator(_) => "RegisterCollator",
            TxBody::DeregisterCollator(_) => "DeregisterCollator",
            TxBody::SetVerificationModule(_) => "SetVerificationModule",
            TxBody::BondWorker(_) => "BondWorker",
            TxBody::SetCollatorKeys(_) => "SetCollatorKeys",
            TxBody::RefuseInbound(_) => "RefuseInbound",
            TxBody::OpenServiceChannel(_) => "OpenServiceChannel",
            TxBody::TopUpChannel(_) => "TopUpChannel",
            TxBody::SettleChannels(_) => "SettleChannels",
            TxBody::RequestReservation(_) => "RequestReservation",
            TxBody::AcceptReservation(_) => "AcceptReservation",
            TxBody::CancelReservation(_) => "CancelReservation",
            TxBody::AttestSketch(_) => "AttestSketch",
            TxBody::AttestCopySketch(_) => "AttestCopySketch",
        }
    }

    /// The digest a signature over this body covers: the TOG digest for Ed25519 and `Secp256k1`,
    /// the EIP-712 digest under `chain_id` (the executing chain's replay domain) for `Secp256k1Eip712`.
    pub fn digest_for(&self, sig: &Signature, chain_id: u64) -> Hash32 {
        match sig {
            Signature::Secp256k1Eip712(_) => crate::eip712::digest(self, chain_id),
            _ => self.signing_hash(),
        }
    }
}

/// A signed transaction.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SignedTx {
    /// Body.
    pub body: TxBody,
    /// Signature over [`TxBody::digest_for`]; check it with [`SignedTx::signer`].
    pub sig: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{DealId, RetentionClass};
    use crate::storage::{DealOwner, Layout, ReplayGuard};
    use tog_primitives::Scheme;

    #[test]
    fn variant_indices_match_spec() {
        // Each body also checks its lane against the 0002 §5 table.
        let first = |b: &TxBody| {
            let i = borsh::to_vec(b).unwrap()[0];
            let lane = if matches!(i, 2..=8 | 11 | 14..=22 | 24..=27 | 29 | 40 | 42 | 56 | 60 | 61 | 75 | 81 | 83 | 84)
            {
                Lane::Compute
            } else {
                Lane::User
            };
            assert_eq!(b.lane(), lane, "variant {i}");
            i
        };
        assert_eq!(first(&TxBody::ClaimJob(ClaimTx { job_id: [0; 32], bond: 0 })), 2);
        assert_eq!(
            first(&TxBody::ReleaseClaim(ReleaseClaimTx {
                job_id: [0; 32],
                reason: Default::default(),
                claim_height: 0
            })),
            3
        );
        let dead = ReleaseClaimTx { job_id: [0; 32], reason: ReleaseReason::LocatorsDead, claim_height: 7 };
        let dead = borsh::to_vec(&dead).unwrap();
        assert_eq!((dead.len(), dead[32], dead[33]), (41, 1, 7), "claim_height is the last field");
        let stalled = ReleaseReason::HoldersStalled { deal: crate::job::DealId(9) };
        assert_eq!(borsh::to_vec(&stalled).unwrap(), [4, 9, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(borsh::to_vec(&ReleaseReason::BadResume).unwrap(), [5]);
        let commit = ResultCommitTx { job_id: [0; 32], commit: [0; 32], checkpoints: vec![], claim_height: 0 };
        assert_eq!(first(&TxBody::CommitResult(commit)), 4);
        assert_eq!(first(&TxBody::ReleaseKeys(KeyReleaseTx { job_id: [0; 32], keys: vec![] })), 6);
        let vc = VerifierCommit {
            job_id: [0; 32],
            segment: 0,
            sortition_proof: crate::verifier::VrfProof([0; 80]),
            output_commitment: [0; 32],
        };
        assert_eq!(first(&TxBody::VerifierCommit(vc)), 7);
        let vr = VerifierReveal {
            job_id: [0; 32],
            segment: 0,
            own_vote_root: [0; 32],
            own_plaintext_root: [0; 32],
            own_metrics: [0; 32],
            own_sketch: None,
            own_output_locator: None,
        };
        assert_eq!(first(&TxBody::VerifierReveal(Box::new(vr))), 8);
        let key = crate::hub_key::IbeCiphertext { ek_epoch: 0, u: [0; 48], v: [0; 32], w: [0; 32] };
        let enc = EncryptedTx {
            chain_id: 0,
            payer: [0; 20],
            nonce: 0,
            target_height: 0,
            gas_limit: 0,
            max_fee_per_gas: 0,
            key: key.clone(),
            body: vec![],
        };
        assert_eq!(first(&TxBody::SubmitEncrypted(Box::new(enc))), 10);
        let checkpoint = CheckpointCommitment {
            segment: 0,
            plaintext_root: [0; 32],
            ciphertext_root: [0; 32],
            key_commitment: [0; 32],
            size: 0,
            metrics_hash: [0; 32],
            sketch: None,
            checker: None,
        };
        let escrow = KeyEscrowTx {
            job_id: [0; 32],
            segment: 0,
            segment_hash: [0; 32],
            metrics_hash: [0; 32],
            checkpoint,
            work_units: 0,
            escrowed_key: key,
        };
        assert_eq!(first(&TxBody::EscrowKey(Box::new(escrow))), 11);
        let audit = AuditResponseTx { job_id: [0; 32], segment: 0, openings: vec![] };
        assert_eq!(first(&TxBody::AuditResponse(Box::new(audit))), 16);
        let challenge = ChallengeTx { job_id: [0; 32], segment: 0, max_bond: 0, output_commitment: None };
        assert_eq!(first(&TxBody::Challenge(challenge)), 17);
        assert_eq!(first(&TxBody::Appeal(AppealTx { job_id: [0; 32], segment: 0, max_bond: 0 })), 18);
        let open = OpenDealTx {
            owner: DealOwner::Account([0; 20]),
            class: RetentionClass::Hot,
            layout: Layout::Replicate { r: 3 },
            payloads: vec![],
            duration: Some(1),
            max_cost: 0,
            segment: None,
            replay: Some(ReplayGuard { chain_id: 1, nonce: 0 }),
            regions: None,
        };
        assert_eq!(first(&TxBody::OpenDeal(Box::new(open))), 19);
        let append = AppendPayloadTx {
            deal: DealId(0),
            at_count: 0,
            payloads: vec![],
            max_cost: 0,
            segment: None,
            replay: None,
        };
        assert_eq!(first(&TxBody::AppendPayload(append)), 20);
        let post = PostEncodingTx { deal: DealId(0), shard_roots: [0; 32], shard_size: 0 };
        assert_eq!(first(&TxBody::PostEncoding(post)), 22);
        let replay = ReplayGuard { chain_id: 1, nonce: 0 };
        let renew = RenewDealTx { deal: DealId(0), extra_blocks: 1, max_cost: 0, replay };
        assert_eq!(first(&TxBody::RenewDeal(renew)), 25);
        let dispute = RetrievalDisputeTx { deal: DealId(0), slot: 0, offsets: vec![0], max_bond: 0, replay };
        assert_eq!(first(&TxBody::RetrievalDispute(dispute)), 26);
        let stall = FetchStallTx {
            job_id: [0; 32],
            segment: 0,
            draw: crate::sortition::DrawKind::Verify { draw: 0 },
            deal: DealId(0),
            sortition_proof: crate::verifier::VrfProof([0; 80]),
        };
        assert_eq!(first(&TxBody::FetchStall(Box::new(stall))), 27);
        assert_eq!(
            first(&TxBody::OpenChannel(OpenChannelTx {
                holder: crate::por::StorageWorkerId([0; 20]),
                deposit: 1,
                replay
            })),
            28
        );
        let close = CloseChannelTx { channel: crate::channel::ChannelId(0), voucher: None };
        assert_eq!(first(&TxBody::CloseChannel(Box::new(close))), 29);

        use crate::staking::*;
        let (chain_id, signer, nonce) = (1, [1; 20], 0);
        let dkg_key = DkgKey { era: 2, pk: [0; 48], pop: SchnorrPop { a: [0; 48], z: [0; 32] } };
        let register = RegisterValidatorTx {
            chain_id,
            signer,
            nonce,
            consensus_key: [1; 32],
            bls_key: [2; 48],
            bls_pop: [3; 96],
            network_key: [4; 32],
            dkg_key: dkg_key.clone(),
            commission_bps: 500,
            self_bond: MIN_SELF_BOND,
        };
        assert_eq!(first(&TxBody::RegisterValidator(Box::new(register))), 30);
        assert_eq!(first(&TxBody::Bond(BondTx { chain_id, signer, nonce, amount: 1 })), 31);
        assert_eq!(first(&TxBody::Unbond(UnbondTx { chain_id, signer, nonce, amount: 1 })), 32);
        assert_eq!(first(&TxBody::Withdraw(WithdrawTx { chain_id, signer, nonce })), 33);
        assert_eq!(first(&TxBody::Nominate(NominateTx { chain_id, signer, nonce, targets: vec![] })), 34);
        assert_eq!(first(&TxBody::SetCommission(SetCommissionTx { chain_id, signer, nonce, commission_bps: 0 })), 35);
        let set = SetDkgKeyTx { chain_id, signer, nonce, key: dkg_key };
        assert_eq!(first(&TxBody::SetDkgKey(Box::new(set))), 36);
        use crate::storage_worker::*;
        let (owner, owner_nonce, worker) = ([2; 20], 1, crate::por::StorageWorkerId([3; 20]));
        let update = UpdateStorageWorkerTx {
            chain_id,
            owner,
            owner_nonce,
            worker,
            operator_group: None,
            region: crate::eligibility::Region(*b"DE"),
            asn: 1,
            classes: ClassSet(1),
            capacity_bytes: 1 << 30,
            ask: StorageAsk::default(),
        };
        assert_eq!(first(&TxBody::UpdateStorageWorker(Box::new(update))), 37);
        let bond = BondStorageWorkerTx { chain_id, owner, owner_nonce, worker, amount: 1 };
        assert_eq!(first(&TxBody::BondStorageWorker(bond)), 38);
        assert_eq!(
            first(&TxBody::UnbondStorageWorker(UnbondStorageWorkerTx { chain_id, owner, owner_nonce, worker })),
            39
        );
        let locator = crate::storage::ExternalLocator::Arweave { tx_id: [0; 32] };
        let post = crate::storage::PostExternalLocatorTx { deal: DealId(1), locator };
        assert_eq!(first(&TxBody::PostExternalLocator(post)), 40);
        let deliver = crate::enclave::DeliverConfKeyTx {
            chain_id,
            sender: signer,
            nonce,
            job_id: [0; 32],
            enc_key: [1; 32],
            sealed: [2; 80],
        };
        assert_eq!(first(&TxBody::DeliverConfKey(Box::new(deliver))), 41);
        let probe = crate::probe::ProbeReportTx {
            target: [1; 20],
            session: 2,
            proof: crate::verifier::VrfProof([0; 80]),
            ingress_bps: 3,
            egress_bps: 4,
            rtt_us: 5,
            asn: 6,
            region_ok: true,
        };
        assert_eq!(first(&TxBody::ProbeReport(Box::new(probe))), 42);
        let walk = crate::walk::TierProbeReportTx {
            target: crate::por::StorageWorkerId([1; 20]),
            tier: crate::walk::MediaTier::Hdd,
            session: 2,
            proof: crate::verifier::VrfProof([0; 80]),
            net_us: 3,
            transcript_root: [4; 32],
        };
        assert_eq!(first(&TxBody::TierProbeReport(Box::new(walk))), 56);
        let media = crate::walk::DeclareStorageMediaTx {
            worker: crate::por::StorageWorkerId([1; 20]),
            capacity: [2, 3],
            replay: crate::storage::ReplayGuard { chain_id, nonce: 4 },
        };
        assert_eq!(first(&TxBody::DeclareStorageMedia(media)), 57);
        let slots = vec![(DealId(1), 2)];
        let faults = crate::fault::DeclareFaultsTx {
            worker: crate::por::StorageWorkerId([1; 20]),
            slots: slots.clone(),
            replay: ReplayGuard { chain_id, nonce: 5 },
        };
        assert_eq!(first(&TxBody::DeclareFaults(faults)), 60);
        let recovery = crate::fault::DeclareRecoveryTx {
            worker: crate::por::StorageWorkerId([1; 20]),
            slots,
            replay: ReplayGuard { chain_id, nonce: 6 },
        };
        assert_eq!(first(&TxBody::DeclareRecovery(recovery)), 61);
        let unbond = crate::worker::UnbondWorkerTx { chain_id, owner, owner_nonce, worker: [3; 20] };
        assert_eq!(first(&TxBody::UnbondWorker(unbond)), 43);
        let opt = crate::worker::SetOptInsTx { chain_id, owner, owner_nonce, worker: [3; 20], opted_in: vec![] };
        assert_eq!(first(&TxBody::SetOptIns(opt)), 44);
        let up = crate::appchain::tests::upload();
        assert_eq!(first(&TxBody::UploadCode(up)), 45);
        let reg = crate::appchain::tests::register();
        assert_eq!(first(&TxBody::RegisterAppChain(Box::new(reg))), 46);
        let (signer, nonce, chain) = ([1; 20], 0, tog_primitives::ChainId(2));
        let buy = PurchaseRegionTx { chain_id, signer, nonce, chain, period: 1, max_price: 9 };
        assert_eq!(first(&TxBody::PurchaseRegion(buy)), 47);
        let fund = FundOnDemandTx { chain_id, signer, nonce, chain, amount: 9 };
        assert_eq!(first(&TxBody::FundOnDemand(fund)), 48);
        let deliver = DeliverCgmpTx { chain_id, signer, nonce, source: chain, messages: vec![], proof: vec![] };
        assert_eq!(first(&TxBody::DeliverCgmp(Box::new(deliver))), 49);
        let deposit = DepositToChainTx { chain_id, signer, nonce, chain, to: [2; 20], amount: 1 };
        assert_eq!(first(&TxBody::DepositToChain(deposit)), 50);
        assert_eq!(first(&TxBody::CloseAppChain(CloseAppChainTx { chain_id, signer, nonce, chain })), 51);
        let proof = crate::state::StateProof { leaf: None, siblings: vec![] };
        let exit = ExitClaimTx { chain_id, signer, nonce, chain, account: [2; 20], value: vec![], proof };
        assert_eq!(first(&TxBody::ExitClaim(Box::new(exit))), 52);
        let reg = RegisterCollatorTx { chain_id, signer, nonce, chain, network_key: [3; 32], session_key: [4; 20] };
        assert_eq!(first(&TxBody::RegisterCollator(reg)), 53);
        assert_eq!(first(&TxBody::DeregisterCollator(DeregisterCollatorTx { chain_id, signer, nonce, chain })), 54);
        let id = crate::job::VerificationModuleId([4; 16]);
        let set = SetVerificationModuleTx { chain_id, signer, nonce, chain, id, code_hash: [5; 32] };
        assert_eq!(first(&TxBody::SetVerificationModule(set)), 55);
        let bond = BondWorkerTx { chain_id, owner, owner_nonce, worker: [3; 20], amount: 1 };
        assert_eq!(first(&TxBody::BondWorker(bond)), 68);
        let keys = SetCollatorKeysTx { chain_id, signer, nonce, chain, network_key: [3; 32], session_key: [4; 20] };
        assert_eq!(first(&TxBody::SetCollatorKeys(keys)), 69);
        let refuse =
            RefuseInboundTx { chain_id, signer, nonce, dest: chain, source: tog_primitives::ChainId(9), refuse: true };
        assert_eq!(first(&TxBody::RefuseInbound(refuse)), 70);
        assert!(borsh::from_slice::<TxBody>(&[56]).is_err(), "56–67 are unassigned");
        let accept = crate::reservation::AcceptReservationTx { id: 7, offered_at: 9 };
        assert_eq!(first(&TxBody::AcceptReservation(accept)), 81);
        let cancel = crate::reservation::CancelReservationTx { chain_id, payer: signer, nonce, id: 7 };
        assert_eq!(first(&TxBody::CancelReservation(cancel)), 82);
        let attest = AttestSketchTx { job_id: [0; 32], segment: 0, sketch_hash: [0; 32], sketch: None };
        assert_eq!(first(&TxBody::AttestSketch(attest)), 83);
        let copy = AttestCopySketchTx { job_id: [0; 32], segment: 1, copy_hash: [0; 32], sketch: None };
        assert_eq!(first(&TxBody::AttestCopySketch(copy)), 84);
        let replay = ReplayGuard { chain_id, nonce };
        let open = crate::channel::OpenServiceChannelTx {
            service: crate::channel::ServiceKind::Retrieval { holder: crate::por::StorageWorkerId([1; 20]) },
            deposit: 1,
            voucher_key: None,
            max_price_per_gib: 2,
            replay,
        };
        assert_eq!(first(&TxBody::OpenServiceChannel(open)), 72);
        let top_up = crate::channel::TopUpChannelTx { channel: crate::channel::ChannelId(3), amount: 1, replay };
        assert_eq!(first(&TxBody::TopUpChannel(top_up)), 73);
        assert_eq!(first(&TxBody::SettleChannels(crate::channel::SettleChannelsTx { vouchers: vec![] })), 75);
        for i in [71, 74, 76, 77, 78, 79] {
            let err = <TxBody as BorshDeserialize>::deserialize(&mut &[&[i][..], &[0; 256]].concat()[..]).unwrap_err();
            assert!(err.to_string().contains("variant"), "{i} is unassigned: {err}");
        }
        // Each staking body starts with `chain_id`, the signer and its nonce.
        let bond = borsh::to_vec(&TxBody::Bond(BondTx { chain_id: 5, signer: [9; 20], nonce: 3, amount: 1 })).unwrap();
        assert_eq!(bond[1..37], [&5u64.to_le_bytes()[..], &[9; 20], &3u64.to_le_bytes()].concat());
    }

    #[test]
    fn signature_scheme_byte() {
        let ed = Signature::Ed25519 { public_key: [1; 32], sig: [0; 64] };
        assert_eq!(borsh::to_vec(&ed).unwrap()[0], Scheme::Ed25519 as u8);
        assert_eq!(borsh::to_vec(&Signature::Secp256k1([0; 65])).unwrap()[0], Scheme::Secp256k1 as u8);
        assert_eq!(borsh::to_vec(&Signature::Secp256k1Eip712([0; 65])).unwrap()[0], 2);
        assert_eq!(Signature::Secp256k1Eip712([0; 65]).ed25519_signer(), None);
        assert_eq!(ed.ed25519_signer(), Some(ed25519_address(&[1; 32])));
    }
}
