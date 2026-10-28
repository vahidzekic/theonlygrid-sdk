//! AppChain heads and backed candidates as the Hub holds them (TOG-SPEC-0002 §4.2, §4.4,
//! TOG-SPEC-0007 §3.4).
//!
//! ```text
//! head hash       = H("TOG/v1/appchain-header" ‖ HeadData)
//! pov_hash        = H("TOG/v1/pov" ‖ borsh(Pov))
//! candidate_hash  = H("TOG/v1/candidate" ‖ borsh(CandidateReceipt))
//! backing message = H("TOG/v1/backing" ‖ u64 hub_chain_id ‖ candidate_hash)
//! s, q            = ⌊r / session_length⌋, ⌊(r mod session_length) / GROUP_ROTATION⌋, r = relay_parent.0
//! β               = HubBeacon(s · session_length − 1), [0; 32] for s = 0
//! π               = ValidatorIndex 0..n ordered by H("TOG/v1/backing-group" ‖ β ‖ u32 i), ties by index
//! G, off          = max(1, ⌊n / 5⌋), u64_le(H("TOG/v1/backing-offset" ‖ β)[0..8]) mod G
//! group(c, r)     = π[5j .. 5j + 5), j = (rank(c, s) + off + q) mod G (all n when n < 5)
//! reserves(c, r)  = the first BACKING_RESERVES of π[(5j + 5) mod n], … not in group(c, r)
//! legacy group    = (backing rule 1) the BACKING_GROUP_SIZE validators with the smallest
//!                   H("TOG/v1/backing-group" ‖ β ‖ u32 c ‖ u32 i), ties by index
//! pre-check msg   = H("TOG/v1/precheck" ‖ u64 hub_chain_id ‖ code_hash ‖ u64 era ‖ u8 accept)
//! ```
//!
//! Registration and code (TOG-SPEC-0007 §8): `UploadCode` (TxBody 45) in chunks, pre-check votes
//! (`SystemItem::PreCheckVote`), then `RegisterAppChain` (TxBody 46).

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Amount, ChainId, Domain, Hash32, HubHeight};

use crate::consensus::ValidatorIndex;
use crate::eligibility::WorkerSetRules;
use crate::job::VerificationModuleId;

/// `MaxRelayAge`: a candidate's relay parent is one of the last this many Hub blocks.
pub const MAX_RELAY_AGE: u64 = 4;
/// `MaxPending`: most included, not yet final candidates per chain.
pub const MAX_PENDING: usize = 8;
/// `MaxAwaiting`: a `BackedCandidate` is valid only while `appchains.awaiting` holds fewer
/// entries, which bounds `Bitfield.bits` to 80 bytes (TOG-SPEC-0002 §4.4, §4.6).
pub const MAX_AWAITING: usize = 640;
/// Validators in a chain's backing group.
pub const BACKING_GROUP_SIZE: usize = 5;
/// Distinct backing-group votes a `BackedCandidate` needs.
pub const MIN_BACKING_VOTES: usize = 3;
/// `BACKING_RESERVES`: validators beyond a group that may back its chain once the chain has had
/// no inclusion for [`T_FALLBACK`] blocks (backing rule 2).
pub const BACKING_RESERVES: usize = 2;
/// `T_FALLBACK`, in Hub blocks: below [`MAX_RELAY_AGE`].
pub const T_FALLBACK: u64 = 3;
/// `GROUP_ROTATION`, in Hub blocks: every chain moves to the next group this often; divides
/// `session_length` under backing rule 2.
pub const GROUP_ROTATION: u64 = 30;
/// `appchains.backing_rules` absent or `1`: the legacy per-chain draw, no reserves.
pub const BACKING_RULES_LEGACY: u8 = 1;
/// `appchains.backing_rules = 2`: disjoint groups, rotation and reserves (TOG-SPEC-0002 §4.4).
pub const BACKING_RULES_GROUPS: u8 = 2;

/// Most bytes of one `UploadCode` chunk.
pub const MAX_CODE_CHUNK: usize = 1 << 20;
/// Most bytes of Zstd-compressed runtime code.
pub const MAX_CODE_LEN: u32 = 4 << 20;
/// Bytes of one `appchains.code_pieces` entry: an upload is kept in pieces this size (the last
/// shorter), so no state value holds a whole runtime and a vote or a status read doesn't load it
/// (TOG-SPEC-0007 §8.1).
pub const CODE_PIECE: usize = 256 << 10;
/// Most bytes of runtime code once decompressed.
pub const MAX_CODE_UNCOMPRESSED: usize = 16 << 20;
/// Most bytes of a `genesis_head`.
pub const MAX_GENESIS_HEAD: usize = 4 << 10;
/// Most verification modules of a chain.
pub const MAX_VERIFICATION_MODULES: usize = 16;
/// `CodeDepositPerByte`, atto-TOG reserved per byte of code or genesis head (testnet genesis value).
pub const CODE_DEPOSIT_PER_BYTE: Amount = 100_000_000_000_000;
/// `PreCheckPeriod`, in Hub blocks.
pub const PRE_CHECK_PERIOD: u64 = 300;
/// `UpgradeDelay`, in Hub blocks.
pub const UPGRADE_DELAY: u64 = 100;
/// `appchains.next_chain_id` at genesis: 0 is the Hub, 1 the Gateway (TOG-SPEC-0000 §13.2).
pub const FIRST_APPCHAIN_ID: ChainId = ChainId(2);
/// Validator-plane topic of backing statements.
pub const BACKING_TOPIC: &str = "/tog/val/1/backing";
/// Most bytes of a gossiped backing statement.
pub const BACKING_STATEMENT_MAX: usize = 64 * 1024;
/// Request/response protocol of PoV fetches between group members.
pub const POV_PROTOCOL: &str = "/tog/val/1/pov";
/// Frame type of a [`PovRequest`].
pub const POV_REQUEST: u8 = 0x01;
/// Frame type of a PoV.
pub const POV_RESPONSE: u8 = 0x81;
/// Frame type of `NotAvailable`, with no body.
pub const POV_NOT_AVAILABLE: u8 = 0xFF;
/// Bytes of a [`PovRequest`] frame.
pub const POV_REQUEST_LEN: usize = 33;
/// Request/response protocol of candidate submission on the collation plane (TOG-SPEC-0006 §2.2).
pub const COLLATE_PROTOCOL: &str = "/tog/col/1/collate";
/// Frame type of a [`Collation`].
pub const COLLATE_REQUEST: u8 = 0x01;
/// Frame type of `Seconded` ([`BackingStatement`]).
pub const COLLATE_SECONDED: u8 = 0x81;
/// Frame type of an error: one byte, [`CollateError`].
pub const COLLATE_ERROR: u8 = 0xFF;
/// Request/response protocol of PoV recovery for collators on the collation plane (TOG-SPEC-0002
/// §4.5 "PoV recovery for collators").
pub const RECOVER_PROTOCOL: &str = "/tog/col/1/recover";
/// Frame type of a [`RecoverRequest`].
pub const RECOVER_REQUEST: u8 = 0x01;
/// Frame type of `Recovered` (`c`).
pub const RECOVER_RESPONSE: u8 = 0x81;
/// Frame type of an error: one byte, [`RecoverError`].
pub const RECOVER_ERROR: u8 = 0xFF;
/// Bytes of a [`RecoverRequest`] frame.
pub const RECOVER_REQUEST_LEN: usize = 37;
/// Recover requests one peer may make per minute; one at a time.
pub const RECOVERS_PER_MINUTE: usize = 6;
/// Recoveries a validator runs at once.
pub const RECOVERIES_AT_ONCE: usize = 4;

/// An AppChain block's head data: `borsh(Header)` of the runtime (TOG-SPEC-0007 §3.4).
pub type HeadData = Vec<u8>;

/// The head hash of `head`.
pub fn head_hash(head: &[u8]) -> Hash32 {
    tagged_hash(Domain::AppchainHeader, &[head])
}

/// `pov_hash` of an uncompressed `borsh(Pov)`.
pub fn pov_hash(pov: &[u8]) -> Hash32 {
    tagged_hash(Domain::Pov, &[pov])
}

/// `appchains.heads[ChainId]` (TOG-SPEC-0002 §7.2, §4.2), Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppChainHeads {
    /// Head of the last included backed candidate; back to `final_head` on a failed dispute.
    pub pending: HeadData,
    /// Head of the last final candidate.
    pub final_head: HeadData,
    /// Hub height at which `final_head` became final.
    pub final_at: HubHeight,
}

impl AppChainHeads {
    /// At registration: both heads are the chain's `genesis_head` (TOG-SPEC-0007 §8.1).
    pub fn genesis(genesis_head: HeadData, registered_at: HubHeight) -> Self {
        Self { pending: genesis_head.clone(), final_head: genesis_head, final_at: registered_at }
    }
}

/// An AppChain block header (TOG-SPEC-0007 §3.4); its Borsh is [`HeadData`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Header {
    /// Head hash of the parent block; block 1's parent is the genesis head.
    pub parent: Hash32,
    /// Block number.
    pub number: u64,
    /// JMT root after the block.
    pub state_root: Hash32,
    /// `lane_root` over the block's inherents then extrinsics.
    pub extrinsics_root: Hash32,
    /// The Hub block this block was built on: height and hash.
    pub relay_parent: (HubHeight, Hash32),
    /// CGMP outbox root after the block.
    pub outbox_root: Hash32,
    /// Total CGMP messages this chain has processed, after the block.
    pub inbox_processed: u64,
    /// Collator-selection data; opaque to the Hub.
    pub digest: Vec<u8>,
}

impl Header {
    /// Whether `head` is a genesis head (TOG-SPEC-0007 §3.4 "Genesis head"): exactly
    /// `borsh(Header)` with `number = 0` and every field but `state_root` zero.
    pub fn is_genesis(head: &[u8]) -> bool {
        borsh::from_slice::<Header>(head).is_ok_and(|h| {
            h.parent == [0; 32]
                && h.number == 0
                && h.extrinsics_root == [0; 32]
                && h.relay_parent == (0, [0; 32])
                && h.outbox_root == [0; 32]
                && h.inbox_processed == 0
                && h.digest.is_empty()
        })
    }
}

/// What `validate_block` returns (TOG-SPEC-0007 §3.4): a candidate's commitments.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ValidationResult {
    /// The new head.
    pub head: HeadData,
    /// Outbox root after the block.
    pub outbox_root: Hash32,
    /// Total CGMP messages processed after the block.
    pub inbox_processed: u64,
    /// Code hash of an authorized upgrade enacted by this block (TOG-SPEC-0007 §8.3).
    pub new_code: Option<Hash32>,
    /// `(dest, queue head, last nonce)` of every outgoing channel the block appended to,
    /// ascending by `dest`.
    pub outbox: Vec<(ChainId, Hash32, u64)>,
    /// `(source, next nonce)` of every inbound channel the block processed from, ascending by
    /// `source`.
    pub inbox: Vec<(ChainId, u64)>,
}

/// What a candidate is (TOG-SPEC-0002 §4.4).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CandidateDescriptor {
    /// The chain.
    pub chain_id: ChainId,
    /// The block's `header.relay_parent`.
    pub relay_parent: (HubHeight, Hash32),
    /// The block's `Inherent::Collator`.
    pub collator: Address,
    /// Head hash of `Pov.parent_head`.
    pub parent_head_hash: Hash32,
    /// [`pov_hash`] of the uncompressed PoV.
    pub pov_hash: Hash32,
    /// Root of the PoV's availability chunks.
    pub erasure_root: Hash32,
    /// The runtime code the backers ran.
    pub code_hash: Hash32,
}

/// A candidate and its commitments.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CandidateReceipt {
    /// What the candidate is.
    pub descriptor: CandidateDescriptor,
    /// What executing it produced.
    pub commitments: ValidationResult,
}

impl CandidateReceipt {
    /// `candidate_hash`.
    pub fn hash(&self) -> Hash32 {
        tagged_hash(Domain::Candidate, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }
}

/// The backing message a backer signs with its consensus key, for `hub_chain_id =
/// network_id << 32` (TOG-SPEC-0000 §13.2).
pub fn backing_message(hub_chain_id: u64, candidate_hash: &Hash32) -> Hash32 {
    tagged_hash(Domain::Backing, &[&hub_chain_id.to_le_bytes(), candidate_hash])
}

/// A backing group member's statement on a candidate, gossiped on [`BACKING_TOPIC`]
/// (TOG-SPEC-0006 §2.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BackingStatement {
    /// The candidate.
    pub receipt: CandidateReceipt,
    /// In the current era's set.
    pub validator: ValidatorIndex,
    /// Ed25519 by `consensus_key` over [`backing_message`] of the receipt's hash.
    pub sig: [u8; 64],
}

impl BackingStatement {
    /// Whether `sig` verifies under `consensus_key` (`verify_strict`).
    pub fn verify_sig(&self, hub_chain_id: u64, consensus_key: &[u8; 32]) -> bool {
        let m = backing_message(hub_chain_id, &self.receipt.hash());
        ed25519_dalek::VerifyingKey::from_bytes(consensus_key)
            .is_ok_and(|k| k.verify_strict(&m, &ed25519_dalek::Signature::from_bytes(&self.sig)).is_ok())
    }
}

/// How a candidate left `appchains.candidates`, as `approvals_root` records it
/// (TOG-SPEC-0002 §3.1); Borsh indices 0–2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum CandidateFate {
    /// Final (§4.4 "Finality").
    Final,
    /// Removed by an invalid dispute, with the later entries removed with it.
    Invalid,
    /// Dropped by a timeout (§4.6).
    Dropped,
}

/// `SystemItem::BackedCandidate` (variant 6): a candidate with its backing votes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BackedCandidate {
    /// The candidate.
    pub receipt: CandidateReceipt,
    /// Ascending by index: Ed25519 signatures by `consensus_key` over [`backing_message`].
    pub votes: Vec<(ValidatorIndex, [u8; 64])>,
}

/// One entry of `appchains.candidates[ChainId]`, oldest first: an included candidate not yet final.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PendingCandidate {
    /// `candidate_hash`.
    pub hash: Hash32,
    /// The candidate.
    pub receipt: CandidateReceipt,
    /// The indices in `votes`.
    pub backers: Vec<ValidatorIndex>,
    /// Era of the inclusion block, whose `ValidatorIndex` order `backers` use.
    pub era: u64,
    /// Hub height of inclusion.
    pub included_at: HubHeight,
}

/// The session of a relay parent at `relay_height`.
pub fn backing_session(relay_height: HubHeight, session_length: u64) -> u64 {
    relay_height / session_length.max(1)
}

/// The legacy `group(c, s)` of backing rule 1 among `validators` active validators, ascending by
/// index. `beacon` is `HubBeacon(s · session_length − 1)`, `[0; 32]` for session 0.
pub fn backing_group(beacon: &Hash32, chain: ChainId, validators: u16) -> Vec<ValidatorIndex> {
    let mut draws: Vec<(Hash32, u16)> = (0..validators)
        .map(|i| (tagged_hash(Domain::BackingGroup, &[beacon, &chain.0.to_le_bytes(), &u32::from(i).to_le_bytes()]), i))
        .collect();
    draws.sort_unstable();
    let mut group: Vec<ValidatorIndex> =
        draws.into_iter().take(BACKING_GROUP_SIZE).map(|(_, i)| ValidatorIndex(i)).collect();
    group.sort_unstable();
    group
}

/// Who may back a chain's candidate under backing rule 2 (TOG-SPEC-0002 §4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackingAssignment {
    /// `group(c, r)`, ascending by index.
    pub group: Vec<ValidatorIndex>,
    /// `reserves(c, r)`, in permutation order: at most [`BACKING_RESERVES`], none in `group`.
    pub reserves: Vec<ValidatorIndex>,
}

/// `π`: the validator indexes `0..validators` ordered by `H("TOG/v1/backing-group" ‖ β ‖ u32 i)`,
/// ties by index. `beacon` is `β = HubBeacon(s · session_length − 1)`, `[0; 32]` for session 0.
pub fn backing_permutation(beacon: &Hash32, validators: u16) -> Vec<ValidatorIndex> {
    let mut draws: Vec<(Hash32, u16)> = (0..validators)
        .map(|i| (tagged_hash(Domain::BackingGroup, &[beacon, &u32::from(i).to_le_bytes()]), i))
        .collect();
    draws.sort_unstable();
    draws.into_iter().map(|(_, i)| ValidatorIndex(i)).collect()
}

/// `rank(c, s)`: the chain's position in `appchains.session_chains` for the relay parent's session
/// (`session_chains`); a chain not listed there takes `|session_chains|` plus its position among
/// the unlisted chains of `appchains.chain_ids` (`chain_ids`, ascending). `None` for a chain in
/// neither.
pub fn chain_rank(chain: ChainId, session_chains: &[ChainId], chain_ids: &[ChainId]) -> Option<u64> {
    if let Some(i) = session_chains.iter().position(|c| *c == chain) {
        return Some(i as u64);
    }
    let unlisted = chain_ids.iter().filter(|c| !session_chains.contains(c));
    unlisted.enumerate().find(|(_, c)| **c == chain).map(|(i, _)| (session_chains.len() + i) as u64)
}

/// `group(c, r)` and `reserves(c, r)` of backing rule 2 for the chain of rank `rank` (see
/// [`chain_rank`]) and a relay parent at `relay_height`, among `validators` active validators of
/// that height's era. `beacon` is `HubBeacon(s · session_length − 1)`, `[0; 32]` for session 0.
pub fn backing_assignment(
    beacon: &Hash32,
    rank: u64,
    relay_height: HubHeight,
    session_length: u64,
    validators: u16,
) -> BackingAssignment {
    let pi = backing_permutation(beacon, validators);
    let n = pi.len();
    if n <= BACKING_GROUP_SIZE {
        let mut group = pi;
        group.sort_unstable();
        return BackingAssignment { group, reserves: Vec::new() };
    }
    let groups = (n / BACKING_GROUP_SIZE) as u64;
    let step = (relay_height % session_length.max(1)) / GROUP_ROTATION;
    let draw = tagged_hash(Domain::BackingOffset, &[beacon]);
    let offset = u64::from_le_bytes(draw[..8].try_into().expect("8 bytes")) % groups;
    let j = ((u128::from(rank) + u128::from(offset) + u128::from(step)) % u128::from(groups)) as usize;
    let first = j * BACKING_GROUP_SIZE;
    let mut group = pi[first..first + BACKING_GROUP_SIZE].to_vec();
    let reserves = (0..n)
        .map(|k| pi[(first + BACKING_GROUP_SIZE + k) % n])
        .filter(|v| !group.contains(v))
        .take(BACKING_RESERVES)
        .collect();
    group.sort_unstable();
    BackingAssignment { group, reserves }
}

/// `appchains.chains[ChainId]` (TOG-SPEC-0007 §8.1), Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppChainRecord {
    /// The account that registered the chain.
    pub manager: Address,
    /// BLAKE3 of the uncompressed Wasm in effect.
    pub code_hash: Hash32,
    /// `(code_hash, Hub height from which it applies)` (TOG-SPEC-0007 §8.3).
    pub pending_upgrade: Option<(Hash32, HubHeight)>,
    /// At most [`MAX_VERIFICATION_MODULES`], strictly ascending.
    pub verification_modules: Vec<VerificationModuleId>,
    /// Reserved from the manager for the genesis head.
    pub deposit: Amount,
}

/// `appchains.code[code_hash]` (TOG-SPEC-0007 §8.1), Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredCode {
    /// The uploader, who holds its deposit.
    pub payer: Address,
    /// Zstd-compressed length, at most [`MAX_CODE_LEN`].
    pub total_len: u32,
    /// Compressed bytes received so far, kept in `appchains.code_pieces`.
    pub received: u32,
    /// Pre-check status.
    pub status: CodeStatus,
}

/// Status of uploaded code. Borsh index = position.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CodeStatus {
    /// 0: chunks still coming.
    Uploading {
        /// `h + UploadPeriod` of the last chunk; past it, a new upload of the hash replaces it.
        until: HubHeight,
    },
    /// 1: being voted on.
    PreCheck {
        /// Era whose validators vote.
        era: u64,
        /// Hub height at which it is rejected without acceptance.
        until: HubHeight,
        /// `Accept` voters, ascending.
        accept: Vec<ValidatorIndex>,
        /// `Reject` voters, ascending.
        reject: Vec<ValidatorIndex>,
    },
    /// 2: may be registered or upgraded to.
    Accepted,
    /// 3: deposit returned; a new upload may replace it.
    Rejected,
}

/// `UploadPeriod`: Hub blocks an upload may wait for its next chunk (TOG-SPEC-0007 §8.2).
pub const UPLOAD_PERIOD: u64 = 600;

/// Why a transaction fails its stateless checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AppChainTxError {
    /// A chunk empty or over [`MAX_CODE_CHUNK`].
    #[error("code chunk of {0} bytes")]
    Chunk(usize),
    /// `total_len` over [`MAX_CODE_LEN`], or the chunk past it.
    #[error("code length or offset out of range")]
    Length,
    /// `genesis_head` over [`MAX_GENESIS_HEAD`] or not a genesis header.
    #[error("genesis head malformed")]
    GenesisHead,
    /// Verification modules over [`MAX_VERIFICATION_MODULES`] or not strictly ascending.
    #[error("verification modules malformed")]
    Modules,
    /// `worker_set_rules` not well formed.
    #[error("worker-set rules malformed")]
    Rules,
}

/// `TxBody` variant 45, user lane: a chunk of runtime code (TOG-SPEC-0007 §8.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UploadCodeTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; the payer.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// BLAKE3 of the uncompressed Wasm.
    pub code_hash: Hash32,
    /// Zstd-compressed length of the whole code.
    pub total_len: u32,
    /// Where this chunk starts.
    pub offset: u32,
    /// The chunk.
    pub bytes: Vec<u8>,
}

impl UploadCodeTx {
    /// The checks that need no Hub state.
    pub fn check_stateless(&self) -> Result<(), AppChainTxError> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_CODE_CHUNK {
            return Err(AppChainTxError::Chunk(self.bytes.len()));
        }
        let end = u64::from(self.offset) + self.bytes.len() as u64;
        if self.total_len > MAX_CODE_LEN || end > u64::from(self.total_len) {
            return Err(AppChainTxError::Length);
        }
        Ok(())
    }
}

/// `TxBody` variant 46, user lane: registers an AppChain with pre-checked code (TOG-SPEC-0007 §8.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegisterAppChainTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; the manager.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// `Accepted` code.
    pub code_hash: Hash32,
    /// A genesis header, at most [`MAX_GENESIS_HEAD`].
    pub genesis_head: HeadData,
    /// The chain's worker-set rules.
    pub worker_set_rules: WorkerSetRules,
    /// At most [`MAX_VERIFICATION_MODULES`], strictly ascending.
    pub verification_modules: Vec<VerificationModuleId>,
}

impl RegisterAppChainTx {
    /// The checks that need no Hub state; the toolchains named by the rules are checked against it.
    pub fn check_stateless(&self) -> Result<(), AppChainTxError> {
        if self.genesis_head.len() > MAX_GENESIS_HEAD || !Header::is_genesis(&self.genesis_head) {
            return Err(AppChainTxError::GenesisHead);
        }
        let m = &self.verification_modules;
        if m.len() > MAX_VERIFICATION_MODULES || !m.windows(2).all(|w| w[0] < w[1]) {
            return Err(AppChainTxError::Modules);
        }
        let f = &self.worker_set_rules.hw_filter;
        if !f.is_well_formed() || !f.cc.as_ref().map_or(true, |cc| cc.min <= cc.max) {
            return Err(AppChainTxError::Rules);
        }
        Ok(())
    }
}

/// `SystemItem::PreCheckVote` (variant 7): a validator's vote on uploaded code (TOG-SPEC-0007 §8.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PreCheckVote {
    /// The code.
    pub code_hash: Hash32,
    /// The entry's `PreCheck.era`.
    pub era: u64,
    /// In era `era`'s active set.
    pub validator: ValidatorIndex,
    /// `Accept` or `Reject`.
    pub accept: bool,
    /// Ed25519 by `consensus_key` over [`PreCheckVote::message`].
    pub sig: [u8; 64],
}

impl PreCheckVote {
    /// The signed message under `hub_chain_id`.
    pub fn message(&self, hub_chain_id: u64) -> Hash32 {
        tagged_hash(
            Domain::PreCheck,
            &[&hub_chain_id.to_le_bytes(), &self.code_hash, &self.era.to_le_bytes(), &[u8::from(self.accept)]],
        )
    }
}

/// `0x01 Collation`: a collator's candidate.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Collation {
    /// Filled by the collator, `erasure_root` and `commitments` included.
    pub receipt: CandidateReceipt,
    /// `c`, the Zstd-compressed `borsh(Pov)`, at most [`crate::erasure::MAX_POV_COMPRESSED`].
    pub pov: Vec<u8>,
}

impl Collation {
    /// `0x01 ‖ borsh(self)`.
    pub fn encode_frame(&self) -> Vec<u8> {
        let mut m = vec![COLLATE_REQUEST];
        m.extend_from_slice(&borsh::to_vec(self).expect("in-memory borsh cannot fail"));
        m
    }

    /// A request frame, if it is exactly one with a PoV within bounds.
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        match msg.split_first()? {
            (&COLLATE_REQUEST, body) => {
                borsh::from_slice::<Collation>(body).ok().filter(|c| c.pov.len() <= crate::erasure::MAX_POV_COMPRESSED)
            }
            _ => None,
        }
    }
}

/// `0xFF Error` codes of `/tog/col/1/collate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CollateError {
    /// 0.
    BadRequest = 0,
    /// 1: the validator is not in the chain's group.
    NotInGroup = 1,
    /// 2: a check failed.
    InvalidCandidate = 2,
    /// 3.
    Busy = 3,
    /// 4: it already seconded a candidate of this chain at this relay parent.
    AlreadySeconded = 4,
}

/// A `/tog/col/1/collate` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollateResponse {
    /// `0x81 Seconded`.
    Seconded(Box<BackingStatement>),
    /// `0xFF Error`.
    Error(CollateError),
}

impl CollateResponse {
    /// The frame.
    pub fn encode_frame(&self) -> Vec<u8> {
        match self {
            CollateResponse::Seconded(s) => {
                let mut m = vec![COLLATE_SECONDED];
                m.extend_from_slice(&borsh::to_vec(&**s).expect("in-memory borsh cannot fail"));
                m
            }
            CollateResponse::Error(e) => vec![COLLATE_ERROR, *e as u8],
        }
    }

    /// A response frame, if it is exactly one.
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        let error = |e| Some(CollateResponse::Error(e));
        match msg.split_first()? {
            (&COLLATE_SECONDED, body) => borsh::from_slice(body).ok().map(|s| CollateResponse::Seconded(Box::new(s))),
            (&COLLATE_ERROR, [0]) => error(CollateError::BadRequest),
            (&COLLATE_ERROR, [1]) => error(CollateError::NotInGroup),
            (&COLLATE_ERROR, [2]) => error(CollateError::InvalidCandidate),
            (&COLLATE_ERROR, [3]) => error(CollateError::Busy),
            (&COLLATE_ERROR, [4]) => error(CollateError::AlreadySeconded),
            _ => None,
        }
    }
}

/// `0x01` on [`POV_PROTOCOL`]: the PoV `c` of a candidate a group member wants to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PovRequest {
    /// `candidate_hash`.
    pub candidate: Hash32,
}

impl PovRequest {
    /// `0x01 ‖ candidate_hash`.
    pub fn encode_frame(&self) -> Vec<u8> {
        let mut m = vec![POV_REQUEST];
        m.extend_from_slice(&self.candidate);
        m
    }

    /// A request frame, if it is exactly one.
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        match msg.split_first() {
            Some((&POV_REQUEST, body)) if msg.len() == POV_REQUEST_LEN => {
                Some(PovRequest { candidate: body.try_into().ok()? })
            }
            _ => None,
        }
    }
}

/// A [`POV_PROTOCOL`] response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PovResponse {
    /// `0x81 ‖ borsh(pov)`: `c`, at most [`crate::erasure::MAX_POV_COMPRESSED`].
    Pov(Vec<u8>),
    /// `0xFF`, no body: a malformed request, an unknown candidate or a busy server.
    NotAvailable,
}

impl PovResponse {
    /// The frame.
    pub fn encode_frame(&self) -> Vec<u8> {
        match self {
            PovResponse::Pov(c) => {
                let mut m = vec![POV_RESPONSE];
                m.extend_from_slice(&borsh::to_vec(c).expect("in-memory borsh cannot fail"));
                m
            }
            PovResponse::NotAvailable => vec![POV_NOT_AVAILABLE],
        }
    }

    /// A response frame, if it is exactly one with a PoV within bounds.
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        match msg.split_first()? {
            (&POV_RESPONSE, body) => borsh::from_slice::<Vec<u8>>(body)
                .ok()
                .filter(|c| c.len() <= crate::erasure::MAX_POV_COMPRESSED)
                .map(PovResponse::Pov),
            (&POV_NOT_AVAILABLE, []) => Some(PovResponse::NotAvailable),
            _ => None,
        }
    }
}

/// `0x01` on [`RECOVER_PROTOCOL`]: the PoV `c` of a source chain's included candidate, which a
/// destination collator re-executes for the message bodies its source collators withhold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RecoverRequest {
    /// The source chain: the candidate's `descriptor.chain_id`.
    pub chain: ChainId,
    /// `candidate_hash`.
    pub candidate: Hash32,
}

impl RecoverRequest {
    /// `0x01 ‖ borsh(self)`.
    pub fn encode_frame(&self) -> Vec<u8> {
        let mut m = vec![RECOVER_REQUEST];
        m.extend_from_slice(&borsh::to_vec(self).expect("in-memory borsh cannot fail"));
        m
    }

    /// A request frame, if it is exactly one.
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        match msg.split_first() {
            Some((&RECOVER_REQUEST, body)) if msg.len() == RECOVER_REQUEST_LEN => borsh::from_slice(body).ok(),
            _ => None,
        }
    }
}

/// `0xFF Error` codes of [`RECOVER_PROTOCOL`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoverError {
    /// 0.
    BadRequest = 0,
    /// 1: no such included candidate of the chain in the chunk window, or its recovery failed.
    NotAvailable = 1,
    /// 2: over a limit.
    Busy = 2,
}

/// A [`RECOVER_PROTOCOL`] response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoverResponse {
    /// `0x81 Recovered`: `c`, at most [`crate::erasure::MAX_POV_COMPRESSED`].
    Recovered(Vec<u8>),
    /// `0xFF Error`.
    Error(RecoverError),
}

impl RecoverResponse {
    /// The frame.
    pub fn encode_frame(&self) -> Vec<u8> {
        match self {
            RecoverResponse::Recovered(c) => {
                let mut m = vec![RECOVER_RESPONSE];
                m.extend_from_slice(&borsh::to_vec(c).expect("in-memory borsh cannot fail"));
                m
            }
            RecoverResponse::Error(e) => vec![RECOVER_ERROR, *e as u8],
        }
    }

    /// A response frame, if it is exactly one with a PoV within bounds.
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        let error = |e| Some(RecoverResponse::Error(e));
        match msg.split_first()? {
            (&RECOVER_RESPONSE, body) => borsh::from_slice::<Vec<u8>>(body)
                .ok()
                .filter(|c| c.len() <= crate::erasure::MAX_POV_COMPRESSED)
                .map(RecoverResponse::Recovered),
            (&RECOVER_ERROR, [0]) => error(RecoverError::BadRequest),
            (&RECOVER_ERROR, [1]) => error(RecoverError::NotAvailable),
            (&RECOVER_ERROR, [2]) => error(RecoverError::Busy),
            _ => None,
        }
    }
}

/// Approval checkers per candidate in tranche 0 (`k` of TOG-SPEC-0002 §4.6).
pub const APPROVAL_CHECKERS: u64 = 30;
/// `T_tranche`: blocks between approval tranches.
pub const T_TRANCHE: u64 = 4;
/// `T_approve_min`: blocks from availability before finality.
pub const T_APPROVE_MIN: u64 = 5;
/// `T_avail`: blocks from inclusion before an unavailable candidate is dropped.
pub const T_AVAIL: u64 = 10;
/// `T_dispute`: blocks an open dispute may last before the candidate is dropped.
pub const T_DISPUTE: u64 = 300;
/// DST of the approval assignment's BLS signature.
pub const APPROVAL_DST: &[u8] = b"TOG_V1_APPROVAL_BLS12381G2_XMD:SHA-256_SSWU_RO_";
/// Type byte of an `ApprovalVote` on `/tog/val/1/approvals`.
pub const APPROVAL_GOSSIP_VOTE: u8 = 0x00;
/// Type byte of a single-vote `CandidateDispute` on `/tog/val/1/approvals`.
pub const APPROVAL_GOSSIP_DISPUTE: u8 = 0x01;

/// `A_req`: approvals a candidate needs with `n` validators in its era.
pub fn approvals_required(n: usize) -> usize {
    (2 * n / 3 + 1).min(20)
}

/// A bitset over validator indices, LSB first: whether bit `i` is set.
pub fn bit(bits: &[u8], i: usize) -> bool {
    bits.get(i / 8).is_some_and(|b| b >> (i % 8) & 1 == 1)
}

/// Sets bit `i`, growing `bits` as needed.
pub fn set_bit(bits: &mut Vec<u8>, i: usize) {
    if bits.len() <= i / 8 {
        bits.resize(i / 8 + 1, 0);
    }
    bits[i / 8] |= 1 << (i % 8);
}

/// Set bits.
pub fn count_bits(bits: &[u8]) -> usize {
    bits.iter().map(|b| b.count_ones() as usize).sum()
}

/// `SystemItem::AvailabilityBitfield` (variant 3): which awaiting candidates of `era` a validator
/// holds its chunk of (TOG-SPEC-0002 §4.6).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Bitfield {
    /// Hash of block `h − 1`; the bits index the awaiting list of its post-state.
    pub parent: Hash32,
    /// The era whose awaiting candidates the bits cover.
    pub era: u64,
    /// In `staking.sets[era]`.
    pub validator: ValidatorIndex,
    /// Bit `j`: holds its chunk of the `j`-th awaiting entry of `era`; `⌈A / 8⌉` bytes.
    pub bits: Vec<u8>,
    /// Ed25519 by `consensus_key` over [`Bitfield::message`].
    pub sig: [u8; 64],
}

impl Bitfield {
    /// `H("TOG/v1/bitfield" ‖ u64 hub_chain_id ‖ borsh((parent, era, validator, bits)))`.
    pub fn message(&self, hub_chain_id: u64) -> Hash32 {
        let fields =
            borsh::to_vec(&(&self.parent, self.era, self.validator, &self.bits)).expect("in-memory borsh cannot fail");
        tagged_hash(Domain::Bitfield, &[&hub_chain_id.to_le_bytes(), &fields])
    }
}

/// `SystemItem::ApprovalVote` (variant 4): publishing the assignment signature approves the
/// candidate.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ApprovalVote {
    /// `candidate_hash`.
    pub candidate: Hash32,
    /// In the candidate's era.
    pub validator: ValidatorIndex,
    /// Tranche, open from `available_at + 2 + T_TRANCHE · tranche`.
    pub tranche: u32,
    /// BLS by `bls_key` over [`approval_assignment`] with [`APPROVAL_DST`].
    pub sig: [u8; 96],
}

impl ApprovalVote {
    /// The VRF output `out` of this vote's signature.
    pub fn out(&self) -> u64 {
        let h = tagged_hash(Domain::ApprovalOut, &[&self.sig]);
        u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
    }

    /// `selected(tranche)` with `n` validators in the candidate's era.
    pub fn selected(&self, n: u64) -> bool {
        let scale: u128 = if self.tranche == 0 { 1 << 64 } else { 1 << 63 };
        let bound = u128::from(APPROVAL_CHECKERS) * scale / u128::from(n.max(1));
        u128::from(self.out()) < bound
    }
}

/// `assignment(c, t)`: what an approval checker signs; `beacon` is `HubBeacon(available_at)`.
pub fn approval_assignment(hub_chain_id: u64, beacon: &Hash32, candidate: &Hash32, tranche: u32) -> Hash32 {
    tagged_hash(Domain::ApprovalVrf, &[&hub_chain_id.to_le_bytes(), beacon, candidate, &tranche.to_le_bytes()])
}

/// One validator's vote in a candidate dispute.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DisputeVote {
    /// In the candidate's era.
    pub validator: ValidatorIndex,
    /// The candidate checks out.
    pub valid: bool,
    /// Ed25519 by `consensus_key` over [`DisputeVote::message`].
    pub sig: [u8; 64],
}

impl DisputeVote {
    /// `H("TOG/v1/dispute-vote" ‖ u64 hub_chain_id ‖ candidate ‖ u8 valid)`.
    pub fn message(&self, hub_chain_id: u64, candidate: &Hash32) -> Hash32 {
        tagged_hash(Domain::DisputeVote, &[&hub_chain_id.to_le_bytes(), candidate, &[u8::from(self.valid)]])
    }
}

/// `SystemItem::Dispute` (variant 5): votes on an L1 candidate.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CandidateDispute {
    /// The candidate's chain.
    pub chain: ChainId,
    /// `candidate_hash`.
    pub candidate: Hash32,
    /// Ascending by validator, distinct, non-empty.
    pub votes: Vec<DisputeVote>,
}

impl CandidateDispute {
    /// Votes non-empty, ascending and distinct by validator.
    pub fn is_well_formed(&self) -> bool {
        !self.votes.is_empty() && self.votes.windows(2).all(|w| w[0].validator < w[1].validator)
    }
}

/// `appchains.approvals[candidate_hash]`.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ApprovalProgress {
    /// The block in which the candidate became available.
    pub available_at: HubHeight,
    /// Bitset over era indices of accepted `ApprovalVote`s.
    pub approvals: Vec<u8>,
    /// A dispute on it concluded valid; no new dispute is accepted.
    pub cleared: bool,
    /// `HubBeacon(available_at)`, written at the start of block `available_at + 1` before its
    /// system items; `None` until then. An `ApprovalVote`'s assignment needs it (TOG-SPEC-0002 §4.6).
    pub beacon: Option<Hash32>,
}

/// `appchains.disputes[candidate_hash]`: an open dispute.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DisputeState {
    /// Height it opened.
    pub opened_at: HubHeight,
    /// Bitset over era indices voting valid.
    pub valid: Vec<u8>,
    /// Bitset over era indices voting invalid.
    pub invalid: Vec<u8>,
}

/// The two leading fields of the standard `balances` module's `AccountData` (TOG-SPEC-0007
/// §8.4): `(free, reserved)` from `value`, ignoring the bytes after them.
pub fn exit_balance(value: &[u8]) -> Option<(Amount, Amount)> {
    let mut rest = value;
    let free = Amount::deserialize(&mut rest).ok()?;
    let reserved = Amount::deserialize(&mut rest).ok()?;
    Some((free, reserved))
}

/// `TxBody` variant 51, user lane: closes an AppChain for exits (TOG-SPEC-0007 §8.4).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CloseAppChainTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer: the manager, or anyone once no candidate was final for a whole period.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// Chain closed; never the Gateway.
    pub chain: ChainId,
}

/// `TxBody` variant 52, user lane: pays out `account`'s balance on a closed chain by state proof.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExitClaimTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; anyone.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// The closed chain.
    pub chain: ChainId,
    /// Account paid on the Hub.
    pub account: Address,
    /// `balances.accounts[account]` on the chain; see [`exit_balance`].
    pub value: Vec<u8>,
    /// Proof of `Some(value)` against the `state_root` of the chain's `final_head`.
    pub proof: crate::state::StateProof,
}

/// `MaxCollators`: most registered collators per chain.
pub const MAX_COLLATORS: usize = 64;
/// `CollatorBond`, reserved per collator record: 100 $TOG (testnet value).
pub const COLLATOR_BOND: Amount = 100 * 1_000_000_000_000_000_000;

/// `appchains.collators[(chain, account)]` (TOG-SPEC-0007 §8.5), Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CollatorRecord {
    /// Ed25519 libp2p key of the collator node; its `PeerId` is this identity.
    pub network_key: [u8; 32],
    /// Reserved from the account.
    pub bond: Amount,
    /// Signs the collator's gossip seals (TOG-SPEC-0006 §2.5); may equal the bond account.
    pub session_key: Address,
}

/// `TxBody` variant 53, user lane: bonds a collator for `chain` and binds its network key.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegisterCollatorTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; the collator account.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// The chain.
    pub chain: ChainId,
    /// The collator node's Ed25519 libp2p key.
    pub network_key: [u8; 32],
    /// The address of the key that signs the collator's gossip seals; may equal `signer`.
    pub session_key: Address,
}

/// `TxBody` variant 69, user lane: replaces the network and session keys of the signer's
/// collator record for `chain` (TOG-SPEC-0007 §8.5 "Collator keys"); the bond stays.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SetCollatorKeysTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; the collator's bond account.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// The chain.
    pub chain: ChainId,
    /// The new Ed25519 libp2p key.
    pub network_key: [u8; 32],
    /// The new session key's address.
    pub session_key: Address,
}

/// `TxBody` variant 54, user lane: removes the signer's collator record for `chain`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeregisterCollatorTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; the collator account.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// The chain.
    pub chain: ChainId,
}

/// `TxBody` variant 55, user lane, signed by the chain's `manager`: binds an `Accepted` code blob to
/// verification module `id` of `chain`, write-once (TOG-SPEC-0007 §7.2, §8.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SetVerificationModuleTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; the chain's manager.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// The chain.
    pub chain: ChainId,
    /// The module id; a new version is a new id.
    pub id: VerificationModuleId,
    /// `appchains.code[code_hash]`, `Accepted`: the module blob.
    pub code_hash: Hash32,
}

#[cfg(test)]
pub(crate) mod tests;
