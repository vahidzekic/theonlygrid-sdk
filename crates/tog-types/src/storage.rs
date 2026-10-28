//! Storage deal transactions and the payload set tree (TOG-SPEC-0004 §2.2, §4.4.1).
//!
//! A deal stores a set of payloads under one root: a binary Merkle tree of fixed depth 32 over
//! [`PayloadSetLeaf`]s in append order, padded with empty subtrees. The Hub keeps only the
//! [`SetFrontier`]; holders and the executor know every leaf and build [`MerklePath`]s from them.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Amount, Domain, Hash32};

use crate::eligibility::Region;
use crate::job::{DealId, RetentionClass};
use crate::payload::PayloadCommitment;
use crate::sortition::DrawKind;
use crate::state::DealRole;
use crate::verifier::VrfProof;

/// Depth of every payload set tree.
pub const SET_DEPTH: usize = 32;
/// Most payloads one `OpenDeal` or `AppendPayload` adds.
pub const MAX_PAYLOADS_PER_TX: usize = 256;
/// `MAX_DEAL_LEAVES`: the most leaves a deal's payload set holds (§4.4.1 rule 3 "Leaf cap"); an
/// `OpenDeal` or `AppendPayload` past it is invalid.
pub const MAX_DEAL_LEAVES: u32 = 65_536;

/// Who owns a deal (TOG-SPEC-0004 §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum DealOwner {
    /// 0: one of a job's deals; at most one per role.
    Job {
        /// Job.
        job_id: Hash32,
        /// Role.
        role: DealRole,
    },
    /// 1: an account's own deal.
    Account(Address),
}

/// How a deal's set is stored (TOG-SPEC-0004 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Layout {
    /// 0: `r` full replicas.
    Replicate {
        /// Replicas.
        r: u8,
    },
    /// 1: systematic RS(k, m) over GF(2^16), striped by 4 KiB rows.
    ReedSolomon {
        /// Data shards.
        k: u8,
        /// Parity shards.
        m: u8,
        /// Merkle root over the `k + m` shard roots.
        shard_roots: Hash32,
    },
}

impl Layout {
    /// Slots one placement of the deal draws (TOG-SPEC-0004 §4.4): `r`, or 2 for an RS deal,
    /// whose first placement is `Replicate { r: 2 }` (§5.6.1).
    pub fn placement_slots(&self) -> u64 {
        match *self {
            Layout::Replicate { r } => u64::from(r),
            Layout::ReedSolomon { .. } => 2,
        }
    }

    /// `stored` of the deal charge (TOG-SPEC-0004 §4.4.1 rule 2): `r × new_bytes`, or for RS
    /// `(k + m) × shard_size` over the whole deal's `deal_bytes`.
    pub fn stored(&self, new_bytes: u64, deal_bytes: u64) -> u128 {
        match *self {
            Layout::Replicate { r } => u128::from(r) * u128::from(new_bytes),
            Layout::ReedSolomon { k, m, .. } => {
                (u128::from(k) + u128::from(m)) * u128::from(crate::rs::shard_size(deal_bytes, k))
            }
        }
    }
}

/// Blocks per hour (2 s blocks).
pub const BLOCKS_PER_HOUR: u128 = 1800;

/// Fixed part of `T_place` in blocks (TOG-SPEC-0004 §4.4).
pub const T_PLACE_BASE: u64 = 60;
/// Bytes placed per 2 s block on mainnet (`network_id` 1): `B_place` = 10^8 B/s, 1 Gbps with
/// 0.8 goodput (TOG-SPEC-0004 §4.4, §14).
pub const PLACE_BYTES_PER_BLOCK: u64 = 200_000_000;
/// Bytes placed per 2 s block on every other network: `B_place` = 5·10^6 B/s, what testnet
/// holders on home links sustain (TOG-SPEC-0004 §4.4).
pub const PLACE_BYTES_PER_BLOCK_TESTNET: u64 = 10_000_000;

/// `B_place × 2 s` of network `network_id`.
pub fn place_bytes_per_block(network_id: u32) -> u64 {
    if network_id == 1 {
        PLACE_BYTES_PER_BLOCK
    } else {
        PLACE_BYTES_PER_BLOCK_TESTNET
    }
}

/// `T_place` for `S = bytes` on network `network_id`: `60 + ⌈S / (B_place × 2 s)⌉` blocks, `S`
/// the bytes the source sends for the acks the deadline covers (TOG-SPEC-0004 §4.4).
pub fn t_place(bytes: u64, network_id: u32) -> u64 {
    T_PLACE_BASE + bytes.div_ceil(place_bytes_per_block(network_id))
}

/// `T_place` of `size` new bytes sent to each of `slots` slots: `S = slots × size`, saturating
/// (TOG-SPEC-0004 §4.4).
pub fn t_place_slots(size: u64, slots: u64, network_id: u32) -> u64 {
    t_place(size.saturating_mul(slots), network_id)
}

/// Replicas of a `ChallengeWindow` deal (TOG-SPEC-0004 §4.1), the layout a job's deals will
/// have when `T_place` is written with the job's one byte count (§4.4).
pub const CHALLENGE_WINDOW_REPLICAS: u8 = 3;
/// Bytes per GiB.
const GIB: u128 = 1 << 30;

/// What an export agent posts once an external copy exists; a hint only (TOG-SPEC-0004 §4.6).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ExternalLocator {
    /// 0: Arweave transaction.
    Arweave {
        /// Transaction id.
        tx_id: [u8; 32],
    },
    /// 1: Filecoin deal.
    Filecoin {
        /// Deal id.
        deal_id: u64,
        /// Piece CID bytes.
        piece_cid: Vec<u8>,
    },
}

/// Most bytes of a Filecoin `piece_cid` (TOG-SPEC-0004 §4.6).
pub const MAX_PIECE_CID: usize = 128;

/// `TxBody` variant 40 (compute market), signed by the storage key of a holder of `deal`
/// with an `Active` slot: an export agent's locator (TOG-SPEC-0004 §4.6).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PostExternalLocatorTx {
    /// A `Job { role: Outputs }` deal of class `LongTerm`.
    pub deal: DealId,
    /// The locator; its variant index is its `ExternalBackend` index.
    pub locator: ExternalLocator,
}

/// When a deal ends (TOG-SPEC-0004 §4.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum DealEnd {
    /// 0: at this height.
    At(u64),
    /// 1: `ChallengeWindow`: `G_release` after the job is terminal with no dispute open, never later
    /// than `max_end`.
    OnJobTerminal {
        /// Job.
        job_id: Hash32,
        /// Bound from admission ([`crate::timing::max_end`]).
        max_end: u64,
    },
}

impl DealEnd {
    /// The last height the deal is paid for.
    pub fn paid_until(&self) -> u64 {
        match *self {
            DealEnd::At(h) => h,
            DealEnd::OnJobTerminal { max_end, .. } => max_end,
        }
    }
}

/// Where a deal is in its lifecycle (TOG-SPEC-0004 §4.7, §11).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum DealState {
    /// 0: a lazy checkpoint deal before V3: no holders (§4.8).
    Deferred,
    /// 1: holders are drawn and must ack by `deadline`.
    Placing {
        /// `h + T_place`.
        deadline: u64,
    },
    /// 2: every slot acked.
    Active,
    /// 3: replacements are being drawn for these slots.
    Repairing {
        /// Bit `i` (LSB first) set iff slot `i` is being repaired, `⌈slots / 8⌉` bytes.
        slots: Vec<u8>,
    },
    /// 4: holders may delete the bytes after `until`.
    Releasing {
        /// Last height.
        until: u64,
    },
    /// 5: collateral unlocked, budget refunded.
    Closed,
    /// 6: an RS re-encoding gave up (§5.6.1); terminal like `Closed`.
    Lost,
}

/// A holder slot's standing (TOG-SPEC-0004 §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SlotStatus {
    /// 0: drawn, not yet acked.
    Placing,
    /// 1: acked.
    Active,
    /// 2: failed a challenge at this height.
    Failed {
        /// Height.
        at: u64,
    },
    /// 3: released.
    Released,
}

/// One holder of a deal (TOG-SPEC-0004 §11).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HolderSlot {
    /// The storage worker.
    pub worker: crate::por::StorageWorkerId,
    /// Replica index, or RS shard index.
    pub shard: u16,
    /// Height of its valid `Ack` answer.
    pub acked_at: Option<u64>,
    /// Standing.
    pub status: SlotStatus,
    /// Lazy `Checkpoints` deals only (§4.8): the (leaf index, leaf) pairs this slot holds,
    /// ascending. Empty for every other deal: the slot holds the whole set.
    pub leaves: Vec<(u32, PayloadSetLeaf)>,
    /// The set this slot's last valid `Ack` (placement or append, §4.4.1 rule 3) proved: the
    /// `set` of that Ack's span, even when the deal grew before the answer. Recorded only for a
    /// slot that holds the whole payload set, and never replaced by a smaller set. A `Holder`
    /// span of such a slot names it (§5.1 "Spans"); `None` (no Ack yet) and every other slot use
    /// the slot's ordinary set.
    pub acked_set: Option<PayloadSetRoot>,
}

/// `storage.deals[DealId]` (TOG-SPEC-0004 §11, TOG-SPEC-0002 §7.2), Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StorageDeal {
    /// Id, in opening order.
    pub id: DealId,
    /// Owner.
    pub owner: DealOwner,
    /// The payload set.
    pub payloads: PayloadSetRoot,
    /// Its incremental tree frontier (§4.4.1), at most 32 entries.
    pub frontier: Vec<Hash32>,
    /// Retention class.
    pub class: RetentionClass,
    /// Layout.
    pub layout: Layout,
    /// Holders: `r`, or `k + m`.
    pub slots: Vec<HolderSlot>,
    /// Reference price per GiB·hour at open (§4.2).
    pub price_per_gib_hour: Amount,
    /// Placement price per GiB at open: `storage.prices[class].place_per_gib` (§4.2).
    pub place_per_gib: Amount,
    /// Collateral each slot locks (§3.2).
    pub collateral_per_slot: Amount,
    /// Storage fees not yet streamed to slots in good standing.
    pub budget: Amount,
    /// Reserved for verifier and juror reimbursements (§6.4).
    pub retrieval_allowance: Amount,
    /// Funded by slashes (§5.4).
    pub repair_reserve: Amount,
    /// Opening height.
    pub start: u64,
    /// End.
    pub end: DealEnd,
    /// Lifecycle state.
    pub state: DealState,
    /// External copies; hints only (§4.6).
    pub external: Vec<ExternalLocator>,
    /// Lazy `Checkpoints` deals only (§4.8): bit `i` (LSB first) set iff leaf `i` is materialized,
    /// `⌈count / 8⌉` bytes. Empty for every other deal, where all leaves are.
    pub materialized: Vec<u8>,
    /// Holder regions the data owner accepts (§4.3 "Region preference", §11): `OpenDealTx.regions`
    /// of an `Account` or `Job { Inputs }` deal, recorded at open for every later draw; `None`
    /// for the other job roles, which read the job's `WorkerSetRules.regions`. Appended last.
    pub regions: Option<Vec<Region>>,
}

impl StorageDeal {
    /// The set and its frontier together.
    pub fn set(&self) -> SetFrontier {
        SetFrontier { set: self.payloads, frontier: self.frontier.clone() }
    }
}

/// `storage.encodings[DealId]`: a `ReedSolomon` deal's encoding (TOG-SPEC-0004 §5.6.1, §11
/// "Encoding state"), from `OpenDeal` until the deal is pruned. Borsh in field order.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Encoding {
    /// The encoder that must post, if any.
    pub encoder: Option<PendingEncoder>,
    /// The shards in force: their root is the deal's `shard_roots`.
    pub current: Option<ShardSet>,
    /// Shards of a re-encoding, being acked; they replace `current` once all are `Active`.
    pub next: Option<ShardSet>,
    /// Encoders of the pending re-encoding that missed their deadline in a row.
    pub misses: u8,
}

impl Encoding {
    /// The shard set `slot` holds a shard of; `None` for a slot holding the whole set.
    pub fn shards_of(&self, slot: u16) -> Option<&ShardSet> {
        [&self.current, &self.next].into_iter().flatten().find(|s| s.slots.contains(&slot))
    }
}

/// An encoder drawn to post a deal's shards (TOG-SPEC-0004 §5.6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PendingEncoder {
    /// Its index in `StorageDeal.slots`; that slot holds the whole set.
    pub slot: u16,
    /// Last height its `PostEncodingTx` is accepted; `None` until a newly drawn encoder acks.
    pub deadline: Option<u64>,
}

/// One posted set of RS shards (TOG-SPEC-0004 §5.6.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShardSet {
    /// `shard_roots`.
    pub roots: Hash32,
    /// Bytes per shard.
    pub size: u64,
    /// The slot holding each shard, by shard index `0..k+m`; a redrawn holder takes the failed
    /// slot's place.
    pub slots: Vec<u16>,
    /// The encoder's slot, whose collateral stays locked as the encoding bond until the deal ends.
    pub encoder: u16,
    /// A fraud proof has slashed the bond.
    pub slashed: bool,
    /// Shard indices a valid `Data` fraud proof named, ascending, no duplicates: read as erasures.
    pub bad: Vec<u16>,
    /// Shard acks missed while the set is placed, from its `PostEncoding` until all its `k + m`
    /// slots are first `Active`; the set is abandoned when it exceeds `m` (TOG-SPEC-0004 §5.6.1
    /// step 4 "Abandoned shard set").
    pub missed: u16,
}

/// Storage prices of the era at a transaction's inclusion height (TOG-SPEC-0005), in atto-TOG:
/// `storage.prices[class]` (TOG-SPEC-0002 §7.2, TOG-SPEC-0004 §4.2), Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoragePrices {
    /// The class's reference price per GiB·hour.
    pub per_gib_hour: Amount,
    /// Placement price per GiB.
    pub place_per_gib: Amount,
}

/// `storage.params` (TOG-SPEC-0002 §7.2), set at genesis and changed by governance. Borsh in
/// field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StorageParams {
    /// `κ_gb`: collateral floor per GiB (TOG-SPEC-0004 §3.2).
    pub kappa_gb: Amount,
    /// `B_chunk`: `RetrievalDispute` bond per chunk (TOG-SPEC-0004 §6.6).
    pub b_chunk: Amount,
    /// `ChallengeWindowMinEgressBps`: least probed egress of a `ChallengeWindow` holder, and
    /// `B_lazy` (TOG-SPEC-0004 §3.1 "Egress floors (exact)", §4.8).
    pub challenge_window_min_egress_bps: u64,
    /// `LongTermMinEgressBps`: least probed egress of a `LongTerm` holder (TOG-SPEC-0004 §3.1).
    pub long_term_min_egress_bps: u64,
}

impl StorageParams {
    /// The least `(challenge_window_min_egress_bps, long_term_min_egress_bps)` a genesis of
    /// `network_id` may set (TOG-SPEC-0004 §3.1 "Egress floors (exact)"): 10 and 1 Gbps on
    /// mainnet (1), 1 Gbps and 100 Mbps on the public testnet (2), anything above 0 elsewhere.
    pub fn egress_floors(network_id: u32) -> (u64, u64) {
        match network_id {
            1 => (10_000_000_000, 1_000_000_000),
            2 => (1_000_000_000, 100_000_000),
            _ => (1, 1),
        }
    }

    /// Both egress floors are at least [`Self::egress_floors`] of `network_id`.
    pub fn meets_egress_floors(&self, network_id: u32) -> bool {
        let (cw, lt) = Self::egress_floors(network_id);
        self.challenge_window_min_egress_bps >= cw && self.long_term_min_egress_bps >= lt
    }

    /// The defaults of a genesis of `network_id`: its floors on networks 1 and 2, 100 Mbps and
    /// 10 Mbps elsewhere (TOG-SPEC-0004 §3.1).
    pub fn default_egress(network_id: u32) -> (u64, u64) {
        match network_id {
            1 | 2 => Self::egress_floors(network_id),
            _ => (100_000_000, 10_000_000),
        }
    }
}

/// The least a payload is charged for: `max(size, 1 MiB)` (C-37).
pub const MIN_BILLED_PAYLOAD: u64 = 1 << 20;

/// The bytes payloads of `sizes` are charged for, each `max(size, MIN_BILLED_PAYLOAD)` (C-37).
/// `None` on overflow.
pub fn charged_bytes(sizes: impl IntoIterator<Item = u64>) -> Option<u64> {
    sizes.into_iter().try_fold(0u64, |a, s| a.checked_add(s.max(MIN_BILLED_PAYLOAD)))
}

/// A whole deal's bytes for a later holding charge (`RenewDeal`, an extension): its set keeps no
/// sizes per payload, so `max(total_size, count × MIN_BILLED_PAYLOAD)`, a lower bound of
/// [`charged_bytes`] over its payloads (C-37).
pub fn charged_set_bytes(set: &PayloadSetRoot) -> u64 {
    set.total_size.max(u64::from(set.count).saturating_mul(MIN_BILLED_PAYLOAD))
}

/// What the Hub charges an `OpenDeal` or `AppendPayload` storing `stored` bytes for `blocks`
/// blocks (TOG-SPEC-0004 §4.4.1 rule 2): `⌈p_class × stored × blocks / (2^30 × 1800)⌉ +
/// ⌈p_place × stored / 2^30⌉`, each term rounded up on its own. `None` on `u128` overflow.
/// Wallets and `togd` use it for `max_cost`.
pub fn deal_charge(stored: u128, blocks: u64, prices: &StoragePrices) -> Option<Amount> {
    let hold =
        prices.per_gib_hour.checked_mul(stored)?.checked_mul(u128::from(blocks))?.div_ceil(GIB * BLOCKS_PER_HOUR);
    let place = prices.place_per_gib.checked_mul(stored)?.div_ceil(GIB);
    hold.checked_add(place)
}

/// Replay protection of an `Account` deal transaction: the signer's next nonce, as in `TransferTx`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReplayGuard {
    /// Replay domain, TOG-SPEC-0000 §13.2.
    pub chain_id: u64,
    /// Signer account nonce.
    pub nonce: u64,
}

/// `TxBody` variant 19. Opens a deal and adds its first leaves (TOG-SPEC-0004 §4.4.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OpenDealTx {
    /// Owner; a job has at most one deal per role.
    pub owner: DealOwner,
    /// Retention class.
    pub class: RetentionClass,
    /// Must match the class (§4.1).
    pub layout: Layout,
    /// 1 to [`MAX_PAYLOADS_PER_TX`] payloads; leaves in this order.
    pub payloads: Vec<PayloadCommitment>,
    /// Blocks; `Some` for `Account` deals (end = `h + duration`), `None` for job deals.
    pub duration: Option<u64>,
    /// Rejected if what the Hub charges exceeds it.
    pub max_cost: Amount,
    /// `Dissent` deals only: the disputed segment whose bond pays.
    pub segment: Option<u32>,
    /// `Some` for `Account` deals, `None` for job deals.
    pub replay: Option<ReplayGuard>,
    /// Holder regions the data owner accepts (§4.3 "Region preference"): `Account` and
    /// `Job { Inputs }` deals only. `Some` is 1 to [`MAX_DEAL_REGIONS`], strictly ascending.
    /// Appended last.
    pub regions: Option<Vec<Region>>,
}

/// Most entries of `OpenDealTx.regions`.
pub const MAX_DEAL_REGIONS: usize = 16;

/// `TxBody` variant 20. Appends leaves to an open `Replicate` deal (TOG-SPEC-0004 §4.4.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppendPayloadTx {
    /// Deal.
    pub deal: DealId,
    /// The set's count before this append; a replayed or stale copy fails.
    pub at_count: u32,
    /// 1 to [`MAX_PAYLOADS_PER_TX`] payloads.
    pub payloads: Vec<PayloadCommitment>,
    /// As in [`OpenDealTx`].
    pub max_cost: Amount,
    /// As in [`OpenDealTx`].
    pub segment: Option<u32>,
    /// As in [`OpenDealTx`].
    pub replay: Option<ReplayGuard>,
}

/// Most chunks one [`RetrievalDisputeTx`] names (TOG-SPEC-0004 §6.6).
pub const MAX_DISPUTE_OFFSETS: usize = 16;

/// `TxBody` variant 25 (compute market). Extends a deal's term; any account may pay
/// (TOG-SPEC-0004 §6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RenewDealTx {
    /// Deal; its end must be `At(e)`, state `Placing` or `Active`.
    pub deal: DealId,
    /// Blocks added to the end; at least 1.
    pub extra_blocks: u64,
    /// Rejected if the charge exceeds it.
    pub max_cost: Amount,
    /// The payer's next nonce.
    pub replay: ReplayGuard,
}

/// `TxBody` variant 26 (compute market). A bonded on-chain request for named chunks of one slot,
/// answered by an ordinary `RespondChallengeTx` (TOG-SPEC-0004 §6.5, §6.6).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RetrievalDisputeTx {
    /// Deal.
    pub deal: DealId,
    /// Slot.
    pub slot: u16,
    /// 1 to [`MAX_DISPUTE_OFFSETS`] byte offsets in the deal's set (the shard for RS), strictly
    /// ascending; each below the set's `total_size` (checked against state).
    pub offsets: Vec<u64>,
    /// Rejected if the bond `offsets.len() × B_chunk` exceeds it.
    pub max_bond: Amount,
    /// The signer's next nonce.
    pub replay: ReplayGuard,
}

/// `TxBody` variant 27 (compute market). A selected verifier or juror that can't fetch from
/// `deal`; signed by its worker key (TOG-SPEC-0004 §6.5 step 1, §6.6).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FetchStallTx {
    /// Job.
    pub job_id: Hash32,
    /// Segment.
    pub segment: u32,
    /// The draw the signer was selected in.
    pub draw: DrawKind,
    /// One of the job's deals the segment reads (`Inputs` or `Checkpoints`).
    pub deal: DealId,
    /// Sortition proof selecting the signer in `(job_id, segment, draw)`.
    pub sortition_proof: VrfProof,
}

/// Why a deal transaction is malformed, before any state is read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DealTxError {
    /// No payloads, or more than [`MAX_PAYLOADS_PER_TX`].
    #[error("a deal transaction adds 1 to 256 payloads")]
    PayloadCount,
    /// The layout does not fit the retention class.
    #[error("layout does not match the retention class")]
    Layout,
    /// `duration` or `replay` set for a job deal, or missing for an account deal.
    #[error("duration and replay are for account deals only, and required there")]
    Owner,
    /// `segment` set outside a `Dissent` deal, or missing on one.
    #[error("segment is for Dissent deals only, and required there")]
    Segment,
    /// `extra_blocks` is 0.
    #[error("a renewal adds at least one block")]
    ExtraBlocks,
    /// No offsets, more than [`MAX_DISPUTE_OFFSETS`], or not strictly ascending.
    #[error("a retrieval dispute names 1 to 16 strictly ascending offsets")]
    Offsets,
    /// A payload commitment isn't `version` 1 with `piece_log2` in 20..=22 (§2.2).
    #[error("payload commitments are version 1 with piece_log2 20..=22")]
    Commitment,
    /// `regions` empty, longer than [`MAX_DEAL_REGIONS`], not strictly ascending, or set on a job
    /// deal other than `Inputs` (§4.3 "Region preference").
    #[error("regions: 1 to 16 strictly ascending, Account and Inputs deals only")]
    Regions,
}

impl RenewDealTx {
    /// Shape rules of §6.6 that need no state.
    pub fn check(&self) -> Result<(), DealTxError> {
        if self.extra_blocks == 0 {
            return Err(DealTxError::ExtraBlocks);
        }
        Ok(())
    }
}

impl RetrievalDisputeTx {
    /// Shape rules of §6.6 that need no state.
    pub fn check(&self) -> Result<(), DealTxError> {
        let ascending = self.offsets.windows(2).all(|w| w[0] < w[1]);
        if !(1..=MAX_DISPUTE_OFFSETS).contains(&self.offsets.len()) || !ascending {
            return Err(DealTxError::Offsets);
        }
        Ok(())
    }
}

fn check_payloads(payloads: &[PayloadCommitment]) -> Result<(), DealTxError> {
    if !(1..=MAX_PAYLOADS_PER_TX).contains(&payloads.len()) {
        return Err(DealTxError::PayloadCount);
    }
    // §2.2: a holder or fetcher splits the payload into 2^piece_log2-byte pieces.
    let v1 = |p: &PayloadCommitment| p.version == 1 && (20..=22).contains(&p.piece_log2);
    if !payloads.iter().all(v1) {
        return Err(DealTxError::Commitment);
    }
    Ok(())
}

impl OpenDealTx {
    /// Shape rules of §4.4.1 that need no state.
    pub fn check(&self) -> Result<(), DealTxError> {
        check_payloads(&self.payloads)?;
        let rs = matches!(self.layout, Layout::ReedSolomon { .. });
        if rs != (self.class == RetentionClass::LongTerm) {
            return Err(DealTxError::Layout);
        }
        let account = matches!(self.owner, DealOwner::Account(_));
        if self.duration.is_some() != account || self.replay.is_some() != account {
            return Err(DealTxError::Owner);
        }
        let dissent = matches!(self.owner, DealOwner::Job { role: DealRole::Dissent, .. });
        if self.segment.is_some() != dissent {
            return Err(DealTxError::Segment);
        }
        // §4.3 "Region preference": only the data owner narrows the holders.
        if let Some(regions) = &self.regions {
            let owner = matches!(self.owner, DealOwner::Account(_) | DealOwner::Job { role: DealRole::Inputs, .. });
            let ascending = regions.windows(2).all(|w| w[0] < w[1]);
            if !owner || regions.is_empty() || regions.len() > MAX_DEAL_REGIONS || !ascending {
                return Err(DealTxError::Regions);
            }
        }
        Ok(())
    }

    /// The leaves this transaction adds to an empty set; `None` if the sizes overflow.
    pub fn leaves(&self) -> Option<Vec<PayloadSetLeaf>> {
        PayloadSetLeaf::chain(0, &self.payloads)
    }
}

impl AppendPayloadTx {
    /// Shape rules of §4.4.1 that need no state; the deal decides `segment` and `replay`.
    pub fn check(&self) -> Result<(), DealTxError> {
        check_payloads(&self.payloads)
    }
}

/// One payload of a set, at its cumulative byte offset (TOG-SPEC-0004 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PayloadSetLeaf {
    /// Payload root.
    pub root: Hash32,
    /// Sum of the sizes of the leaves before it.
    pub offset: u64,
    /// Payload size.
    pub size: u64,
}

impl PayloadSetLeaf {
    /// Leaves for `payloads` appended to a set whose `total_size` is `offset`; `None` if the
    /// offsets overflow.
    pub fn chain(mut offset: u64, payloads: &[PayloadCommitment]) -> Option<Vec<Self>> {
        payloads
            .iter()
            .map(|p| {
                let leaf = Self { root: p.root, offset, size: p.size };
                offset = offset.checked_add(p.size)?;
                Some(leaf)
            })
            .collect()
    }

    /// `H("TOG/v1/set-leaf" ‖ borsh(leaf))`.
    pub fn hash(&self) -> Hash32 {
        tagged_hash(Domain::SetLeaf, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }
}

/// A deal's set: tree root, leaf count, and bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PayloadSetRoot {
    /// Root of the depth-32 tree.
    pub root: Hash32,
    /// Leaves.
    pub count: u32,
    /// Sum of leaf sizes.
    pub total_size: u64,
}

/// Opening of one leaf: exactly [`SET_DEPTH`] siblings, leaf level first.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MerklePath {
    /// Leaf index.
    pub index: u32,
    /// Siblings, leaf level first.
    pub siblings: Vec<Hash32>,
}

/// `H("TOG/v1/set-node" ‖ left ‖ right)`.
fn node(left: &Hash32, right: &Hash32) -> Hash32 {
    tagged_hash(Domain::SetNode, &[left, right])
}

/// Roots of empty subtrees: `Z_0 = H("TOG/v1/set-empty")`, `Z_{d+1} = node(Z_d, Z_d)`.
pub fn empty_roots() -> [Hash32; SET_DEPTH + 1] {
    let mut z = [tagged_hash(Domain::SetEmpty, &[]); SET_DEPTH + 1];
    for d in 0..SET_DEPTH {
        z[d + 1] = node(&z[d], &z[d]);
    }
    z
}

/// The Hub's view of a set: its root and the incremental tree frontier.
///
/// `frontier[d]` is the left sibling at level `d` where bit `d` of `count` is set, and `Z_d` where
/// it is clear, so the frontier has `⌈log2(count + 1)⌉` entries and one canonical value.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SetFrontier {
    /// The set.
    pub set: PayloadSetRoot,
    /// Frontier.
    pub frontier: Vec<Hash32>,
}

/// Why a set operation failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetError {
    /// The tree is full or `total_size` overflows.
    #[error("payload set is full")]
    Full,
    /// The frontier does not fit `count`.
    #[error("frontier does not match the set")]
    Frontier,
}

impl Default for SetFrontier {
    fn default() -> Self {
        Self::new()
    }
}

impl SetFrontier {
    /// The empty set.
    pub fn new() -> Self {
        Self { set: PayloadSetRoot { root: empty_roots()[SET_DEPTH], count: 0, total_size: 0 }, frontier: Vec::new() }
    }

    /// Appends `payloads` and returns their leaves. Leaves `self` unchanged on error.
    pub fn append(&mut self, payloads: &[PayloadCommitment]) -> Result<Vec<PayloadSetLeaf>, SetError> {
        let z = empty_roots();
        if self.frontier.len() != bit_len(self.set.count) {
            return Err(SetError::Frontier);
        }
        let leaves = PayloadSetLeaf::chain(self.set.total_size, payloads).ok_or(SetError::Full)?;
        let mut next = self.clone();
        for leaf in &leaves {
            next.set.total_size = leaf.offset + leaf.size;
            let count = next.set.count;
            if count == u32::MAX {
                return Err(SetError::Full);
            }
            let mut acc = leaf.hash();
            let mut d = 0;
            while count >> d & 1 == 1 {
                acc = node(&next.frontier[d], &acc);
                next.frontier[d] = z[d];
                d += 1;
            }
            match next.frontier.get_mut(d) {
                Some(slot) => *slot = acc,
                None => next.frontier.push(acc),
            }
            next.set.count = count + 1;
        }
        next.set.root = root_of(next.set.count, &next.frontier, &z);
        *self = next;
        Ok(leaves)
    }
}

fn bit_len(count: u32) -> usize {
    (u32::BITS - count.leading_zeros()) as usize
}

fn root_of(count: u32, frontier: &[Hash32], z: &[Hash32; SET_DEPTH + 1]) -> Hash32 {
    // Start from the empty slot at index `count` and climb.
    let mut acc = z[0];
    for (d, zd) in z.iter().enumerate().take(SET_DEPTH) {
        acc = if count >> d & 1 == 1 { node(&frontier[d], &acc) } else { node(&acc, zd) };
    }
    acc
}

/// True if `path` opens `leaf` at `path.index < set.count` under `set.root`.
pub fn verify_path(set: &PayloadSetRoot, leaf: &PayloadSetLeaf, path: &MerklePath) -> bool {
    if path.siblings.len() != SET_DEPTH || path.index >= set.count {
        return false;
    }
    let mut acc = leaf.hash();
    for (d, sib) in path.siblings.iter().enumerate() {
        acc = if path.index >> d & 1 == 1 { node(sib, &acc) } else { node(&acc, sib) };
    }
    acc == set.root
}

/// Path of leaf `index` in the set of all `leaves`, as a holder or the executor builds it.
/// Hashes the whole tree: for several paths of one set, build a [`SetTree`] once.
pub fn path(leaves: &[PayloadSetLeaf], index: u32) -> Option<MerklePath> {
    if index as usize >= leaves.len() {
        return None;
    }
    SetTree::new(leaves).path(index)
}

/// Every node of a set's tree, so that each path costs no hashing after the ~2n of building it.
#[derive(Clone, Debug)]
pub struct SetTree {
    /// Level `d` from the leaves up, with no padding: a missing right child is `Z_d`.
    levels: Vec<Vec<Hash32>>,
    z: [Hash32; SET_DEPTH + 1],
}

impl SetTree {
    /// The tree of the set of all `leaves`.
    pub fn new(leaves: &[PayloadSetLeaf]) -> Self {
        let z = empty_roots();
        let mut levels = Vec::with_capacity(SET_DEPTH);
        let mut level: Vec<Hash32> = leaves.iter().map(PayloadSetLeaf::hash).collect();
        for zd in z.iter().take(SET_DEPTH) {
            // Above the top every level is one node, or none: nothing further to keep.
            if level.len() <= 1 {
                break;
            }
            let next = level.chunks(2).map(|c| node(&c[0], c.get(1).unwrap_or(zd))).collect();
            levels.push(core::mem::replace(&mut level, next));
        }
        levels.push(level);
        Self { levels, z }
    }

    /// Leaves in the tree.
    pub fn count(&self) -> usize {
        self.levels[0].len()
    }

    /// Path of leaf `index`, as [`path`] builds it.
    pub fn path(&self, index: u32) -> Option<MerklePath> {
        if index as usize >= self.count() {
            return None;
        }
        let i = index as usize;
        let siblings = (0..SET_DEPTH)
            .map(|d| self.levels.get(d).and_then(|l| l.get((i >> d) ^ 1)).copied().unwrap_or(self.z[d]))
            .collect();
        Some(MerklePath { index, siblings })
    }
}

#[cfg(test)]
mod tests;
