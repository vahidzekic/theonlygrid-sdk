//! Cross-Grid Messaging Protocol: messages and the outbox hashing (TOG-SPEC-0000 §7.2).
//!
//! ```text
//! msg_hash(m)  = H("TOG/v1/cgmp-msg" ‖ borsh(m))
//! head_0       = [0; 32]
//! head'        = H("TOG/v1/cgmp-queue" ‖ head ‖ msg_hash(m))
//! leaf(dest)   = H("TOG/v1/cgmp-leaf" ‖ borsh((dest, head, last_nonce)))
//! node(a, b)   = H("TOG/v1/cgmp-node" ‖ a ‖ b)
//! outbox_root  = [0; 32] with no channels, else the binary tree over the leaves ascending by
//!                dest, pairing left to right, an unpaired last node moving up unchanged
//! ```

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Amount, ChainId, Domain, Hash32, HubHeight};

use crate::job::{CallbackRef, EscrowRef, JobSpec, ModuleId};
use crate::payload::PayloadCommitment;
use crate::state::JobOutcome;

/// The only `CgmpMessage::version`.
pub const CGMP_VERSION: u8 = 1;
/// Most bytes of `CgmpPayload::Call::call`.
pub const MAX_CALL_LEN: usize = 64 * 1024;
/// Most outputs of a `ComputeResult`: one per `OutputSpec` path.
pub const MAX_OUTPUTS: usize = 256;
/// Queue head of a channel with no messages.
pub const HEAD_0: Hash32 = [0; 32];
/// `outbox_root` with no channels.
pub const EMPTY_OUTBOX: Hash32 = [0; 32];
/// `CgmpBaseFee`: atto-TOG every message to the Hub pays at least (TOG-SPEC-0002 §4.7).
pub const CGMP_BASE_FEE: Amount = 1_000_000_000_000_000;
/// `CgmpByteFee`: atto-TOG per byte of `borsh(m)` (TOG-SPEC-0002 §4.7).
pub const CGMP_BYTE_FEE: Amount = 1_000_000_000_000;
/// `MaxInChannels`: AppChain sources a chain may receive from (TOG-SPEC-0007 §4.6).
pub const MAX_IN_CHANNELS: usize = 64;
/// `MaxBacklog`: the most unprocessed messages a channel from an AppChain may hold once its
/// candidate is final (TOG-SPEC-0002 §4.4 "Channel checks", 0007 §3.4 "Backlog cap", E-03). The
/// Hub drops a candidate past it; the runtime's sends and Timeout Acks stay within it.
pub const MAX_BACKLOG: u64 = 1_024;
/// `MaxOutChannels`: destinations a chain may send to (TOG-SPEC-0007 §4.6).
pub const MAX_OUT_CHANNELS: usize = 64;
/// The Hub's `"appchains"` module, ASCII zero-padded (TOG-SPEC-0002 §4.7).
pub const APPCHAINS_MODULE: ModuleId = ModuleId(*b"appchains\0\0\0\0\0\0\0");

/// The least fee the Hub takes for `m`: `CgmpBaseFee + CgmpByteFee · len(borsh(m))`
/// (TOG-SPEC-0002 §4.7); the SDK puts at least this on every message to the Hub.
pub fn min_hub_fee(m: &CgmpMessage) -> Amount {
    let len = borsh::object_length(m).expect("in-memory borsh cannot fail") as Amount;
    CGMP_BASE_FEE.saturating_add(CGMP_BYTE_FEE.saturating_mul(len))
}

/// Calls of the Hub's `"appchains"` module; `call = borsh(self)` (TOG-SPEC-0002 §4.7).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AppchainsCall {
    /// 0: replaces `appchains.worker_set_rules` of the origin chain.
    SetWorkerSetRules(crate::eligibility::WorkerSetRules),
}

/// One message on the `(source, dest)` channel.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CgmpMessage {
    /// [`CGMP_VERSION`].
    pub version: u8,
    /// Sending chain; [`ChainId::HUB`] for the Hub.
    pub source: ChainId,
    /// Receiving chain.
    pub dest: ChainId,
    /// Strictly increasing per `(source, dest)`, from 0.
    pub channel_nonce: u64,
    /// Hub height after which the message is refunded, not delivered.
    pub timeout_height: HubHeight,
    /// Paid on the source, credited to execution on the destination.
    pub fee: Amount,
    /// Who sent it.
    pub origin: CgmpOrigin,
    /// What it carries.
    pub payload: CgmpPayload,
}

/// Sender of a message.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CgmpOrigin {
    /// 0: an account on a chain.
    Account {
        /// Its chain.
        chain: ChainId,
        /// The account.
        account: Address,
    },
    /// 1: a chain itself.
    Chain(ChainId),
    /// 2: a runtime module of a chain.
    Module {
        /// Its chain.
        chain: ChainId,
        /// The module.
        module: ModuleId,
    },
}

/// Message body.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CgmpPayload {
    /// 0: $TOG moves between the Hub and an L1; updates `supply_ledger` on the Hub.
    TransferTog {
        /// Recipient on the destination.
        to: Address,
        /// atto-TOG.
        amount: Amount,
    },
    /// 1: L1 → Hub compute market.
    ComputeRequest {
        /// The job.
        spec: Box<JobSpec>,
        /// Escrow that funds it.
        escrow: EscrowRef,
        /// Where the result goes.
        callback: Option<CallbackRef>,
    },
    /// 2: Hub compute market → L1 (TOG-SPEC-0007 §7.1).
    ComputeResult(ComputeResult),
    /// 3: generic L1 → L1 application call.
    Call {
        /// Destination module.
        module: ModuleId,
        /// SDK-defined, versioned call, at most [`MAX_CALL_LEN`] bytes.
        call: Vec<u8>,
        /// Most weight the call may use.
        weight_limit: Weight,
    },
    /// 4: acknowledgement of an earlier message on the reverse channel.
    Ack {
        /// `channel_nonce` of the acknowledged message.
        of_nonce: u64,
        /// How it went.
        result: Result<(), CgmpError>,
    },
    /// 5: Hub → L1: a worker on the L1's `WorkerSetRules.allowlist` was slashed (TOG-SPEC-0000
    /// §5.5, 0002 §4.7 "Worker slash notices"). The same bytes as the spec's
    /// `WorkerSlashed { worker, offence, job }`.
    WorkerSlashed(WorkerSlashed),
}

/// Why the Hub slashed a compute worker (TOG-SPEC-0002 §4.7 "Worker slash notices"). Borsh: one
/// u8 tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum WorkerOffence {
    /// 0: a job it executed became `Terminal` with `JobOutcome::ExecutorFault` (0003 §7).
    ExecutorFault,
    /// 1: its claim's lease expired, or it released a claim after escrowing a final (0001 §5.3,
    /// 0003 §5.3).
    LeaseExpired,
    /// 2: its revealed verifier vote is against the segment's final outcome (0003 §7).
    VerifierAgainst,
    /// 3: its revealed juror vote is outside a decided round's majority (0003 §7).
    JurorAgainst,
    /// 4: it posted a dissent, challenge or appeal bond and the executor won (0003 §7).
    LostRound,
    /// 5: a checkpoint key it escrowed mismatched its `key_commitment` (0009 §5.2 rule 5).
    EscrowFault,
}

/// The fields of a `WorkerSlashed` notice.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WorkerSlashed {
    /// The slashed worker.
    pub worker: crate::worker::WorkerId,
    /// Why.
    pub offence: WorkerOffence,
    /// The job whose bond, vote or claim the offence concerns.
    pub job: Hash32,
}

/// The outcome of a job, delivered to its callback.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ComputeResult {
    /// The job.
    pub job_id: Hash32,
    /// How it ended (TOG-SPEC-0002 §7.2).
    pub outcome: JobOutcome,
    /// Root of its receipt.
    pub receipt_root: Hash32,
    /// One per `OutputSpec` path, in path order; at most [`MAX_OUTPUTS`].
    pub outputs: Vec<(String, PayloadCommitment)>,
    /// Work units charged.
    pub work_units: u64,
    /// atto-TOG charged.
    pub charged: Amount,
}

/// Execution weight, shared by the Hub and every AppChain runtime (TOG-SPEC-0007 §6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct Weight {
    /// Picoseconds of reference-validator execution.
    pub ref_time: u64,
    /// Bytes of (uncompressed) PoV witness.
    pub proof_size: u64,
}

impl Weight {
    /// No weight.
    pub const ZERO: Weight = Weight { ref_time: 0, proof_size: 0 };
    /// The largest representable weight.
    pub const MAX: Weight = Weight { ref_time: u64::MAX, proof_size: u64::MAX };

    /// Weight from both dimensions.
    pub const fn from_parts(ref_time: u64, proof_size: u64) -> Self {
        Weight { ref_time, proof_size }
    }

    /// Component-wise saturating sum.
    pub const fn saturating_add(self, o: Weight) -> Weight {
        Weight {
            ref_time: self.ref_time.saturating_add(o.ref_time),
            proof_size: self.proof_size.saturating_add(o.proof_size),
        }
    }

    /// Component-wise saturating difference.
    pub const fn saturating_sub(self, o: Weight) -> Weight {
        Weight {
            ref_time: self.ref_time.saturating_sub(o.ref_time),
            proof_size: self.proof_size.saturating_sub(o.proof_size),
        }
    }

    /// Component-wise checked sum.
    pub const fn checked_add(self, o: Weight) -> Option<Weight> {
        match (self.ref_time.checked_add(o.ref_time), self.proof_size.checked_add(o.proof_size)) {
            (Some(ref_time), Some(proof_size)) => Some(Weight { ref_time, proof_size }),
            _ => None,
        }
    }

    /// `self` scaled by `n`, saturating.
    pub const fn saturating_mul(self, n: u64) -> Weight {
        Weight { ref_time: self.ref_time.saturating_mul(n), proof_size: self.proof_size.saturating_mul(n) }
    }

    /// Component-wise minimum; `Ord::min` compares lexicographically instead.
    pub const fn min_each(self, o: Weight) -> Weight {
        Weight {
            ref_time: if self.ref_time < o.ref_time { self.ref_time } else { o.ref_time },
            proof_size: if self.proof_size < o.proof_size { self.proof_size } else { o.proof_size },
        }
    }

    /// Whether both components are `<=` those of `o`. Weights are only partially ordered by
    /// this; the derived `Ord` is lexicographic, for sorting only.
    pub const fn all_lte(self, o: Weight) -> bool {
        self.ref_time <= o.ref_time && self.proof_size <= o.proof_size
    }
}

/// Why a message failed, in an [`CgmpPayload::Ack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CgmpError {
    /// 0: not processed by `timeout_height`.
    Timeout,
    /// 1: needed more than its `weight_limit`.
    WeightExceeded,
    /// 2: `fee` did not cover the weight.
    InsufficientFee,
    /// 3: no such module on the destination.
    UnknownModule,
    /// 4: the module rejected the call.
    DispatchFailed,
    /// 5: a `TransferTog` would take a chain's `supply_ledger` entry below zero.
    SupplyLedgerUnderflow,
}

impl CgmpMessage {
    /// `msg_hash(m)`.
    pub fn hash(&self) -> Hash32 {
        tagged_hash(Domain::CgmpMsg, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }

    /// Whether the version is [`CGMP_VERSION`] and every bounded list fits its bound.
    pub fn is_well_formed(&self) -> bool {
        self.version == CGMP_VERSION
            && match &self.payload {
                CgmpPayload::Call { call, .. } => call.len() <= MAX_CALL_LEN,
                CgmpPayload::ComputeResult(r) => r.outputs.len() <= MAX_OUTPUTS,
                _ => true,
            }
    }
}

/// `head'`: the channel's queue head after appending the message with hash `msg_hash`.
pub fn next_head(head: &Hash32, msg_hash: &Hash32) -> Hash32 {
    tagged_hash(Domain::CgmpQueue, &[head, msg_hash])
}

/// One outgoing channel as `outbox_root` commits to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OutboxChannel {
    /// Destination chain.
    pub dest: ChainId,
    /// Current queue head.
    pub head: Hash32,
    /// `channel_nonce` of the last message appended.
    pub last_nonce: u64,
}

impl OutboxChannel {
    /// `leaf(dest)`; `borsh(self)` is `borsh((dest, head, last_nonce))`.
    pub fn leaf(&self) -> Hash32 {
        tagged_hash(Domain::CgmpLeaf, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }
}

/// `node(a, b)`.
pub fn outbox_node(a: &Hash32, b: &Hash32) -> Hash32 {
    tagged_hash(Domain::CgmpNode, &[a, b])
}

/// `outbox_root` over every outgoing channel; sorts by `dest` itself.
pub fn outbox_root(channels: &[OutboxChannel]) -> Hash32 {
    let mut sorted: Vec<&OutboxChannel> = channels.iter().collect();
    sorted.sort_by_key(|c| c.dest);
    let mut level: Vec<Hash32> = sorted.iter().map(|c| c.leaf()).collect();
    if level.is_empty() {
        return EMPTY_OUTBOX;
    }
    while level.len() > 1 {
        level = level.chunks(2).map(|c| if let [a, b] = c { outbox_node(a, b) } else { c[0] }).collect();
    }
    level[0]
}

/// `MaxLag`: most pending messages a destination may leave on one inbound channel (TOG-SPEC-0002
/// §7.2 `cgmp.channels`).
pub const MAX_LAG: u32 = 256;

/// `cgmp.channels[(source, dest)]` (TOG-SPEC-0002 §7.2, TOG-SPEC-0000 §7), Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CgmpChannel {
    /// The source's queue head as of its `final_head`.
    pub head: Hash32,
    /// `channel_nonce` of the source's last message as of its `final_head`; `None` before the
    /// first.
    pub last_nonce: Option<u64>,
    /// Next `channel_nonce` the destination must process, as of its `final_head`.
    pub next_nonce: u64,
    /// [`MAX_LAG`].
    pub max_lag: u32,
}

impl Default for CgmpChannel {
    /// As created when the channel's first message is recorded.
    fn default() -> Self {
        Self { head: HEAD_0, last_nonce: None, next_nonce: 0, max_lag: MAX_LAG }
    }
}

impl CgmpChannel {
    /// Messages the destination has not processed: `last_nonce + 1 − next_nonce`, 0 while
    /// `last_nonce` is `None`.
    pub fn pending(&self) -> u64 {
        self.last_nonce.map_or(0, |l| l.saturating_add(1).saturating_sub(self.next_nonce))
    }

    /// The `max_lag` check of a destination block that leaves `next_nonce` as its new next nonce
    /// on this channel (TOG-SPEC-0007 §3.4): `true` if it is within `max_lag`.
    pub fn within_lag(&self, next_nonce: u64) -> bool {
        Self { next_nonce, ..*self }.pending() <= u64::from(self.max_lag)
    }

    /// Checks the inbox proof of message `msg_hash` with `channel_nonce = nonce` against this
    /// channel as read at the relay parent (TOG-SPEC-0007 §3.4 "Inbox proofs"), for a destination
    /// whose `cgmp` module expects `next_nonce` and holds `queue_head`. `proof` is the `msg_hash`
    /// of every later message up to `last_nonce`. Returns the module's new `queue_head`.
    pub fn check_inbox(
        &self,
        next_nonce: u64,
        queue_head: &Hash32,
        nonce: u64,
        msg_hash: &Hash32,
        proof: &[Hash32],
    ) -> Option<Hash32> {
        let last = self.last_nonce?;
        if nonce != next_nonce || nonce.checked_add(proof.len() as u64) != Some(last) {
            return None;
        }
        let head = next_head(queue_head, msg_hash);
        (proof.iter().fold(head, |h, m| next_head(&h, m)) == self.head).then_some(head)
    }
}

/// Most messages of one `DeliverCgmp`.
pub const MAX_DELIVER: usize = 64;
/// `DepositToChain` needs fewer than this many unprocessed messages on channel `(0, chain)`:
/// `MaxLag / 2`, leaving room for `ComputeResult`s and `Ack`s.
pub const DEPOSIT_MAX_PENDING: u64 = MAX_LAG as u64 / 2;

/// Checks a `DeliverCgmp` batch against `cgmp.channels[(source, 0)]` and `cgmp.hub_queue[source]`
/// (TOG-SPEC-0002 §4.7): consecutive nonces from `next_nonce`, then the fold over the messages'
/// `msg_hash` and `proof` gives the channel's head with `first + len + len(proof) − 1 =
/// last_nonce`. Returns the queue head after each message, in order.
pub fn check_delivery(
    channel: &CgmpChannel,
    hub_queue: &Hash32,
    source: ChainId,
    messages: &[CgmpMessage],
    proof: &[Hash32],
) -> Option<Vec<Hash32>> {
    if messages.is_empty() || messages.len() > MAX_DELIVER {
        return None;
    }
    let last = channel.last_nonce?;
    let mut heads = Vec::with_capacity(messages.len());
    let mut head = *hub_queue;
    for (i, m) in messages.iter().enumerate() {
        let well_placed = m.version == CGMP_VERSION
            && m.source == source
            && m.dest == ChainId::HUB
            && Some(m.channel_nonce) == channel.next_nonce.checked_add(i as u64);
        if !well_placed {
            return None;
        }
        head = next_head(&head, &m.hash());
        heads.push(head);
    }
    let end = channel.next_nonce.checked_add((messages.len() + proof.len()) as u64)?;
    let folded = proof.iter().fold(head, |h, x| next_head(&h, x));
    (end == last.checked_add(1)? && folded == channel.head).then_some(heads)
}

/// `TxBody` variant 49, user lane: delivers final messages from `source` to the Hub (TOG-SPEC-0002 §4.7).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeliverCgmpTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; pays and earns nothing.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// Sending chain.
    pub source: ChainId,
    /// `1..=MAX_DELIVER` messages with consecutive nonces from the channel's `next_nonce`.
    pub messages: Vec<CgmpMessage>,
    /// `msg_hash` of every later message of the channel up to its `last_nonce`.
    pub proof: Vec<Hash32>,
}

/// `TxBody` variant 50, user lane: moves $TOG from the signer to `to` on `chain`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DepositToChainTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; pays.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// Destination chain.
    pub chain: ChainId,
    /// Account credited there.
    pub to: Address,
    /// More than 0.
    pub amount: Amount,
}

/// `TxBody` variant 70, user lane: `dest`'s manager refuses (or accepts again) channels from
/// `source` (TOG-SPEC-0002 §4.7, 0007 §4.6 "Refused sources", E-04).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RefuseInboundTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer: `dest`'s manager.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// The refusing chain.
    pub dest: ChainId,
    /// The refused source; never 0 or `dest`.
    pub source: ChainId,
    /// `true` refuses, `false` lifts the refusal.
    pub refuse: bool,
}

#[cfg(test)]
mod tests;
