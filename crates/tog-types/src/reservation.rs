//! Reserved capacity (TOG-SPEC-0015): a payer books a slice of one compute worker's GPUs, cores,
//! RAM and scratch for a span of blocks; its beneficiary's jobs then run on that slice ahead of
//! the open market.
//!
//! `RequestReservation` (TxBody 80) and `CancelReservation` (82) are user-lane transactions that
//! carry `chain_id`, the payer and its next nonce, in that order, before their own fields.
//! `AcceptReservation` (81) is a compute-lane transaction signed by the offered worker's key.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{Address, Amount, ChainId, Hash32};

use crate::job::{CpuIsaLevel, GpuRequirement, IsolationTier};
use crate::state::Booking;
use crate::worker::WorkerId;

/// `ReservationId`: assigned in request order from `compute_market.next_reservation_id`, never
/// reused (§1).
pub type ReservationId = u64;

/// `MaxReservationMisses`: misses that end an `Active` reservation as a worker fault (§5.2).
pub const MAX_RESERVATION_MISSES: u8 = 3;

/// Blocks an offer stays open after its draw, `N_claim` (0001 §4.2, §3).
pub const OFFER_WINDOW: u64 = 10;

/// Basis points in one whole.
pub const BP: u32 = 10_000;

/// Whose jobs a reservation serves (§1). Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Beneficiary {
    /// 0: jobs with `origin = ChainId(0)` and this sender.
    Account(Address),
    /// 1: jobs with `origin` = this chain (any sender), never `ChainId(0)`.
    Chain(ChainId),
}

impl Beneficiary {
    /// Whether a job of `origin` and `sender` is this beneficiary's (§4.1).
    pub fn matches(&self, origin: ChainId, sender: &Address) -> bool {
        match self {
            Beneficiary::Account(a) => origin == ChainId::HUB && sender == a,
            Beneficiary::Chain(c) => origin == *c,
        }
    }
}

/// What is reserved: whole GPUs, cores, RAM and scratch of one worker (§1). Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReservationSlice {
    /// 0001 §3.2, `allow_mig = false`; `None` for a CPU-only slice.
    pub gpu: Option<GpuRequirement>,
    /// Cores.
    pub cpu_cores: u16,
    /// Minimum ISA level.
    pub cpu_isa_level: CpuIsaLevel,
    /// RAM.
    pub ram_bytes: u64,
    /// Scratch disk.
    pub scratch_bytes: u64,
    /// Weakest sandbox the slice runs in.
    pub min_isolation: IsolationTier,
}

/// Why a slice is malformed (§2 rule 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SliceError {
    /// `gpu.count` outside `1..=8`.
    #[error("gpu count {0} is outside 1..=8")]
    GpuCount(u8),
    /// `gpu.allow_mig` is set.
    #[error("a slice takes whole GPUs")]
    Mig,
    /// `gpu.interconnect` is set iff `count > 1` is broken.
    #[error("interconnect must be set iff more than one GPU")]
    Interconnect,
    /// `compute_capability.min > max`.
    #[error("compute capability range is empty")]
    ComputeCapability,
    /// A resource below the floor a job has (0001 §3.4 rule 2).
    #[error("{0} is below its floor")]
    Floor(&'static str),
}

impl ReservationSlice {
    /// §2 rule 2: whole GPUs with an interconnect iff more than one and a non-empty capability
    /// range, and the resource floors of a job (0001 §3.4 rule 2).
    pub fn check(&self) -> Result<(), SliceError> {
        if let Some(r) = &self.gpu {
            if !(1..=8).contains(&r.count) {
                return Err(SliceError::GpuCount(r.count));
            }
            if r.allow_mig {
                return Err(SliceError::Mig);
            }
            if r.interconnect.is_some() != (r.count > 1) {
                return Err(SliceError::Interconnect);
            }
            if r.compute_capability.min > r.compute_capability.max {
                return Err(SliceError::ComputeCapability);
            }
        }
        let floor = |ok: bool, field| if ok { Ok(()) } else { Err(SliceError::Floor(field)) };
        floor(self.cpu_cores >= 1, "cpu_cores")?;
        floor(self.ram_bytes >= crate::admission::MIN_RAM_BYTES, "ram_bytes")?;
        floor(self.scratch_bytes == 0 || self.scratch_bytes >= crate::admission::MIN_SCRATCH_BYTES, "scratch_bytes")
    }

    /// The slice as a job's hardware request, for the fit rules of 0001 §4.2.1 (§3).
    pub fn hw(&self) -> crate::job::HardwareRequirements {
        crate::job::HardwareRequirements {
            gpu: self.gpu.clone(),
            cpu_cores: self.cpu_cores,
            cpu_isa_level: self.cpu_isa_level,
            ram_bytes: self.ram_bytes,
            scratch_bytes: self.scratch_bytes,
        }
    }
}

/// `compute_market.reservations[id]` (§1). Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Reservation {
    /// The account that prepaid it.
    pub payer: Address,
    /// Whose jobs it serves.
    pub beneficiary: Beneficiary,
    /// The worker set its worker comes from.
    pub worker_set: ChainId,
    /// What is reserved.
    pub slice: ReservationSlice,
    /// Blocks from acceptance to end.
    pub duration_blocks: u64,
    /// The price of the whole slice per block.
    pub price_per_block: Amount,
    /// The block of its `RequestReservation`.
    pub requested_at: u64,
    /// The last block in which an offer may still be accepted.
    pub match_deadline: u64,
    /// Where it is.
    pub status: ReservationStatus,
}

impl Reservation {
    /// `price_per_block × duration_blocks`, prepaid at the request (§2).
    pub fn escrow(&self) -> Option<Amount> {
        self.price_per_block.checked_mul(Amount::from(self.duration_blocks))
    }
}

/// Where a reservation is (§1). Borsh index = position.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ReservationStatus {
    /// 0: waiting for a draw; workers that let an offer lapse, ascending.
    Requested {
        /// Never drawn again.
        excluded: Vec<WorkerId>,
    },
    /// 1: offered to `worker` at block `at` (§3).
    Offered {
        /// The drawn worker.
        worker: WorkerId,
        /// The drawing block.
        at: u64,
        /// As in `Requested`.
        excluded: Vec<WorkerId>,
    },
    /// 2: running on `worker` from `start` to `end`.
    Active {
        /// The accepting worker.
        worker: WorkerId,
        /// The accepting block.
        start: u64,
        /// `start + duration_blocks`; the slice is free again from block `end`.
        end: u64,
        /// The booked GPU indices, ascending; empty for a CPU-only slice.
        gpus: Vec<u8>,
        /// The worker's reservation bond, locked from its free bond.
        bond: Amount,
        /// What beneficiary jobs now book inside the slice, summed (0002 §7.2).
        used: Booking,
        /// Reservation misses so far (§5.1).
        misses: u8,
    },
    /// 3: ended at `at`; kept until pruned (§6).
    Ended {
        /// How.
        outcome: ReservationOutcome,
        /// The ending block.
        at: u64,
    },
}

/// How a reservation ended (§1). Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ReservationOutcome {
    /// 0: reached `end`.
    Completed,
    /// 1: the payer cancelled (§5.3).
    Cancelled,
    /// 2: no worker accepted by `match_deadline`; the escrow went back.
    Unmatched,
    /// 3: §5.2.
    WorkerFault,
}

/// `compute_market.reservation_params` (§7); absent means the market is off. Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReservationParams {
    /// Shortest reservation.
    pub min_duration_blocks: u64,
    /// Longest reservation.
    pub max_duration_blocks: u64,
    /// The least `price_per_block`, so a request can't be free (C-37).
    pub min_price_per_block: Amount,
    /// The worker's reservation bond, basis points of the total price.
    pub bond_bp: u32,
    /// Per miss, basis points of the bond at acceptance.
    pub miss_penalty_bp: u32,
    /// At a worker fault, basis points of the bond at acceptance.
    pub fault_penalty_bp: u32,
    /// Notice fee on a payer's cancel, in blocks of price.
    pub cancel_notice_blocks: u64,
    /// Treasury share of reservation payments.
    pub treasury_bp: u32,
    /// Most reservations of one payer not `Ended`; technical default 16.
    pub max_open_per_payer: u32,
    /// Blocks an ended reservation is kept; technical default `era_length`.
    pub retention_blocks: u64,
}

impl ReservationParams {
    /// Genesis validity (§7): `1 ≤ min_duration_blocks ≤ max_duration_blocks` and every `_bp`
    /// at most 10 000.
    pub fn is_valid(&self) -> bool {
        let bps = [self.bond_bp, self.miss_penalty_bp, self.fault_penalty_bp, self.treasury_bp];
        self.min_duration_blocks >= 1
            && self.min_duration_blocks <= self.max_duration_blocks
            && bps.iter().all(|b| *b <= BP)
    }
}

/// The decided testnet values (§7, 2026-10-24): 1 hour to 28 days at 2 s blocks, at least 0.001
/// TOG per block, a bond of 10% of the total price, 5% of it per miss and all of it at a fault, one
/// hour of price as cancel notice, 3% to the treasury, 16 open per payer, and an ended reservation
/// kept for one era of `era_length` blocks.
pub const fn testnet_reservation_params(era_length: u64) -> ReservationParams {
    ReservationParams {
        min_duration_blocks: 1_800,
        max_duration_blocks: 1_209_600,
        min_price_per_block: 1_000_000_000_000_000,
        bond_bp: 1_000,
        miss_penalty_bp: 500,
        fault_penalty_bp: 10_000,
        cancel_notice_blocks: 1_800,
        treasury_bp: 300,
        max_open_per_payer: 16,
        retention_blocks: era_length,
    }
}

/// `⌈amount × bp / 10 000⌉` (§3, §5.1, §5.2), exact for every `amount` and saturating only
/// where the result itself passes `u128` (`bp > 10 000`).
pub fn bp_ceil(amount: Amount, bp: u32) -> Amount {
    let (q, r) = (amount / Amount::from(BP), amount % Amount::from(BP));
    let bp = Amount::from(bp);
    q.saturating_mul(bp).saturating_add((r * bp).div_ceil(Amount::from(BP)))
}

/// `⌊amount × bp / 10 000⌋` (§5.4), exact for every `amount`.
pub fn bp_floor(amount: Amount, bp: u32) -> Amount {
    let (q, r) = (amount / Amount::from(BP), amount % Amount::from(BP));
    q * Amount::from(bp) + r * Amount::from(bp) / Amount::from(BP)
}

/// TxBody 80: ask for a slice of one worker in `worker_set` (§2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RequestReservationTx {
    /// Replay domain, TOG-SPEC-0000 §13.2.
    pub chain_id: u64,
    /// The signer.
    pub payer: Address,
    /// The payer's next nonce.
    pub nonce: u64,
    /// Whose jobs it serves.
    pub beneficiary: Beneficiary,
    /// The set its worker comes from.
    pub worker_set: ChainId,
    /// What is reserved.
    pub slice: ReservationSlice,
    /// Blocks from acceptance to end.
    pub duration_blocks: u64,
    /// The price of the whole slice per block.
    pub price_per_block: Amount,
    /// The last block in which an offer may be accepted.
    pub match_deadline: u64,
}

/// TxBody 81: the offered worker takes the offer (§3). No nonce: `offered_at` makes an old accept
/// invalid.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AcceptReservationTx {
    /// The reservation.
    pub id: ReservationId,
    /// `Offered.at`; any other value is invalid.
    pub offered_at: u64,
}

/// TxBody 82: the payer ends its reservation (§5.3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CancelReservationTx {
    /// Replay domain, TOG-SPEC-0000 §13.2.
    pub chain_id: u64,
    /// The signer.
    pub payer: Address,
    /// The payer's next nonce.
    pub nonce: u64,
    /// The reservation.
    pub id: ReservationId,
}

/// `Event::Reservation.kind` (§6). Borsh index = position.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ReservationEventKind {
    /// 0
    Requested,
    /// 1
    Offered {
        /// The drawn worker.
        worker: WorkerId,
    },
    /// 2
    Accepted {
        /// The accepting worker.
        worker: WorkerId,
        /// The accepting block.
        start: u64,
        /// `start + duration_blocks`.
        end: u64,
    },
    /// 3
    Miss {
        /// The job whose claim window lapsed.
        job_id: Hash32,
    },
    /// 4
    Ended {
        /// How.
        outcome: ReservationOutcome,
        /// Paid out of the escrow to the worker's owner and the treasury.
        paid: Amount,
        /// Returned to the payer.
        refunded: Amount,
    },
}

/// The `subject` of a reservation's `Balance` events: `u64_le(id)` padded with zeros (§6).
pub fn subject(id: ReservationId) -> Hash32 {
    let mut s = [0; 32];
    s[..8].copy_from_slice(&id.to_le_bytes());
    s
}

#[cfg(test)]
mod tests;
