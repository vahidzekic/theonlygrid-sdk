//! Declared storage faults (TOG-SPEC-0012 §3.2): a holder that knows it lost a slot's data says so
//! before a challenge finds out, and pays `PHI_FAULT` × the slot's fee per era instead of a slash.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};

use crate::job::DealId;
use crate::por::{ChallengeId, StorageWorkerId};

/// Most slots one `DeclareFaults` or `DeclareRecovery` lists.
pub const MAX_DECLARED_SLOTS: usize = 256;
/// `F_MAX` of `Hot` and `LongTerm` slots: eras a declared fault may last before the slot fails.
/// `ChallengeWindow` slots have 0: they exit at once.
pub const F_MAX: u8 = 3;
/// `PHI_FAULT`: per declared era, the multiple of the slot's fee for one era charged from the
/// holder's free bond into the deal's `repair_reserve`.
pub const PHI_FAULT: u128 = 2;

/// `TxBody` 60, compute-market lane, signed by the storage key (TOG-SPEC-0012 §3.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeclareFaultsTx {
    /// The holder.
    pub worker: StorageWorkerId,
    /// 1 to [`MAX_DECLARED_SLOTS`] distinct `(deal, slot)` of `worker`.
    pub slots: Vec<(DealId, u16)>,
    /// Replay domain and the storage key's account nonce.
    pub replay: crate::storage::ReplayGuard,
}

/// `TxBody` 61, compute-market lane, signed by the storage key (TOG-SPEC-0012 §3.2): asks to prove
/// declared slots again.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeclareRecoveryTx {
    /// The holder.
    pub worker: StorageWorkerId,
    /// 1 to [`MAX_DECLARED_SLOTS`] distinct declared `(deal, slot)` of `worker`.
    pub slots: Vec<(DealId, u16)>,
    /// Replay domain and the storage key's account nonce: an old signed body can't be included
    /// again after a later declaration of the same slot.
    pub replay: crate::storage::ReplayGuard,
}

/// `storage.faults[(StorageWorkerId, DealId, u16)]` (TOG-SPEC-0002 §7.2), from `DeclareFaults`
/// until recovered, exited or failed. Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeclaredFault {
    /// Height of the `DeclareFaults`.
    pub since: u64,
    /// Era boundaries passed since.
    pub eras: u8,
    /// The `Slot` challenge of a `DeclareRecovery` in progress.
    pub recovery: Option<ChallengeId>,
}

/// Whether `slots` is a well-formed list: 1 to [`MAX_DECLARED_SLOTS`] entries, none twice.
pub fn well_formed(slots: &[(DealId, u16)]) -> bool {
    let mut sorted = slots.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    !slots.is_empty() && slots.len() <= MAX_DECLARED_SLOTS && sorted.len() == slots.len()
}
