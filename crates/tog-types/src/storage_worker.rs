//! Storage worker registration, holder placement draw and the scheduled challenge draw
//! (TOG-SPEC-0004 §3.1, §4.3, §5.1).

use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{ed25519_address, tagged_hash, Address, Amount, Domain, Hash32, HubHeight};

use crate::eligibility::Region;
use crate::job::{DealId, RetentionClass};
use crate::por::StorageWorkerId;
use crate::worker::NetProfile;

/// Smallest declared capacity.
pub const MIN_CAPACITY_BYTES: u64 = 1 << 30;

/// A declared label: records with the same value count as one operator for diversity and
/// sortition exclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct OperatorGroupId(pub Address);

/// Bit 0 Hot, bit 1 ChallengeWindow, bit 2 LongTerm (`RetentionClass` index); other bits zero;
/// never 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ClassSet(pub u8);

impl ClassSet {
    /// True if `class` is served.
    pub fn contains(&self, class: RetentionClass) -> bool {
        self.0 & (1 << class as u8) != 0
    }

    /// Only the three class bits, and at least one.
    pub fn is_valid(&self) -> bool {
        self.0 != 0 && self.0 & !0b111 == 0
    }
}

/// Prices of one class, in atto-TOG.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ClassAsk {
    /// Per GiB·hour stored.
    pub price_per_gib_hour: Amount,
    /// Per GiB retrieved (TOG-SPEC-0004 §7).
    pub retrieval_price_per_gib: Amount,
}

/// Asks indexed by `RetentionClass` (0 Hot, 1 ChallengeWindow, 2 LongTerm).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StorageAsk {
    /// One per class.
    pub per_class: [ClassAsk; 3],
}

impl StorageAsk {
    /// The ask of `class`.
    pub fn for_class(&self, class: RetentionClass) -> &ClassAsk {
        &self.per_class[class as usize]
    }

    /// A class outside `classes` has both prices 0; a class inside has `price_per_gib_hour > 0`.
    pub fn matches(&self, classes: ClassSet) -> bool {
        [RetentionClass::Hot, RetentionClass::ChallengeWindow, RetentionClass::LongTerm].into_iter().all(|c| {
            let a = self.for_class(c);
            if classes.contains(c) {
                a.price_per_gib_hour > 0
            } else {
                *a == ClassAsk::default()
            }
        })
    }
}

/// Storage worker lifecycle. Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum StorageWorkerStatus {
    /// 0.
    Active,
    /// 1: missed a scheduled challenge (TOG-SPEC-0004 §5.4).
    Suspect {
        /// Height of the miss.
        since: HubHeight,
    },
    /// 2 (TOG-SPEC-0004 §3.1).
    Jailed {
        /// Release height.
        until: HubHeight,
        /// A fraud jail; else a liveness jail.
        fraud: bool,
    },
    /// 3: takes no new slots (TOG-SPEC-0004 §3.2).
    Unbonding {
        /// End of unbonding.
        until: HubHeight,
    },
}

/// Hub state `storage_registry.workers`. Borsh layout is exact: fields in this order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StorageWorkerRecord {
    /// Address of the storage key.
    pub id: StorageWorkerId,
    /// Owner account.
    pub owner: Address,
    /// Declared operator group.
    pub operator_group: Option<OperatorGroupId>,
    /// Declared; latency-probed (TOG-SPEC-0004 §3.3).
    pub region: Region,
    /// Declared; checked against observed endpoints.
    pub asn: u32,
    /// Retention classes served.
    pub classes: ClassSet,
    /// Declared capacity.
    pub capacity_bytes: u64,
    /// Sum over active slots, maintained by the Hub.
    pub committed_bytes: u64,
    /// Probed bandwidth.
    pub net: NetProfile,
    /// Prices.
    pub ask: StorageAsk,
    /// Bond in atto-TOG.
    pub bond: Amount,
    /// Collateral of active slots (TOG-SPEC-0004 §3.2).
    pub locked_collateral: Amount,
    /// Reputation.
    pub reputation: u32,
    /// Lifecycle.
    pub status: StorageWorkerStatus,
    /// Set by the region / ASN probe vote, cleared by the next clean probe.
    pub region_flagged: bool,
}

/// `TxBody` variant 23. Signed by the owner; the storage key proves possession with
/// `storage_sig` over [`RegisterStorageWorkerTx::bind_digest`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegisterStorageWorkerTx {
    /// Replay domain, TOG-SPEC-0000 §13.2.
    pub chain_id: u64,
    /// Owner; the transaction's signer.
    pub owner: Address,
    /// The owner account's next nonce, consumed by this transaction.
    pub owner_nonce: u64,
    /// Ed25519 storage key; the `StorageWorkerId` is its address.
    pub storage_key: [u8; 32],
    /// Storage key's signature over the bind digest.
    pub storage_sig: [u8; 64],
    /// Declared operator group.
    pub operator_group: Option<OperatorGroupId>,
    /// Declared country.
    pub region: Region,
    /// Declared ASN, not 0.
    pub asn: u32,
    /// Classes served.
    pub classes: ClassSet,
    /// At least [`MIN_CAPACITY_BYTES`].
    pub capacity_bytes: u64,
    /// Prices.
    pub ask: StorageAsk,
    /// Moved from the owner's free balance.
    pub bond: Amount,
}

/// `TxBody` variant 37: replaces the declared fields of a record; signed by its owner (TOG-SPEC-0004 §3.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UpdateStorageWorkerTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Owner; the signer.
    pub owner: Address,
    /// The owner's next nonce.
    pub owner_nonce: u64,
    /// The record.
    pub worker: StorageWorkerId,
    /// Declared operator group.
    pub operator_group: Option<OperatorGroupId>,
    /// Declared country.
    pub region: Region,
    /// Declared ASN, not 0.
    pub asn: u32,
    /// Classes served.
    pub classes: ClassSet,
    /// At least `max(1 GiB, committed_bytes)`.
    pub capacity_bytes: u64,
    /// Prices for placements from the next block.
    pub ask: StorageAsk,
}

/// `TxBody` variant 38: moves `amount` from the owner's free balance into the record's bond.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BondStorageWorkerTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Owner; the signer.
    pub owner: Address,
    /// The owner's next nonce.
    pub owner_nonce: u64,
    /// The record.
    pub worker: StorageWorkerId,
    /// More than 0.
    pub amount: Amount,
}

/// `TxBody` variant 39: starts unbonding the whole record (TOG-SPEC-0004 §3.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UnbondStorageWorkerTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Owner; the signer.
    pub owner: Address,
    /// The owner's next nonce.
    pub owner_nonce: u64,
    /// The record.
    pub worker: StorageWorkerId,
}

/// Stateless `RegisterStorageWorker` rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageRegistrationError {
    /// `region` is not two uppercase ASCII letters.
    #[error("region must be an uppercase ISO 3166-1 alpha-2 code")]
    Region,
    /// `asn` is 0.
    #[error("asn must not be 0")]
    Asn,
    /// `classes` has no class or stray bits.
    #[error("classes must name at least one retention class and nothing else")]
    Classes,
    /// `ask` does not match `classes`.
    #[error("ask must price exactly the served classes")]
    Ask,
    /// `capacity_bytes` below 1 GiB.
    #[error("capacity must be at least 1 GiB")]
    Capacity,
    /// `storage_sig` does not verify under `storage_key`.
    #[error("storage_sig does not verify")]
    Signature,
}

/// `H("TOG/v1/storage-bind" ‖ u64 chain_id ‖ owner ‖ u64 owner_nonce ‖ storage_key)`, the message
/// of the storage key's proof of possession (what `tog-signer` signs for `ProvePossession`).
pub fn bind_digest(chain_id: u64, owner: &Address, owner_nonce: u64, storage_key: &[u8; 32]) -> Hash32 {
    tagged_hash(Domain::StorageBind, &[&chain_id.to_le_bytes(), owner, &owner_nonce.to_le_bytes(), storage_key])
}

impl RegisterStorageWorkerTx {
    /// The new worker's id, the address of `storage_key`.
    pub fn worker_id(&self) -> StorageWorkerId {
        StorageWorkerId(ed25519_address(&self.storage_key))
    }

    /// `H("TOG/v1/storage-bind" ‖ u64 chain_id ‖ owner ‖ u64 owner_nonce ‖ storage_key)`.
    pub fn bind_digest(&self) -> Hash32 {
        bind_digest(self.chain_id, &self.owner, self.owner_nonce, &self.storage_key)
    }

    /// Rules that need no Hub state, the storage signature included (`verify_strict`). The
    /// signer, chain, nonce, id uniqueness, bond floor and balance are the Hub's.
    pub fn check_stateless(&self) -> Result<(), StorageRegistrationError> {
        if !self.region.is_well_formed() {
            return Err(StorageRegistrationError::Region);
        }
        if self.asn == 0 {
            return Err(StorageRegistrationError::Asn);
        }
        if !self.classes.is_valid() {
            return Err(StorageRegistrationError::Classes);
        }
        if !self.ask.matches(self.classes) {
            return Err(StorageRegistrationError::Ask);
        }
        if self.capacity_bytes < MIN_CAPACITY_BYTES {
            return Err(StorageRegistrationError::Capacity);
        }
        let sig = ed25519_dalek::Signature::from_bytes(&self.storage_sig);
        let ok = ed25519_dalek::VerifyingKey::from_bytes(&self.storage_key)
            .is_ok_and(|k| k.verify_strict(&self.bind_digest(), &sig).is_ok());
        if !ok {
            return Err(StorageRegistrationError::Signature);
        }
        Ok(())
    }

    /// The record a valid registration creates.
    pub fn record(&self, reputation: u32) -> StorageWorkerRecord {
        StorageWorkerRecord {
            id: self.worker_id(),
            owner: self.owner,
            operator_group: self.operator_group,
            region: self.region,
            asn: self.asn,
            classes: self.classes,
            capacity_bytes: self.capacity_bytes,
            committed_bytes: 0,
            net: NetProfile::default(),
            ask: self.ask,
            bond: self.bond,
            locked_collateral: 0,
            reputation,
            status: StorageWorkerStatus::Active,
            region_flagged: false,
        }
    }
}

/// `u256_be(H("TOG/v1/place" ‖ beacon ‖ u64 deal_id ‖ u32 i)) mod total` (TOG-SPEC-0004 §4.3);
/// `total > 0`.
pub fn place_draw(beacon: &[u8; 32], deal: DealId, i: u32, total: u128) -> u128 {
    assert!(total > 0, "empty pool");
    let h = tagged_hash(Domain::Place, &[beacon, &deal.0.to_le_bytes(), &i.to_le_bytes()]);
    // Horner over the big-endian bytes: r ← (r · 256 + byte) mod total.
    h.iter().fold(0u128, |r, &byte| addmod(mulmod(r, 256, total), u128::from(byte) % total, total))
}

fn addmod(a: u128, b: u128, m: u128) -> u128 {
    let (s, carry) = a.overflowing_add(b);
    if carry || s >= m {
        s.wrapping_sub(m)
    } else {
        s
    }
}

/// `a · b mod m` for `a, b < 2^128` by doubling.
fn mulmod(a: u128, b: u128, m: u128) -> u128 {
    let (mut a, mut b, mut r) = (a % m, b, 0u128);
    while b > 0 {
        if b & 1 == 1 {
            r = addmod(r, a, m);
        }
        a = addmod(a, a, m);
        b >>= 1;
    }
    r
}

/// True if `worker` is due a scheduled `Holder` challenge in the block with this `beacon`
/// (TOG-SPEC-0004 §5.1): the first 8 bytes, little-endian, of `H("TOG/v1/sched" ‖ beacon ‖ w.id)`
/// are below `⌊2^64 / I_sched⌋`. The status, committed-bytes and open-challenge conditions are
/// the Hub's. `i_sched > 0`.
pub fn is_scheduled(beacon: &[u8; 32], worker: &StorageWorkerId, i_sched: u64) -> bool {
    let u = u64::from_le_bytes(sched_hash(beacon, worker)[..8].try_into().expect("8 bytes"));
    u128::from(u) < sched_threshold(i_sched)
}

fn sched_hash(beacon: &[u8; 32], worker: &StorageWorkerId) -> Hash32 {
    tagged_hash(Domain::Sched, &[beacon, &worker.0])
}

/// `⌊2^64 / i_sched⌋`; `2^64` itself when `i_sched = 1`.
fn sched_threshold(i_sched: u64) -> u128 {
    (1u128 << 64) / u128::from(i_sched)
}

#[cfg(test)]
mod tests;
