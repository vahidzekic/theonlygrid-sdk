//! `system`: account nonces, the block number and runtime upgrades (TOG-SPEC-0007 §7, §4.3, §8.3).
//!
//! A signed transaction carries the signer's next nonce; `pre_dispatch` checks it with
//! [`check_nonce`] in the pool and bumps it with [`inc_nonce`] before dispatch, so a transaction
//! can't be replayed. The nonce is shared by native and Ethereum-format transactions (§7.3).
//!
//! **Upgrades.** The chain's governance calls [`authorize_upgrade`] with the hash of code already
//! uploaded to the Hub; at the end of the block [`take_authorized_upgrade`] gives the block's
//! `ValidationResult.new_code`. The Hub switches the code once that block is final and the delay has
//! passed. [`RUNTIME_VERSION`] holds the `spec_version` whose migrations last ran: the first block
//! under code with a higher one runs the runtime's `on_runtime_upgrade` hook, which migrates each
//! module whose [`StorageVersion`] is behind (§5).
//!
//! **Multi-block migrations.** A migration too large for one block starts with
//! [`start_migration`]: [`MIGRATION`] then holds its cursor, and each block gives the runtime's
//! `migration_step` hook the block's weight to move it on until the hook reports it done. While
//! one is ongoing the block takes no transactions; inbox messages are still delivered, so a
//! module whose state is half migrated must accept both layouts in its CGMP handlers.
//!
//! **Hub time.** [`hub_last_block`] reads the Hub's `system.last_block` at the relay parent: the BFT
//! time of Hub block `h − 1` and `HubBeacon(h − 2)` for relay parent `h` (§3.2), which the block
//! author knows while it builds.
//!
//! **Events.** [`EVENTS`] holds the events of the last block, written once at its end (the
//! executive collects them while the block runs): one [`Event`] per inbox message and per
//! transaction with its outcome, and the events the runtime's calls deposit, each tagged with its
//! [`Phase`]. A call's events go with it when it fails. Every block replaces the value, so its
//! previous content is in the next block's witness: the executive charges its size to that
//! block's `proof_size`, and a block keeps at most [`MAX_EVENTS_BYTES`] of records, counting the
//! rest in [`Events::dropped`]. Nodes read the value from each block's state for RPC and indexers
//! (§9).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use tog_runtime_core::env::Env;
use tog_runtime_core::{
    AccountId, BlockNumber, ChainId, DispatchError, Hash32, Origin, Storage, StorageError, StorageMap, StorageValue,
    Weight,
};
use tog_types::state::items::system_last_block;

/// `system.nonces: Address → u64`, the next nonce each account must use (absent = 0). Its bytes
/// are in the account's deposit ([`balances::ACCOUNT_BYTES`](crate::balances::ACCOUNT_BYTES));
/// the entry is never removed, so it outlives a reaped account (§5).
pub const NONCES: StorageMap<AccountId, u64> = StorageMap::new("system", "nonces");
/// `system.number`: the number of the block being executed.
pub const NUMBER: StorageValue<BlockNumber> = StorageValue::new("system", "number");

/// `system.authorized_upgrade`: the code hash authorized in the block being executed; cleared by
/// [`take_authorized_upgrade`] at its end.
pub const AUTHORIZED_UPGRADE: StorageValue<Hash32> = StorageValue::new("system", "authorized_upgrade");
/// `system.runtime_version`: the `spec_version` whose migrations last ran, written at genesis.
pub const RUNTIME_VERSION: StorageValue<u32> = StorageValue::new("system", "runtime_version");
/// `system.migration`: the cursor of the ongoing multi-block migration, absent when none is.
pub const MIGRATION: StorageValue<Vec<u8>> = StorageValue::new("system", "migration");

/// `system.events`: the last block's events.
pub const EVENTS: StorageValue<Events> = StorageValue::new("system", "events");

/// Call index of [`authorize_upgrade`].
pub const AUTHORIZE_UPGRADE: u8 = 0;

/// The module's metadata. Errors: 0 `BadOrigin` (`DispatchError::BadOrigin`), 1
/// [`UpgradeError::AlreadyAuthorized`].
pub fn metadata() -> tog_runtime_core::metadata::ModuleMetadata {
    tog_runtime_core::metadata::ModuleMetadata::from_names(
        "system",
        &[(AUTHORIZE_UPGRADE, "authorize_upgrade", &[("code_hash", "Hash32")])],
        &["nonces", "number", "authorized_upgrade", "runtime_version", "migration", "events"],
        &["ExtrinsicSuccess", "ExtrinsicFailed", "Message", "Upgraded", "MigrationCompleted"],
        &["BadOrigin", "AlreadyAuthorized"],
    )
}
/// Most bytes of records a block keeps; later events are counted, not kept.
pub const MAX_EVENTS_BYTES: usize = 64 * 1024;

/// Where in its block an event happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Phase {
    /// While the block processed its `i`-th inbox message.
    Inbox(u32),
    /// While the block's `i`-th transaction ran.
    Extrinsic(u32),
    /// Before the inbox: the runtime upgrade, `on_initialize` and the multi-block migration's step.
    Initialization,
    /// After the transactions: `on_idle` and `on_finalize`.
    Finalization,
}

/// One event: the module that deposited it and its Borsh-encoded body, the module's own type.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EventRecord {
    /// When.
    pub phase: Phase,
    /// The module's name in the runtime metadata (`"system"` for [`Event`]).
    pub module: String,
    /// `borsh(event)`.
    pub event: Vec<u8>,
}

/// A block's events.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Events {
    /// In order.
    pub records: Vec<EventRecord>,
    /// Events left out because the block had [`MAX_EVENTS_BYTES`] of records already.
    pub dropped: u32,
    /// The records' size, as of a given number of records; not stored.
    #[borsh(skip)]
    used: SizeCache,
}

/// `(records, their size)`: [`Events::push`]'s running total. Equal to any other, so it never
/// tells two `Events` apart.
#[derive(Clone, Copy, Debug, Default)]
struct SizeCache(Option<(usize, usize)>);

impl PartialEq for SizeCache {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for SizeCache {}

impl Events {
    /// The events `records`, with `dropped` left out.
    pub fn new(records: Vec<EventRecord>, dropped: u32) -> Self {
        Events { records, dropped, used: SizeCache::default() }
    }

    /// Adds a record unless the block's records are full.
    pub fn push(&mut self, phase: Phase, module: &str, event: Vec<u8>) {
        let size = |r: &EventRecord| 5 + 4 + r.module.len() + 4 + r.event.len();
        // The records' size, summed once and then kept up to date, not summed again per push (R-10);
        // summed again if `records` changed length behind its back.
        let used = match self.used.0 {
            Some((n, used)) if n == self.records.len() => used,
            _ => self.records.iter().map(size).sum(),
        };
        let r = EventRecord { phase, module: module.to_string(), event };
        if used + size(&r) > MAX_EVENTS_BYTES {
            self.dropped = self.dropped.saturating_add(1);
            self.used.0 = Some((self.records.len(), used));
        } else {
            self.used.0 = Some((self.records.len() + 1, used + size(&r)));
            self.records.push(r);
        }
    }
}

/// A [`DispatchError`] as an event carries it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Failure {
    /// The call doesn't accept this origin.
    BadOrigin,
    /// A module's error: the module's index and the error's.
    Module {
        /// Module index.
        module: u8,
        /// Error index.
        error: u8,
    },
    /// Stored state doesn't decode or a value is too large.
    Storage,
    /// Out of weight.
    Exhausted,
    /// Arithmetic overflow or underflow.
    Arithmetic,
    /// Anything else.
    Other(String),
}

impl From<DispatchError> for Failure {
    fn from(e: DispatchError) -> Self {
        match e {
            DispatchError::BadOrigin => Failure::BadOrigin,
            DispatchError::Module { module, error } => Failure::Module { module, error },
            DispatchError::Storage(_) => Failure::Storage,
            DispatchError::Exhausted => Failure::Exhausted,
            DispatchError::Arithmetic => Failure::Arithmetic,
            DispatchError::Other(s) => Failure::Other(s.to_string()),
        }
    }
}

/// What became of an inbox message.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Outcome {
    /// Its handler ran, or it needed none.
    Executed,
    /// Its handler (a `Call`, or a `ComputeResult`'s callback) failed and was reverted.
    Failed(Failure),
    /// Past its `timeout_height`: consumed without running (§3.4).
    Expired,
}

/// The `system` module's events.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Event {
    /// A transaction's call succeeded, using `weight`.
    ExtrinsicSuccess {
        /// Weight it used.
        weight: Weight,
    },
    /// A transaction's call failed and was reverted; its fee was still paid.
    ExtrinsicFailed {
        /// Weight it was charged.
        weight: Weight,
        /// Why.
        error: Failure,
    },
    /// An inbox message was processed.
    Message {
        /// The chain that sent it.
        source: ChainId,
        /// Its nonce on the channel.
        nonce: u64,
        /// What became of it.
        outcome: Outcome,
    },
    /// The block was the first under runtime `to`, and the runtime's `on_runtime_upgrade` ran.
    Upgraded {
        /// The previous `spec_version`.
        from: u32,
        /// This runtime's.
        to: u32,
    },
    /// The multi-block migration finished in this block; transactions are taken again.
    MigrationCompleted,
}

/// Why a nonce check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceError {
    /// Already used: the transaction is stale and can never be included.
    Stale,
    /// Ahead of the account's next nonce: the pool may keep it until the gap is filled.
    Future,
    /// Stored state doesn't decode.
    Storage,
}

impl From<StorageError> for NonceError {
    fn from(_: StorageError) -> Self {
        NonceError::Storage
    }
}

/// The next nonce `who` must use.
pub fn nonce(s: &mut impl Storage, who: &AccountId) -> Result<u64, StorageError> {
    NONCES.get_or_default(s, who)
}

/// `Ok` iff `n` is `who`'s next nonce.
pub fn check_nonce(s: &mut impl Storage, who: &AccountId, n: u64) -> Result<(), NonceError> {
    let next = nonce(s, who)?;
    match n.cmp(&next) {
        core::cmp::Ordering::Less => Err(NonceError::Stale),
        core::cmp::Ordering::Greater => Err(NonceError::Future),
        core::cmp::Ordering::Equal => Ok(()),
    }
}

/// Check `n` and advance `who`'s nonce past it.
pub fn inc_nonce(s: &mut impl Storage, who: &AccountId, n: u64) -> Result<(), NonceError> {
    check_nonce(s, who, n)?;
    // `n == u64::MAX` would wrap to a used nonce; such an account can't transact any more.
    let next = n.checked_add(1).ok_or(NonceError::Stale)?;
    NONCES.insert(s, who, &next)?;
    Ok(())
}

/// The number of the block being executed (0 before the first block).
pub fn block_number(s: &mut impl Storage) -> Result<BlockNumber, StorageError> {
    NUMBER.get_or_default(s)
}

/// Record the start of block `n`; it must follow the stored number.
pub fn initialize(s: &mut impl Storage, n: BlockNumber) -> Result<(), StorageError> {
    debug_assert_eq!(block_number(s)?.checked_add(1), Some(n), "blocks are consecutive");
    NUMBER.put(s, &n)
}

/// Why an upgrade couldn't be authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeError {
    /// Only the chain's governance (`Root`) may authorize an upgrade.
    BadOrigin,
    /// The block already authorizes one: a block carries a single `new_code`.
    AlreadyAuthorized,
    /// Stored state doesn't decode.
    Storage,
}

impl From<StorageError> for UpgradeError {
    fn from(_: StorageError) -> Self {
        UpgradeError::Storage
    }
}

/// `system::authorize_upgrade(code_hash)` (§8.3 step 2): make this block's `new_code` `code_hash`.
/// The Hub ignores it unless `appchains.code[code_hash]` is `Accepted`.
pub fn authorize_upgrade(s: &mut impl Storage, origin: &Origin, code_hash: Hash32) -> Result<(), UpgradeError> {
    if *origin != Origin::Root {
        return Err(UpgradeError::BadOrigin);
    }
    if AUTHORIZED_UPGRADE.get(s)?.is_some() {
        return Err(UpgradeError::AlreadyAuthorized);
    }
    AUTHORIZED_UPGRADE.put(s, &code_hash)?;
    Ok(())
}

/// The block's `new_code`, at the end of the block; clears it so the next block starts with none.
pub fn take_authorized_upgrade(s: &mut impl Storage) -> Result<Option<Hash32>, StorageError> {
    let code = AUTHORIZED_UPGRADE.get(s)?;
    if code.is_some() {
        AUTHORIZED_UPGRADE.kill(s);
    }
    Ok(code)
}

/// A module's storage layout version (§5): stored under `module.storage_version`, absent = 0. A
/// module starts at 0 and raises `current` with each change to its stored types; it writes
/// `current` at genesis with [`StorageVersion::put_current`], and the runtime's
/// `on_runtime_upgrade` brings an older chain forward with [`StorageVersion::migrate`].
pub struct StorageVersion {
    item: StorageValue<u16>,
    current: u16,
}

impl StorageVersion {
    /// `module` at layout `current`.
    pub const fn new(module: &'static str, current: u16) -> Self {
        StorageVersion { item: StorageValue::new(module, "storage_version"), current }
    }

    /// The layout the code expects.
    pub const fn current(&self) -> u16 {
        self.current
    }

    /// The layout the state has.
    pub fn on_chain(&self, s: &mut impl Storage) -> Result<u16, StorageError> {
        self.item.get_or_default(s)
    }

    /// Record that the state has the current layout.
    pub fn put_current(&self, s: &mut impl Storage) -> Result<(), StorageError> {
        self.item.put(s, &self.current)
    }

    /// If the state is behind, run `migrate(on_chain)` and record the current layout; returns the
    /// weight `migrate` used (zero when the state was current). A state ahead of the code is left
    /// as it is: code never migrates backwards.
    pub fn migrate<S: Storage>(
        &self,
        s: &mut S,
        migrate: impl FnOnce(&mut S, u16) -> Weight,
    ) -> Result<Weight, StorageError> {
        let from = self.on_chain(s)?;
        if from >= self.current {
            return Ok(Weight::ZERO);
        }
        let w = migrate(s, from);
        self.put_current(s)?;
        Ok(w)
    }
}

/// Why a multi-block migration couldn't start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationError {
    /// Another one is ongoing.
    Ongoing,
    /// Stored state doesn't decode.
    Storage,
}

impl From<StorageError> for MigrationError {
    fn from(_: StorageError) -> Self {
        MigrationError::Storage
    }
}

/// Start a multi-block migration at `cursor`, which the runtime's `migration_step` hook reads; its
/// first step runs in this block if called from `on_runtime_upgrade` or `on_initialize`.
pub fn start_migration(s: &mut impl Storage, cursor: Vec<u8>) -> Result<(), MigrationError> {
    if MIGRATION.get(s)?.is_some() {
        return Err(MigrationError::Ongoing);
    }
    MIGRATION.put(s, &cursor)?;
    Ok(())
}

/// The ongoing multi-block migration's cursor.
pub fn migration(s: &mut impl Storage) -> Result<Option<Vec<u8>>, StorageError> {
    MIGRATION.get(s)
}

/// The Hub's `system.last_block` at the relay parent: `(time, beacon)`, the BFT time of Hub
/// block `h − 1` and `HubBeacon(h − 2)` for relay parent `h` (§3.2); `None` before Hub block 1.
pub fn hub_last_block(e: &mut impl Env) -> Result<Option<(u64, Hash32)>, StorageError> {
    e.hub_read(&system_last_block()).map(|b| borsh::from_slice(&b).map_err(|_| StorageError::Corrupt)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tog_runtime_core::memory::MemoryStorage;

    const A: AccountId = [1; 20];

    #[test]
    fn nonces_advance_one_at_a_time() {
        let mut s = MemoryStorage::default();
        assert_eq!(check_nonce(&mut s, &A, 1), Err(NonceError::Future));
        inc_nonce(&mut s, &A, 0).unwrap();
        assert_eq!(inc_nonce(&mut s, &A, 0), Err(NonceError::Stale));
        inc_nonce(&mut s, &A, 1).unwrap();
        assert_eq!(nonce(&mut s, &A).unwrap(), 2);
        assert_eq!(nonce(&mut s, &[2; 20]).unwrap(), 0);
    }

    #[test]
    fn a_block_keeps_events_up_to_its_byte_limit_and_counts_the_rest() {
        let mut e = Events::default();
        let body = vec![7u8; 1_000];
        while e.dropped == 0 {
            e.push(Phase::Extrinsic(e.records.len() as u32), "balances", body.clone());
        }
        let size = 5 + 4 + "balances".len() + 4 + body.len();
        assert_eq!(e.records.len(), MAX_EVENTS_BYTES / size);
        assert_eq!(e.dropped, 1);
        // A smaller one still fits in what is left.
        e.push(Phase::Inbox(0), "system", vec![]);
        assert_eq!((e.dropped, e.records.last().unwrap().phase), (1, Phase::Inbox(0)));
        assert!(borsh::to_vec(&e).unwrap().len() <= MAX_EVENTS_BYTES + 8);
        // Decoded, or with records taken out directly, the running size starts over.
        let mut d: Events = borsh::from_slice(&borsh::to_vec(&e).unwrap()).unwrap();
        assert_eq!(d, e);
        d.push(Phase::Inbox(1), "balances", body.clone());
        assert_eq!(d.dropped, 2);
        e.records.truncate(1);
        e.push(Phase::Inbox(1), "balances", body);
        assert_eq!((e.records.len(), e.dropped), (2, 1));
    }

    #[test]
    fn last_nonce_is_unusable() {
        let mut s = MemoryStorage::default();
        NONCES.insert(&mut s, &A, &u64::MAX).unwrap();
        assert_eq!(inc_nonce(&mut s, &A, u64::MAX), Err(NonceError::Stale));
    }

    #[test]
    fn block_number_follows_initialize() {
        let mut s = MemoryStorage::default();
        assert_eq!(block_number(&mut s).unwrap(), 0);
        initialize(&mut s, 1).unwrap();
        initialize(&mut s, 2).unwrap();
        assert_eq!(block_number(&mut s).unwrap(), 2);
    }

    #[test]
    fn one_upgrade_per_block_by_root() {
        let mut s = MemoryStorage::default();
        assert_eq!(authorize_upgrade(&mut s, &Origin::Signed(A), [7; 32]), Err(UpgradeError::BadOrigin));
        assert_eq!(take_authorized_upgrade(&mut s).unwrap(), None);
        authorize_upgrade(&mut s, &Origin::Root, [7; 32]).unwrap();
        assert_eq!(authorize_upgrade(&mut s, &Origin::Root, [8; 32]), Err(UpgradeError::AlreadyAuthorized));
        assert_eq!(take_authorized_upgrade(&mut s).unwrap(), Some([7; 32]));
        assert_eq!(take_authorized_upgrade(&mut s).unwrap(), None, "the next block starts with none");
        authorize_upgrade(&mut s, &Origin::Root, [8; 32]).unwrap();
    }

    #[test]
    fn a_module_migrates_once_and_never_backwards() {
        let mut s = MemoryStorage::default();
        let mut runs = Vec::new();
        let v2 = StorageVersion::new("balances", 2);
        let w = Weight::from_parts(5, 1);
        assert_eq!(
            v2.migrate(&mut s, |_, from| {
                runs.push(from);
                w
            })
            .unwrap(),
            w
        );
        assert_eq!(
            v2.migrate(&mut s, |_, from| {
                runs.push(from);
                w
            })
            .unwrap(),
            Weight::ZERO
        );
        assert_eq!(v2.on_chain(&mut s).unwrap(), 2);
        let v1 = StorageVersion::new("balances", 1);
        assert_eq!(
            v1.migrate(&mut s, |_, from| {
                runs.push(from);
                w
            })
            .unwrap(),
            Weight::ZERO,
            "never backwards"
        );
        assert_eq!(StorageVersion::new("sudo", 1).on_chain(&mut s).unwrap(), 0, "per module");
        assert_eq!(runs, [0]);
    }

    #[test]
    fn one_multi_block_migration_at_a_time() {
        let mut s = MemoryStorage::default();
        assert_eq!(migration(&mut s).unwrap(), None);
        start_migration(&mut s, vec![1]).unwrap();
        assert_eq!(start_migration(&mut s, vec![2]), Err(MigrationError::Ongoing));
        assert_eq!(migration(&mut s).unwrap(), Some(vec![1]));
    }
}
