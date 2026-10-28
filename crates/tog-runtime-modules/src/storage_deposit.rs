//! `storage_deposit`: state bloat paid for by whoever causes it (TOG-SPEC-0007 §5).
//!
//! A call that adds state reserves `per_byte` for every byte it keeps (the value, its 96-byte key
//! and the deposit's own record) from the account that caused it, and the deposit comes back when
//! the state is removed. The SDK default is [`DEFAULT_PER_BYTE`]; a chain may set another.
//!
//! The deposit is recorded per storage key, so a module only says which key it wrote or removed:
//! [`insert`] and [`remove`] wrap a [`StorageMap`], and [`charge`] / [`release`] work on any key. A
//! value rewritten by its payer reserves or returns only the difference; rewritten by someone else,
//! the old payer is refunded in full and the new one pays.

use borsh::BorshSerialize;
use tog_runtime_core::storage::StorageKey;
use tog_runtime_core::{AccountId, Balance, Storage, StorageError, StorageMap};

use crate::balances;

/// `StorageDepositPerByte`, the SDK default: 10¹⁴ atto-TOG, as `CodeDepositPerByte` (§5, §8.1).
pub const DEFAULT_PER_BYTE: Balance = 100_000_000_000_000;

/// `storage_deposit.deposits: storage_key → (payer, amount)`.
pub const DEPOSITS: StorageMap<StorageKey, (AccountId, Balance)> = StorageMap::new("storage_deposit", "deposits");

/// Bytes a deposited value keeps besides the value: its key, and the record's key and value.
pub const OVERHEAD: u64 = 96 + 96 + 20 + 16;

/// Why a deposit couldn't be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The payer's free balance doesn't cover it.
    InsufficientBalance,
    /// Stored state doesn't decode, or an amount overflows.
    Storage,
}

impl From<StorageError> for Error {
    fn from(_: StorageError) -> Self {
        Error::Storage
    }
}

impl From<balances::Error> for Error {
    fn from(e: balances::Error) -> Self {
        match e {
            balances::Error::InsufficientBalance => Error::InsufficientBalance,
            _ => Error::Storage,
        }
    }
}

/// The deposit for keeping a value of `len` bytes.
pub fn deposit_for(len: u64, per_byte: Balance) -> Option<Balance> {
    Balance::from(len.checked_add(OVERHEAD)?).checked_mul(per_byte)
}

/// Hold the deposit for `len` bytes at `key` from `payer`. On failure nothing changes.
pub fn charge(
    s: &mut impl Storage,
    key: &StorageKey,
    payer: &AccountId,
    len: u64,
    per_byte: Balance,
) -> Result<(), Error> {
    let amount = deposit_for(len, per_byte).ok_or(Error::Storage)?;
    match DEPOSITS.get(s, key)? {
        Some((old, held)) if old == *payer => {
            if amount > held {
                balances::reserve(s, payer, amount - held)?;
            } else {
                balances::unreserve(s, payer, held - amount)?;
            }
        }
        Some((old, held)) => {
            balances::reserve(s, payer, amount)?;
            balances::unreserve(s, &old, held)?;
        }
        None => balances::reserve(s, payer, amount)?,
    }
    DEPOSITS.insert(s, key, &(*payer, amount))?;
    Ok(())
}

/// Return the deposit held for `key`, if any, to its payer.
pub fn release(s: &mut impl Storage, key: &StorageKey) -> Result<(), Error> {
    if let Some((payer, held)) = DEPOSITS.take(s, key)? {
        balances::unreserve(s, &payer, held)?;
    }
    Ok(())
}

/// Insert `v` at `k` in `map`, with `payer`'s deposit for its encoded size.
pub fn insert<K: BorshSerialize, V: BorshSerialize + borsh::BorshDeserialize>(
    s: &mut impl Storage,
    map: &StorageMap<K, V>,
    k: &K,
    v: &V,
    payer: &AccountId,
    per_byte: Balance,
) -> Result<(), Error> {
    let len = borsh::to_vec(v).map_err(|_| Error::Storage)?.len() as u64;
    charge(s, &map.key(k), payer, len, per_byte)?;
    map.insert(s, k, v)?;
    Ok(())
}

/// Remove `k` from `map` and return its deposit.
pub fn remove<K: BorshSerialize, V: BorshSerialize + borsh::BorshDeserialize>(
    s: &mut impl Storage,
    map: &StorageMap<K, V>,
    k: &K,
) -> Result<(), Error> {
    map.remove(s, k);
    release(s, &map.key(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use tog_runtime_core::memory::MemoryStorage;

    const A: AccountId = [1; 20];
    const B: AccountId = [2; 20];
    const NOTES: StorageMap<u32, Vec<u8>> = StorageMap::new("test", "notes");

    fn free(s: &mut MemoryStorage, who: &AccountId) -> Balance {
        balances::free_balance(s, who).unwrap()
    }

    #[test]
    fn whoever_adds_state_pays_per_byte_and_gets_it_back() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, 10_000).unwrap();
        balances::deposit(&mut s, &B, 10_000).unwrap();
        let held = |len: u64| deposit_for(len + 4, 2).unwrap(); // borsh(Vec<u8>) has a 4-byte length

        insert(&mut s, &NOTES, &1, &vec![0; 100], &A, 2).unwrap();
        assert_eq!(free(&mut s, &A), 10_000 - held(100));
        assert_eq!(balances::account(&mut s, &A).unwrap().reserved, held(100));

        // A rewrite by the payer moves only the difference, both ways.
        insert(&mut s, &NOTES, &1, &vec![0; 300], &A, 2).unwrap();
        assert_eq!(free(&mut s, &A), 10_000 - held(300));
        insert(&mut s, &NOTES, &1, &vec![0; 10], &A, 2).unwrap();
        assert_eq!(free(&mut s, &A), 10_000 - held(10));

        // Someone else's rewrite refunds the old payer in full.
        insert(&mut s, &NOTES, &1, &vec![0; 50], &B, 2).unwrap();
        assert_eq!(free(&mut s, &A), 10_000);
        assert_eq!(free(&mut s, &B), 10_000 - held(50));

        remove(&mut s, &NOTES, &1).unwrap();
        assert_eq!(free(&mut s, &B), 10_000);
        assert_eq!(NOTES.get(&mut s, &1).unwrap(), None);
        assert_eq!(DEPOSITS.get(&mut s, &NOTES.key(&1)).unwrap(), None);
        remove(&mut s, &NOTES, &1).unwrap();
    }

    #[test]
    fn an_unpaid_write_changes_nothing() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, 100).unwrap();
        assert_eq!(insert(&mut s, &NOTES, &1, &vec![0; 100], &A, 2), Err(Error::InsufficientBalance));
        assert_eq!(NOTES.get(&mut s, &1).unwrap(), None);
        assert_eq!(free(&mut s, &A), 100);
    }
}
