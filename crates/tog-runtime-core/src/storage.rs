//! State keys and typed storage items (TOG-SPEC-0007 §5).
//!
//! An AppChain's state is a Jellyfish Merkle tree keyed exactly like the Hub's
//! (TOG-SPEC-0002 §7.1): `B(module) ‖ B(item) ‖ B(borsh(key))`, each part plain BLAKE3-256. Hashing
//! every part spreads keys uniformly, so nobody can build a deep, unbalanced branch.
//!
//! [`StorageValue`], [`StorageMap`], [`StorageDoubleMap`] and [`StorageNMap`] are `const`-constructible handles that
//! a module declares once and uses with any [`Storage`] backend:
//!
//! ```
//! use tog_runtime_core::{memory::MemoryStorage, StorageMap};
//!
//! const ACCOUNTS: StorageMap<[u8; 20], u128> = StorageMap::new("balances", "accounts");
//!
//! let mut s = MemoryStorage::default();
//! ACCOUNTS.insert(&mut s, &[1; 20], &5).unwrap();
//! assert_eq!(ACCOUNTS.get(&mut s, &[1; 20]).unwrap(), Some(5));
//! ```

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};

/// A full state key: `B(module) ‖ B(item) ‖ B(borsh(key))`.
pub type StorageKey = [u8; 96];

/// Largest encoded value one key may hold. Provisional SDK default (0007 §3.2 bounds values but
/// doesn't fix the number yet); a chain's PoV limit (§6) is the real bound on what one block reads.
pub const MAX_VALUE_LEN: usize = 1 << 20;

/// `B(module) ‖ B(item) ‖ B(borsh_key)` with plain BLAKE3-256, the Hub's layout (0002 §7.1).
pub use tog_types::state::storage_key;

/// The raw key-value interface a runtime sees through the host ABI's storage group (§3.2).
///
/// Reads take `&mut self` because a backend may record every access into the PoV witness.
pub trait Storage {
    /// Value under `key`, if any.
    fn get(&mut self, key: &StorageKey) -> Option<Vec<u8>>;
    /// Store `value` under `key`, replacing what was there.
    fn set(&mut self, key: &StorageKey, value: Vec<u8>);
    /// Remove `key`.
    fn clear(&mut self, key: &StorageKey);
    /// Whether `key` holds a value.
    fn exists(&mut self, key: &StorageKey) -> bool {
        self.get(key).is_some()
    }
    /// The smallest key strictly greater than `key` that holds a value, in byte order.
    fn next_key(&mut self, key: &StorageKey) -> Option<StorageKey>;
}

/// Why a typed storage access failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// The stored bytes don't decode as the item's type: the state was written by other code.
    Corrupt,
    /// The encoded value is longer than [`MAX_VALUE_LEN`].
    ValueTooLarge,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Corrupt => f.write_str("stored value does not decode"),
            StorageError::ValueTooLarge => f.write_str("value exceeds the storage value limit"),
        }
    }
}

fn encode<V: BorshSerialize>(v: &V) -> Result<Vec<u8>, StorageError> {
    let bytes = borsh::to_vec(v).map_err(|_| StorageError::ValueTooLarge)?;
    if bytes.len() > MAX_VALUE_LEN {
        return Err(StorageError::ValueTooLarge);
    }
    Ok(bytes)
}

fn read<V: BorshDeserialize>(s: &mut impl Storage, key: &StorageKey) -> Result<Option<V>, StorageError> {
    s.get(key).map(|b| borsh::from_slice(&b).map_err(|_| StorageError::Corrupt)).transpose()
}

fn write<V: BorshSerialize>(s: &mut impl Storage, key: &StorageKey, v: &V) -> Result<(), StorageError> {
    s.set(key, encode(v)?);
    Ok(())
}

fn borsh_key<K: BorshSerialize>(k: &K) -> Vec<u8> {
    // Writing to a Vec can't fail.
    borsh::to_vec(k).unwrap_or_default()
}

/// One value of type `V` at `(module, item)`; its key part is `borsh(())`, the empty string.
pub struct StorageValue<V> {
    module: &'static str,
    item: &'static str,
    _v: PhantomData<fn() -> V>,
}

impl<V: BorshSerialize + BorshDeserialize> StorageValue<V> {
    /// Handle for `module.item`.
    pub const fn new(module: &'static str, item: &'static str) -> Self {
        StorageValue { module, item, _v: PhantomData }
    }

    /// Its state key.
    pub fn key(&self) -> StorageKey {
        storage_key(self.module, self.item, &[])
    }

    /// The stored value, if any.
    pub fn get(&self, s: &mut impl Storage) -> Result<Option<V>, StorageError> {
        read(s, &self.key())
    }

    /// Store `v`.
    pub fn put(&self, s: &mut impl Storage, v: &V) -> Result<(), StorageError> {
        write(s, &self.key(), v)
    }

    /// Remove the value.
    pub fn kill(&self, s: &mut impl Storage) {
        s.clear(&self.key())
    }

    /// Remove and return the value.
    pub fn take(&self, s: &mut impl Storage) -> Result<Option<V>, StorageError> {
        let v = self.get(s)?;
        self.kill(s);
        Ok(v)
    }

    /// Whether a value is stored.
    pub fn exists(&self, s: &mut impl Storage) -> bool {
        s.exists(&self.key())
    }
}

impl<V: BorshSerialize + BorshDeserialize + Default> StorageValue<V> {
    /// The stored value, or `V::default()` when absent.
    pub fn get_or_default(&self, s: &mut impl Storage) -> Result<V, StorageError> {
        Ok(self.get(s)?.unwrap_or_default())
    }

    /// Read, change and write back the value (starting from the default when absent).
    pub fn mutate<R>(&self, s: &mut impl Storage, f: impl FnOnce(&mut V) -> R) -> Result<R, StorageError> {
        let mut v = self.get_or_default(s)?;
        let r = f(&mut v);
        self.put(s, &v)?;
        Ok(r)
    }
}

/// A map `K -> V` at `(module, item)`; entry `k` lives at `storage_key(module, item, borsh(k))`.
pub struct StorageMap<K, V> {
    module: &'static str,
    item: &'static str,
    _kv: PhantomData<fn(K) -> V>,
}

impl<K: BorshSerialize, V: BorshSerialize + BorshDeserialize> StorageMap<K, V> {
    /// Handle for `module.item`.
    pub const fn new(module: &'static str, item: &'static str) -> Self {
        StorageMap { module, item, _kv: PhantomData }
    }

    /// State key of entry `k`.
    pub fn key(&self, k: &K) -> StorageKey {
        storage_key(self.module, self.item, &borsh_key(k))
    }

    /// Entry `k`, if any.
    pub fn get(&self, s: &mut impl Storage, k: &K) -> Result<Option<V>, StorageError> {
        read(s, &self.key(k))
    }

    /// Store `v` at `k`.
    pub fn insert(&self, s: &mut impl Storage, k: &K, v: &V) -> Result<(), StorageError> {
        write(s, &self.key(k), v)
    }

    /// Remove entry `k`.
    pub fn remove(&self, s: &mut impl Storage, k: &K) {
        s.clear(&self.key(k))
    }

    /// Remove and return entry `k`.
    pub fn take(&self, s: &mut impl Storage, k: &K) -> Result<Option<V>, StorageError> {
        let key = self.key(k);
        let v = read(s, &key)?;
        s.clear(&key);
        Ok(v)
    }

    /// Whether entry `k` exists.
    pub fn contains_key(&self, s: &mut impl Storage, k: &K) -> bool {
        s.exists(&self.key(k))
    }
}

impl<K: BorshSerialize, V: BorshSerialize + BorshDeserialize + Default> StorageMap<K, V> {
    /// Entry `k`, or `V::default()` when absent.
    pub fn get_or_default(&self, s: &mut impl Storage, k: &K) -> Result<V, StorageError> {
        Ok(self.get(s, k)?.unwrap_or_default())
    }

    /// Read, change and write back entry `k` (starting from the default when absent).
    pub fn mutate<R>(&self, s: &mut impl Storage, k: &K, f: impl FnOnce(&mut V) -> R) -> Result<R, StorageError> {
        let key = self.key(k);
        let mut v = read(s, &key)?.unwrap_or_default();
        let r = f(&mut v);
        write(s, &key, &v)?;
        Ok(r)
    }
}

/// A map `(K1, K2) -> V`; entry `(a, b)` lives at `storage_key(module, item, borsh((a, b)))`,
/// which is `borsh(a) ‖ borsh(b)`.
pub struct StorageDoubleMap<K1, K2, V> {
    module: &'static str,
    item: &'static str,
    _kv: PhantomData<fn(K1, K2) -> V>,
}

impl<K1: BorshSerialize, K2: BorshSerialize, V: BorshSerialize + BorshDeserialize> StorageDoubleMap<K1, K2, V> {
    /// Handle for `module.item`.
    pub const fn new(module: &'static str, item: &'static str) -> Self {
        StorageDoubleMap { module, item, _kv: PhantomData }
    }

    /// State key of entry `(a, b)`.
    pub fn key(&self, a: &K1, b: &K2) -> StorageKey {
        let mut k = borsh_key(a);
        k.extend_from_slice(&borsh_key(b));
        storage_key(self.module, self.item, &k)
    }

    /// Entry `(a, b)`, if any.
    pub fn get(&self, s: &mut impl Storage, a: &K1, b: &K2) -> Result<Option<V>, StorageError> {
        read(s, &self.key(a, b))
    }

    /// Store `v` at `(a, b)`.
    pub fn insert(&self, s: &mut impl Storage, a: &K1, b: &K2, v: &V) -> Result<(), StorageError> {
        write(s, &self.key(a, b), v)
    }

    /// Remove entry `(a, b)`.
    pub fn remove(&self, s: &mut impl Storage, a: &K1, b: &K2) {
        s.clear(&self.key(a, b))
    }

    /// Whether entry `(a, b)` exists.
    pub fn contains_key(&self, s: &mut impl Storage, a: &K1, b: &K2) -> bool {
        s.exists(&self.key(a, b))
    }
}

/// A map over a tuple of keys `K = (K1, …, Kn) -> V`; entry `k` lives at
/// `storage_key(module, item, borsh(k))`, which is `borsh(k1) ‖ … ‖ borsh(kn)`. A two-tuple
/// `StorageNMap` and a [`StorageDoubleMap`] at the same `(module, item)` share their keys.
pub struct StorageNMap<K, V> {
    module: &'static str,
    item: &'static str,
    _kv: PhantomData<fn(K) -> V>,
}

impl<K: BorshSerialize, V: BorshSerialize + BorshDeserialize> StorageNMap<K, V> {
    /// Handle for `module.item`.
    pub const fn new(module: &'static str, item: &'static str) -> Self {
        StorageNMap { module, item, _kv: PhantomData }
    }

    /// State key of entry `k`.
    pub fn key(&self, k: &K) -> StorageKey {
        storage_key(self.module, self.item, &borsh_key(k))
    }

    /// Entry `k`, if any.
    pub fn get(&self, s: &mut impl Storage, k: &K) -> Result<Option<V>, StorageError> {
        read(s, &self.key(k))
    }

    /// Store `v` at `k`.
    pub fn insert(&self, s: &mut impl Storage, k: &K, v: &V) -> Result<(), StorageError> {
        write(s, &self.key(k), v)
    }

    /// Remove entry `k`.
    pub fn remove(&self, s: &mut impl Storage, k: &K) {
        s.clear(&self.key(k))
    }

    /// Remove and return entry `k`.
    pub fn take(&self, s: &mut impl Storage, k: &K) -> Result<Option<V>, StorageError> {
        let key = self.key(k);
        let v = read(s, &key)?;
        s.clear(&key);
        Ok(v)
    }

    /// Whether entry `k` exists.
    pub fn contains_key(&self, s: &mut impl Storage, k: &K) -> bool {
        s.exists(&self.key(k))
    }
}

impl<K: BorshSerialize, V: BorshSerialize + BorshDeserialize + Default> StorageNMap<K, V> {
    /// Entry `k`, or `V::default()` when absent.
    pub fn get_or_default(&self, s: &mut impl Storage, k: &K) -> Result<V, StorageError> {
        Ok(self.get(s, k)?.unwrap_or_default())
    }

    /// Read, change and write back entry `k` (starting from the default when absent).
    pub fn mutate<R>(&self, s: &mut impl Storage, k: &K, f: impl FnOnce(&mut V) -> R) -> Result<R, StorageError> {
        let key = self.key(k);
        let mut v = read(s, &key)?.unwrap_or_default();
        let r = f(&mut v);
        write(s, &key, &v)?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStorage;

    #[test]
    fn double_map_key_is_borsh_of_the_tuple() {
        const M: StorageDoubleMap<u32, [u8; 20], u64> = StorageDoubleMap::new("cgmp", "channels");
        let tuple = borsh::to_vec(&(7u32, [9u8; 20])).unwrap();
        assert_eq!(M.key(&7, &[9; 20]), storage_key("cgmp", "channels", &tuple));
    }

    #[test]
    fn n_map_keys_are_borsh_of_the_tuple() {
        const N: StorageNMap<(u32, [u8; 20], u64), u128> = StorageNMap::new("assets", "approvals");
        const D: StorageDoubleMap<u32, [u8; 20], u128> = StorageDoubleMap::new("assets", "pairs");
        const N2: StorageNMap<(u32, [u8; 20]), u128> = StorageNMap::new("assets", "pairs");
        let k = (7u32, [9u8; 20], 3u64);
        assert_eq!(N.key(&k), storage_key("assets", "approvals", &borsh::to_vec(&k).unwrap()));
        assert_eq!(N2.key(&(7, [9; 20])), D.key(&7, &[9; 20]));

        let mut s = MemoryStorage::default();
        N.insert(&mut s, &k, &10).unwrap();
        N.mutate(&mut s, &(7, [9; 20], 4), |v| *v += 5).unwrap();
        assert_eq!(N.get(&mut s, &k).unwrap(), Some(10));
        assert_eq!(N.get_or_default(&mut s, &(7, [9; 20], 4)).unwrap(), 5);
        assert_eq!(N.take(&mut s, &k).unwrap(), Some(10));
        assert!(!N.contains_key(&mut s, &k));
        N.remove(&mut s, &(7, [9; 20], 4));
        assert_eq!(N.get(&mut s, &(7, [9; 20], 4)).unwrap(), None);
    }

    #[test]
    fn value_roundtrip_mutate_take() {
        const N: StorageValue<u64> = StorageValue::new("system", "number");
        let mut s = MemoryStorage::default();
        assert_eq!(N.get(&mut s).unwrap(), None);
        assert_eq!(
            N.mutate(&mut s, |n| {
                *n += 3;
                *n
            })
            .unwrap(),
            3
        );
        assert!(N.exists(&mut s));
        assert_eq!(N.take(&mut s).unwrap(), Some(3));
        assert!(!N.exists(&mut s));
    }

    #[test]
    fn map_entries_are_independent() {
        const M: StorageMap<u32, u128> = StorageMap::new("balances", "accounts");
        let mut s = MemoryStorage::default();
        M.insert(&mut s, &1, &10).unwrap();
        M.mutate(&mut s, &2, |v| *v += 5).unwrap();
        assert_eq!(M.get(&mut s, &1).unwrap(), Some(10));
        assert_eq!(M.get_or_default(&mut s, &2).unwrap(), 5);
        assert_eq!(M.take(&mut s, &1).unwrap(), Some(10));
        assert!(!M.contains_key(&mut s, &1));
    }

    #[test]
    fn corrupt_value_is_an_error() {
        const M: StorageMap<u32, u128> = StorageMap::new("balances", "accounts");
        let mut s = MemoryStorage::default();
        s.set(&M.key(&1), alloc::vec![1, 2, 3]);
        assert_eq!(M.get(&mut s, &1), Err(StorageError::Corrupt));
    }

    #[test]
    fn oversized_value_is_refused() {
        const V: StorageValue<Vec<u8>> = StorageValue::new("m", "big");
        let mut s = MemoryStorage::default();
        assert_eq!(V.put(&mut s, &alloc::vec![0; MAX_VALUE_LEN]), Err(StorageError::ValueTooLarge));
        assert!(!V.exists(&mut s));
    }
}
