//! [`Storage`] over the host's `storage_*` functions.

use alloc::vec::Vec;

use tog_runtime_core::env::Env;
use tog_runtime_core::storage::{Storage, StorageKey};
use tog_runtime_core::{ChainId, Hash32, HubHeight};

use crate::{ffi, read_var};

/// The chain state as the host serves it: from the database in collators, from the PoV witness
/// on validators. Zero-sized; every call goes to the host.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostStorage;

impl HostStorage {
    /// The state root with every change so far applied.
    pub fn root(&self) -> Hash32 {
        ffi::root()
    }
}

impl Storage for HostStorage {
    fn get(&mut self, key: &StorageKey) -> Option<Vec<u8>> {
        read_var(256, |buf| ffi::get(key, buf))
    }

    fn set(&mut self, key: &StorageKey, value: Vec<u8>) {
        ffi::set(key, &value)
    }

    fn clear(&mut self, key: &StorageKey) {
        ffi::clear(key)
    }

    fn exists(&mut self, key: &StorageKey) -> bool {
        ffi::exists(key)
    }

    fn next_key(&mut self, key: &StorageKey) -> Option<StorageKey> {
        ffi::next_key(key)
    }
}

/// [`HostStorage`] with the rest of the host: the [`Env`] a runtime's executive runs against.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostEnv;

impl Storage for HostEnv {
    fn get(&mut self, key: &StorageKey) -> Option<Vec<u8>> {
        HostStorage.get(key)
    }
    fn set(&mut self, key: &StorageKey, value: Vec<u8>) {
        HostStorage.set(key, value)
    }
    fn clear(&mut self, key: &StorageKey) {
        HostStorage.clear(key)
    }
    fn exists(&mut self, key: &StorageKey) -> bool {
        HostStorage.exists(key)
    }
    fn next_key(&mut self, key: &StorageKey) -> Option<StorageKey> {
        HostStorage.next_key(key)
    }
}

impl Env for HostEnv {
    fn chain_context(&mut self) -> (ChainId, u32) {
        crate::hub::chain_context()
    }
    fn relay_parent(&mut self) -> (HubHeight, Hash32) {
        crate::hub::relay_parent()
    }
    fn hub_read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        crate::hub::read(key)
    }
    fn inbox_next(&mut self) -> Option<Vec<u8>> {
        crate::cgmp::inbox_next()
    }
    fn outbox_push(&mut self, msg: &[u8]) {
        crate::cgmp::outbox_push(msg)
    }
    fn storage_root(&mut self) -> Hash32 {
        ffi::root()
    }
}
