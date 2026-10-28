//! What a runtime reaches besides its storage (TOG-SPEC-0007 §3.2): the chain's identity, the Hub
//! relay parent, proven Hub reads, the CGMP queues and the state root. In a Wasm runtime it is the
//! host (`tog_runtime_io::HostEnv`); natively, tests supply their own.

use alloc::vec::Vec;

use crate::storage::Storage;
use crate::{ChainId, Hash32, HubHeight};

/// The host side of a runtime, over its storage.
pub trait Env: Storage {
    /// The executing chain's `ChainId` and the Hub's `network_id`.
    fn chain_context(&mut self) -> (ChainId, u32);
    /// Height and state root of the relay parent.
    fn relay_parent(&mut self) -> (HubHeight, Hash32);
    /// Hub state key `key` at the relay parent, proven; `None` if absent.
    fn hub_read(&mut self, key: &[u8]) -> Option<Vec<u8>>;
    /// The next inbox entry, `borsh((CgmpMessage, Option<Vec<Hash32>>))`; `None` when none is left.
    fn inbox_next(&mut self) -> Option<Vec<u8>>;
    /// Append a `borsh(CgmpMessage)` to the outbox.
    fn outbox_push(&mut self, msg: &[u8]);
    /// The state root with every change so far applied.
    fn storage_root(&mut self) -> Hash32;

    /// The chain's replay domain, `(network_id << 32) | ChainId` (TOG-SPEC-0000 §13.2).
    fn replay_domain(&mut self) -> u64 {
        let (chain, network) = self.chain_context();
        (u64::from(network) << 32) | u64::from(chain.0)
    }
}
