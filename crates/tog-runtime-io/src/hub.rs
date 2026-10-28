//! Chain and Hub context (§3.2): the chain's identity, the relay parent and proven reads of Hub
//! state. The only sources of time and randomness a runtime has: BFT time and `HubBeacon` are Hub
//! state (`system.last_block`) read through [`read`].

use alloc::vec::Vec;

use tog_runtime_core::{ChainId, Hash32, HubHeight};

use crate::{ffi, read_var};

/// The executing chain's `ChainId` and the Hub's `network_id`, fixed for the chain's life.
pub fn chain_context() -> (ChainId, u32) {
    let b = ffi::context();
    let word = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    (ChainId(word(0)), word(4))
}

/// The chain's replay domain, `(network_id << 32) | ChainId` (TOG-SPEC-0000 §13.2), which its
/// transactions carry as `chain_id`.
pub fn replay_domain() -> u64 {
    let (chain, network) = chain_context();
    (u64::from(network) << 32) | u64::from(chain.0)
}

/// Height and state root of the Hub block this block builds on.
pub fn relay_parent() -> (HubHeight, Hash32) {
    let b = ffi::relay_parent();
    let mut h = [0u8; 8];
    h.copy_from_slice(&b[..8]);
    let mut root = [0u8; 32];
    root.copy_from_slice(&b[8..]);
    (u64::from_le_bytes(h), root)
}

/// The value of Hub state key `key` at the relay parent, proven by the host; `None` if absent.
pub fn read(key: &[u8]) -> Option<Vec<u8>> {
    read_var(256, |buf| ffi::hub_read(key, buf))
}
