//! `tog-runtime-core`: the `no_std` framework an AppChain runtime is built on (TOG-SPEC-0007).
//!
//! A runtime is one deterministic Wasm blob (0007 §3). This crate holds what every runtime and
//! every standard module shares:
//!
//! - [`abi`]: the versioned names of the runtime's exports and the host's imports (§3.1, §3.2, §12);
//! - [`storage`]: the state key layout, identical to the Hub's (§5, TOG-SPEC-0002 §7.1), and
//!   typed storage items over any [`storage::Storage`] backend;
//! - [`bounded`]: bounded collections, so one call can't produce an unbounded PoV (§5);
//! - [`weight`]: the two-dimensional block weight and its default limits (§6);
//! - [`dispatch`]: origins and dispatch results (§4.2);
//! - [`env`]: the host side a runtime runs against (§3.2);
//! - [`block`]: header, block, inherents, PoV, witness and validation result (§3.4);
//! - [`tx`]: signed transactions and their signature check (§4.3, §4.5);
//! - [`verification`]: the `VerificationModule` trait of a chain's verification blob (§7.2);
//! - [`hash`]: domain-separated hashing and the lane tree (TOG-SPEC-0000 §13.1, 0002 §3.1);
//! - [`metadata`]: what a module tells clients about its calls, storage, events and errors;
//! - [`memory`]: an in-memory backend that records the storage witness, for tests and for
//!   building a PoV.
//!
//! It compiles without `std` (the `std` feature is on by default for native builds and tests).
//! Nothing here reads a clock, randomness or the network: those only reach a runtime through the
//! Hub context of the host ABI.
//!
//! This is unaudited code: 0007 §11 requires an audit of the runtime core before mainnet.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod abi;
pub mod block;
pub mod bounded;
pub mod dispatch;
pub mod env;
pub mod hash;
pub mod memory;
pub mod metadata;
pub mod storage;
pub mod tx;
pub mod verification;
pub mod weight;

pub use bounded::BoundedVec;
pub use dispatch::{DispatchError, DispatchResult, ModuleError, Origin};
pub use storage::{storage_key, Storage, StorageDoubleMap, StorageError, StorageMap, StorageNMap, StorageValue};
pub use weight::Weight;

pub use tog_primitives::{Address, Amount, ChainId, Hash32, HubHeight};

/// 20-byte account address, the same on the Hub and on every AppChain (0007 §4.5, 0000 §13.2).
pub type AccountId = Address;

/// Amount of atto-TOG (or of a chain's own token): 10^18 per whole unit.
pub type Balance = Amount;

/// Height of a block of this AppChain.
pub type BlockNumber = u64;
