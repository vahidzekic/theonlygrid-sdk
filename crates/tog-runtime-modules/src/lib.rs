//! Standard modules of an AppChain runtime (TOG-SPEC-0007 §7).
//!
//! Each module is plain functions over any [`Storage`](tog_runtime_core::Storage) backend, so the
//! same code runs in the Wasm runtime (through the host ABI), in the collator and in native tests:
//!
//! - [`system`]: account nonces and the block number;
//! - [`assets`]: optional fungible assets besides $TOG, ERC-20 style;
//! - [`balances`]: $TOG accounts, with the `AccountData` layout the Hub reads for exit claims
//!   (§8.4);
//! - [`cgmp`]: both ends of channels (§3.4), $TOG to and from the Hub, and the refunds of what the
//!   Hub refuses (§7.1);
//! - [`compute`]: jobs on the Hub compute market and their results (§7.1);
//! - [`collator_selection`]: which collator authors a block (`Aura`);
//! - [`transaction_payment`]: fees of signed transactions (§4.3);
//! - [`sudo`]: an optional key with the `Root` origin (§7.5);
//! - [`governance`]: an optional council with the `Root` origin (§7, §7.5);
//! - [`verify`]: the chain's mirror of its verification modules bound on the Hub (§7.2);
//! - [`storage_deposit`]: per-byte deposits for the state a call adds (§5);
//! - [`executive`]: the runtime's entry points over these modules, for a chain's own calls (§3.1).
//!
//! A chain's own modules are written with [`tog_module`] (§4.1), which generates their storage
//! layout, dispatch, events, errors, weights and metadata.
//!
//! This is unaudited code: 0007 §11
//! requires an audit of the standard modules before mainnet.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
// So the code `#[tog_module]` generates names this crate the same way inside it as outside.
extern crate self as tog_runtime_modules;

pub use tog_runtime_macros::tog_module;

/// What `#[tog_module]`'s generated code names; not an API.
#[doc(hidden)]
pub mod __private {
    pub extern crate alloc;
    pub use borsh;
    pub use tog_runtime_core;
    pub use tog_types::cgmp::WorkerSlashed;
}

pub mod assets;
pub mod balances;
pub mod cgmp;
pub mod collator_selection;
pub mod compute;
pub mod executive;
pub mod governance;
pub mod remark;
pub mod storage_deposit;
pub mod sudo;
pub mod system;
pub mod transaction_payment;
pub mod verify;
