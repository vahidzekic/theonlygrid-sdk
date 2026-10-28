//! Consensus objects of the Hub `compute_market` that a worker reads and writes
//! (TOG-SPEC-0001 §3, TOG-SPEC-0003 §2).
//!
//! All types encode with Borsh. Field order and enum variant order are part of the
//! wire format: only append, never reorder.
//!
//! With the default `std` feature off the crate is `no_std` + `alloc`, so the
//! types and their verification also build for `wasm32-unknown-unknown`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[allow(unused_imports)]
pub(crate) mod prelude {
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
    pub use alloc::{format, vec};
}

pub mod admission;
pub mod appchain;
pub mod audit;
pub mod availability;
pub mod bisection;
pub mod bridge;
pub mod calibration;
pub mod cgmp;
pub mod channel;
pub mod checkpoint;
pub mod cipher;
pub mod consensus;
pub mod coretime;
pub mod dispute;
pub mod eip712;
pub mod eligibility;
pub mod enclave;
pub mod endpoint;
pub mod erasure;
pub mod events;
pub mod fault;
pub mod genesis;
pub mod hub_key;
pub mod ibe;
pub mod job;
pub mod metering;
pub mod p2p;
pub mod payload;
pub mod por;
pub mod probe;
pub mod receipt;
pub mod reservation;
pub mod rs;
pub mod signing;
pub mod sketch;
pub mod sortition;
pub mod staking;
pub mod state;
pub mod storage;
pub mod storage_worker;
pub mod timing;
pub mod tx;
pub mod verifier;
pub mod walk;
pub mod worker;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use job::*;
pub use tx::{Signature, SignedTx, TransferTx, TxBody};
