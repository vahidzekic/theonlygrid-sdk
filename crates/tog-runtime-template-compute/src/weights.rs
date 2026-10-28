//! Benchmarked weights of the template's calls (TOG-SPEC-0007 §6), written by
//! `tog-collator bench`; don't edit by hand. `ref_time` is the fuel the call adds to a block at
//! one nanosecond per unit, plus 10%; `proof_size` is the witness it adds, doubled for larger
//! trees (see `tog_collator_node::bench`).

use tog_runtime_core::Weight;

/// Picoseconds of `ref_time` per byte of a transaction or inbox entry, besides its byte of `proof_size`.
pub const BYTE_REF_TIME: u64 = 88_747;

/// Every transaction besides its call: decoding, signature, fee, nonce, outcome.
pub const TX_BASE: Weight = Weight::from_parts(656_000_000, 5_312);

/// Every inbox entry besides its bytes and its handler's limit: the worse of an expired `Call` answered with a `Timeout` `Ack` and a `Timeout` `Ack` that settles a sent call.
pub const INBOX_ENTRY: Weight = Weight::from_parts(937_000_000, 10_688);

/// `balances.transfer` to a new account.
pub const TRANSFER: Weight = Weight::from_parts(398_000_000, 2_368);

/// A `sudo` call itself (`set_key`, `remove_key`, `call` without its inner call).
pub const SUDO_CALL: Weight = Weight::from_parts(177_000_000, 1_728);

/// `system.authorize_upgrade`.
pub const UPGRADE: Weight = Weight::from_parts(26_000_000, 0);

/// `collator_selection.set_authorities` with `MAX_AUTHORITIES` accounts.
pub const SET_AUTHORITIES: Weight = Weight::from_parts(148_000_000, 0);

/// `compute.request` of a job whose transaction is `MAX_JOB_TX_BYTES`.
pub const COMPUTE_REQUEST: Weight = Weight::from_parts(7_848_000_000, 10_368);

/// `compute.take_result` of the largest result a job can have.
pub const COMPUTE_TAKE_RESULT: Weight = Weight::from_parts(1_425_000_000, 210_944);

/// `model_registry.register` of the largest spec.
pub const MODEL_REGISTRY_REGISTER: Weight = Weight::from_parts(1_745_000_000, 2_112);

/// `model_registry.publish` of a model with the largest spec and the largest pending archive.
pub const MODEL_REGISTRY_PUBLISH: Weight = Weight::from_parts(1_018_000_000, 132_736);

/// `model_registry.fine_tune` of a model with the largest spec; the `compute.request` it makes included.
pub const MODEL_REGISTRY_FINE_TUNE: Weight = Weight::from_parts(8_155_000_000, 144_640);
