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
pub const TRANSFER: Weight = Weight::from_parts(397_000_000, 2_368);

/// A `sudo` call itself (`set_key`, `remove_key`, `call` without its inner call).
pub const SUDO_CALL: Weight = Weight::from_parts(177_000_000, 1_728);

/// `system.authorize_upgrade`.
pub const UPGRADE: Weight = Weight::from_parts(26_000_000, 0);

/// `collator_selection.set_authorities` with `MAX_AUTHORITIES` accounts.
pub const SET_AUTHORITIES: Weight = Weight::from_parts(148_000_000, 0);

/// `compute.request` of a job whose transaction is `MAX_JOB_TX_BYTES`.
pub const COMPUTE_REQUEST: Weight = Weight::from_parts(7_849_000_000, 10_368);

/// `compute.take_result` of the largest result a job can have.
pub const COMPUTE_TAKE_RESULT: Weight = Weight::from_parts(1_425_000_000, 210_944);

/// `cgmp.withdraw` of $TOG to the Hub.
pub const CGMP_WITHDRAW: Weight = Weight::from_parts(694_000_000, 3_904);

/// `cgmp.send` of a `Call` that opens a channel to an AppChain with a full inbound list.
pub const CGMP_SEND: Weight = Weight::from_parts(933_000_000, 11_520);

/// `cgmp.prune` of a sent `Call`'s record.
pub const CGMP_PRUNE: Weight = Weight::from_parts(538_000_000, 9_984);

/// `verify.bind` of the last module a chain may have.
pub const VERIFY_BIND: Weight = Weight::from_parts(31_000_000, 2_624);

/// `reserved_compute.bind` of a reservation record of `MAX_RESERVATION_BYTES`.
pub const RESERVED_COMPUTE_BIND: Weight = Weight::from_parts(162_000_000, 11_776);

/// `reserved_compute.unbind`.
pub const RESERVED_COMPUTE_UNBIND: Weight = Weight::from_parts(12_000_000, 2_688);

/// `reserved_compute.run` of a job whose transaction is `MAX_JOB_TX_BYTES`; the `compute.request` it makes included.
pub const RESERVED_COMPUTE_RUN: Weight = Weight::from_parts(8_688_000_000, 14_720);

/// `assets.create`, its module's `#[benchmark]`.
pub const ASSETS_CREATE: Weight = Weight::from_parts(351_000_000, 2_176);

/// `assets.mint`, its module's `#[benchmark]`.
pub const ASSETS_MINT: Weight = Weight::from_parts(509_000_000, 3_840);

/// `assets.burn`, its module's `#[benchmark]`.
pub const ASSETS_BURN: Weight = Weight::from_parts(475_000_000, 6_784);

/// `assets.transfer`, its module's `#[benchmark]`.
pub const ASSETS_TRANSFER: Weight = Weight::from_parts(673_000_000, 9_600);

/// `assets.approve`, its module's `#[benchmark]`.
pub const ASSETS_APPROVE: Weight = Weight::from_parts(361_000_000, 3_648);

/// `assets.transfer_from`, its module's `#[benchmark]`.
pub const ASSETS_TRANSFER_FROM: Weight = Weight::from_parts(978_000_000, 14_464);

/// `assets.set_owner`, its module's `#[benchmark]`.
pub const ASSETS_SET_OWNER: Weight = Weight::from_parts(180_000_000, 1_408);

/// `remark.remark`, its module's `#[benchmark]`.
pub const REMARK_REMARK: Weight = Weight::from_parts(68_000_000, 0);
