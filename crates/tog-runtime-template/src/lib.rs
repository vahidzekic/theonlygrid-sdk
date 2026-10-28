//! The AppChain SDK template runtime (TOG-SPEC-0007 §7): what a new chain starts from. It runs
//! the standard modules through [`executive`], with the chain's calls in this order:
//!
//! | index | module               | calls                                                    |
//! |-------|----------------------|----------------------------------------------------------|
//! | 0     | `balances`           | 0 `transfer { to, amount }`                              |
//! | 1     | `sudo`               | 0 `call(inner)`, 1 `set_key(new)`, 2 `remove_key()`      |
//! | 2     | `system`             | 0 `authorize_upgrade(code_hash)` (`Root`)                |
//! | 3     | `collator_selection` | 0 `set_authorities(set)` (`Root`)                        |
//! | 4     | `compute`            | 0 `request { spec, fee, timeout }` (signed)              |
//! | 5     | `cgmp`               | 0 `withdraw { to, amount, fee, timeout }`, 1 `send { dest, module, call, weight_limit, fee, timeout }`, 2 `prune { dest, nonce }` (signed) |
//! | 6     | `verify`             | 0 `bind { id, code_hash }` (`Root`)                      |
//! | 7     | `assets`             | 0 `create`, 1 `mint`, 2 `burn`, 3 `transfer`, 4 `approve`, 5 `transfer_from`, 6 `set_owner` (signed) |
//! | 8     | `remark`             | 0 `remark(data)` (signed)                                |
//!
//! `compute.request` asks the Hub compute market for a job paid from the signer's balance; its
//! `ComputeRequest` leaves in the block's outbox and the job's result comes back as a `compute`
//! event (`tog_runtime_modules::compute::Event`); `tog_v1_query("compute_job", job_id)` reads an
//! open job.
//!
//! A `balances.transfer` that creates the recipient's account reserves the storage deposit for it
//! from the sender (`StorageDepositPerByte` = 10¹⁴ atto-TOG per byte, §5), returned to the sender
//! when that account is emptied and removed.
//!
//! `cgmp.withdraw` moves the signer's $TOG to a Hub account in a `TransferTog`; `cgmp.send` sends
//! a `Call` to another AppChain's module for the signer; `cgmp.prune` deletes the record of a sent
//! `Call` that ran (§4.6, §7.1).
//!
//! `sudo` is optional (§7.5): a chain without it drops module 1 and sets no `root_key`. Here the
//! genesis [`GenesisConfig::root_key`] is its only `Root` source, as the templates ship it.
//!
//! `assets` (written with `#[tog_module]`) holds fungible assets besides $TOG; it starts with none.
//!
//! `remark` records a note as an event. It is also the module other AppChains reach: a CGMP `Call`
//! to `tog/remark` runs `remark` here for the sending chain (§4.6), and no other module takes one.
//!
//! Call weights are benchmarks (§6), in [`weights`]: `tog-collator bench` measures them on this
//! runtime's Wasm and writes that file, the `#[benchmark]`s of its `#[tog_module]` modules
//! ([`Runtime::benchmarks`]) included. A chain that changes a call runs it again.

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use tog_runtime_core::metadata::RuntimeMetadata;
use tog_runtime_core::{AccountId, Balance, ChainId, DispatchError, Hash32, ModuleError, Origin, Weight};
use tog_runtime_io::crypto::HostCheck;
use tog_runtime_io::{export_entry, HostEnv};
use tog_runtime_modules::executive::{self, Call, Context, Runtime, Scoped};
use tog_runtime_modules::{assets, balances, cgmp, collator_selection, compute, remark, sudo, system, verify};
use tog_types::cgmp::CgmpOrigin;
use tog_types::job::ModuleId;

pub use tog_runtime_core::env::Env;

/// Module index of `balances`.
pub const BALANCES: u8 = 0;
/// Module index of `sudo`.
pub const SUDO: u8 = 1;
/// Module index of `system`.
pub const SYSTEM: u8 = 2;
/// Module index of `collator_selection`.
pub const COLLATOR_SELECTION: u8 = 3;
/// Module index of `compute`.
pub const COMPUTE: u8 = 4;
/// Module index of `cgmp`.
pub const CGMP: u8 = 5;
/// Module index of `verify`.
pub const VERIFY: u8 = 6;
/// Module index of `assets`.
pub const ASSETS: u8 = 7;
/// Module index of `remark`.
pub const REMARK: u8 = 8;

/// `tog_v1_genesis`'s config, `borsh(GenesisConfig)`.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GenesisConfig {
    /// Initial free balances.
    pub balances: Vec<(AccountId, Balance)>,
    /// The Aura set, strictly ascending.
    pub authorities: Vec<AccountId>,
    /// `sudo.key`; `None` starts the chain without a `Root` source.
    pub root_key: Option<AccountId>,
}

pub mod weights;

use weights::{
    ASSETS_APPROVE, ASSETS_BURN, ASSETS_CREATE, ASSETS_MINT, ASSETS_SET_OWNER, ASSETS_TRANSFER, ASSETS_TRANSFER_FROM,
    CGMP_PRUNE, CGMP_SEND, CGMP_WITHDRAW, COMPUTE_REQUEST, COMPUTE_TAKE_RESULT, REMARK_REMARK, SET_AUTHORITIES,
    SUDO_CALL, TRANSFER, UPGRADE, VERIFY_BIND,
};

/// The template runtime.
pub struct Template;

fn decode<T: BorshDeserialize>(b: &[u8]) -> Result<T, DispatchError> {
    borsh::from_slice(b).map_err(|_| DispatchError::Other("call arguments"))
}

impl Runtime for Template {
    const NAME: &'static str = "tog-runtime-template";
    const SPEC_VERSION: u32 = 1;
    const TX_BASE_WEIGHT: Weight = weights::TX_BASE;
    const INBOX_ENTRY_WEIGHT: Weight = weights::INBOX_ENTRY;
    const BYTE_REF_TIME: u64 = weights::BYTE_REF_TIME;

    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
        Some(match (module, call) {
            (BALANCES, balances::TRANSFER) => ("balances", "transfer"),
            (SUDO, sudo::CALL) => ("sudo", "call"),
            (SUDO, sudo::SET_KEY) => ("sudo", "set_key"),
            (SUDO, sudo::REMOVE_KEY) => ("sudo", "remove_key"),
            (SYSTEM, system::AUTHORIZE_UPGRADE) => ("system", "authorize_upgrade"),
            (COLLATOR_SELECTION, collator_selection::SET_AUTHORITIES) => ("collator_selection", "set_authorities"),
            (COMPUTE, compute::REQUEST) => ("compute", "request"),
            (COMPUTE, compute::TAKE_RESULT) => ("compute", "take_result"),
            (CGMP, cgmp::WITHDRAW) => ("cgmp", "withdraw"),
            (CGMP, cgmp::SEND) => ("cgmp", "send"),
            (CGMP, cgmp::PRUNE) => ("cgmp", "prune"),
            (VERIFY, verify::BIND) => ("verify", "bind"),
            (ASSETS, call) => (assets::MODULE, assets::call_name(call)?),
            (REMARK, call) => (remark::MODULE, remark::call_name(call)?),
            _ => return None,
        })
    }

    fn call_weight(call: &Call) -> Option<Weight> {
        weight_within(call, sudo::MAX_NESTING)
    }

    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError> {
        let w = Self::call_weight(&call).ok_or(DispatchError::Other("unknown call"))?;
        match (call.0, call.1) {
            (BALANCES, balances::TRANSFER) => {
                let c: balances::Call = decode(&call.2)?;
                let balances::Call::Transfer { to, amount } = c.clone();
                let from = match origin {
                    Origin::Signed(a) => Some(a),
                    _ => None,
                };
                balances::dispatch(e, BALANCES, origin, c)?;
                if let Some(from) = from {
                    e.deposit_event("balances", &balances::Event::Transfer { from, to, amount });
                }
            }
            (SUDO, sudo::CALL) => {
                // The inner call's own result goes to the block's events; it fails alone.
                let inner = sudo::call(e, origin, decode(&call.2)?, |s, o, inner| {
                    s.nested(|s| Self::dispatch(s, cx, o, inner)).map(|_| ())
                })?;
                e.deposit_event("sudo", &sudo::Event::Sudid(inner.map_err(Into::into)));
            }
            (SUDO, sudo::SET_KEY) => sudo::set_key(e, origin, decode(&call.2)?)?,
            (SUDO, sudo::REMOVE_KEY) => sudo::remove_key(e, origin)?,
            (SYSTEM, system::AUTHORIZE_UPGRADE) => system::authorize_upgrade(e, &origin, decode::<Hash32>(&call.2)?)
                .map_err(|err| match err {
                    system::UpgradeError::BadOrigin => DispatchError::BadOrigin,
                    system::UpgradeError::AlreadyAuthorized => DispatchError::Module { module: SYSTEM, error: 1 },
                    system::UpgradeError::Storage => DispatchError::Other("storage"),
                })?,
            (COLLATOR_SELECTION, collator_selection::SET_AUTHORITIES) => {
                collator_selection::set_authorities(e, &origin, decode(&call.2)?).map_err(|err| match err {
                    collator_selection::SetError::BadOrigin => DispatchError::BadOrigin,
                    collator_selection::SetError::Size => {
                        DispatchError::Module { module: COLLATOR_SELECTION, error: 1 }
                    }
                    collator_selection::SetError::Unsorted => {
                        DispatchError::Module { module: COLLATOR_SELECTION, error: 2 }
                    }
                    collator_selection::SetError::Storage => DispatchError::Other("storage"),
                })?
            }
            (COMPUTE, compute::REQUEST) => {
                compute::dispatch(e, cx, COMPUTE, origin, decode(&call.2)?, Self::STORAGE_DEPOSIT_PER_BYTE)?;
            }
            (COMPUTE, compute::TAKE_RESULT) => compute::dispatch_take_result(e, COMPUTE, origin, decode(&call.2)?)?,
            (CGMP, index) => {
                let c: cgmp::Call = decode(&call.2)?;
                let expected = match c {
                    cgmp::Call::Withdraw { .. } => cgmp::WITHDRAW,
                    cgmp::Call::Send { .. } => cgmp::SEND,
                    cgmp::Call::Prune { .. } => cgmp::PRUNE,
                };
                if index != expected {
                    return Err(DispatchError::Other("call arguments"));
                }
                cgmp::dispatch(e, cx, CGMP, origin, c, cgmp::CallDeposits::default())?;
            }
            (VERIFY, verify::BIND) => verify::dispatch(e, VERIFY, origin, decode(&call.2)?)?,
            (ASSETS, index) => {
                assets::dispatch(e, cx, ASSETS, origin, index, &call.2)?;
            }
            (REMARK, index) => {
                remark::dispatch(e, cx, REMARK, origin, index, &call.2)?;
            }
            _ => return Err(DispatchError::Other("unknown call")),
        }
        Ok(w)
    }

    fn metadata() -> Vec<u8> {
        let modules = alloc::vec![
            (BALANCES, balances::metadata()),
            (SUDO, sudo::metadata()),
            (SYSTEM, system::metadata()),
            (COLLATOR_SELECTION, collator_selection::metadata()),
            (COMPUTE, compute::metadata()),
            (CGMP, cgmp::metadata()),
            (VERIFY, verify::metadata()),
            (ASSETS, assets::metadata()),
            (REMARK, remark::metadata()),
        ];
        borsh::to_vec(&RuntimeMetadata::new(Self::NAME, Self::SPEC_VERSION, modules)).expect("metadata encodes")
    }

    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        let c: GenesisConfig = borsh::from_slice(config).expect("genesis config decodes");
        for (who, amount) in &c.balances {
            balances::deposit(e, who, *amount).expect("genesis balance");
        }
        collator_selection::genesis(e, c.authorities).expect("genesis authorities");
        sudo::genesis(e, c.root_key).expect("genesis sudo key");
    }

    fn benchmarks() -> Vec<(u8, u8, bool)> {
        let assets = assets::BENCHMARKS.iter().map(|&(call, root)| (ASSETS, call, root));
        assets.chain(remark::BENCHMARKS.iter().map(|&(call, root)| (REMARK, call, root))).collect()
    }

    fn bench_setup<E: Env>(
        e: &mut Scoped<'_, E>,
        module: u8,
        call: u8,
        caller: AccountId,
    ) -> Option<Result<Vec<u8>, DispatchError>> {
        match module {
            ASSETS => assets::bench_setup(e, ASSETS, call, caller),
            REMARK => remark::bench_setup(e, REMARK, call, caller),
            _ => None,
        }
    }

    fn cgmp_call_limit(module: ModuleId, call: &[u8]) -> Option<Weight> {
        (module == remark::CGMP_NAME && remark::accepts(call)).then_some(REMARK_REMARK)
    }

    fn cgmp_call<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        source: ChainId,
        origin: &CgmpOrigin,
        module: ModuleId,
        call: &[u8],
        _weight_limit: Weight,
    ) -> Option<Result<Weight, DispatchError>> {
        (module == remark::CGMP_NAME).then(|| {
            remark::received(e, source, origin, call).map(|()| REMARK_REMARK).map_err(|err| err.into_dispatch(REMARK))
        })
    }

    fn as_root(call: Call) -> Option<Call> {
        Some((SUDO, sudo::CALL, borsh::to_vec(&call).expect("in-memory borsh")))
    }
}

/// `tog_v1_version`.
pub fn version(_: &[u8]) -> Vec<u8> {
    executive::version::<Template>()
}

/// `tog_v1_query`.
pub fn query(input: &[u8]) -> Vec<u8> {
    executive::query::<Template, _>(&mut HostEnv, input)
}

/// `tog_v1_genesis`.
pub fn genesis(input: &[u8]) -> Vec<u8> {
    executive::genesis::<Template, _>(&mut HostEnv, input)
}

/// `tog_v1_build_block`.
pub fn build_block(input: &[u8]) -> Vec<u8> {
    executive::build_block::<Template, _>(&mut HostEnv, &HostCheck, input)
}

/// `tog_v1_execute_block`.
pub fn execute_block(input: &[u8]) -> Vec<u8> {
    executive::execute_block::<Template, _>(&mut HostEnv, &HostCheck, input)
}

/// `tog_v1_validate_block`.
pub fn validate_block(input: &[u8]) -> Vec<u8> {
    executive::validate_block::<Template, _>(&mut HostEnv, &HostCheck, input)
}

/// `tog_v1_validate_tx`.
pub fn validate_tx(input: &[u8]) -> Vec<u8> {
    executive::validate_tx::<Template, _>(&mut HostEnv, &HostCheck, input)
}

export_entry!(tog_v1_version, version);
export_entry!(tog_v1_query, query);
export_entry!(tog_v1_genesis, genesis);
export_entry!(tog_v1_build_block, build_block);
export_entry!(tog_v1_execute_block, execute_block);
export_entry!(tog_v1_validate_block, validate_block);
export_entry!(tog_v1_validate_tx, validate_tx);

/// The weight of `call`, nesting at most `depth` more `sudo.call`s; `None` for an unknown call
/// or one nested deeper (R-1).
fn weight_within(call: &Call, depth: u32) -> Option<Weight> {
    match (call.0, call.1) {
        (BALANCES, balances::TRANSFER) => Some(TRANSFER),
        (SUDO, sudo::CALL) => {
            let depth = depth.checked_sub(1)?;
            let inner: Call = borsh::from_slice(&call.2).ok()?;
            weight_within(&inner, depth).map(|w| w.saturating_add(SUDO_CALL))
        }
        (SUDO, sudo::SET_KEY | sudo::REMOVE_KEY) => Some(SUDO_CALL),
        (SYSTEM, system::AUTHORIZE_UPGRADE) => Some(UPGRADE),
        (COLLATOR_SELECTION, collator_selection::SET_AUTHORITIES) => Some(SET_AUTHORITIES),
        (COMPUTE, compute::REQUEST) => Some(COMPUTE_REQUEST),
        (COMPUTE, compute::TAKE_RESULT) => Some(COMPUTE_TAKE_RESULT),
        (CGMP, cgmp::WITHDRAW) => Some(CGMP_WITHDRAW),
        (CGMP, cgmp::SEND) => Some(CGMP_SEND),
        (CGMP, cgmp::PRUNE) => Some(CGMP_PRUNE),
        (VERIFY, verify::BIND) => Some(VERIFY_BIND),
        (ASSETS, index) => {
            // The module's own weights are SDK defaults; these are measured on this runtime.
            assets::call_weight(index, &call.2)?;
            Some(match index {
                0 => ASSETS_CREATE,
                1 => ASSETS_MINT,
                2 => ASSETS_BURN,
                3 => ASSETS_TRANSFER,
                4 => ASSETS_APPROVE,
                5 => ASSETS_TRANSFER_FROM,
                6 => ASSETS_SET_OWNER,
                _ => return None,
            })
        }
        (REMARK, index) => {
            remark::call_weight(index, &call.2)?;
            (index == remark::REMARK).then_some(REMARK_REMARK)
        }
        _ => None,
    }
}
