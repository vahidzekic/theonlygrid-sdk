//! The AppChain SDK storage template runtime (TOG-SPEC-0007 §7.1): the template plus
//! [`file_registry`], a chain module that names files kept in Hub storage deals (TOG-SPEC-0004).
//! It runs the standard modules through [`executive`], with the chain's calls in this order:
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
//! | 8     | `file_registry`      | 0 `register(name, file, offset, path)`, 1 `refresh(name)`, 2 `remove(name)` (signed) |
//! | 9     | `remark`             | 0 `remark(data)` (signed)                                |
//!
//! `file_registry.register` names a payload that a Hub storage deal holds: the chain reads the
//! deal at its relay parent and takes the file only while the deal is held and the payload is in
//! its set. Whoever opened the deal pays the holders on the Hub; the chain keeps the name, its
//! storage deposit paid by the registrant. `refresh` follows the deal as it is renewed or ends.
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
/// Module index of `file_registry`.
pub const FILE_REGISTRY: u8 = 8;
/// Module index of `remark`.
pub const REMARK: u8 = 9;

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

/// A chain's own module (§4.1, §13): names for files kept in Hub storage deals (TOG-SPEC-0004).
///
/// Anyone may register a free name for a payload that a deal holds. The chain reads the deal
/// (`storage.deals[id]`) at its relay parent, proven like every Hub read, and takes the file only
/// while the deal is held (`Active` or `Repairing`, ending at a height after the relay parent)
/// and the payload is a leaf of its set: the registrant gives the leaf's offset and its Merkle
/// path. The deal is whoever opened it on the Hub, paying its holders; the chain pays nothing,
/// and keeps only the name, whose storage deposit the registrant pays.
///
/// A deal may be renewed on the Hub (`RenewDeal`, by anyone) or end; `refresh`, also by anyone,
/// reads it again and either moves the file's end or, once the deal no longer holds it, drops
/// the name and returns its deposit to the registrant. The registrant may `remove` it at any
/// time. Readers fetch the payload from the deal's holders (`tog-cli`'s sender does).
#[tog_runtime_modules::tog_module]
pub mod file_registry {
    use alloc::string::String;

    use borsh::{BorshDeserialize, BorshSerialize};
    use tog_runtime_core::env::Env;
    use tog_runtime_core::{AccountId, HubHeight, Origin, Storage, StorageError, StorageMap};
    use tog_runtime_modules::executive::{Context, Scoped};
    use tog_runtime_modules::storage_deposit;
    use tog_types::job::{DealId, PayloadRef};
    use tog_types::state::items;
    use tog_types::storage::{verify_path, DealEnd, DealState, MerklePath, PayloadSetLeaf, StorageDeal};

    /// Longest name, in bytes.
    pub const MAX_NAME: usize = 64;
    /// Largest deal record the chain reads: its proof is in the call's weight, so a larger one
    /// (many holders or locators) can't name a file.
    pub const MAX_DEAL_BYTES: usize = 8_192;

    /// A named file.
    #[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    pub struct File {
        /// Who registered it, and paid its deposit.
        pub owner: AccountId,
        /// The payload and the deal that holds it.
        pub file: PayloadRef,
        /// The Hub height the deal ends at, as last read.
        pub end: HubHeight,
    }

    /// Each file by name.
    #[storage]
    pub type Files = StorageMap<String, File>;

    /// The module's events, `borsh` in the block's events under module `"file_registry"`.
    #[event]
    pub enum Event {
        /// `name` is `file`, held until Hub height `end`.
        Registered {
            /// The name.
            name: String,
            /// Its registrant.
            owner: AccountId,
            /// The payload and its deal.
            file: PayloadRef,
            /// The deal's end.
            end: HubHeight,
        },
        /// The deal behind `name` now ends at `end`.
        Refreshed {
            /// The name.
            name: String,
            /// The deal's end.
            end: HubHeight,
        },
        /// `name` is free again: its registrant removed it, or its deal no longer holds it.
        Removed {
            /// The name.
            name: String,
            /// Whether the deal ended (by `refresh`) rather than the registrant removing it.
            expired: bool,
        },
    }

    /// Why a call failed; its index is the module error index.
    #[error]
    pub enum Error {
        /// The call needs a signed origin.
        BadOrigin,
        /// The name is empty or longer than [`MAX_NAME`].
        BadName,
        /// The name is taken.
        Taken,
        /// No file has the name.
        Unknown,
        /// Only the registrant may remove it.
        NotOwner,
        /// The file names no deal, or the Hub has no such deal.
        NoDeal,
        /// The deal's record is over [`MAX_DEAL_BYTES`].
        DealTooLarge,
        /// The deal isn't held now: placing, released, closed, or past its end.
        NotHeld,
        /// The payload isn't the set's leaf at that offset and path.
        NotInDeal,
        /// Stored state doesn't decode.
        Storage(StorageError),
        /// The signer's free $TOG doesn't cover the storage deposit.
        DepositUnpaid,
        /// The leaf is in a lazy deal's set but isn't materialized: nobody holds its bytes.
        NotMaterialized,
        /// The commitment isn't a v1 one: version 1, `piece_log2` in `20..=22`.
        BadPayload,
    }

    impl From<storage_deposit::Error> for Error {
        fn from(e: storage_deposit::Error) -> Self {
            match e {
                storage_deposit::Error::InsufficientBalance => Error::DepositUnpaid,
                storage_deposit::Error::Storage => Error::Storage(StorageError::Corrupt),
            }
        }
    }

    fn signed(origin: Origin) -> Result<AccountId, Error> {
        match origin {
            Origin::Signed(who) => Ok(who),
            _ => Err(Error::BadOrigin),
        }
    }

    /// The file `name`, if any.
    pub fn file(s: &mut impl Storage, name: &String) -> Result<Option<File>, StorageError> {
        FILES.get(s, name)
    }

    /// Deal `id` at the relay parent, if the Hub has it and it fits [`MAX_DEAL_BYTES`].
    fn deal(e: &mut impl Env, id: DealId) -> Result<StorageDeal, Error> {
        let bytes = e.hub_read(&items::deal(&id)).ok_or(Error::NoDeal)?;
        if bytes.len() > MAX_DEAL_BYTES {
            return Err(Error::DealTooLarge);
        }
        borsh::from_slice(&bytes).map_err(|_| Error::Storage(StorageError::Corrupt))
    }

    /// The height `d` ends at, if it is held after `relay`: its holders keep the bytes.
    fn held_until(d: &StorageDeal, relay: HubHeight) -> Option<HubHeight> {
        let held = matches!(d.state, DealState::Active | DealState::Repairing { .. });
        match d.end {
            DealEnd::At(end) if held && end > relay => Some(end),
            _ => None,
        }
    }

    /// Whether leaf `i` of `d` has holders: every leaf, unless `d` is lazy (§4.8).
    fn materialized(d: &StorageDeal, i: u32) -> bool {
        d.materialized.is_empty() || d.materialized.get(i as usize / 8).is_some_and(|b| b >> (i % 8) & 1 == 1)
    }

    /// `register(name, file, offset, path)`: names `file`, whose deal must hold it now, as the
    /// leaf at `offset` with Merkle `path` in its set. A lazy deal must have materialized that
    /// leaf. The path proves the root and size only: `kind`, `oci_digest` and `encryption` are the
    /// registrant's claim, which readers check against the bytes they fetch.
    #[call(index = 0, weight = crate::weights::FILE_REGISTRY_REGISTER)]
    pub fn register<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        name: String,
        file: PayloadRef,
        offset: u64,
        path: MerklePath,
    ) -> Result<(), Error> {
        let owner = signed(origin)?;
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::BadName);
        }
        if FILES.contains_key(e, &name) {
            return Err(Error::Taken);
        }
        let d = deal(e, file.deal.ok_or(Error::NoDeal)?)?;
        let end = held_until(&d, cx.relay).ok_or(Error::NotHeld)?;
        let p = &file.payload;
        if p.version != 1 || !(20..=22).contains(&p.piece_log2) {
            return Err(Error::BadPayload);
        }
        let leaf = PayloadSetLeaf { root: p.root, offset, size: p.size };
        if !verify_path(&d.payloads, &leaf, &path) {
            return Err(Error::NotInDeal);
        }
        if !materialized(&d, path.index) {
            return Err(Error::NotMaterialized);
        }
        let f = File { owner, file: file.clone(), end };
        storage_deposit::insert(e, &FILES, &name, &f, &owner, cx.per_byte)?;
        Event::Registered { name, owner, file, end }.deposit(e);
        Ok(())
    }

    /// `refresh(name)`, by anyone: reads the file's deal again. Still held, the file takes its
    /// end; no longer held, the name is dropped and its deposit returns to the registrant. A file
    /// still held at the same end changes nothing. The leaf isn't checked again: a deal's set
    /// only grows, and a leaf the Hub materialized stays so (§4.8).
    #[call(index = 1, weight = crate::weights::FILE_REGISTRY_REFRESH)]
    pub fn refresh<E: Env>(e: &mut Scoped<'_, E>, cx: &Context, origin: Origin, name: String) -> Result<(), Error> {
        signed(origin)?;
        let mut f = FILES.get(e, &name)?.ok_or(Error::Unknown)?;
        let id = f.file.deal.ok_or(Error::NoDeal)?;
        // A deal the Hub dropped holds nothing.
        let held = match deal(e, id) {
            Ok(d) => held_until(&d, cx.relay),
            Err(Error::NoDeal) => None,
            Err(err) => return Err(err),
        };
        match held {
            Some(end) => {
                if end != f.end {
                    f.end = end;
                    FILES.insert(e, &name, &f)?;
                    Event::Refreshed { name, end }.deposit(e);
                }
            }
            None => {
                storage_deposit::remove(e, &FILES, &name)?;
                Event::Removed { name, expired: true }.deposit(e);
            }
        }
        Ok(())
    }

    /// `remove(name)`, by the registrant: frees the name and returns its deposit. The deal is the
    /// Hub's and stays as it is.
    #[call(index = 2, weight = crate::weights::FILE_REGISTRY_REMOVE)]
    pub fn remove<E: Env>(e: &mut Scoped<'_, E>, _cx: &Context, origin: Origin, name: String) -> Result<(), Error> {
        let who = signed(origin)?;
        let f = FILES.get(e, &name)?.ok_or(Error::Unknown)?;
        if f.owner != who {
            return Err(Error::NotOwner);
        }
        storage_deposit::remove(e, &FILES, &name)?;
        Event::Removed { name, expired: false }.deposit(e);
        Ok(())
    }
}

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
    const NAME: &'static str = "tog-runtime-template-storage";
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
            (FILE_REGISTRY, call) => (file_registry::MODULE, file_registry::call_name(call)?),
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
            (FILE_REGISTRY, index) => return file_registry::dispatch(e, cx, FILE_REGISTRY, origin, index, &call.2),
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
            (FILE_REGISTRY, file_registry::metadata()),
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
        (FILE_REGISTRY, index) => file_registry::call_weight(index, &call.2),
        (REMARK, index) => {
            remark::call_weight(index, &call.2)?;
            (index == remark::REMARK).then_some(REMARK_REMARK)
        }
        _ => None,
    }
}
