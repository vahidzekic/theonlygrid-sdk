//! `executive`: the runtime entry points built on the standard modules (TOG-SPEC-0007 §3.1, §3.4,
//! §4.3, §4.5, §4.6, §7.1).
//!
//! A chain describes its own calls with [`Runtime`]; the executive does the rest the same way for
//! every chain, so `build_block`, `execute_block` and `validate_block` run the same code on the same
//! bytes and reach the same verdict:
//!
//! 1. The parent header is the one kept in [`LAST_HEADER`] with `state_root` zeroed; at the start
//!    of a block, before any write, `storage_root` is the parent's state root, which completes it.
//! 2. The inherents are exactly `[RelayParent, Collator]`; `collator_selection` checks the author.
//! 3. The hooks (§4.4, §5): in the first block under a new `SPEC_VERSION`,
//!    [`Runtime::on_runtime_upgrade`]; then [`Runtime::on_initialize`]; then, while a multi-block
//!    migration is ongoing, one [`Runtime::migration_step`]. [`Runtime::finalize_weight`] is
//!    reserved before the inbox.
//! 4. The inbox, in order: the `cgmp` module checks nonces and proofs ([`cgmp::InboxRun`]); an
//!    expired message is answered with a `Timeout` `Ack` (queued while the channel back is at
//!    `MaxBacklog`, and sent first in a later block); the rest go to their handlers: $TOG from
//!    the Hub, Hub `Ack`s, `Timeout` `Ack`s from AppChains, `ComputeResult`s, `Call`s and the
//!    Hub's `WorkerSlashed` notices. A `ComputeResult`'s callback, a `Call` and each module's
//!    `on_worker_slashed` hook run in a storage overlay, discarded if they fail or exceed their
//!    declared weight; the block reserves that declared weight before each runs. A `Call` whose
//!    `weight_limit` exceeds its declared maximum isn't run. Each entry, and each owed `Timeout`
//!    `Ack` sent first, costs [`Runtime::INBOX_ENTRY_WEIGHT`] besides its bytes ([`bytes_weight`]). At the end,
//!    `max_lag` with `MinDrain`.
//! 5. The transactions, none while a multi-block migration is ongoing: signature (EIP-712 kinds from [`Runtime::call_name`]), expiry, weight,
//!    the call's own check, fee and nonce ([`transaction_payment`]), dispatch in an overlay, then
//!    the refund of unused weight. A block builder leaves out a transaction that fails a check; an
//!    importer refuses the block.
//! 6. [`Runtime::on_idle`] with the weight left, then [`Runtime::on_finalize`].
//! 7. The header: roots, counts, `relay_parent`, and the upgrade the block authorized.
//!
//! Hooks are infallible and run in an overlay that is always kept; a hook whose weight doesn't fit
//! fills the block instead of failing it, since a runtime can't refuse its own upgrade.
//!
//! Along the way the block's events are collected (an outcome per inbox message and per
//! transaction, after the events its call deposited through [`Scoped::deposit_event`]; the hooks'
//! under [`system::Phase::Initialization`] and [`system::Phase::Finalization`]) and
//! written to [`system::EVENTS`] at the end; the previous block's value is charged to
//! `proof_size` at the start, since it is in the witness.
//!
//! An invalid block panics, which traps the runtime: the host turns that into "block invalid".

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use tog_runtime_core::abi::ABI_VERSION;
use tog_runtime_core::block::{
    extrinsics_root, head_hash, Block, HeadData, Header, Inherent, Pov, ValidationResult, PEEK_ROOM,
};
use tog_runtime_core::env::Env;
use tog_runtime_core::memory::Overlay;
use tog_runtime_core::storage::StorageKey;
use tog_runtime_core::tx::{AppTx, RuntimeVersion, SignatureCheck, TxError, TxSource, TxValidity, ValidTx};
use tog_runtime_core::weight::{BlockLimits, WeightMeter};
use tog_runtime_core::{
    AccountId, BlockNumber, ChainId, DispatchError, Hash32, HubHeight, Origin, Storage, StorageValue, Weight,
};
use tog_types::cgmp::{CgmpChannel, CgmpMessage, CgmpOrigin, CgmpPayload, WorkerSlashed};
use tog_types::job::ModuleId;
use tog_types::state::items::{cgmp_channel, cgmp_inbound};

use crate::transaction_payment::{self, FeeParams, TogFees};
use crate::{cgmp, collator_selection, compute, system};

/// `executive.last_header`: the last block's header with `state_root` zeroed.
pub const LAST_HEADER: StorageValue<Header> = StorageValue::new("executive", "last_header");

/// A runtime call: module index, call index, `borsh(args)` (§4.5).
pub type Call = (u8, u8, Vec<u8>);

/// What a call sees of the block it runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    /// This chain.
    pub chain: ChainId,
    /// The Hub genesis's `network_id`.
    pub network_id: u32,
    /// The relay parent's height.
    pub relay: HubHeight,
    /// The block's number.
    pub number: BlockNumber,
    /// The block's author, its `Collator` inherent.
    pub author: AccountId,
    /// The runtime's [`Runtime::STORAGE_DEPOSIT_PER_BYTE`], for modules that take deposits (§5).
    pub per_byte: tog_runtime_core::Balance,
}

impl Context {
    /// The `compute` module's view of where it runs.
    pub fn compute_env(&self) -> compute::Env {
        compute::Env { chain: self.chain, network_id: self.network_id }
    }
}

/// One benchmark a runtime declares (§6), from `query("benchmarks")`: `tog bench` measures call
/// `call` of module `module` on the state its setup writes.
#[derive(Clone, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BenchCase {
    /// The module's index.
    pub module: u8,
    /// The call's index.
    pub call: u8,
    /// `"<module>.<call>"`, from the runtime's call names.
    pub name: String,
    /// The call needs `Root`: it is measured wrapped in [`Runtime::as_root`], whose own weight
    /// isn't the call's.
    pub root: bool,
}

/// `query("bench_setup", (module, call, caller))`: what a benchmark's setup wrote, and the call to
/// measure on that state, signed by `caller`.
#[derive(Clone, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BenchSetup {
    /// The setup's writes; `None` clears the key.
    pub writes: Vec<(StorageKey, Option<Vec<u8>>)>,
    /// The transaction's call, already wrapped in [`Runtime::as_root`] for a `Root` call.
    pub call: Call,
    /// The weight the runtime declares for the measured call (not the wrapper).
    pub declared: Weight,
}

/// A chain's runtime: its calls and handlers. Everything else is the executive's.
pub trait Runtime {
    /// Runtime name, for `tog_v1_version`.
    const NAME: &'static str;
    /// Raised by every runtime upgrade.
    const SPEC_VERSION: u32;
    /// SDK-defined hash of the runtime's calls, events and storage; informative.
    const API_HASH: Hash32 = [0; 32];
    /// What every transaction costs besides its call and its bytes: decoding, the signature
    /// check, the fee and the nonce, and its outcome event (§4.3, §6). A transaction's weight is
    /// this plus [`Runtime::call_weight`] plus its bytes ([`Runtime::BYTE_REF_TIME`]).
    const TX_BASE_WEIGHT: Weight = Weight::ZERO;
    /// Picoseconds of `ref_time` per byte of a transaction or inbox entry: decoding, hashing and
    /// copying it, which grows with its length (§6). Each byte also costs one byte of
    /// `proof_size`.
    const BYTE_REF_TIME: u64 = 0;
    /// What every inbox entry costs besides its bytes and the declared limit of the handler it
    /// reaches: acceptance, the channel's state, a `Timeout` `Ack` for an expired message, the
    /// settlement of an `Ack` (refund, deposit), its outcome event (§3.4, §6, R-2). Each owed
    /// `Timeout` `Ack` sent at the start of the inbox costs it too.
    const INBOX_ENTRY_WEIGHT: Weight = Weight::ZERO;

    /// `StorageDepositPerByte` (§5) for what the runtime's own machinery keeps on a payer's behalf:
    /// a compute result kept after its callback failed.
    const STORAGE_DEPOSIT_PER_BYTE: tog_runtime_core::Balance = crate::storage_deposit::DEFAULT_PER_BYTE;

    /// The module's and the call's names in the runtime metadata, lower snake case, which make an
    /// EIP-712 `kind` `"<module>.<call>"`; `None` for an unknown call.
    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)>;

    /// The call's benchmarked weight; `None` if it names no call or its arguments don't decode.
    fn call_weight(call: &Call) -> Option<Weight>;

    /// The call's own pre-dispatch check for the pool and the block builder: `Err(code)` refuses it
    /// with `TxError::Call(code)`. It runs on an overlay that is then dropped, so anything it
    /// writes is discarded, whatever it returns (R-8).
    fn pre_check(_s: &mut impl Storage, _signer: &AccountId, _call: &Call) -> Result<(), u8> {
        Ok(())
    }

    /// Run `call` under `origin`; returns the weight it actually used. On `Err` its state changes
    /// are discarded.
    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError>;

    /// The declared maximum weight of the CGMP `Call` `call` to `module` (§4.6); `None` when the
    /// module is unknown or `call` doesn't decode. A `Call` runs only when its `weight_limit` is at
    /// most this, and the block reserves its `weight_limit` before it runs (§7.1).
    fn cgmp_call_limit(_module: ModuleId, _call: &[u8]) -> Option<Weight> {
        None
    }

    /// A CGMP `Call` to `module` from `source` (§4.6): dispatched with origin `Chain(source)`, with
    /// the message's `CgmpOrigin` as `source`'s claim. Called only when
    /// [`Runtime::cgmp_call_limit`] admits it; `None` consumes the message without running. On
    /// `Err` the call is reverted.
    fn cgmp_call<E: Env>(
        _e: &mut Scoped<'_, E>,
        _cx: &Context,
        _source: ChainId,
        _origin: &CgmpOrigin,
        _module: ModuleId,
        _call: &[u8],
        _weight_limit: Weight,
    ) -> Option<Result<Weight, DispatchError>> {
        None
    }

    /// The weight limit `module`'s `on_compute_result` hook declares; `None` if it has none.
    fn compute_callback_limit(_module: ModuleId) -> Option<Weight> {
        None
    }

    /// `module`'s `on_compute_result` hook for call `call` (§7.1), run under `Origin::Hub` in an
    /// overlay limited to [`Runtime::compute_callback_limit`]; returns the weight it used.
    fn on_compute_result<E: Env>(
        _e: &mut Scoped<'_, E>,
        _cx: &Context,
        _module: ModuleId,
        _call: u16,
        _done: &compute::Completed,
    ) -> Result<Weight, DispatchError> {
        Err(DispatchError::Other("no compute callback"))
    }

    /// The modules with an `on_worker_slashed` hook, in module index order, each with the weight
    /// its hook declares (§7.1 "Worker slash notices"). The block reserves their sum for every
    /// notice.
    fn worker_slashed_hooks() -> &'static [(u8, Weight)] {
        &[]
    }

    /// Module `module`'s `on_worker_slashed` hook: the Hub slashed a worker this chain's
    /// `WorkerSetRules.allowlist` lists (TOG-SPEC-0000 §5.5), and the chain may slash the worker's
    /// stake in its own token by its own rules. Runs under `Origin::Hub` in an overlay limited to
    /// the module's [`Runtime::worker_slashed_hooks`] weight, discarded alone on error; returns
    /// the weight it used.
    fn on_worker_slashed<E: Env>(
        _e: &mut Scoped<'_, E>,
        _cx: &Context,
        _module: u8,
        _notice: &WorkerSlashed,
    ) -> Result<Weight, DispatchError> {
        Err(DispatchError::Other("no worker slash hook"))
    }

    /// A `Timeout` `Ack` for a message this chain sent to another AppChain, after its fee went back
    /// to the sender (§7.1): the sending module's `on_cgmp_message` hook.
    fn on_timeout<E: Env>(_e: &mut E, _cx: &Context, _ack: &CgmpMessage, _pending: &cgmp::PendingCall) {}

    /// Build the genesis state from the chain's opaque `config`. Modules with a
    /// [`system::StorageVersion`] write their current one here.
    fn genesis<E: Env>(e: &mut E, config: &[u8]);

    /// The first block under this runtime's `SPEC_VERSION`, before anything else in it: migrate
    /// the modules whose storage version is behind (`from` is the `spec_version` that ran before).
    /// Returns the weight used. Work that doesn't fit in a block starts a multi-block migration
    /// with [`system::start_migration`].
    fn on_runtime_upgrade<E: Env>(_e: &mut Scoped<'_, E>, _cx: &Context, _from: u32) -> Weight {
        Weight::ZERO
    }

    /// The start of every block, after the upgrade; returns the weight used.
    fn on_initialize<E: Env>(_e: &mut Scoped<'_, E>, _cx: &Context) -> Weight {
        Weight::ZERO
    }

    /// One step of the ongoing multi-block migration at `cursor`, using at most `limit`: the
    /// weight used and the next cursor, or `None` when the migration is done. Runs after
    /// `on_initialize` in every block until then.
    fn migration_step<E: Env>(
        _e: &mut Scoped<'_, E>,
        _cx: &Context,
        _cursor: &[u8],
        _limit: Weight,
    ) -> (Weight, Option<Vec<u8>>) {
        (Weight::ZERO, None)
    }

    /// After the transactions, with what is left of the block's weight (less `on_finalize`'s
    /// reservation); returns the weight used, at most `remaining`.
    fn on_idle<E: Env>(_e: &mut Scoped<'_, E>, _cx: &Context, _remaining: Weight) -> Weight {
        Weight::ZERO
    }

    /// Most weight `on_finalize` uses: reserved before the inbox and the transactions.
    fn finalize_weight() -> Weight {
        Weight::ZERO
    }

    /// The end of every block, within [`Runtime::finalize_weight`].
    fn on_finalize<E: Env>(_e: &mut Scoped<'_, E>, _cx: &Context) {}

    /// The benchmarks of the runtime's modules (§6): `(module, call, root)` for each call a
    /// module's `#[benchmark]` sets up.
    fn benchmarks() -> Vec<(u8, u8, bool)> {
        Vec::new()
    }

    /// The setup of the benchmark of call `call` of module `module` for signer `caller`: it writes
    /// the call's worst case to state and returns the call's arguments. `None` if there is none.
    fn bench_setup<E: Env>(
        _e: &mut Scoped<'_, E>,
        _module: u8,
        _call: u8,
        _caller: AccountId,
    ) -> Option<Result<Vec<u8>, DispatchError>> {
        None
    }

    /// `call` as a transaction dispatches it under `Root` (the `sudo` or governance wrapper); `None`
    /// if the runtime has no such call. For benchmarks of `Root` calls.
    fn as_root(_call: Call) -> Option<Call> {
        None
    }

    /// `query("metadata")`: `borsh(RuntimeMetadata)` of the runtime's modules (provisional until
    /// v2 fixes the format; empty by default).
    fn metadata() -> Vec<u8> {
        Vec::new()
    }

    /// The chain's fee prices.
    fn fee_params() -> FeeParams {
        FeeParams::DEFAULT
    }
}

/// Events a call deposited: module name, `borsh(event)`.
pub type Deposited = Vec<(&'static str, Vec<u8>)>;

/// [`Env`] over an overlay, which every call runs in: storage writes, outbox pushes and deposited
/// events are kept until the call succeeds, and dropped otherwise. A nested call that may fail without undoing the
/// outer one (`sudo.call`'s inner call) runs through [`Scoped::nested`]. `inbox_next` and
/// `storage_root` aren't available inside a call.
pub struct Scoped<'a, E: Env> {
    ov: Overlay<'a, E>,
    pushed: Vec<Vec<u8>>,
    events: Deposited,
}

impl<'a, E: Env> Scoped<'a, E> {
    fn new(e: &'a mut E) -> Self {
        Scoped { ov: Overlay::new(e), pushed: Vec::new(), events: Vec::new() }
    }

    fn commit(self) -> Deposited {
        let base = self.ov.commit();
        for m in &self.pushed {
            base.outbox_push(m);
        }
        self.events
    }

    /// Run `f`; if it fails, drop what it changed and keep what came before.
    pub fn nested<T, Err>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Err>) -> Result<T, Err> {
        let (c, n, d) = (self.ov.checkpoint(), self.pushed.len(), self.events.len());
        let r = f(self);
        if r.is_err() {
            self.ov.restore(c);
            self.pushed.truncate(n);
            self.events.truncate(d);
        }
        r
    }

    /// Deposit `module`'s `event` (its own Borsh type) in the block's events, if the call succeeds.
    pub fn deposit_event(&mut self, module: &'static str, event: &impl borsh::BorshSerialize) {
        self.events.push((module, borsh::to_vec(event).expect("in-memory borsh")));
    }
}

impl<E: Env> Storage for Scoped<'_, E> {
    fn get(&mut self, key: &StorageKey) -> Option<Vec<u8>> {
        self.ov.get(key)
    }
    fn set(&mut self, key: &StorageKey, value: Vec<u8>) {
        self.ov.set(key, value)
    }
    fn clear(&mut self, key: &StorageKey) {
        self.ov.clear(key)
    }
    fn next_key(&mut self, key: &StorageKey) -> Option<StorageKey> {
        self.ov.next_key(key)
    }
}

impl<E: Env> Env for Scoped<'_, E> {
    fn chain_context(&mut self) -> (ChainId, u32) {
        self.ov.base().chain_context()
    }
    fn relay_parent(&mut self) -> (HubHeight, Hash32) {
        self.ov.base().relay_parent()
    }
    fn hub_read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.ov.base().hub_read(key)
    }
    fn inbox_next(&mut self) -> Option<Vec<u8>> {
        panic!("inbox_next inside a call")
    }
    fn outbox_push(&mut self, msg: &[u8]) {
        self.pushed.push(msg.to_vec())
    }
    fn storage_root(&mut self) -> Hash32 {
        panic!("storage_root inside a call")
    }
}

/// Run `f` in an overlay and keep its changes only if it returns `Ok` within `limit`; the events
/// it deposited then go to `events`.
fn transactional<E: Env>(
    e: &mut E,
    limit: Option<Weight>,
    events: &mut Deposited,
    f: impl FnOnce(&mut Scoped<'_, E>) -> Result<Weight, DispatchError>,
) -> Result<Weight, DispatchError> {
    let mut sc = Scoped::new(e);
    match f(&mut sc) {
        Ok(w) if limit.map_or(true, |l| w.all_lte(l)) => {
            events.extend(sc.commit());
            Ok(w)
        }
        Ok(_) => Err(DispatchError::Exhausted),
        Err(err) => Err(err),
    }
}

/// Run `call` under `origin` on `e` outside a block, as a block runs a call: its changes, messages
/// and events are kept only if it succeeds. For native tests (`tog-runtime-test`), which reach
/// origins no transaction has (`Root`, `Hub`, `Chain`).
pub fn dispatch_as<R: Runtime, E: Env>(
    e: &mut E,
    cx: &Context,
    origin: Origin,
    call: Call,
) -> (Result<Weight, DispatchError>, Deposited) {
    let mut events = Vec::new();
    let r = transactional(e, None, &mut events, |sc| R::dispatch(sc, cx, origin, call));
    (r, events)
}

/// How a block is run: built (a failing transaction is left out) or imported (it fails the block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Build,
    /// Taking exactly `inbox` entries.
    Import {
        inbox: u64,
    },
}

/// What a block did.
struct Executed {
    header: Header,
    included: Vec<Vec<u8>>,
    outbox: Vec<(ChainId, Hash32, u64)>,
    inbox: Vec<(ChainId, u64)>,
    new_code: Option<Hash32>,
    /// It stopped at a peek: the next inbox entry, read and not taken.
    peeked: bool,
}

/// The `kind` of an EIP-712 signature over `call`.
fn kind<R: Runtime>(call: &Call) -> Option<String> {
    R::call_name(call.0, call.1).map(|(m, c)| format!("{m}.{c}"))
}

/// A transaction's checks short of state: decoding, signature and weight. Returns the transaction,
/// its signer and its declared weight with its own bytes added to `proof_size`.
fn check_tx<R: Runtime>(
    chain_id: u64,
    bytes: &[u8],
    c: &impl SignatureCheck,
) -> Result<(AppTx, AccountId, Weight), TxError> {
    let tx: AppTx = borsh::from_slice(bytes).map_err(|_| TxError::BadFormat)?;
    let signer = tx.check(chain_id, kind::<R>(&tx.body.call).as_deref(), c)?;
    let w = tx_weight::<R>(&tx.body.call, bytes.len()).ok_or(TxError::BadFormat)?;
    Ok((tx, signer, w))
}

/// [`Runtime::pre_check`] on an overlay of `s` that is dropped: it reads the state, never writes it.
fn pre_check<R: Runtime>(s: &mut impl Storage, signer: &AccountId, call: &Call) -> Result<(), TxError> {
    R::pre_check(&mut Overlay::new(s), signer, call).map_err(TxError::Call)
}

/// What `len` bytes of a transaction or inbox entry cost: [`Runtime::BYTE_REF_TIME`] each in
/// `ref_time`, and themselves in `proof_size`.
pub fn bytes_weight<R: Runtime>(len: usize) -> Weight {
    let len = len as u64;
    Weight::from_parts(len.saturating_mul(R::BYTE_REF_TIME), len)
}

/// A transaction's declared weight: [`Runtime::TX_BASE_WEIGHT`], its call's, and its `len` bytes
/// ([`bytes_weight`]); `None` for an unknown call.
pub fn tx_weight<R: Runtime>(call: &Call, len: usize) -> Option<Weight> {
    let w = R::call_weight(call)?.saturating_add(R::TX_BASE_WEIGHT);
    Some(w.saturating_add(bytes_weight::<R>(len)))
}

/// Apply one transaction; on `Err` nothing changed. Returns its outcome, after the events its call
/// deposited in `events`.
fn apply_tx<R: Runtime, E: Env>(
    e: &mut E,
    cx: &Context,
    bytes: &[u8],
    c: &impl SignatureCheck,
    meter: &mut WeightMeter,
    events: &mut Deposited,
) -> Result<system::Event, TxError> {
    let chain_id = e.replay_domain();
    let (tx, signer, weight) = check_tx::<R>(chain_id, bytes, c)?;
    tx.check_expiry(cx.number)?;
    if !meter.can_consume(weight) {
        return Err(TxError::ExhaustsResources);
    }
    pre_check::<R>(e, &signer, &tx.body.call)?;
    let p = R::fee_params();
    let charged = transaction_payment::pre_dispatch(e, &p, &TogFees, &signer, tx.body.nonce, tx.body.tip, weight)?;
    let call = tx.body.call;
    let (actual, outcome) = match transactional(e, None, events, |sc| R::dispatch(sc, cx, Origin::Signed(signer), call))
    {
        Ok(w) => (w.min(weight), None),
        Err(err) => (weight, Some(err)),
    };
    transaction_payment::post_dispatch(e, &p, &TogFees, &signer, charged, actual, Some(&cx.author))
        .expect("fee settles");
    meter.try_consume(actual);
    Ok(match outcome {
        None => system::Event::ExtrinsicSuccess { weight: actual },
        Some(err) => system::Event::ExtrinsicFailed { weight: actual, error: err.into() },
    })
}

/// Most bytes a Hub proof adds to the PoV besides its value: `(key, value, borsh(StateProof))` with
/// a 96-byte key, a leaf and all 256 siblings, and Borsh lengths.
pub const HUB_PROOF_BYTES: u64 = 4 + 96 + 5 + 4 + 1 + 64 + 4 + 256 * 32;

/// The Hub reads the executive makes itself, each charged to the block's `proof_size` once: its
/// proof goes in the PoV once however often it is read (§6). A call's own Hub reads are in its
/// benchmarked weight.
#[derive(Default)]
struct HubReads(alloc::collections::BTreeSet<Vec<u8>>);

impl HubReads {
    fn read(&mut self, e: &mut impl Env, meter: &mut WeightMeter, key: &[u8]) -> Option<Vec<u8>> {
        let v = e.hub_read(key);
        if self.0.insert(key.to_vec()) {
            let len = v.as_ref().map_or(0, |v| v.len() as u64);
            meter.try_consume(Weight::from_parts(0, HUB_PROOF_BYTES + len));
        }
        v
    }

    /// The channel `source → me` at the relay parent.
    fn channel(&mut self, e: &mut impl Env, meter: &mut WeightMeter, source: &ChainId, me: &ChainId) -> CgmpChannel {
        self.read(e, meter, &cgmp_channel(source, me))
            .map(|b| borsh::from_slice(&b).expect("channel decodes"))
            .expect("channel on the Hub")
    }

    /// The `next_nonce` of the channel `me → dest` at the relay parent: 0 while the Hub has none.
    fn delivered(&mut self, e: &mut impl Env, meter: &mut WeightMeter, me: &ChainId, dest: &ChainId) -> u64 {
        self.read(e, meter, &cgmp_channel(me, dest))
            .map_or(0, |b| borsh::from_slice::<CgmpChannel>(&b).expect("channel decodes").next_nonce)
    }
}

fn event_bytes(e: &impl borsh::BorshSerialize) -> Vec<u8> {
    borsh::to_vec(e).expect("in-memory borsh")
}

/// Push `m` to the outbox.
fn push(e: &mut impl Env, m: &CgmpMessage) {
    e.outbox_push(&borsh::to_vec(m).expect("in-memory borsh"));
}

/// The declared limits of the handlers message `m` will reach at relay parent height `h`, read
/// before it is accepted (§7.1, R-3): a `Call` that will run, its `weight_limit`; a Hub
/// `ComputeResult` of an open job with a callback, the callback's limit; a Hub `WorkerSlashed`,
/// every slash hook's; nothing for an expired message or any other.
fn reservation<R: Runtime>(s: &mut impl Storage, m: &CgmpMessage, h: HubHeight) -> Weight {
    if h > m.timeout_height {
        return Weight::ZERO;
    }
    match &m.payload {
        CgmpPayload::Call { module, call, weight_limit } => {
            if R::cgmp_call_limit(*module, call).is_some_and(|max| weight_limit.all_lte(max)) {
                *weight_limit
            } else {
                Weight::ZERO
            }
        }
        CgmpPayload::ComputeResult(result) if m.source == ChainId::HUB => {
            match compute::JOBS.get(s, &result.job_id).expect("compute state").and_then(|j| j.callback) {
                Some((module, _)) => R::compute_callback_limit(module).unwrap_or(Weight::ZERO),
                None => Weight::ZERO,
            }
        }
        CgmpPayload::WorkerSlashed(_) if m.source == ChainId::HUB => {
            R::worker_slashed_hooks().iter().fold(Weight::ZERO, |w, (_, limit)| w.saturating_add(*limit))
        }
        _ => Weight::ZERO,
    }
}

/// The sources that owe `MinDrain` now, ascending: over `max_lag` with this block's progress, and
/// fewer than [`cgmp::MIN_DRAIN`] taken in it (§3.4 "max_lag (exact)").
fn debtors(s: &mut impl Storage, run: &cgmp::InboxRun, channels: &[(ChainId, CgmpChannel)]) -> Vec<ChainId> {
    channels
        .iter()
        .filter(|(source, ch)| {
            let next = cgmp::inbound(s, *source).expect("inbound decodes").next_nonce;
            !ch.within_lag(next) && run.taken(*source) < cgmp::MIN_DRAIN
        })
        .map(|(source, _)| *source)
        .collect()
}

/// Hand an accepted, unexpired message to its handler; the events its handler deposited go to
/// `events`. The block reserved the declared limit of each handler it reaches ([`reservation`])
/// before it was accepted, whatever it then uses.
fn deliver<R: Runtime, E: Env>(e: &mut E, cx: &Context, m: &CgmpMessage, events: &mut Deposited) -> system::Outcome {
    let mut outcome = system::Outcome::Executed;
    match &m.payload {
        CgmpPayload::TransferTog { .. } => {
            cgmp::receive_tog(e, m).expect("deposit");
        }
        CgmpPayload::Ack { .. } if m.source == ChainId::HUB => {
            if let Some(acked) = cgmp::receive_ack(e, m).expect("ack settles") {
                if let Some(job_id) = compute::on_ack(e, &acked).expect("compute state") {
                    events.push(("compute", event_bytes(&compute::Event::Refused { job_id })));
                }
            }
        }
        CgmpPayload::Ack { .. } => {
            if let Some(p) = cgmp::receive_timeout(e, m).expect("timeout refund") {
                R::on_timeout(e, cx, m, &p);
            }
        }
        CgmpPayload::ComputeResult(result) => {
            let Some(done) = compute::on_result(e, m).expect("compute refund") else { return outcome };
            let completed = compute::Event::Completed { result: result.clone(), refunded: done.refunded };
            events.push(("compute", event_bytes(&completed)));
            if let Some((module, call)) = done.job.callback {
                let limit = R::compute_callback_limit(module).unwrap_or(Weight::ZERO);
                let ran = transactional(e, Some(limit), events, |sc| R::on_compute_result(sc, cx, module, call, &done));
                if let Err(err) = ran {
                    compute::keep_result(e, &done.job.payer, result, R::STORAGE_DEPOSIT_PER_BYTE).expect("result kept");
                    outcome = system::Outcome::Failed(err.into());
                }
            }
        }
        CgmpPayload::Call { module, call, weight_limit } => {
            // Consumed without running when the module is unknown, the call doesn't decode or
            // `weight_limit` exceeds the call's declared maximum (§4.6).
            if !R::cgmp_call_limit(*module, call).is_some_and(|max| weight_limit.all_lte(max)) {
                return system::Outcome::Failed(DispatchError::Other("not run").into());
            }
            let ran = transactional(e, Some(*weight_limit), events, |sc| {
                R::cgmp_call(sc, cx, m.source, &m.origin, *module, call, *weight_limit)
                    .unwrap_or(Err(DispatchError::Other("not run")))
            });
            if let Err(err) = ran {
                outcome = system::Outcome::Failed(err.into());
            }
        }
        // Only the Hub reports slashes; one from another chain is consumed without effect.
        CgmpPayload::WorkerSlashed(notice) if m.source == ChainId::HUB => {
            events.push(("compute", event_bytes(&compute::Event::WorkerSlashed(notice.clone()))));
            for (module, limit) in R::worker_slashed_hooks() {
                let ran = transactional(e, Some(*limit), events, |sc| R::on_worker_slashed(sc, cx, *module, notice));
                if let (Err(err), system::Outcome::Executed) = (ran, &outcome) {
                    outcome = system::Outcome::Failed(err.into());
                }
            }
        }
        CgmpPayload::WorkerSlashed(_) | CgmpPayload::ComputeRequest { .. } => {}
    }
    outcome
}

/// Adds the events of phase `phase`: those its call deposited, then the system's `outcome`.
fn record(events: &mut system::Events, phase: system::Phase, deposited: Deposited, outcome: &system::Event) {
    for (module, event) in deposited {
        events.push(phase, module, event);
    }
    events.push(phase, "system", event(outcome));
}

fn event(e: &system::Event) -> Vec<u8> {
    borsh::to_vec(e).expect("in-memory borsh")
}

/// Run hook `f` in an overlay that is always kept; its events go to `events` under `phase`.
fn hook<E: Env, T>(
    e: &mut E,
    events: &mut system::Events,
    phase: system::Phase,
    f: impl FnOnce(&mut Scoped<'_, E>) -> T,
) -> T {
    let mut sc = Scoped::new(e);
    let r = f(&mut sc);
    for (module, event) in sc.commit() {
        events.push(phase, module, event);
    }
    r
}

/// Consume `w`, or all that is left if it doesn't fit; returns what it consumed.
fn fill(meter: &mut WeightMeter, w: Weight) -> Weight {
    if meter.try_consume(w) {
        return w;
    }
    let left = meter.remaining();
    meter.try_consume(left);
    left
}

/// Run a block body on the parent state.
fn run<R: Runtime, E: Env>(
    e: &mut E,
    inherents: &[Inherent],
    txs: Vec<Vec<u8>>,
    digest: Vec<u8>,
    c: &impl SignatureCheck,
    mode: Mode,
) -> Executed {
    let mut parent = LAST_HEADER.get(e).expect("header decodes").expect("genesis ran");
    parent.state_root = e.storage_root();

    let (relay, author) = match inherents {
        [Inherent::RelayParent { height, hash }, Inherent::Collator { account }] => ((*height, *hash), *account),
        _ => panic!("inherents must be [RelayParent, Collator]"),
    };
    assert!(relay.0 == e.relay_parent().0, "relay parent height");
    collator_selection::check_author(e, relay.0, parent.relay_parent.0, &digest, inherents).expect("block author");
    let number = parent.number + 1;
    system::initialize(e, number).expect("block number");
    let (chain, network_id) = e.chain_context();
    let cx = Context { chain, network_id, relay: relay.0, number, author, per_byte: R::STORAGE_DEPOSIT_PER_BYTE };
    let outbox_before = cgmp::outbox(e).expect("outbox decodes");
    let mut meter = WeightMeter::new(BlockLimits::DEFAULT.max_block);
    // The last block's events are in the witness: this block replaces them.
    let last_events = e.get(&system::EVENTS.key()).map_or(0, |v| v.len() as u64);
    meter.try_consume(Weight::from_parts(0, last_events));
    let mut events = system::Events::default();

    // The hooks before the inbox.
    let init = system::Phase::Initialization;
    let from = system::RUNTIME_VERSION.get_or_default(e).expect("runtime version decodes");
    if from < R::SPEC_VERSION {
        let w = hook(e, &mut events, init, |sc| R::on_runtime_upgrade(sc, &cx, from));
        fill(&mut meter, w);
        system::RUNTIME_VERSION.put(e, &R::SPEC_VERSION).expect("runtime version encodes");
        events.push(init, "system", event(&system::Event::Upgraded { from, to: R::SPEC_VERSION }));
    }
    let w = hook(e, &mut events, init, |sc| R::on_initialize(sc, &cx));
    fill(&mut meter, w);
    let finalize = R::finalize_weight();
    if let Some(cursor) = system::migration(e).expect("migration cursor decodes") {
        let limit = meter.remaining().saturating_sub(finalize);
        let (w, next) = hook(e, &mut events, init, |sc| R::migration_step(sc, &cx, &cursor, limit));
        fill(&mut meter, w.min(limit));
        match next {
            Some(c) => system::MIGRATION.put(e, &c).expect("migration cursor encodes"),
            None => {
                system::MIGRATION.kill(e);
                events.push(init, "system", event(&system::Event::MigrationCompleted));
            }
        }
    }
    let migrating = system::migration(e).expect("migration cursor decodes").is_some();
    // What the init hooks left of `finalize` (R-4): all of it unless they filled the block.
    let reserved = fill(&mut meter, finalize);

    // The inbox.
    let mut inbox_processed = parent.inbox_processed;
    let mut run = cgmp::InboxRun::default();
    let mut hub = HubReads::default();
    // Timeout Acks that waited for room under `MaxBacklog` go first.
    let owed = cgmp::owed_sources(e).expect("owed acks decode");
    let delivered: Vec<(ChainId, u64)> = owed.iter().map(|d| (*d, hub.delivered(e, &mut meter, &chain, d))).collect();
    for ack in cgmp::send_owed_acks(e, chain, &delivered).expect("owed acks") {
        fill(&mut meter, R::INBOX_ENTRY_WEIGHT);
        push(e, &ack);
    }
    // The channels to this chain, read first: while a source owes `MinDrain`, the order of the
    // entries and where the block may stop depend on them (§3.4 "max_lag (exact)", R-3).
    let mut sources: Vec<ChainId> = hub
        .read(e, &mut meter, &cgmp_inbound(&chain))
        .map(|b| borsh::from_slice(&b).expect("inbound decodes"))
        .unwrap_or_default();
    sources.sort();
    let channels: Vec<(ChainId, CgmpChannel)> =
        sources.iter().map(|s| (*s, hub.channel(e, &mut meter, s, &chain))).collect();
    // The source of the last entry taken while some source owed, for the round-robin.
    let mut last_debtor: Option<ChainId> = None;
    let mut peeked = false;
    loop {
        let debtors = debtors(e, &run, &channels);
        // An imported block takes exactly its entries; then, if some source still owes, the next
        // entry is its peek.
        if let Mode::Import { inbox } = mode {
            if inbox_processed - parent.inbox_processed == inbox && debtors.is_empty() {
                break;
            }
        }
        let Some(entry) = e.inbox_next() else { break };
        // An entry this state can't take (the collator read the inbox for another parent) ends
        // the inbox of a block being built: the block takes the entries before it, which is what
        // `inbox_processed` tells the host to keep.
        let Ok((m, proof)) = borsh::from_slice::<(CgmpMessage, Option<Vec<Hash32>>)>(&entry) else {
            assert!(mode == Mode::Build, "inbox entry decodes");
            break;
        };
        // While some source owes, the entries go round the sources that owe, ascending.
        let due = debtors.iter().find(|d| last_debtor.map_or(true, |l| **d > l)).or(debtors.first()).copied();
        if due.is_some_and(|d| d != m.source) {
            assert!(mode == Mode::Build, "inbox entry out of the round-robin of sources owing MinDrain");
            break;
        }
        let ch = hub.channel(e, &mut meter, &m.source, &chain);
        // What the entry needs, reserved before anything runs; while some source owes, it fits only
        // with `PEEK_ROOM` to spare, so a peek fits the PoV. Only the block's first entry is taken
        // when it doesn't fit.
        let need = R::INBOX_ENTRY_WEIGHT
            .saturating_add(bytes_weight::<R>(entry.len()))
            .saturating_add(reservation::<R>(e, &m, relay.0));
        let room = Weight::from_parts(0, if due.is_some() { PEEK_ROOM } else { 0 });
        let fits = meter.can_consume(need.saturating_add(room));
        let first = inbox_processed == parent.inbox_processed;
        let taking = match mode {
            Mode::Import { inbox } => inbox_processed - parent.inbox_processed < inbox,
            Mode::Build => first || fits,
        };
        if !taking {
            // A block may stop while some source owes only at the next entry of the round that
            // doesn't fit: that entry is its peek, checked and not run.
            let peek = due.is_some() && !fits && run.peek(e, &m, proof.as_deref(), &ch).is_ok();
            assert!(peek || mode == Mode::Build, "inbox peek: a source owes, the entry is its next and doesn't fit");
            peeked = peek;
            break;
        }
        assert!(first || fits, "inbox entry over the block's weight");
        let delivery = match run.accept(e, &m, proof.as_deref(), &ch, relay.0) {
            Ok(d) => d,
            Err(_) if mode == Mode::Build => break,
            Err(err) => panic!("inbox: {err:?}"),
        };
        fill(&mut meter, need);
        if due.is_some() {
            last_debtor = Some(m.source);
        }
        let mut deposited = Vec::new();
        let outcome = match delivery {
            cgmp::Delivery::Expired => {
                let delivered = match m.payload {
                    CgmpPayload::Ack { .. } => 0,
                    _ => hub.delivered(e, &mut meter, &chain, &m.source),
                };
                if let Some(ack) = cgmp::timeout_ack(e, chain, &m, delivered).expect("timeout ack") {
                    push(e, &ack);
                }
                system::Outcome::Expired
            }
            cgmp::Delivery::Execute => deliver::<R, E>(e, &cx, &m, &mut deposited),
        };
        let phase = system::Phase::Inbox((inbox_processed - parent.inbox_processed) as u32);
        let event = system::Event::Message { source: m.source, nonce: m.channel_nonce, outcome };
        record(&mut events, phase, deposited, &event);
        inbox_processed += 1;
    }
    if let Mode::Import { inbox } = mode {
        assert!(inbox_processed - parent.inbox_processed == inbox, "inbox_processed");
    }
    let inbox = run.finish(e, &channels, peeked).expect("inbox proofs and max_lag");

    // The transactions, none while a migration is ongoing.
    let mut included = Vec::new();
    assert!(!migrating || mode == Mode::Build || txs.is_empty(), "transactions during a migration");
    for (i, x) in txs.into_iter().enumerate().filter(|_| !migrating) {
        let mut deposited = Vec::new();
        match (apply_tx::<R, E>(e, &cx, &x, c, &mut meter, &mut deposited), mode) {
            (Ok(outcome), _) => {
                record(&mut events, system::Phase::Extrinsic(included.len() as u32), deposited, &outcome);
                included.push(x);
            }
            (Err(_), Mode::Build) => {}
            (Err(err), Mode::Import { .. }) => panic!("transaction {i}: {err:?}"),
        }
    }

    // The hooks after the transactions.
    let fin = system::Phase::Finalization;
    meter.refund(reserved);
    let idle = meter.remaining().saturating_sub(finalize);
    let w = hook(e, &mut events, fin, |sc| R::on_idle(sc, &cx, idle));
    fill(&mut meter, w.min(idle));
    hook(e, &mut events, fin, |sc| R::on_finalize(sc, &cx));

    let new_code = system::take_authorized_upgrade(e).expect("authorized upgrade decodes");
    let outbox_after = cgmp::outbox(e).expect("outbox decodes");
    let outbox =
        outbox_after.iter().filter(|c| !outbox_before.contains(c)).map(|c| (c.dest, c.head, c.last_nonce)).collect();
    let mut header = Header {
        parent: parent.hash(),
        number,
        state_root: [0; 32],
        extrinsics_root: extrinsics_root(inherents, &included),
        relay_parent: relay,
        outbox_root: tog_types::cgmp::outbox_root(&outbox_after),
        inbox_processed,
        digest,
    };
    system::EVENTS.put(e, &events).expect("events encode");
    LAST_HEADER.put(e, &header).expect("header encodes");
    header.state_root = e.storage_root();
    Executed { header, included, outbox, inbox, new_code, peeked }
}

/// `tog_v1_build_block((parent_head, inherents, txs)) -> (Block, peeked)`: leaves out the
/// transactions that fail and fills the header. `peeked`: the block stopped while a source owed
/// `MinDrain`, at the next inbox entry after its own, which its PoV carries as its peek (§3.4).
pub fn build_block<R: Runtime, E: Env>(e: &mut E, c: &impl SignatureCheck, input: &[u8]) -> Vec<u8> {
    let (parent_head, inherents, txs): (HeadData, Vec<Inherent>, Vec<Vec<u8>>) =
        borsh::from_slice(input).expect("input decodes");
    let x = run::<R, E>(e, &inherents, txs, Vec::new(), c, Mode::Build);
    assert!(x.header.parent == head_hash(&parent_head), "parent head mismatch");
    let block = Block { header: x.header, inherents, extrinsics: x.included };
    borsh::to_vec(&(block, x.peeked)).expect("in-memory borsh")
}

/// Import `b`: every transaction must apply and the header must be what the run produces.
fn import<R: Runtime, E: Env>(e: &mut E, c: &impl SignatureCheck, b: Block) -> Executed {
    let parent = LAST_HEADER.get(e).expect("header decodes").expect("genesis ran");
    let inbox = b.header.inbox_processed.checked_sub(parent.inbox_processed).expect("inbox_processed");
    let x = run::<R, E>(e, &b.inherents, b.extrinsics, b.header.digest.clone(), c, Mode::Import { inbox });
    assert!(x.header == b.header, "header mismatch");
    x
}

/// `tog_v1_execute_block(block) -> ()`.
pub fn execute_block<R: Runtime, E: Env>(e: &mut E, c: &impl SignatureCheck, input: &[u8]) -> Vec<u8> {
    import::<R, E>(e, c, borsh::from_slice(input).expect("block decodes"));
    Vec::new()
}

/// `tog_v1_validate_block(pov) -> ValidationResult`.
pub fn validate_block<R: Runtime, E: Env>(e: &mut E, c: &impl SignatureCheck, input: &[u8]) -> Vec<u8> {
    let pov: Pov = borsh::from_slice(input).expect("pov decodes");
    let parent = head_hash(&pov.parent_head);
    let x = import::<R, E>(e, c, pov.block);
    assert!(x.header.parent == parent, "parent head mismatch");
    let r = ValidationResult {
        head: x.header.head_data(),
        outbox_root: x.header.outbox_root,
        inbox_processed: x.header.inbox_processed,
        new_code: x.new_code,
        outbox: x.outbox,
        inbox: x.inbox,
    };
    borsh::to_vec(&r).expect("in-memory borsh")
}

/// `tog_v1_validate_tx((tx, source)) -> TxValidity`, for the next block on the current state.
pub fn validate_tx<R: Runtime, E: Env>(e: &mut E, c: &impl SignatureCheck, input: &[u8]) -> Vec<u8> {
    let v: TxValidity = match borsh::from_slice::<(Vec<u8>, TxSource)>(input) {
        Ok((bytes, _)) => check_pool::<R, E>(e, c, &bytes),
        Err(_) => Err(TxError::BadFormat),
    };
    borsh::to_vec(&v).expect("in-memory borsh")
}

fn check_pool<R: Runtime, E: Env>(e: &mut E, c: &impl SignatureCheck, bytes: &[u8]) -> TxValidity {
    let chain_id = e.replay_domain();
    let (tx, signer, weight) = check_tx::<R>(chain_id, bytes, c)?;
    let next = LAST_HEADER.get(e).ok().flatten().map_or(1, |h| h.number + 1);
    tx.check_expiry(next)?;
    if !weight.all_lte(BlockLimits::DEFAULT.max_block) {
        return Err(TxError::ExhaustsResources);
    }
    pre_check::<R>(e, &signer, &tx.body.call)?;
    let p = R::fee_params();
    let priority = transaction_payment::validate(e, &p, &TogFees, &signer, tx.body.nonce, tx.body.tip, weight)?;
    Ok(ValidTx { sender: signer, nonce: tx.body.nonce, priority, longevity: tx.longevity(next) })
}

/// `tog_v1_query((method, args)) -> Result<Vec<u8>, String>`, with the standard methods (§3.1):
/// `"metadata"`, `"slot_author"` (`borsh(HubHeight)` → `borsh(Option<Address>)`),
/// `"fee_estimate"` (`borsh(AppTx)` → `borsh(Amount)`), `"account"` (`borsh(AccountId)` →
/// `borsh((u64, AccountData))`: the account's next nonce and its balances), and the `compute` module's
/// `"compute_job"` (`borsh(job_id)` → `borsh(Option<compute::Job>)`, an open job) and
/// `"compute_result"` (`borsh(job_id)` → `borsh(Option<ComputeResult>)`, a kept result).
pub fn query<R: Runtime, E: Env>(e: &mut E, input: &[u8]) -> Vec<u8> {
    let r: Result<Vec<u8>, String> = match borsh::from_slice::<(String, Vec<u8>)>(input) {
        Err(_) => Err("bad query".to_string()),
        Ok((method, args)) => match method.as_str() {
            "metadata" => Ok(R::metadata()),
            "benchmarks" => {
                let cases: Vec<BenchCase> = R::benchmarks()
                    .into_iter()
                    .map(|(module, call, root)| {
                        let name = R::call_name(module, call).map(|(m, c)| format!("{m}.{c}")).unwrap_or_default();
                        BenchCase { module, call, name, root }
                    })
                    .collect();
                Ok(borsh::to_vec(&cases).expect("in-memory borsh"))
            }
            "bench_setup" => match borsh::from_slice::<(u8, u8, AccountId)>(&args) {
                Ok((module, call, caller)) => bench_setup::<R, E>(e, module, call, caller),
                Err(_) => Err("bad args".to_string()),
            },
            "slot_author" => match borsh::from_slice::<HubHeight>(&args) {
                Ok(h) => collator_selection::slot_author(e, h)
                    .map(|a| borsh::to_vec(&a).expect("in-memory borsh"))
                    .map_err(|_| "storage".to_string()),
                Err(_) => Err("bad args".to_string()),
            },
            "fee_estimate" => match borsh::from_slice::<AppTx>(&args) {
                Ok(tx) => tx_weight::<R>(&tx.body.call, args.len())
                    .and_then(|w| transaction_payment::fee_estimate(&R::fee_params(), w, tx.body.tip))
                    .map(|fee| borsh::to_vec(&fee).expect("in-memory borsh"))
                    .ok_or_else(|| "unknown call".to_string()),
                Err(_) => Err("bad args".to_string()),
            },
            "account" => match borsh::from_slice::<AccountId>(&args) {
                Ok(who) => system::nonce(e, &who)
                    .ok()
                    .zip(crate::balances::account(e, &who).ok())
                    .map(|a| borsh::to_vec(&a).expect("in-memory borsh"))
                    .ok_or_else(|| "storage".to_string()),
                Err(_) => Err("bad args".to_string()),
            },
            "compute_job" => match borsh::from_slice::<Hash32>(&args) {
                Ok(id) => compute::JOBS
                    .get(e, &id)
                    .map(|j| borsh::to_vec(&j).expect("in-memory borsh"))
                    .map_err(|_| "storage".to_string()),
                Err(_) => Err("bad args".to_string()),
            },
            "compute_result" => match borsh::from_slice::<Hash32>(&args) {
                Ok(id) => compute::RESULTS
                    .get(e, &id)
                    .map(|r| borsh::to_vec(&r).expect("in-memory borsh"))
                    .map_err(|_| "storage".to_string()),
                Err(_) => Err("bad args".to_string()),
            },
            _ => Err(format!("unknown method {method}")),
        },
    };
    borsh::to_vec(&r).expect("in-memory borsh")
}

/// Runs a benchmark's setup in an overlay that is dropped, returning its writes ([`BenchSetup`]).
fn bench_setup<R: Runtime, E: Env>(e: &mut E, module: u8, call: u8, caller: AccountId) -> Result<Vec<u8>, String> {
    let root = R::benchmarks()
        .into_iter()
        .find(|(m, c, _)| (*m, *c) == (module, call))
        .map(|(.., root)| root)
        .ok_or_else(|| "no benchmark".to_string())?;
    let mut s = Scoped::new(e);
    let args = R::bench_setup(&mut s, module, call, caller)
        .ok_or_else(|| "no benchmark".to_string())?
        .map_err(|err| format!("setup: {err:?}"))?;
    let measured = (module, call, args);
    let declared = R::call_weight(&measured).ok_or_else(|| "the setup's call doesn't decode".to_string())?;
    let call = if root { R::as_root(measured).ok_or_else(|| "no Root wrapper".to_string())? } else { measured };
    let writes = s.ov.into_changes().into_iter().collect();
    Ok(borsh::to_vec(&BenchSetup { writes, call, declared }).expect("in-memory borsh"))
}

/// `tog_v1_genesis(config) -> Hash32`: the chain's genesis state and its root. The genesis head is
/// `Header::genesis(root)`.
pub fn genesis<R: Runtime, E: Env>(e: &mut E, input: &[u8]) -> Vec<u8> {
    let config: Vec<u8> = borsh::from_slice(input).expect("config decodes");
    R::genesis(e, &config);
    system::RUNTIME_VERSION.put(e, &R::SPEC_VERSION).expect("runtime version encodes");
    LAST_HEADER.put(e, &Header::genesis([0; 32])).expect("header encodes");
    borsh::to_vec(&e.storage_root()).expect("in-memory borsh")
}

/// `tog_v1_version() -> RuntimeVersion`.
pub fn version<R: Runtime>() -> Vec<u8> {
    let v = RuntimeVersion {
        name: R::NAME.to_string(),
        spec_version: R::SPEC_VERSION,
        abi_version: ABI_VERSION,
        api_hash: R::API_HASH,
    };
    borsh::to_vec(&v).expect("in-memory borsh")
}

#[cfg(test)]
mod tests;
