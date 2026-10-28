//! The AppChain SDK compute template runtime (TOG-SPEC-0007 §7.1, §13): the minimal template plus
//! [`model_registry`], a chain module that fine-tunes models through the compute API. It runs the
//! standard modules through [`executive`], with the chain's calls in this order:
//!
//! | index | module               | calls                                                    |
//! |-------|----------------------|----------------------------------------------------------|
//! | 0     | `balances`           | 0 `transfer { to, amount }`                              |
//! | 1     | `sudo`               | 0 `call(inner)`, 1 `set_key(new)`, 2 `remove_key()`      |
//! | 2     | `system`             | 0 `authorize_upgrade(code_hash)` (`Root`)                |
//! | 3     | `collator_selection` | 0 `set_authorities(set)` (`Root`)                        |
//! | 4     | `compute`            | 0 `request { spec, fee, timeout }` (signed)              |
//! | 5     | `model_registry`     | 0 `register(spec, weights)`, 1 `fine_tune(model, dataset, max_budget, fee)`, 2 `publish(model, weights)` (signed) |
//! | 6     | `remark`             | 0 `remark(data)` (signed)                                |
//!
//! `compute.request` asks the Hub compute market for a job paid from the signer's balance; its
//! `ComputeRequest` leaves in the block's outbox and the job's result comes back as a `compute`
//! event (`tog_runtime_modules::compute::Event`); `tog_v1_query("compute_job", job_id)` reads an
//! open job.
//!
//! `model_registry.fine_tune` asks for a job from the model's registered `JobSpec` with the model's
//! current weights and the dataset as inputs, and names the module's `on_compute_result` hook as
//! the callback: a settled job's sealed output archive becomes the model's pending version
//! ([`model_registry::on_result`]), and the owner `publish`es it, opened and stored, as the next.
//!
//! `remark` records a note as an event. It is also the module other AppChains reach: a CGMP `Call`
//! to `tog/remark` runs `remark` here for the sending chain (§4.6), and no other module takes one.
//!
//! `sudo` is optional (§7.5): a chain without it drops module 1 and sets no `root_key`. Here the
//! genesis [`GenesisConfig::root_key`] is its only `Root` source, as the templates ship it.
//!
//! Call weights are benchmarks (§6), in [`weights`]: `tog-collator bench` measures them on this
//! runtime's Wasm and writes that file. A chain that changes a call runs it again. The
//! `model_registry` and `remark` weights are provisional, declared on their calls: `tog bench` measures modules
//! 0 to 4 only.

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use tog_runtime_core::metadata::RuntimeMetadata;
use tog_runtime_core::{AccountId, Balance, ChainId, DispatchError, Hash32, ModuleError, Origin, Weight};
use tog_runtime_io::crypto::HostCheck;
use tog_runtime_io::{export_entry, HostEnv};
use tog_runtime_modules::executive::{self, Call, Context, Runtime, Scoped};
use tog_runtime_modules::{balances, collator_selection, compute, remark, sudo, system};
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
/// Module index of `model_registry`.
pub const MODEL_REGISTRY: u8 = 5;
/// Module index of `remark`.
pub const REMARK: u8 = 6;

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

/// A chain's own module (§4.1, §13): models fine-tuned by jobs on the compute market.
///
/// An owner registers a model as the `JobSpec` that trains it and its current weights. Each
/// `fine_tune` asks for one job from that spec, with inputs `base` (the weights) and `data` (the
/// dataset), paid by the owner from their balance; the job's id maps to the model until its result
/// comes back to [`on_result`]. Workers stage a job's inputs from their deals, so the weights and
/// the dataset each name one.
///
/// A settled job's output archive is sealed under the job's last checkpoint key (TOG-SPEC-0004
/// §9.1), and a job takes no sealed input, so it can't train the next job as it is. It becomes the
/// model's pending version: the owner opens it (the key is in the Hub's `released_keys`), stores
/// the plaintext in a deal and `publish`es it, which the chain takes only if its root is the
/// sealed archive's `plaintext_root`: exactly the job's weights.
#[tog_runtime_modules::tog_module]
pub mod model_registry {
    use alloc::vec;

    use borsh::{BorshDeserialize, BorshSerialize};
    use tog_runtime_core::env::Env;
    use tog_runtime_core::{
        AccountId, Amount, Hash32, Origin, Storage, StorageError, StorageMap, StorageValue, Weight,
    };
    use tog_runtime_modules::cgmp::SendError;
    use tog_runtime_modules::compute;
    use tog_runtime_modules::executive::{Context, Scoped};
    use tog_types::job::{InputRef, JobSpec, ModuleId, PayloadRef};
    use tog_types::payload::{Encryption, PayloadCommitment};
    use tog_types::state::JobOutcome;

    /// The module as a compute callback's target.
    pub const CALLBACK: ModuleId = ModuleId(*b"model_registry\0\0");
    /// The callback's call: [`on_result`].
    pub const ON_RESULT: u16 = 0;
    /// Most weight [`on_result`] uses: provisional, like the calls'.
    pub const ON_RESULT_WEIGHT: Weight = Weight::from_parts(120_000_000, 2_000);
    /// Largest spec a model may have: a job transaction holds it and at most `MAX_JOB_TX_BYTES`.
    pub const MAX_SPEC_BYTES: usize = tog_types::admission::MAX_JOB_TX_BYTES;
    /// Mount name of a model's weights in its jobs.
    pub const BASE_INPUT: &str = "base";
    /// Mount name of the dataset in a model's jobs.
    pub const DATA_INPUT: &str = "data";
    /// Hub blocks a fine-tuning job may wait for its executor, from the relay parent: its
    /// `claim_deadline_height`, whatever the registered spec says, so a model stays trainable
    /// after an era (the Hub takes a deadline at most an era ahead, C-37).
    pub const CLAIM_WINDOW: u64 = 600;

    /// A version a job trained that the owner hasn't published yet.
    #[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    pub struct Pending {
        /// The job.
        pub job_id: Hash32,
        /// Its output archive, sealed.
        pub sealed: PayloadCommitment,
    }

    impl Pending {
        /// The root the published weights must have: the sealed archive's plaintext.
        pub fn plaintext_root(&self) -> Hash32 {
            match self.sealed.encryption {
                Encryption::Checkpoint { plaintext_root, .. } => plaintext_root,
                _ => self.sealed.root,
            }
        }
    }

    /// A registered model.
    #[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    pub struct Model {
        /// Who fine-tunes it.
        pub owner: AccountId,
        /// The job that trains it; `fine_tune` replaces its inputs and `fee.max_budget`.
        pub spec: JobSpec,
        /// Its current weights, plaintext in a deal.
        pub weights: PayloadRef,
        /// How many versions were published after the first.
        pub version: u32,
        /// The last settled job's weights, until the owner publishes them.
        pub pending: Option<Pending>,
    }

    /// Each model by id.
    #[storage]
    pub type Models = StorageMap<u64, Model>;
    /// The next model's id.
    #[storage]
    pub type NextModel = StorageValue<u64>;
    /// The model each open job fine-tunes.
    #[storage]
    pub type Training = StorageMap<Hash32, u64>;

    /// The module's events, `borsh` in the block's events under module `"model_registry"`.
    #[event]
    pub enum Event {
        /// `model` was registered by `owner`.
        Registered {
            /// The model.
            model: u64,
            /// Its owner.
            owner: AccountId,
        },
        /// A job fine-tunes `model`; its `ComputeRequest` is in this block's outbox.
        FineTuning {
            /// The model.
            model: u64,
            /// The job.
            job_id: Hash32,
        },
        /// A job settled: its sealed output archive is `model`'s pending version.
        Trained {
            /// The model.
            model: u64,
            /// The job.
            job_id: Hash32,
            /// Its output archive, sealed.
            sealed: PayloadCommitment,
        },
        /// The owner published the pending weights: `weights` is `model`'s version `version`.
        NewVersion {
            /// The model.
            model: u64,
            /// Its new version.
            version: u32,
            /// Its new weights.
            weights: PayloadRef,
        },
        /// A job ended without new weights; the model keeps its own.
        NotTrained {
            /// The model.
            model: u64,
            /// The job.
            job_id: Hash32,
            /// How it ended.
            outcome: JobOutcome,
        },
    }

    /// Why a call failed; its index is the module error index.
    #[error]
    pub enum Error {
        /// The call needs a signed origin.
        BadOrigin,
        /// No model has the id.
        UnknownModel,
        /// Only the model's owner may fine-tune it.
        NotOwner,
        /// [`compute::MAX_OUTSTANDING_JOBS`] are open.
        TooManyJobs,
        /// The owner can't pay the budget, the inclusion fee and the message fee.
        InsufficientBalance,
        /// The message fee is below the Hub's minimum.
        FeeBelowHubMinimum,
        /// The request couldn't be sent.
        SendFailed,
        /// Stored state doesn't decode.
        Storage(StorageError),
        /// The owner has [`compute::MAX_OPEN_JOBS_PER_PAYER`] open.
        TooManyJobsForPayer,
        /// The spec's job transaction would be over `MAX_JOB_TX_BYTES`: the Hub would refuse it.
        SpecTooLarge,
        /// The weights or the dataset aren't plaintext in a deal: workers couldn't stage them.
        NotStaged,
        /// The model has no pending version.
        NothingPending,
        /// The weights aren't the pending version's plaintext.
        NotThePending,
    }

    impl From<compute::Error> for Error {
        fn from(e: compute::Error) -> Self {
            match e {
                compute::Error::TooManyJobs => Error::TooManyJobs,
                compute::Error::TooManyJobsForPayer => Error::TooManyJobsForPayer,
                compute::Error::SpecTooLarge => Error::SpecTooLarge,
                compute::Error::Send(SendError::Balance(_)) => Error::InsufficientBalance,
                compute::Error::Send(SendError::FeeBelowHubMinimum { .. }) => Error::FeeBelowHubMinimum,
                compute::Error::Send(SendError::Storage) | compute::Error::Storage => {
                    Error::Storage(StorageError::Corrupt)
                }
                compute::Error::Send(_) => Error::SendFailed,
            }
        }
    }

    fn signed(origin: Origin) -> Result<AccountId, Error> {
        match origin {
            Origin::Signed(who) => Ok(who),
            _ => Err(Error::BadOrigin),
        }
    }

    /// Whether a job can stage `p`: plaintext (the Hub refuses sealed inputs), in a deal.
    fn staged(p: &PayloadRef) -> Result<(), Error> {
        match (p.deal, &p.payload.encryption) {
            (Some(_), Encryption::None) => Ok(()),
            _ => Err(Error::NotStaged),
        }
    }

    /// The model `id`, if any.
    pub fn model(s: &mut impl Storage, id: u64) -> Result<Option<Model>, StorageError> {
        MODELS.get(s, &id)
    }

    /// `register(spec, weights)`: a new model owned by the signer, at version 0, its weights
    /// plaintext in a deal.
    #[call(index = 0, weight = crate::weights::MODEL_REGISTRY_REGISTER)]
    pub fn register<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        origin: Origin,
        spec: JobSpec,
        weights: PayloadRef,
    ) -> Result<(), Error> {
        let owner = signed(origin)?;
        staged(&weights)?;
        // A model whose jobs the Hub would refuse can't be fine-tuned; nor stored at any size.
        if borsh::object_length(&spec).map_err(|_| Error::SpecTooLarge)? > MAX_SPEC_BYTES {
            return Err(Error::SpecTooLarge);
        }
        let model = NEXT_MODEL.get_or_default(e)?;
        MODELS.insert(e, &model, &Model { owner, spec, weights, version: 0, pending: None })?;
        NEXT_MODEL.put(e, &(model + 1))?;
        Event::Registered { model, owner }.deposit(e);
        Ok(())
    }

    /// `fine_tune(model, dataset, max_budget, fee)`: one job on `dataset` (plaintext in a deal)
    /// from the model's spec and current weights, paid by the owner, with [`on_result`] as its
    /// callback. Its weight is measured on a model with the largest spec, the `compute.request` it
    /// makes included.
    #[call(index = 1, weight = crate::weights::MODEL_REGISTRY_FINE_TUNE)]
    pub fn fine_tune<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        model: u64,
        dataset: PayloadRef,
        max_budget: Amount,
        fee: Amount,
    ) -> Result<(), Error> {
        let who = signed(origin)?;
        staged(&dataset)?;
        let m = MODELS.get(e, &model)?.ok_or(Error::UnknownModel)?;
        if m.owner != who {
            return Err(Error::NotOwner);
        }
        let mut spec = m.spec;
        let input = |name: &str, content| InputRef { mount_name: name.into(), content, locators: vec![] };
        // Sorted by mount name.
        spec.inputs = vec![input(BASE_INPUT, m.weights), input(DATA_INPUT, dataset)];
        spec.fee.max_budget = max_budget;
        spec.fee.claim_deadline_height = cx.relay + CLAIM_WINDOW;
        let req = compute::Request { spec, callback: Some((CALLBACK, ON_RESULT)), fee, timeout: None };
        let handle = compute::request(e, cx.compute_env(), cx.relay, &who, req, cx.per_byte)?;
        e.outbox_push(&borsh::to_vec(&handle.message).expect("in-memory borsh"));
        TRAINING.insert(e, &handle.job_id, &model)?;
        let nonce = handle.message.channel_nonce;
        e.deposit_event("compute", &compute::Event::Requested { job_id: handle.job_id, payer: who, nonce });
        Event::FineTuning { model, job_id: handle.job_id }.deposit(e);
        Ok(())
    }

    /// `publish(model, weights)`, by the owner: the pending version, opened and stored plaintext
    /// in a deal, becomes the model's next version. Its root must be the sealed archive's
    /// `plaintext_root`.
    #[call(index = 2, weight = crate::weights::MODEL_REGISTRY_PUBLISH)]
    pub fn publish<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        origin: Origin,
        model: u64,
        weights: PayloadRef,
    ) -> Result<(), Error> {
        let who = signed(origin)?;
        staged(&weights)?;
        let mut m = MODELS.get(e, &model)?.ok_or(Error::UnknownModel)?;
        if m.owner != who {
            return Err(Error::NotOwner);
        }
        let pending = m.pending.as_ref().ok_or(Error::NothingPending)?;
        if weights.payload.root != pending.plaintext_root() {
            return Err(Error::NotThePending);
        }
        m.weights = weights;
        m.version += 1;
        m.pending = None;
        Event::NewVersion { model, version: m.version, weights: m.weights.clone() }.deposit(e);
        MODELS.insert(e, &model, &m)?;
        Ok(())
    }

    /// The `on_compute_result` hook of a `fine_tune` job, within [`ON_RESULT_WEIGHT`]: a settled
    /// job's output archive is the model's pending version, replacing any earlier one; any other
    /// end leaves the model as it was.
    pub fn on_result<E: Env>(e: &mut Scoped<'_, E>, done: &compute::Completed) -> Result<Weight, Error> {
        let job_id = done.result.job_id;
        let Some(model) = TRAINING.get(e, &job_id)? else { return Ok(ON_RESULT_WEIGHT) };
        TRAINING.remove(e, &job_id);
        let mut m = MODELS.get(e, &model)?.ok_or(Error::UnknownModel)?;
        match (&done.result.outcome, compute::output_archive(&done.result)) {
            (JobOutcome::Settled, Some(sealed)) => {
                m.pending = Some(Pending { job_id, sealed: sealed.clone() });
                Event::Trained { model, job_id, sealed: sealed.clone() }.deposit(e);
                MODELS.insert(e, &model, &m)?;
            }
            (outcome, _) => Event::NotTrained { model, job_id, outcome: *outcome }.deposit(e),
        }
        Ok(ON_RESULT_WEIGHT)
    }
}

use weights::{COMPUTE_REQUEST, COMPUTE_TAKE_RESULT, SET_AUTHORITIES, SUDO_CALL, TRANSFER, UPGRADE};

/// The template runtime.
pub struct Template;

/// `call`'s declared weight, or `None` for an unknown call or one with more than `depth` nested
/// `sudo.call`s (R-1).
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
        (MODEL_REGISTRY, c) => model_registry::call_weight(c, &call.2),
        (REMARK, c) => remark::call_weight(c, &call.2),
        _ => None,
    }
}

fn decode<T: BorshDeserialize>(b: &[u8]) -> Result<T, DispatchError> {
    borsh::from_slice(b).map_err(|_| DispatchError::Other("call arguments"))
}

impl Runtime for Template {
    const NAME: &'static str = "tog-runtime-template-compute";
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
            (MODEL_REGISTRY, c) => (model_registry::MODULE, model_registry::call_name(c)?),
            (REMARK, c) => (remark::MODULE, remark::call_name(c)?),
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
            (MODEL_REGISTRY, c) => return model_registry::dispatch(e, cx, MODEL_REGISTRY, origin, c, &call.2),
            (REMARK, c) => return remark::dispatch(e, cx, REMARK, origin, c, &call.2),
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
            (MODEL_REGISTRY, model_registry::metadata()),
            (REMARK, remark::metadata()),
        ];
        borsh::to_vec(&RuntimeMetadata::new(Self::NAME, Self::SPEC_VERSION, modules)).expect("metadata encodes")
    }

    fn cgmp_call_limit(module: ModuleId, call: &[u8]) -> Option<Weight> {
        if module != remark::CGMP_NAME || !remark::accepts(call) {
            return None;
        }
        remark::call_weight(remark::REMARK, &call[1..])
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
        let limit = Self::cgmp_call_limit(module, call)?;
        Some(remark::received(e, source, origin, call).map(|()| limit).map_err(|err| err.into_dispatch(REMARK)))
    }

    fn compute_callback_limit(module: ModuleId) -> Option<Weight> {
        (module == model_registry::CALLBACK).then_some(model_registry::ON_RESULT_WEIGHT)
    }

    fn on_compute_result<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        module: ModuleId,
        call: u16,
        done: &compute::Completed,
    ) -> Result<Weight, DispatchError> {
        if module != model_registry::CALLBACK || call != model_registry::ON_RESULT {
            return Err(DispatchError::Other("no compute callback"));
        }
        model_registry::on_result(e, done).map_err(|err| err.into_dispatch(MODEL_REGISTRY))
    }

    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        let c: GenesisConfig = borsh::from_slice(config).expect("genesis config decodes");
        for (who, amount) in &c.balances {
            balances::deposit(e, who, *amount).expect("genesis balance");
        }
        collator_selection::genesis(e, c.authorities).expect("genesis authorities");
        sudo::genesis(e, c.root_key).expect("genesis sudo key");
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
