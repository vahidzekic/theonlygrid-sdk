//! `compute`: jobs on the Hub compute market from this chain (TOG-SPEC-0007 §7.1, 0000 §8.1).
//!
//! [`request`] burns `max_budget`, the job's `inclusion_fee` and the message fee from the payer and
//! sends a `ComputeRequest` to the Hub ([`cgmp::send_paid`]); no `TransferTog` goes with it, since
//! the Hub takes `max_budget + inclusion_fee` from this chain's sovereign account when it admits
//! the request (and burns the `inclusion_fee`, as for any `SubmitJob`). This is the
//! spec's `open_escrow` and `request` in one step: the escrow is the request's own. The Hub opens the job's escrow out of this chain's sovereign
//! account, under the [`EscrowRef`] of the message (0000 §13.2), and the job's `job_id` follows from
//! the `JobTx` the Hub builds (0001 §3.5), so both are known here before the Hub answers.
//!
//! The job's callback always comes back to this module ([`MODULE`]): the result carries `charged`,
//! so the rest of `max_budget` goes back to the payer ([`on_result`]), and the application's own
//! callback, if it gave one, is returned to the runtime to dispatch. A request the Hub refuses
//! comes back as an `Ack` error, which [`cgmp::receive_ack`] refunds and [`on_ack`] closes.
//! A callback that fails doesn't undo anything: the runtime keeps the result with [`keep_result`]
//! for the application to take later.
//!
//! [`dispatch`] is the module's one call, `compute.request` (signed): what a runtime exposes so an
//! account requests a job in a transaction. Its [`Event`]s tell the job's story from outside: the
//! request, then its result or the Hub's refusal.
//!
//! There is no `cancel` in v1 (CGMP has no message for it): an unclaimed job ends at its claim
//! deadline with a full refund, which comes back through its `ComputeResult`.

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_runtime_core::dispatch::{ensure_signed, DispatchError, Origin};
use tog_runtime_core::env::Env as HostEnv;
use tog_runtime_core::{
    AccountId, Amount, ChainId, Hash32, HubHeight, Storage, StorageError, StorageMap, StorageValue,
};
use tog_types::cgmp::{CgmpMessage, CgmpPayload, ComputeResult, WorkerSlashed};
use tog_types::job::{CallbackRef, EscrowOrigin, EscrowRef, JobSpec, JobTx, ModuleId};
use tog_types::payload::PayloadCommitment;

use crate::cgmp::{self, Acked, SendError};
use crate::executive::{Context, Scoped};
use crate::storage_deposit;

/// This module, as the Hub's callback target.
pub const MODULE: ModuleId = ModuleId(*b"tog/compute\0\0\0\0\0");
/// The callback's call index: a `ComputeResult`.
pub const RESULT_CALL: u16 = 0;
/// `MaxOutstandingJobs`: open requests at most.
pub const MAX_OUTSTANDING_JOBS: u32 = 10_000;
/// `MaxOpenJobsPerPayer`: open requests one payer may have, so one account can't take every one
/// of the chain's [`MAX_OUTSTANDING_JOBS`].
pub const MAX_OPEN_JOBS_PER_PAYER: u32 = 64;

/// An open job.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Job {
    /// Who paid `max_budget`.
    pub payer: AccountId,
    /// What the payer paid into the escrow.
    pub max_budget: Amount,
    /// Nonce of the `ComputeRequest` on the channel to the Hub.
    pub nonce: u64,
    /// The application's callback: its module and call.
    pub callback: Option<(ModuleId, u16)>,
}

/// `compute.jobs: job_id → Job`, the open jobs.
pub const JOBS: StorageMap<Hash32, Job> = StorageMap::new("compute", "jobs");
/// `compute.by_nonce: u64 → job_id`, open requests the Hub hasn't acked yet.
pub const BY_NONCE: StorageMap<u64, Hash32> = StorageMap::new("compute", "by_nonce");
/// `compute.outstanding`: the number of [`JOBS`].
pub const OUTSTANDING: StorageValue<u32> = StorageValue::new("compute", "outstanding");
/// `compute.open_by_payer: payer → n`, each payer's number of [`JOBS`] (absent = 0).
pub const OPEN_BY_PAYER: StorageMap<AccountId, u32> = StorageMap::new("compute", "open_by_payer");
/// `compute.results: job_id → ComputeResult`, results kept for the application.
pub const RESULTS: StorageMap<Hash32, ComputeResult> = StorageMap::new("compute", "results");

/// Where the runtime runs: its chain, and the network whose Hub takes the job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Env {
    /// This chain.
    pub chain: ChainId,
    /// The Hub genesis's `network_id` (0000 §13.2).
    pub network_id: u32,
}

/// A job to request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The job; `spec.fee.max_budget` is what the payer pays into the escrow.
    pub spec: JobSpec,
    /// The application's callback.
    pub callback: Option<(ModuleId, u16)>,
    /// The message fee.
    pub fee: Amount,
    /// Hub height after which the request is refunded, not admitted; `None` for the SDK default,
    /// the relay parent's height plus [`cgmp::DEFAULT_TIMEOUT`] (§4.6).
    pub timeout: Option<HubHeight>,
}

/// A requested job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobHandle {
    /// Its id on the Hub.
    pub job_id: Hash32,
    /// Its escrow on the Hub.
    pub escrow: EscrowRef,
    /// The `ComputeRequest`, for `outbox_push`.
    pub message: CgmpMessage,
}

/// Why a request failed. Nothing changes on error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// [`MAX_OUTSTANDING_JOBS`] are open.
    TooManyJobs,
    /// The payer has [`MAX_OPEN_JOBS_PER_PAYER`] open.
    TooManyJobsForPayer,
    /// The message couldn't be paid or sent.
    Send(SendError),
    /// Stored state doesn't decode.
    Storage,
    /// The job transaction the Hub would build is over `MAX_JOB_TX_BYTES`, which the Hub refuses
    /// (0001 §3.4 step 1); refused here so a request's work stays within its declared weight.
    SpecTooLarge,
}

impl From<StorageError> for Error {
    fn from(_: StorageError) -> Self {
        Error::Storage
    }
}

impl From<SendError> for Error {
    fn from(e: SendError) -> Self {
        Error::Send(e)
    }
}

/// The `JobTx` the Hub builds from a `ComputeRequest` of `env.chain` with nonce `nonce` (0001 §3.5).
pub fn job_tx(env: Env, nonce: u64, timeout_height: HubHeight, spec: JobSpec) -> JobTx {
    JobTx {
        chain_id: u64::from(env.network_id) << 32,
        sender: env.chain.sovereign_address(),
        nonce,
        valid_until_height: timeout_height,
        origin: env.chain,
        escrow: escrow(env.chain, nonce),
        callback: Some(CallbackRef { chain: env.chain, module: MODULE, call: RESULT_CALL }),
        spec,
    }
}

/// The escrow a `ComputeRequest` with nonce `nonce` opens: the message's first.
pub fn escrow(chain: ChainId, nonce: u64) -> EscrowRef {
    EscrowRef::derive(&EscrowOrigin::Cgmp { source: chain, channel_nonce: nonce, index: 0 })
}

/// Request a job paid by `payer` in one step (§7.1): burn `spec.fee.max_budget`,
/// `spec.fee.inclusion_fee` and `fee` from `payer` and send one `ComputeRequest`, which opens the
/// escrow; `job_id` and the escrow are known before the Hub answers. `h` is the relay parent's
/// height. The Hub takes `max_budget + inclusion_fee` from the sovereign account, so the payer
/// pays both here; a refused request mints both back ([`cgmp::receive_ack`]), a result mints back
/// `max_budget − charged` ([`on_result`]).
pub fn request(
    s: &mut impl Storage,
    env: Env,
    h: HubHeight,
    payer: &AccountId,
    req: Request,
    per_byte: Amount,
) -> Result<JobHandle, Error> {
    let open = OUTSTANDING.get_or_default(s)?;
    if open >= MAX_OUTSTANDING_JOBS {
        return Err(Error::TooManyJobs);
    }
    let mine = OPEN_BY_PAYER.get_or_default(s, payer)?;
    if mine >= MAX_OPEN_JOBS_PER_PAYER {
        return Err(Error::TooManyJobsForPayer);
    }
    let nonce = cgmp::next_nonce(s, ChainId::HUB)?;
    let timeout_height = cgmp::timeout_height(h, req.timeout);
    let tx = job_tx(env, nonce, timeout_height, req.spec);
    if borsh::object_length(&tx).map_err(|_| Error::Storage)? > tog_types::admission::MAX_JOB_TX_BYTES {
        return Err(Error::SpecTooLarge);
    }
    let (job_id, escrow, max_budget) = (tx.job_id(), tx.escrow, tx.spec.fee.max_budget);
    let paid = max_budget
        .checked_add(tx.spec.fee.inclusion_fee)
        .ok_or(SendError::Balance(crate::balances::Error::Overflow))?;
    let payload = CgmpPayload::ComputeRequest { spec: Box::new(tx.spec), escrow, callback: tx.callback };
    let job = Job { payer: *payer, max_budget, nonce, callback: req.callback };
    // The job's records hold the payer's storage deposit until it closes (§5, R-6).
    let deposit = |s: &mut _, key, len| storage_deposit::charge(s, &key, payer, len, per_byte).map_err(deposit_error);
    deposit(s, JOBS.key(&job_id), borsh::object_length(&job).map_err(|_| Error::Storage)? as u64)?;
    if let Err(e) = deposit(s, BY_NONCE.key(&nonce), 32) {
        storage_deposit::release(s, &JOBS.key(&job_id)).map_err(deposit_error)?;
        return Err(e);
    }
    let message = match cgmp::send_paid(s, env.chain, payer, paid, req.fee, timeout_height, payload, per_byte) {
        Ok(m) => m,
        Err(e) => {
            storage_deposit::release(s, &JOBS.key(&job_id)).map_err(deposit_error)?;
            storage_deposit::release(s, &BY_NONCE.key(&nonce)).map_err(deposit_error)?;
            return Err(e.into());
        }
    };
    debug_assert_eq!(message.channel_nonce, nonce);
    JOBS.insert(s, &job_id, &job)?;
    BY_NONCE.insert(s, &nonce, &job_id)?;
    OUTSTANDING.put(s, &(open + 1))?;
    OPEN_BY_PAYER.insert(s, payer, &(mine + 1))?;
    Ok(JobHandle { job_id, escrow, message })
}

/// The module's call (`borsh` arguments of its call index 0).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Call {
    /// `request { spec, fee, timeout }`: [`request`] paid by the signer, without an application
    /// callback; the job's result comes back as [`Event::Completed`].
    Request {
        /// The job.
        spec: JobSpec,
        /// The message fee, at least the Hub's minimum for it.
        fee: Amount,
        /// [`Request::timeout`].
        timeout: Option<HubHeight>,
    },
}

/// The module's call index of `request`.
pub const REQUEST: u8 = 0;
/// The module's call index of `take_result`; its arguments are the `job_id` (`Hash32`).
pub const TAKE_RESULT: u8 = 1;

/// The module's metadata; its errors as [`dispatch_error`] numbers them.
pub fn metadata() -> tog_runtime_core::metadata::ModuleMetadata {
    tog_runtime_core::metadata::ModuleMetadata::from_names(
        "compute",
        &[
            (REQUEST, "request", &[("spec", "JobSpec"), ("fee", "Amount"), ("timeout", "Option<HubHeight>")]),
            (TAKE_RESULT, "take_result", &[("job_id", "Hash32")]),
        ],
        &["jobs", "by_nonce", "outstanding", "results", "open_by_payer"],
        &["Requested", "Completed", "Refused", "WorkerSlashed", "ResultTaken"],
        &[
            "TooManyJobs",
            "InsufficientBalance",
            "FeeBelowHubMinimum",
            "SendFailed",
            "TooManyJobsForPayer",
            "NoKeptResult",
            "SpecTooLarge",
        ],
    )
}

/// The module's events, `borsh` in the block's events under module `"compute"`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Event {
    /// A job was requested: its `ComputeRequest` is in this block's outbox.
    Requested {
        /// Its id on the Hub.
        job_id: Hash32,
        /// Who paid.
        payer: AccountId,
        /// Nonce of its `ComputeRequest` on the channel to the Hub.
        nonce: u64,
    },
    /// The job's result arrived and the rest of its budget went back to the payer.
    Completed {
        /// The result.
        result: ComputeResult,
        /// What went back to the payer.
        refunded: Amount,
    },
    /// The Hub refused the request; the payer got the budget back.
    Refused {
        /// The job.
        job_id: Hash32,
    },
    /// The Hub slashed a worker this chain's allowlist lists (TOG-SPEC-0000 §5.5); the runtime's
    /// `on_worker_slashed` hook runs after it.
    WorkerSlashed(WorkerSlashed),
    /// Its payer took a kept result ([`TAKE_RESULT`]) and got its deposit back.
    ResultTaken {
        /// The job.
        job_id: Hash32,
    },
}

/// The `DispatchError` of `e` for this module at index `module` in the runtime: `Module` errors
/// 0 [`Error::TooManyJobs`], 1 the payer can't pay, 2 the fee is below the Hub's minimum, 3 any
/// other send failure, 4 [`Error::TooManyJobsForPayer`]; 5 is `take_result`'s: no result kept for
/// that job paid by the signer.
pub fn dispatch_error(e: Error, module: u8) -> DispatchError {
    let error = match e {
        Error::TooManyJobs => 0,
        Error::TooManyJobsForPayer => 4,
        Error::SpecTooLarge => 6,
        Error::Send(SendError::Balance(_)) => 1,
        Error::Send(SendError::FeeBelowHubMinimum { .. }) => 2,
        Error::Send(SendError::Storage) | Error::Storage => return DispatchError::Other("compute storage"),
        Error::Send(_) => 3,
    };
    DispatchError::Module { module, error }
}

/// Dispatch `call` from `origin` (signed) in block context `cx`: [`request`] with storage deposits
/// at `per_byte`, its `ComputeRequest` pushed to the outbox and [`Event::Requested`] deposited.
/// `module` is this module's index in the runtime.
pub fn dispatch<E: HostEnv>(
    e: &mut Scoped<'_, E>,
    cx: &Context,
    module: u8,
    origin: Origin,
    call: Call,
    per_byte: Amount,
) -> Result<JobHandle, DispatchError> {
    let payer = ensure_signed(origin)?;
    let Call::Request { spec, fee, timeout } = call;
    let req = Request { spec, callback: None, fee, timeout };
    let handle =
        request(e, cx.compute_env(), cx.relay, &payer, req, per_byte).map_err(|err| dispatch_error(err, module))?;
    e.outbox_push(&borsh::to_vec(&handle.message).expect("in-memory borsh"));
    let nonce = handle.message.channel_nonce;
    e.deposit_event("compute", &Event::Requested { job_id: handle.job_id, payer, nonce });
    Ok(handle)
}

/// Dispatch `take_result(job_id)` from `origin`: the payer of a result kept for `job_id`
/// ([`keep_result`]) removes it and gets its deposit back (§5), with [`Event::ResultTaken`]. The
/// result itself was in the block's events when it arrived. `module` is this module's index.
pub fn dispatch_take_result<E: HostEnv>(
    e: &mut Scoped<'_, E>,
    module: u8,
    origin: Origin,
    job_id: Hash32,
) -> Result<(), DispatchError> {
    let who = ensure_signed(origin)?;
    let storage = |_| DispatchError::Other("compute storage");
    match storage_deposit::DEPOSITS.get(e, &RESULTS.key(&job_id)).map_err(storage)? {
        Some((payer, _)) if payer == who => {}
        _ => return Err(DispatchError::Module { module, error: 5 }),
    }
    take_result(e, &job_id).map_err(storage)?;
    e.deposit_event("compute", &Event::ResultTaken { job_id });
    Ok(())
}

/// A job that ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completed {
    /// The job.
    pub job: Job,
    /// Its result, for the application's callback.
    pub result: ComputeResult,
    /// What went back to the payer: `max_budget − charged`.
    pub refunded: Amount,
}

/// Close the job of a `ComputeResult` from the Hub, after `cgmp::accept`, and refund the rest of its
/// budget. `None` when `m` isn't one or its job isn't open here.
pub fn on_result(s: &mut impl Storage, m: &CgmpMessage) -> Result<Option<Completed>, crate::balances::Error> {
    let CgmpPayload::ComputeResult(result) = &m.payload else { return Ok(None) };
    if m.source != ChainId::HUB {
        return Ok(None);
    }
    let Some(job) = close(s, &result.job_id)? else { return Ok(None) };
    let refunded = job.max_budget.saturating_sub(result.charged);
    crate::balances::deposit(s, &job.payer, refunded)?;
    Ok(Some(Completed { job, result: result.clone(), refunded }))
}

/// The commitment of a result's output archive (0000 §7.2 "`ComputeResult` fields"): `outputs` is
/// empty or the one entry `("", archive)`. Anything else, including reserved non-empty paths, gives
/// `None`; settlement doesn't depend on it.
pub fn output_archive(result: &ComputeResult) -> Option<&PayloadCommitment> {
    match result.outputs.as_slice() {
        [(path, archive)] if path.is_empty() => Some(archive),
        _ => None,
    }
}

/// Follow up [`cgmp::receive_ack`]: a request the Hub took is admitted and waits for its result; one
/// it refused is closed (its payer is already refunded). Returns the refused job's id.
pub fn on_ack(s: &mut impl Storage, acked: &Acked) -> Result<Option<Hash32>, StorageError> {
    match *acked {
        Acked::Taken { nonce } => {
            BY_NONCE.remove(s, &nonce);
            storage_deposit::release(s, &BY_NONCE.key(&nonce)).map_err(|_| StorageError::Corrupt)?;
            Ok(None)
        }
        Acked::Refunded { nonce, .. } => {
            let Some(job_id) = BY_NONCE.get(s, &nonce)? else { return Ok(None) };
            close(s, &job_id)?;
            Ok(Some(job_id))
        }
    }
}

/// Remove an open job.
fn close(s: &mut impl Storage, job_id: &Hash32) -> Result<Option<Job>, StorageError> {
    let Some(job) = JOBS.take(s, job_id)? else { return Ok(None) };
    BY_NONCE.remove(s, &job.nonce);
    storage_deposit::release(s, &JOBS.key(job_id)).map_err(|_| StorageError::Corrupt)?;
    storage_deposit::release(s, &BY_NONCE.key(&job.nonce)).map_err(|_| StorageError::Corrupt)?;
    OUTSTANDING.mutate(s, |n| *n = n.saturating_sub(1))?;
    match OPEN_BY_PAYER.get_or_default(s, &job.payer)? {
        0 | 1 => OPEN_BY_PAYER.remove(s, &job.payer),
        n => OPEN_BY_PAYER.insert(s, &job.payer, &(n - 1))?,
    }
    Ok(Some(job))
}

fn deposit_error(e: storage_deposit::Error) -> Error {
    match e {
        storage_deposit::Error::InsufficientBalance => {
            Error::Send(SendError::Balance(crate::balances::Error::InsufficientBalance))
        }
        storage_deposit::Error::Storage => Error::Storage,
    }
}

/// Keep a result whose callback failed, for the application to take later, with `payer`'s storage
/// deposit at `per_byte` (§5). A payer who can't cover it gets no kept result: the result is in
/// the block's events all the same. Returns whether it was kept.
pub fn keep_result(
    s: &mut impl Storage,
    payer: &AccountId,
    result: &ComputeResult,
    per_byte: Amount,
) -> Result<bool, StorageError> {
    match storage_deposit::insert(s, &RESULTS, &result.job_id, result, payer, per_byte) {
        Ok(()) => Ok(true),
        Err(storage_deposit::Error::InsufficientBalance) => Ok(false),
        Err(storage_deposit::Error::Storage) => Err(StorageError::Corrupt),
    }
}

/// Take a kept result, returning its deposit.
pub fn take_result(s: &mut impl Storage, job_id: &Hash32) -> Result<Option<ComputeResult>, StorageError> {
    let r = RESULTS.take(s, job_id)?;
    storage_deposit::release(s, &RESULTS.key(job_id)).map_err(|_| StorageError::Corrupt)?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{balances, cgmp::TO_HUB};
    use tog_runtime_core::memory::MemoryStorage;
    use tog_types::cgmp::{CgmpError, CgmpOrigin};
    use tog_types::state::JobOutcome;
    use tog_types::testing::sample_spec;

    const ENV: Env = Env { chain: ChainId(9), network_id: 7 };
    const PAYER: AccountId = [1; 20];
    /// A message fee above the Hub's minimum.
    const FEE: Amount = 10_000_000_000_000_000;

    /// The job's `inclusion_fee`, which the Hub burns out of the sovereign account.
    const INCLUSION: Amount = 50;

    fn spec(budget: Amount) -> JobSpec {
        let mut spec = sample_spec();
        spec.fee.max_budget = budget;
        spec.fee.inclusion_fee = INCLUSION;
        spec
    }

    fn req(budget: Amount) -> Request {
        Request { spec: spec(budget), callback: Some((ModuleId([4; 16]), 2)), fee: FEE, timeout: Some(100) }
    }

    fn from_hub(payload: CgmpPayload) -> CgmpMessage {
        CgmpMessage {
            version: tog_types::cgmp::CGMP_VERSION,
            source: ChainId::HUB,
            dest: ENV.chain,
            channel_nonce: 0,
            timeout_height: u64::MAX,
            fee: 0,
            origin: CgmpOrigin::Chain(ChainId::HUB),
            payload,
        }
    }

    fn result(job_id: Hash32, charged: Amount) -> ComputeResult {
        ComputeResult {
            job_id,
            outcome: JobOutcome::Settled,
            receipt_root: [3; 32],
            outputs: vec![],
            work_units: 10,
            charged,
        }
    }

    fn funded() -> MemoryStorage {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &PAYER, 1_000 + 3 * (FEE + INCLUSION)).unwrap();
        s
    }

    /// A job's records, its message's and a kept result's hold the payer's storage deposits until
    /// they go (R-6); a payer who can't cover a kept result's gets none kept.
    #[test]
    fn a_job_holds_deposits_until_it_closes_and_a_kept_result_until_taken() {
        let per_byte = storage_deposit::DEFAULT_PER_BYTE;
        let job = Job { payer: PAYER, max_budget: 0, nonce: 0, callback: Some((ModuleId([4; 16]), 2)) };
        let held = |len: u64| storage_deposit::deposit_for(len, per_byte).unwrap();
        let job_held = held(borsh::object_length(&job).unwrap() as u64) + held(32) + held(cgmp::TO_HUB_BYTES);
        let reserved = |s: &mut MemoryStorage| balances::account(s, &PAYER).unwrap().reserved;
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &PAYER, 300 + FEE + INCLUSION + job_held).unwrap();
        let h = request(&mut s, ENV, 10, &PAYER, req(300), per_byte).unwrap();
        assert_eq!((reserved(&mut s), balances::free_balance(&mut s, &PAYER).unwrap()), (job_held, 0));

        // The Hub takes it: the message's and the nonce index's deposits come back.
        let taken = cgmp::receive_ack(&mut s, &from_hub(CgmpPayload::Ack { of_nonce: 0, result: Ok(()) })).unwrap();
        on_ack(&mut s, &taken.unwrap()).unwrap();
        assert_eq!(reserved(&mut s), held(borsh::object_length(&job).unwrap() as u64));

        // The result closes the job and the rest comes back. Its callback failed, so it is kept,
        // which the payer, having spent it all, can't cover.
        let done = on_result(&mut s, &from_hub(CgmpPayload::ComputeResult(result(h.job_id, 300)))).unwrap().unwrap();
        assert_eq!((reserved(&mut s), balances::free_balance(&mut s, &PAYER).unwrap()), (0, job_held));
        balances::withdraw(&mut s, &PAYER, job_held).unwrap();
        assert_eq!(keep_result(&mut s, &PAYER, &done.result, per_byte), Ok(false));
        assert_eq!(take_result(&mut s, &h.job_id), Ok(None));
        // Funded, it is kept until taken.
        let kept = held(borsh::object_length(&done.result).unwrap() as u64);
        balances::deposit(&mut s, &PAYER, kept).unwrap();
        assert_eq!(keep_result(&mut s, &PAYER, &done.result, per_byte), Ok(true));
        assert_eq!(reserved(&mut s), kept);
        assert_eq!(take_result(&mut s, &h.job_id), Ok(Some(done.result)));
        assert_eq!((reserved(&mut s), balances::free_balance(&mut s, &PAYER).unwrap()), (0, kept));

        // Short of the job's deposits: nothing is sent or reserved.
        let mut poor = MemoryStorage::default();
        balances::deposit(&mut poor, &PAYER, 300 + FEE + INCLUSION).unwrap();
        assert_eq!(
            request(&mut poor, ENV, 10, &PAYER, req(300), per_byte),
            Err(Error::Send(SendError::Balance(balances::Error::InsufficientBalance)))
        );
        assert_eq!((reserved(&mut poor), cgmp::next_nonce(&mut poor, ChainId::HUB)), (0, Ok(0)));
        assert!(storage_deposit::DEPOSITS.get(&mut poor, &JOBS.key(&h.job_id)).unwrap().is_none());
    }

    #[test]
    fn the_default_timeout_is_600_hub_blocks_after_the_relay_parent() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &PAYER, 1_000 + FEE + INCLUSION).unwrap();
        let h = request(&mut s, ENV, 10, &PAYER, Request { timeout: None, ..req(300) }, 0).unwrap();
        assert_eq!(h.message.timeout_height, 610);
    }

    #[test]
    fn a_request_pays_the_budget_and_names_the_job_the_hub_will_build() {
        let mut s = funded();
        let h = request(&mut s, ENV, 10, &PAYER, req(300), 0).unwrap();
        let left = 700 + 2 * FEE + 2 * INCLUSION;
        assert_eq!(balances::free_balance(&mut s, &PAYER).unwrap(), left);
        assert_eq!(balances::total_issuance(&mut s).unwrap(), left, "budget, inclusion fee and fee leave the chain");

        let CgmpPayload::ComputeRequest { spec: sent, escrow, callback } = &h.message.payload else { panic!() };
        assert_eq!((h.message.dest, h.message.fee, h.message.timeout_height), (ChainId::HUB, FEE, 100));
        assert_eq!(*callback, Some(CallbackRef { chain: ENV.chain, module: MODULE, call: RESULT_CALL }));
        // The Hub's JobTx for this message (0001 §3.5) has the id the chain recorded.
        let hub_tx = JobTx {
            chain_id: 7 << 32,
            sender: ENV.chain.sovereign_address(),
            nonce: h.message.channel_nonce,
            valid_until_height: h.message.timeout_height,
            origin: ENV.chain,
            escrow: *escrow,
            callback: callback.clone(),
            spec: (**sent).clone(),
        };
        assert_eq!(hub_tx.job_id(), h.job_id);
        assert_eq!(*escrow, EscrowRef::derive(&EscrowOrigin::Cgmp { source: ENV.chain, channel_nonce: 0, index: 0 }));
        assert_eq!(JOBS.get(&mut s, &h.job_id).unwrap().unwrap().callback, Some((ModuleId([4; 16]), 2)));
        assert_eq!(TO_HUB.get(&mut s, &0).unwrap().unwrap().amount, 300 + INCLUSION, "what the Hub takes");

        // The same spec again is another job.
        let h2 = request(&mut s, ENV, 10, &PAYER, req(300), 0).unwrap();
        assert_ne!(h2.job_id, h.job_id);
        assert_eq!(OUTSTANDING.get(&mut s).unwrap(), Some(2));

        // Unpaid: nothing recorded.
        assert_eq!(
            request(&mut s, ENV, 10, &PAYER, req(1_000), 0),
            Err(Error::Send(SendError::Balance(balances::Error::InsufficientBalance)))
        );
        assert_eq!(OUTSTANDING.get(&mut s).unwrap(), Some(2));
    }

    #[test]
    fn the_result_refunds_what_the_job_did_not_spend() {
        let mut s = funded();
        let h = request(&mut s, ENV, 10, &PAYER, req(300), 0).unwrap();
        let ack = cgmp::receive_ack(&mut s, &from_hub(CgmpPayload::Ack { of_nonce: 0, result: Ok(()) })).unwrap();
        assert_eq!(on_ack(&mut s, &ack.unwrap()), Ok(None));
        assert!(!BY_NONCE.contains_key(&mut s, &0));

        let done = on_result(&mut s, &from_hub(CgmpPayload::ComputeResult(result(h.job_id, 120)))).unwrap().unwrap();
        assert_eq!((done.refunded, done.job.callback), (180, Some((ModuleId([4; 16]), 2))));
        // The inclusion fee is the Hub's, burned there.
        assert_eq!(balances::free_balance(&mut s, &PAYER).unwrap(), 880 + 2 * FEE + 2 * INCLUSION);
        assert_eq!(OUTSTANDING.get(&mut s).unwrap(), Some(0));

        // Once only, and only from the Hub.
        let again = from_hub(CgmpPayload::ComputeResult(result(h.job_id, 0)));
        assert_eq!(on_result(&mut s, &again), Ok(None));
        let h2 = request(&mut s, ENV, 10, &PAYER, req(100), 0).unwrap();
        let mut forged = from_hub(CgmpPayload::ComputeResult(result(h2.job_id, 0)));
        forged.source = ChainId(3);
        assert_eq!(on_result(&mut s, &forged), Ok(None));

        // A failed callback leaves the result for later.
        keep_result(&mut s, &PAYER, &done.result, 0).unwrap();
        assert_eq!(take_result(&mut s, &h.job_id), Ok(Some(done.result)));
        assert_eq!(take_result(&mut s, &h.job_id), Ok(None));
    }

    #[test]
    fn a_refused_request_is_refunded_and_closed() {
        let mut s = funded();
        let h = request(&mut s, ENV, 10, &PAYER, req(300), 0).unwrap();
        let refused = from_hub(CgmpPayload::Ack { of_nonce: 0, result: Err(CgmpError::DispatchFailed) });
        let ack = cgmp::receive_ack(&mut s, &refused).unwrap().unwrap();
        assert_eq!(on_ack(&mut s, &ack), Ok(Some(h.job_id)));
        // The Hub took the fee but opened no escrow and burned no inclusion fee.
        assert_eq!(balances::free_balance(&mut s, &PAYER).unwrap(), 1_000 + 2 * FEE + 3 * INCLUSION);
        assert_eq!((JOBS.get(&mut s, &h.job_id), OUTSTANDING.get(&mut s)), (Ok(None), Ok(Some(0))));
    }

    #[test]
    fn open_jobs_are_bounded() {
        let mut s = funded();
        OUTSTANDING.put(&mut s, &MAX_OUTSTANDING_JOBS).unwrap();
        assert_eq!(request(&mut s, ENV, 10, &PAYER, req(1), 0), Err(Error::TooManyJobs));
        assert_eq!(balances::free_balance(&mut s, &PAYER).unwrap(), 1_000 + 3 * (FEE + INCLUSION));
    }

    #[test]
    fn open_jobs_are_bounded_per_payer() {
        let mut s = funded();
        OPEN_BY_PAYER.insert(&mut s, &PAYER, &MAX_OPEN_JOBS_PER_PAYER).unwrap();
        assert_eq!(request(&mut s, ENV, 10, &PAYER, req(1), 0), Err(Error::TooManyJobsForPayer));
        OPEN_BY_PAYER.insert(&mut s, &PAYER, &(MAX_OPEN_JOBS_PER_PAYER - 1)).unwrap();
        let h = request(&mut s, ENV, 10, &PAYER, req(1), 0).unwrap();
        assert_eq!(OPEN_BY_PAYER.get(&mut s, &PAYER).unwrap(), Some(MAX_OPEN_JOBS_PER_PAYER));
        assert!(close(&mut s, &h.job_id).unwrap().is_some());
        assert_eq!(OPEN_BY_PAYER.get(&mut s, &PAYER).unwrap(), Some(MAX_OPEN_JOBS_PER_PAYER - 1));
    }

    #[test]
    fn a_spec_the_hub_would_refuse_for_its_size_is_refused_here() {
        use tog_types::admission::MAX_JOB_TX_BYTES;
        let mut s = funded();
        let mut big = req(1);
        let len = |r: &Request| borsh::object_length(&job_tx(ENV, 0, 0, r.spec.clone())).unwrap();
        let room = MAX_JOB_TX_BYTES - len(&big) - 4;
        big.spec.command.args.push("a".repeat(room));
        assert_eq!(len(&big), MAX_JOB_TX_BYTES);
        let mut over = big.clone();
        over.spec.command.args.last_mut().unwrap().push('a');
        assert_eq!(request(&mut s, ENV, 10, &PAYER, over, 0), Err(Error::SpecTooLarge));
        assert_eq!(OUTSTANDING.get(&mut s).unwrap(), None, "nothing changed");
        // At the limit the size is no reason (here the fee for so long a message is).
        assert_ne!(request(&mut s, ENV, 10, &PAYER, big, 0).err(), Some(Error::SpecTooLarge));
    }

    #[test]
    fn the_archive_is_the_one_unnamed_output() {
        use tog_types::payload::PayloadKind;
        let archive = tog_types::testing::payload(PayloadKind::Output, 7, 100, None);
        let mut r = result([1; 32], 0);
        assert_eq!(output_archive(&r), None, "no accepted result");
        r.outputs = vec![(String::new(), archive.clone())];
        assert_eq!(output_archive(&r), Some(&archive));
        r.outputs = vec![("weights".into(), archive.clone())];
        assert_eq!(output_archive(&r), None, "named paths are reserved");
        r.outputs = vec![(String::new(), archive.clone()), (String::new(), archive)];
        assert_eq!(output_archive(&r), None);
    }
}
