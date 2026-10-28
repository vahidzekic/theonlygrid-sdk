//! `tog test`'s harness (TOG-SPEC-0007 §10): a chain's runtime run natively on in-memory state,
//! block by block, with the Hub, other chains and the compute market simulated around it.
//!
//! [`TestChain`] runs any [`Runtime`] through the executive's own `build_block`, so a test sees
//! what a collator would: transactions from [`TestChain::submit`] are signed with development
//! signatures ([`DevSignatures`]) and included or left out as the runtime decides, the block's
//! events are in [`TestChain::events`], and every block is imported again on its parent state and
//! must reach the same state root, which catches a runtime that isn't deterministic.
//!
//! - **CGMP harness.** [`TestChain::send_from`] sends the chain a message from the Hub or another
//!   chain: it goes on the simulated Hub channel at once and into the next block's inbox, with
//!   the inbox proofs a collator would carry. What the chain sends is in [`TestChain::take_sent`],
//!   and [`TestChain::ack`] answers it from its destination.
//! - **Compute harness.** [`TestChain::take_compute_requests`] are the jobs the chain asked the
//!   Hub for, each with the `job_id` the Hub gives it; [`TestChain::complete`] has the Hub accept
//!   one and send back a scripted [`ComputeResult`], settled or failed in any of the ways a job
//!   ends ([`JobOutcome`], `Nondeterministic` among them); [`TestChain::refuse`] has the Hub refuse
//!   it.
//! - **Calls outside a block.** [`TestChain::dispatch`] runs a call under any origin (`Root`,
//!   `Hub`, `Chain`), which no transaction carries.
//!
//! ```ignore
//! let mut chain = TestChain::<Template>::new(ChainId(5), |author| genesis(author));
//! chain.submit(ALICE, transfer(BOB, 10));
//! chain.block();
//! assert_eq!(chain.outcomes(), vec![Ok(..)]);
//! ```

use std::collections::{BTreeMap, VecDeque};
use std::marker::PhantomData;

use borsh::BorshDeserialize;
use tog_runtime_core::block::{Block, HeadData, Header, Inherent};
use tog_runtime_core::env::Env;
use tog_runtime_core::hash::tagged;
use tog_runtime_core::memory::MemoryStorage;
use tog_runtime_core::storage::{Storage, StorageKey};
use tog_runtime_core::tx::{AppTx, AppTxBody, SignatureCheck};
use tog_runtime_core::{AccountId, ChainId, DispatchError, Hash32, HubHeight, Origin, Weight};
use tog_runtime_modules::compute;
use tog_runtime_modules::executive::{self, Call, Context, Runtime};
use tog_runtime_modules::system;
use tog_types::cgmp::{next_head, CgmpChannel, CGMP_VERSION};
use tog_types::state::items::{cgmp_channel, cgmp_inbound};
use tog_types::tx::Signature;

pub use tog_runtime_modules::system::{EventRecord, Failure, Phase};
pub use tog_types::cgmp::{CgmpError, CgmpMessage, CgmpOrigin, CgmpPayload, ComputeResult};
pub use tog_types::job::JobSpec;
pub use tog_types::state::JobOutcome;

/// The block author: the chain's genesis config must make it the Aura authority.
pub const AUTHOR: AccountId = [0xa0; 20];
/// The simulated Hub's `network_id`.
pub const NETWORK_ID: u32 = 1;
/// Blocks a transaction stays valid for.
const LONGEVITY: u64 = 1_000;

/// The host, natively: in-memory storage, the relay parent, Hub state and the CGMP queues. Its
/// state root hashes every item; it is not the Hub's tree root, but it changes exactly when the
/// state does.
#[derive(Clone, Debug)]
pub struct TestEnv {
    /// The chain's state.
    pub storage: MemoryStorage,
    chain: ChainId,
    relay: (HubHeight, Hash32),
    hub: BTreeMap<Vec<u8>, Vec<u8>>,
    inbox: VecDeque<Vec<u8>>,
    outbox: Vec<Vec<u8>>,
}

impl TestEnv {
    fn new(chain: ChainId) -> Self {
        TestEnv {
            storage: MemoryStorage::default(),
            chain,
            relay: (1, relay_hash(1)),
            hub: BTreeMap::new(),
            inbox: VecDeque::new(),
            outbox: Vec::new(),
        }
    }
}

fn relay_hash(height: HubHeight) -> Hash32 {
    tagged("tog-runtime-test/relay", &[&height.to_le_bytes()])
}

impl Storage for TestEnv {
    fn get(&mut self, key: &StorageKey) -> Option<Vec<u8>> {
        self.storage.get(key)
    }
    fn set(&mut self, key: &StorageKey, value: Vec<u8>) {
        self.storage.set(key, value)
    }
    fn clear(&mut self, key: &StorageKey) {
        self.storage.clear(key)
    }
    fn next_key(&mut self, key: &StorageKey) -> Option<StorageKey> {
        self.storage.next_key(key)
    }
}

impl Env for TestEnv {
    fn chain_context(&mut self) -> (ChainId, u32) {
        (self.chain, NETWORK_ID)
    }
    fn relay_parent(&mut self) -> (HubHeight, Hash32) {
        self.relay
    }
    fn hub_read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.hub.get(key).cloned()
    }
    fn inbox_next(&mut self) -> Option<Vec<u8>> {
        self.inbox.pop_front()
    }
    fn outbox_push(&mut self, msg: &[u8]) {
        self.outbox.push(msg.to_vec())
    }
    fn storage_root(&mut self) -> Hash32 {
        let parts: Vec<&[u8]> = self.storage.iter().flat_map(|(k, v)| [&k[..], &v[..]]).collect();
        tagged("tog-runtime-test/root", &parts)
    }
}

/// Development signatures: a secp256k1 signature is the signer's address followed by zeros, with
/// recovery id 0; ed25519 signatures never verify. Only for tests: anyone can sign as anyone.
#[derive(Clone, Copy, Debug, Default)]
pub struct DevSignatures;

impl DevSignatures {
    /// `signer`'s signature of anything.
    pub fn sign(signer: &AccountId) -> Signature {
        let mut sig = [0; 65];
        sig[..20].copy_from_slice(signer);
        Signature::Secp256k1(sig)
    }
}

impl SignatureCheck for DevSignatures {
    fn ed25519_verify(&self, _: &[u8; 32], _: &[u8; 64], _: &[u8]) -> bool {
        false
    }
    fn secp256k1_signer(&self, _: &Hash32, sig: &[u8; 65]) -> Option<AccountId> {
        (sig[64] == 0 && sig[20..64].iter().all(|b| *b == 0)).then(|| sig[..20].try_into().expect("20 bytes"))
    }
}

/// A job the chain asked the Hub for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeRequest {
    /// The id the Hub gives it.
    pub job_id: Hash32,
    /// The job.
    pub spec: JobSpec,
    /// The `ComputeRequest` message.
    pub message: CgmpMessage,
}

/// What a call outside a block did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispatched {
    /// Its result: the weight it used, or why it failed (its changes then discarded).
    pub result: Result<Weight, DispatchError>,
    /// The events it deposited, `(module, borsh(event))`; none if it failed.
    pub events: Vec<(&'static str, Vec<u8>)>,
}

/// A channel to the chain on the simulated Hub, and the messages on it the chain hasn't taken.
#[derive(Clone, Debug, Default)]
struct Inbound {
    channel: CgmpChannel,
    queued: VecDeque<CgmpMessage>,
}

/// A chain of runtime `R` on in-memory state; see the crate documentation.
pub struct TestChain<R: Runtime> {
    env: TestEnv,
    head: HeadData,
    pending: Vec<Vec<u8>>,
    nonces: BTreeMap<AccountId, u64>,
    inbound: BTreeMap<ChainId, Inbound>,
    sent: Vec<CgmpMessage>,
    _runtime: PhantomData<fn() -> R>,
}

impl<R: Runtime> TestChain<R> {
    /// Chain `chain` at genesis: `R`'s genesis with the config `config(AUTHOR)` returns, which
    /// must make [`AUTHOR`] the block author.
    pub fn new(chain: ChainId, config: impl FnOnce(AccountId) -> Vec<u8>) -> Self {
        let mut env = TestEnv::new(chain);
        let input = borsh::to_vec(&config(AUTHOR)).expect("in-memory borsh");
        let root: Hash32 = borsh::from_slice(&executive::genesis::<R, _>(&mut env, &input)).expect("genesis root");
        TestChain {
            env,
            head: Header::genesis(root).head_data(),
            pending: Vec::new(),
            nonces: BTreeMap::new(),
            inbound: BTreeMap::new(),
            sent: Vec::new(),
            _runtime: PhantomData,
        }
    }

    /// The chain.
    pub fn chain(&self) -> ChainId {
        self.env.chain
    }

    /// The current head's header.
    pub fn header(&self) -> Header {
        Header::try_from_slice(&self.head).expect("head decodes")
    }

    /// The chain's state, to read or set with the modules' storage items.
    pub fn state(&mut self) -> &mut TestEnv {
        &mut self.env
    }

    /// Sets (`Some`) or removes Hub state key `key`, as the runtime reads it at the next block's
    /// relay parent.
    pub fn set_hub(&mut self, key: &[u8], value: Option<Vec<u8>>) {
        match value {
            Some(v) => self.env.hub.insert(key.to_vec(), v),
            None => self.env.hub.remove(key),
        };
    }

    /// Queues a transaction of `call` signed by `signer` for the next block, with its next nonce
    /// and no tip.
    pub fn submit(&mut self, signer: AccountId, call: Call) {
        let next = match self.nonces.get(&signer) {
            Some(n) => *n,
            None => system::nonce(&mut self.env, &signer).expect("nonce decodes"),
        };
        self.nonces.insert(signer, next + 1);
        let body = AppTxBody {
            chain_id: self.env.replay_domain(),
            nonce: next,
            tip: 0,
            valid_until: self.header().number + LONGEVITY,
            call,
        };
        self.submit_tx(AppTx { body, signer, sig: DevSignatures::sign(&signer) });
    }

    /// Queues `tx` for the next block as it is.
    pub fn submit_tx(&mut self, tx: AppTx) {
        self.pending.push(borsh::to_vec(&tx).expect("in-memory borsh"));
    }

    /// Builds the next block on a relay parent one Hub block later: the queued transactions and
    /// every message waiting in the inbox. The block is then imported again on its parent state,
    /// which must reach the same state root. Messages the block didn't take wait for the next one.
    pub fn block(&mut self) -> Block {
        let height = self.env.relay.0 + 1;
        self.env.relay = (height, relay_hash(height));
        let offered: Vec<CgmpMessage> = self.inbound.values().flat_map(|i| i.queued.iter().cloned()).collect();
        self.env.inbox = offered.iter().map(|m| self.inbox_entry(m)).collect();
        let inherents =
            vec![Inherent::RelayParent { height, hash: self.env.relay.1 }, Inherent::Collator { account: AUTHOR }];
        let input = borsh::to_vec(&(&self.head, &inherents, std::mem::take(&mut self.pending))).expect("borsh");
        self.nonces.clear();

        let mut parent = self.env.clone();
        let built = executive::build_block::<R, _>(&mut self.env, &DevSignatures, &input);
        let (block, peeked): (Block, bool) = borsh::from_slice(&built).expect("block decodes");
        let taken = (block.header.inbox_processed - self.header().inbox_processed) as usize;
        parent.inbox = offered[..taken + usize::from(peeked)].iter().map(|m| self.inbox_entry(m)).collect();
        executive::execute_block::<R, _>(&mut parent, &DevSignatures, &borsh::to_vec(&block).expect("borsh"));
        assert_eq!(parent.storage_root(), self.env.storage_root(), "importing the block reaches another state");

        for m in &offered[..taken] {
            self.inbound.get_mut(&m.source).expect("queued").queued.pop_front();
        }
        self.env.inbox.clear();
        for b in std::mem::take(&mut self.env.outbox) {
            self.sent.push(borsh::from_slice(&b).expect("outbox message decodes"));
        }
        self.head = block.header.head_data();
        block
    }

    /// Builds `n` blocks.
    pub fn blocks(&mut self, n: usize) {
        for _ in 0..n {
            self.block();
        }
    }

    /// `m` as an inbox entry, with the hashes of every later message on its channel.
    fn inbox_entry(&self, m: &CgmpMessage) -> Vec<u8> {
        let later: Vec<Hash32> = self.inbound[&m.source]
            .queued
            .iter()
            .filter(|x| x.channel_nonce > m.channel_nonce)
            .map(|x| x.hash())
            .collect();
        borsh::to_vec(&(m, Some(later))).expect("in-memory borsh")
    }

    /// The last block's events.
    pub fn events(&mut self) -> Vec<EventRecord> {
        system::EVENTS.get(&mut self.env).expect("events decode").map(|e| e.records).unwrap_or_default()
    }

    /// The last block's events of `module`, decoded as `T`.
    pub fn events_of<T: BorshDeserialize>(&mut self, module: &str) -> Vec<T> {
        self.events()
            .into_iter()
            .filter(|r| r.module == module)
            .map(|r| T::try_from_slice(&r.event).expect("event decodes"))
            .collect()
    }

    /// How each transaction of the last block went, in order: the weight it used, or why it
    /// failed.
    pub fn outcomes(&mut self) -> Vec<Result<Weight, Failure>> {
        self.events()
            .into_iter()
            .filter(|r| r.module == "system" && matches!(r.phase, Phase::Extrinsic(_)))
            .filter_map(|r| match system::Event::try_from_slice(&r.event) {
                Ok(system::Event::ExtrinsicSuccess { weight }) => Some(Ok(weight)),
                Ok(system::Event::ExtrinsicFailed { error, .. }) => Some(Err(error)),
                _ => None,
            })
            .collect()
    }

    /// Runs `call` under `origin` on the current state, outside a block.
    pub fn dispatch(&mut self, origin: Origin, call: Call) -> Dispatched {
        let cx = Context {
            chain: self.env.chain,
            network_id: NETWORK_ID,
            relay: self.env.relay.0,
            number: self.header().number,
            author: AUTHOR,
            per_byte: R::STORAGE_DEPOSIT_PER_BYTE,
        };
        let (result, events) = executive::dispatch_as::<R, _>(&mut self.env, &cx, origin, call);
        // A call outside a block may still send; it leaves with the next block's.
        for b in std::mem::take(&mut self.env.outbox) {
            self.sent.push(borsh::from_slice(&b).expect("outbox message decodes"));
        }
        Dispatched { result, events }
    }

    /// The runtime's `tog_v1_query(method, args)`.
    pub fn query(&mut self, method: &str, args: &[u8]) -> Result<Vec<u8>, String> {
        let input = borsh::to_vec(&(method.to_string(), args.to_vec())).expect("in-memory borsh");
        borsh::from_slice(&executive::query::<R, _>(&mut self.env, &input)).expect("query result decodes")
    }

    /// Sends the chain `payload` from `source` (the Hub or another chain, as itself) with no fee
    /// and no timeout; it is on the Hub at once and in the next block's inbox. Returns the
    /// message.
    pub fn send_from(&mut self, source: ChainId, payload: CgmpPayload) -> CgmpMessage {
        self.send(source, CgmpOrigin::Chain(source), payload, HubHeight::MAX, 0)
    }

    /// Sends the chain a message from `source` with `origin`, timing out after Hub height
    /// `timeout_height`, with `fee`; its nonce is the channel's next.
    pub fn send(
        &mut self,
        source: ChainId,
        origin: CgmpOrigin,
        payload: CgmpPayload,
        timeout_height: HubHeight,
        fee: u128,
    ) -> CgmpMessage {
        let me = self.env.chain;
        let inbound = self.inbound.entry(source).or_default();
        let ch = &mut inbound.channel;
        let nonce = ch.last_nonce.map_or(0, |n| n + 1);
        let m = CgmpMessage {
            version: CGMP_VERSION,
            source,
            dest: me,
            channel_nonce: nonce,
            timeout_height,
            fee,
            origin,
            payload,
        };
        ch.head = next_head(&ch.head, &m.hash());
        ch.last_nonce = Some(nonce);
        let channel = *ch;
        inbound.queued.push_back(m.clone());
        self.env.hub.insert(cgmp_channel(&source, &me).to_vec(), borsh::to_vec(&channel).expect("borsh"));
        let sources: Vec<ChainId> = self.inbound.keys().copied().collect();
        self.env.hub.insert(cgmp_inbound(&me).to_vec(), borsh::to_vec(&sources).expect("borsh"));
        m
    }

    /// The messages the chain sent since the last call, in order.
    pub fn take_sent(&mut self) -> Vec<CgmpMessage> {
        std::mem::take(&mut self.sent)
    }

    /// Answers `m`, a message the chain sent, from its destination with `result`.
    pub fn ack(&mut self, m: &CgmpMessage, result: Result<(), CgmpError>) -> CgmpMessage {
        assert_eq!(m.source, self.env.chain, "an ack answers the chain's own message");
        self.send_from(m.dest, CgmpPayload::Ack { of_nonce: m.channel_nonce, result })
    }

    /// The jobs the chain asked for since the last call, taken out of [`TestChain::take_sent`]'s
    /// messages.
    pub fn take_compute_requests(&mut self) -> Vec<ComputeRequest> {
        let env = compute::Env { chain: self.env.chain, network_id: NETWORK_ID };
        let (requests, rest): (Vec<CgmpMessage>, Vec<CgmpMessage>) = std::mem::take(&mut self.sent)
            .into_iter()
            .partition(|m| m.dest == ChainId::HUB && matches!(m.payload, CgmpPayload::ComputeRequest { .. }));
        self.sent = rest;
        requests
            .into_iter()
            .map(|message| {
                let CgmpPayload::ComputeRequest { spec, .. } = &message.payload else { unreachable!("partitioned") };
                let spec = (**spec).clone();
                let job_id = compute::job_tx(env, message.channel_nonce, message.timeout_height, spec.clone()).job_id();
                ComputeRequest { job_id, spec, message }
            })
            .collect()
    }

    /// The Hub accepts `request` and the job ends with `result` (its `job_id` set to the
    /// request's): both arrive in the next block.
    pub fn complete(&mut self, request: &ComputeRequest, mut result: ComputeResult) {
        result.job_id = request.job_id;
        self.ack(&request.message, Ok(()));
        self.send_from(ChainId::HUB, CgmpPayload::ComputeResult(result));
    }

    /// The Hub refuses `request` with `error`.
    pub fn refuse(&mut self, request: &ComputeRequest, error: CgmpError) {
        self.ack(&request.message, Err(error));
    }
}

/// A job's result: `outcome`, `charged` atto-TOG, no outputs.
pub fn job_result(outcome: JobOutcome, charged: u128) -> ComputeResult {
    ComputeResult { job_id: [0; 32], outcome, receipt_root: [0; 32], outputs: Vec::new(), work_units: 0, charged }
}

#[cfg(test)]
mod tests;
