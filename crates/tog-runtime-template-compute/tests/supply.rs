//! $TOG conservation on the compute template under random interleavings of transfers, Hub
//! deposits, model registrations, fine-tuning jobs, plain compute requests and every answer to
//! them, replays included (pre-audit §6 gaps): after every block the accounts hold exactly the
//! total issuance, which is the genesis funds plus what the Hub sent, minus what left in requests,
//! plus what their answers refund, each refund paid once. A fine-tuning job's callback runs once:
//! a settled result with an output archive is the model's pending version, which its owner
//! publishes, any other leaves it, and a replayed result changes no model. The callback never fails here, so no result is kept.

use std::collections::BTreeMap;

use proptest::prelude::*;
use tog_runtime_core::{AccountId, Balance, ChainId, Hash32};
use tog_runtime_modules::{balances, cgmp, compute};
use tog_runtime_template_compute::model_registry;
use tog_runtime_template_compute::{GenesisConfig, Template, BALANCES, COMPUTE, MODEL_REGISTRY};
use tog_runtime_test::{job_result, CgmpError, CgmpPayload, ComputeRequest, JobOutcome, TestChain, AUTHOR};
use tog_types::job::{DealId, PayloadRef};
use tog_types::payload::{PayloadCommitment, PayloadKind};
use tog_types::testing::{payload, sample_spec};

const CHAIN: ChainId = ChainId(5);
const USERS: [AccountId; 3] = [[2; 20], [3; 20], [4; 20]];
const FUNDS: Balance = 1_000_000_000_000_000_000_000;
const FEE: Balance = 10_000_000_000_000_000;

#[derive(Clone, Debug)]
enum Action {
    Transfer {
        from: usize,
        to: usize,
        amount: Balance,
    },
    Deposit {
        to: usize,
        amount: Balance,
    },
    /// Register a model whose spec carries `pad` more bytes.
    Register {
        from: usize,
        pad: usize,
    },
    /// Fine-tune a model, possibly not the signer's.
    FineTune {
        from: usize,
        pick: usize,
        budget: Balance,
    },
    Request {
        from: usize,
        budget: Balance,
    },
    /// Answer an open message: `how` picks the answer, `charged` (per mille of the budget) a
    /// job's charge.
    Answer {
        pick: usize,
        how: u8,
        charged: u16,
    },
    /// Send an answer already given once more.
    Replay {
        pick: usize,
    },
    /// Publish a model's pending version, possibly as someone else.
    Publish {
        from: usize,
        pick: usize,
    },
    /// Take a result the chain kept, as anyone.
    TakeResult {
        from: usize,
        pick: usize,
    },
    Block,
}

fn action() -> impl Strategy<Value = Action> {
    let who = 0..USERS.len();
    let amount = 1..1_000_000_000_000_000_000u128;
    let budget = 1..1_000_000_000u128;
    prop_oneof![
        1 => (who.clone(), who.clone(), amount.clone()).prop_map(|(from, to, amount)| Action::Transfer { from, to, amount }),
        1 => (who.clone(), amount).prop_map(|(to, amount)| Action::Deposit { to, amount }),
        1 => (who.clone(), 0..20_000usize).prop_map(|(from, pad)| Action::Register { from, pad }),
        2 => (who.clone(), any::<usize>(), budget.clone()).prop_map(|(from, pick, budget)| Action::FineTune { from, pick, budget }),
        1 => (who.clone(), budget).prop_map(|(from, budget)| Action::Request { from, budget }),
        3 => (any::<usize>(), any::<u8>(), 0..=1000u16).prop_map(|(pick, how, charged)| Action::Answer { pick, how, charged }),
        1 => any::<usize>().prop_map(|pick| Action::Replay { pick }),
        2 => (who.clone(), any::<usize>()).prop_map(|(from, pick)| Action::Publish { from, pick }),
        1 => (who, any::<usize>()).prop_map(|(from, pick)| Action::TakeResult { from, pick }),
        3 => Just(Action::Block),
    ]
}

/// A message the chain sent that waits for its answer.
#[derive(Clone, Debug)]
enum Open {
    /// A request to the Hub: what its `TO_HUB` record says the chain paid, the job's budget and
    /// its inclusion fee.
    ToHub { request: ComputeRequest, amount: Balance, fee: Balance },
    /// A job the Hub took: its budget.
    Job { request: ComputeRequest, budget: Balance },
}

fn archive(root: u8) -> PayloadCommitment {
    payload(PayloadKind::Output, root, 1_000, None)
}

/// `archive(root)` in deal `root`.
fn stored(root: u8) -> PayloadRef {
    PayloadRef { payload: archive(root), deal: Some(DealId(u64::from(root))) }
}

struct Model {
    chain: TestChain<Template>,
    /// What the issuance must be.
    expected: Balance,
    open: Vec<Open>,
    /// Answers given, to replay: payload.
    given: Vec<CgmpPayload>,
    /// Each registered model's version, as the publishes so far make it.
    versions: BTreeMap<u64, u32>,
    /// Each registered model's owner.
    owners: BTreeMap<u64, usize>,
    /// The output archive (`archive(root)`) each model's last trained job made, until published.
    pending: BTreeMap<u64, u8>,
    /// The model each fine-tuning job trains.
    training: BTreeMap<Hash32, u64>,
    /// Every job a result arrived for.
    answered: Vec<Hash32>,
}

impl Model {
    fn new() -> Self {
        let chain = TestChain::new(CHAIN, |author| {
            let balances = USERS.iter().map(|u| (*u, FUNDS)).collect();
            borsh::to_vec(&GenesisConfig { balances, authorities: vec![author], root_key: None }).unwrap()
        });
        Model {
            chain,
            expected: FUNDS * USERS.len() as Balance,
            open: Vec::new(),
            given: Vec::new(),
            versions: BTreeMap::new(),
            owners: BTreeMap::new(),
            pending: BTreeMap::new(),
            training: BTreeMap::new(),
            answered: Vec::new(),
        }
    }

    fn answer(&mut self, payload: CgmpPayload) {
        self.chain.send_from(ChainId::HUB, payload.clone());
        self.given.push(payload);
    }

    fn apply(&mut self, a: Action) {
        let c = &mut self.chain;
        match a {
            Action::Transfer { from, to, amount } => {
                let call = balances::Call::Transfer { to: USERS[to], amount };
                c.submit(USERS[from], (BALANCES, balances::TRANSFER, borsh::to_vec(&call).unwrap()));
            }
            Action::Deposit { to, amount } => {
                c.send_from(ChainId::HUB, CgmpPayload::TransferTog { to: USERS[to], amount });
                self.expected += amount;
            }
            Action::Register { from, pad } => {
                let mut spec = sample_spec();
                spec.command.args.push("a".repeat(pad));
                let call = model_registry::Call::Register { spec, weights: stored(1) };
                c.submit(USERS[from], call.into_call(MODEL_REGISTRY));
            }
            Action::FineTune { from, pick, budget } => {
                // A model id past the last now and then.
                let model = (pick % (self.versions.len() + 1)) as u64;
                // A large spec's job message needs a higher fee.
                let call =
                    model_registry::Call::FineTune { model, dataset: stored(9), max_budget: budget, fee: FEE * 1_000 };
                c.submit(USERS[from], call.into_call(MODEL_REGISTRY));
            }
            Action::Request { from, budget } => {
                let mut spec = sample_spec();
                spec.fee.max_budget = budget;
                spec.fee.inclusion_fee = 0;
                let call = compute::Call::Request { spec, fee: FEE, timeout: None };
                c.submit(USERS[from], (COMPUTE, compute::REQUEST, borsh::to_vec(&call).unwrap()));
            }
            Action::Answer { pick, how, charged } => {
                if self.open.is_empty() {
                    return;
                }
                match self.open.remove(pick % self.open.len()) {
                    Open::ToHub { request, amount, fee } => {
                        let errors = [CgmpError::Timeout, CgmpError::InsufficientFee, CgmpError::DispatchFailed];
                        let result = match how % 4 {
                            0 => Ok(()),
                            i => Err(errors[usize::from(i) - 1]),
                        };
                        self.expected += match result {
                            Ok(()) => 0,
                            Err(CgmpError::Timeout | CgmpError::InsufficientFee) => amount + fee,
                            Err(_) => amount,
                        };
                        let of_nonce = request.message.channel_nonce;
                        self.answer(CgmpPayload::Ack { of_nonce, result });
                        if result.is_ok() {
                            // What came back is the budget; the inclusion fee stays burnt.
                            let budget = request.spec.fee.max_budget;
                            self.open.push(Open::Job { request, budget });
                        } else {
                            self.training.remove(&request.job_id);
                        }
                    }
                    Open::Job { request, budget } => {
                        let outcome = if how % 2 == 0 { JobOutcome::Settled } else { JobOutcome::ExecutorFault };
                        let charged = budget * Balance::from(charged) / 1000;
                        let mut result = job_result(outcome, charged);
                        result.job_id = request.job_id;
                        // Half the settled jobs name no output archive: the model stays.
                        if how % 4 == 0 {
                            result.outputs = vec![(String::new(), archive(how))];
                        }
                        if let Some(model) = self.training.remove(&request.job_id) {
                            if compute::output_archive(&result).is_some() && outcome == JobOutcome::Settled {
                                self.pending.insert(model, how);
                            }
                        }
                        self.expected += budget - charged;
                        self.answered.push(request.job_id);
                        self.answer(CgmpPayload::ComputeResult(result));
                    }
                }
            }
            Action::Replay { pick } => {
                if !self.given.is_empty() {
                    let payload = self.given[pick % self.given.len()].clone();
                    c.send_from(ChainId::HUB, payload);
                }
            }
            Action::Publish { from, pick } => {
                let model = (pick % (self.versions.len() + 1)) as u64;
                // Only the owner publishes, and only what the pending job made.
                let root = self.pending.get(&model).copied();
                let call = model_registry::Call::Publish { model, weights: stored(root.unwrap_or(1)) };
                c.submit(USERS[from], call.into_call(MODEL_REGISTRY));
                if root.is_some() && self.owners.get(&model) == Some(&from) {
                    self.pending.remove(&model);
                    *self.versions.get_mut(&model).expect("a registered model") += 1;
                }
            }
            Action::TakeResult { from, pick } => {
                let job_id = match self.answered.len() {
                    0 => [pick as u8; 32],
                    n => self.answered[pick % n],
                };
                c.submit(USERS[from], (COMPUTE, compute::TAKE_RESULT, borsh::to_vec(&job_id).unwrap()));
            }
            Action::Block => self.block(),
        }
    }

    /// One block, then the checks; what it sent becomes open.
    fn block(&mut self) {
        let c = &mut self.chain;
        c.block();
        let requests = c.take_compute_requests();
        let events: Vec<model_registry::Event> = c.events_of("model_registry");
        let s = c.state();
        for e in events {
            match e {
                model_registry::Event::Registered { model, owner } => {
                    assert_eq!(model, self.versions.len() as u64, "ids in order");
                    self.versions.insert(model, 0);
                    self.owners.insert(model, USERS.iter().position(|u| *u == owner).expect("a user"));
                }
                model_registry::Event::FineTuning { model, job_id } => {
                    self.training.insert(job_id, model);
                }
                _ => {}
            }
        }
        for request in requests {
            let r = cgmp::TO_HUB.get(s, &request.message.channel_nonce).unwrap().expect("a request's record");
            self.expected -= r.amount + r.fee;
            self.open.push(Open::ToHub { request, amount: r.amount, fee: r.fee });
        }
        for (model, version) in &self.versions {
            let m = model_registry::model(s, *model).unwrap().expect("a registered model");
            assert_eq!(m.version, *version, "model {model}'s version follows its publishes");
            let pending = m.pending.as_ref().map(|p| p.plaintext_root());
            assert_eq!(pending, self.pending.get(model).map(|r| archive(*r).root), "model {model}'s pending version");
        }
        for job_id in &self.answered {
            assert_eq!(compute::RESULTS.get(s, job_id).unwrap(), None, "no callback failed");
        }
        let issuance = balances::total_issuance(s).unwrap();
        let held: Balance = USERS.iter().chain([&AUTHOR]).map(|u| balances::account(s, u).unwrap().total()).sum();
        assert_eq!(held, issuance, "the accounts hold the issuance");
        assert_eq!(issuance, self.expected, "the issuance follows what came and went");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn tog_is_conserved_and_every_model_trained_once(actions in prop::collection::vec(action(), 1..80)) {
        let mut m = Model::new();
        for a in actions {
            m.apply(a);
        }
        // Every answer arrives.
        m.block();
        m.block();
    }
}

#[test]
fn a_replayed_result_trains_no_model_and_refunds_nothing() {
    let mut m = Model::new();
    m.apply(Action::Register { from: 0, pad: 0 });
    m.block();
    m.apply(Action::FineTune { from: 0, pick: 0, budget: 500 });
    m.apply(Action::Request { from: 1, budget: 700 });
    m.block();
    assert_eq!(m.open.len(), 2, "{:?}", m.chain.outcomes());
    // Both taken, then both settled with an archive.
    m.apply(Action::Answer { pick: 0, how: 0, charged: 300 });
    m.apply(Action::Answer { pick: 0, how: 0, charged: 300 });
    m.block();
    m.apply(Action::Answer { pick: 0, how: 0, charged: 300 });
    m.apply(Action::Answer { pick: 0, how: 0, charged: 300 });
    m.block();
    assert_eq!((m.versions[&0], m.pending.get(&0)), (0, Some(&0)));
    m.apply(Action::Publish { from: 1, pick: 0 });
    m.apply(Action::Publish { from: 0, pick: 0 });
    m.block();
    assert_eq!((m.versions[&0], m.pending.get(&0)), (1, None));
    for pick in 0..m.given.len() {
        m.apply(Action::Replay { pick });
    }
    m.block();
    m.block();
}
