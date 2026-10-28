//! $TOG conservation on the template runtime under random interleavings of transfers, Hub
//! deposits, withdrawals, compute requests, calls to another chain and every answer to them,
//! replays included (pre-audit §6 gaps): after every block the accounts hold exactly the total
//! issuance, and the issuance is the genesis funds plus what the Hub sent, minus what left in
//! messages, plus what their answers refund, each refund paid once.

use proptest::prelude::*;
use tog_runtime_core::{AccountId, Balance, ChainId, Weight};
use tog_runtime_modules::{balances, cgmp, compute};
use tog_runtime_template::{GenesisConfig, Template, BALANCES, CGMP, COMPUTE};
use tog_runtime_test::{
    job_result, CgmpError, CgmpMessage, CgmpPayload, ComputeRequest, JobOutcome, TestChain, AUTHOR,
};
use tog_types::job::ModuleId;

const CHAIN: ChainId = ChainId(5);
const PEER: ChainId = ChainId(9);
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
    Withdraw {
        from: usize,
        amount: Balance,
    },
    Request {
        from: usize,
        budget: Balance,
    },
    Send {
        from: usize,
    },
    /// Answer an open message: `how` picks the answer, `charged` (per mille of the budget) a
    /// compute job's charge.
    Answer {
        pick: usize,
        how: u8,
        charged: u16,
    },
    /// Send an answer already given once more.
    Replay {
        pick: usize,
    },
    Block,
}

fn action() -> impl Strategy<Value = Action> {
    let who = 0..USERS.len();
    let amount = 1..1_000_000_000_000_000_000u128;
    prop_oneof![
        1 => (who.clone(), who.clone(), amount.clone()).prop_map(|(from, to, amount)| Action::Transfer { from, to, amount }),
        1 => (who.clone(), amount.clone()).prop_map(|(to, amount)| Action::Deposit { to, amount }),
        1 => (who.clone(), amount).prop_map(|(from, amount)| Action::Withdraw { from, amount }),
        1 => (who.clone(), 1..1_000_000_000u128).prop_map(|(from, budget)| Action::Request { from, budget }),
        1 => who.prop_map(|from| Action::Send { from }),
        3 => (any::<usize>(), any::<u8>(), 0..=1000u16).prop_map(|(pick, how, charged)| Action::Answer { pick, how, charged }),
        1 => any::<usize>().prop_map(|pick| Action::Replay { pick }),
        3 => Just(Action::Block),
    ]
}

/// A message the chain sent that waits for its answer.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)] // test bookkeeping
enum Open {
    /// To the Hub: what its `TO_HUB` record says the chain paid.
    ToHub { message: CgmpMessage, amount: Balance, fee: Balance, job: Option<ComputeRequest> },
    /// A compute job the Hub took: its budget.
    Job { request: ComputeRequest, budget: Balance },
    /// To `PEER`: the fee its `PENDING_CALLS` record holds.
    Call { message: CgmpMessage, fee: Balance },
}

struct Model {
    chain: TestChain<Template>,
    /// What the issuance must be.
    expected: Balance,
    open: Vec<Open>,
    /// Answers given, to replay: source and payload.
    given: Vec<(ChainId, CgmpPayload)>,
}

impl Model {
    fn new() -> Self {
        let chain = TestChain::new(CHAIN, |author| {
            let balances = USERS.iter().map(|u| (*u, FUNDS)).collect();
            borsh::to_vec(&GenesisConfig { balances, authorities: vec![author], root_key: None }).unwrap()
        });
        Model { chain, expected: FUNDS * USERS.len() as Balance, open: Vec::new(), given: Vec::new() }
    }

    fn answer(&mut self, source: ChainId, payload: CgmpPayload) {
        self.chain.send_from(source, payload.clone());
        self.given.push((source, payload));
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
            Action::Withdraw { from, amount } => {
                let call = cgmp::Call::Withdraw { to: USERS[from], amount, fee: FEE, timeout: None };
                c.submit(USERS[from], (CGMP, 0, borsh::to_vec(&call).unwrap()));
            }
            Action::Request { from, budget } => {
                let mut spec = tog_types::testing::sample_spec();
                spec.fee.max_budget = budget;
                spec.fee.inclusion_fee = 0;
                let call = compute::Call::Request { spec, fee: FEE, timeout: None };
                c.submit(USERS[from], (COMPUTE, compute::REQUEST, borsh::to_vec(&call).unwrap()));
            }
            Action::Send { from } => {
                let call = cgmp::Call::Send {
                    dest: PEER,
                    module: ModuleId(*b"remote\0\0\0\0\0\0\0\0\0\0"),
                    call: vec![1],
                    weight_limit: Weight::from_parts(1, 1),
                    fee: FEE,
                    timeout: None,
                };
                c.submit(USERS[from], (CGMP, 1, borsh::to_vec(&call).unwrap()));
            }
            Action::Answer { pick, how, charged } => {
                if self.open.is_empty() {
                    return;
                }
                match self.open.remove(pick % self.open.len()) {
                    Open::ToHub { message, amount, fee, job } => {
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
                        self.answer(ChainId::HUB, CgmpPayload::Ack { of_nonce: message.channel_nonce, result });
                        if let (Ok(()), Some(request)) = (result, job) {
                            self.open.push(Open::Job { request, budget: amount });
                        }
                    }
                    Open::Job { request, budget } => {
                        let outcome = if how % 2 == 0 { JobOutcome::Settled } else { JobOutcome::ExecutorFault };
                        let charged = budget * Balance::from(charged) / 1000;
                        let mut result = job_result(outcome, charged);
                        result.job_id = request.job_id;
                        self.expected += budget - charged;
                        self.answer(ChainId::HUB, CgmpPayload::ComputeResult(result));
                    }
                    Open::Call { message, fee } => {
                        let result = if how % 2 == 0 { Ok(()) } else { Err(CgmpError::Timeout) };
                        if result.is_err() {
                            self.expected += fee;
                        }
                        self.answer(PEER, CgmpPayload::Ack { of_nonce: message.channel_nonce, result });
                    }
                }
            }
            Action::Replay { pick } => {
                if !self.given.is_empty() {
                    let (source, payload) = self.given[pick % self.given.len()].clone();
                    c.send_from(source, payload);
                }
            }
            Action::Block => self.block(),
        }
    }

    /// One block, then the checks; what it sent becomes open.
    fn block(&mut self) {
        let c = &mut self.chain;
        c.block();
        let requests = c.take_compute_requests();
        let sent = c.take_sent();
        let s = c.state();
        for request in requests {
            let r = cgmp::TO_HUB.get(s, &request.message.channel_nonce).unwrap().expect("a request's record");
            self.expected -= r.amount + r.fee;
            let message = request.message.clone();
            self.open.push(Open::ToHub { message, amount: r.amount, fee: r.fee, job: Some(request) });
        }
        for m in sent {
            if m.dest == ChainId::HUB {
                let r = cgmp::TO_HUB.get(s, &m.channel_nonce).unwrap().expect("a withdrawal's record");
                self.expected -= r.amount + r.fee;
                self.open.push(Open::ToHub { message: m, amount: r.amount, fee: r.fee, job: None });
            } else if m.dest == PEER && matches!(m.payload, CgmpPayload::Call { .. }) {
                let r = cgmp::PENDING_CALLS.get(s, &(PEER, m.channel_nonce)).unwrap().expect("a call's record");
                self.expected -= r.fee;
                self.open.push(Open::Call { message: m, fee: r.fee });
            }
        }
        let issuance = balances::total_issuance(s).unwrap();
        let held: Balance = USERS.iter().chain([&AUTHOR]).map(|u| balances::account(s, u).unwrap().total()).sum();
        assert_eq!(held, issuance, "the accounts hold the issuance");
        assert_eq!(issuance, self.expected, "the issuance follows what came and went");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn tog_is_conserved_and_every_refund_paid_once(actions in prop::collection::vec(action(), 1..80)) {
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
fn a_replayed_answer_refunds_nothing() {
    let mut m = Model::new();
    m.apply(Action::Withdraw { from: 0, amount: 1_000 });
    m.apply(Action::Request { from: 1, budget: 500 });
    m.apply(Action::Send { from: 2 });
    m.block();
    assert_eq!(m.open.len(), 3, "{:?}", m.chain.outcomes());
    // A refused withdrawal, a taken request, a timed-out call.
    for how in [1, 0, 1] {
        m.apply(Action::Answer { pick: 0, how, charged: 300 });
    }
    m.block();
    // The job's result, then every answer again.
    m.apply(Action::Answer { pick: 0, how: 0, charged: 300 });
    m.block();
    for pick in 0..m.given.len() {
        m.apply(Action::Replay { pick });
    }
    m.block();
    m.block();
}
