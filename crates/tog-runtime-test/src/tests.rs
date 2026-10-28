//! The harness on the SDK's template runtime.

use tog_runtime_core::{AccountId, ChainId, Origin};
use tog_runtime_modules::{balances, compute};
use tog_runtime_template::{GenesisConfig, Template, BALANCES, COMPUTE, SYSTEM};
use tog_types::cgmp::{CgmpError, CgmpPayload};

use super::*;

const ALICE: AccountId = [2; 20];
const BOB: AccountId = [3; 20];
const FUNDS: u128 = 1_000_000_000_000_000_000;
const CHAIN: ChainId = ChainId(5);

fn chain() -> TestChain<Template> {
    TestChain::new(CHAIN, |author| {
        borsh::to_vec(&GenesisConfig { balances: vec![(ALICE, FUNDS)], authorities: vec![author], root_key: None })
            .unwrap()
    })
}

fn transfer(to: AccountId, amount: u128) -> Call {
    (BALANCES, 0, borsh::to_vec(&balances::Call::Transfer { to, amount }).unwrap())
}

fn free(c: &mut TestChain<Template>, who: &AccountId) -> u128 {
    balances::free_balance(c.state(), who).unwrap()
}

/// Free and reserved: storage deposits move between them (R-6).
fn total(c: &mut TestChain<Template>, who: &AccountId) -> u128 {
    balances::account(c.state(), who).unwrap().total()
}

#[test]
fn transactions_run_in_blocks_with_their_outcomes_and_events() {
    let mut c = chain();
    c.submit(ALICE, transfer(BOB, 1_000));
    c.submit(ALICE, transfer(BOB, FUNDS)); // can't pay: fails, fee charged
    c.submit(BOB, transfer(ALICE, 1)); // no funds for the fee: left out
    let block = c.block();
    assert_eq!((block.header.number, block.extrinsics.len()), (1, 2));
    let outcomes = c.outcomes();
    assert!(outcomes[0].is_ok());
    assert!(matches!(outcomes[1], Err(Failure::Module { module: 0, .. })));
    assert_eq!(free(&mut c, &BOB), 1_000);
    let transfers: Vec<balances::Event> = c.events_of("balances");
    assert_eq!(transfers, vec![balances::Event::Transfer { from: ALICE, to: BOB, amount: 1_000 }]);

    // Nonces carry on in the next block.
    c.submit(ALICE, transfer(BOB, 1));
    c.block();
    assert_eq!(c.outcomes().len(), 1);
    assert_eq!(c.header().number, 2);
}

#[test]
fn a_call_outside_a_block_takes_any_origin() {
    let mut c = chain();
    let upgrade = (SYSTEM, 0, borsh::to_vec(&[9u8; 32]).unwrap());
    assert!(c.dispatch(Origin::Signed(ALICE), upgrade.clone()).result.is_err());
    assert!(c.dispatch(Origin::Root, upgrade).result.is_ok());
}

#[test]
fn messages_from_the_hub_and_other_chains_arrive_in_the_next_block() {
    let mut c = chain();
    c.send_from(ChainId::HUB, CgmpPayload::TransferTog { to: BOB, amount: 70 });
    c.send_from(ChainId::HUB, CgmpPayload::TransferTog { to: BOB, amount: 5 });
    let peer = ChainId(9);
    c.send_from(peer, CgmpPayload::TransferTog { to: BOB, amount: 1 });
    let block = c.block();
    assert_eq!(block.header.inbox_processed, 3);
    assert_eq!(free(&mut c, &BOB), 75, "only the Hub mints $TOG here");
    let outcomes: Vec<system::Event> = c.events_of("system");
    assert!(outcomes.iter().any(|e| matches!(e, system::Event::Message { source, nonce: 0, .. } if *source == peer)));
    c.block();
    assert_eq!(c.header().inbox_processed, 3, "nothing new");
}

/// Alice asks for a job; its request is on its way to the Hub.
fn requested(c: &mut TestChain<Template>) -> ComputeRequest {
    let mut spec = tog_types::testing::sample_spec();
    spec.fee.max_budget = 300;
    spec.fee.inclusion_fee = 50;
    let call = compute::Call::Request { spec, fee: 10_000_000_000_000_000, timeout: None };
    c.submit(ALICE, (COMPUTE, compute::REQUEST, borsh::to_vec(&call).unwrap()));
    c.block();
    assert!(c.outcomes()[0].is_ok(), "{:?}", c.outcomes());
    let mut requests = c.take_compute_requests();
    assert_eq!(requests.len(), 1);
    let r = requests.remove(0);
    let events: Vec<compute::Event> = c.events_of("compute");
    assert_eq!(events, vec![compute::Event::Requested { job_id: r.job_id, payer: ALICE, nonce: 0 }]);
    assert!(c.take_sent().is_empty());
    r
}

#[test]
fn scripted_compute_results_come_back_as_events() {
    for (outcome, charged, refunded) in
        [(JobOutcome::Settled, 120, 180), (JobOutcome::Nondeterministic, 0, 300), (JobOutcome::ExecutorFault, 0, 300)]
    {
        let mut c = chain();
        let r = requested(&mut c);
        let before = total(&mut c, &ALICE);
        c.complete(&r, job_result(outcome, charged));
        c.block();
        let events: Vec<compute::Event> = c.events_of("compute");
        let compute::Event::Completed { result, refunded: back } = &events[0] else { panic!("{events:?}") };
        assert_eq!((result.job_id, result.outcome, *back), (r.job_id, outcome, refunded));
        assert_eq!(total(&mut c, &ALICE), before + refunded);
    }
}

#[test]
fn a_refused_request_is_refunded() {
    let mut c = chain();
    let r = requested(&mut c);
    let before = free(&mut c, &ALICE);
    c.refuse(&r, CgmpError::InsufficientFee);
    c.block();
    let events: Vec<compute::Event> = c.events_of("compute");
    assert_eq!(events, vec![compute::Event::Refused { job_id: r.job_id }]);
    assert!(free(&mut c, &ALICE) >= before + 350, "the budget and inclusion fee back");
}

#[test]
fn queries_reach_the_runtime() {
    let mut c = chain();
    let r = requested(&mut c);
    let job: Option<compute::Job> = borsh::from_slice(&c.query("compute_job", &r.job_id).unwrap()).unwrap();
    assert_eq!(job.map(|j| j.payer), Some(ALICE));
    assert!(c.query("nothing", &[]).is_err());

    // The metadata names exactly the calls the runtime dispatches.
    let meta: tog_runtime_core::metadata::RuntimeMetadata =
        borsh::from_slice(&c.query("metadata", &[]).unwrap()).unwrap();
    assert_eq!((meta.format, meta.name.as_str()), (0, "tog-runtime-template"));
    assert_eq!(meta.module(COMPUTE).map(|m| m.name.as_str()), Some("compute"));
    let mut named = 0;
    for module in 0..=u8::MAX {
        for call in 0..=u8::MAX {
            assert_eq!(meta.call_name(module, call), Template::call_name(module, call), "{module}.{call}");
            named += usize::from(meta.call_name(module, call).is_some());
        }
    }
    assert_eq!(named, 20);
}
