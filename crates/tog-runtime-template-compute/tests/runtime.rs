//! The runtime on an in-memory chain (`tog test`): a model fine-tuned by scripted compute results.

use tog_runtime_core::{AccountId, ChainId};
use tog_runtime_template_compute::model_registry::{self, Event};
use tog_runtime_template_compute::{GenesisConfig, Template, MODEL_REGISTRY};
use tog_runtime_test::{job_result, JobOutcome, TestChain};
use tog_types::job::{DealId, PayloadRef};
use tog_types::payload::{Encryption, PayloadCommitment, PayloadKind};
use tog_types::testing::{payload, sample_spec};

const ALICE: AccountId = [2; 20];
const BOB: AccountId = [3; 20];

fn chain() -> TestChain<Template> {
    TestChain::new(ChainId(5), |author| {
        let config = GenesisConfig {
            balances: vec![(ALICE, 10u128.pow(21)), (BOB, 10u128.pow(21))],
            authorities: vec![author],
            root_key: None,
        };
        borsh::to_vec(&config).unwrap()
    })
}

fn archive(root: u8) -> PayloadCommitment {
    payload(PayloadKind::Output, root, 1_000, None)
}

/// `archive(root)` in deal `root`.
fn stored(root: u8) -> PayloadRef {
    PayloadRef { payload: archive(root), deal: Some(DealId(u64::from(root))) }
}

/// A job's output archive `root`, sealed, whose plaintext is `archive(plain)`.
fn sealed(root: u8, plain: u8) -> PayloadCommitment {
    let encryption = Encryption::Checkpoint { plaintext_root: [plain; 32], key_commitment: [0xee; 32] };
    PayloadCommitment { encryption, ..archive(root) }
}

fn publish(model: u64, weights: PayloadRef) -> model_registry::Call {
    model_registry::Call::Publish { model, weights }
}

/// Alice registers model 0 with weights `archive(1)`.
fn registered(c: &mut TestChain<Template>) {
    let call = model_registry::Call::Register { spec: sample_spec(), weights: stored(1) };
    c.submit(ALICE, call.into_call(MODEL_REGISTRY));
    c.block();
    assert!(c.outcomes()[0].is_ok(), "{:?}", c.outcomes());
}

fn fine_tune(model: u64) -> model_registry::Call {
    model_registry::Call::FineTune { model, dataset: stored(9), max_budget: 300, fee: 10u128.pow(16) }
}

#[test]
fn a_settled_job_is_the_models_next_version_once_published() {
    let mut c = chain();
    registered(&mut c);
    c.submit(ALICE, fine_tune(0).into_call(MODEL_REGISTRY));
    c.block();
    assert!(c.outcomes()[0].is_ok(), "{:?}", c.outcomes());

    // The job trains the model's weights on the dataset, each staged from its deal.
    let request = c.take_compute_requests().remove(0);
    let mounts: Vec<_> = request.spec.inputs.iter().map(|i| (i.mount_name.as_str(), i.content.clone())).collect();
    assert_eq!(mounts, [("base", stored(1)), ("data", stored(9))]);
    assert_eq!(request.spec.fee.max_budget, 300);
    // Its executor may be found until a window after the block's relay parent, a few blocks in.
    let relay = request.spec.fee.claim_deadline_height - model_registry::CLAIM_WINDOW;
    assert!((1..10).contains(&relay), "relay parent {relay}");
    let events: Vec<Event> = c.events_of("model_registry");
    assert_eq!(events, [Event::FineTuning { model: 0, job_id: request.job_id }]);

    // Its sealed output archive is pending.
    let mut result = job_result(JobOutcome::Settled, 120);
    result.outputs = vec![(String::new(), sealed(7, 8))];
    c.complete(&request, result);
    c.block();
    let events: Vec<Event> = c.events_of("model_registry");
    assert_eq!(events, [Event::Trained { model: 0, job_id: request.job_id, sealed: sealed(7, 8) }]);
    let m = model_registry::model(c.state(), 0).unwrap().unwrap();
    assert_eq!((m.version, &m.weights, m.pending.map(|p| p.plaintext_root())), (0, &stored(1), Some([8; 32])));

    // Only the owner publishes, and only its plaintext, in a deal.
    c.submit(BOB, publish(0, stored(8)).into_call(MODEL_REGISTRY));
    c.submit(ALICE, publish(0, stored(9)).into_call(MODEL_REGISTRY));
    c.submit(ALICE, publish(0, PayloadRef { payload: archive(8), deal: None }).into_call(MODEL_REGISTRY));
    c.submit(ALICE, publish(0, PayloadRef { payload: sealed(7, 8), deal: Some(DealId(7)) }).into_call(MODEL_REGISTRY));
    c.block();
    assert!(c.outcomes().iter().all(Result::is_err), "{:?}", c.outcomes());

    c.submit(ALICE, publish(0, stored(8)).into_call(MODEL_REGISTRY));
    c.block();
    assert!(c.outcomes()[0].is_ok(), "{:?}", c.outcomes());
    let events: Vec<Event> = c.events_of("model_registry");
    assert_eq!(events, [Event::NewVersion { model: 0, version: 1, weights: stored(8) }]);
    let m = model_registry::model(c.state(), 0).unwrap().unwrap();
    assert_eq!((m.version, &m.weights, &m.pending), (1, &stored(8), &None));

    // The next job trains version 1; nothing is pending to publish again.
    c.submit(ALICE, publish(0, stored(8)).into_call(MODEL_REGISTRY));
    c.submit(ALICE, fine_tune(0).into_call(MODEL_REGISTRY));
    c.block();
    let outcomes = c.outcomes();
    assert!(outcomes[0].is_err() && outcomes[1].is_ok(), "{outcomes:?}");
    let request = c.take_compute_requests().remove(0);
    assert_eq!(request.spec.inputs[0].content, stored(8));
}

#[test]
fn weights_and_datasets_are_plaintext_in_a_deal() {
    let mut c = chain();
    let loose = PayloadRef { payload: archive(1), deal: None };
    let call = model_registry::Call::Register { spec: sample_spec(), weights: loose.clone() };
    c.submit(ALICE, call.into_call(MODEL_REGISTRY));
    let sealed = PayloadRef { payload: sealed(1, 2), deal: Some(DealId(1)) };
    c.submit(ALICE, model_registry::Call::Register { spec: sample_spec(), weights: sealed }.into_call(MODEL_REGISTRY));
    c.block();
    assert!(c.outcomes().iter().all(Result::is_err), "{:?}", c.outcomes());
    assert_eq!(model_registry::model(c.state(), 0).unwrap(), None);

    registered(&mut c);
    let call = model_registry::Call::FineTune { model: 0, dataset: loose, max_budget: 300, fee: 10u128.pow(16) };
    c.submit(ALICE, call.into_call(MODEL_REGISTRY));
    c.block();
    assert!(c.outcomes()[0].is_err());
    assert!(c.take_compute_requests().is_empty());
}

#[test]
fn a_job_that_doesnt_settle_leaves_the_model() {
    let mut c = chain();
    registered(&mut c);
    c.submit(ALICE, fine_tune(0).into_call(MODEL_REGISTRY));
    c.block();
    let request = c.take_compute_requests().remove(0);
    c.complete(&request, job_result(JobOutcome::Nondeterministic, 0));
    c.block();
    let events: Vec<Event> = c.events_of("model_registry");
    let outcome = JobOutcome::Nondeterministic;
    assert_eq!(events, [Event::NotTrained { model: 0, job_id: request.job_id, outcome }]);
    let m = model_registry::model(c.state(), 0).unwrap().unwrap();
    assert_eq!((m.version, m.weights), (0, stored(1)));
}

#[test]
fn only_the_owner_fine_tunes() {
    let mut c = chain();
    registered(&mut c);
    c.submit(BOB, fine_tune(0).into_call(MODEL_REGISTRY));
    c.submit(BOB, fine_tune(1).into_call(MODEL_REGISTRY));
    c.block();
    let outcomes = c.outcomes();
    assert!(outcomes.iter().all(|o| o.is_err()), "{outcomes:?}");
    assert!(c.take_compute_requests().is_empty());
}

#[test]
fn sudo_calls_nest_at_most_four_deep() {
    // R-1: a call is weighed before any fee or key check, one decode per level; past
    // `MAX_NESTING` it is an unknown call.
    use tog_runtime_modules::executive::{Call, Runtime};
    use tog_runtime_modules::sudo;
    use tog_runtime_template_compute::SUDO;
    let nest = |depth: u32| {
        let set_key: Call = (SUDO, sudo::SET_KEY, borsh::to_vec(&ALICE).unwrap());
        (0..depth).fold(set_key, |inner, _| (SUDO, sudo::CALL, borsh::to_vec(&inner).unwrap()))
    };
    assert!(Template::call_weight(&nest(sudo::MAX_NESTING)).is_some());
    for depth in [sudo::MAX_NESTING + 1, 40_000] {
        assert_eq!(Template::call_weight(&nest(depth)), None, "depth {depth}");
    }
}

#[test]
fn a_spec_too_large_for_its_jobs_is_not_registered() {
    let mut c = chain();
    let mut spec = sample_spec();
    spec.command.args.push("a".repeat(model_registry::MAX_SPEC_BYTES));
    c.submit(ALICE, model_registry::Call::Register { spec, weights: stored(1) }.into_call(MODEL_REGISTRY));
    c.block();
    assert!(c.outcomes()[0].is_err());
    assert_eq!(model_registry::model(c.state(), 0).unwrap(), None);
}

#[test]
fn another_chain_s_note_reaches_remark() {
    use tog_runtime_modules::remark;
    let mut c = chain();
    let by = tog_runtime_test::CgmpOrigin::Account { chain: ChainId(3), account: [9; 20] };
    let mut call = vec![remark::REMARK];
    call.extend(borsh::to_vec(&(b"hi".to_vec(),)).unwrap());
    let weight_limit = tog_runtime_modules::remark::call_weight(
        tog_runtime_modules::remark::REMARK,
        &borsh::to_vec(&(b"hi".to_vec(),)).unwrap(),
    )
    .unwrap();
    let payload = tog_runtime_test::CgmpPayload::Call { module: remark::CGMP_NAME, call, weight_limit };
    c.send(ChainId(3), by.clone(), payload, u64::MAX, 0);
    c.block();
    let noted = remark::Event::Remarked { source: ChainId(3), by, data: b"hi".to_vec() };
    assert_eq!(c.events_of::<remark::Event>("remark"), vec![noted]);
}
