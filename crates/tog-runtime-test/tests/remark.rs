//! `remark` on the template runtime: a signed note, and a note another AppChain sends as a CGMP
//! `Call` to `tog/remark` (TOG-SPEC-0007 §4.6), the one call the templates take from other chains.

use tog_runtime_core::{AccountId, ChainId};
use tog_runtime_modules::remark::{self, Event, CGMP_NAME, MAX_LEN};
use tog_runtime_modules::system::{self, Outcome};
use tog_runtime_template::{GenesisConfig, Template, REMARK};
use tog_runtime_test::{CgmpOrigin, CgmpPayload, TestChain};
use tog_types::job::ModuleId;

const CHAIN: ChainId = ChainId(5);
const SOURCE: ChainId = ChainId(3);
const ALICE: AccountId = [2; 20];

fn chain() -> TestChain<Template> {
    TestChain::new(CHAIN, |author| {
        let config =
            GenesisConfig { balances: vec![(ALICE, 10u128.pow(21))], authorities: vec![author], root_key: None };
        borsh::to_vec(&config).unwrap()
    })
}

/// `borsh((0u8, data))`: the `Call` bytes of `remark(data)`.
fn note(data: &[u8]) -> Vec<u8> {
    let mut call = vec![remark::REMARK];
    call.extend(borsh::to_vec(&(data.to_vec(),)).unwrap());
    call
}

/// The outcomes of the last block's inbox messages.
fn inbox(c: &mut TestChain<Template>) -> Vec<Outcome> {
    c.events_of::<system::Event>("system")
        .into_iter()
        .filter_map(|e| match e {
            system::Event::Message { outcome, .. } => Some(outcome),
            _ => None,
        })
        .collect()
}

#[test]
fn a_signed_note_is_an_event_of_this_chain() {
    let mut c = chain();
    let (index, args) = remark::Call::Remark { data: b"hello".to_vec() }.encode();
    c.submit(ALICE, (REMARK, index, args));
    c.block();
    assert!(c.outcomes()[0].is_ok());
    let by = CgmpOrigin::Account { chain: CHAIN, account: ALICE };
    assert_eq!(c.events_of::<Event>("remark"), vec![Event::Remarked { source: CHAIN, by, data: b"hello".to_vec() }]);

    let (index, args) = remark::Call::Remark { data: vec![0; MAX_LEN + 1] }.encode();
    c.submit(ALICE, (REMARK, index, args));
    c.block();
    assert!(c.outcomes()[0].is_err(), "a note over MAX_LEN");
}

#[test]
fn another_chain_s_note_runs_with_its_claimed_sender() {
    let mut c = chain();
    let by = CgmpOrigin::Account { chain: SOURCE, account: [9; 20] };
    let limit = tog_runtime_template::weights::REMARK_REMARK;
    let call = |module: ModuleId, call: Vec<u8>| CgmpPayload::Call { module, call, weight_limit: limit };
    c.send(SOURCE, by.clone(), call(CGMP_NAME, note(b"from chain 3")), u64::MAX, 0);
    c.block();
    assert_eq!(inbox(&mut c), vec![Outcome::Executed]);
    assert_eq!(
        c.events_of::<Event>("remark"),
        vec![Event::Remarked { source: SOURCE, by, data: b"from chain 3".to_vec() }]
    );

    // Consumed without running: another module, another call, a note over MAX_LEN, a weight limit
    // over the declared one.
    c.send_from(SOURCE, call(ModuleId(*b"tog/assets\0\0\0\0\0\0"), note(b"x")));
    c.send_from(SOURCE, call(CGMP_NAME, vec![1]));
    c.send_from(SOURCE, call(CGMP_NAME, note(&[0; MAX_LEN + 1])));
    let over = limit.saturating_add(tog_runtime_core::Weight::from_parts(1, 0));
    c.send_from(SOURCE, CgmpPayload::Call { module: CGMP_NAME, call: note(b"x"), weight_limit: over });
    c.block();
    let outcomes = inbox(&mut c);
    assert_eq!(outcomes.len(), 4);
    assert!(outcomes.iter().all(|o| matches!(o, Outcome::Failed(_))), "{outcomes:?}");
    assert!(c.events_of::<Event>("remark").is_empty());
}
