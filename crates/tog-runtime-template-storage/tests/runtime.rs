//! The runtime on an in-memory chain (`tog test`): files named in the registry while a scripted
//! Hub deal holds them.

use tog_runtime_core::{AccountId, ChainId, DispatchError, ModuleError, Origin};
use tog_runtime_modules::balances;
use tog_runtime_modules::executive::Call;
use tog_runtime_template_storage::file_registry::{self, Error, Event, MAX_DEAL_BYTES, MAX_NAME};
use tog_runtime_template_storage::{GenesisConfig, Template, FILE_REGISTRY};
use tog_runtime_test::TestChain;
use tog_types::job::{DealId, PayloadRef, RetentionClass};
use tog_types::payload::{PayloadCommitment, PayloadKind};
use tog_types::state::items;
use tog_types::storage::{
    path, DealEnd, DealOwner, DealState, ExternalLocator, Layout, MerklePath, PayloadSetLeaf, SetFrontier, StorageDeal,
};
use tog_types::testing::payload;

const ALICE: AccountId = [2; 20];
const BOB: AccountId = [3; 20];
/// The deal's id on the Hub.
const DEAL: DealId = DealId(7);

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

/// The deal's three payloads.
fn payloads() -> Vec<PayloadCommitment> {
    (1..=3).map(|i| payload(PayloadKind::Input, i, 1_000 * u64::from(i), None)).collect()
}

/// `payloads()` in a deal of `ALICE`'s, in `state`, ending at `end`.
fn deal(state: DealState, end: u64) -> StorageDeal {
    let mut set = SetFrontier::new();
    set.append(&payloads()).unwrap();
    StorageDeal {
        id: DEAL,
        owner: DealOwner::Account(ALICE),
        payloads: set.set,
        frontier: set.frontier,
        class: RetentionClass::Hot,
        layout: Layout::Replicate { r: 3 },
        slots: vec![],
        price_per_gib_hour: 1,
        place_per_gib: 1,
        collateral_per_slot: 1,
        budget: 1,
        retrieval_allowance: 0,
        repair_reserve: 0,
        start: 1,
        end: DealEnd::At(end),
        state,
        external: vec![],
        materialized: vec![],
        regions: None,
    }
}

/// The Hub now holds `d`, or no deal.
fn hub(c: &mut TestChain<Template>, d: Option<&StorageDeal>) {
    c.set_hub(&items::deal(&DEAL), d.map(|d| borsh::to_vec(d).unwrap()));
}

/// Payload `i` of the deal, its offset and its path.
fn leaf(i: u32) -> (PayloadRef, u64, MerklePath) {
    let leaves = PayloadSetLeaf::chain(0, &payloads()).unwrap();
    let l = &leaves[i as usize];
    let file = PayloadRef { payload: payloads()[i as usize].clone(), deal: Some(DEAL) };
    (file, l.offset, path(&leaves, i).unwrap())
}

fn register(name: &str, i: u32) -> Call {
    let (file, offset, path) = leaf(i);
    file_registry::Call::Register { name: name.into(), file, offset, path }.into_call(FILE_REGISTRY)
}

fn err(e: Error) -> Result<tog_runtime_core::Weight, DispatchError> {
    Err(e.into_dispatch(FILE_REGISTRY))
}

fn reserved(c: &mut TestChain<Template>, who: &AccountId) -> u128 {
    balances::account(c.state(), who).unwrap().reserved
}

#[test]
fn a_held_payload_is_named_followed_and_removed() {
    let mut c = chain();
    hub(&mut c, Some(&deal(DealState::Active, 1_000)));
    c.submit(ALICE, register("photos/cat.jpg", 1));
    c.block();
    assert!(c.outcomes()[0].is_ok(), "{:?}", c.outcomes());
    let (file, ..) = leaf(1);
    let events: Vec<Event> = c.events_of("file_registry");
    let name = String::from("photos/cat.jpg");
    assert_eq!(events, [Event::Registered { name: name.clone(), owner: ALICE, file: file.clone(), end: 1_000 }]);
    let f = file_registry::file(c.state(), &name).unwrap().unwrap();
    assert_eq!((f.owner, f.file, f.end), (ALICE, file, 1_000));
    let deposit = reserved(&mut c, &ALICE);
    assert!(deposit > 0, "the name's deposit");

    // The name is Alice's; a wrong offset or path is no leaf of the set.
    assert_eq!(c.dispatch(Origin::Signed(BOB), register("photos/cat.jpg", 2)).result, err(Error::Taken));
    let (file, offset, path) = leaf(2);
    let off =
        file_registry::Call::Register { name: "x".into(), file: file.clone(), offset: offset + 1, path: path.clone() };
    assert_eq!(c.dispatch(Origin::Signed(BOB), off.into_call(FILE_REGISTRY)).result, err(Error::NotInDeal));
    let (_, _, other) = leaf(0);
    let wrong = file_registry::Call::Register { name: "x".into(), file, offset, path: other };
    assert_eq!(c.dispatch(Origin::Signed(BOB), wrong.into_call(FILE_REGISTRY)).result, err(Error::NotInDeal));

    // Renewed on the Hub: anyone's refresh moves the end, and the same end changes nothing.
    hub(&mut c, Some(&deal(DealState::Repairing { slots: vec![1] }, 5_000)));
    let refresh = file_registry::Call::Refresh { name: name.clone() }.into_call(FILE_REGISTRY);
    c.submit(BOB, refresh.clone());
    c.submit(BOB, refresh);
    c.block();
    assert!(c.outcomes().iter().all(Result::is_ok), "{:?}", c.outcomes());
    let events: Vec<Event> = c.events_of("file_registry");
    assert_eq!(events, [Event::Refreshed { name: name.clone(), end: 5_000 }]);
    assert_eq!(file_registry::file(c.state(), &name).unwrap().unwrap().end, 5_000);

    // Only Alice removes it, and her deposit comes back.
    let remove = file_registry::Call::Remove { name: name.clone() }.into_call(FILE_REGISTRY);
    assert_eq!(c.dispatch(Origin::Signed(BOB), remove.clone()).result, err(Error::NotOwner));
    c.submit(ALICE, remove);
    c.block();
    assert!(c.outcomes()[0].is_ok(), "{:?}", c.outcomes());
    let events: Vec<Event> = c.events_of("file_registry");
    assert_eq!(events, [Event::Removed { name: name.clone(), expired: false }]);
    assert_eq!(file_registry::file(c.state(), &name).unwrap(), None);
    assert_eq!(reserved(&mut c, &ALICE), 0, "the deposit is back");
}

#[test]
fn a_file_is_dropped_once_its_deal_no_longer_holds_it() {
    for gone in [Some(deal(DealState::Releasing { until: 900 }, 1_000)), Some(deal(DealState::Active, 3)), None] {
        let mut c = chain();
        hub(&mut c, Some(&deal(DealState::Active, 1_000)));
        c.submit(ALICE, register("a", 0));
        c.block();
        assert!(reserved(&mut c, &ALICE) > 0);

        // Released, past its end, or gone from the Hub: Bob's refresh frees the name.
        hub(&mut c, gone.as_ref());
        c.blocks(3);
        c.submit(BOB, file_registry::Call::Refresh { name: "a".into() }.into_call(FILE_REGISTRY));
        c.block();
        assert!(c.outcomes()[0].is_ok(), "{gone:?}: {:?}", c.outcomes());
        let events: Vec<Event> = c.events_of("file_registry");
        assert_eq!(events, [Event::Removed { name: "a".into(), expired: true }], "{gone:?}");
        assert_eq!(reserved(&mut c, &ALICE), 0, "{gone:?}: Alice's deposit is back");
        // Nor can the deal name it again.
        let again = c.dispatch(Origin::Signed(BOB), register("a", 0)).result;
        assert_eq!(again, err(if gone.is_some() { Error::NotHeld } else { Error::NoDeal }), "{gone:?}");
    }
}

#[test]
fn only_a_held_deal_in_reach_names_a_file() {
    let mut c = chain();
    let try_register =
        |c: &mut TestChain<Template>, name: &str| c.dispatch(Origin::Signed(ALICE), register(name, 0)).result;
    assert_eq!(try_register(&mut c, "a"), err(Error::NoDeal));
    hub(&mut c, Some(&deal(DealState::Placing { deadline: 50 }, 1_000)));
    assert_eq!(try_register(&mut c, "a"), err(Error::NotHeld));
    let relay = 1;
    hub(&mut c, Some(&deal(DealState::Active, relay)));
    assert_eq!(try_register(&mut c, "a"), err(Error::NotHeld));
    hub(&mut c, Some(&deal(DealState::Active, 1_000)));
    assert_eq!(try_register(&mut c, ""), err(Error::BadName));
    assert_eq!(try_register(&mut c, &"n".repeat(MAX_NAME + 1)), err(Error::BadName));
    assert!(try_register(&mut c, &"n".repeat(MAX_NAME)).is_ok());

    // A payload with no deal, and a deal too large to read.
    let (file, offset, path) = leaf(0);
    let no_deal =
        file_registry::Call::Register { name: "b".into(), file: PayloadRef { deal: None, ..file }, offset, path };
    assert_eq!(c.dispatch(Origin::Signed(ALICE), no_deal.into_call(FILE_REGISTRY)).result, err(Error::NoDeal));
    let mut large = deal(DealState::Active, 1_000);
    large.external = vec![ExternalLocator::Arweave { tx_id: [9; 32] }; MAX_DEAL_BYTES / 32];
    hub(&mut c, Some(&large));
    assert_eq!(try_register(&mut c, "b"), err(Error::DealTooLarge));
}

#[test]
fn a_lazy_deal_names_only_its_materialized_leaves() {
    let mut c = chain();
    let mut lazy = deal(DealState::Active, 1_000);
    lazy.materialized = vec![0b101];
    hub(&mut c, Some(&lazy));
    let mut try_register = |name: &str, i| c.dispatch(Origin::Signed(ALICE), register(name, i)).result;
    assert!(try_register("a", 0).is_ok());
    assert_eq!(try_register("b", 1), err(Error::NotMaterialized));
    assert!(try_register("c", 2).is_ok());
}

#[test]
fn a_commitment_that_is_not_v1_names_no_file() {
    let mut c = chain();
    hub(&mut c, Some(&deal(DealState::Active, 1_000)));
    let (file, offset, path) = leaf(0);
    let with = |f: fn(&mut PayloadCommitment)| {
        let mut file = file.clone();
        f(&mut file.payload);
        file_registry::Call::Register { name: "a".into(), file, offset, path: path.clone() }.into_call(FILE_REGISTRY)
    };
    for bad in [with(|p| p.version = 2), with(|p| p.piece_log2 = 19), with(|p| p.piece_log2 = 23)] {
        assert_eq!(c.dispatch(Origin::Signed(ALICE), bad).result, err(Error::BadPayload));
    }
    assert!(c.dispatch(Origin::Signed(ALICE), with(|p| p.piece_log2 = 22)).result.is_ok());
}

#[test]
fn another_chain_s_note_reaches_remark() {
    use tog_runtime_modules::remark;
    let mut c = chain();
    let by = tog_runtime_test::CgmpOrigin::Account { chain: ChainId(3), account: [9; 20] };
    let mut call = vec![remark::REMARK];
    call.extend(borsh::to_vec(&(b"hi".to_vec(),)).unwrap());
    let weight_limit = tog_runtime_template_storage::weights::REMARK_REMARK;
    let payload = tog_runtime_test::CgmpPayload::Call { module: remark::CGMP_NAME, call, weight_limit };
    c.send(ChainId(3), by.clone(), payload, u64::MAX, 0);
    c.block();
    let noted = remark::Event::Remarked { source: ChainId(3), by, data: b"hi".to_vec() };
    assert_eq!(c.events_of::<remark::Event>("remark"), vec![noted]);
}
