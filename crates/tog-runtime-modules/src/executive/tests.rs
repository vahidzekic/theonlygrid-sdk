use super::*;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use tog_runtime_core::hash::tagged;
use tog_runtime_core::memory::MemoryStorage;
use tog_runtime_core::tx::AppTxBody;
use tog_types::tx::Signature;

use crate::{balances, governance, storage_deposit, sudo};

const CHAIN: ChainId = ChainId(5);
const NETWORK: u32 = 1;
const DOMAIN: u64 = (1 << 32) | 5;
const AUTHOR: AccountId = [9; 20];
const ROOT: AccountId = [1; 20];
const ALICE: AccountId = [2; 20];
const BOB: AccountId = [3; 20];
const FUNDS: Balance = 1_000_000_000_000_000_000;
const CALL_WEIGHT: Weight = Weight::from_parts(1_000_000, 100);
const CODE: Hash32 = [7; 32];

use tog_runtime_core::Balance;

/// The host, natively: storage, a fixed relay parent and Hub state, the CGMP queues, and a state
/// root that hashes every item.
#[derive(Clone, Default)]
struct Mock {
    s: MemoryStorage,
    relay: (HubHeight, Hash32),
    hub: BTreeMap<Vec<u8>, Vec<u8>>,
    inbox: VecDeque<Vec<u8>>,
    outbox: Vec<Vec<u8>>,
}

impl Storage for Mock {
    fn get(&mut self, key: &StorageKey) -> Option<Vec<u8>> {
        self.s.get(key)
    }
    fn set(&mut self, key: &StorageKey, value: Vec<u8>) {
        self.s.set(key, value)
    }
    fn clear(&mut self, key: &StorageKey) {
        self.s.clear(key)
    }
    fn next_key(&mut self, key: &StorageKey) -> Option<StorageKey> {
        self.s.next_key(key)
    }
}

impl Env for Mock {
    fn chain_context(&mut self) -> (ChainId, u32) {
        (CHAIN, NETWORK)
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
        let parts: Vec<&[u8]> = self.s.iter().flat_map(|(k, v)| [&k[..], &v[..]]).collect();
        tagged("test/root", &parts)
    }
}

/// Signatures are `address ‖ 0…` with `v = 0`; any other `v` is a bad one.
struct Check;

impl SignatureCheck for Check {
    fn ed25519_verify(&self, _: &[u8; 32], _: &[u8; 64], _: &[u8]) -> bool {
        false
    }
    fn secp256k1_signer(&self, _: &Hash32, sig: &[u8; 65]) -> Option<AccountId> {
        (sig[64] == 0).then(|| sig[..20].try_into().unwrap())
    }
}

/// Modules: 0 `balances`, 1 `sudo`, 2 `system`.
struct Test;

impl Runtime for Test {
    const NAME: &'static str = "test";
    const SPEC_VERSION: u32 = 3;

    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
        Some(match (module, call) {
            (0, 0) => ("balances", "transfer"),
            (1, 0) => ("sudo", "call"),
            (1, 1) => ("sudo", "set_key"),
            (1, 2) => ("sudo", "remove_key"),
            (2, 0) => ("system", "authorize_upgrade"),
            (3, compute::REQUEST) => ("compute", "request"),
            _ => return None,
        })
    }

    fn call_weight(call: &Call) -> Option<Weight> {
        Self::call_name(call.0, call.1).map(|_| CALL_WEIGHT)
    }

    fn pre_check(s: &mut impl Storage, _: &AccountId, call: &Call) -> Result<(), u8> {
        // A check that writes (R-8): the write must never reach the state.
        s.set(&PRE_CHECK_MARK, vec![1]);
        // A transfer of nothing is refused before it is paid for.
        match (call.0, call.1, borsh::from_slice::<balances::Call>(&call.2)) {
            (0, 0, Ok(balances::Call::Transfer { amount: 0, .. })) => Err(1),
            _ => Ok(()),
        }
    }

    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError> {
        let bad = || DispatchError::Other("bad call");
        match (call.0, call.1) {
            (0, 0) => {
                let c: balances::Call = borsh::from_slice(&call.2).map_err(|_| bad())?;
                let balances::Call::Transfer { to, amount } = c.clone();
                // Deposited first: a failing transfer must take it with it.
                e.deposit_event("balances", &balances::Event::Transfer { from: ALICE, to, amount });
                balances::dispatch(e, 0, origin, c)
            }
            (1, sudo::CALL) => {
                let inner: Call = borsh::from_slice(&call.2).map_err(|_| bad())?;
                // The inner result goes to the block's events; the outer call succeeds.
                let r =
                    sudo::call(e, origin, inner, |s, o, i| s.nested(|sc| Self::dispatch(sc, cx, o, i)).map(|_| ()))?;
                e.deposit_event("sudo", &sudo::Event::Sudid(r.map_err(Into::into)));
                Ok(())
            }
            (1, sudo::SET_KEY) => sudo::set_key(e, origin, borsh::from_slice(&call.2).map_err(|_| bad())?),
            (1, sudo::REMOVE_KEY) => sudo::remove_key(e, origin),
            (2, 0) => system::authorize_upgrade(e, &origin, borsh::from_slice(&call.2).map_err(|_| bad())?)
                .map_err(|_| DispatchError::BadOrigin),
            (3, compute::REQUEST) => {
                compute::dispatch(e, cx, 3, origin, borsh::from_slice(&call.2).map_err(|_| bad())?, 0).map(|_| ())
            }
            _ => Err(bad()),
        }
        .map(|()| CALL_WEIGHT)
    }

    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        let (accounts, root): (Vec<(AccountId, Balance)>, Option<AccountId>) =
            borsh::from_slice(config).expect("config decodes");
        for (who, amount) in accounts {
            balances::deposit(e, &who, amount).expect("genesis balance");
        }
        collator_selection::genesis(e, vec![AUTHOR]).expect("authorities");
        sudo::genesis(e, root).expect("sudo key");
    }
}

/// A chain at genesis with `ROOT` and `ALICE` funded and the relay parent at 10.
fn chain() -> (Mock, HeadData) {
    let mut m = Mock { relay: (10, [4; 32]), ..Mock::default() };
    let config = borsh::to_vec(&(vec![(ROOT, FUNDS), (ALICE, FUNDS)], Some(ROOT))).unwrap();
    let root: Hash32 = borsh::from_slice(&genesis::<Test, _>(&mut m, &borsh::to_vec(&config).unwrap())).unwrap();
    assert_eq!(root, m.storage_root());
    (m, Header::genesis(root).head_data())
}

fn tx(signer: AccountId, nonce: u64, call: Call) -> Vec<u8> {
    let body = AppTxBody { chain_id: DOMAIN, nonce, tip: 5, valid_until: 100, call };
    let mut sig = [0; 65];
    sig[..20].copy_from_slice(&signer);
    borsh::to_vec(&AppTx { body, signer, sig: Signature::Secp256k1(sig) }).unwrap()
}

fn transfer(to: AccountId, amount: Balance) -> Call {
    (0, 0, borsh::to_vec(&balances::Call::Transfer { to, amount }).unwrap())
}

fn inherents(m: &Mock) -> Vec<Inherent> {
    vec![Inherent::RelayParent { height: m.relay.0, hash: m.relay.1 }, Inherent::Collator { account: AUTHOR }]
}

/// What `Test::pre_check` writes.
const PRE_CHECK_MARK: StorageKey = [0xEE; 96];

fn build(m: &mut Mock, parent: &HeadData, txs: Vec<Vec<u8>>) -> Block {
    let input = borsh::to_vec(&(parent.clone(), inherents(m), txs)).unwrap();
    borsh::from_slice::<(Block, bool)>(&build_block::<Test, _>(m, &Check, &input)).unwrap().0
}

#[test]
fn a_built_block_executes_and_validates_to_the_same_head() {
    let (genesis_state, genesis_head) = chain();
    let mut built = genesis_state.clone();
    let block = build(
        &mut built,
        &genesis_head,
        vec![
            tx(ALICE, 0, transfer(BOB, 1_000)),
            tx(ALICE, 0, transfer(BOB, 1_000)), // stale nonce: left out
            tx(BOB, 0, transfer(ALICE, 1)),     // can't pay: left out
            tx(ALICE, 1, transfer(BOB, 0)),     // refused by the call's own check: left out
            tx(ALICE, 1, transfer(BOB, FUNDS)), // dispatch fails: included, fee paid
            tx(ROOT, 0, (2, 0, borsh::to_vec(&CODE).unwrap())), // not Root: included, fails
        ],
    );
    assert_eq!(block.extrinsics.len(), 3);
    assert_eq!(built.get(&PRE_CHECK_MARK), None, "pre_check's writes are discarded, refused or not");
    assert_eq!(block.header.number, 1);
    assert_eq!(block.header.parent, head_hash(&genesis_head));
    assert_eq!(block.header.state_root, built.storage_root());
    assert_eq!(balances::free_balance(&mut built, &BOB).unwrap(), 1_000);
    assert_eq!(system::nonce(&mut built, &ALICE).unwrap(), 2);
    // The author got every fee and tip.
    // Alice also reserved the storage deposit for Bob's new account.
    let alice = balances::account(&mut built, &ALICE).unwrap();
    let held = storage_deposit::deposit_for(balances::ACCOUNT_BYTES, storage_deposit::DEFAULT_PER_BYTE).unwrap();
    assert_eq!(alice.reserved, held);
    let alice_paid = FUNDS - 1_000 - alice.total();
    let root_paid = FUNDS - balances::free_balance(&mut built, &ROOT).unwrap();
    assert_eq!(balances::free_balance(&mut built, &AUTHOR).unwrap(), alice_paid + root_paid);
    assert!(root_paid > 5);

    let mut imported = genesis_state.clone();
    execute_block::<Test, _>(&mut imported, &Check, &borsh::to_vec(&block).unwrap());
    assert_eq!(imported.storage_root(), built.storage_root());

    let mut validated = genesis_state;
    let pov = Pov {
        parent_head: genesis_head,
        block: block.clone(),
        witness: Default::default(),
        inbox: Vec::new(),
        hub_proofs: Vec::new(),
    };
    let r: ValidationResult =
        borsh::from_slice(&validate_block::<Test, _>(&mut validated, &Check, &borsh::to_vec(&pov).unwrap())).unwrap();
    assert_eq!(r.head, block.header.head_data());
    assert_eq!(r.new_code, None);
    assert!(r.outbox.is_empty() && r.inbox.is_empty());

    // The next block builds on it.
    built.relay = (11, [5; 32]);
    let next = build(&mut built, &block.header.head_data(), vec![tx(ALICE, 2, transfer(BOB, 1))]);
    assert_eq!((next.header.number, next.extrinsics.len()), (2, 1));
    assert_eq!(next.header.parent, block.header.hash());
}

#[test]
#[should_panic(expected = "transaction 1: StaleNonce")]
fn an_imported_block_with_a_failing_transaction_is_invalid() {
    let (mut m, head) = chain();
    let mut block = build(&mut m.clone(), &head, vec![tx(ALICE, 0, transfer(BOB, 1))]);
    block.extrinsics.push(tx(ALICE, 0, transfer(BOB, 1)));
    execute_block::<Test, _>(&mut m, &Check, &borsh::to_vec(&block).unwrap());
}

#[test]
#[should_panic(expected = "header mismatch")]
fn an_imported_block_must_carry_the_header_it_produces() {
    let (mut m, head) = chain();
    let mut block = build(&mut m.clone(), &head, vec![tx(ALICE, 0, transfer(BOB, 1))]);
    block.header.state_root[0] ^= 1;
    execute_block::<Test, _>(&mut m, &Check, &borsh::to_vec(&block).unwrap());
}

#[test]
#[should_panic(expected = "block author")]
fn only_the_slot_author_may_build() {
    let (mut m, head) = chain();
    let input = borsh::to_vec(&(
        head,
        vec![inherents(&m)[0].clone(), Inherent::Collator { account: BOB }],
        Vec::<Vec<u8>>::new(),
    ))
    .unwrap();
    build_block::<Test, _>(&mut m, &Check, &input);
}

#[test]
fn sudo_runs_a_call_as_root_and_the_upgrade_reaches_the_result() {
    let (mut m, head) = chain();
    let upgrade = (2, 0, borsh::to_vec(&CODE).unwrap());
    let as_root = |c: &Call| (1, sudo::CALL, borsh::to_vec(c).unwrap());
    let block = build(
        &mut m.clone(),
        &head,
        vec![
            tx(ALICE, 0, as_root(&upgrade)), // not the key: the outer call fails, the tx is in
            tx(ROOT, 0, as_root(&upgrade)),
            tx(ROOT, 1, as_root(&upgrade)), // inner fails (already authorized), outer succeeds
            tx(ROOT, 2, (1, sudo::REMOVE_KEY, Vec::new())),
            tx(ROOT, 3, as_root(&upgrade)), // no key any more
        ],
    );
    assert_eq!(block.extrinsics.len(), 5);
    let pov = Pov { parent_head: head, block, witness: Default::default(), inbox: Vec::new(), hub_proofs: Vec::new() };
    let r: ValidationResult =
        borsh::from_slice(&validate_block::<Test, _>(&mut m, &Check, &borsh::to_vec(&pov).unwrap())).unwrap();
    assert_eq!(r.new_code, Some(CODE));
    assert_eq!(sudo::key(&mut m).unwrap(), None);
    assert_eq!(system::AUTHORIZED_UPGRADE.get(&mut m).unwrap(), None);
}

#[test]
fn the_pool_check_matches_the_block_rules() {
    let (mut m, _) = chain();
    let check = |m: &mut Mock, x: Vec<u8>| -> TxValidity {
        borsh::from_slice(&validate_tx::<Test, _>(m, &Check, &borsh::to_vec(&(x, TxSource::External)).unwrap()))
            .unwrap()
    };
    assert_eq!(
        check(&mut m, tx(ALICE, 3, transfer(BOB, 1))),
        Ok(ValidTx { sender: ALICE, nonce: 3, priority: 5, longevity: 100 })
    );
    assert_eq!(check(&mut m, tx(BOB, 0, transfer(ALICE, 1))), Err(TxError::CannotPay));
    assert_eq!(check(&mut m, tx(ALICE, 0, transfer(BOB, 0))), Err(TxError::Call(1)));
    assert_eq!(check(&mut m, tx(ALICE, 0, (0, 9, Vec::new()))), Err(TxError::BadFormat));
    assert_eq!(check(&mut m, vec![1, 2, 3]), Err(TxError::BadFormat));

    let mut bad = borsh::from_slice::<AppTx>(&tx(ALICE, 0, transfer(BOB, 1))).unwrap();
    bad.body.chain_id = 5;
    assert_eq!(check(&mut m, borsh::to_vec(&bad).unwrap()), Err(TxError::WrongChain));
    bad.body.chain_id = DOMAIN;
    bad.body.valid_until = 0;
    assert_eq!(check(&mut m, borsh::to_vec(&bad).unwrap()), Err(TxError::Expired));
    // An EIP-712 signature is checked against the call's kind.
    bad.body.valid_until = 100;
    let Signature::Secp256k1(sig) = bad.sig else { unreachable!() };
    bad.sig = Signature::Secp256k1Eip712(sig);
    assert_eq!(check(&mut m, borsh::to_vec(&bad).unwrap()).map(|v| v.sender), Ok(ALICE));
    bad.body.call = (0, 9, Vec::new());
    assert_eq!(check(&mut m, borsh::to_vec(&bad).unwrap()), Err(TxError::BadFormat));
}

#[test]
fn standard_queries_and_version() {
    let (mut m, _) = chain();
    let q = |m: &mut Mock, method: &str, args: Vec<u8>| -> Result<Vec<u8>, String> {
        borsh::from_slice(&query::<Test, _>(m, &borsh::to_vec(&(method.to_string(), args)).unwrap())).unwrap()
    };
    let author = q(&mut m, "slot_author", borsh::to_vec(&12u64).unwrap()).unwrap();
    assert_eq!(borsh::from_slice::<Option<AccountId>>(&author).unwrap(), Some(AUTHOR));

    let x = tx(ALICE, 0, transfer(BOB, 1));
    let fee: Balance = borsh::from_slice(&q(&mut m, "fee_estimate", x.clone()).unwrap()).unwrap();
    let w = CALL_WEIGHT.saturating_add(Weight::from_parts(0, x.len() as u64));
    assert_eq!(fee, FeeParams::DEFAULT.fee(w).unwrap() + 5);

    let account = |m: &mut Mock, who: AccountId| -> (u64, balances::AccountData) {
        borsh::from_slice(&q(m, "account", borsh::to_vec(&who).unwrap()).unwrap()).unwrap()
    };
    let (nonce, alice) = account(&mut m, ALICE);
    assert_eq!((nonce, alice), (0, balances::account(&mut m, &ALICE).unwrap()));
    assert!(alice.free > 0);
    assert_eq!(account(&mut m, [0x77; 20]), (0, balances::AccountData::default()));
    assert!(q(&mut m, "account", vec![1]).is_err());

    assert_eq!(q(&mut m, "metadata", Vec::new()), Ok(Vec::new()));
    assert!(q(&mut m, "nothing", Vec::new()).is_err());

    let v: RuntimeVersion = borsh::from_slice(&version::<Test>()).unwrap();
    assert_eq!((v.name.as_str(), v.spec_version, v.abi_version), ("test", 3, ABI_VERSION));
}

#[test]
fn hub_time_is_read_at_the_relay_parent() {
    let (mut m, _) = chain();
    let key = tog_types::state::items::system_last_block().to_vec();
    m.hub.insert(key.clone(), Vec::new());
    assert_eq!(system::hub_last_block(&mut m), Err(tog_runtime_core::StorageError::Corrupt));
    m.hub.insert(key, borsh::to_vec(&(1_700_000_000_000u64, [8u8; 32])).unwrap());
    assert_eq!(system::hub_last_block(&mut m), Ok(Some((1_700_000_000_000, [8; 32]))));
}

#[test]
fn a_hub_proof_is_at_most_its_charge() {
    use tog_types::state::{ProofLeaf, StateProof};
    let proof =
        StateProof { leaf: Some(ProofLeaf { key_hash: [1; 32], value_hash: [2; 32] }), siblings: vec![[3; 32]; 256] };
    let value = vec![7u8; 40];
    let entry: tog_runtime_core::block::HubProof = (vec![0; 96], Some(value.clone()), borsh::to_vec(&proof).unwrap());
    assert!(borsh::to_vec(&entry).unwrap().len() as u64 <= HUB_PROOF_BYTES + value.len() as u64);
}

#[test]
fn a_block_records_each_outcome_and_a_failed_calls_events_go_with_it() {
    let (mut m, head) = chain();
    assert_eq!(system::EVENTS.get(&mut m).unwrap(), None, "genesis has none");
    let as_root = |c: &Call| (1, sudo::CALL, borsh::to_vec(c).unwrap());
    let block = build(
        &mut m,
        &head,
        vec![
            tx(ALICE, 0, transfer(BOB, 1_000)),
            tx(ALICE, 1, transfer(BOB, FUNDS)), // fails: its Transfer event goes with it
            tx(ROOT, 0, as_root(&transfer(BOB, 1))), // the inner call fails, sudo succeeds
        ],
    );
    assert_eq!(block.extrinsics.len(), 3);
    let ev = |phase: u32, module: &str, event: Vec<u8>| system::EventRecord {
        phase: system::Phase::Extrinsic(phase),
        module: module.into(),
        event,
    };
    let sys = |e: system::Event| borsh::to_vec(&e).unwrap();
    let ok = sys(system::Event::ExtrinsicSuccess { weight: CALL_WEIGHT });
    let funds = balances::Error::InsufficientBalance.dispatch(0).into();
    let failed = sys(system::Event::ExtrinsicFailed {
        weight: CALL_WEIGHT.saturating_add(Weight::from_parts(0, block.extrinsics[1].len() as u64)),
        error: funds,
    });
    let transfer_event = borsh::to_vec(&balances::Event::Transfer { from: ALICE, to: BOB, amount: 1_000 }).unwrap();
    // `Root` isn't a signer: the inner transfer fails, and its own event goes with it.
    let sudid = borsh::to_vec(&sudo::Event::Sudid(Err(system::Failure::BadOrigin))).unwrap();
    let events = system::EVENTS.get(&mut m).unwrap().unwrap();
    assert_eq!(
        events,
        system::Events::new(
            vec![
                ev(0, "balances", transfer_event),
                ev(0, "system", ok.clone()),
                ev(1, "system", failed),
                ev(2, "sudo", sudid),
                ev(2, "system", ok),
            ],
            0,
        )
    );

    // Importing the block writes the same; the next block replaces them.
    let (mut imported, _) = chain();
    execute_block::<Test, _>(&mut imported, &Check, &borsh::to_vec(&block).unwrap());
    assert_eq!(system::EVENTS.get(&mut imported).unwrap(), Some(events));
    m.relay = (11, [5; 32]);
    build(&mut m, &block.header.head_data(), vec![]);
    assert_eq!(system::EVENTS.get(&mut m).unwrap(), Some(system::Events::default()));
}

/// `Test` after an upgrade to spec version 4, which moves `demo.old[i]` to `demo.new[i]` for
/// `i < ITEMS`, one item per block, and records what each hook saw.
struct Upgraded;

const ITEMS: u32 = 3;
const DEMO: system::StorageVersion = system::StorageVersion::new("demo", 1);
const OLD: tog_runtime_core::StorageMap<u32, u64> = tog_runtime_core::StorageMap::new("demo", "old");
const NEW: tog_runtime_core::StorageMap<u32, u64> = tog_runtime_core::StorageMap::new("demo", "new");
const INITS: StorageValue<u32> = StorageValue::new("demo", "inits");
const IDLE: StorageValue<Weight> = StorageValue::new("demo", "idle");
const FINALIZED: StorageValue<BlockNumber> = StorageValue::new("demo", "finalized");
const STEP: Weight = Weight::from_parts(1_000, 10);
const FINALIZE: Weight = Weight::from_parts(PS_PER_SECOND, 0);

use tog_runtime_core::weight::PS_PER_SECOND;

impl Runtime for Upgraded {
    const NAME: &'static str = "test";
    const SPEC_VERSION: u32 = 4;
    const TX_BASE_WEIGHT: Weight = STEP;

    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
        Test::call_name(module, call)
    }
    fn call_weight(call: &Call) -> Option<Weight> {
        Test::call_weight(call)
    }
    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError> {
        Test::dispatch(e, cx, origin, call)
    }
    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        Test::genesis(e, config);
        DEMO.put_current(e).unwrap();
    }

    fn on_runtime_upgrade<E: Env>(e: &mut Scoped<'_, E>, _: &Context, from: u32) -> Weight {
        assert_eq!(from, 3);
        DEMO.migrate(e, |e, from| {
            assert_eq!(from, 0);
            system::start_migration(e, borsh::to_vec(&0u32).unwrap()).unwrap();
            e.deposit_event("demo", &from);
            STEP
        })
        .unwrap()
    }
    fn on_initialize<E: Env>(e: &mut Scoped<'_, E>, _: &Context) -> Weight {
        let n = INITS.get_or_default(e).unwrap();
        INITS.put(e, &(n + 1)).unwrap();
        STEP
    }
    fn migration_step<E: Env>(
        e: &mut Scoped<'_, E>,
        _: &Context,
        cursor: &[u8],
        limit: Weight,
    ) -> (Weight, Option<Vec<u8>>) {
        assert!(STEP.all_lte(limit));
        let i: u32 = borsh::from_slice(cursor).unwrap();
        let v = OLD.get(e, &i).unwrap().unwrap();
        OLD.remove(e, &i);
        NEW.insert(e, &i, &v).unwrap();
        (STEP, (i + 1 < ITEMS).then(|| borsh::to_vec(&(i + 1)).unwrap()))
    }
    fn on_idle<E: Env>(e: &mut Scoped<'_, E>, _: &Context, remaining: Weight) -> Weight {
        IDLE.put(e, &remaining).unwrap();
        Weight::ZERO
    }
    fn finalize_weight() -> Weight {
        FINALIZE
    }
    fn on_finalize<E: Env>(e: &mut Scoped<'_, E>, cx: &Context) {
        FINALIZED.put(e, &cx.number).unwrap();
        e.deposit_event("demo", &cx.number);
    }
}

fn build_as<R: Runtime>(m: &mut Mock, parent: &HeadData, txs: Vec<Vec<u8>>) -> Block {
    let input = borsh::to_vec(&(parent.clone(), inherents(m), txs)).unwrap();
    borsh::from_slice::<(Block, bool)>(&build_block::<R, _>(m, &Check, &input)).unwrap().0
}

#[test]
fn genesis_records_the_runtime_version_so_the_first_block_upgrades_nothing() {
    let (mut m, head) = chain();
    assert_eq!(system::RUNTIME_VERSION.get(&mut m).unwrap(), Some(3));
    build(&mut m, &head, vec![]);
    assert_eq!(system::EVENTS.get(&mut m).unwrap(), Some(system::Events::default()));
}

#[test]
fn an_upgrade_migrates_once_and_its_multi_block_migration_holds_transactions_until_done() {
    let (mut m, _) = chain();
    for i in 0..ITEMS {
        OLD.insert(&mut m, &i, &(100 + i as u64)).unwrap();
    }
    let mut head = Header::genesis(m.storage_root()).head_data();
    let sys = |phase, e: system::Event| system::EventRecord {
        phase,
        module: "system".into(),
        event: borsh::to_vec(&e).unwrap(),
    };
    let init = system::Phase::Initialization;
    let fin = |n: BlockNumber| system::EventRecord {
        phase: system::Phase::Finalization,
        module: "demo".into(),
        event: borsh::to_vec(&n).unwrap(),
    };
    let pay = tx(ALICE, 0, transfer(BOB, 1));

    // Block 1, the first under spec 4: the upgrade, the first step, no transactions.
    let before = m.clone();
    let b1 = build_as::<Upgraded>(&mut m, &head, vec![pay.clone()]);
    assert!(b1.extrinsics.is_empty(), "held while migrating");
    let events = system::EVENTS.get(&mut m).unwrap().unwrap();
    let demo_from = system::EventRecord { phase: init, module: "demo".into(), event: borsh::to_vec(&0u16).unwrap() };
    assert_eq!(events.records, vec![demo_from, sys(init, system::Event::Upgraded { from: 3, to: 4 }), fin(1)]);
    assert_eq!((DEMO.on_chain(&mut m).unwrap(), system::RUNTIME_VERSION.get(&mut m).unwrap()), (1, Some(4)));
    assert_eq!(system::migration(&mut m).unwrap(), Some(borsh::to_vec(&1u32).unwrap()));
    assert_eq!((OLD.get(&mut m, &0).unwrap(), NEW.get(&mut m, &0).unwrap()), (None, Some(100)));
    assert_eq!((INITS.get(&mut m).unwrap(), FINALIZED.get(&mut m).unwrap()), (Some(1), Some(1)));
    // `on_idle` saw what was left after the hooks and `on_finalize`'s reservation.
    let used = STEP.saturating_mul(3);
    let idle = IDLE.get(&mut m).unwrap().unwrap();
    assert_eq!(idle.ref_time, BlockLimits::DEFAULT.max_block.ref_time - used.ref_time - FINALIZE.ref_time);
    // An importer reaches the same state, and refuses a block that takes a transaction meanwhile.
    let mut imported = before.clone();
    execute_block::<Upgraded, _>(&mut imported, &Check, &borsh::to_vec(&b1).unwrap());
    assert_eq!(imported.storage_root(), m.storage_root());
    let mut bad = b1.clone();
    bad.extrinsics.push(pay.clone());
    let refused = std::panic::catch_unwind(|| {
        execute_block::<Upgraded, _>(&mut before.clone(), &Check, &borsh::to_vec(&bad).unwrap())
    });
    let why = refused.unwrap_err();
    assert_eq!(why.downcast_ref::<&str>(), Some(&"transactions during a migration"));

    // Block 2: one more step, still no transactions.
    head = b1.header.head_data();
    m.relay = (11, [5; 32]);
    let b2 = build_as::<Upgraded>(&mut m, &head, vec![pay.clone()]);
    assert!(b2.extrinsics.is_empty());
    assert_eq!(system::EVENTS.get(&mut m).unwrap().unwrap().records, vec![fin(2)], "no second upgrade");

    // Block 3: the last step; the transaction goes in the same block.
    head = b2.header.head_data();
    m.relay = (12, [6; 32]);
    let b3 = build_as::<Upgraded>(&mut m, &head, vec![pay.clone()]);
    assert_eq!(b3.extrinsics, vec![pay]);
    let records = system::EVENTS.get(&mut m).unwrap().unwrap().records;
    assert_eq!(records[0], sys(init, system::Event::MigrationCompleted));
    assert_eq!(records.last(), Some(&fin(3)));
    assert_eq!(system::migration(&mut m).unwrap(), None);
    assert_eq!((0..ITEMS).map(|i| NEW.get(&mut m, &i).unwrap()).collect::<Vec<_>>(), [Some(100), Some(101), Some(102)]);
    assert_eq!(INITS.get(&mut m).unwrap(), Some(3));
}

#[test]
fn a_transactions_weight_is_its_base_its_call_and_its_bytes() {
    let call = transfer(BOB, 1);
    let bytes = Weight::from_parts(0, 100);
    assert_eq!(tx_weight::<Test>(&call, 100), Some(CALL_WEIGHT.saturating_add(bytes)));
    assert_eq!(tx_weight::<Upgraded>(&call, 100), Some(CALL_WEIGHT.saturating_add(STEP).saturating_add(bytes)));
    assert_eq!(tx_weight::<Test>(&(0, 9, vec![]), 100), None);
    // Each byte costs `BYTE_REF_TIME` too.
    struct PerByte;
    impl Runtime for PerByte {
        const NAME: &'static str = "test";
        const SPEC_VERSION: u32 = 3;
        const BYTE_REF_TIME: u64 = 7;
        fn call_weight(call: &Call) -> Option<Weight> {
            Test::call_weight(call)
        }
        fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
            Test::call_name(module, call)
        }
        fn dispatch<E: Env>(
            e: &mut Scoped<'_, E>,
            cx: &Context,
            origin: Origin,
            call: Call,
        ) -> Result<Weight, DispatchError> {
            Test::dispatch(e, cx, origin, call)
        }
        fn genesis<E: Env>(e: &mut E, config: &[u8]) {
            Test::genesis(e, config);
        }
    }
    assert_eq!(tx_weight::<PerByte>(&call, 100), Some(CALL_WEIGHT.saturating_add(Weight::from_parts(700, 100))));
}

#[test]
fn a_requested_job_goes_out_and_its_result_comes_back_as_events() {
    use tog_types::cgmp::{next_head, CgmpChannel, CgmpOrigin, ComputeResult, CGMP_VERSION, HEAD_0};
    use tog_types::state::items::{cgmp_channel, cgmp_inbound};
    use tog_types::state::JobOutcome;

    let (mut m, head) = chain();
    let fee: Balance = 10_000_000_000_000_000;
    let mut spec = tog_types::testing::sample_spec();
    spec.fee.max_budget = 300;
    spec.fee.inclusion_fee = 50;
    let call = compute::Call::Request { spec, fee, timeout: None };
    let block = build(&mut m, &head, vec![tx(ALICE, 0, (3, compute::REQUEST, borsh::to_vec(&call).unwrap()))]);
    assert_eq!(block.extrinsics.len(), 1);

    // The request is in the outbox, and its event names the job.
    assert_eq!(m.outbox.len(), 1);
    let request: CgmpMessage = borsh::from_slice(&m.outbox[0]).unwrap();
    assert_eq!((request.dest, request.channel_nonce, request.timeout_height), (ChainId::HUB, 0, 10 + 600));
    assert!(matches!(request.payload, CgmpPayload::ComputeRequest { .. }));
    let events = system::EVENTS.get(&mut m).unwrap().unwrap();
    let requested = events.records.iter().find(|r| r.module == "compute").expect("compute event");
    let compute::Event::Requested { job_id, payer, nonce } = borsh::from_slice(&requested.event).unwrap() else {
        panic!("not Requested")
    };
    assert_eq!((payer, nonce), (ALICE, 0));
    assert_eq!(compute::JOBS.get(&mut m, &job_id).unwrap().unwrap().max_budget, 300);
    let ask = |m: &mut Mock, method: &str| -> Result<Vec<u8>, String> {
        borsh::from_slice(&query::<Test, _>(m, &borsh::to_vec(&(method.to_string(), job_id.to_vec())).unwrap()))
            .unwrap()
    };
    let open: Option<compute::Job> = borsh::from_slice(&ask(&mut m, "compute_job").unwrap()).unwrap();
    assert_eq!(open.map(|j| j.payer), Some(ALICE));
    let paid = FUNDS - balances::free_balance(&mut m, &ALICE).unwrap();
    assert!(paid >= 300 + 50 + fee, "budget, inclusion fee and message fee are paid");

    // The Hub acks it, then sends the result: both in the next block's inbox.
    let from_hub = |nonce: u64, payload: CgmpPayload| CgmpMessage {
        version: CGMP_VERSION,
        source: ChainId::HUB,
        dest: CHAIN,
        channel_nonce: nonce,
        timeout_height: u64::MAX,
        fee: 0,
        origin: CgmpOrigin::Chain(ChainId::HUB),
        payload,
    };
    let ack = from_hub(0, CgmpPayload::Ack { of_nonce: 0, result: Ok(()) });
    let result = ComputeResult {
        job_id,
        outcome: JobOutcome::Settled,
        receipt_root: [3; 32],
        outputs: vec![],
        work_units: 10,
        charged: 120,
    };
    let done = from_hub(1, CgmpPayload::ComputeResult(result.clone()));
    let channel = CgmpChannel {
        head: next_head(&next_head(&HEAD_0, &ack.hash()), &done.hash()),
        last_nonce: Some(1),
        next_nonce: 0,
        ..CgmpChannel::default()
    };
    m.hub.insert(cgmp_channel(&ChainId::HUB, &CHAIN).to_vec(), borsh::to_vec(&channel).unwrap());
    m.hub.insert(cgmp_inbound(&CHAIN).to_vec(), borsh::to_vec(&vec![ChainId::HUB]).unwrap());
    let none: Option<Vec<Hash32>> = None;
    m.inbox.push_back(borsh::to_vec(&(ack, none)).unwrap());
    m.inbox.push_back(borsh::to_vec(&(done, Some(Vec::<Hash32>::new()))).unwrap());
    m.relay = (11, [5; 32]);
    let before = balances::free_balance(&mut m, &ALICE).unwrap();
    build(&mut m, &block.header.head_data(), vec![]);
    let events = system::EVENTS.get(&mut m).unwrap().unwrap();
    let compute_events: Vec<compute::Event> =
        events.records.iter().filter(|r| r.module == "compute").map(|r| borsh::from_slice(&r.event).unwrap()).collect();
    assert_eq!(compute_events, vec![compute::Event::Completed { result, refunded: 180 }]);
    assert_eq!(balances::free_balance(&mut m, &ALICE).unwrap(), before + 180);
    assert_eq!(compute::JOBS.get(&mut m, &job_id).unwrap(), None, "closed");
    let open: Option<compute::Job> = borsh::from_slice(&ask(&mut m, "compute_job").unwrap()).unwrap();
    assert_eq!(open, None);
    let kept: Option<ComputeResult> = borsh::from_slice(&ask(&mut m, "compute_result").unwrap()).unwrap();
    assert_eq!(kept, None, "no callback failed");
}

/// A chain's own module, written with `#[tog_module]`.
#[crate::tog_module]
pub mod counter {
    use tog_runtime_core::env::Env;
    use tog_runtime_core::{AccountId, Origin, Storage, StorageError, StorageMap, StorageNMap, StorageValue, Weight};

    use crate::executive::{Context, Scoped};

    /// The sum of every addition.
    #[storage]
    pub type Total = StorageValue<u64>;
    #[storage]
    pub type ByAccount = StorageMap<AccountId, u64>;
    /// How many times each account added each amount.
    #[storage]
    pub type Additions = StorageNMap<(AccountId, u64), u32>;
    /// The blocks `on_initialize` saw, and the last one `on_finalize` closed.
    #[storage]
    pub type Blocks = StorageValue<(u32, u64)>;

    #[event]
    pub enum Event {
        Added { who: AccountId, by: u64 },
        Reset,
    }

    #[error]
    pub enum Error {
        BadOrigin,
        Overflow,
        Storage(StorageError),
    }

    #[genesis]
    pub struct GenesisConfig {
        pub start: u64,
    }

    pub fn genesis(s: &mut impl Storage, config: &GenesisConfig) -> Result<(), StorageError> {
        TOTAL.put(s, &config.start)
    }

    #[call(index = 0, weight = Weight::from_parts(2_000_000, 50))]
    pub fn add<E: Env>(e: &mut Scoped<'_, E>, _cx: &Context, origin: Origin, by: u64) -> Result<(), Error> {
        let Origin::Signed(who) = origin else { return Err(Error::BadOrigin) };
        let total = TOTAL.get_or_default(e)?.checked_add(by).ok_or(Error::Overflow)?;
        TOTAL.put(e, &total)?;
        BY_ACCOUNT.mutate(e, &who, |n| *n += by)?;
        ADDITIONS.mutate(e, &(who, by), |n| *n += 1)?;
        Event::Added { who, by }.deposit(e);
        Ok(())
    }

    #[hook(on_initialize)]
    fn count_block<E: Env>(e: &mut Scoped<'_, E>, _cx: &Context) -> Weight {
        let _ = BLOCKS.mutate(e, |(seen, _)| *seen += 1);
        Weight::from_parts(3_000, 1)
    }

    #[hook(on_finalize, weight = Weight::from_parts(4_000, 2))]
    fn close_block<E: Env>(e: &mut Scoped<'_, E>, cx: &Context) {
        let _ = BLOCKS.mutate(e, |(_, last)| *last = cx.number);
    }

    #[hook(on_worker_slashed, limit = Weight::from_parts(5_000, 3))]
    fn slashed<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        notice: &tog_types::cgmp::WorkerSlashed,
    ) -> Result<Weight, Error> {
        if notice.worker == [0; 20] {
            return Err(Error::Overflow);
        }
        BY_ACCOUNT.remove(e, &notice.worker);
        Ok(Weight::from_parts(1_000, 1))
    }

    #[call(index = 2, weight = Weight::from_parts(1_000_000, 10))]
    pub fn reset_to<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        origin: Origin,
        total: u64,
        note: alloc::string::String,
    ) -> Result<(), Error> {
        if origin != Origin::Root {
            return Err(Error::BadOrigin);
        }
        let _ = note;
        TOTAL.put(e, &total)?;
        Event::Reset.deposit(e);
        Ok(())
    }
}

/// `Test` with `counter` at module index 4.
struct Counted;

const COUNTER: u8 = 4;

impl Runtime for Counted {
    const NAME: &'static str = "test";
    const SPEC_VERSION: u32 = 3;

    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
        match module {
            COUNTER => counter::call_name(call).map(|c| (counter::MODULE, c)),
            _ => Test::call_name(module, call),
        }
    }

    fn call_weight(call: &Call) -> Option<Weight> {
        match call.0 {
            COUNTER => counter::call_weight(call.1, &call.2),
            _ => Test::call_weight(call),
        }
    }

    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError> {
        match call.0 {
            COUNTER => counter::dispatch(e, cx, COUNTER, origin, call.1, &call.2),
            _ => Test::dispatch(e, cx, origin, call),
        }
    }

    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        Test::genesis(e, config);
        counter::genesis(e, &counter::GenesisConfig { start: 10 }).expect("counter genesis");
    }

    fn on_initialize<E: Env>(e: &mut Scoped<'_, E>, cx: &Context) -> Weight {
        Test::on_initialize(e, cx).saturating_add(counter::Hooks::on_initialize(e, cx))
    }

    fn finalize_weight() -> Weight {
        Test::finalize_weight().saturating_add(counter::Hooks::FINALIZE_WEIGHT)
    }

    fn on_finalize<E: Env>(e: &mut Scoped<'_, E>, cx: &Context) {
        Test::on_finalize(e, cx);
        counter::Hooks::on_finalize(e, cx);
    }
}

#[test]
fn a_tog_module_stores_dispatches_and_describes_itself() {
    let mut m = Mock { relay: (10, [4; 32]), ..Mock::default() };
    let config = borsh::to_vec(&(vec![(ROOT, FUNDS), (ALICE, FUNDS)], Some(ROOT))).unwrap();
    let root: Hash32 = borsh::from_slice(&genesis::<Counted, _>(&mut m, &borsh::to_vec(&config).unwrap())).unwrap();
    let head = Header::genesis(root).head_data();
    assert_eq!(counter::TOTAL.get(&mut m).unwrap(), Some(10));
    assert_eq!(counter::TOTAL.key(), StorageValue::<u64>::new("counter", "total").key());
    assert_eq!(
        counter::BY_ACCOUNT.key(&ALICE),
        tog_runtime_core::StorageMap::<AccountId, u64>::new("counter", "by_account").key(&ALICE)
    );

    let add = |by: u64| counter::Call::Add { by }.into_call(COUNTER);
    let reset = counter::Call::ResetTo { total: 3, note: "x".into() };
    assert_eq!(reset.encode(), (2, borsh::to_vec(&(3u64, String::from("x"))).unwrap()));
    assert_eq!(Counted::call_name(COUNTER, 2), Some(("counter", "reset_to")));
    assert_eq!(Counted::call_name(COUNTER, 1), None);
    assert_eq!(Counted::call_weight(&add(1)), Some(Weight::from_parts(2_000_000, 50)));
    assert_eq!(Counted::call_weight(&(COUNTER, 0, vec![1])), None, "arguments that don't decode");

    let block = build_as::<Counted>(
        &mut m,
        &head,
        vec![
            tx(ALICE, 0, add(5)),
            tx(ALICE, 1, add(u64::MAX)),                    // overflows
            tx(ALICE, 2, reset.clone().into_call(COUNTER)), // not Root
        ],
    );
    assert_eq!(block.extrinsics.len(), 3);
    assert_eq!(counter::TOTAL.get(&mut m).unwrap(), Some(15));
    assert_eq!(counter::BY_ACCOUNT.get(&mut m, &ALICE).unwrap(), Some(5));
    assert_eq!(counter::ADDITIONS.get(&mut m, &(ALICE, 5)).unwrap(), Some(1));
    assert_eq!(
        counter::ADDITIONS.key(&(ALICE, 5)),
        tog_runtime_core::StorageDoubleMap::<AccountId, u64, u32>::new("counter", "additions").key(&ALICE, &5)
    );

    let records = system::EVENTS.get(&mut m).unwrap().unwrap().records;
    let of = |phase: u32| -> Vec<(String, Vec<u8>)> {
        records
            .iter()
            .filter(|r| r.phase == system::Phase::Extrinsic(phase))
            .map(|r| (r.module.clone(), r.event.clone()))
            .collect()
    };
    let added = borsh::to_vec(&counter::Event::Added { who: ALICE, by: 5 }).unwrap();
    assert_eq!(of(0)[0], ("counter".into(), added));
    let failure = |phase: u32| match borsh::from_slice(&of(phase).last().unwrap().1).unwrap() {
        system::Event::ExtrinsicFailed { error, .. } => error,
        other => panic!("{other:?}"),
    };
    assert_eq!(failure(1), system::Failure::Module { module: COUNTER, error: 1 });
    assert_eq!(failure(2), system::Failure::BadOrigin);

    // `Root` reaches it directly, without a transaction.
    let cx = Context { chain: CHAIN, network_id: NETWORK, relay: 10, number: 2, author: AUTHOR, per_byte: 0 };
    let mut e = Scoped::new(&mut m);
    let (index, args) = reset.encode();
    assert_eq!(
        counter::dispatch(&mut e, &cx, COUNTER, Origin::Root, index, &args),
        Ok(Weight::from_parts(1_000_000, 10))
    );
    assert_eq!(counter::TOTAL.get(&mut e).unwrap(), Some(3));

    let meta = counter::metadata();
    assert_eq!(meta.name, "counter");
    assert_eq!(
        meta.calls.iter().map(|c| (c.index, c.name.as_str())).collect::<Vec<_>>(),
        vec![(0, "add"), (2, "reset_to")]
    );
    assert_eq!(
        meta.calls[1].args,
        vec![("total".into(), "u64".into()), ("note".into(), "alloc::string::String".into())]
    );
    assert_eq!(meta.storage, vec!["total", "by_account", "additions", "blocks"]);
    assert_eq!(meta.events, vec!["Added", "Reset"]);
    assert_eq!(meta.errors, vec!["BadOrigin", "Overflow", "Storage"]);
    assert_eq!(counter::GenesisConfig::default(), counter::GenesisConfig { start: 0 });
}

#[test]
fn a_tog_module_hands_its_hooks_to_the_runtime() {
    use tog_types::cgmp::{WorkerOffence, WorkerSlashed};

    let mut m = Mock { relay: (10, [4; 32]), ..Mock::default() };
    let config = borsh::to_vec(&(vec![(ROOT, FUNDS), (ALICE, FUNDS)], Some(ROOT))).unwrap();
    let root: Hash32 = borsh::from_slice(&genesis::<Counted, _>(&mut m, &borsh::to_vec(&config).unwrap())).unwrap();
    let block = build_as::<Counted>(&mut m, &Header::genesis(root).head_data(), vec![]);
    m.relay = (11, [5; 32]);
    build_as::<Counted>(&mut m, &block.header.head_data(), vec![]);
    assert_eq!(counter::BLOCKS.get(&mut m).unwrap(), Some((2, 2)), "on_initialize twice, on_finalize of block 2");
    assert_eq!(counter::Hooks::FINALIZE_WEIGHT, Weight::from_parts(4_000, 2));
    assert_eq!(counter::Hooks::WORKER_SLASHED_LIMIT, Some(Weight::from_parts(5_000, 3)));
    assert_eq!(counter::Hooks::COMPUTE_RESULT_LIMIT, None);

    let cx = Context { chain: CHAIN, network_id: NETWORK, relay: 10, number: 3, author: AUTHOR, per_byte: 0 };
    let mut e = Scoped::new(&mut m);
    // What the module doesn't write does nothing.
    assert_eq!(counter::Hooks::on_idle(&mut e, &cx, Weight::MAX), Weight::ZERO);
    assert_eq!(counter::Hooks::on_runtime_upgrade(&mut e, &cx, 2), Weight::ZERO);
    counter::BY_ACCOUNT.insert(&mut e, &ALICE, &7).unwrap();
    let notice = |worker| WorkerSlashed { worker, offence: WorkerOffence::LostRound, job: [8; 32] };
    assert_eq!(
        counter::Hooks::on_worker_slashed(&mut e, &cx, COUNTER, &notice(ALICE)),
        Ok(Weight::from_parts(1_000, 1))
    );
    assert_eq!(counter::BY_ACCOUNT.get(&mut e, &ALICE).unwrap(), None);
    assert_eq!(
        counter::Hooks::on_worker_slashed(&mut e, &cx, COUNTER, &notice([0; 20])),
        Err(DispatchError::Module { module: COUNTER, error: 1 }),
        "its errors carry the module's index"
    );
    assert_eq!(crate::assets::Hooks::WORKER_SLASHED_LIMIT, None);
}

#[test]
fn assets_are_created_minted_moved_approved_and_burned() {
    use crate::assets::{self, Call as A, Error, Event};

    const ASSETS: u8 = 6;
    let carol: AccountId = [4; 20];
    let mut m = Mock { relay: (10, [4; 32]), ..Mock::default() };
    let cx = Context { chain: CHAIN, network_id: NETWORK, relay: 10, number: 1, author: AUTHOR, per_byte: 0 };
    let mut e = Scoped::new(&mut m);
    let run = |e: &mut Scoped<'_, Mock>, who: AccountId, call: A| {
        let (index, args) = call.encode();
        assets::dispatch(e, &cx, ASSETS, Origin::Signed(who), index, &args).map(|_| ())
    };
    let err = |error: Error| {
        Err(DispatchError::Module {
            module: ASSETS,
            error: assets::metadata().errors.iter().position(|n| *n == format!("{error:?}")).unwrap() as u8,
        })
    };

    run(&mut e, ALICE, A::Create { id: 1, decimals: 6, symbol: "USDT".into() }).unwrap();
    assert_eq!(run(&mut e, BOB, A::Create { id: 1, decimals: 0, symbol: "X".into() }), err(Error::Exists));
    assert_eq!(
        run(&mut e, BOB, A::Create { id: 2, decimals: 0, symbol: "A_VERY_LONG_SYMBOL".into() }),
        err(Error::SymbolTooLong)
    );
    assert_eq!(run(&mut e, BOB, A::Mint { id: 1, to: BOB, amount: 5 }), err(Error::NotOwner));
    assert_eq!(run(&mut e, ALICE, A::Mint { id: 9, to: BOB, amount: 5 }), err(Error::Unknown));
    run(&mut e, ALICE, A::Mint { id: 1, to: BOB, amount: 100 }).unwrap();
    assert_eq!(run(&mut e, ALICE, A::Mint { id: 1, to: BOB, amount: u128::MAX }), err(Error::Overflow));

    run(&mut e, BOB, A::Transfer { id: 1, to: carol, amount: 30 }).unwrap();
    assert_eq!(run(&mut e, BOB, A::Transfer { id: 1, to: carol, amount: 71 }), err(Error::InsufficientBalance));
    assert_eq!((assets::balance(&mut e, 1, &BOB).unwrap(), assets::balance(&mut e, 1, &carol).unwrap()), (70, 30));

    // An approval allows exactly its amount, and is gone once spent.
    run(&mut e, BOB, A::Approve { id: 1, spender: ALICE, amount: 20 }).unwrap();
    assert_eq!(
        run(&mut e, ALICE, A::TransferFrom { id: 1, holder: BOB, to: ALICE, amount: 21 }),
        err(Error::InsufficientAllowance)
    );
    run(&mut e, ALICE, A::TransferFrom { id: 1, holder: BOB, to: ALICE, amount: 15 }).unwrap();
    assert_eq!(assets::APPROVALS.get(&mut e, &(1, BOB, ALICE)).unwrap(), Some(5));
    run(&mut e, ALICE, A::TransferFrom { id: 1, holder: BOB, to: carol, amount: 5 }).unwrap();
    assert!(!assets::APPROVALS.contains_key(&mut e, &(1, BOB, ALICE)));
    assert_eq!(assets::balance(&mut e, 1, &BOB).unwrap(), 50);

    // The owner burns, and hands the asset on.
    run(&mut e, ALICE, A::Burn { id: 1, from: carol, amount: 35 }).unwrap();
    assert!(!assets::BALANCES.contains_key(&mut e, &1, &carol), "an emptied balance is removed");
    assert_eq!(assets::details(&mut e, 1).unwrap().unwrap().supply, 65);
    run(&mut e, ALICE, A::SetOwner { id: 1, owner: BOB }).unwrap();
    assert_eq!(run(&mut e, ALICE, A::Mint { id: 1, to: ALICE, amount: 1 }), err(Error::NotOwner));
    run(&mut e, BOB, A::Mint { id: 1, to: ALICE, amount: 1 }).unwrap();
    assert_eq!(run(&mut e, ALICE, A::Create { id: 3, decimals: 0, symbol: "".into() }).map(|_| ()), Ok(()));
    let none = assets::dispatch(&mut e, &cx, ASSETS, Origin::Root, 3, &borsh::to_vec(&(1u32, BOB, 1u128)).unwrap());
    assert_eq!(none, Err(DispatchError::BadOrigin));

    let events: Vec<Event> =
        e.events.iter().filter(|(m, _)| *m == "assets").map(|(_, b)| borsh::from_slice(b).unwrap()).collect();
    assert_eq!(events[0], Event::Created { id: 1, owner: ALICE });
    assert!(events.contains(&Event::Burned { id: 1, from: carol, amount: 35 }));
    assert_eq!(events.last(), Some(&Event::Created { id: 3, owner: ALICE }));

    // Genesis, and what clients read.
    let mut g = MemoryStorage::default();
    let config = assets::GenesisConfig { assets: vec![(7, ALICE, 2, "GLD".into(), vec![(BOB, 9), (carol, 1)])] };
    assets::genesis(&mut g, &config).unwrap();
    assert_eq!(assets::details(&mut g, 7).unwrap().map(|a| (a.owner, a.supply)), Some((ALICE, 10)));
    let meta = assets::metadata();
    assert_eq!(meta.storage, vec!["assets", "balances", "approvals"]);
    assert_eq!(meta.calls.len(), 7);
}

#[test]
fn only_the_payer_takes_a_kept_result_and_gets_its_deposit_back() {
    let mut m = Mock { relay: (10, [4; 32]), ..Mock::default() };
    let mut e = Scoped::new(&mut m);
    let result = tog_types::cgmp::ComputeResult {
        job_id: [7; 32],
        outcome: tog_types::state::JobOutcome::Settled,
        receipt_root: [8; 32],
        outputs: vec![],
        work_units: 1,
        charged: 1,
    };
    balances::deposit(&mut e, &ALICE, 10_000).unwrap();
    assert_eq!(compute::keep_result(&mut e, &ALICE, &result, 1), Ok(true));
    assert!(balances::account(&mut e, &ALICE).unwrap().reserved > 0);
    let none = Err(DispatchError::Module { module: 3, error: 5 });
    assert_eq!(compute::dispatch_take_result(&mut e, 3, Origin::Signed(BOB), result.job_id), none);
    assert_eq!(compute::dispatch_take_result(&mut e, 3, Origin::Signed(ALICE), [9; 32]), none);
    compute::dispatch_take_result(&mut e, 3, Origin::Signed(ALICE), result.job_id).unwrap();
    assert_eq!(balances::account(&mut e, &ALICE).unwrap().reserved, 0);
    assert_eq!(compute::RESULTS.get(&mut e, &result.job_id).unwrap(), None);
    assert_eq!(compute::dispatch_take_result(&mut e, 3, Origin::Signed(ALICE), result.job_id), none);
    let taken = borsh::to_vec(&compute::Event::ResultTaken { job_id: result.job_id }).unwrap();
    assert!(e.events.iter().any(|(m, b)| *m == "compute" && *b == taken));
}

#[test]
fn assets_hold_deposits_for_what_they_add() {
    use crate::assets::{self, Call as A, Error};
    use crate::storage_deposit::{deposit_for, DEPOSITS};

    const ASSETS: u8 = 6;
    let carol: AccountId = [4; 20];
    let mut m = Mock { relay: (10, [4; 32]), ..Mock::default() };
    let cx = Context { chain: CHAIN, network_id: NETWORK, relay: 10, number: 1, author: AUTHOR, per_byte: 1 };
    let mut e = Scoped::new(&mut m);
    for who in [ALICE, BOB] {
        balances::deposit(&mut e, &who, 10_000).unwrap();
    }
    let run = |e: &mut Scoped<'_, Mock>, who: AccountId, call: A| {
        let (index, args) = call.encode();
        assets::dispatch(e, &cx, ASSETS, Origin::Signed(who), index, &args).map(|_| ())
    };
    let reserved = |e: &mut Scoped<'_, Mock>, who| balances::account(e, &who).unwrap().reserved;
    let amount = deposit_for(16, 1).unwrap();

    // The creator holds the asset's record.
    run(&mut e, ALICE, A::Create { id: 1, decimals: 6, symbol: "USDT".into() }).unwrap();
    let details = borsh::object_length(&assets::details(&mut e, 1).unwrap().unwrap()).unwrap() as u64;
    assert_eq!(reserved(&mut e, ALICE), deposit_for(details, 1).unwrap());
    let created = reserved(&mut e, ALICE);

    // The minter holds a new holder's balance; more of it adds nothing.
    run(&mut e, ALICE, A::Mint { id: 1, to: BOB, amount: 100 }).unwrap();
    run(&mut e, ALICE, A::Mint { id: 1, to: BOB, amount: 1 }).unwrap();
    assert_eq!(reserved(&mut e, ALICE), created + amount);

    // A transfer to a new holder: the sender holds it, and gets it back when it's emptied.
    run(&mut e, BOB, A::Transfer { id: 1, to: carol, amount: 30 }).unwrap();
    assert_eq!(reserved(&mut e, BOB), amount);
    assert_eq!(DEPOSITS.get(&mut e, &assets::BALANCES.key(&1, &carol)).unwrap(), Some((BOB, amount)));
    run(&mut e, ALICE, A::Burn { id: 1, from: carol, amount: 30 }).unwrap();
    assert_eq!(reserved(&mut e, BOB), 0);

    // An approval holds the holder's deposit until it is used up, or taken back.
    run(&mut e, BOB, A::Approve { id: 1, spender: ALICE, amount: 20 }).unwrap();
    assert_eq!(reserved(&mut e, BOB), amount);
    run(&mut e, ALICE, A::TransferFrom { id: 1, holder: BOB, to: ALICE, amount: 20 }).unwrap();
    assert_eq!((reserved(&mut e, BOB), reserved(&mut e, ALICE)), (0, created + 2 * amount));
    run(&mut e, BOB, A::Approve { id: 1, spender: carol, amount: 5 }).unwrap();
    run(&mut e, BOB, A::Approve { id: 1, spender: carol, amount: 0 }).unwrap();
    assert_eq!(reserved(&mut e, BOB), 0);

    // An emptied balance returns its deposit to whoever paid it, whoever empties it.
    run(&mut e, BOB, A::Transfer { id: 1, to: ALICE, amount: 51 }).unwrap();
    assert_eq!(reserved(&mut e, ALICE), created + amount, "BOB's balance, paid by ALICE's mint, is gone");

    // A signer who can't cover the deposit gets nothing.
    let poor: AccountId = [5; 20];
    let err = Err(DispatchError::Module {
        module: ASSETS,
        error: assets::metadata().errors.iter().position(|n| n == "DepositUnpaid").unwrap() as u8,
    });
    assert_eq!(run(&mut e, poor, A::Create { id: 2, decimals: 0, symbol: "P".into() }), err);
    assert_eq!(assets::details(&mut e, 2).unwrap(), None);
    let _ = Error::DepositUnpaid;
}

#[test]
fn a_timeout_ack_waits_while_the_channel_back_is_at_max_backlog() {
    use tog_types::cgmp::{next_head, CgmpChannel, CgmpError, CgmpOrigin, OutboxChannel, CGMP_VERSION, HEAD_0};
    use tog_types::state::items::{cgmp_channel, cgmp_inbound};

    const SRC: ChainId = ChainId(3);
    let (mut m, _) = chain();
    // This chain already sent SRC a full backlog, none of it processed.
    let full = vec![OutboxChannel { dest: SRC, head: HEAD_0, last_nonce: cgmp::MAX_BACKLOG - 1 }];
    cgmp::OUTBOX.put(&mut m, &full).unwrap();
    let head = Header::genesis(m.storage_root()).head_data();
    let expired = CgmpMessage {
        version: CGMP_VERSION,
        source: SRC,
        dest: CHAIN,
        channel_nonce: 0,
        timeout_height: 5,
        fee: 0,
        origin: CgmpOrigin::Chain(SRC),
        payload: CgmpPayload::TransferTog { to: [1; 20], amount: 1 },
    };
    let channel =
        CgmpChannel { head: next_head(&HEAD_0, &expired.hash()), last_nonce: Some(0), ..CgmpChannel::default() };
    m.hub.insert(cgmp_channel(&SRC, &CHAIN).to_vec(), borsh::to_vec(&channel).unwrap());
    m.hub.insert(cgmp_inbound(&CHAIN).to_vec(), borsh::to_vec(&vec![SRC]).unwrap());
    m.inbox.push_back(borsh::to_vec(&(expired, Some(Vec::<Hash32>::new()))).unwrap());
    let block = build(&mut m, &head, vec![]);
    assert!(m.outbox.is_empty(), "no room for the Ack");
    assert_eq!(cgmp::OWED_ACKS.get(&mut m, &SRC).unwrap(), Some(vec![0]));

    // SRC processed one message: the owed Ack goes out first thing in the next block.
    let back = CgmpChannel { next_nonce: 1, last_nonce: Some(cgmp::MAX_BACKLOG - 1), ..CgmpChannel::default() };
    m.hub.insert(cgmp_channel(&CHAIN, &SRC).to_vec(), borsh::to_vec(&back).unwrap());
    m.relay = (11, [5; 32]);
    build(&mut m, &block.header.head_data(), vec![]);
    let ack: CgmpMessage = borsh::from_slice(&m.outbox[0]).unwrap();
    assert_eq!((ack.dest, ack.channel_nonce), (SRC, cgmp::MAX_BACKLOG));
    assert_eq!(ack.payload, CgmpPayload::Ack { of_nonce: 0, result: Err(CgmpError::Timeout) });
    assert_eq!(cgmp::owed_sources(&mut m).unwrap(), vec![]);
}

/// `Test` with two `on_worker_slashed` hooks: module 6 counts each slashed worker, module 7
/// writes and then fails.
struct Slashing;

const COUNTS: tog_runtime_core::StorageMap<AccountId, u32> = tog_runtime_core::StorageMap::new("stake", "slashes");
const SCRATCH: StorageValue<u32> = StorageValue::new("broken", "scratch");

impl Runtime for Slashing {
    const NAME: &'static str = "test";
    const SPEC_VERSION: u32 = 3;

    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
        Test::call_name(module, call)
    }

    fn call_weight(call: &Call) -> Option<Weight> {
        Test::call_weight(call)
    }

    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError> {
        Test::dispatch(e, cx, origin, call)
    }

    fn worker_slashed_hooks() -> &'static [(u8, Weight)] {
        &[(6, CALL_WEIGHT), (7, CALL_WEIGHT)]
    }

    fn on_worker_slashed<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        module: u8,
        notice: &WorkerSlashed,
    ) -> Result<Weight, DispatchError> {
        match module {
            6 => {
                COUNTS.mutate(e, &notice.worker, |n| *n += 1)?;
                e.deposit_event("stake", &notice.job);
                Ok(CALL_WEIGHT)
            }
            _ => {
                SCRATCH.put(e, &1)?;
                Err(DispatchError::Module { module, error: 0 })
            }
        }
    }

    fn cgmp_call_limit(module: ModuleId, _call: &[u8]) -> Option<Weight> {
        (module == REMOTE).then_some(CALL_WEIGHT)
    }

    fn cgmp_call<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        _source: ChainId,
        _origin: &CgmpOrigin,
        _module: ModuleId,
        _call: &[u8],
        _weight_limit: Weight,
    ) -> Option<Result<Weight, DispatchError>> {
        Some(CALLS.mutate(e, |n| *n += 1).map(|_| Weight::from_parts(1, 0)).map_err(Into::into))
    }

    fn on_idle<E: Env>(e: &mut Scoped<'_, E>, _: &Context, remaining: Weight) -> Weight {
        IDLE.put(e, &remaining).unwrap();
        Weight::ZERO
    }

    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        Test::genesis(e, config);
    }
}

const REMOTE: ModuleId = ModuleId(*b"remote\0\0\0\0\0\0\0\0\0\0");
const CALLS: StorageValue<u32> = StorageValue::new("remote", "calls");

/// Builds a `Slashing` block whose inbox is `msg`, the one message on its channel, and returns the
/// state after it with the weight `on_idle` was left.
fn idle_after(msg: CgmpMessage) -> (Mock, Weight) {
    use tog_types::cgmp::{next_head, HEAD_0};
    let mut m = Mock { relay: (10, [4; 32]), ..Mock::default() };
    let config = borsh::to_vec(&(vec![(ROOT, FUNDS), (ALICE, FUNDS)], None::<AccountId>)).unwrap();
    let root: Hash32 = borsh::from_slice(&genesis::<Slashing, _>(&mut m, &borsh::to_vec(&config).unwrap())).unwrap();
    let head = Header::genesis(root).head_data();
    let channel = CgmpChannel { head: next_head(&HEAD_0, &msg.hash()), last_nonce: Some(0), ..CgmpChannel::default() };
    m.hub.insert(cgmp_channel(&msg.source, &CHAIN).to_vec(), borsh::to_vec(&channel).unwrap());
    m.hub.insert(cgmp_inbound(&CHAIN).to_vec(), borsh::to_vec(&vec![msg.source]).unwrap());
    m.inbox.push_back(borsh::to_vec(&(msg, Some(Vec::<Hash32>::new()))).unwrap());
    let input = borsh::to_vec(&(head, inherents(&m), Vec::<Vec<u8>>::new())).unwrap();
    let (block, _): (Block, bool) = borsh::from_slice(&build_block::<Slashing, _>(&mut m, &Check, &input)).unwrap();
    assert_eq!(block.header.inbox_processed, 1);
    let idle = IDLE.get(&mut m).unwrap().unwrap();
    (m, idle)
}

#[test]
fn the_block_reserves_the_declared_limit_of_each_inbox_handler() {
    use tog_types::cgmp::{WorkerOffence, CGMP_VERSION};
    let message = |source: ChainId, payload: CgmpPayload| CgmpMessage {
        version: CGMP_VERSION,
        source,
        dest: CHAIN,
        channel_nonce: 0,
        timeout_height: u64::MAX,
        fee: 0,
        origin: CgmpOrigin::Chain(source),
        payload,
    };
    let peer = ChainId(9);
    let call = |weight_limit: Weight| {
        message(peer, CgmpPayload::Call { module: REMOTE, call: Default::default(), weight_limit })
    };

    // A `Call` within its declared maximum runs, and the block reserves its whole `weight_limit`
    // although it used 1; one above the maximum is consumed without running or reserving.
    let (mut ran, ran_idle) = idle_after(call(CALL_WEIGHT));
    let over = Weight::from_parts(CALL_WEIGHT.ref_time + 1, CALL_WEIGHT.proof_size);
    let (mut refused, refused_idle) = idle_after(call(over));
    assert_eq!(CALLS.get(&mut ran).unwrap(), Some(1));
    assert_eq!(CALLS.get(&mut refused).unwrap(), None);
    assert_eq!(refused_idle.ref_time - ran_idle.ref_time, CALL_WEIGHT.ref_time);

    // The Hub's slash notice reserves both hooks' limits; a forged one runs no hook and reserves none.
    let notice = WorkerSlashed { worker: [0x77; 20], offence: WorkerOffence::LostRound, job: [8; 32] };
    let (_, hub_idle) = idle_after(message(ChainId::HUB, CgmpPayload::WorkerSlashed(notice.clone())));
    let (_, forged_idle) = idle_after(message(peer, CgmpPayload::WorkerSlashed(notice)));
    assert_eq!(forged_idle.ref_time - hub_idle.ref_time, 2 * CALL_WEIGHT.ref_time);
}

#[test]
fn a_worker_slash_notice_from_the_hub_reaches_each_hook_in_its_own_overlay() {
    use tog_types::cgmp::{next_head, WorkerOffence, CGMP_VERSION, HEAD_0};
    let mut m = Mock { relay: (10, [4; 32]), ..Mock::default() };
    let config = borsh::to_vec(&(vec![(ROOT, FUNDS), (ALICE, FUNDS)], None::<AccountId>)).unwrap();
    let root: Hash32 = borsh::from_slice(&genesis::<Slashing, _>(&mut m, &borsh::to_vec(&config).unwrap())).unwrap();
    let head = Header::genesis(root).head_data();

    let worker = [0x77; 20];
    let notice = WorkerSlashed { worker, offence: WorkerOffence::VerifierAgainst, job: [8; 32] };
    let message = |source: ChainId, nonce: u64| CgmpMessage {
        version: CGMP_VERSION,
        source,
        dest: CHAIN,
        channel_nonce: nonce,
        timeout_height: u64::MAX,
        fee: 0,
        origin: CgmpOrigin::Chain(source),
        payload: CgmpPayload::WorkerSlashed(notice.clone()),
    };
    let peer = ChainId(9);
    let (from_hub, forged) = (message(ChainId::HUB, 0), message(peer, 0));
    for (source, m0) in [(ChainId::HUB, &from_hub), (peer, &forged)] {
        let channel =
            CgmpChannel { head: next_head(&HEAD_0, &m0.hash()), last_nonce: Some(0), ..CgmpChannel::default() };
        m.hub.insert(cgmp_channel(&source, &CHAIN).to_vec(), borsh::to_vec(&channel).unwrap());
    }
    m.hub.insert(cgmp_inbound(&CHAIN).to_vec(), borsh::to_vec(&vec![ChainId::HUB, peer]).unwrap());
    m.inbox.push_back(borsh::to_vec(&(from_hub, Some(Vec::<Hash32>::new()))).unwrap());
    m.inbox.push_back(borsh::to_vec(&(forged, Some(Vec::<Hash32>::new()))).unwrap());
    let input = borsh::to_vec(&(head, inherents(&m), Vec::<Vec<u8>>::new())).unwrap();
    let (block, _): (Block, bool) = borsh::from_slice(&build_block::<Slashing, _>(&mut m, &Check, &input)).unwrap();
    assert_eq!(block.header.inbox_processed, 2);

    // Module 6 counted the Hub's notice once; module 7's write went with its error.
    assert_eq!(COUNTS.get(&mut m, &worker).unwrap(), Some(1), "the forged notice did nothing");
    assert_eq!(SCRATCH.get(&mut m).unwrap(), None);
    let records = system::EVENTS.get(&mut m).unwrap().unwrap().records;
    let at = |i: u32| -> Vec<(String, Vec<u8>)> {
        records
            .iter()
            .filter(|r| r.phase == system::Phase::Inbox(i))
            .map(|r| (r.module.clone(), r.event.clone()))
            .collect()
    };
    let hub = at(0);
    assert_eq!(hub[0], ("compute".into(), borsh::to_vec(&compute::Event::WorkerSlashed(notice)).unwrap()));
    assert_eq!(hub[1], ("stake".into(), borsh::to_vec(&[8u8; 32]).unwrap()));
    let outcome = |ev: &[(String, Vec<u8>)]| match borsh::from_slice(&ev.last().unwrap().1).unwrap() {
        system::Event::Message { outcome, .. } => outcome,
        other => panic!("{other:?}"),
    };
    assert_eq!(outcome(&hub), system::Outcome::Failed(system::Failure::Module { module: 7, error: 0 }));
    let forged = at(1);
    assert_eq!((forged.len(), outcome(&forged)), (1, system::Outcome::Executed), "consumed, no event");
}

/// `Test` with `governance` at module index 5.
struct Governed;

const GOVERNANCE: u8 = 5;

impl Runtime for Governed {
    const NAME: &'static str = "test";
    const SPEC_VERSION: u32 = 3;

    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
        Some(match (module, call) {
            (GOVERNANCE, governance::SET_MEMBERS) => ("governance", "set_members"),
            (GOVERNANCE, governance::PROPOSE) => ("governance", "propose"),
            (GOVERNANCE, governance::VOTE) => ("governance", "vote"),
            (GOVERNANCE, governance::CLOSE) => ("governance", "close"),
            _ => return Test::call_name(module, call),
        })
    }

    fn call_weight(call: &Call) -> Option<Weight> {
        match (call.0, call.1) {
            // `close` also pays for the call it may run.
            (GOVERNANCE, governance::CLOSE) => {
                let (_, inner): (u32, Call) = borsh::from_slice(&call.2).ok()?;
                Self::call_weight(&inner).map(|w| w.saturating_add(CALL_WEIGHT))
            }
            (GOVERNANCE, _) => Self::call_name(call.0, call.1).map(|_| CALL_WEIGHT),
            _ => Test::call_weight(call),
        }
    }

    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError> {
        let bad = || DispatchError::Other("bad call");
        let w = Self::call_weight(&call).ok_or_else(bad)?;
        let event = match (call.0, call.1) {
            (1, sudo::CALL) => {
                // Inner calls reach this runtime's modules, not only `Test`'s.
                let inner: Call = borsh::from_slice(&call.2).map_err(|_| bad())?;
                let r =
                    sudo::call(e, origin, inner, |s, o, i| s.nested(|sc| Self::dispatch(sc, cx, o, i)).map(|_| ()))?;
                e.deposit_event("sudo", &sudo::Event::Sudid(r.map_err(Into::into)));
                return Ok(w);
            }
            (GOVERNANCE, governance::SET_MEMBERS) => {
                governance::set_members(e, &origin, borsh::from_slice(&call.2).map_err(|_| bad())?)
            }
            (GOVERNANCE, governance::PROPOSE) => {
                governance::propose(e, origin, cx.number, borsh::from_slice(&call.2).map_err(|_| bad())?)
            }
            (GOVERNANCE, governance::VOTE) => {
                let (id, aye) = borsh::from_slice(&call.2).map_err(|_| bad())?;
                governance::vote(e, origin, id, aye)
            }
            (GOVERNANCE, governance::CLOSE) => {
                let (id, inner) = borsh::from_slice(&call.2).map_err(|_| bad())?;
                governance::close(e, origin, cx.number, id, inner, |s, o, i| {
                    s.nested(|sc| Self::dispatch(sc, cx, o, i)).map(|_| ())
                })
            }
            _ => return Test::dispatch(e, cx, origin, call),
        };
        e.deposit_event("governance", &event.map_err(|err| err.into_dispatch(GOVERNANCE))?);
        Ok(w)
    }

    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        Test::genesis(e, config);
        governance::genesis(e, vec![]).expect("no council at genesis");
    }
}

#[test]
fn sudo_hands_root_to_a_council() {
    let mut m = Mock { relay: (10, [4; 32]), ..Mock::default() };
    let config = borsh::to_vec(&(vec![(ROOT, FUNDS), (ALICE, FUNDS), (BOB, FUNDS)], Some(ROOT))).unwrap();
    let root: Hash32 = borsh::from_slice(&genesis::<Governed, _>(&mut m, &borsh::to_vec(&config).unwrap())).unwrap();
    let head = Header::genesis(root).head_data();

    let as_root = |inner: Call| (1, sudo::CALL, borsh::to_vec(&inner).unwrap());
    let council = (GOVERNANCE, governance::SET_MEMBERS, borsh::to_vec(&vec![ALICE, BOB]).unwrap());
    let upgrade: Call = (2, 0, borsh::to_vec(&CODE).unwrap());
    let propose = (GOVERNANCE, governance::PROPOSE, borsh::to_vec(&upgrade).unwrap());
    let vote = (GOVERNANCE, governance::VOTE, borsh::to_vec(&(0u32, true)).unwrap());
    let close = (GOVERNANCE, governance::CLOSE, borsh::to_vec(&(0u32, upgrade.clone())).unwrap());
    assert_eq!(Governed::call_weight(&close), Some(CALL_WEIGHT.saturating_add(CALL_WEIGHT)));

    let block = build_as::<Governed>(
        &mut m.clone(),
        &head,
        vec![
            tx(ROOT, 0, as_root(council)),
            tx(ROOT, 1, (1, sudo::REMOVE_KEY, vec![])),
            tx(ALICE, 0, propose),
            tx(ALICE, 1, close.clone()), // 1 of 2 isn't enough
            tx(BOB, 0, vote),
            tx(BOB, 1, close),
        ],
    );
    assert_eq!(block.extrinsics.len(), 6);
    let pov = Pov { parent_head: head, block, witness: Default::default(), inbox: Vec::new(), hub_proofs: Vec::new() };
    let r: ValidationResult =
        borsh::from_slice(&validate_block::<Governed, _>(&mut m, &Check, &borsh::to_vec(&pov).unwrap())).unwrap();
    assert_eq!(r.new_code, Some(CODE), "the council authorized the upgrade");
    assert_eq!(sudo::key(&mut m).unwrap(), None);
    assert_eq!(governance::members(&mut m).unwrap(), vec![ALICE, BOB]);
    let records = system::EVENTS.get(&mut m).unwrap().unwrap().records;
    let ours: Vec<governance::Event> =
        records.iter().filter(|r| r.module == "governance").map(|r| borsh::from_slice(&r.event).unwrap()).collect();
    assert_eq!(
        ours,
        vec![
            governance::Event::MembersSet { members: vec![ALICE, BOB] },
            governance::Event::Proposed { id: 0, proposer: ALICE },
            governance::Event::Voted { id: 0, who: BOB, aye: true },
            governance::Event::Executed { id: 0, result: Ok(()) },
        ]
    );
}

/// [`Test`] whose `on_initialize` uses all of the block's `proof_size`, with a `finalize_weight`
/// that needs some.
struct ProofFull;

const FINALIZE_BOTH: Weight = Weight::from_parts(PS_PER_SECOND / 10, 1_000);

impl Runtime for ProofFull {
    const NAME: &'static str = "test";
    const SPEC_VERSION: u32 = 3;

    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
        Test::call_name(module, call)
    }
    fn call_weight(call: &Call) -> Option<Weight> {
        Test::call_weight(call)
    }
    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError> {
        Test::dispatch(e, cx, origin, call)
    }
    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        Test::genesis(e, config);
    }
    fn on_initialize<E: Env>(_: &mut Scoped<'_, E>, _: &Context) -> Weight {
        Weight::from_parts(0, BlockLimits::DEFAULT.max_block.proof_size)
    }
    fn on_idle<E: Env>(e: &mut Scoped<'_, E>, _: &Context, remaining: Weight) -> Weight {
        IDLE.put(e, &remaining).unwrap();
        Weight::ZERO
    }
    fn finalize_weight() -> Weight {
        FINALIZE_BOTH
    }
}

#[test]
fn on_idle_gets_back_what_the_finalize_reservation_took_not_more() {
    // R-4: when the init hooks fill one dimension, the reservation for `on_finalize` takes what
    // is left, and only that comes back before `on_idle`.
    let (mut m, head) = chain();
    build_as::<ProofFull>(&mut m, &head, vec![]);
    let idle = IDLE.get(&mut m).unwrap().unwrap();
    let max = BlockLimits::DEFAULT.max_block;
    assert_eq!(idle, Weight::from_parts(max.ref_time - FINALIZE_BOTH.ref_time, 0));
}

/// [`Test`] whose inbox entries cost [`ENTRY`], recording what is left for `on_idle`.
struct Inboxed;

const ENTRY: Weight = Weight::from_parts(PS_PER_SECOND / 100, 500);

impl Runtime for Inboxed {
    const NAME: &'static str = "test";
    const SPEC_VERSION: u32 = 3;
    const INBOX_ENTRY_WEIGHT: Weight = ENTRY;

    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
        Test::call_name(module, call)
    }
    fn call_weight(call: &Call) -> Option<Weight> {
        Test::call_weight(call)
    }
    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError> {
        Test::dispatch(e, cx, origin, call)
    }
    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        Test::genesis(e, config);
    }
    fn on_idle<E: Env>(e: &mut Scoped<'_, E>, _: &Context, remaining: Weight) -> Weight {
        IDLE.put(e, &remaining).unwrap();
        Weight::ZERO
    }
}

#[test]
fn each_inbox_entry_costs_the_runtime_s_entry_weight_and_its_bytes() {
    // R-2: an entry costs `INBOX_ENTRY_WEIGHT` besides its bytes and its handler's limit.
    use tog_types::cgmp::{next_head, CGMP_VERSION, HEAD_0};
    let transfer = CgmpMessage {
        version: CGMP_VERSION,
        source: ChainId::HUB,
        dest: CHAIN,
        channel_nonce: 0,
        timeout_height: u64::MAX,
        fee: 0,
        origin: CgmpOrigin::Chain(ChainId::HUB),
        payload: CgmpPayload::TransferTog { to: BOB, amount: 7 },
    };
    let entry = borsh::to_vec(&(transfer.clone(), Some(Vec::<Hash32>::new()))).unwrap();
    let idle = |offer: bool| {
        let (mut m, head) = chain();
        let channel =
            CgmpChannel { head: next_head(&HEAD_0, &transfer.hash()), last_nonce: Some(0), ..CgmpChannel::default() };
        m.hub.insert(cgmp_channel(&ChainId::HUB, &CHAIN).to_vec(), borsh::to_vec(&channel).unwrap());
        m.hub.insert(cgmp_inbound(&CHAIN).to_vec(), borsh::to_vec(&vec![ChainId::HUB]).unwrap());
        if offer {
            m.inbox.push_back(entry.clone());
        }
        let block = build_as::<Inboxed>(&mut m, &head, vec![]);
        assert_eq!(block.header.inbox_processed, offer as u64);
        IDLE.get(&mut m).unwrap().unwrap()
    };
    let (quiet, one) = (idle(false), idle(true));
    assert_eq!(quiet.saturating_sub(one), ENTRY.saturating_add(Weight::from_parts(0, entry.len() as u64)));
}

/// [`Test`] whose inbox entries each cost an eighth of a second, so a block takes about a dozen.
struct Drained;

impl Runtime for Drained {
    const NAME: &'static str = "test";
    const SPEC_VERSION: u32 = 3;
    const INBOX_ENTRY_WEIGHT: Weight = Weight::from_parts(PS_PER_SECOND / 8, 0);

    fn call_name(module: u8, call: u8) -> Option<(&'static str, &'static str)> {
        Test::call_name(module, call)
    }
    fn call_weight(call: &Call) -> Option<Weight> {
        Test::call_weight(call)
    }
    fn dispatch<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        call: Call,
    ) -> Result<Weight, DispatchError> {
        Test::dispatch(e, cx, origin, call)
    }
    fn genesis<E: Env>(e: &mut E, config: &[u8]) {
        Test::genesis(e, config);
    }
}

/// Sources `3` and `4`, `PER_SOURCE` messages each on channels with `max_lag`; returns the chain
/// at genesis with both channels on the Hub, and the entries (each with its full proof) round-robin.
fn owing(max_lag: u32) -> (Mock, HeadData, Vec<Vec<u8>>) {
    use tog_types::cgmp::{next_head, CGMP_VERSION, HEAD_0};
    const PER_SOURCE: u64 = 8;
    let msg = |source: ChainId, nonce: u64| CgmpMessage {
        version: CGMP_VERSION,
        source,
        dest: CHAIN,
        channel_nonce: nonce,
        timeout_height: u64::MAX,
        fee: 0,
        origin: CgmpOrigin::Chain(source),
        payload: CgmpPayload::TransferTog { to: BOB, amount: 1 },
    };
    let (mut m, head) = chain();
    let sources = [ChainId(3), ChainId(4)];
    for source in sources {
        let hashes: Vec<Hash32> = (0..PER_SOURCE).map(|n| msg(source, n).hash()).collect();
        let channel = CgmpChannel {
            head: hashes.iter().fold(HEAD_0, |h, x| next_head(&h, x)),
            last_nonce: Some(PER_SOURCE - 1),
            next_nonce: 0,
            max_lag,
        };
        m.hub.insert(cgmp_channel(&source, &CHAIN).to_vec(), borsh::to_vec(&channel).unwrap());
    }
    m.hub.insert(cgmp_inbound(&CHAIN).to_vec(), borsh::to_vec(&sources.to_vec()).unwrap());
    let entry = |source: ChainId, n: u64| {
        let later: Vec<Hash32> = (n + 1..PER_SOURCE).map(|k| msg(source, k).hash()).collect();
        borsh::to_vec(&(msg(source, n), Some(later))).unwrap()
    };
    let entries = (0..PER_SOURCE).flat_map(|n| sources.map(|s| entry(s, n))).collect();
    (m, head, entries)
}

/// Builds a `Drained` block on `entries`: the block, whether it peeked, and the state before it.
fn drained(m: &mut Mock, head: &HeadData, entries: &[Vec<u8>]) -> (Block, bool, Mock) {
    let before = m.clone();
    m.inbox = entries.iter().cloned().collect();
    let input = borsh::to_vec(&(head.clone(), inherents(m), Vec::<Vec<u8>>::new())).unwrap();
    let (block, peeked) = borsh::from_slice(&build_block::<Drained, _>(m, &Check, &input)).unwrap();
    (block, peeked, before)
}

/// Imports `block` on `before` with inbox `entries`; the panic message if it is refused.
fn import_drained(before: &Mock, block: &Block, entries: &[Vec<u8>]) -> Result<Mock, String> {
    let mut m = before.clone();
    m.inbox = entries.iter().cloned().collect();
    let input = borsh::to_vec(block).unwrap();
    std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| execute_block::<Drained, _>(&mut m, &Check, &input)))
        .map(|_| m)
        .map_err(|e| {
            e.downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_default()
        })
}

#[test]
fn while_sources_owe_min_drain_a_block_takes_them_in_turn_and_stops_at_a_peek() {
    // R-3: both channels are over `max_lag` 0 and a block holds fewer than `MinDrain` entries.
    let (mut m, head, entries) = owing(0);
    let (block, peeked, before) = drained(&mut m, &head, &entries);
    let took = block.header.inbox_processed as usize;
    assert!(peeked && took > 1 && took < entries.len(), "took {took} of {}", entries.len());
    assert_eq!(m.inbox.len(), entries.len() - took - 1, "the peek was read, not taken");
    // One of each source per round, ascending.
    let next = |m: &mut Mock, c| cgmp::inbound(m, c).unwrap().next_nonce;
    assert_eq!((next(&mut m, ChainId(3)), next(&mut m, ChainId(4))), (took.div_ceil(2) as u64, (took / 2) as u64));

    // Importing it needs the peek, and only the round's next entry is one.
    let mut imported = import_drained(&before, &block, &entries[..took + 1]).unwrap();
    assert_eq!(imported.storage_root(), m.storage_root());
    let missing = import_drained(&before, &block, &entries[..took]).err().unwrap();
    assert_eq!(missing, "inbox proofs and max_lag: Lag");
    let mut skipped = entries[..took].to_vec();
    skipped.push(entries[took + 1].clone());
    let out_of_turn = import_drained(&before, &block, &skipped).err().unwrap();
    assert_eq!(out_of_turn, "inbox entry out of the round-robin of sources owing MinDrain");

    // A block that stops early while sources owe is invalid, though each entry is well-formed.
    let mut short = block.clone();
    short.header.inbox_processed -= 1;
    assert!(import_drained(&before, &short, &entries[..took]).is_err());
}

#[test]
fn a_block_no_source_owes_takes_what_fits_and_reads_no_peek() {
    let (mut m, head, entries) = owing(cgmp::MAX_BACKLOG as u32);
    let (block, peeked, before) = drained(&mut m, &head, &entries);
    let took = block.header.inbox_processed as usize;
    assert!(!peeked && took < entries.len());
    // An importer offered one more entry leaves it unread; a validator refuses a PoV holding it.
    let mut imported = before.clone();
    imported.inbox = entries[..took + 1].iter().cloned().collect();
    execute_block::<Drained, _>(&mut imported, &Check, &borsh::to_vec(&block).unwrap());
    assert_eq!(imported.inbox.len(), 1);
    assert_eq!(imported.storage_root(), m.storage_root());
}
