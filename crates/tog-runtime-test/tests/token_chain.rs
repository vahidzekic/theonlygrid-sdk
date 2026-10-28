//! The token chain, the first reference AppChain of the public testnet: the template runtime as
//! it ships (TOG-SPEC-0007 §7), its $TOG all from the Hub. $TOG arrives in a Hub `TransferTog`,
//! moves on the chain with every transaction paying its fee to the block author
//! (`transaction_payment`), pays the storage deposits of an asset made with `assets`, and leaves
//! again in a `TransferTog` to the Hub (`cgmp.withdraw`), taken or refunded by the Hub's `Ack`.
//! After every block the accounts hold exactly the total issuance, and the issuance is what the
//! Hub sent, minus what left, plus what came back.

use tog_runtime_core::{AccountId, Balance, ChainId};
use tog_runtime_modules::assets::{self, Call as Asset};
use tog_runtime_modules::executive::Call;
use tog_runtime_modules::{balances, cgmp};
use tog_runtime_template::{GenesisConfig, Template, ASSETS, BALANCES, CGMP};
use tog_runtime_test::{CgmpError, CgmpOrigin, CgmpPayload, TestChain, AUTHOR};

const CHAIN: ChainId = ChainId(5);
const ALICE: AccountId = [2; 20];
const BOB: AccountId = [3; 20];
/// Bob's account on the Hub.
const BOB_ON_HUB: AccountId = [0xb0; 20];
const ONE_TOG: Balance = 1_000_000_000_000_000_000;
/// What the Hub sends Alice: all of the chain's $TOG.
const FUNDS: Balance = 100 * ONE_TOG;
/// The CGMP fee of a withdrawal: above the Hub's minimum.
const HUB_FEE: Balance = ONE_TOG / 100;
/// The demo asset.
const DEMO: assets::AssetId = 1;

/// A token chain with no $TOG of its own at genesis.
fn chain() -> TestChain<Template> {
    TestChain::new(CHAIN, |author| {
        borsh::to_vec(&GenesisConfig { balances: vec![], authorities: vec![author], root_key: None }).unwrap()
    })
}

fn transfer(to: AccountId, amount: Balance) -> Call {
    (BALANCES, balances::TRANSFER, borsh::to_vec(&balances::Call::Transfer { to, amount }).unwrap())
}

fn asset(call: Asset) -> Call {
    let (index, args) = call.encode();
    (ASSETS, index, args)
}

fn withdraw(to: AccountId, amount: Balance) -> Call {
    let call = cgmp::Call::Withdraw { to, amount, fee: HUB_FEE, timeout: None };
    (CGMP, cgmp::WITHDRAW, borsh::to_vec(&call).unwrap())
}

/// Free and reserved: storage deposits move between them.
fn total(c: &mut TestChain<Template>, who: &AccountId) -> Balance {
    balances::account(c.state(), who).unwrap().total()
}

fn issuance(c: &mut TestChain<Template>) -> Balance {
    balances::total_issuance(c.state()).unwrap()
}

/// Every account holds part of the issuance and together they hold all of it, which must be
/// `expected`.
fn conserved(c: &mut TestChain<Template>, expected: Balance) {
    let held: Balance = [ALICE, BOB, AUTHOR].iter().map(|who| total(c, who)).sum();
    assert_eq!(issuance(c), expected, "issuance");
    assert_eq!(held, expected, "the accounts hold the issuance");
}

/// Runs a block of `calls` by `who`, each of which must succeed.
fn block_of(c: &mut TestChain<Template>, calls: Vec<(AccountId, Call)>) {
    let n = calls.len();
    for (who, call) in calls {
        c.submit(who, call);
    }
    c.block();
    let outcomes = c.outcomes();
    assert_eq!(outcomes.len(), n, "every transaction is in the block");
    assert!(outcomes.iter().all(Result::is_ok), "{outcomes:?}");
}

#[test]
fn tog_comes_from_the_hub_moves_on_the_chain_and_goes_back() {
    let mut c = chain();
    conserved(&mut c, 0);

    // The Hub's `TransferTog` (a `DepositToChain` there) mints Alice's $TOG here.
    c.send_from(ChainId::HUB, CgmpPayload::TransferTog { to: ALICE, amount: FUNDS });
    c.block();
    assert_eq!(total(&mut c, &ALICE), FUNDS);
    conserved(&mut c, FUNDS);

    // A transfer pays its fee to the author; the new account's deposit stays Alice's, reserved.
    block_of(&mut c, vec![(ALICE, transfer(BOB, 10 * ONE_TOG))]);
    let fee = total(&mut c, &AUTHOR);
    assert!(fee > 0, "the author is paid");
    assert_eq!(balances::free_balance(c.state(), &BOB).unwrap(), 10 * ONE_TOG);
    assert_eq!(total(&mut c, &ALICE), FUNDS - 10 * ONE_TOG - fee);
    assert!(balances::account(c.state(), &ALICE).unwrap().reserved > 0, "Bob's account deposit");
    conserved(&mut c, FUNDS);

    // Alice's own token: created, minted, given to Bob, and spent by Bob from her allowance.
    block_of(
        &mut c,
        vec![
            (ALICE, asset(Asset::Create { id: DEMO, decimals: 12, symbol: "DEMO".into() })),
            (ALICE, asset(Asset::Mint { id: DEMO, to: ALICE, amount: 1_000_000 })),
            (ALICE, asset(Asset::Transfer { id: DEMO, to: BOB, amount: 250_000 })),
            (ALICE, asset(Asset::Approve { id: DEMO, spender: BOB, amount: 100_000 })),
        ],
    );
    block_of(&mut c, vec![(BOB, asset(Asset::TransferFrom { id: DEMO, holder: ALICE, to: BOB, amount: 60_000 }))]);
    let s = c.state();
    let details = assets::details(s, DEMO).unwrap().unwrap();
    assert_eq!((details.owner, details.supply, details.symbol.as_str()), (ALICE, 1_000_000, "DEMO"));
    assert_eq!(assets::balance(s, DEMO, &ALICE).unwrap(), 690_000);
    assert_eq!(assets::balance(s, DEMO, &BOB).unwrap(), 310_000);
    let events: Vec<assets::Event> = c.events_of("assets");
    let moved = assets::Event::Transferred { id: DEMO, from: ALICE, to: BOB, amount: 60_000 };
    assert!(events.contains(&moved), "{events:?}");
    conserved(&mut c, FUNDS);

    // Bob takes $TOG back to the Hub: the amount and the CGMP fee leave the chain's issuance.
    block_of(&mut c, vec![(BOB, withdraw(BOB_ON_HUB, 4 * ONE_TOG))]);
    let sent = c.take_sent();
    assert_eq!(sent.len(), 1);
    let m = &sent[0];
    assert_eq!((m.dest, m.fee), (ChainId::HUB, HUB_FEE));
    assert_eq!(m.origin, CgmpOrigin::Account { chain: CHAIN, account: BOB });
    assert_eq!(m.payload, CgmpPayload::TransferTog { to: BOB_ON_HUB, amount: 4 * ONE_TOG });
    let events: Vec<cgmp::Event> = c.events_of("cgmp");
    let withdrawn = cgmp::Event::Withdrawn { from: BOB, to: BOB_ON_HUB, amount: 4 * ONE_TOG, nonce: m.channel_nonce };
    assert_eq!(events, vec![withdrawn]);
    let left = FUNDS - 4 * ONE_TOG - HUB_FEE;
    conserved(&mut c, left);
    assert_eq!(cgmp::PENDING_TRANSFERS.get_or_default(c.state()).unwrap(), 1);

    // The Hub takes it: nothing comes back, and the record's deposit returns to Bob.
    let reserved = balances::account(c.state(), &BOB).unwrap().reserved;
    c.ack(m, Ok(()));
    c.block();
    assert_eq!(cgmp::PENDING_TRANSFERS.get_or_default(c.state()).unwrap(), 0);
    assert!(balances::account(c.state(), &BOB).unwrap().reserved < reserved, "the record's deposit is back");
    conserved(&mut c, left);

    // A withdrawal the Hub never took (timed out) comes back whole, the fee with it.
    let (bob, author) = (total(&mut c, &BOB), total(&mut c, &AUTHOR));
    block_of(&mut c, vec![(BOB, withdraw(BOB_ON_HUB, ONE_TOG))]);
    let fee = total(&mut c, &AUTHOR) - author;
    let m = c.take_sent().remove(0);
    conserved(&mut c, left - ONE_TOG - HUB_FEE);
    c.ack(&m, Err(CgmpError::Timeout));
    c.block();
    conserved(&mut c, left);
    assert_eq!(total(&mut c, &BOB), bob - fee, "only the transaction fee is spent");
}

#[test]
fn a_withdrawal_needs_the_hub_fee_and_the_funds() {
    let mut c = chain();
    c.send_from(ChainId::HUB, CgmpPayload::TransferTog { to: ALICE, amount: FUNDS });
    c.block();

    let low = cgmp::Call::Withdraw { to: BOB_ON_HUB, amount: ONE_TOG, fee: 0, timeout: None };
    c.submit(ALICE, (CGMP, cgmp::WITHDRAW, borsh::to_vec(&low).unwrap()));
    c.submit(ALICE, withdraw(BOB_ON_HUB, FUNDS));
    c.block();
    let outcomes = c.outcomes();
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.iter().all(Result::is_err), "{outcomes:?}");
    assert!(c.take_sent().is_empty(), "nothing leaves");
    // Only the fees moved, to the author.
    conserved(&mut c, FUNDS);
}
