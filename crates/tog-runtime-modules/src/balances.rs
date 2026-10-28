//! `balances`: $TOG accounts on an AppChain (TOG-SPEC-0007 §7, §8.4).
//!
//! $TOG reaches a chain only through Hub deposits and leaves it only through CGMP withdrawals, so
//! [`deposit`] and [`withdraw`] are the only calls that change [`TOTAL_ISSUANCE`], and the Hub's
//! supply ledger for the chain (0000 §8.2) bounds it.
//!
//! **Layout (exact, §8.4).** `balances.accounts[account]` holds `borsh(AccountData)`, and
//! `AccountData` begins with `free: Amount, reserved: Amount`. When a chain is closed, the Hub pays
//! `ExitClaim`s from these two fields, proven against the chain's final state root, so the layout
//! must not change. An account with nothing in either field is removed from state.

use borsh::{BorshDeserialize, BorshSerialize};
use tog_runtime_core::dispatch::{ensure_signed, DispatchError, DispatchResult, Origin};
use tog_runtime_core::{AccountId, Balance, Storage, StorageError, StorageMap, StorageValue};

/// An account's balances. Borsh in field order; `ExitClaim` reads the first 32 bytes (§8.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountData {
    /// Spendable.
    pub free: Balance,
    /// Held for deposits and bonds; not spendable until unreserved.
    pub reserved: Balance,
}

impl AccountData {
    /// `free + reserved`, saturating.
    pub fn total(&self) -> Balance {
        self.free.saturating_add(self.reserved)
    }

    fn is_empty(&self) -> bool {
        self.free == 0 && self.reserved == 0
    }
}

/// `balances.accounts: Address → AccountData`.
pub const ACCOUNTS: StorageMap<AccountId, AccountData> = StorageMap::new("balances", "accounts");
/// `balances.total_issuance`: the $TOG held on this chain, deposited minus withdrawn.
pub const TOTAL_ISSUANCE: StorageValue<Balance> = StorageValue::new("balances", "total_issuance");

/// Call index of [`Call::Transfer`].
pub const TRANSFER: u8 = 0;

/// The module's metadata; its errors in [`Error`] index order.
pub fn metadata() -> tog_runtime_core::metadata::ModuleMetadata {
    tog_runtime_core::metadata::ModuleMetadata::from_names(
        "balances",
        &[(TRANSFER, "transfer", &[("to", "AccountId"), ("amount", "Balance")])],
        &["accounts", "total_issuance"],
        &["Transfer"],
        &["InsufficientBalance", "InsufficientReserved", "Overflow", "Storage"],
    )
}

/// What a balance operation can fail on. Its index is the module error index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Error {
    /// The free balance doesn't cover the amount.
    InsufficientBalance = 0,
    /// The reserved balance doesn't cover the amount.
    InsufficientReserved = 1,
    /// A balance or the total issuance would overflow.
    Overflow = 2,
    /// Stored state doesn't decode.
    Storage = 3,
}

impl From<StorageError> for Error {
    fn from(_: StorageError) -> Self {
        Error::Storage
    }
}

impl Error {
    /// As a [`DispatchError`] of the module at `module` in the runtime.
    pub fn dispatch(self, module: u8) -> DispatchError {
        DispatchError::Module { module, error: self as u8 }
    }
}

/// The account's balances (zero when absent).
pub fn account(s: &mut impl Storage, who: &AccountId) -> Result<AccountData, Error> {
    Ok(ACCOUNTS.get_or_default(s, who)?)
}

/// The account's free balance.
pub fn free_balance(s: &mut impl Storage, who: &AccountId) -> Result<Balance, Error> {
    Ok(account(s, who)?.free)
}

/// The $TOG held on this chain.
pub fn total_issuance(s: &mut impl Storage) -> Result<Balance, Error> {
    Ok(TOTAL_ISSUANCE.get_or_default(s)?)
}

fn put(s: &mut impl Storage, who: &AccountId, a: &AccountData) -> Result<(), Error> {
    if a.is_empty() {
        ACCOUNTS.remove(s, who);
        // A reaped account's storage deposit goes back to whoever created it ([`transfer_paying`]).
        crate::storage_deposit::release(s, &ACCOUNTS.key(who)).map_err(|_| Error::Storage)?;
    } else {
        ACCOUNTS.insert(s, who, a)?;
    }
    Ok(())
}

/// Credit `amount` deposited from the Hub to `who`'s free balance (a CGMP `TransferTog` from the
/// Hub, 0002 §4.7).
pub fn deposit(s: &mut impl Storage, who: &AccountId, amount: Balance) -> Result<(), Error> {
    let issuance = total_issuance(s)?.checked_add(amount).ok_or(Error::Overflow)?;
    let mut a = account(s, who)?;
    a.free = a.free.checked_add(amount).ok_or(Error::Overflow)?;
    put(s, who, &a)?;
    TOTAL_ISSUANCE.put(s, &issuance)?;
    Ok(())
}

/// Debit `amount` from `who`'s free balance for a withdrawal to the Hub; the caller sends the
/// CGMP message that carries it.
pub fn withdraw(s: &mut impl Storage, who: &AccountId, amount: Balance) -> Result<(), Error> {
    let mut a = account(s, who)?;
    a.free = a.free.checked_sub(amount).ok_or(Error::InsufficientBalance)?;
    // The issuance covers every balance, so it can't underflow unless state is corrupt.
    let issuance = total_issuance(s)?.checked_sub(amount).ok_or(Error::Storage)?;
    put(s, who, &a)?;
    TOTAL_ISSUANCE.put(s, &issuance)?;
    Ok(())
}

/// Move `amount` of free balance from `from` to `to`.
pub fn transfer(s: &mut impl Storage, from: &AccountId, to: &AccountId, amount: Balance) -> Result<(), Error> {
    let mut a = account(s, from)?;
    a.free = a.free.checked_sub(amount).ok_or(Error::InsufficientBalance)?;
    if from == to {
        return Ok(());
    }
    // `to` is read after `from` is written: reaping `from` may return a deposit to `to`.
    put(s, from, &a)?;
    let mut b = account(s, to)?;
    b.free = b.free.checked_add(amount).ok_or(Error::Overflow)?;
    put(s, to, &b)
}

/// Bytes an account keeps: `borsh(AccountData)` (32), and its `system.nonces` entry (8) once it
/// pays a fee. A nonce can't be removed (it stops replays), so it outlives a reaped account: the
/// deposit for it comes back with the account's, and the entry stays (§5).
pub const ACCOUNT_BYTES: u64 = 32 + 8;

/// [`transfer`], and when it creates `to`'s account, `from` reserves the storage deposit for it at
/// `per_byte` (§5), returned to `from` when the account is reaped. On failure nothing changes.
pub fn transfer_paying(
    s: &mut impl Storage,
    from: &AccountId,
    to: &AccountId,
    amount: Balance,
    per_byte: Balance,
) -> Result<(), Error> {
    use crate::storage_deposit;
    let creates = from != to && amount > 0 && !ACCOUNTS.contains_key(s, to);
    if !creates {
        return transfer(s, from, to, amount);
    }
    let deposit = storage_deposit::deposit_for(ACCOUNT_BYTES, per_byte).ok_or(Error::Overflow)?;
    if free_balance(s, from)? < amount.checked_add(deposit).ok_or(Error::Overflow)? {
        return Err(Error::InsufficientBalance);
    }
    transfer(s, from, to, amount)?;
    storage_deposit::charge(s, &ACCOUNTS.key(to), from, ACCOUNT_BYTES, per_byte).map_err(|e| match e {
        storage_deposit::Error::InsufficientBalance => Error::InsufficientBalance,
        storage_deposit::Error::Storage => Error::Storage,
    })
}

/// Move `amount` from `who`'s free balance to its reserved balance.
pub fn reserve(s: &mut impl Storage, who: &AccountId, amount: Balance) -> Result<(), Error> {
    let mut a = account(s, who)?;
    a.free = a.free.checked_sub(amount).ok_or(Error::InsufficientBalance)?;
    a.reserved = a.reserved.checked_add(amount).ok_or(Error::Overflow)?;
    put(s, who, &a)
}

/// Move `amount` from `who`'s reserved balance back to its free balance.
pub fn unreserve(s: &mut impl Storage, who: &AccountId, amount: Balance) -> Result<(), Error> {
    let mut a = account(s, who)?;
    a.reserved = a.reserved.checked_sub(amount).ok_or(Error::InsufficientReserved)?;
    a.free = a.free.checked_add(amount).ok_or(Error::Overflow)?;
    put(s, who, &a)
}

/// Move `amount` of `from`'s reserved balance to `to`'s free balance (a forfeited deposit).
pub fn repatriate_reserved(
    s: &mut impl Storage,
    from: &AccountId,
    to: &AccountId,
    amount: Balance,
) -> Result<(), Error> {
    if from == to {
        return unreserve(s, from, amount);
    }
    let mut a = account(s, from)?;
    a.reserved = a.reserved.checked_sub(amount).ok_or(Error::InsufficientReserved)?;
    // `to` is read after `from` is written: reaping `from` may return a deposit to `to`.
    put(s, from, &a)?;
    let mut b = account(s, to)?;
    b.free = b.free.checked_add(amount).ok_or(Error::Overflow)?;
    put(s, to, &b)
}

/// The `balances` module's events.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Event {
    /// Free balance moved by [`Call::Transfer`].
    Transfer {
        /// Sender.
        from: AccountId,
        /// Recipient.
        to: AccountId,
        /// Amount in atto-TOG.
        amount: Balance,
    },
}

/// A call of the `balances` module: `borsh(Call)` inside the runtime's call enum.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Call {
    /// 0: move free balance from the signer to `to`.
    Transfer {
        /// Recipient.
        to: AccountId,
        /// Amount in atto-TOG.
        amount: Balance,
    },
}

/// Dispatch `call` from `origin`; `module` is this module's index in the runtime. A transfer
/// that creates an account takes the SDK's default storage deposit ([`transfer_paying`]).
pub fn dispatch(s: &mut impl Storage, module: u8, origin: Origin, call: Call) -> DispatchResult {
    match call {
        Call::Transfer { to, amount } => {
            let from = ensure_signed(origin)?;
            transfer_paying(s, &from, &to, amount, crate::storage_deposit::DEFAULT_PER_BYTE)
                .map_err(|e| e.dispatch(module))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tog_runtime_core::memory::MemoryStorage;
    use tog_runtime_core::storage_key;

    const A: AccountId = [1; 20];
    const B: AccountId = [2; 20];

    fn funded() -> MemoryStorage {
        let mut s = MemoryStorage::default();
        deposit(&mut s, &A, 100).unwrap();
        s
    }

    #[test]
    fn layout_is_what_exit_claims_read() {
        let mut s = funded();
        reserve(&mut s, &A, 30).unwrap();
        // The Hub proves `balances.accounts[account]` (§8.4): the key is the 0002 §7.1 layout of
        // `borsh(address)`, and the value starts with `free`, `reserved` as two LE u128s.
        let key = storage_key("balances", "accounts", &A);
        assert_eq!(ACCOUNTS.key(&A), key);
        let raw = s.get(&key).unwrap();
        assert_eq!(raw.len(), 32);
        assert_eq!(u128::from_le_bytes(raw[..16].try_into().unwrap()), 70);
        assert_eq!(u128::from_le_bytes(raw[16..32].try_into().unwrap()), 30);
    }

    #[test]
    fn deposit_and_withdraw_track_issuance() {
        let mut s = funded();
        deposit(&mut s, &B, 50).unwrap();
        assert_eq!(total_issuance(&mut s).unwrap(), 150);
        withdraw(&mut s, &A, 40).unwrap();
        assert_eq!(total_issuance(&mut s).unwrap(), 110);
        assert_eq!(free_balance(&mut s, &A).unwrap(), 60);
        assert_eq!(withdraw(&mut s, &A, 61), Err(Error::InsufficientBalance));
        assert_eq!(total_issuance(&mut s).unwrap(), 110);
    }

    #[test]
    fn transfer_moves_free_balance_and_reaps_empty_accounts() {
        let mut s = funded();
        assert_eq!(transfer(&mut s, &A, &B, 101), Err(Error::InsufficientBalance));
        transfer(&mut s, &A, &B, 100).unwrap();
        assert!(!ACCOUNTS.contains_key(&mut s, &A));
        assert_eq!(free_balance(&mut s, &B).unwrap(), 100);
        transfer(&mut s, &B, &B, 100).unwrap();
        assert_eq!(free_balance(&mut s, &B).unwrap(), 100);
        assert_eq!(total_issuance(&mut s).unwrap(), 100);
    }

    #[test]
    fn a_transfer_that_creates_an_account_holds_its_deposit_until_it_is_reaped() {
        let mut s = funded();
        let held = crate::storage_deposit::deposit_for(ACCOUNT_BYTES, 1).unwrap();
        assert_eq!(held, 268);
        deposit(&mut s, &A, 1_000).unwrap();
        // Too little for the amount and the deposit: nothing moves.
        let all = free_balance(&mut s, &A).unwrap();
        assert_eq!(transfer_paying(&mut s, &A, &B, all - held + 1, 1), Err(Error::InsufficientBalance));
        assert_eq!((free_balance(&mut s, &A).unwrap(), ACCOUNTS.contains_key(&mut s, &B)), (all, false));

        transfer_paying(&mut s, &A, &B, 10, 1).unwrap();
        assert_eq!(account(&mut s, &A).unwrap(), AccountData { free: all - 10 - held, reserved: held });
        // An existing account takes no second deposit, nor does a transfer to oneself.
        transfer_paying(&mut s, &A, &B, 5, 1).unwrap();
        transfer_paying(&mut s, &A, &A, 5, 1).unwrap();
        assert_eq!(account(&mut s, &A).unwrap().reserved, held);
        // B can't create an account it can't pay the deposit for; emptying its own into A's
        // reaps it, and A gets B's deposit back.
        let c = [9; 20];
        assert_eq!(transfer_paying(&mut s, &B, &c, 15, 1), Err(Error::InsufficientBalance));
        transfer_paying(&mut s, &B, &A, 15, 1).unwrap();
        assert!(!ACCOUNTS.contains_key(&mut s, &B));
        assert_eq!(account(&mut s, &A).unwrap(), AccountData { free: all, reserved: 0 });
        assert_eq!(total_issuance(&mut s).unwrap(), 1_100);
    }

    #[test]
    fn reserve_unreserve_repatriate() {
        let mut s = funded();
        reserve(&mut s, &A, 60).unwrap();
        assert_eq!(transfer(&mut s, &A, &B, 41), Err(Error::InsufficientBalance));
        assert_eq!(unreserve(&mut s, &A, 61), Err(Error::InsufficientReserved));
        unreserve(&mut s, &A, 10).unwrap();
        repatriate_reserved(&mut s, &A, &B, 50).unwrap();
        assert_eq!(account(&mut s, &A).unwrap(), AccountData { free: 50, reserved: 0 });
        assert_eq!(account(&mut s, &B).unwrap(), AccountData { free: 50, reserved: 0 });
        assert_eq!(total_issuance(&mut s).unwrap(), 100);
    }

    #[test]
    fn overflow_is_refused_without_changes() {
        let mut s = funded();
        assert_eq!(deposit(&mut s, &B, Balance::MAX), Err(Error::Overflow));
        assert_eq!(free_balance(&mut s, &B).unwrap(), 0);
        assert_eq!(total_issuance(&mut s).unwrap(), 100);
    }

    #[test]
    fn dispatch_needs_a_signer() {
        let mut s = funded();
        let call = Call::Transfer { to: B, amount: 5 };
        assert_eq!(dispatch(&mut s, 1, Origin::Root, call.clone()), Err(DispatchError::BadOrigin));
        let held =
            crate::storage_deposit::deposit_for(ACCOUNT_BYTES, crate::storage_deposit::DEFAULT_PER_BYTE).unwrap();
        assert_eq!(
            dispatch(&mut s, 1, Origin::Signed(A), call.clone()),
            Err(DispatchError::Module { module: 1, error: 0 })
        );
        deposit(&mut s, &A, held).unwrap();
        dispatch(&mut s, 1, Origin::Signed(A), call).unwrap();
        assert_eq!(account(&mut s, &A).unwrap().reserved, held, "B's account deposit");
        assert_eq!(free_balance(&mut s, &B).unwrap(), 5);
        assert_eq!(
            dispatch(&mut s, 1, Origin::Signed(B), Call::Transfer { to: A, amount: 6 }),
            Err(DispatchError::Module { module: 1, error: 0 })
        );
        assert_eq!(borsh::to_vec(&Call::Transfer { to: B, amount: 5 }).unwrap()[0], 0);
    }
}
