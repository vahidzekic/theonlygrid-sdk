//! The optional `assets` module (TOG-SPEC-0007 §7): fungible assets a chain issues besides $TOG,
//! written with [`tog_module`](crate::tog_module).
//!
//! Anyone signed creates an asset under a free id and owns it; the owner mints, burns from any
//! account and hands the asset on. Holders transfer and approve spenders, ERC-20 style. Balances
//! are `u128` in the asset's smallest unit; `decimals` and `symbol` are for clients only.
//!
//! The weights are what `tog bench` measured for the module's `#[benchmark]`s on the template
//! runtime; a runtime that includes the module measures its own.
//!
//! Storage deposits (§5), at the runtime's `StorageDepositPerByte`: `create` holds the asset's
//! record from its creator for as long as the asset exists (there is no destroy, so for good); a
//! `mint`, `transfer` or `transfer_from` that gives an account its first balance of an asset holds
//! that balance from the signer until it reaches 0; `approve` holds the approval from the holder
//! until it is taken back or used up. Genesis assets and balances hold none.

use crate::tog_module;

#[tog_module]
mod assets {
    use alloc::string::String;
    use alloc::vec::Vec;

    use borsh::{BorshDeserialize, BorshSerialize};
    use tog_runtime_core::env::Env;
    use tog_runtime_core::{
        AccountId, Origin, Storage, StorageDoubleMap, StorageError, StorageMap, StorageNMap, Weight,
    };

    use crate::executive::{Context, Scoped};
    use crate::storage_deposit;
    use tog_runtime_core::Balance;

    /// Bytes a balance or an approval keeps: `borsh(u128)`.
    const AMOUNT_BYTES: u64 = 16;

    /// Who pays a deposit, and at what rate per byte; `None` at genesis.
    type Payer<'a> = Option<(&'a AccountId, Balance)>;

    /// An asset's id on the chain.
    pub type AssetId = u32;

    /// Longest `symbol`, in bytes.
    pub const MAX_SYMBOL: usize = 16;

    /// One asset.
    #[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    pub struct AssetDetails {
        /// Who mints, burns and hands it on.
        pub owner: AccountId,
        /// All of its balances together.
        pub supply: u128,
        /// Decimal places clients show.
        pub decimals: u8,
        /// Its ticker, at most [`MAX_SYMBOL`] bytes.
        pub symbol: String,
    }

    /// Each asset by id.
    #[storage]
    pub type Assets = StorageMap<AssetId, AssetDetails>;
    /// Balances: (asset, holder).
    #[storage]
    pub type Balances = StorageDoubleMap<AssetId, AccountId, u128>;
    /// What a spender may still move: (asset, holder, spender).
    #[storage]
    pub type Approvals = StorageNMap<(AssetId, AccountId, AccountId), u128>;

    /// The module's events, `borsh` in the block's events under module `"assets"`.
    #[event]
    pub enum Event {
        /// Asset `id` was created, owned by `owner`.
        Created {
            /// The asset.
            id: AssetId,
            /// Its owner.
            owner: AccountId,
        },
        /// `amount` of `id` was minted to `to`.
        Issued {
            /// The asset.
            id: AssetId,
            /// The holder.
            to: AccountId,
            /// How much.
            amount: u128,
        },
        /// `amount` of `id` was burned from `from`.
        Burned {
            /// The asset.
            id: AssetId,
            /// The holder.
            from: AccountId,
            /// How much.
            amount: u128,
        },
        /// `amount` of `id` moved from `from` to `to`.
        Transferred {
            /// The asset.
            id: AssetId,
            /// The holder it left.
            from: AccountId,
            /// The holder it reached.
            to: AccountId,
            /// How much.
            amount: u128,
        },
        /// `spender` may now move `amount` of `holder`'s `id`.
        Approved {
            /// The asset.
            id: AssetId,
            /// The holder.
            holder: AccountId,
            /// The spender.
            spender: AccountId,
            /// The approval, replacing the previous one.
            amount: u128,
        },
        /// Asset `id` is now owned by `owner`.
        OwnerChanged {
            /// The asset.
            id: AssetId,
            /// The new owner.
            owner: AccountId,
        },
    }

    /// Why a call failed; its index is the module error index.
    #[error]
    pub enum Error {
        /// The call needs a signed origin.
        BadOrigin,
        /// The id is taken.
        Exists,
        /// No asset has the id.
        Unknown,
        /// Only the asset's owner may do this.
        NotOwner,
        /// The balance doesn't cover the amount.
        InsufficientBalance,
        /// The approval doesn't cover the amount.
        InsufficientAllowance,
        /// The supply would overflow.
        Overflow,
        /// The symbol is longer than [`MAX_SYMBOL`].
        SymbolTooLong,
        /// Stored state doesn't decode.
        Storage(StorageError),
        /// The signer's free $TOG doesn't cover the storage deposit.
        DepositUnpaid,
    }

    impl From<storage_deposit::Error> for Error {
        fn from(e: storage_deposit::Error) -> Self {
            match e {
                storage_deposit::Error::InsufficientBalance => Error::DepositUnpaid,
                storage_deposit::Error::Storage => Error::Storage(StorageError::Corrupt),
            }
        }
    }

    /// An asset at genesis: id, owner, decimals, symbol, and the balances it starts with.
    pub type GenesisAsset = (AssetId, AccountId, u8, String, Vec<(AccountId, u128)>);

    /// Assets at genesis.
    #[genesis]
    pub struct GenesisConfig {
        /// The assets.
        pub assets: Vec<GenesisAsset>,
    }

    /// Applies `config`.
    pub fn genesis(s: &mut impl Storage, config: &GenesisConfig) -> Result<(), Error> {
        for (id, owner, decimals, symbol, balances) in &config.assets {
            create_asset(s, *id, *owner, *decimals, symbol.clone(), None)?;
            for (who, amount) in balances {
                issue(s, *id, who, *amount, None)?;
            }
        }
        Ok(())
    }

    /// The asset `id`, if any.
    pub fn details(s: &mut impl Storage, id: AssetId) -> Result<Option<AssetDetails>, StorageError> {
        ASSETS.get(s, &id)
    }

    /// `who`'s balance of `id`.
    pub fn balance(s: &mut impl Storage, id: AssetId, who: &AccountId) -> Result<u128, StorageError> {
        BALANCES.get(s, &id, who).map(Option::unwrap_or_default)
    }

    fn signed(origin: Origin) -> Result<AccountId, Error> {
        match origin {
            Origin::Signed(who) => Ok(who),
            _ => Err(Error::BadOrigin),
        }
    }

    fn owned(s: &mut impl Storage, id: AssetId, who: &AccountId) -> Result<AssetDetails, Error> {
        let a = ASSETS.get(s, &id)?.ok_or(Error::Unknown)?;
        if &a.owner != who {
            return Err(Error::NotOwner);
        }
        Ok(a)
    }

    fn create_asset(
        s: &mut impl Storage,
        id: AssetId,
        owner: AccountId,
        decimals: u8,
        symbol: String,
        payer: Payer<'_>,
    ) -> Result<(), Error> {
        if symbol.len() > MAX_SYMBOL {
            return Err(Error::SymbolTooLong);
        }
        if ASSETS.contains_key(s, &id) {
            return Err(Error::Exists);
        }
        let a = AssetDetails { owner, supply: 0, decimals, symbol };
        if let Some((payer, per_byte)) = payer {
            let len = borsh::object_length(&a).map_err(|_| Error::Storage(StorageError::Corrupt))? as u64;
            storage_deposit::charge(s, &ASSETS.key(&id), payer, len, per_byte)?;
        }
        ASSETS.insert(s, &id, &a)?;
        Ok(())
    }

    fn issue(s: &mut impl Storage, id: AssetId, to: &AccountId, amount: u128, payer: Payer<'_>) -> Result<(), Error> {
        let mut a = ASSETS.get(s, &id)?.ok_or(Error::Unknown)?;
        a.supply = a.supply.checked_add(amount).ok_or(Error::Overflow)?;
        // Every balance is at most the supply, so this can't overflow either; checked all the same (R-9).
        let b = balance(s, id, to)?.checked_add(amount).ok_or(Error::Overflow)?;
        ASSETS.insert(s, &id, &a)?;
        set_balance(s, id, to, b, payer)
    }

    /// Set `who`'s balance of `id`: a new balance holds `payer`'s deposit, 0 removes it and
    /// returns its deposit.
    fn set_balance(s: &mut impl Storage, id: AssetId, who: &AccountId, b: u128, payer: Payer<'_>) -> Result<(), Error> {
        let key = BALANCES.key(&id, who);
        if b == 0 {
            BALANCES.remove(s, &id, who);
            return Ok(storage_deposit::release(s, &key)?);
        }
        if let Some((payer, per_byte)) = payer {
            if !BALANCES.contains_key(s, &id, who) {
                storage_deposit::charge(s, &key, payer, AMOUNT_BYTES, per_byte)?;
            }
        }
        Ok(BALANCES.insert(s, &id, who, &b)?)
    }

    fn move_balance(
        s: &mut impl Storage,
        id: AssetId,
        from: &AccountId,
        to: &AccountId,
        amount: u128,
        payer: Payer<'_>,
    ) -> Result<(), Error> {
        if !ASSETS.contains_key(s, &id) {
            return Err(Error::Unknown);
        }
        let have = balance(s, id, from)?;
        let left = have.checked_sub(amount).ok_or(Error::InsufficientBalance)?;
        set_balance(s, id, from, left, None)?;
        let b = balance(s, id, to)?.checked_add(amount).ok_or(Error::Overflow)?;
        set_balance(s, id, to, b, payer)
    }

    /// `create(id, decimals, symbol)`: a new asset owned by the signer, with no supply.
    #[call(index = 0, weight = Weight::from_parts(351_000_000, 2_176))]
    pub fn create<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        id: AssetId,
        decimals: u8,
        symbol: String,
    ) -> Result<(), Error> {
        let owner = signed(origin)?;
        create_asset(e, id, owner, decimals, symbol, Some((&owner, cx.per_byte)))?;
        Event::Created { id, owner }.deposit(e);
        Ok(())
    }

    /// `mint(id, to, amount)`, by the owner.
    #[call(index = 1, weight = Weight::from_parts(509_000_000, 3_840))]
    pub fn mint<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        id: AssetId,
        to: AccountId,
        amount: u128,
    ) -> Result<(), Error> {
        let who = signed(origin)?;
        owned(e, id, &who)?;
        issue(e, id, &to, amount, Some((&who, cx.per_byte)))?;
        Event::Issued { id, to, amount }.deposit(e);
        Ok(())
    }

    /// `burn(id, from, amount)`, by the owner.
    #[call(index = 2, weight = Weight::from_parts(475_000_000, 6_784))]
    pub fn burn<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        origin: Origin,
        id: AssetId,
        from: AccountId,
        amount: u128,
    ) -> Result<(), Error> {
        let who = signed(origin)?;
        let mut a = owned(e, id, &who)?;
        let left = balance(e, id, &from)?.checked_sub(amount).ok_or(Error::InsufficientBalance)?;
        a.supply = a.supply.checked_sub(amount).ok_or(Error::Overflow)?;
        ASSETS.insert(e, &id, &a)?;
        set_balance(e, id, &from, left, None)?;
        Event::Burned { id, from, amount }.deposit(e);
        Ok(())
    }

    /// `transfer(id, to, amount)` from the signer.
    #[call(index = 3, weight = Weight::from_parts(674_000_000, 9_600))]
    pub fn transfer<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        id: AssetId,
        to: AccountId,
        amount: u128,
    ) -> Result<(), Error> {
        let from = signed(origin)?;
        move_balance(e, id, &from, &to, amount, Some((&from, cx.per_byte)))?;
        Event::Transferred { id, from, to, amount }.deposit(e);
        Ok(())
    }

    /// `approve(id, spender, amount)`: `spender` may move up to `amount` of the signer's; 0 takes
    /// the approval back.
    #[call(index = 4, weight = Weight::from_parts(361_000_000, 3_648))]
    pub fn approve<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        id: AssetId,
        spender: AccountId,
        amount: u128,
    ) -> Result<(), Error> {
        let holder = signed(origin)?;
        if !ASSETS.contains_key(e, &id) {
            return Err(Error::Unknown);
        }
        let key = (id, holder, spender);
        if amount == 0 {
            APPROVALS.remove(e, &key);
            storage_deposit::release(e, &APPROVALS.key(&key))?;
        } else {
            if !APPROVALS.contains_key(e, &key) {
                storage_deposit::charge(e, &APPROVALS.key(&key), &holder, AMOUNT_BYTES, cx.per_byte)?;
            }
            APPROVALS.insert(e, &key, &amount)?;
        }
        Event::Approved { id, holder, spender, amount }.deposit(e);
        Ok(())
    }

    /// `transfer_from(id, holder, to, amount)` by a spender `holder` approved.
    #[call(index = 5, weight = Weight::from_parts(978_000_000, 14_464))]
    pub fn transfer_from<E: Env>(
        e: &mut Scoped<'_, E>,
        cx: &Context,
        origin: Origin,
        id: AssetId,
        holder: AccountId,
        to: AccountId,
        amount: u128,
    ) -> Result<(), Error> {
        let spender = signed(origin)?;
        let key = (id, holder, spender);
        let left =
            APPROVALS.get(e, &key)?.unwrap_or_default().checked_sub(amount).ok_or(Error::InsufficientAllowance)?;
        move_balance(e, id, &holder, &to, amount, Some((&spender, cx.per_byte)))?;
        if left == 0 {
            APPROVALS.remove(e, &key);
            storage_deposit::release(e, &APPROVALS.key(&key))?;
        } else {
            APPROVALS.insert(e, &key, &left)?;
        }
        Event::Transferred { id, from: holder, to, amount }.deposit(e);
        Ok(())
    }

    /// `set_owner(id, owner)`, by the owner.
    #[call(index = 6, weight = Weight::from_parts(180_000_000, 1_408))]
    pub fn set_owner<E: Env>(
        e: &mut Scoped<'_, E>,
        _cx: &Context,
        origin: Origin,
        id: AssetId,
        owner: AccountId,
    ) -> Result<(), Error> {
        let who = signed(origin)?;
        let mut a = owned(e, id, &who)?;
        a.owner = owner;
        ASSETS.insert(e, &id, &a)?;
        Event::OwnerChanged { id, owner }.deposit(e);
        Ok(())
    }

    // Benchmarks (§6): each call's worst case. The calls touch a fixed number of keys, so the worst
    // case is the longest symbol, writes that create a key rather than update one (and take its
    // deposit), and amounts that empty a balance or an approval (and return its deposit).

    /// The asset the benchmarks run on, owned by `owner`, with `holder` holding 100.
    const BENCH_ASSET: AssetId = 1;
    /// Who receives in the benchmarks: an account with no balance yet.
    const BENCH_NEW: AccountId = [0xbe; 20];

    /// The benchmark asset, `holder`'s 100 of it holding `payer`'s deposit.
    fn bench_asset(s: &mut impl Storage, owner: AccountId, holder: AccountId, payer: AccountId) -> Result<(), Error> {
        create_asset(s, BENCH_ASSET, owner, 18, "B".repeat(MAX_SYMBOL), None)?;
        issue(s, BENCH_ASSET, &holder, 100, Some((&payer, storage_deposit::DEFAULT_PER_BYTE)))
    }

    #[benchmark(create)]
    fn bench_create<E: Env>(_e: &mut Scoped<'_, E>, _caller: AccountId) -> Result<Call, Error> {
        Ok(Call::Create { id: BENCH_ASSET, decimals: 18, symbol: "B".repeat(MAX_SYMBOL) })
    }

    #[benchmark(mint)]
    fn bench_mint<E: Env>(e: &mut Scoped<'_, E>, caller: AccountId) -> Result<Call, Error> {
        bench_asset(e, caller, caller, caller)?;
        Ok(Call::Mint { id: BENCH_ASSET, to: BENCH_NEW, amount: 10 })
    }

    #[benchmark(burn)]
    fn bench_burn<E: Env>(e: &mut Scoped<'_, E>, caller: AccountId) -> Result<Call, Error> {
        bench_asset(e, caller, BENCH_NEW, caller)?;
        Ok(Call::Burn { id: BENCH_ASSET, from: BENCH_NEW, amount: 100 })
    }

    #[benchmark(transfer)]
    fn bench_transfer<E: Env>(e: &mut Scoped<'_, E>, caller: AccountId) -> Result<Call, Error> {
        bench_asset(e, BENCH_NEW, caller, caller)?;
        Ok(Call::Transfer { id: BENCH_ASSET, to: BENCH_NEW, amount: 100 })
    }

    #[benchmark(approve)]
    fn bench_approve<E: Env>(e: &mut Scoped<'_, E>, caller: AccountId) -> Result<Call, Error> {
        bench_asset(e, BENCH_NEW, caller, caller)?;
        Ok(Call::Approve { id: BENCH_ASSET, spender: BENCH_NEW, amount: 10 })
    }

    #[benchmark(transfer_from)]
    fn bench_transfer_from<E: Env>(e: &mut Scoped<'_, E>, caller: AccountId) -> Result<Call, Error> {
        let holder: AccountId = [0xbf; 20];
        bench_asset(e, holder, holder, caller)?;
        let key = (BENCH_ASSET, holder, caller);
        storage_deposit::charge(e, &APPROVALS.key(&key), &caller, AMOUNT_BYTES, storage_deposit::DEFAULT_PER_BYTE)?;
        APPROVALS.insert(e, &key, &100)?;
        Ok(Call::TransferFrom { id: BENCH_ASSET, holder, to: BENCH_NEW, amount: 100 })
    }

    #[benchmark(set_owner)]
    fn bench_set_owner<E: Env>(e: &mut Scoped<'_, E>, caller: AccountId) -> Result<Call, Error> {
        bench_asset(e, caller, caller, caller)?;
        Ok(Call::SetOwner { id: BENCH_ASSET, owner: BENCH_NEW })
    }
}

pub use assets::*;
