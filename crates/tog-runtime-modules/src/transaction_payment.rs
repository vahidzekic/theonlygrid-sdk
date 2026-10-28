//! `transaction_payment`: the fee pipeline of signed transactions (TOG-SPEC-0007 §4.3, §6).
//!
//! ```text
//! validate (pool) → pre_dispatch (bump nonce, charge the declared weight's fee and the tip)
//!                 → dispatch → post_dispatch (refund the unused weight, pay the author)
//! ```
//!
//! **SDK default (exact).** `fee(w) = 2 500 · w.ref_time + 10⁹ · w.proof_size` atto-TOG for weight
//! `w` (2 500 atto-TOG per ps, 10⁹ per proof byte: a block full in either dimension costs about
//! 0.005 TOG), plus the transaction's `tip`. `pre_dispatch` charges the fee of the call's
//! benchmarked weight and `post_dispatch` refunds the difference to its actual weight; fee and tip
//! go to the block's `Inherent::Collator` account ([`TogFees`]). There is no base-fee adjustment in
//! v1. A chain may set other prices ([`FeeParams`]) or plug in its own [`FeeHandler`].
//!
//! Storage deposits (§5) are charged by the calls that add state ([`crate::storage_deposit`]), not
//! here.

use tog_runtime_core::tx::TxError;
use tog_runtime_core::{AccountId, Balance, Storage, StorageError, Weight};

use crate::{balances, system};

/// A chain's fee prices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeParams {
    /// atto-TOG per picosecond of `ref_time`.
    pub per_ps: Balance,
    /// atto-TOG per byte of `proof_size`.
    pub per_proof_byte: Balance,
}

impl FeeParams {
    /// The SDK default (§4.3).
    pub const DEFAULT: FeeParams = FeeParams { per_ps: 2_500, per_proof_byte: 1_000_000_000 };

    /// The fee of weight `w`, without tip.
    pub fn fee(&self, w: Weight) -> Option<Balance> {
        self.per_ps
            .checked_mul(Balance::from(w.ref_time))?
            .checked_add(self.per_proof_byte.checked_mul(Balance::from(w.proof_size))?)
    }
}

impl Default for FeeParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a transaction can't pay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentError {
    /// Its nonce is used.
    Stale,
    /// Its nonce is ahead of the account's; the pool may keep it.
    Future,
    /// The signer can't pay the fee.
    InsufficientBalance,
    /// Stored state doesn't decode, or a fee overflows.
    Storage,
}

impl From<StorageError> for PaymentError {
    fn from(_: StorageError) -> Self {
        PaymentError::Storage
    }
}

impl From<system::NonceError> for PaymentError {
    fn from(e: system::NonceError) -> Self {
        match e {
            system::NonceError::Stale => PaymentError::Stale,
            system::NonceError::Future => PaymentError::Future,
            system::NonceError::Storage => PaymentError::Storage,
        }
    }
}

impl From<balances::Error> for PaymentError {
    fn from(e: balances::Error) -> Self {
        match e {
            balances::Error::InsufficientBalance => PaymentError::InsufficientBalance,
            _ => PaymentError::Storage,
        }
    }
}

/// Where fees come from and go.
pub trait FeeHandler {
    /// Take `fee` from `who` before dispatch.
    fn withdraw(&self, s: &mut impl Storage, who: &AccountId, fee: Balance) -> Result<(), PaymentError>;
    /// After dispatch: give `refund` back to `who` and `paid` to the block's `author` (burned without
    /// one).
    fn settle(
        &self,
        s: &mut impl Storage,
        who: &AccountId,
        refund: Balance,
        paid: Balance,
        author: Option<&AccountId>,
    ) -> Result<(), PaymentError>;
    /// Whether `who` could pay `fee` now (for the pool).
    fn can_pay(&self, s: &mut impl Storage, who: &AccountId, fee: Balance) -> Result<bool, PaymentError>;
}

/// Fees in $TOG from the `balances` module, paid to the block author.
#[derive(Clone, Copy, Debug, Default)]
pub struct TogFees;

impl FeeHandler for TogFees {
    fn withdraw(&self, s: &mut impl Storage, who: &AccountId, fee: Balance) -> Result<(), PaymentError> {
        Ok(balances::withdraw(s, who, fee)?)
    }

    fn settle(
        &self,
        s: &mut impl Storage,
        who: &AccountId,
        refund: Balance,
        paid: Balance,
        author: Option<&AccountId>,
    ) -> Result<(), PaymentError> {
        if refund > 0 {
            balances::deposit(s, who, refund)?;
        }
        if let (Some(author), true) = (author, paid > 0) {
            balances::deposit(s, author, paid)?;
        }
        Ok(())
    }

    fn can_pay(&self, s: &mut impl Storage, who: &AccountId, fee: Balance) -> Result<bool, PaymentError> {
        Ok(balances::free_balance(s, who)? >= fee)
    }
}

/// What [`pre_dispatch`] charged, for [`post_dispatch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Charged {
    /// The fee of the declared weight.
    pub fee: Balance,
    /// The tip.
    pub tip: Balance,
}

impl From<PaymentError> for TxError {
    fn from(e: PaymentError) -> Self {
        match e {
            PaymentError::Stale => TxError::StaleNonce,
            PaymentError::Future | PaymentError::Storage => TxError::BadFormat,
            PaymentError::InsufficientBalance => TxError::CannotPay,
        }
    }
}

/// The weight fee plus `tip`.
fn total(p: &FeeParams, weight: Weight, tip: Balance) -> Result<(Balance, Balance), PaymentError> {
    let fee = p.fee(weight).ok_or(PaymentError::Storage)?;
    Ok((fee, fee.checked_add(tip).ok_or(PaymentError::Storage)?))
}

/// Pool check of a transaction by `signer` with `nonce`, `tip` and declared `weight`; returns its
/// priority, the tip (higher first). A nonce ahead of the signer's is fine: the pool holds the
/// transaction until the nonce is reached (§3.1 `ValidTx`).
pub fn validate(
    s: &mut impl Storage,
    p: &FeeParams,
    h: &impl FeeHandler,
    signer: &AccountId,
    nonce: u64,
    tip: Balance,
    weight: Weight,
) -> Result<Balance, PaymentError> {
    match system::check_nonce(s, signer, nonce) {
        Ok(()) | Err(system::NonceError::Future) => {}
        Err(e) => return Err(e.into()),
    }
    let (_, due) = total(p, weight, tip)?;
    if !h.can_pay(s, signer, due)? {
        return Err(PaymentError::InsufficientBalance);
    }
    Ok(tip)
}

/// The fee a transaction pays before dispatch: its weight's fee plus `tip` (the `"fee_estimate"`
/// query, §3.1).
pub fn fee_estimate(p: &FeeParams, weight: Weight, tip: Balance) -> Option<Balance> {
    p.fee(weight)?.checked_add(tip)
}

/// Before dispatch: bump `signer`'s nonce and take the fee of the declared `weight` and the `tip`.
/// A failure leaves state unchanged and the transaction out of the block.
pub fn pre_dispatch(
    s: &mut impl Storage,
    p: &FeeParams,
    h: &impl FeeHandler,
    signer: &AccountId,
    nonce: u64,
    tip: Balance,
    weight: Weight,
) -> Result<Charged, PaymentError> {
    system::check_nonce(s, signer, nonce)?;
    let (fee, due) = total(p, weight, tip)?;
    h.withdraw(s, signer, due)?;
    system::inc_nonce(s, signer, nonce)?;
    Ok(Charged { fee, tip })
}

/// After dispatch, whatever its result: charge the fee of the `actual` weight (at most what was
/// declared), refund the rest and pay it and the tip to the block's author (burned without one).
pub fn post_dispatch(
    s: &mut impl Storage,
    p: &FeeParams,
    h: &impl FeeHandler,
    signer: &AccountId,
    charged: Charged,
    actual: Weight,
    author: Option<&AccountId>,
) -> Result<(), PaymentError> {
    let used = p.fee(actual).ok_or(PaymentError::Storage)?.min(charged.fee);
    let paid = used.checked_add(charged.tip).ok_or(PaymentError::Storage)?;
    h.settle(s, signer, charged.fee - used, paid, author)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tog_runtime_core::memory::MemoryStorage;
    use tog_runtime_core::weight::BlockLimits;

    const A: AccountId = [1; 20];
    const AUTHOR: AccountId = [9; 20];
    const P: FeeParams = FeeParams::DEFAULT;

    /// 1 µs: 2.5 · 10⁹ atto-TOG.
    const W: Weight = Weight::from_parts(1_000_000, 0);
    const FEE: Balance = 2_500_000_000;

    #[test]
    fn a_full_block_costs_about_five_milli_tog_in_either_dimension() {
        let limits = BlockLimits::DEFAULT.max_block;
        let time = P.fee(Weight::from_parts(limits.ref_time, 0)).unwrap();
        let proof = P.fee(Weight::from_parts(0, limits.proof_size)).unwrap();
        assert_eq!(time, 3_750_000_000_000_000);
        assert_eq!(proof, 5_000_000_000_000_000);
        assert_eq!(P.fee(Weight::from_parts(2, 3)), Some(5_000 + 3_000_000_000));
        assert_eq!(fee_estimate(&P, W, 7), Some(FEE + 7));
    }

    #[test]
    fn charges_the_declared_weight_and_tip_and_refunds_the_unused_part() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, 10 * FEE).unwrap();

        assert_eq!(validate(&mut s, &P, &TogFees, &A, 0, 100, W), Ok(100));
        let c = pre_dispatch(&mut s, &P, &TogFees, &A, 0, 100, W).unwrap();
        assert_eq!(c, Charged { fee: FEE, tip: 100 });
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), 9 * FEE - 100);
        assert_eq!(system::nonce(&mut s, &A).unwrap(), 1);

        // It used 40%: that and the tip go to the author, the rest back.
        post_dispatch(&mut s, &P, &TogFees, &A, c, Weight::from_parts(400_000, 0), Some(&AUTHOR)).unwrap();
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), 9 * FEE + FEE * 6 / 10 - 100);
        assert_eq!(balances::free_balance(&mut s, &AUTHOR).unwrap(), FEE * 4 / 10 + 100);

        // Using more than declared still pays only what was declared; without an author it's burned.
        let before = balances::total_issuance(&mut s).unwrap();
        let c = pre_dispatch(&mut s, &P, &TogFees, &A, 1, 0, W).unwrap();
        post_dispatch(&mut s, &P, &TogFees, &A, c, W.saturating_mul(5), None).unwrap();
        assert_eq!(balances::total_issuance(&mut s).unwrap(), before - FEE);
    }

    #[test]
    fn refuses_a_used_nonce_or_an_empty_account_and_holds_a_future_one() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, FEE).unwrap();
        assert_eq!(pre_dispatch(&mut s, &P, &TogFees, &A, 1, 0, W), Err(PaymentError::Future));
        assert_eq!(validate(&mut s, &P, &TogFees, &A, 1, 0, W), Ok(0), "the pool holds it");
        assert_eq!(validate(&mut s, &P, &TogFees, &A, 0, 1, W), Err(PaymentError::InsufficientBalance));
        assert_eq!(pre_dispatch(&mut s, &P, &TogFees, &A, 0, 1, W), Err(PaymentError::InsufficientBalance));
        assert_eq!(system::nonce(&mut s, &A).unwrap(), 0, "a refused transaction doesn't use its nonce");

        pre_dispatch(&mut s, &P, &TogFees, &A, 0, 0, W).unwrap();
        assert_eq!(validate(&mut s, &P, &TogFees, &A, 0, 0, W), Err(PaymentError::Stale));
    }
}
