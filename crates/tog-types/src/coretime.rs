//! Coretime in v1 (TOG-SPEC-0005 §6.3): bulk regions per period and prepaid on-demand candidates.
//!
//! ```text
//! period_length       = 28 · era_length; period p covers [p · period_length, (p + 1) · period_length)
//! adjust(price, sold) = max(1, ⌊price · clamp(10^6 + 2 · (u − 900 000), 700 000, 1 300 000) / 10^6⌋),
//!                       u = ⌊sold · 10^6 / bulk⌋
//! renewal(paid)       = min(next_price, ⌊paid · 105 / 100⌋)
//! open(h)             = next_price + ⌊next_price · (W − d) / W⌋, d = min(h − P_p − W, W), W = 7 · era_length
//! od_price'           = max(od_min_price, ⌊od_price · (7T + x) / (8T)⌋), T = max(1, ⌊on_demand_cores / 2⌋)
//! ```

use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{Address, Amount, ChainId, HubHeight};

/// Eras per coretime period.
pub const ERAS_PER_PERIOD: u64 = 28;
/// Eras of the renewal window `W`.
pub const RENEWAL_WINDOW_ERAS: u64 = 7;

/// `coretime.params` (TOG-SPEC-0002 §2.3), from genesis; Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoretimeParams {
    /// All cores.
    pub cores: u32,
    /// Cores for on-demand candidates; `1 ≤ on_demand_cores < cores`.
    pub on_demand_cores: u32,
    /// Price per region in periods 0 and 1.
    pub launch_price: Amount,
    /// Floor of the on-demand price per candidate.
    pub od_min_price: Amount,
}

impl CoretimeParams {
    /// `bulk = cores − on_demand_cores`: regions sold per period.
    pub fn bulk(&self) -> u32 {
        self.cores.saturating_sub(self.on_demand_cores)
    }

    /// The genesis checks: `1 ≤ on_demand_cores < cores`, both prices positive.
    pub fn is_well_formed(&self) -> bool {
        self.on_demand_cores >= 1 && self.on_demand_cores < self.cores && self.launch_price > 0 && self.od_min_price > 0
    }
}

/// `coretime.status`; Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoretimeStatus {
    /// Current period `p`.
    pub period: u64,
    /// Price of a region of `p`.
    pub price: Amount,
    /// Price of a region of `p + 1`.
    pub next_price: Amount,
    /// On-demand price per candidate, at the start of the block.
    pub od_price: Amount,
}

impl CoretimeStatus {
    /// At genesis: `(0, launch_price, launch_price, od_min_price)`.
    pub fn genesis(p: &CoretimeParams) -> Self {
        Self { period: 0, price: p.launch_price, next_price: p.launch_price, od_price: p.od_min_price }
    }
}

/// `coretime.regions[(period, chain)]`: a bulk region; Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Region {
    /// Who paid.
    pub payer: Address,
    /// What was paid.
    pub paid: Amount,
}

/// Blocks per period.
pub fn period_length(era_length: u64) -> u64 {
    ERAS_PER_PERIOD * era_length
}

/// The period of height `h`.
pub fn period_of(h: HubHeight, era_length: u64) -> u64 {
    h / period_length(era_length).max(1)
}

/// `adjust(price, sold)` with `bulk` regions per period.
pub fn adjust(price: Amount, sold: u32, bulk: u32) -> Amount {
    let u = i128::from(sold) * 1_000_000 / i128::from(bulk.max(1));
    let factor = (1_000_000 + 2 * (u - 900_000)).clamp(700_000, 1_300_000) as Amount;
    (price.saturating_mul(factor) / 1_000_000).max(1)
}

/// `renewal(c)` for a chain that paid `paid` for its region of `p`.
pub fn renewal(next_price: Amount, paid: Amount) -> Amount {
    next_price.min(paid.saturating_mul(105) / 100)
}

/// `open(h)`: the open-sale price of a region of `p + 1` at `h ≥ P_p + W`.
pub fn open_price(next_price: Amount, h: HubHeight, period_start: HubHeight, era_length: u64) -> Amount {
    let w = RENEWAL_WINDOW_ERAS * era_length;
    if w == 0 {
        return next_price;
    }
    let d = h.saturating_sub(period_start).saturating_sub(w).min(w);
    next_price.saturating_add(next_price.saturating_mul(Amount::from(w - d)) / Amount::from(w))
}

/// The on-demand price of the next block after `inclusions` on-demand inclusions in this one.
pub fn next_od_price(od_price: Amount, inclusions: u32, p: &CoretimeParams) -> Amount {
    let t = Amount::from((p.on_demand_cores / 2).max(1));
    let next = od_price.saturating_mul(7 * t + Amount::from(inclusions)) / (8 * t);
    next.max(p.od_min_price)
}

/// The revenue split of a coretime payment `x`: `(era_fees, treasury, burned)`.
pub fn split(x: Amount) -> (Amount, Amount, Amount) {
    let fees = x * 3 / 10;
    let treasury = x * 2 / 10;
    (fees, treasury, x - fees - treasury)
}

/// `TxBody` variant 47, user lane: buys a bulk region for `chain` (TOG-SPEC-0005 §6.3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PurchaseRegionTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; the payer.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// Chain the region is for.
    pub chain: ChainId,
    /// The current period or the next.
    pub period: u64,
    /// Most the signer pays.
    pub max_price: Amount,
}

/// `TxBody` variant 48, user lane: prepays on-demand coretime for `chain`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FundOnDemandTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer; the payer.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// Chain funded.
    pub chain: ChainId,
    /// More than 0.
    pub amount: Amount,
}

#[cfg(test)]
mod tests;
