//! Retrieval payment channels (TOG-SPEC-0004 §6.2, §6.6): unidirectional from a payer to a
//! payee, opened and closed on the Hub, paid off-chain with vouchers whose `cumulative` only grows.
//! Service channels, the fee table and `settle` (TOG-SPEC-0011 §2, §3) generalize them to every
//! kind of service.

use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Amount, Domain, Hash32};

use crate::job::RetentionClass;
use crate::por::StorageWorkerId;
#[allow(unused_imports)]
use crate::prelude::*;
use crate::signing::SignatureError;
use crate::tx::Signature;

/// Channel id, assigned in open order and never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct ChannelId(pub u64);

/// `TxBody` variant 28 (user). Opens a channel from the signer (payer) to `holder`'s owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OpenChannelTx {
    /// The storage worker the channel pays for; it must have a registered record.
    pub holder: StorageWorkerId,
    /// More than 0; moved from the payer's free balance to reserved.
    pub deposit: Amount,
    /// The payer's next nonce.
    pub replay: crate::storage::ReplayGuard,
}

/// `TxBody` variant 29 (compute market). Closes a channel; signed by its payer or its payee.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CloseChannelTx {
    /// Channel.
    pub channel: ChannelId,
    /// Required from the payee; optional from the payer (`None` claims 0).
    pub voucher: Option<SignedVoucher>,
}

/// What the payer owes the payee so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Voucher {
    /// Channel.
    pub channel: ChannelId,
    /// Total owed to the payee so far.
    pub cumulative: Amount,
}

impl Voucher {
    /// The digest the payer signs on the Hub of replay domain `chain_id` (TOG-SPEC-0000 §13.2):
    /// `H("TOG/v1/voucher" ‖ borsh(chain_id) ‖ borsh(voucher))` (TOG-SPEC-0004 §6.6), so a voucher
    /// of one network doesn't verify on another.
    pub fn signing_hash(&self, chain_id: u64) -> Hash32 {
        let voucher = borsh::to_vec(self).expect("in-memory borsh cannot fail");
        tagged_hash(Domain::Voucher, &[&chain_id.to_le_bytes(), &voucher])
    }
}

/// A voucher signed by the channel's payer.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SignedVoucher {
    /// Voucher.
    pub voucher: Voucher,
    /// Payer's account signature over [`Voucher::signing_hash`].
    pub sig: Signature,
}

impl SignedVoucher {
    /// Signs `voucher` for the Hub of `chain_id` with the payer's Ed25519 key.
    pub fn sign_ed25519(voucher: Voucher, chain_id: u64, key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let sig = key.sign(&voucher.signing_hash(chain_id)).to_bytes();
        SignedVoucher { voucher, sig: Signature::Ed25519 { public_key: key.verifying_key().to_bytes(), sig } }
    }

    /// Verifies the signature for the Hub of `chain_id` and returns the signer's address; the Hub
    /// checks it is the payer. An EIP-712 signature covers a transaction digest, never a
    /// voucher's, so it is rejected.
    pub fn signer(&self, chain_id: u64) -> Result<Address, SignatureError> {
        if matches!(self.sig, Signature::Secp256k1Eip712(_)) {
            return Err(SignatureError::Invalid);
        }
        self.sig.verify(&self.voucher.signing_hash(chain_id))
    }
}

/// `storage.channels[ChannelId]` (TOG-SPEC-0002 §7.2), until settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Channel {
    /// Payer.
    pub payer: Address,
    /// Payee.
    pub payee: Address,
    /// Deposit, reserved from the payer.
    pub deposit: Amount,
    /// After a payer close: the claimed amount and the last height of its dispute period.
    pub closing: Option<(Amount, u64)>,
    /// The storage worker the channel pays for.
    pub holder: StorageWorkerId,
    /// The holder's `retrieval_price_per_gib` per `RetentionClass` (by Borsh index) at open.
    pub prices: [Amount; 3],
    /// Height of the block that opened it (informational).
    pub opened: u64,
}

impl Channel {
    /// The price of `bytes` of a payload in a deal of `class`: `⌈prices[class] × bytes / 2^30⌉`
    /// (TOG-SPEC-0004 §6.2 rule 1).
    pub fn price(&self, class: RetentionClass, bytes: u64) -> Amount {
        let per_gib = self.prices[class as usize];
        let n = per_gib.saturating_mul(u128::from(bytes));
        n.div_ceil(1 << 30)
    }
}

/// A router's key address (connectivity spec).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct RouterId(pub Address);

/// An exit node's key address (connectivity spec).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct ExitId(pub Address);

/// What a channel pays for (TOG-SPEC-0011 §2.1). Borsh variant index is stable; new kinds are
/// appended, never renumbered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub enum ServiceKind {
    /// 0: retrieval from one storage worker (TOG-SPEC-0004 §6.2). Prices: the holder's retrieval
    /// price per retention class.
    Retrieval {
        /// The storage worker the channel pays for.
        holder: StorageWorkerId,
    },
    /// 1: Wi-Fi bandwidth carried by a router through an exit node. Records, prices and the payee
    /// split are defined by the connectivity spec; until it is active, a channel of this kind
    /// can't be opened.
    Bandwidth {
        /// Router.
        router: RouterId,
        /// Exit node.
        exit: ExitId,
    },
}

impl ServiceKind {
    /// The fee-table row its settlements use: `class(Retrieval) = Retrieval`,
    /// `class(Bandwidth) = Bandwidth` (TOG-SPEC-0011 §2.4).
    pub fn fee_class(&self) -> FeeClass {
        match self {
            ServiceKind::Retrieval { .. } => FeeClass::Retrieval,
            ServiceKind::Bandwidth { .. } => FeeClass::Bandwidth,
        }
    }
}

/// The row of the fee table a payout uses (TOG-SPEC-0011 §3): one row per kind of service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum FeeClass {
    /// `F_exec` of a job (TOG-SPEC-0005 §3, §5).
    ComputeExec = 0,
    /// Slot fees and placement fees of a deal (TOG-SPEC-0004 §4.2, §11).
    StorageDeal = 1,
    /// [`ServiceKind::Retrieval`].
    Retrieval = 2,
    /// [`ServiceKind::Bandwidth`].
    Bandwidth = 3,
}

impl FeeClass {
    /// Every class, in Borsh index order.
    pub const ALL: [FeeClass; 4] =
        [FeeClass::ComputeExec, FeeClass::StorageDeal, FeeClass::Retrieval, FeeClass::Bandwidth];
}

/// The prices a channel charges, copied from the provider's record at open (TOG-SPEC-0011 §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ChannelPrices {
    /// Retrieval: atto-TOG per GiB, by `RetentionClass` Borsh index (as [`Channel::prices`]).
    PerClass([Amount; 3]),
    /// Bandwidth: atto-TOG per GiB, router and exit together.
    PerGib(Amount),
}

impl ChannelPrices {
    /// The price `OpenServiceChannelTx::max_price_per_gib` bounds: the largest class for
    /// `PerClass` (TOG-SPEC-0011 §2.2).
    pub fn max_per_gib(&self) -> Amount {
        match self {
            ChannelPrices::PerClass(p) => p.iter().copied().max().unwrap_or(0),
            ChannelPrices::PerGib(p) => *p,
        }
    }
}

/// Who is paid (TOG-SPEC-0011 §2.1). `second` takes its ppm of the providers' share; `first`
/// takes the rest (§3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Payees {
    /// First payee.
    pub first: Address,
    /// Second payee and its share in ppm, `1..=999_999` ([`Payees::is_valid`]).
    pub second: Option<(Address, u32)>,
}

impl Payees {
    /// One payee taking all of the providers' share.
    pub fn one(first: Address) -> Self {
        Payees { first, second: None }
    }

    /// Whether `second`'s share is in `1..=999_999` ppm.
    pub fn is_valid(&self) -> bool {
        self.second.map_or(true, |(_, ppm)| (1..PPM).contains(&ppm))
    }

    /// Whether `account` is one of the payees.
    pub fn contains(&self, account: &Address) -> bool {
        self.first == *account || self.second.is_some_and(|(a, _)| a == *account)
    }
}

/// `payments.channels[ChannelId]` (TOG-SPEC-0002 §7.2, TOG-SPEC-0011 §2.1); replaces
/// `storage.channels` at the next regenesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ServiceChannel {
    /// Whose deposit; refunds go here.
    pub payer: Address,
    /// Signs vouchers; the payer unless set at open.
    pub voucher_key: Address,
    /// What the channel pays for.
    pub service: ServiceKind,
    /// Who is paid; fixed at open.
    pub payees: Payees,
    /// Prices copied at open.
    pub prices: ChannelPrices,
    /// Deposit, reserved from the payer (plus top-ups).
    pub deposit: Amount,
    /// After a payer close: the claimed amount and the last height of its dispute period.
    pub closing: Option<(Amount, u64)>,
    /// Height of the block that opened it (informational).
    pub opened: u64,
}

impl ServiceChannel {
    /// The 0004 §6.6 [`Channel`] the retrieval protocol reads, for a `Retrieval` channel priced
    /// per class; `None` for any other. Its `payer` is the **voucher key**, the account whose
    /// signature a voucher needs (§2.3): the payer itself unless one was set at open.
    pub fn retrieval_view(&self) -> Option<Channel> {
        let (ServiceKind::Retrieval { holder }, ChannelPrices::PerClass(prices)) = (self.service, self.prices) else {
            return None;
        };
        Some(Channel {
            payer: self.voucher_key,
            payee: self.payees.first,
            deposit: self.deposit,
            closing: self.closing,
            holder,
            prices,
            opened: self.opened,
        })
    }
}

/// A retrieval channel as read from both places one can be: `storage.channels[id]` (a store from
/// before TOG-SPEC-0011) or `payments.channels[id]`. One id counter serves both, so at most one
/// holds `id`; read [`retrieval_channel_keys`] and pass the two values here.
pub fn retrieval_channel(legacy: Option<Channel>, service: Option<ServiceChannel>) -> Option<Channel> {
    legacy.or_else(|| service.and_then(|c| c.retrieval_view()))
}

/// The keys [`retrieval_channel`] reads for `id`: `storage.channels[id]`, then `payments.channels[id]`.
pub fn retrieval_channel_keys(id: &ChannelId) -> [[u8; 96]; 2] {
    [crate::state::items::channel(id), crate::state::items::service_channel(id)]
}

/// `TxBody` variant 72 (user). Opens a service channel; the signer is the payer
/// (TOG-SPEC-0011 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OpenServiceChannelTx {
    /// What the channel pays for.
    pub service: ServiceKind,
    /// More than 0; moved from the payer's free balance to reserved.
    pub deposit: Amount,
    /// `None`: the payer signs vouchers.
    pub voucher_key: Option<Address>,
    /// Fails if the price copied at open is higher ([`ChannelPrices::max_per_gib`]).
    pub max_price_per_gib: Amount,
    /// The payer's next nonce.
    pub replay: crate::storage::ReplayGuard,
}

impl From<OpenChannelTx> for OpenServiceChannelTx {
    /// `OpenChannel` (28) executes exactly as this (TOG-SPEC-0011 §2.2).
    fn from(t: OpenChannelTx) -> Self {
        OpenServiceChannelTx {
            service: ServiceKind::Retrieval { holder: t.holder },
            deposit: t.deposit,
            voucher_key: None,
            max_price_per_gib: Amount::MAX,
            replay: t.replay,
        }
    }
}

/// `TxBody` variant 73 (user). Adds to an open channel's deposit; any account may pay, refunds
/// still go to the payer (TOG-SPEC-0011 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TopUpChannelTx {
    /// Channel.
    pub channel: ChannelId,
    /// More than 0; moved from the signer's free balance to the channel's reserve.
    pub amount: Amount,
    /// The signer's next nonce.
    pub replay: crate::storage::ReplayGuard,
}

/// Most vouchers in one [`SettleChannelsTx`].
pub const MAX_SETTLE: usize = 64;

/// `TxBody` variant 75 (compute market). A payee settles up to [`MAX_SETTLE`] channels at once
/// with their highest vouchers (TOG-SPEC-0011 §2.4).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SettleChannelsTx {
    /// 1 to [`MAX_SETTLE`] vouchers, strictly ascending channel id ([`SettleChannelsTx::is_well_formed`]).
    pub vouchers: Vec<SignedVoucher>,
}

impl SettleChannelsTx {
    /// Whether it has 1 to [`MAX_SETTLE`] vouchers in strictly ascending channel id.
    pub fn is_well_formed(&self) -> bool {
        (1..=MAX_SETTLE).contains(&self.vouchers.len())
            && self.vouchers.windows(2).all(|w| w[0].voucher.channel < w[1].voucher.channel)
    }
}

/// Parts per million: the unit of the fee table.
pub const PPM: u32 = 1_000_000;

/// `payments.fee_splits[FeeClass]`: a genesis constant in v1 (TOG-SPEC-0011 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeSplit {
    /// Burned share, ppm.
    pub burn_ppm: u32,
    /// Treasury share, ppm.
    pub treasury_ppm: u32,
    /// Upper bound of an issuance-funded bonus for this class (§3.3); 0 = none.
    pub bonus_cap_ppm: u32,
}

/// The decided testnet genesis table, by [`FeeClass`] Borsh index (TOG-SPEC-0011 §3.1): providers /
/// burned / treasury of 90 / 7 / 3 (compute), 90 / 5 / 5 (storage), 95 / 3 / 2 (retrieval) and
/// 90 / 7 / 3 (bandwidth); no bonus.
pub const TESTNET_FEE_SPLITS: [FeeSplit; 4] = [
    FeeSplit { burn_ppm: 70_000, treasury_ppm: 30_000, bonus_cap_ppm: 0 },
    FeeSplit { burn_ppm: 50_000, treasury_ppm: 50_000, bonus_cap_ppm: 0 },
    FeeSplit { burn_ppm: 30_000, treasury_ppm: 20_000, bonus_cap_ppm: 0 },
    FeeSplit { burn_ppm: 70_000, treasury_ppm: 30_000, bonus_cap_ppm: 0 },
];

/// Why a fee table doesn't load (TOG-SPEC-0011 §3.2 "Bounds checked at genesis load").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeTableError {
    /// `burn_ppm + treasury_ppm` above 200 000.
    Take(FeeClass),
    /// `bonus_cap_ppm` above `burn_ppm`.
    Bonus(FeeClass),
    /// `ComputeExec`'s `burn_ppm + treasury_ppm` outside 5–15% (TOG-SPEC-0005 §10 `τ`).
    ComputeTake,
}

/// Checks a fee table, by [`FeeClass`] Borsh index, against the genesis bounds of TOG-SPEC-0011 §3.2.
pub fn check_fee_splits(splits: &[FeeSplit; 4]) -> Result<(), FeeTableError> {
    for (class, s) in FeeClass::ALL.into_iter().zip(splits) {
        let take = u64::from(s.burn_ppm) + u64::from(s.treasury_ppm);
        if take > 200_000 {
            return Err(FeeTableError::Take(class));
        }
        if s.bonus_cap_ppm > s.burn_ppm {
            return Err(FeeTableError::Bonus(class));
        }
        if class == FeeClass::ComputeExec && !(50_000..=150_000).contains(&take) {
            return Err(FeeTableError::ComputeTake);
        }
    }
    Ok(())
}

/// Where `settle(x, class, payees)` sends `x` (TOG-SPEC-0011 §3.2); the parts sum to `x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settlement {
    /// Credited to `payees.first`.
    pub to_first: Amount,
    /// Credited to `payees.second`'s account; 0 without one.
    pub to_second: Amount,
    /// Credited to the treasury.
    pub treasury: Amount,
    /// Burned.
    pub burn: Amount,
}

impl FeeSplit {
    /// Splits `x` exactly as `settle` does: `⌊x·burn⌋` burned and `⌊x·treasury⌋` to the treasury
    /// (ppm), the second payee `⌊providers·ppm⌋` of the rest, dust to the first payee. Rounding
    /// is exact; a split that passes [`check_fee_splits`] never overflows for any `x`.
    pub fn settle(&self, x: Amount, payees: &Payees) -> Settlement {
        let burn = mul_ppm(x, self.burn_ppm);
        let treasury = mul_ppm(x, self.treasury_ppm);
        let providers = x - burn - treasury;
        let to_second = payees.second.map_or(0, |(_, ppm)| mul_ppm(providers, ppm));
        Settlement { to_first: providers - to_second, to_second, treasury, burn }
    }
}

/// `⌊x · ppm / 10⁶⌋` without overflow for any `x`, for `ppm ≤ 10⁶`.
fn mul_ppm(x: Amount, ppm: u32) -> Amount {
    let (q, r) = (x / u128::from(PPM), x % u128::from(PPM));
    q * u128::from(ppm) + r * u128::from(ppm) / u128::from(PPM)
}

#[cfg(test)]
mod tests;
