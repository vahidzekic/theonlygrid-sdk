//! Staking transactions, validator records and DKG encryption keys (TOG-SPEC-0002 §2.4, TOG-SPEC-0009 §2.2).
//!
//! A validator is identified by its **stash** address, the account that signed `RegisterValidator`.
//! Every staking transaction is a user-lane `TxBody` (30–36) and carries `chain_id`, the signer's
//! address and its next nonce, in that order, before its own fields. The Hub checks that `signer`
//! is the address of the transaction's signature.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use bls12_381::{G1Affine, G1Projective, Scalar};
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{Address, Amount, Domain};

/// `min_self_bond`: 50 000 $TOG in atto-TOG (governance, §2.1).
pub const MIN_SELF_BOND: Amount = 50_000 * 10u128.pow(18);
/// Highest commission, in basis points (20%).
pub const MAX_COMMISSION_BPS: u16 = 2_000;
/// Eras an unbonded amount stays locked (28 days at 24 h eras).
pub const UNBONDING_ERAS: u64 = 28;
/// Most validators one account nominates.
pub const MAX_NOMINATIONS: usize = 16;

/// TxBody 30: register the signer as a validator with its keys and self-bond.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegisterValidatorTx {
    /// Replay domain, TOG-SPEC-0000 §13.2.
    pub chain_id: u64,
    /// The stash: the signer's address.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// Ed25519 consensus key.
    pub consensus_key: [u8; 32],
    /// BLS12-381 G1 key (min-pk).
    pub bls_key: [u8; 48],
    /// BLS proof of possession of `bls_key` (G2, DST `BLS_POP_…`, TOG-SPEC-0002 §3.1).
    pub bls_pop: [u8; 96],
    /// Ed25519 libp2p key of the validator's Hub-plane node; not `consensus_key`.
    pub network_key: [u8; 32],
    /// DKG encryption key for era `current + 2`.
    pub dkg_key: DkgKey,
    /// Commission, at most [`MAX_COMMISSION_BPS`].
    pub commission_bps: u16,
    /// At least [`MIN_SELF_BOND`]; moved from free balance to the stash's ledger.
    pub self_bond: Amount,
}

/// TxBody 31: free balance → ledger `active`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BondTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// More than 0.
    pub amount: Amount,
}

/// TxBody 32: ledger `active` → `unlocking` until era `current + 28`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UnbondTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// `0 < amount ≤ active`.
    pub amount: Amount,
}

/// TxBody 33: unlocked entries → free balance.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WithdrawTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
}

/// TxBody 34: replaces the signer's nominations.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NominateTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// 1–16 validator stashes, ascending, no duplicates.
    pub targets: Vec<Address>,
}

impl NominateTx {
    /// The stateless rule: 1–[`MAX_NOMINATIONS`] targets, strictly ascending.
    pub fn well_formed(&self) -> bool {
        (1..=MAX_NOMINATIONS).contains(&self.targets.len()) && self.targets.windows(2).all(|w| w[0] < w[1])
    }
}

/// TxBody 35: commission from the next era boundary.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SetCommissionTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer, a validator stash.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// At most [`MAX_COMMISSION_BPS`].
    pub commission_bps: u16,
}

/// TxBody 36: the DKG encryption key for era `current + 1` or `current + 2` (TOG-SPEC-0009 §2.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SetDkgKeyTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Signer, a validator stash.
    pub signer: Address,
    /// The signer's next nonce.
    pub nonce: u64,
    /// The key.
    pub key: DkgKey,
}

/// `staking.validators[stash]` (TOG-SPEC-0002 §7.2); never removed in v1.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ValidatorRecord {
    /// Ed25519 consensus key.
    pub consensus_key: [u8; 32],
    /// BLS12-381 G1 key.
    pub bls_key: [u8; 48],
    /// Ed25519 libp2p key.
    pub network_key: [u8; 32],
    /// Commission now.
    pub commission_bps: u16,
    /// Commission from the next era boundary, set by `SetCommission`.
    pub next_commission: Option<u16>,
    /// Hub height of the `RegisterValidator`.
    pub registered: u64,
}

/// One elected validator in `staking.elected[era]` (TOG-SPEC-0002 §2.1 "Election (exact)").
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Exposure {
    /// The validator's stash.
    pub stash: Address,
    /// Sum of `backing`.
    pub total: Amount,
    /// Who backs it and with how much, ascending by address (the stash itself included).
    pub backing: Vec<(Address, Amount)>,
}

/// `staking.ledgers[account]`: bonded stake and its unbonding chunks.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Ledger {
    /// Bonded stake.
    pub active: Amount,
    /// `(amount, era it unlocks)`, ascending by era.
    pub unlocking: Vec<(Amount, u64)>,
}

impl Ledger {
    /// The ledger after `Withdraw` in era `current` and the amount freed; `None` if nothing unlocks.
    pub fn withdraw(&self, current: u64) -> Option<(Ledger, Amount)> {
        let (free, locked): (Vec<_>, Vec<_>) = self.unlocking.iter().partition(|(_, era)| *era <= current);
        if free.is_empty() {
            return None;
        }
        let amount = free.iter().map(|(a, _)| a).sum();
        Some((Ledger { active: self.active, unlocking: locked }, amount))
    }

    /// True when the ledger holds nothing and is removed.
    pub fn is_empty(&self) -> bool {
        self.active == 0 && self.unlocking.is_empty()
    }
}

/// A DKG encryption key `pk = x · g1` for the dealings to era `era` (TOG-SPEC-0009 §2.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DkgKey {
    /// Era whose dealings it receives.
    pub era: u64,
    /// `x · g1`, compressed.
    pub pk: [u8; 48],
    /// Schnorr proof of possession of `x`.
    pub pop: SchnorrPop,
}

/// Schnorr proof of possession: `a = k · g1`, `z = k + c · x`; valid iff `z · g1 = a + c · pk`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SchnorrPop {
    /// `k · g1`, compressed.
    pub a: [u8; 48],
    /// `z`, 32 bytes big-endian, `< r`.
    pub z: [u8; 32],
}

impl DkgKey {
    /// A key for `era` with its proof, from the secret `x` and the nonce `k` (fresh, never reused).
    pub fn prove(chain_id: u64, stash: &Address, era: u64, x: &Scalar, k: &Scalar) -> Self {
        let pk = G1Affine::from(G1Affine::generator() * x).to_compressed();
        let a = G1Affine::from(G1Affine::generator() * k).to_compressed();
        let c = pop_challenge(chain_id, stash, era, &pk, &a);
        DkgKey { era, pk, pop: SchnorrPop { a, z: scalar_to_be(&(k + c * x)) } }
    }

    /// Checks the proof of possession for `stash` on `chain_id`. Rejects non-canonical encodings
    /// and the identity as `pk` or `a`.
    pub fn verify(&self, chain_id: u64, stash: &Address) -> bool {
        let (Some(pk), Some(a), Some(z)) = (g1_nonzero(&self.pk), g1_nonzero(&self.pop.a), scalar_from_be(&self.pop.z))
        else {
            return false;
        };
        let c = pop_challenge(chain_id, stash, self.era, &self.pk, &self.pop.a);
        G1Projective::generator() * z == G1Projective::from(a) + G1Projective::from(pk) * c
    }
}

/// `c = Hs_r("TOG/v1/dkg-pop" ‖ borsh((chain_id, stash, era, pk, a)))`.
fn pop_challenge(chain_id: u64, stash: &Address, era: u64, pk: &[u8; 48], a: &[u8; 48]) -> Scalar {
    hs_r(Domain::DkgPop, &borsh::to_vec(&(chain_id, stash, era, pk, a)).expect("in-memory borsh cannot fail"))
}

/// `Hs_r`: 64 bytes of the BLAKE3 XOF under `domain`, read as a big-endian integer, mod `r`
/// (TOG-SPEC-0009 §2.2).
pub fn hs_r(domain: Domain, x: &[u8]) -> Scalar {
    let mut h = blake3::Hasher::new_derive_key(domain.tag());
    h.update(x);
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    wide.reverse();
    Scalar::from_bytes_wide(&wide)
}

/// A canonical scalar from 32 big-endian bytes.
pub fn scalar_from_be(b: &[u8; 32]) -> Option<Scalar> {
    let mut le = *b;
    le.reverse();
    Option::from(Scalar::from_bytes(&le))
}

/// A scalar as 32 big-endian bytes.
pub fn scalar_to_be(s: &Scalar) -> [u8; 32] {
    let mut b = s.to_bytes();
    b.reverse();
    b
}

/// A canonical, non-identity G1 point.
fn g1_nonzero(b: &[u8; 48]) -> Option<G1Affine> {
    Option::<G1Affine>::from(G1Affine::from_compressed(b)).filter(|p| !bool::from(p.is_identity()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STASH: Address = [7; 20];

    #[test]
    fn a_dkg_key_proves_possession_for_its_stash_era_and_chain() {
        let (x, k) = (Scalar::from(1234u64), Scalar::from(98765u64));
        let key = DkgKey::prove(1, &STASH, 9, &x, &k);
        assert!(key.verify(1, &STASH));
        assert!(!key.verify(2, &STASH));
        assert!(!key.verify(1, &[8; 20]));
        assert!(!DkgKey { era: 10, ..key.clone() }.verify(1, &STASH));
        let other = DkgKey::prove(1, &STASH, 9, &Scalar::from(5u64), &k);
        assert!(!DkgKey { pk: other.pk, ..key.clone() }.verify(1, &STASH));
        // `z ≥ r` is not canonical.
        assert!(!DkgKey { pop: SchnorrPop { z: [0xff; 32], ..key.pop.clone() }, ..key.clone() }.verify(1, &STASH));
        // The identity is no key.
        let mut zero = key.clone();
        zero.pk = G1Affine::identity().to_compressed();
        assert!(!zero.verify(1, &STASH));
    }

    #[test]
    fn scalars_are_big_endian() {
        assert_eq!(scalar_to_be(&Scalar::from(1u64))[31], 1);
        assert_eq!(scalar_from_be(&scalar_to_be(&Scalar::from(77u64))), Some(Scalar::from(77u64)));
    }

    #[test]
    fn nominations_are_1_to_16_ascending() {
        let n = |targets: Vec<Address>| NominateTx { chain_id: 1, signer: STASH, nonce: 0, targets }.well_formed();
        assert!(n(vec![[1; 20], [2; 20]]));
        assert!(!n(vec![]));
        assert!(!n(vec![[2; 20], [1; 20]]));
        assert!(!n(vec![[1; 20], [1; 20]]));
        assert!(n((0..16u8).map(|i| [i; 20]).collect()));
        assert!(!n((0..17u8).map(|i| [i; 20]).collect()));
    }

    #[test]
    fn withdraw_frees_unlocked_entries() {
        let l = Ledger { active: 5, unlocking: vec![(10, 3), (20, 4), (40, 9)] };
        assert_eq!(l.withdraw(2), None);
        assert_eq!(l.withdraw(4), Some((Ledger { active: 5, unlocking: vec![(40, 9)] }, 30)));
        let (rest, all) = Ledger { active: 0, ..l }.withdraw(9).unwrap();
        assert_eq!((rest.is_empty(), all), (true, 70));
    }
}
