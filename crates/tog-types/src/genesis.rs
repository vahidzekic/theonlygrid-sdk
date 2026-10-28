//! The Hub genesis file (TOG-SPEC-0002 §2.3 "Genesis (exact)").
//!
//! The file is `borsh(Genesis)`; its hash `H("TOG/v1/genesis" ‖ file bytes)` is what nodes and
//! light clients pin. The Hub builds the height-0 state from it; every node reads `network_id`,
//! the era grid, the genesis time and the era-0 validator set from it.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Amount, ChainId, Domain, Hash32};

use crate::calibration::KernelSet;
use crate::channel::{check_fee_splits, FeeSplit, FeeTableError};
use crate::eligibility::{GpuModel, ToolchainProfile, WorkerSetRules};
use crate::enclave::{EnclavePolicy, Reference, TeeVendor};
use crate::job::ToolchainProfileId;
use crate::metering::WuWeights;
use crate::reservation::ReservationParams;
use crate::sortition::ComputeParams;
use crate::staking::{DkgKey, MAX_COMMISSION_BPS};
use crate::storage::{StorageParams, StoragePrices};

/// `MaxValidators` (TOG-SPEC-0002 §3.1).
pub const MAX_VALIDATORS: usize = 1024;

/// `tee_collateral.revoked_serials` value: `(issuer key hash, serial)` pairs, strictly ascending.
pub type RevokedSerials = Vec<(Hash32, Vec<u8>)>;

/// The genesis file's content, Borsh in field order.
///
/// The last fields are a canonical tail: `backing_rules`, `reservation_params`, `fee_splits`,
/// `compute_limits` and `fast_on_hdd` are written only up to the last one that isn't its default
/// (`Legacy`, `None`, `None`, `None`, `false`), so a file from before a field decodes with its
/// default and encodes back to the same bytes and hash. Before the last written one,
/// `backing_rules` is the byte `1` or `2`, the options are Borsh options and `fast_on_hdd` is a
/// Borsh bool; the last written one is never its default. A file therefore ends with nothing, `2`,
/// `1|2 ‖ 1 ‖ params`, `1|2 ‖ 0|1 ‖ … ‖ 1 ‖ splits`, `1|2 ‖ 0|1 ‖ … ‖ 0|1 ‖ … ‖ 1 ‖ limits`, or
/// `1|2 ‖ 0|1 ‖ … ‖ 0|1 ‖ … ‖ 0|1 ‖ … ‖ 1`. "Nothing means the
/// default" holds only because [`Genesis`] is a top-level file: never nest it in another Borsh type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    /// `chain_id = network_id << 32` (TOG-SPEC-0000 §13.2).
    pub network_id: u32,
    /// `BftTime` of header 0, ms.
    pub time: u64,
    /// Blocks per era; positive and a multiple of 4 (TOG-SPEC-0008 §3.2).
    pub era_length: u64,
    /// Blocks per session; positive, divides `era_length`, at least two per era.
    pub session_length: u64,
    /// `staking.validator_count`: seats per election (§2.1), `validators.len() ..= MaxValidators`.
    pub validator_count: u32,
    /// The era-0 set, in election order (= `ValidatorIndex`).
    pub validators: Vec<GenesisValidator>,
    /// Free balances, strictly ascending by address.
    pub accounts: Vec<(Address, Amount)>,
    /// `balances.treasury`.
    pub treasury: Amount,
    /// `compute_market.p_ref`.
    pub p_ref: Amount,
    /// `compute_market.wu_weights`.
    pub wu_weights: WuWeights,
    /// `compute_market.params`.
    pub compute_params: ComputeParams,
    /// `hardware_registry.kernel_sets`, strictly ascending by root.
    pub kernel_sets: Vec<(Hash32, KernelSet)>,
    /// `hardware_registry.current_kernel_set`; one of `kernel_sets`.
    pub current_kernel_set: Hash32,
    /// `hardware_registry.gpu_models`, strictly ascending by PCI device id.
    pub gpu_models: Vec<(u16, GpuModel)>,
    /// `compute_market.toolchains`, strictly ascending by id.
    pub toolchains: Vec<(ToolchainProfileId, ToolchainProfile)>,
    /// `tee_collateral.roots`: DER root certificates per vendor, strictly ascending by vendor, each
    /// list strictly ascending by bytes (TOG-SPEC-0010 §2.4).
    pub tee_roots: Vec<(TeeVendor, Vec<Vec<u8>>)>,
    /// `tee_collateral.gpu_references`, strictly ascending by `(driver_version, vbios_version)`,
    /// each well-formed (TOG-SPEC-0010 §2.4).
    pub gpu_references: Vec<Reference>,
    /// `tee_collateral.revoked_serials`, strictly ascending by vendor, each list strictly ascending.
    pub tee_revoked_serials: Vec<(TeeVendor, RevokedSerials)>,
    /// `hardware_registry.min_tdx_qe_svn`: the least TDX QE `ISVSVN` (TOG-SPEC-0010 §2.2 rule 2).
    pub min_tdx_qe_svn: u16,
    /// `hardware_registry.enclave_policies`, strictly ascending by `EnclavePolicyId`, each
    /// well-formed (TOG-SPEC-0010 §3).
    pub enclave_policies: Vec<EnclavePolicy>,
    /// `appchains.worker_set_rules`, strictly ascending by `ChainId`; each `required_toolchains`
    /// entry in `toolchains` and `hw_filter.cc` with `min ≤ max` (TOG-SPEC-0000 §5.2). The Hub's own
    /// set, `ChainId(0)`, gets its rules only here.
    pub worker_set_rules: Vec<(ChainId, WorkerSetRules)>,
    /// `storage.params` (TOG-SPEC-0004 §3.2, §6.6); every value positive.
    pub storage_params: StorageParams,
    /// Era-0 `storage.prices`, indexed by `RetentionClass` (0 Hot, 1 ChallengeWindow, 2 LongTerm);
    /// every price positive (TOG-SPEC-0004 §4.2).
    pub storage_prices: [StoragePrices; 3],
    /// `coretime.params` (TOG-SPEC-0005 §6.3): `1 ≤ on_demand_cores < cores`, prices positive.
    pub coretime: crate::coretime::CoretimeParams,
    /// `appchains.backing_rules` (TOG-SPEC-0002 §4.4 "Backing rules"). First of the tail: absent
    /// in a file from before the field, which decodes as [`BackingRules::Legacy`].
    pub backing_rules: BackingRules,
    /// `compute_market.reservation_params` (TOG-SPEC-0015 §7, §9 Q6); `None`: the reservation
    /// market is off. Valid when present ([`ReservationParams::is_valid`]).
    pub reservation_params: Option<ReservationParams>,
    /// `payments.fee_splits` by [`FeeClass`](crate::channel::FeeClass) Borsh index
    /// (TOG-SPEC-0011 §3.1); within the bounds of §3.2 when present
    /// ([`check_fee_splits`](crate::channel::check_fee_splits)). `None` in a genesis from before
    /// TOG-SPEC-0011.
    pub fee_splits: Option<[FeeSplit; 4]>,
    /// What compute the chain admits (TOG-SPEC-0002 §2.3 "Compute limits"); `None`: no limits.
    /// Fixed for the chain's life and read from the file, never a state item.
    pub compute_limits: Option<ComputeLimits>,
    /// `Hot` and `ChallengeWindow` slots may go on a `Hdd` tier when no `Nvme` tier fits
    /// (TOG-SPEC-0012 §1.3 "Fast classes on Hdd"); testnets only. Read from the file, never a
    /// state item.
    pub fast_on_hdd: bool,
}

/// `Genesis.compute_limits` (TOG-SPEC-0002 §2.3 "Compute limits (exact)"): the highest isolation
/// tier a worker may offer or a job may ask for, and whether GPUs are admitted at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ComputeLimits {
    /// Highest tier a worker may offer, a job or a reservation may ask for.
    pub max_isolation: crate::job::IsolationTier,
    /// False: no GPU workers, jobs or reservations.
    pub gpus: bool,
}

impl ComputeLimits {
    /// Whether these limit anything and are coherent: `T3Confidential` needs GPUs, and
    /// `T3Confidential` with GPUs is no limit (it is `None`).
    pub fn is_valid(&self) -> bool {
        self.max_isolation < crate::job::IsolationTier::T3Confidential
    }

    /// Whether a worker offering `tiers` on `hw` may register or keep them.
    pub fn admits_worker(&self, tiers: &[crate::job::IsolationTier], hw: &crate::worker::HwSignature) -> bool {
        tiers.iter().all(|t| *t <= self.max_isolation) && (self.gpus || hw.gpus.is_empty())
    }

    /// Whether a job or reservation asking for `tier`, with `gpu` its GPU request, is admitted.
    pub fn admits(&self, tier: crate::job::IsolationTier, gpu: bool) -> bool {
        tier <= self.max_isolation && (self.gpus || !gpu)
    }
}

impl BorshSerialize for Genesis {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        self.network_id.serialize(w)?;
        self.time.serialize(w)?;
        self.era_length.serialize(w)?;
        self.session_length.serialize(w)?;
        self.validator_count.serialize(w)?;
        self.validators.serialize(w)?;
        self.accounts.serialize(w)?;
        self.treasury.serialize(w)?;
        self.p_ref.serialize(w)?;
        self.wu_weights.serialize(w)?;
        self.compute_params.serialize(w)?;
        self.kernel_sets.serialize(w)?;
        self.current_kernel_set.serialize(w)?;
        self.gpu_models.serialize(w)?;
        self.toolchains.serialize(w)?;
        self.tee_roots.serialize(w)?;
        self.gpu_references.serialize(w)?;
        self.tee_revoked_serials.serialize(w)?;
        self.min_tdx_qe_svn.serialize(w)?;
        self.enclave_policies.serialize(w)?;
        self.worker_set_rules.serialize(w)?;
        self.storage_params.serialize(w)?;
        self.storage_prices.serialize(w)?;
        self.coretime.serialize(w)?;
        // The tail, up to its last field that isn't the default.
        let written = if self.fast_on_hdd {
            5
        } else if self.compute_limits.is_some() {
            4
        } else if self.fee_splits.is_some() {
            3
        } else if self.reservation_params.is_some() {
            2
        } else {
            usize::from(self.backing_rules == BackingRules::Groups)
        };
        if written >= 1 {
            w.write_all(&[self.backing_rules.value()])?;
        }
        if written >= 2 {
            self.reservation_params.serialize(w)?;
        }
        if written >= 3 {
            self.fee_splits.serialize(w)?;
        }
        if written >= 4 {
            self.compute_limits.serialize(w)?;
        }
        if written >= 5 {
            self.fast_on_hdd.serialize(w)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for Genesis {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let network_id = BorshDeserialize::deserialize_reader(r)?;
        let time = BorshDeserialize::deserialize_reader(r)?;
        let era_length = BorshDeserialize::deserialize_reader(r)?;
        let session_length = BorshDeserialize::deserialize_reader(r)?;
        let validator_count = BorshDeserialize::deserialize_reader(r)?;
        let validators = BorshDeserialize::deserialize_reader(r)?;
        let accounts = BorshDeserialize::deserialize_reader(r)?;
        let treasury = BorshDeserialize::deserialize_reader(r)?;
        let p_ref = BorshDeserialize::deserialize_reader(r)?;
        let wu_weights = BorshDeserialize::deserialize_reader(r)?;
        let compute_params = BorshDeserialize::deserialize_reader(r)?;
        let kernel_sets = BorshDeserialize::deserialize_reader(r)?;
        let current_kernel_set = BorshDeserialize::deserialize_reader(r)?;
        let gpu_models = BorshDeserialize::deserialize_reader(r)?;
        let toolchains = BorshDeserialize::deserialize_reader(r)?;
        let tee_roots = BorshDeserialize::deserialize_reader(r)?;
        let gpu_references = BorshDeserialize::deserialize_reader(r)?;
        let tee_revoked_serials = BorshDeserialize::deserialize_reader(r)?;
        let min_tdx_qe_svn = BorshDeserialize::deserialize_reader(r)?;
        let enclave_policies = BorshDeserialize::deserialize_reader(r)?;
        let worker_set_rules = BorshDeserialize::deserialize_reader(r)?;
        let storage_params = BorshDeserialize::deserialize_reader(r)?;
        let storage_prices = BorshDeserialize::deserialize_reader(r)?;
        let coretime = BorshDeserialize::deserialize_reader(r)?;
        let bad = |what| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, what);
        let mut g = Genesis {
            network_id,
            time,
            era_length,
            session_length,
            validator_count,
            validators,
            accounts,
            treasury,
            p_ref,
            wu_weights,
            compute_params,
            kernel_sets,
            current_kernel_set,
            gpu_models,
            toolchains,
            tee_roots,
            gpu_references,
            tee_revoked_serials,
            min_tdx_qe_svn,
            enclave_policies,
            worker_set_rules,
            storage_params,
            storage_prices,
            coretime,
            backing_rules: BackingRules::Legacy,
            reservation_params: None,
            fee_splits: None,
            compute_limits: None,
            fast_on_hdd: false,
        };
        // Each tail field is absent at the end of the file; a present one opens with a byte.
        let mut last_is_default = false;
        if let Some(b) = next_byte(r)? {
            g.backing_rules = match b {
                crate::appchain::BACKING_RULES_LEGACY => BackingRules::Legacy,
                crate::appchain::BACKING_RULES_GROUPS => BackingRules::Groups,
                _ => return Err(bad("backing_rules is 1 or 2")),
            };
            last_is_default = g.backing_rules == BackingRules::Legacy;
            if let Some(tag) = next_byte(r)? {
                g.reservation_params = option_after(tag, r)?;
                last_is_default = g.reservation_params.is_none();
                if let Some(tag) = next_byte(r)? {
                    g.fee_splits = option_after(tag, r)?;
                    last_is_default = g.fee_splits.is_none();
                    if let Some(tag) = next_byte(r)? {
                        g.compute_limits = option_after(tag, r)?;
                        last_is_default = g.compute_limits.is_none();
                        if let Some(b) = next_byte(r)? {
                            g.fast_on_hdd = match b {
                                0 => false,
                                1 => true,
                                _ => return Err(bad("fast_on_hdd is 0 or 1")),
                            };
                            last_is_default = !g.fast_on_hdd;
                        }
                    }
                }
            }
        }
        if last_is_default {
            return Err(bad("the genesis tail ends with a default"));
        }
        Ok(g)
    }
}

/// The next byte, or `None` at the end of the file.
fn next_byte<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Option<u8>> {
    let mut byte = [0u8; 1];
    Ok((r.read(&mut byte)? == 1).then_some(byte[0]))
}

/// A Borsh `Option<T>` whose tag byte `tag` was already read.
fn option_after<T: BorshDeserialize, R: borsh::io::Read>(tag: u8, r: &mut R) -> borsh::io::Result<Option<T>> {
    match tag {
        0 => Ok(None),
        1 => T::deserialize_reader(r).map(Some),
        _ => Err(borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, "an option tag is 0 or 1")),
    }
}

/// `Genesis.backing_rules`: `1` (legacy per-chain draw) or `2` (groups, rotation, reserves). The
/// file encodes it as the first field of its tail ([`Genesis`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackingRules {
    /// `1`: a chain's group is the legacy draw, with no reserves.
    #[default]
    Legacy,
    /// `2`: disjoint groups, rotation every `GROUP_ROTATION` blocks and reserves.
    Groups,
}

impl BackingRules {
    /// The `appchains.backing_rules` value.
    pub fn value(self) -> u8 {
        match self {
            BackingRules::Legacy => crate::appchain::BACKING_RULES_LEGACY,
            BackingRules::Groups => crate::appchain::BACKING_RULES_GROUPS,
        }
    }
}

/// A genesis validator: `RegisterValidator` (TOG-SPEC-0002 §2.4) without the nonce.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GenesisValidator {
    /// Stash.
    pub stash: Address,
    /// Ed25519 consensus key.
    pub consensus_key: [u8; 32],
    /// BLS12-381 G1 key.
    pub bls_key: [u8; 48],
    /// Proof of possession of `bls_key`; checked by the Hub (TOG-SPEC-0002 §3.1).
    pub bls_pop: [u8; 96],
    /// Ed25519 libp2p key.
    pub network_key: [u8; 32],
    /// DKG key for era 1.
    pub dkg_key: DkgKey,
    /// Commission.
    pub commission_bps: u16,
    /// Self-bond: the stash's ledger `active`, on top of `accounts`.
    pub self_bond: Amount,
}

/// Why a genesis is refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum GenesisError {
    /// The file is not exactly `borsh(Genesis)`.
    #[error("not a borsh Genesis")]
    Decode,
    /// `era_length` is 0 or not a multiple of 4.
    #[error("era_length must be positive and a multiple of 4")]
    EraLength,
    /// `session_length` is 0, doesn't divide `era_length`, or leaves fewer than two sessions per era.
    #[error("session_length must be positive, divide era_length and fit twice in an era")]
    SessionLength,
    /// `backing_rules` is 2 and `GROUP_ROTATION` doesn't divide `session_length`.
    #[error("backing rule 2 needs session_length to be a multiple of {}", crate::appchain::GROUP_ROTATION)]
    GroupRotation,
    /// No validator, or not `validators.len() ≤ validator_count ≤` [`MAX_VALIDATORS`].
    #[error("validator count outside 1..=validator_count, or validator_count above {MAX_VALIDATORS}")]
    ValidatorCount,
    /// A stash or key repeats, or a network key equals its consensus key.
    #[error("validator {0}: duplicate stash or key")]
    DuplicateKey(usize),
    /// The DKG key is not for era 1 or its proof of possession fails.
    #[error("validator {0}: bad DKG key")]
    DkgKey(usize),
    /// Commission above the cap.
    #[error("validator {0}: commission above {MAX_COMMISSION_BPS} bps")]
    Commission(usize),
    /// Self-bond below `min_self_bond`.
    #[error("validator {0}: self-bond below min_self_bond")]
    SelfBond(usize),
    /// A list is not strictly ascending.
    #[error("{0} not strictly ascending")]
    NotCanonical(&'static str),
    /// An account with a zero balance.
    #[error("zero balance")]
    ZeroBalance,
    /// `Σ accounts + treasury + Σ self_bond` overflows `u128`.
    #[error("total supply overflows u128")]
    Supply,
    /// A kernel set is malformed, or `current_kernel_set` is not one of them.
    #[error("kernel sets")]
    KernelSet,
    /// A storage parameter or era-0 storage price is 0.
    #[error("storage parameters and prices must be positive")]
    Storage,
    /// `coretime` is not well formed.
    #[error("coretime needs 1 <= on_demand_cores < cores and positive prices")]
    Coretime,
    /// A GPU reference is malformed.
    #[error("gpu reference {0} is malformed")]
    GpuReference(usize),
    /// An enclave policy is malformed.
    #[error("enclave policy {0} is malformed")]
    EnclavePolicy(usize),
    /// Worker-set rules name an unknown toolchain or have a bad hardware filter.
    #[error("worker set rules {0} are malformed")]
    WorkerSetRules(usize),
    /// `reservation_params` is present and not valid (TOG-SPEC-0015 §7).
    #[error("reservation params are not valid")]
    ReservationParams,
    /// `fee_splits` is present and outside the bounds of TOG-SPEC-0011 §3.2.
    #[error("fee splits out of bounds: {0:?}")]
    FeeSplits(FeeTableError),
    /// `compute_limits` is present and limits nothing, or allows `T3Confidential` without GPUs.
    #[error("compute limits are not valid")]
    ComputeLimits,
    /// `fast_on_hdd` on mainnet (`network_id = 1`, TOG-SPEC-0012 §1.3).
    #[error("fast_on_hdd is for testnets only")]
    FastOnHdd,
}

impl Genesis {
    /// Decodes a genesis file, exactly.
    pub fn decode(file: &[u8]) -> Result<Self, GenesisError> {
        borsh::from_slice(file).map_err(|_| GenesisError::Decode)
    }

    /// The genesis hash of a file: `H("TOG/v1/genesis" ‖ file bytes)`.
    pub fn hash_of(file: &[u8]) -> Hash32 {
        tagged_hash(Domain::Genesis, &[file])
    }

    /// The genesis hash of this genesis, encoded.
    pub fn hash(&self) -> Hash32 {
        Self::hash_of(&borsh::to_vec(self).expect("in-memory borsh cannot fail"))
    }

    /// The Hub's replay domain, `network_id << 32`.
    pub fn chain_id(&self) -> u64 {
        ChainId::HUB.replay_domain(self.network_id)
    }

    /// Every check of TOG-SPEC-0002 §2.3 except the BLS proofs of possession, which need the
    /// Hub's BLS code. `min_self_bond` is the governance value at genesis.
    pub fn check(&self, min_self_bond: Amount) -> Result<(), GenesisError> {
        if self.era_length == 0 || self.era_length % 4 != 0 {
            return Err(GenesisError::EraLength);
        }
        let s = self.session_length;
        if s == 0 || self.era_length % s != 0 || self.era_length < 2 * s {
            return Err(GenesisError::SessionLength);
        }
        if self.backing_rules == BackingRules::Groups && s % crate::appchain::GROUP_ROTATION != 0 {
            return Err(GenesisError::GroupRotation);
        }
        if self.fast_on_hdd && self.network_id == 1 {
            return Err(GenesisError::FastOnHdd);
        }
        let params = &self.storage_params;
        let priced = self.storage_prices.iter().all(|p| p.per_gib_hour > 0 && p.place_per_gib > 0);
        // TOG-SPEC-0004 §3.1 "Egress floors (exact)": at least the network's row.
        let floors = params.meets_egress_floors(self.network_id);
        if params.kappa_gb == 0 || params.b_chunk == 0 || !floors || !priced {
            return Err(GenesisError::Storage);
        }
        if !self.coretime.is_well_formed() {
            return Err(GenesisError::Coretime);
        }
        let seats = self.validator_count as usize;
        if self.validators.is_empty() || self.validators.len() > seats || seats > MAX_VALIDATORS {
            return Err(GenesisError::ValidatorCount);
        }
        let chain_id = self.chain_id();
        let mut stashes = alloc::collections::BTreeSet::new();
        let mut keys = alloc::collections::BTreeSet::new();
        for (i, v) in self.validators.iter().enumerate() {
            let fresh = stashes.insert(v.stash)
                && keys.insert(v.consensus_key.to_vec())
                && keys.insert(v.network_key.to_vec())
                && keys.insert(v.bls_key.to_vec())
                && keys.insert(v.dkg_key.pk.to_vec());
            if !fresh {
                return Err(GenesisError::DuplicateKey(i));
            }
            if v.dkg_key.era != 1 || !v.dkg_key.verify(chain_id, &v.stash) {
                return Err(GenesisError::DkgKey(i));
            }
            if v.commission_bps > MAX_COMMISSION_BPS {
                return Err(GenesisError::Commission(i));
            }
            if v.self_bond < min_self_bond {
                return Err(GenesisError::SelfBond(i));
            }
        }
        ascending(self.accounts.iter().map(|a| &a.0), "accounts")?;
        ascending(self.kernel_sets.iter().map(|k| &k.0), "kernel_sets")?;
        ascending(self.gpu_models.iter().map(|g| g.0), "gpu_models")?;
        ascending(self.toolchains.iter().map(|t| t.0 .0), "toolchains")?;
        // That each root parses as a self-signed X.509 certificate is checked by the node's attestation code.
        ascending(self.tee_roots.iter().map(|t| t.0), "tee_roots")?;
        for (_, roots) in &self.tee_roots {
            ascending(roots.iter(), "tee_roots")?;
        }
        ascending(self.gpu_references.iter().map(|r| (&r.driver_version, &r.vbios_version)), "gpu_references")?;
        if let Some(i) = self.gpu_references.iter().position(|r| !r.well_formed()) {
            return Err(GenesisError::GpuReference(i));
        }
        ascending(self.tee_revoked_serials.iter().map(|t| t.0), "tee_revoked_serials")?;
        for (_, serials) in &self.tee_revoked_serials {
            ascending(serials.iter(), "tee_revoked_serials")?;
        }
        let policy_ok = |p: &EnclavePolicy| p.check().is_ok() && !p.tees.is_empty() && !p.measurements.is_empty();
        if let Some(i) = self.enclave_policies.iter().position(|p| !policy_ok(p)) {
            return Err(GenesisError::EnclavePolicy(i));
        }
        ascending(self.enclave_policies.iter().map(|p| p.id()), "enclave_policies")?;
        ascending(self.worker_set_rules.iter().map(|r| r.0), "worker_set_rules")?;
        let rules_ok = |r: &WorkerSetRules| {
            r.hw_filter.is_well_formed()
                && r.hw_filter.cc.as_ref().map_or(true, |cc| cc.min <= cc.max)
                && r.required_toolchains.iter().all(|t| self.toolchains.iter().any(|(id, _)| id == t))
        };
        if let Some(i) = self.worker_set_rules.iter().position(|(_, r)| !rules_ok(r)) {
            return Err(GenesisError::WorkerSetRules(i));
        }
        if self.accounts.iter().any(|(_, a)| *a == 0) {
            return Err(GenesisError::ZeroBalance);
        }
        let balances = self.accounts.iter().map(|a| a.1).chain(self.validators.iter().map(|v| v.self_bond));
        if balances.into_iter().try_fold(self.treasury, |s, a| s.checked_add(a)).is_none() {
            return Err(GenesisError::Supply);
        }
        let kernels_ok = self.kernel_sets.iter().all(|(_, k)| k.check().is_ok())
            && self.kernel_sets.binary_search_by(|k| k.0.cmp(&self.current_kernel_set)).is_ok();
        if !kernels_ok {
            return Err(GenesisError::KernelSet);
        }
        if self.reservation_params.as_ref().is_some_and(|p| !p.is_valid()) {
            return Err(GenesisError::ReservationParams);
        }
        if let Some(splits) = &self.fee_splits {
            check_fee_splits(splits).map_err(GenesisError::FeeSplits)?;
        }
        if self.compute_limits.is_some_and(|l| !l.is_valid()) {
            return Err(GenesisError::ComputeLimits);
        }
        Ok(())
    }
}

fn ascending<T: Ord>(mut it: impl Iterator<Item = T>, what: &'static str) -> Result<(), GenesisError> {
    let Some(mut prev) = it.next() else { return Ok(()) };
    for x in it {
        if x <= prev {
            return Err(GenesisError::NotCanonical(what));
        }
        prev = x;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bls12_381::Scalar;

    use super::*;
    use crate::staking::MIN_SELF_BOND;

    const NETWORK: u32 = 0xdead;

    fn validator(i: u8) -> GenesisValidator {
        let stash = [i; 20];
        let chain_id = ChainId::HUB.replay_domain(NETWORK);
        let dkg_key = DkgKey::prove(chain_id, &stash, 1, &Scalar::from(u64::from(i) + 1), &Scalar::from(99u64));
        GenesisValidator {
            stash,
            consensus_key: [i; 32],
            bls_key: [i; 48],
            bls_pop: [i; 96],
            network_key: [i + 100; 32],
            dkg_key,
            commission_bps: 500,
            self_bond: MIN_SELF_BOND,
        }
    }

    fn devnet() -> Genesis {
        Genesis {
            network_id: NETWORK,
            time: 1_000,
            era_length: 43_200,
            session_length: 1_800,
            validator_count: 150,
            validators: (1..=4).map(validator).collect(),
            accounts: vec![([1; 20], 5), ([9; 20], 7)],
            treasury: 10,
            p_ref: 1,
            wu_weights: WuWeights { cpu_weight: 1_000, gpu_class_weights: vec![] },
            compute_params: ComputeParams {
                mu_cap_days: 4,
                r2_min_reputation: 50,
                bucket_min_weight: 0,
                w_opt_min: 1_800,
                http_locators: false,
                kappa_hours: 24,
            },
            kernel_sets: vec![([5; 32], KernelSet { expected: vec![] })],
            current_kernel_set: [5; 32],
            gpu_models: vec![],
            toolchains: vec![],
            tee_roots: vec![(TeeVendor::Amd, vec![vec![1], vec![2]]), (TeeVendor::Nvidia, vec![vec![3]])],
            gpu_references: vec![reference("550.1"), reference("560.1")],
            tee_revoked_serials: vec![(TeeVendor::Nvidia, vec![([1; 32], vec![1]), ([1; 32], vec![2])])],
            min_tdx_qe_svn: 0,
            enclave_policies: vec![],
            worker_set_rules: vec![],
            storage_params: StorageParams {
                kappa_gb: 3,
                b_chunk: 2,
                challenge_window_min_egress_bps: 4,
                long_term_min_egress_bps: 5,
            },
            storage_prices: [StoragePrices { per_gib_hour: 1, place_per_gib: 1 }; 3],
            coretime: crate::coretime::CoretimeParams {
                cores: 30,
                on_demand_cores: 6,
                launch_price: 1_000,
                od_min_price: 1,
            },
            backing_rules: BackingRules::Legacy,
            reservation_params: None,
            fee_splits: None,
            compute_limits: None,
            fast_on_hdd: false,
        }
    }

    fn reference(driver: &str) -> Reference {
        Reference {
            driver_version: driver.into(),
            vbios_version: "96.0".into(),
            pci_device_ids: vec![0x2330],
            measurements: vec![(1, vec![vec![1]])],
        }
    }

    fn policy(measurement: u8) -> EnclavePolicy {
        EnclavePolicy {
            tees: vec![crate::enclave::TeeKind::Tdx],
            measurements: vec![[measurement; 48]],
            min_cpu_tcb: vec![],
            gpu_models: vec![],
            min_gpu_driver: crate::job::DriverVersion { major: 550, minor: 0 },
            operators: None,
            allow_sketches: false,
            min_tdx_platform: None,
            require_smt_off: false,
        }
    }

    #[test]
    fn governance_collateral_and_policies_are_canonical() {
        let mut g = devnet();
        let mut policies = vec![policy(1), policy(2)];
        policies.sort_by_key(|p| p.id());
        g.enclave_policies = policies.clone();
        assert_eq!(g.check(MIN_SELF_BOND), Ok(()));
        g.enclave_policies.reverse();
        assert_eq!(g.check(MIN_SELF_BOND), Err(GenesisError::NotCanonical("enclave_policies")));
        g.enclave_policies = vec![EnclavePolicy { measurements: vec![], ..policy(1) }];
        assert_eq!(g.check(MIN_SELF_BOND), Err(GenesisError::EnclavePolicy(0)));

        let check = |f: fn(&mut Genesis)| {
            let mut g = devnet();
            f(&mut g);
            g.check(MIN_SELF_BOND).unwrap_err()
        };
        assert_eq!(check(|g| g.gpu_references.reverse()), GenesisError::NotCanonical("gpu_references"));
        assert_eq!(check(|g| g.gpu_references[1].pci_device_ids.clear()), GenesisError::GpuReference(1));
        assert_eq!(check(|g| g.tee_revoked_serials[0].1.reverse()), GenesisError::NotCanonical("tee_revoked_serials"));
    }

    #[test]
    fn worker_set_rules_are_canonical_and_name_known_toolchains() {
        use crate::eligibility::HwFilter;
        use crate::job::{CcRange, ComputeCapability, IsolationTier};
        let rules = WorkerSetRules {
            min_isolation: IsolationTier::T0Gvisor,
            hw_filter: HwFilter {
                min_gpus: 0,
                cc: None,
                min_vram_bytes: 0,
                gpu_models: None,
                require_cc_capable: false,
                min_cpu_isa: None,
                min_ram_bytes: 0,
            },
            required_toolchains: vec![],
            min_bond: 1,
            min_reputation: 0,
            regions: None,
            accepts_external_jobs: false,
            allowlist: None,
            allowed_policies: None,
        };
        let mut g = devnet();
        g.worker_set_rules = vec![(ChainId(0), rules.clone()), (ChainId(7), rules.clone())];
        assert_eq!(g.check(MIN_SELF_BOND), Ok(()));
        g.worker_set_rules.reverse();
        assert_eq!(g.check(MIN_SELF_BOND), Err(GenesisError::NotCanonical("worker_set_rules")));
        let unknown = WorkerSetRules { required_toolchains: vec![ToolchainProfileId([9; 32])], ..rules.clone() };
        g.worker_set_rules = vec![(ChainId(0), rules.clone()), (ChainId(1), unknown)];
        assert_eq!(g.check(MIN_SELF_BOND), Err(GenesisError::WorkerSetRules(1)));
        let mut inverted = rules;
        let cc = |major| ComputeCapability { major, minor: 0 };
        inverted.hw_filter.cc = Some(CcRange { min: cc(9), max: cc(8) });
        g.worker_set_rules = vec![(ChainId(0), inverted)];
        assert_eq!(g.check(MIN_SELF_BOND), Err(GenesisError::WorkerSetRules(0)));
    }

    #[test]
    fn a_devnet_genesis_checks_round_trips_and_hashes_its_bytes() {
        let g = devnet();
        assert_eq!(g.check(MIN_SELF_BOND), Ok(()));
        let file = borsh::to_vec(&g).unwrap();
        assert_eq!(Genesis::decode(&file), Ok(g.clone()));
        assert_eq!(g.hash(), tagged_hash(Domain::Genesis, &[&file]));
        assert_eq!(Genesis::decode(&[file.as_slice(), &[0]].concat()), Err(GenesisError::Decode));
        assert_eq!(g.chain_id(), u64::from(NETWORK) << 32);
    }

    #[test]
    fn backing_rules_are_written_only_when_2_so_an_older_file_keeps_its_bytes_and_hash() {
        // The devnet fixture's hash on main before `backing_rules` existed (38d4a34b): an older
        // file decodes as rule 1 and encodes back to the same bytes.
        let g = devnet();
        assert_eq!(g.backing_rules, BackingRules::Legacy);
        let file = borsh::to_vec(&g).unwrap();
        let hex: String = g.hash().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "788a1f8bfdafd4a3726741202ff531e64724e9f940d71d3b71e0ba3b93fa2d19");
        assert_eq!(file.len(), 2181);
        let groups = Genesis { backing_rules: BackingRules::Groups, ..g.clone() };
        let two = borsh::to_vec(&groups).unwrap();
        assert_eq!(two, [file.as_slice(), &[2]].concat());
        assert_eq!(Genesis::decode(&two), Ok(groups.clone()));
        assert_eq!(groups.check(MIN_SELF_BOND), Ok(()));
        // An explicit 1 is not canonical; neither is any other byte.
        for b in [0, 1, 3] {
            assert_eq!(Genesis::decode(&[file.as_slice(), &[b]].concat()), Err(GenesisError::Decode));
        }
        assert_eq!((BackingRules::Legacy.value(), BackingRules::Groups.value()), (1, 2));
        // Rule 2 rotates groups every GROUP_ROTATION blocks, which must divide a session.
        let odd = Genesis { era_length: 3_600, session_length: 1_800 - 4, ..groups };
        assert_eq!(odd.check(MIN_SELF_BOND), Err(GenesisError::SessionLength));
        let odd = Genesis { era_length: 3_640, session_length: 1_820, ..odd };
        assert_eq!(odd.check(MIN_SELF_BOND), Err(GenesisError::GroupRotation));
        assert_eq!(Genesis { backing_rules: BackingRules::Legacy, ..odd }.check(MIN_SELF_BOND), Ok(()));
    }

    fn reservation_params() -> ReservationParams {
        ReservationParams {
            min_duration_blocks: 600,
            max_duration_blocks: 432_000,
            min_price_per_block: 1,
            bond_bp: 1_000,
            miss_penalty_bp: 100,
            fault_penalty_bp: 5_000,
            cancel_notice_blocks: 600,
            treasury_bp: 300,
            max_open_per_payer: 16,
            retention_blocks: 3_600,
        }
    }

    #[test]
    fn the_tail_is_written_up_to_its_last_set_field_so_older_files_keep_their_bytes() {
        let g = devnet();
        let file = borsh::to_vec(&g).unwrap();
        let params = reservation_params();
        let splits = crate::channel::TESTNET_FEE_SPLITS;
        let p = borsh::to_vec(&params).unwrap();
        let f = borsh::to_vec(&splits).unwrap();
        let cases = [
            (BackingRules::Legacy, None, None, vec![]),
            (BackingRules::Groups, None, None, vec![2]),
            (BackingRules::Legacy, Some(params.clone()), None, [&[1, 1][..], &p].concat()),
            (BackingRules::Groups, Some(params.clone()), None, [&[2, 1][..], &p].concat()),
            (BackingRules::Legacy, None, Some(splits), [&[1, 0, 1][..], &f].concat()),
            (BackingRules::Groups, Some(params.clone()), Some(splits), [&[2, 1][..], &p, &[1], &f].concat()),
        ];
        for (backing_rules, reservation_params, fee_splits, tail) in cases {
            let full = Genesis { backing_rules, reservation_params, fee_splits, ..g.clone() };
            let bytes = borsh::to_vec(&full).unwrap();
            assert_eq!(bytes, [file.as_slice(), &tail].concat(), "{backing_rules:?}");
            assert_eq!(Genesis::decode(&bytes), Ok(full.clone()));
            assert_eq!(full.check(MIN_SELF_BOND), Ok(()));
        }
        // A tail that ends with a default, or a bad tag, is not canonical.
        for tail in [&[1][..], &[2, 0], &[1, 0], &[2, 1, 2], &[1, 0, 0], &[1, 0, 2], &[2, 2]] {
            assert_eq!(Genesis::decode(&[file.as_slice(), tail].concat()), Err(GenesisError::Decode), "{tail:?}");
        }
        // Nor does anything follow the last field.
        let last = Genesis { fee_splits: Some(splits), ..g.clone() };
        let bytes = borsh::to_vec(&last).unwrap();
        assert_eq!(Genesis::decode(&[bytes.as_slice(), &[0]].concat()), Err(GenesisError::Decode));
    }

    #[test]
    fn compute_limits_close_the_tail_and_must_limit_something() {
        use crate::job::IsolationTier;
        let g = devnet();
        let file = borsh::to_vec(&g).unwrap();
        let public = ComputeLimits { max_isolation: IsolationTier::T2MicroVm, gpus: false };
        let limited = Genesis { compute_limits: Some(public), ..g.clone() };
        let bytes = borsh::to_vec(&limited).unwrap();
        // Every earlier tail field at its default, then `1 ‖ borsh(limits)` (TOG-SPEC-0002 §2.3).
        assert_eq!(bytes, [file.as_slice(), &[1, 0, 0, 1, 2, 0]].concat());
        assert_eq!(Genesis::decode(&bytes), Ok(limited.clone()));
        assert_eq!(limited.check(MIN_SELF_BOND), Ok(()));
        assert_eq!(Genesis::decode(&[file.as_slice(), &[1, 0, 0, 0]].concat()), Err(GenesisError::Decode));
        for (max_isolation, gpus) in [(IsolationTier::T3Confidential, false), (IsolationTier::T3Confidential, true)] {
            let bad = Genesis { compute_limits: Some(ComputeLimits { max_isolation, gpus }), ..g.clone() };
            assert_eq!(bad.check(MIN_SELF_BOND), Err(GenesisError::ComputeLimits), "{max_isolation:?} {gpus}");
        }
        assert!(public.admits(IsolationTier::T2MicroVm, false));
        assert!(!public.admits(IsolationTier::T3Confidential, false));
        assert!(!public.admits(IsolationTier::T0Gvisor, true), "no GPUs");
        let gpus = ComputeLimits { gpus: true, ..public };
        assert!(gpus.admits(IsolationTier::T1Runc, true));
    }

    #[test]
    fn fast_on_hdd_closes_the_tail_and_is_refused_on_mainnet() {
        let g = devnet();
        let file = borsh::to_vec(&g).unwrap();
        let fast = Genesis { fast_on_hdd: true, ..g.clone() };
        let bytes = borsh::to_vec(&fast).unwrap();
        // Every earlier tail field at its default, then the byte `1` (TOG-SPEC-0002 §2.3).
        assert_eq!(bytes, [file.as_slice(), &[1, 0, 0, 0, 1]].concat());
        assert_eq!(Genesis::decode(&bytes), Ok(fast.clone()));
        assert_eq!(Genesis::decode(&[file.as_slice(), &[1, 0, 0, 0, 0]].concat()), Err(GenesisError::Decode));
        assert_eq!(Genesis::decode(&[file.as_slice(), &[1, 0, 0, 0, 2]].concat()), Err(GenesisError::Decode));
        assert_eq!(Genesis::decode(&file), Ok(g.clone()), "a file without it reads false");
        assert_ne!(fast.network_id, 1);
        assert_eq!(fast.check(MIN_SELF_BOND), Ok(()));
        let mainnet = Genesis { network_id: 1, ..fast };
        assert_eq!(mainnet.check(MIN_SELF_BOND), Err(GenesisError::FastOnHdd));
        assert_ne!(Genesis { fast_on_hdd: false, ..mainnet }.check(MIN_SELF_BOND), Err(GenesisError::FastOnHdd));
    }

    #[test]
    fn reservation_params_and_fee_splits_are_checked() {
        let g = devnet();
        let bad = ReservationParams { min_duration_blocks: 0, ..reservation_params() };
        let bad = Genesis { reservation_params: Some(bad), ..g.clone() };
        assert_eq!(bad.check(MIN_SELF_BOND), Err(GenesisError::ReservationParams));
        let mut splits = crate::channel::TESTNET_FEE_SPLITS;
        splits[0].burn_ppm = 10_000;
        let bad = Genesis { fee_splits: Some(splits), ..g };
        assert_eq!(bad.check(MIN_SELF_BOND), Err(GenesisError::FeeSplits(crate::channel::FeeTableError::ComputeTake)));
    }

    #[test]
    fn bad_genesis_files_are_refused() {
        let check = |f: fn(&mut Genesis)| {
            let mut g = devnet();
            f(&mut g);
            g.check(MIN_SELF_BOND).unwrap_err()
        };
        assert_eq!(check(|g| g.era_length = 43_202), GenesisError::EraLength);
        assert_eq!(check(|g| g.session_length = 0), GenesisError::SessionLength);
        assert_eq!(check(|g| g.session_length = 1_801), GenesisError::SessionLength);
        assert_eq!(check(|g| g.session_length = 43_200), GenesisError::SessionLength);
        let half = Genesis { session_length: 21_600, ..devnet() };
        assert_eq!(half.check(MIN_SELF_BOND), Ok(()));
        assert_eq!(check(|g| g.storage_params.kappa_gb = 0), GenesisError::Storage);
        assert_eq!(check(|g| g.storage_params.b_chunk = 0), GenesisError::Storage);
        assert_eq!(check(|g| g.storage_params.challenge_window_min_egress_bps = 0), GenesisError::Storage);
        assert_eq!(check(|g| g.storage_params.long_term_min_egress_bps = 0), GenesisError::Storage);
        assert_eq!(check(|g| g.storage_prices[2].per_gib_hour = 0), GenesisError::Storage);
        assert_eq!(check(|g| g.storage_prices[1].place_per_gib = 0), GenesisError::Storage);
        assert_eq!(check(|g| g.coretime.on_demand_cores = 0), GenesisError::Coretime);
        assert_eq!(check(|g| g.coretime.on_demand_cores = g.coretime.cores), GenesisError::Coretime);
        assert_eq!(check(|g| g.coretime.launch_price = 0), GenesisError::Coretime);
        assert_eq!(check(|g| g.validators.clear()), GenesisError::ValidatorCount);
        assert_eq!(check(|g| g.validator_count = 3), GenesisError::ValidatorCount);
        assert_eq!(check(|g| g.validator_count = MAX_VALIDATORS as u32 + 1), GenesisError::ValidatorCount);
        assert_eq!(check(|g| g.validators[2].bls_key = [1; 48]), GenesisError::DuplicateKey(2));
        assert_eq!(check(|g| g.validators[1].network_key = [2; 32]), GenesisError::DuplicateKey(1));
        assert_eq!(check(|g| g.validators[3].stash = [1; 20]), GenesisError::DuplicateKey(3));
        assert_eq!(check(|g| g.validators[0].dkg_key.era = 2), GenesisError::DkgKey(0));
        assert_eq!(check(|g| g.network_id += 1), GenesisError::DkgKey(0));
        assert_eq!(check(|g| g.validators[0].commission_bps = 2_001), GenesisError::Commission(0));
        assert_eq!(check(|g| g.validators[3].self_bond -= 1), GenesisError::SelfBond(3));
        assert_eq!(check(|g| g.accounts.swap(0, 1)), GenesisError::NotCanonical("accounts"));
        assert_eq!(check(|g| g.tee_roots.swap(0, 1)), GenesisError::NotCanonical("tee_roots"));
        assert_eq!(check(|g| g.tee_roots[0].1[1] = vec![1]), GenesisError::NotCanonical("tee_roots"));
        assert_eq!(check(|g| g.accounts[0].1 = 0), GenesisError::ZeroBalance);
        assert_eq!(check(|g| g.treasury = Amount::MAX), GenesisError::Supply);
        assert_eq!(check(|g| g.current_kernel_set = [6; 32]), GenesisError::KernelSet);
    }
}
