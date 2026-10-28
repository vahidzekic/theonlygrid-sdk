//! Hub state as a light client reads it (TOG-SPEC-0002 §7.1–7.2): storage keys, the Jellyfish
//! Merkle tree hashing, state proofs, and the value types of the items a worker reads.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use alloc::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Amount, Domain, Hash32};

use crate::hub_key::ResumePoint;
use crate::job::JobTx;
use crate::worker::WorkerId;

/// Root of an empty tree and hash of an empty subtree.
pub const EMPTY_SUBTREE: Hash32 = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";
/// Most siblings a proof may have: one per bit of the key hash.
pub const MAX_SIBLINGS: usize = 256;
/// Largest Borsh value the Hub stores at one key, so a snapshot client takes a chunk of 1 MiB of
/// leaves plus one leaf of this (TOG-SPEC-0006 §2.3.3). The largest bounded value is
/// `appchains.code` at `MAX_CODE_LEN` (4 MiB) plus its few fixed fields; a `Vec` such as
/// `hardware_registry.worker_ids` (20 bytes a worker) or `compute_market.job_ids` (32 bytes a
/// job) stays under it past 250 000 entries.
pub const MAX_VALUE_BYTES: usize = 8 << 20;
/// `MaxWorkerJobs`: a worker with this many open jobs is not a candidate.
pub const MAX_WORKER_JOBS: usize = 256;
/// `MaxSample`: most sampled segments in `JobStatus::Verifying`.
pub const MAX_SAMPLE: usize = 1024;

/// Misses or releases of a compute record that liveness-jail it within [`LIVENESS_WINDOW`]
/// blocks; the length bound of `hardware_registry.liveness_misses` (TOG-SPEC-0004 §3.1).
pub const LIVENESS_MISSES: usize = 3;
/// Jail when the [`LIVENESS_MISSES`] heights satisfy `last − first < LIVENESS_WINDOW`.
pub const LIVENESS_WINDOW: u64 = 1000;
/// Slot failures in one era that liveness-jail a storage record (TOG-SPEC-0004 §3.1).
pub const SLOT_FAILURES_JAIL: u8 = 3;

/// `storage_registry.slot_failures` value: `(era, count)`; a failure in a later era resets it
/// to `(era, 1)`.
pub type SlotFailures = (u64, u8);

/// `staking.sets` value: `(source_era, stashes)`, the stashes in `ValidatorIndex` order and the
/// era of the `staking.elected` entry they came from.
pub type EraSet = (u64, Vec<Address>);

/// `staking.era_points` value: per stash, ascending, `(stash, signed precommits, proposed
/// blocks)` in that era (TOG-SPEC-0005 §7.1).
pub type EraPoints = Vec<(Address, u32, u32)>;

/// `compute_market.era_bonus[(era, index)]` value: `(executor, refund_to, f_exec, f_verify)` of the
/// `index`-th job settled in that era, from 0 in settlement order (TOG-SPEC-0005 §4.3).
pub type EraBonus = (WorkerId, Address, Amount, Amount);

/// `compute_market.era_bonus_count[era]` value: the number of `era_bonus` entries of that era and
/// their `Σ f_exec`.
pub type EraBonusCount = (u32, Amount);

/// `storage.counters` value: the next `DealId`, `ChallengeId` and `ChannelId` to assign.
pub type StorageCounters = (u64, u64, u64);

/// `storage.slot_locks` value: `(bytes, collateral)` the slot commits and locks on its holder's
/// record; 0 bytes for an RS encoder whose set is released but whose bond stays.
pub type SlotLock = (u64, Amount);

const LEAF_PREFIX: &[u8] = b"JMT::LeafNode";
const INTERNAL_PREFIX: &[u8] = b"JMT::IntrnalNode";

/// `storage_key = B(module) ‖ B(item) ‖ B(borsh(key))` with plain BLAKE3-256.
pub fn storage_key(module: &str, item: &str, borsh_key: &[u8]) -> [u8; 96] {
    let mut k = [0u8; 96];
    k[..32].copy_from_slice(blake3::hash(module.as_bytes()).as_bytes());
    k[32..64].copy_from_slice(blake3::hash(item.as_bytes()).as_bytes());
    k[64..].copy_from_slice(blake3::hash(borsh_key).as_bytes());
    k
}

/// The JMT `KeyHash`: `Hs(storage_key)`.
pub fn key_hash(storage_key: &[u8; 96]) -> Hash32 {
    tagged_hash(Domain::Jmt, &[storage_key])
}

/// `Hs(borsh(value))`.
pub fn value_hash(borsh_value: &[u8]) -> Hash32 {
    tagged_hash(Domain::Jmt, &[borsh_value])
}

/// `Hs("JMT::LeafNode" ‖ key_hash ‖ value_hash)`.
pub fn leaf_hash(leaf: &ProofLeaf) -> Hash32 {
    tagged_hash(Domain::Jmt, &[LEAF_PREFIX, &leaf.key_hash, &leaf.value_hash])
}

/// `Hs("JMT::IntrnalNode" ‖ left ‖ right)`; a server reduces `jmt` sibling nodes with it.
pub fn internal_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    tagged_hash(Domain::Jmt, &[INTERNAL_PREFIX, left, right])
}

/// Bit `i` of `k`, most significant bit of byte 0 first.
fn bit(k: &Hash32, i: usize) -> bool {
    k[i / 8] >> (7 - i % 8) & 1 == 1
}

fn common_prefix_bits(a: &Hash32, b: &Hash32) -> usize {
    (0..256).take_while(|&i| bit(a, i) == bit(b, i)).count()
}

/// The leaf a proof ends in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProofLeaf {
    /// Its key hash.
    pub key_hash: Hash32,
    /// `Hs(borsh(value))`.
    pub value_hash: Hash32,
}

/// Inclusion or exclusion proof against `state_root`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StateProof {
    /// `None`: the key's path ends in an empty subtree.
    pub leaf: Option<ProofLeaf>,
    /// Bottom-up: `siblings[0]` is the deepest.
    pub siblings: Vec<Hash32>,
}

/// Why a proof was rejected.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StateProofError {
    /// More than 256 siblings.
    #[error("{0} siblings, at most 256")]
    TooDeep(usize),
    /// The proof does not show the claimed value (or absence) for this key.
    #[error("proof is for another key or value")]
    Mismatch,
    /// The recomputed root differs.
    #[error("root does not match")]
    Root,
}

impl StateProof {
    /// Checks `value` (or absence, for `None`) at `key_hash` under `root` (0002 §7.1).
    pub fn verify(&self, root: &Hash32, key_hash: &Hash32, value: Option<&[u8]>) -> Result<(), StateProofError> {
        let d = self.siblings.len();
        if d > MAX_SIBLINGS {
            return Err(StateProofError::TooDeep(d));
        }
        match (value, &self.leaf) {
            (Some(v), Some(l)) if l.key_hash == *key_hash && l.value_hash == value_hash(v) => {}
            (None, None) => {}
            (None, Some(l)) if l.key_hash != *key_hash && common_prefix_bits(&l.key_hash, key_hash) >= d => {}
            _ => return Err(StateProofError::Mismatch),
        }
        let start = self.leaf.as_ref().map_or(EMPTY_SUBTREE, leaf_hash);
        let h = self.siblings.iter().enumerate().fold(start, |h, (i, sib)| {
            if bit(key_hash, d - 1 - i) {
                internal_hash(sib, &h)
            } else {
                internal_hash(&h, sib)
            }
        });
        if h != *root {
            return Err(StateProofError::Root);
        }
        Ok(())
    }
}

/// Storage keys of the items a worker reads (0002 §7.2).
pub mod items {
    use super::*;

    fn key(module: &str, item: &str, k: &impl BorshSerialize) -> [u8; 96] {
        storage_key(module, item, &borsh::to_vec(k).expect("in-memory borsh cannot fail"))
    }

    /// `balances.accounts[address]`: [`Account`], absent while all its fields are 0.
    pub fn account(address: &Address) -> [u8; 96] {
        key("balances", "accounts", address)
    }

    /// `hardware_registry.workers[id]`: [`crate::worker::WorkerRecord`].
    pub fn worker(id: &WorkerId) -> [u8; 96] {
        key("hardware_registry", "workers", id)
    }

    /// `hardware_registry.liveness_misses[id]`: `Vec<u64>` of at most [`super::LIVENESS_MISSES`]
    /// heights, ascending: the worker's latest misses and releases that count toward a liveness
    /// jail (TOG-SPEC-0002 §7.2). Absent when empty.
    pub fn liveness_misses(id: &WorkerId) -> [u8; 96] {
        key("hardware_registry", "liveness_misses", id)
    }

    /// `hardware_registry.audit_misses[owner]`: `u64`, the block of the owner's last missed V8
    /// audit; another within `28 × era_length` blocks of it is fraud (TOG-SPEC-0003 §3.3 "Failed
    /// and missed audits"). Never deleted.
    pub fn audit_misses(owner: &Address) -> [u8; 96] {
        key("hardware_registry", "audit_misses", owner)
    }

    /// `hardware_registry.gpu_devices[gpu_device_id]`: [`crate::worker::WorkerId`], the one
    /// `Active` or `Jailed` worker that attests that physical GPU (TOG-SPEC-0001 §3.2 "GPU device
    /// uniqueness"; the id is tog-attest's `GpuReport::device_id`).
    pub fn gpu_device(id: &Hash32) -> [u8; 96] {
        key("hardware_registry", "gpu_devices", id)
    }

    /// `hardware_registry.vrf_keys[vrf_key]`: [`crate::worker::WorkerId`], the worker that
    /// registered this VRF key; written by `RegisterWorker`, never deleted (TOG-SPEC-0001 §3.2
    /// "VRF key uniqueness").
    pub fn vrf_key(vrf_key: &[u8; 32]) -> [u8; 96] {
        key("hardware_registry", "vrf_keys", vrf_key)
    }

    /// `hardware_registry.worker_gpu_devices[worker]`: `Vec<Hash32>`, the `gpu_devices` keys that
    /// name `worker`, strictly ascending, so they are removed with it. Absent when empty.
    pub fn worker_gpu_devices(worker: &WorkerId) -> [u8; 96] {
        key("hardware_registry", "worker_gpu_devices", worker)
    }

    /// `hardware_registry.min_tdx_qe_svn`: `u16`, the least `ISVSVN` of Intel's TDX Quoting
    /// Enclave a TDX quote's QE report may carry; set at genesis (TOG-SPEC-0010 §2.2 rule 2).
    pub fn min_tdx_qe_svn() -> [u8; 96] {
        key("hardware_registry", "min_tdx_qe_svn", &())
    }

    /// `hardware_registry.session_workers`: `[u64; 2]`, `n_s` and `n_{s−1}`, `active_workers` at
    /// the start of the current and the previous session; the probe threshold `n`
    /// (TOG-SPEC-0002 §7.2, TOG-SPEC-0004 §3.3).
    pub fn session_workers() -> [u8; 96] {
        key("hardware_registry", "session_workers", &())
    }

    /// `hardware_registry.worker_ids`, a `StorageValue`: `Vec<WorkerId>`, every key of
    /// `hardware_registry.workers`, ascending.
    pub fn worker_ids() -> [u8; 96] {
        key("hardware_registry", "worker_ids", &())
    }

    /// `hardware_registry.active_workers`, a `StorageValue`: `u64`, the `WorkerRecord`s with status
    /// `Active`.
    pub fn active_workers() -> [u8; 96] {
        key("hardware_registry", "active_workers", &())
    }

    /// `tee_collateral.roots[vendor]`: `Vec<Vec<u8>>`, DER root certificates ascending by bytes
    /// (TOG-SPEC-0010 §2.4).
    pub fn tee_roots(vendor: crate::enclave::TeeVendor) -> [u8; 96] {
        key("tee_collateral", "roots", &vendor)
    }

    /// `tee_collateral.certificates[(vendor, H(der))]`: `Vec<u8>`, a posted intermediate certificate.
    pub fn tee_certificate(vendor: crate::enclave::TeeVendor, der_hash: &Hash32) -> [u8; 96] {
        key("tee_collateral", "certificates", &(vendor, der_hash))
    }

    /// `tee_collateral.crls[(vendor, H(issuer SPKI DER))]`: `Vec<u8>`, that issuer's latest CRL.
    pub fn tee_crl(vendor: crate::enclave::TeeVendor, issuer_key_hash: &Hash32) -> [u8; 96] {
        key("tee_collateral", "crls", &(vendor, issuer_key_hash))
    }

    /// `tee_collateral.certificate_ids[vendor]`: `Vec<Hash32>`, every `H(der)` key of
    /// `certificates` for that vendor, ascending, absent when empty.
    pub fn tee_certificate_ids(vendor: crate::enclave::TeeVendor) -> [u8; 96] {
        key("tee_collateral", "certificate_ids", &vendor)
    }

    /// `tee_collateral.crl_ids[vendor]`: `Vec<Hash32>`, every issuer key hash of `crls` for that
    /// vendor, ascending, absent when empty.
    pub fn tee_crl_ids(vendor: crate::enclave::TeeVendor) -> [u8; 96] {
        key("tee_collateral", "crl_ids", &vendor)
    }

    /// `tee_collateral.gpu_reference_ids`: `Vec<(String, String)>`, every `(driver, vbios)` key of
    /// `gpu_references`, ascending.
    pub fn gpu_reference_ids() -> [u8; 96] {
        key("tee_collateral", "gpu_reference_ids", &())
    }

    /// `tee_collateral.revoked[issuer_key_hash]`: `Vec<Vec<u8>>`, the revoked serials of that
    /// issuer's stored CRL, strictly ascending, absent when it lists none (TOG-SPEC-0010 §2.4).
    pub fn tee_revoked(issuer_key_hash: &Hash32) -> [u8; 96] {
        key("tee_collateral", "revoked", issuer_key_hash)
    }

    /// `tee_collateral.revoked_serials[vendor]`: `Vec<(Hash32, Vec<u8>)>`, governance-revoked
    /// `(issuer key hash, serial)` pairs, ascending, absent when empty.
    pub fn revoked_serials(vendor: crate::enclave::TeeVendor) -> [u8; 96] {
        key("tee_collateral", "revoked_serials", &vendor)
    }

    /// `tee_collateral.gpu_references[(driver, vbios)]`: [`crate::enclave::Reference`].
    pub fn gpu_reference(driver_version: &str, vbios_version: &str) -> [u8; 96] {
        key("tee_collateral", "gpu_references", &(driver_version, vbios_version))
    }

    /// `hardware_registry.enclaves[id]`: `Vec<`[`crate::enclave::EnclaveRecord`]`>`, absent when empty.
    pub fn enclaves(id: &WorkerId) -> [u8; 96] {
        key("hardware_registry", "enclaves", id)
    }

    /// `hardware_registry.enclave_keys[enc_key]`: `WorkerId`, the worker whose `enclaves` entry
    /// holds a record with that `enc_key`; written and removed with that record.
    pub fn enclave_key(enc_key: &[u8; 32]) -> [u8; 96] {
        key("hardware_registry", "enclave_keys", enc_key)
    }

    /// `hardware_registry.probes[target]`: `Vec<`[`crate::probe::ProbeEntry`]`>`, the last ≤ 5 accepted
    /// probe reports from distinct probers, oldest first (TOG-SPEC-0004 §3.3).
    pub fn probes(target: &Address) -> [u8; 96] {
        key("hardware_registry", "probes", target)
    }

    /// `hardware_registry.rep_gains[id]`: `(era, count)`, the `+1` reputation changes compute
    /// worker `id` took in era `era`, at most `REP_GAIN_MAX` (TOG-SPEC-0000 §5.1 "Gain cap").
    pub fn rep_gains(id: &WorkerId) -> [u8; 96] {
        key("hardware_registry", "rep_gains", id)
    }

    /// `storage_registry.rep_gains[id]`: `(era, count)` as [`rep_gains`], for storage worker `id`.
    pub fn storage_rep_gains(id: &crate::por::StorageWorkerId) -> [u8; 96] {
        key("storage_registry", "rep_gains", id)
    }

    /// `storage_registry.media[id]`: [`crate::walk::MediaRecord`] (TOG-SPEC-0012 §1.1); absent
    /// reads as [`crate::walk::MediaRecord::undeclared`].
    pub fn media(id: &crate::por::StorageWorkerId) -> [u8; 96] {
        key("storage_registry", "media", id)
    }

    /// `storage.slot_media[(deal, slot)]`: the [`crate::walk::MediaTier`] a slot was placed on
    /// (TOG-SPEC-0012 §1.1), removed with the slot.
    pub fn slot_media(deal: crate::job::DealId, slot: u16) -> [u8; 96] {
        key("storage", "slot_media", &(deal, slot))
    }

    /// `storage.registered_at[id]`: the height `RegisterStorageWorker` registered the record at
    /// (`u64`); absent for a record from before the rule, which reads as not new (TOG-SPEC-0012
    /// §1.3 "New records").
    pub fn registered_at(id: &crate::por::StorageWorkerId) -> [u8; 96] {
        key("storage", "registered_at", id)
    }

    /// `storage.slot_probation[(deal, slot)]`: `()` while a slot placed on an `Unverified` tier
    /// counts toward its holder's `probation_bytes` (TOG-SPEC-0012 §1.3), removed with the slot.
    pub fn slot_probation(deal: crate::job::DealId, slot: u16) -> [u8; 96] {
        key("storage", "slot_probation", &(deal, slot))
    }

    /// `storage.faults[(worker, deal, slot)]`: [`crate::fault::DeclaredFault`] (TOG-SPEC-0012
    /// §3.2), from `DeclareFaults` until recovered, exited or failed.
    pub fn fault(worker: &crate::por::StorageWorkerId, deal: crate::job::DealId, slot: u16) -> [u8; 96] {
        key("storage", "faults", &(worker, deal, slot))
    }

    /// `bridge_commitments.mmr`, a `StorageValue`: [`crate::bridge::Mmr`] (TOG-SPEC-0008 §3.2).
    pub fn bridge_mmr() -> [u8; 96] {
        key("bridge_commitments", "mmr", &())
    }

    /// `hardware_registry.enclave_policies[id]`: the governance-registered
    /// [`crate::enclave::EnclavePolicy`] with this `EnclavePolicyId` (TOG-SPEC-0010 §3). Never
    /// changed or removed.
    pub fn enclave_policy(id: &crate::job::EnclavePolicyId) -> [u8; 96] {
        key("hardware_registry", "enclave_policies", id)
    }

    /// `hardware_registry.enclave_policy_ids`, a `StorageValue`: `Vec<EnclavePolicyId>` of every
    /// registered policy, ascending, never removed (TOG-SPEC-0010 §1.4).
    pub fn enclave_policy_ids() -> [u8; 96] {
        key("hardware_registry", "enclave_policy_ids", &())
    }

    /// `hardware_registry.retired_policies[id]`: `u64`, the height the policy was retired; present
    /// only once retired, never removed. Jobs admitted before still run under it (TOG-SPEC-0010 §3).
    pub fn retired_policy(id: &crate::job::EnclavePolicyId) -> [u8; 96] {
        key("hardware_registry", "retired_policies", id)
    }

    /// `hardware_registry.kernel_sets[kernel_set]`: [`crate::calibration::KernelSet`].
    pub fn kernel_set(kernel_set: &Hash32) -> [u8; 96] {
        key("hardware_registry", "kernel_sets", kernel_set)
    }

    /// `hardware_registry.current_kernel_set`, a `StorageValue`: the bundle root `RegisterWorker` must use.
    pub fn current_kernel_set() -> [u8; 96] {
        key("hardware_registry", "current_kernel_set", &())
    }

    /// `compute_market.jobs[job_id]`: [`SubmittedJob`].
    pub fn job(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "jobs", job_id)
    }

    /// `compute_market.job_status[job_id]`: [`JobStatus`].
    pub fn job_status(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "job_status", job_id)
    }

    /// `compute_market.worker_jobs[id]`: ascending open job ids, absent when empty.
    pub fn worker_jobs(id: &WorkerId) -> [u8; 96] {
        key("compute_market", "worker_jobs", id)
    }

    /// `compute_market.occupancy[id]`: [`Occupancy`], absent when nothing is booked.
    pub fn occupancy(id: &WorkerId) -> [u8; 96] {
        key("compute_market", "occupancy", id)
    }

    /// `compute_market.toolchains[id]`: [`crate::eligibility::ToolchainProfile`].
    pub fn toolchain(id: &crate::job::ToolchainProfileId) -> [u8; 96] {
        key("compute_market", "toolchains", id)
    }

    /// `compute_market.toolchain_spread[id]`: [`crate::eligibility::ToolchainSpread`], absent
    /// until the profile's spread is measured (TOG-SPEC-0003 §4.1.1).
    pub fn toolchain_spread(id: &crate::job::ToolchainProfileId) -> [u8; 96] {
        key("compute_market", "toolchain_spread", id)
    }

    /// `compute_market.key_escrows[(job_id, segment)]`: [`crate::hub_key::EscrowedSegment`].
    pub fn key_escrow(job_id: &Hash32, segment: u32) -> [u8; 96] {
        key("compute_market", "key_escrows", &(job_id, segment))
    }

    /// `hardware_registry.gpu_models[pci_device_id]`: [`crate::eligibility::GpuModel`].
    pub fn gpu_model(pci_device_id: u16) -> [u8; 96] {
        key("hardware_registry", "gpu_models", &pci_device_id)
    }

    /// `system.last_block`: `(BftTime, Hash32)`, header `h`'s time and `HubBeacon(h − 1)`, written
    /// at the start of every block; absent before block 1 (TOG-SPEC-0002 §7.2).
    pub fn system_last_block() -> [u8; 96] {
        key("system", "last_block", &())
    }

    /// `appchains.worker_set_rules[chain]`: [`crate::eligibility::WorkerSetRules`].
    pub fn worker_set_rules(chain: &tog_primitives::ChainId) -> [u8; 96] {
        key("appchains", "worker_set_rules", chain)
    }

    /// `appchains.chains[chain]`: [`crate::appchain::AppChainRecord`], never deleted in v1.
    pub fn appchain(chain: &tog_primitives::ChainId) -> [u8; 96] {
        key("appchains", "chains", chain)
    }

    /// `appchains.chain_ids`, a `StorageValue`: `Vec<ChainId>`, every key of `appchains.chains`,
    /// ascending.
    pub fn appchain_ids() -> [u8; 96] {
        key("appchains", "chain_ids", &())
    }

    /// `appchains.next_chain_id`, a `StorageValue`: `ChainId`, the next id `RegisterAppChain`
    /// assigns; [`crate::appchain::FIRST_APPCHAIN_ID`] at genesis.
    pub fn next_chain_id() -> [u8; 96] {
        key("appchains", "next_chain_id", &())
    }

    /// `appchains.code[code_hash]`: [`crate::appchain::StoredCode`].
    pub fn appchain_code(code_hash: &Hash32) -> [u8; 96] {
        key("appchains", "code", code_hash)
    }

    /// `appchains.code_pieces[(code_hash, i)]`: `Vec<u8>`, bytes `i · CODE_PIECE` on of the
    /// compressed upload of `appchains.code[code_hash]`, [`crate::appchain::CODE_PIECE`] each but
    /// the last; removed when the code is `Rejected` or its upload replaced (TOG-SPEC-0007 §8.1).
    pub fn appchain_code_piece(code_hash: &Hash32, index: u32) -> [u8; 96] {
        key("appchains", "code_pieces", &(code_hash, index))
    }

    /// `appchains.code_prechecks`, a `StorageValue`: `Vec<Hash32>`, every `appchains.code` key in
    /// `PreCheck`, ascending.
    pub fn code_prechecks() -> [u8; 96] {
        key("appchains", "code_prechecks", &())
    }

    /// `coretime.params`, a `StorageValue`: [`crate::coretime::CoretimeParams`], from genesis.
    pub fn coretime_params() -> [u8; 96] {
        key("coretime", "params", &())
    }

    /// `coretime.status`, a `StorageValue`: [`crate::coretime::CoretimeStatus`].
    pub fn coretime_status() -> [u8; 96] {
        key("coretime", "status", &())
    }

    /// `coretime.regions[(period, chain)]`: [`crate::coretime::Region`].
    pub fn coretime_region(period: u64, chain: &tog_primitives::ChainId) -> [u8; 96] {
        key("coretime", "regions", &(period, chain))
    }

    /// `coretime.sold[period]`: `u32`, regions sold for that period.
    pub fn coretime_sold(period: u64) -> [u8; 96] {
        key("coretime", "sold", &period)
    }

    /// `coretime.on_demand[chain]`: `Amount`, prepaid on-demand balance; absent when 0.
    pub fn coretime_on_demand(chain: &tog_primitives::ChainId) -> [u8; 96] {
        key("coretime", "on_demand", chain)
    }

    /// `appchains.awaiting`, a `StorageValue`: `Vec<(ChainId, Hash32)>`, included candidates not yet
    /// available, in inclusion order.
    pub fn appchain_awaiting() -> [u8; 96] {
        key("appchains", "awaiting", &())
    }

    /// `appchains.availability[candidate_hash]`: `Vec<u8>`, a bitset over era validator indices.
    pub fn candidate_availability(candidate: &Hash32) -> [u8; 96] {
        key("appchains", "availability", candidate)
    }

    /// `appchains.approvals[candidate_hash]`: [`crate::appchain::ApprovalProgress`].
    pub fn candidate_approvals(candidate: &Hash32) -> [u8; 96] {
        key("appchains", "approvals", candidate)
    }

    /// `appchains.disputes[candidate_hash]`: [`crate::appchain::DisputeState`].
    pub fn candidate_dispute(candidate: &Hash32) -> [u8; 96] {
        key("appchains", "disputes", candidate)
    }

    /// `appchains.closed[chain]`: `u64`, the Hub height at which the chain was closed.
    pub fn appchain_closed(chain: &tog_primitives::ChainId) -> [u8; 96] {
        key("appchains", "closed", chain)
    }

    /// `appchains.exits[(chain, account)]`: `Amount`, what `ExitClaim` paid `account`.
    pub fn appchain_exit(chain: &tog_primitives::ChainId, account: &Address) -> [u8; 96] {
        key("appchains", "exits", &(chain, account))
    }

    /// `appchains.collators[(chain, account)]`: [`crate::appchain::CollatorRecord`].
    pub fn collator(chain: &tog_primitives::ChainId, account: &Address) -> [u8; 96] {
        key("appchains", "collators", &(chain, account))
    }

    /// `appchains.collator_ids[chain]`: `Vec<Address>`, the chain's collators, ascending, at most
    /// [`crate::appchain::MAX_COLLATORS`].
    pub fn collator_ids(chain: &tog_primitives::ChainId) -> [u8; 96] {
        key("appchains", "collator_ids", chain)
    }

    /// `appchains.verification_code[(chain, id)]`: `Hash32`, the code hash of the module blob bound by
    /// `SetVerificationModule` (TOG-SPEC-0007 §7.2); write-once, never deleted in v1.
    pub fn verification_code(chain: &tog_primitives::ChainId, id: &crate::job::VerificationModuleId) -> [u8; 96] {
        key("appchains", "verification_code", &(chain, id))
    }

    /// `appchains.heads[chain]`: [`crate::appchain::AppChainHeads`], from registration.
    pub fn appchain_heads(chain: &tog_primitives::ChainId) -> [u8; 96] {
        key("appchains", "heads", chain)
    }

    /// `appchains.session_beacons`, a `StorageValue`: `Vec<(u64, Hash32)>`, `(session,
    /// HubBeacon(session · session_length − 1))` of the current and the previous session,
    /// ascending, at most 2; `[(0, [0; 32])]` at genesis. Read by `group(c, r)` (TOG-SPEC-0002 §4.4).
    pub fn appchain_session_beacons() -> [u8; 96] {
        key("appchains", "session_beacons", &())
    }

    /// `appchains.session_chains`, a `StorageValue`: `Vec<(u64, Vec<ChainId>)>`, `(session,
    /// chains)` of the current and the previous session, ascending, at most 2: the chains that held
    /// coretime at the session's first block, ascending. Read by `rank(c, s)` (TOG-SPEC-0002 §4.4);
    /// written only under backing rule 2.
    pub fn appchain_session_chains() -> [u8; 96] {
        key("appchains", "session_chains", &())
    }

    /// `appchains.last_included[chain]`: `u64`, the Hub height of the block that last included a
    /// candidate of the chain, for the reserve fallback (TOG-SPEC-0002 §4.4); written by inclusion
    /// under backing rule 2, never deleted in v1.
    pub fn appchain_last_included(chain: &tog_primitives::ChainId) -> [u8; 96] {
        key("appchains", "last_included", chain)
    }

    /// `appchains.backing_rules`, a `StorageValue`: `u8`, [`crate::appchain::BACKING_RULES_GROUPS`]
    /// when the chain runs the backing rules of TOG-SPEC-0002 §4.4; absent means
    /// [`crate::appchain::BACKING_RULES_LEGACY`]. Written only by genesis.
    pub fn appchain_backing_rules() -> [u8; 96] {
        key("appchains", "backing_rules", &())
    }

    /// `appchains.candidates[chain]`: `Vec<`[`crate::appchain::PendingCandidate`]`>`, oldest first,
    /// at most [`crate::appchain::MAX_PENDING`]; absent when empty.
    pub fn appchain_candidates(chain: &tog_primitives::ChainId) -> [u8; 96] {
        key("appchains", "candidates", chain)
    }

    /// `cgmp.channels[(source, dest)]`: [`crate::cgmp::CgmpChannel`], from the channel's first
    /// recorded message.
    pub fn cgmp_channel(source: &tog_primitives::ChainId, dest: &tog_primitives::ChainId) -> [u8; 96] {
        key("cgmp", "channels", &(source, dest))
    }

    /// `cgmp.refused[(source, dest)]`: `()`, present while `dest`'s manager refuses channels from
    /// `source` (TxBody 70, TOG-SPEC-0002 §4.7).
    pub fn cgmp_refused(source: &tog_primitives::ChainId, dest: &tog_primitives::ChainId) -> [u8; 96] {
        key("cgmp", "refused", &(source, dest))
    }

    /// `cgmp.hub_queue[source]`: `Hash32`, the queue head after the last message from `source`
    /// the Hub processed.
    pub fn cgmp_hub_queue(source: &tog_primitives::ChainId) -> [u8; 96] {
        key("cgmp", "hub_queue", source)
    }

    /// `cgmp.hub_outbox[(dest, nonce)]`: [`crate::cgmp::CgmpMessage`], a Hub-sent message not yet
    /// processed by `dest`.
    pub fn cgmp_hub_outbox(dest: &tog_primitives::ChainId, nonce: u64) -> [u8; 96] {
        key("cgmp", "hub_outbox", &(dest, nonce))
    }

    /// `cgmp.inbound[dest]`, a `StorageValue`: `Vec<ChainId>`, every `source` with a
    /// `cgmp.channels` entry to `dest`, ascending.
    pub fn cgmp_inbound(dest: &tog_primitives::ChainId) -> [u8; 96] {
        key("cgmp", "inbound", dest)
    }

    /// `compute_market.nondeterministic[(manifest_digest, toolchain)]`: `u64`, the block of the
    /// `Nondeterministic` verdict that flagged the pair (TOG-SPEC-0003 §5.4); never deleted in v1.
    pub fn nondeterministic(manifest_digest: &[u8; 32], toolchain: &crate::job::ToolchainProfileId) -> [u8; 96] {
        key("compute_market", "nondeterministic", &(manifest_digest, toolchain))
    }

    /// `compute_market.draws[(job_id, segment, kind)]`: [`crate::sortition::SortitionDraw`].
    pub fn draw(job_id: &Hash32, segment: u32, kind: crate::sortition::DrawKind) -> [u8; 96] {
        key("compute_market", "draws", &(job_id, segment, kind))
    }

    /// `compute_market.stalls[(job_id, segment, kind)]`: [`super::DrawStalls`], from the draw's
    /// first `FetchStall` until its `draws` entry is removed (TOG-SPEC-0004 §6.6).
    pub fn stalls(job_id: &Hash32, segment: u32, kind: crate::sortition::DrawKind) -> [u8; 96] {
        key("compute_market", "stalls", &(job_id, segment, kind))
    }

    /// `compute_market.disputes[(job_id, segment)]`: [`crate::dispute::Dispute`], the open dispute
    /// of that segment, removed once its verdict is final or the job is `Terminal`.
    pub fn dispute(job_id: &Hash32, segment: u32) -> [u8; 96] {
        key("compute_market", "disputes", &(job_id, segment))
    }

    /// `compute_market.dispute_ids`, a `StorageValue`: `Vec<(Hash32, u32)>`, every key of
    /// `compute_market.disputes`, ascending.
    pub fn dispute_ids() -> [u8; 96] {
        key("compute_market", "dispute_ids", &())
    }

    /// `compute_market.dispute_progress[(job_id, segment)]`: the Hub's `DisputeProgress`, written
    /// and removed with `disputes`.
    pub fn dispute_progress(job_id: &Hash32, segment: u32) -> [u8; 96] {
        key("compute_market", "dispute_progress", &(job_id, segment))
    }

    /// `compute_market.job_ids`, a `StorageValue`: `Vec<Hash32>`, every key of
    /// `compute_market.jobs`, ascending.
    pub fn job_ids() -> [u8; 96] {
        key("compute_market", "job_ids", &())
    }

    /// `compute_market.job_progress[job_id]`: the Hub's `JobProgress`, removed with `jobs`.
    pub fn job_progress(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "job_progress", job_id)
    }

    /// `compute_market.segment_progress[(job_id, segment)]`: the Hub's `SegmentProgress` of a
    /// sampled segment, written at V3.
    pub fn segment_progress(job_id: &Hash32, segment: u32) -> [u8; 96] {
        key("compute_market", "segment_progress", &(job_id, segment))
    }

    /// `compute_market.rounds[(job_id, segment, kind)]`: the Hub's `RoundVotes` of that draw.
    pub fn round_votes(job_id: &Hash32, segment: u32, kind: crate::sortition::DrawKind) -> [u8; 96] {
        key("compute_market", "rounds", &(job_id, segment, kind))
    }

    /// `compute_market.challenges[(job_id, segment)]`: the Hub's `ChallengeRecord` of an accepted
    /// `ChallengeTx`, removed with the segment's `disputes` entry.
    pub fn job_challenge(job_id: &Hash32, segment: u32) -> [u8; 96] {
        key("compute_market", "challenges", &(job_id, segment))
    }

    /// `compute_market.sketch_attests[(job_id, segment, round)]`: [`crate::dispute::SketchAttests`]
    /// of a derived-sketch round (1 = R1, 2 = R2), removed with the segment's `disputes` entry
    /// (TOG-SPEC-0003 §4.2).
    pub fn sketch_attests(job_id: &Hash32, segment: u32, round: u8) -> [u8; 96] {
        key("compute_market", "sketch_attests", &(job_id, segment, round))
    }

    /// `compute_market.copy_attests[(job_id, segment, round)]`: [`crate::dispute::SketchAttests`]
    /// of the copy test (TOG-SPEC-0003 §3.3 "Copy test"), round 0 for the committee and 1, 2 for
    /// R1, R2; removed with the round.
    pub fn copy_attests(job_id: &Hash32, segment: u32, round: u8) -> [u8; 96] {
        key("compute_market", "copy_attests", &(job_id, segment, round))
    }

    /// `compute_market.copy_like[(job_id, segment)] = ()`: the segment is copy-indistinguishable
    /// and not paid (TOG-SPEC-0003 §3.3 "Copy test"); removed when the job is pruned.
    pub fn copy_like(job_id: &Hash32, segment: u32) -> [u8; 96] {
        key("compute_market", "copy_like", &(job_id, segment))
    }

    /// `compute_market.outputs[job_id]`: [`crate::payload::PayloadCommitment`] of the job's output
    /// archive (kind `Output`, root `receipt.output_root`), from its `Outputs` deal; kept until the
    /// job is pruned, absent when `output_root = [0; 32]` (TOG-SPEC-0003 §5.3).
    pub fn output(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "outputs", job_id)
    }

    /// `compute_market.sub_checkpoints[(job_id, segment)]`: [`crate::payload::PayloadCommitment`]
    /// of the agreed sub-checkpoint `j > 0` of a bisected dispute, once uploaded to the job's
    /// `Dissent` deal; removed with the dispute (TOG-SPEC-0003 §4.5).
    pub fn sub_checkpoint(job_id: &Hash32, segment: u32) -> [u8; 96] {
        key("compute_market", "sub_checkpoints", &(job_id, segment))
    }

    /// `compute_market.draws_at[height]`: ascending `Vec<(Hash32, u32, DrawKind)>` computed in
    /// that block, absent when none.
    pub fn draws_at(height: u64) -> [u8; 96] {
        key("compute_market", "draws_at", &height)
    }

    /// `balances.treasury`, a `StorageValue`: `Amount` (TOG-SPEC-0005 §9).
    pub fn treasury() -> [u8; 96] {
        key("balances", "treasury", &())
    }

    /// `balances.total_supply`, a `StorageValue`: `Amount`, all $TOG in existence (TOG-SPEC-0005
    /// §2.1): set at genesis, raised by every mint and lowered by every burn.
    pub fn total_supply() -> [u8; 96] {
        key("balances", "total_supply", &())
    }

    /// `staking.era_points[era]`: [`super::EraPoints`]; deleted after the era's payout.
    pub fn era_points(era: u64) -> [u8; 96] {
        key("staking", "era_points", &era)
    }

    /// `staking.era_fees`, a `StorageValue`: `Amount`, validator shares of coretime and CGMP fees
    /// since the last payout (TOG-SPEC-0005 §7.1); reset to 0 at each payout.
    pub fn era_fees() -> [u8; 96] {
        key("staking", "era_fees", &())
    }

    /// `staking.unavailable[stash]`: `u64`, the last era the validator signed under 95% of blocks
    /// (TOG-SPEC-0002 §6.1); deleted once two eras older.
    pub fn unavailable(stash: &Address) -> [u8; 96] {
        key("staking", "unavailable", stash)
    }

    /// `staking.jailed[stash]`: `u64`, the last era of the unavailability jail (TOG-SPEC-0002 §6.1).
    pub fn validator_jailed(stash: &Address) -> [u8; 96] {
        key("staking", "jailed", stash)
    }

    /// `staking.dkg_removed[stash]`: `u64`, the height until which the stash's resharing
    /// dealings are invalid (TOG-SPEC-0002 §6.2 "Removal from the DKG"); deleted once passed.
    pub fn dkg_removed(stash: &Address) -> [u8; 96] {
        key("staking", "dkg_removed", stash)
    }

    /// `staking.offences[(kind, window)]`: `Vec<(Address, u32)>`, the offending stashes of that
    /// window, ascending, each with the slash fraction already applied in ppm (TOG-SPEC-0002 §6.2,
    /// §7.2); deleted 28 eras after the window.
    pub fn offences(kind: u8, window: u64) -> [u8; 96] {
        key("staking", "offences", &(kind, window))
    }

    /// `compute_market.era_bonus[(era, index)]`: [`super::EraBonus`], the `index`-th job settled
    /// in that era; deleted at the era's payout (TOG-SPEC-0005 §4.3).
    pub fn era_bonus(era: u64, index: u32) -> [u8; 96] {
        key("compute_market", "era_bonus", &(era, index))
    }

    /// `compute_market.era_bonus_count[era]`: [`super::EraBonusCount`]; deleted at the era's payout.
    pub fn era_bonus_count(era: u64) -> [u8; 96] {
        key("compute_market", "era_bonus_count", &era)
    }

    /// `compute_market.escrows[job_id]`: `Amount`, the job's unspent escrow (TOG-SPEC-0003 §7);
    /// the jury reserve is what of it is not owed to the executor.
    pub fn escrow(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "escrows", job_id)
    }

    /// `compute_market.p_ref`, a `StorageValue`: `Amount`.
    pub fn p_ref() -> [u8; 96] {
        key("compute_market", "p_ref", &())
    }

    /// `compute_market.p_ref_prev`, a `StorageValue`: `Amount`, `P_ref` of the previous era
    /// (TOG-SPEC-0005 §5.2 step 4); genesis writes `p_ref`. The worker base bond reads
    /// `min(p_ref, p_ref_prev)` (TOG-SPEC-0001 §4.2.1).
    pub fn p_ref_prev() -> [u8; 96] {
        key("compute_market", "p_ref_prev", &())
    }

    /// `compute_market.era_prices[index]`: `(Amount, u64)`, the `index`-th `P_ref` sample
    /// `(⌊F_exec / wu⌋, wu)` of this era (TOG-SPEC-0005 §5.2), written at its paid settlement; all
    /// deleted at the era boundary.
    pub fn era_price(index: u32) -> [u8; 96] {
        key("compute_market", "era_prices", &index)
    }

    /// `compute_market.era_prices_count`, a `StorageValue`: `u32`, the number of `era_prices`
    /// entries this era; absent when 0.
    pub fn era_prices_count() -> [u8; 96] {
        key("compute_market", "era_prices_count", &())
    }

    /// `compute_market.locator_reports[job_id]`: `Vec<Address>`, the distinct owners of workers
    /// that released the job with `LocatorsDead`, in arrival order, at most `k_fetch`; deleted
    /// when the job becomes Terminal (TOG-SPEC-0001 §5.3).
    pub fn locator_reports(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "locator_reports", job_id)
    }

    /// `compute_market.reservations[id]`: [`crate::reservation::Reservation`], kept
    /// `retention_blocks` after it ends (TOG-SPEC-0015 §6).
    pub fn reservation(id: u64) -> [u8; 96] {
        key("compute_market", "reservations", &id)
    }

    /// `compute_market.reservation_escrows[id]`: `Amount`, the unspent escrow; removed when the
    /// reservation ends (TOG-SPEC-0015 §6).
    pub fn reservation_escrow(id: u64) -> [u8; 96] {
        key("compute_market", "reservation_escrows", &id)
    }

    /// `compute_market.open_reservations`, a `StorageValue`: ascending `Vec<u64>` of every
    /// reservation not `Ended`; absent when empty (TOG-SPEC-0015 §6).
    pub fn open_reservations() -> [u8; 96] {
        key("compute_market", "open_reservations", &())
    }

    /// `compute_market.worker_reservations[id]`: ascending `Vec<u64>` of the worker's `Active`
    /// reservations; absent when empty (TOG-SPEC-0015 §6).
    pub fn worker_reservations(id: &WorkerId) -> [u8; 96] {
        key("compute_market", "worker_reservations", id)
    }

    /// `compute_market.reservation_jobs[job_id]`: `u64`, the reservation a job was assigned
    /// through (TOG-SPEC-0015 §4.1, §6).
    pub fn reservation_job(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "reservation_jobs", job_id)
    }

    /// `compute_market.reservation_lapsed[job_id]`: `()`, the job's assignment through a
    /// reservation lapsed; removed when the job is terminal (TOG-SPEC-0015 §4.1, §6).
    pub fn reservation_lapsed(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "reservation_lapsed", job_id)
    }

    /// `compute_market.ended_reservations`, a `StorageValue`: `Vec<(u64, u64)>` of `(ended_at,
    /// id)` in the order they ended, awaiting the prune; absent when empty (TOG-SPEC-0015 §6).
    pub fn ended_reservations() -> [u8; 96] {
        key("compute_market", "ended_reservations", &())
    }

    /// `compute_market.next_reservation_id`, a `StorageValue`: `u64`, from 0 (TOG-SPEC-0015 §6).
    pub fn next_reservation_id() -> [u8; 96] {
        key("compute_market", "next_reservation_id", &())
    }

    /// `compute_market.reservation_params`, a `StorageValue`:
    /// [`crate::reservation::ReservationParams`]; absent while the market is off (TOG-SPEC-0015 §7).
    pub fn reservation_params() -> [u8; 96] {
        key("compute_market", "reservation_params", &())
    }

    /// `compute_market.params`, a `StorageValue`: [`crate::sortition::ComputeParams`].
    pub fn compute_params() -> [u8; 96] {
        key("compute_market", "params", &())
    }

    /// `compute_market.lease_rate[job_id]`: `u64` `R` of the job's current (or last) claim,
    /// written by `ClaimJob` (TOG-SPEC-0003 §4.6).
    pub fn lease_rate(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "lease_rate", job_id)
    }

    /// `compute_market.leases[job_id]`: [`Booking`] of the job's current claim, written by
    /// `ClaimJob` with `lease_rate` (TOG-SPEC-0002 §7.2).
    pub fn lease(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "leases", job_id)
    }

    /// `compute_market.lease_bucket[job_id]`: `(ComputeCapability, u16)`, the `(cc, driver major)`
    /// of GPU 0 of the job's current (or last) claim's lease, written by `ClaimJob` with `leases`;
    /// absent for a CPU-only job (TOG-SPEC-0002 §7.2).
    pub fn lease_bucket(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "lease_bucket", job_id)
    }

    /// `compute_market.wu_weights`, a `StorageValue`: [`crate::metering::WuWeights`].
    pub fn wu_weights() -> [u8; 96] {
        key("compute_market", "wu_weights", &())
    }

    /// `compute_market.checkpoints[(job_id, segment)]`: [`crate::checkpoint::CheckpointCommitment`],
    /// `sketch` filled at V6.
    pub fn checkpoint(job_id: &Hash32, segment: u32) -> [u8; 96] {
        key("compute_market", "checkpoints", &(job_id, segment))
    }

    /// `compute_market.released_keys[(job_id, segment)]`: [`KeyRecord`].
    pub fn released_key(job_id: &Hash32, segment: u32) -> [u8; 96] {
        key("compute_market", "released_keys", &(job_id, segment))
    }

    /// `compute_market.receipts[job_id]`: the revealed [`crate::receipt::ExecutionReceipt`], from V2.
    pub fn receipt(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "receipts", job_id)
    }

    /// `compute_market.job_end[job_id]`: [`JobEnd`], from V2.
    pub fn job_end(job_id: &Hash32) -> [u8; 96] {
        key("compute_market", "job_end", job_id)
    }

    /// `storage.job_deals[(job_id, role)]`: `DealId`.
    pub fn job_deals(job_id: &Hash32, role: DealRole) -> [u8; 96] {
        key("storage", "job_deals", &(job_id, role))
    }

    /// `storage.challenges[id]`: [`crate::por::RetrievabilityChallenge`].
    pub fn challenge(id: &crate::por::ChallengeId) -> [u8; 96] {
        key("storage", "challenges", id)
    }

    /// `storage.open_challenges[address]`: ascending `Vec<ChallengeId>` this key must answer, absent
    /// when empty. The executor's `WorkerId` for `Executor` challenges.
    pub fn open_challenges(address: &Address) -> [u8; 96] {
        key("storage", "open_challenges", address)
    }

    /// `storage.challenge_ids`, a `StorageValue`: `Vec<ChallengeId>`, every key of
    /// `storage.challenges` (open challenges), ascending.
    pub fn challenge_ids() -> [u8; 96] {
        key("storage", "challenge_ids", &())
    }

    /// `storage.deal_ids`, a `StorageValue`: `Vec<DealId>`, every key of `storage.deals`, ascending.
    pub fn deal_ids() -> [u8; 96] {
        key("storage", "deal_ids", &())
    }

    /// `storage.owner_deals[address]` (TOG-SPEC-0002 §7.2): `Vec<DealId>`, ascending, every key of
    /// `storage.deals` whose owner is `DealOwner::Account(address)`; absent when there is none.
    pub fn owner_deals(address: &tog_primitives::Address) -> [u8; 96] {
        key("storage", "owner_deals", address)
    }

    /// `storage.closing`, a `StorageValue`: `Vec<(u64, DealId)>`, deals waiting to be pruned with
    /// the height of the block in which each became `Closed` or `Lost`, ascending by
    /// `(height, DealId)` (TOG-SPEC-0004 §4.7 "Pruning"); absent when empty.
    pub fn closing_deals() -> [u8; 96] {
        key("storage", "closing", &())
    }

    /// `storage.channel_ids`, a `StorageValue`: `Vec<ChannelId>`, every key of `storage.channels`
    /// (unsettled channels), ascending.
    pub fn channel_ids() -> [u8; 96] {
        key("storage", "channel_ids", &())
    }

    /// `storage.counters`, a `StorageValue`: [`super::StorageCounters`].
    pub fn storage_counters() -> [u8; 96] {
        key("storage", "counters", &())
    }

    /// `storage.pool_changed`, a `StorageValue`: `u64`, the last height in which the set of
    /// `Active` storage records changed; block `h` retries due draws when it is `h − 1`
    /// (TOG-SPEC-0004 §5.5 "Retry cadence"). Absent before the first change.
    pub fn pool_changed() -> [u8; 96] {
        key("storage", "pool_changed", &())
    }

    /// `storage.retry_backlog`, a `StorageValue`: the order key of the last due draw the block
    /// that wrote it ran, present when it left due draws over the cap of 16, so the next block
    /// retries the ones after it (TOG-SPEC-0004 §5.5).
    pub fn retry_backlog() -> [u8; 96] {
        key("storage", "retry_backlog", &())
    }

    /// `storage.worker_slots[worker]`: `Vec<(DealId, u16)>`, ascending, every slot the storage
    /// worker holds that is `Placing` or `Active`; absent when empty.
    pub fn worker_slots(worker: &crate::por::StorageWorkerId) -> [u8; 96] {
        key("storage", "worker_slots", worker)
    }

    /// `storage.closing_channels[end]`: `Vec<ChannelId>`, ascending, the payer-closed channels whose
    /// dispute period ends in block `end` (TOG-SPEC-0004 §6.6); absent when empty.
    pub fn closing_channels(end: u64) -> [u8; 96] {
        key("storage", "closing_channels", &end)
    }

    /// `storage.slot_locks[(deal, slot)]`: [`super::SlotLock`], what the slot holds on its
    /// holder's record (TOG-SPEC-0004 §3.2); removed when the slot releases both.
    pub fn slot_lock(deal: &crate::job::DealId, slot: u16) -> [u8; 96] {
        key("storage", "slot_locks", &(deal, slot))
    }

    /// `storage.suspects`, a `StorageValue`: `Vec<(StorageWorkerId, u64)>`, ascending: `Suspect`
    /// holders and the height of their missed scheduled challenge (TOG-SPEC-0004 §5.4); absent
    /// when empty.
    pub fn suspects() -> [u8; 96] {
        key("storage", "suspects", &())
    }

    /// `storage.deals[id]`: the deal's `StorageDeal` (TOG-SPEC-0004 §11), from `OpenDeal` until pruned.
    pub fn deal(id: &crate::job::DealId) -> [u8; 96] {
        key("storage", "deals", id)
    }

    /// `storage.encodings[id]`: a `ReedSolomon` deal's [`crate::storage::Encoding`] (TOG-SPEC-0004
    /// §11), from `OpenDeal` until the deal is pruned.
    pub fn encoding(id: &crate::job::DealId) -> [u8; 96] {
        key("storage", "encodings", id)
    }

    /// `storage.prices[class]`: [`crate::storage::StoragePrices`] of the current era, rewritten at
    /// each era boundary (TOG-SPEC-0004 §4.2).
    pub fn storage_prices(class: crate::job::RetentionClass) -> [u8; 96] {
        key("storage", "prices", &class)
    }

    /// `storage.params`: [`crate::storage::StorageParams`], from genesis (TOG-SPEC-0002 §2.3).
    pub fn storage_params() -> [u8; 96] {
        key("storage", "params", &())
    }

    /// `storage.channels[id]`: [`crate::channel::Channel`], until settled.
    pub fn channel(id: &crate::channel::ChannelId) -> [u8; 96] {
        key("storage", "channels", id)
    }

    /// `storage_registry.worker_ids`, a `StorageValue`: `Vec<StorageWorkerId>`, every key of
    /// `storage_registry.workers`, ascending.
    pub fn storage_worker_ids() -> [u8; 96] {
        key("storage_registry", "worker_ids", &())
    }

    /// `storage_registry.workers[id]`: [`crate::storage_worker::StorageWorkerRecord`].
    pub fn storage_worker(id: &crate::por::StorageWorkerId) -> [u8; 96] {
        key("storage_registry", "workers", id)
    }

    /// `storage_registry.slot_failures[id]`: [`super::SlotFailures`], the record's slot failures
    /// in one era (TOG-SPEC-0002 §7.2). Absent when empty.
    pub fn slot_failures(id: &crate::por::StorageWorkerId) -> [u8; 96] {
        key("storage_registry", "slot_failures", id)
    }

    /// `storage_registry.missed`, a `StorageValue`: `Vec<StorageWorkerId>`, ascending: records
    /// that missed a challenge or ack this era; emptied at each era boundary, absent when empty.
    pub fn storage_missed() -> [u8; 96] {
        key("storage_registry", "missed", &())
    }

    /// `storage_registry.i_sched`, a `StorageValue`: `u64`, the era's mean blocks between
    /// scheduled challenges of one holder (`I_sched`, TOG-SPEC-0004 §5.1), written at each era
    /// start.
    pub fn i_sched() -> [u8; 96] {
        key("storage_registry", "i_sched", &())
    }

    /// `storage.payer_channels[(payer, holder)]`: `Vec<ChannelId>`, ascending, the unsettled
    /// channels from `payer` to `holder`; absent when empty.
    pub fn payer_channels(payer: &Address, holder: &crate::por::StorageWorkerId) -> [u8; 96] {
        key("storage", "payer_channels", &(payer, holder))
    }

    /// `payments.fee_splits`, a `StorageValue`: `[FeeSplit; 4]` by
    /// [`FeeClass`](crate::channel::FeeClass) Borsh index (TOG-SPEC-0011 §3.1), from genesis;
    /// absent in a store from before TOG-SPEC-0011, whose retrieval channels stay in
    /// [`channel`] and [`payer_channels`].
    pub fn fee_splits() -> [u8; 96] {
        key("payments", "fee_splits", &())
    }

    /// `payments.channels[id]`: [`crate::channel::ServiceChannel`], until settled (TOG-SPEC-0011
    /// §2.1). One id counter serves both this and [`channel`], so an id names one channel.
    pub fn service_channel(id: &crate::channel::ChannelId) -> [u8; 96] {
        key("payments", "channels", id)
    }

    /// `payments.payer_channels[(payer, service)]`: `Vec<ChannelId>`, ascending, the unsettled
    /// service channels from `payer` for `service`; absent when empty.
    pub fn service_payer_channels(payer: &Address, service: &crate::channel::ServiceKind) -> [u8; 96] {
        key("payments", "payer_channels", &(payer, service))
    }

    /// `threshold_key.release_queue`, a `StorageValue`: `Vec<`[`crate::hub_key::Identity`]`>` in
    /// FIFO order, the backstop of keys not yet released (TOG-SPEC-0009 §3.1, §3.3, §5.5).
    pub fn release_queue() -> [u8; 96] {
        key("threshold_key", "release_queue", &())
    }

    /// `threshold_key.encrypted[h]`: `Vec<`[`crate::hub_key::EncryptedTx`]`>` in block order, the
    /// encrypted transactions included at height `h` until the block carrying `ReleasedKeys` for
    /// `h` executes them, or the end of block `h + 600` (TOG-SPEC-0009 §4.2 rules 3–4).
    pub fn encrypted(height: u64) -> [u8; 96] {
        key("threshold_key", "encrypted", &height)
    }

    /// `threshold_key.encrypted_heights`, a `StorageValue`: `Vec<u64>`, every key of
    /// `threshold_key.encrypted`, ascending.
    pub fn encrypted_heights() -> [u8; 96] {
        key("threshold_key", "encrypted_heights", &())
    }

    /// `compute_market.conf_keys[(job_id, enc_key)]`: `[u8; 80]`, a `Sender` broker's on-chain
    /// `K_conf` delivery (TOG-SPEC-0010 §4.3).
    pub fn conf_key(job_id: &Hash32, enc_key: &[u8; 32]) -> [u8; 96] {
        key("compute_market", "conf_keys", &(job_id, enc_key))
    }

    /// `staking.validators[stash]`: [`crate::staking::ValidatorRecord`].
    pub fn validator(stash: &Address) -> [u8; 96] {
        key("staking", "validators", stash)
    }

    /// `staking.ledgers[account]`: [`crate::staking::Ledger`], absent when empty.
    pub fn ledger(account: &Address) -> [u8; 96] {
        key("staking", "ledgers", account)
    }

    /// `staking.validator_ids`, a `StorageValue`: `Vec<Address>`, every stash in `staking.validators`,
    /// ascending.
    pub fn validator_ids() -> [u8; 96] {
        key("staking", "validator_ids", &())
    }

    /// `staking.nominator_ids`, a `StorageValue`: `Vec<Address>`, every address with
    /// `staking.nominations`, ascending.
    pub fn nominator_ids() -> [u8; 96] {
        key("staking", "nominator_ids", &())
    }

    /// `staking.active_set`, a `StorageValue`: `(u64, Vec<Address>)`, the era whose election produced
    /// the current set and its stashes in `ValidatorIndex` order (the threshold-key share holders).
    pub fn active_set() -> [u8; 96] {
        key("staking", "active_set", &())
    }

    /// `staking.validator_count`, a `StorageValue`: `u32`, seats per election.
    pub fn validator_count() -> [u8; 96] {
        key("staking", "validator_count", &())
    }

    /// `staking.elected[era]`: `Vec<`[`crate::staking::Exposure`]`>` in election order (=
    /// `ValidatorIndex` of the era's set); deleted at the start of era `e` once `era + 29 ≤ e` and
    /// no `staking.sets` entry names `era`.
    pub fn elected(era: u64) -> [u8; 96] {
        key("staking", "elected", &era)
    }

    /// `staking.elected_stashes[era]`: `Vec<Address>`, the stashes of `staking.elected[era]` in
    /// the same order, written and deleted with it; at most `MaxValidators`, so a light client
    /// can prove it (TOG-SPEC-0009 §2.3 "Receivers of a dealing").
    pub fn elected_stashes(era: u64) -> [u8; 96] {
        key("staking", "elected_stashes", &era)
    }

    /// `staking.sets[era]`: [`super::EraSet`], the active set as it stands during that era, written
    /// in its first block; deleted at the start of era `era + 29`.
    pub fn era_set(era: u64) -> [u8; 96] {
        key("staking", "sets", &era)
    }

    /// `staking.nominations[account]`: `Vec<Address>`, 1–16 stashes ascending.
    pub fn nominations(account: &Address) -> [u8; 96] {
        key("staking", "nominations", account)
    }

    /// `staking.dkg_keys[(era, stash)]`: `[u8; 48]`, the DKG key for dealings to `era`.
    pub fn dkg_key(era: u64, stash: &Address) -> [u8; 96] {
        key("staking", "dkg_keys", &(era, stash))
    }

    /// `threshold_key.dealings[(era, dealer)]`: [`crate::consensus::ResharingDealing`], valid
    /// dealings by era-`era` holders.
    pub fn dealing(era: u64, dealer: crate::consensus::ValidatorIndex) -> [u8; 96] {
        key("threshold_key", "dealings", &(era, dealer))
    }

    /// `threshold_key.genesis_dealings[dealer]`: [`crate::consensus::ResharingDealing`], the valid fresh
    /// dealings of the genesis DKG (TOG-SPEC-0009 §2.4); deleted at the start of era 2.
    pub fn genesis_dealing(dealer: crate::consensus::ValidatorIndex) -> [u8; 96] {
        key("threshold_key", "genesis_dealings", &dealer)
    }

    /// `threshold_key.epochs`, a `StorageValue`.
    pub fn threshold_epochs() -> [u8; 96] {
        key("threshold_key", "epochs", &())
    }
}

/// `balances.accounts` value (TOG-SPEC-0002 §7.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Account {
    /// The nonce the account's next nonce-carrying transaction must use; including one
    /// increments it. Worker transactions carry none.
    pub nonce: u64,
    /// Spendable balance.
    pub free: Amount,
    /// Balance locked in bonds and escrows.
    pub reserved: Amount,
}

/// What a job's storage deal holds (TOG-SPEC-0004 §11). Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum DealRole {
    /// 0: job inputs.
    Inputs,
    /// 1: segment checkpoints.
    Checkpoints,
    /// 2: job outputs.
    Outputs,
    /// 3: the micro-bisection sub-checkpoints of every disputed segment (TOG-SPEC-0004 §11).
    Dissent,
}

/// `compute_market.jobs` value.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SubmittedJob {
    /// Signer of `SubmitJob`.
    pub sender: Address,
    /// Inclusion height.
    pub submitted_at: u64,
    /// The job.
    pub job: JobTx,
}

/// Public summary of a job (`compute_market.job_status`). Variant order is the Borsh index.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum JobStatus {
    /// 0: waiting for a draw.
    Unassigned,
    /// 1: claim window.
    Assigned {
        /// Assigned executor.
        worker: WorkerId,
        /// Assignment height.
        at: u64,
        /// Resume point of a reassigned job.
        resume: Option<ResumePoint>,
    },
    /// 2: claimed, running (V0).
    Running {
        /// Executor.
        worker: WorkerId,
        /// Claim height.
        claimed_at: u64,
        /// Job bond.
        bond: Amount,
        /// Resume point of a reassigned job.
        resume: Option<ResumePoint>,
    },
    /// 3: V1–V2, until the sample is drawn.
    Committed {
        /// Executor.
        worker: WorkerId,
        /// Commit height.
        at: u64,
    },
    /// 4: V3–V8.
    Verifying {
        /// Executor.
        worker: WorkerId,
        /// Height of the sample draw.
        sampled_at: u64,
        /// Sampled segments and their stage, ascending by segment, at most [`MAX_SAMPLE`].
        segments: Vec<(u32, VerifyStage)>,
    },
    /// 5: optimistic challenge window.
    ChallengeWindow {
        /// Executor.
        worker: WorkerId,
        /// Last height of the window.
        ends: u64,
    },
    /// 6: reserved so later indices keep their place; never written in v1, where a dispute
    /// leaves the status alone and lives in `compute_market.disputes` (TOG-SPEC-0002 §7.2). A node
    /// that reads it treats the state as corrupt.
    Dispute {
        /// Executor.
        worker: WorkerId,
        /// Disputed segment.
        segment: u32,
    },
    /// 7: done, kept until pruned.
    Terminal {
        /// Outcome.
        outcome: JobOutcome,
        /// Height it ended.
        at: u64,
    },
}

impl JobStatus {
    /// The job's executor, while it has one.
    pub fn executor(&self) -> Option<WorkerId> {
        match self {
            JobStatus::Assigned { worker, .. }
            | JobStatus::Running { worker, .. }
            | JobStatus::Committed { worker, .. }
            | JobStatus::Verifying { worker, .. }
            | JobStatus::ChallengeWindow { worker, .. }
            | JobStatus::Dispute { worker, .. } => Some(*worker),
            JobStatus::Unassigned | JobStatus::Terminal { .. } => None,
        }
    }
}

/// The executor's end of the job, from its revealed receipt (`compute_market.job_end`, TOG-SPEC-0002
/// §7.2, written at V2). Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum JobEnd {
    /// `exit_status = 0`: `last = N − 1`.
    Completed {
        /// Last segment.
        last: u32,
    },
    /// `exit_status ≠ 0`: the fault segment `f` (TOG-SPEC-0003 §3.6).
    Fault {
        /// Fault segment.
        segment: u32,
    },
}

impl JobEnd {
    /// The last segment the executor ran, faulted or not.
    pub fn segment(self) -> u32 {
        match self {
            JobEnd::Completed { last } => last,
            JobEnd::Fault { segment } => segment,
        }
    }
}

/// `compute_market.released_keys[(job_id, segment)]` value (TOG-SPEC-0003 §2): `k_n` once recorded,
/// from a `KeyReleaseTx` or the escrow release path. Borsh in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KeyRecord {
    /// `k_n`.
    pub key: [u8; 32],
    /// Block that recorded it.
    pub at: u64,
    /// `at + T_reveal` iff `n ∈ 𝒮` and this is `n`'s end key (V6): the `VerifierReveal` deadline
    /// of segment `n` (V7).
    pub reveal_deadline: Option<u64>,
}

/// Stage of a sampled segment: V4–V8 of TOG-SPEC-0003 §3.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum VerifyStage {
    /// V4: start-state keys.
    StartKeys,
    /// V5: verifiers re-run.
    Execution,
    /// V6: end-state keys.
    EndKeys,
    /// V7: verifier reveals.
    Reveal,
    /// V8: chunk audits and tally.
    Audit,
    /// The tally recorded a dispute on the segment; it is open in `compute_market.disputes`.
    Dispute,
}

/// How a job ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum JobOutcome {
    /// Paid out.
    Settled,
    /// The jury disagreed with itself (sender fault).
    Nondeterministic,
    /// The executor lost.
    ExecutorFault,
    /// Nobody ran it.
    Refunded,
    /// `k_fetch` workers of distinct owners found every locator of a locator-only payload dead
    /// (TOG-SPEC-0001 §5.3): refunded minus the inclusion fee.
    SenderFault,
}

/// `compute_market.stalls` value: the `FetchStall`s of one draw (TOG-SPEC-0004 §6.6 "Stall rules").
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DrawStalls {
    /// One entry per signer, ascending by `WorkerId`: the deal it stalled on.
    pub stalls: Vec<(WorkerId, crate::job::DealId)>,
    /// The draw's `commit_deadline` has taken its one stall extension.
    pub extended: bool,
    /// The targeted challenges the draw's first `FetchStall` on each deal opened, in order:
    /// deal, first `ChallengeId`, count (consecutive ids).
    pub opened: Vec<(crate::job::DealId, u64, u16)>,
    /// Deals one of those challenges failed on, ascending, each once.
    pub failed: Vec<crate::job::DealId>,
}

/// `compute_market.occupancy` value (0001 §4.2.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Occupancy {
    /// Booked cores.
    pub cores: u32,
    /// Booked RAM.
    pub ram_bytes: u64,
    /// Booked scratch.
    pub scratch_bytes: u64,
    /// Whole GPUs by index.
    pub whole_gpus: BTreeSet<u8>,
    /// GPU index → booked MIG slices.
    pub mig: BTreeMap<u8, MigUse>,
}

/// MIG use of one GPU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MigUse {
    /// Booked memory eighths.
    pub eighths: u8,
    /// MIG jobs on the GPU.
    pub jobs: u8,
}

/// GPUs a job books. Borsh index = position.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum GpuBooking {
    /// CPU-only job.
    None,
    /// Whole GPUs, ascending: the lowest-indexed free ones in `Adm`.
    Whole(Vec<u8>),
    /// `eighths` of the memory of one MIG-capable GPU.
    Mig {
        /// GPU index.
        gpu: u8,
        /// `e = ⌈8 · min_vram_bytes / vram_bytes⌉`.
        eighths: u8,
    },
}

/// `compute_market.leases[job_id]` value (TOG-SPEC-0002 §7.2): what one job's claim booked on its
/// executor (0001 §4.2.1). Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Booking {
    /// Cores.
    pub cores: u32,
    /// RAM.
    pub ram_bytes: u64,
    /// Scratch.
    pub scratch_bytes: u64,
    /// GPUs.
    pub gpus: GpuBooking,
}

impl Booking {
    /// GPU 0 of the lease, whose bucket weighs the lease: `Whole(v)[0]` or `Mig.gpu`; `None` for
    /// a CPU-only booking.
    pub fn gpu0(&self) -> Option<u8> {
        match &self.gpus {
            GpuBooking::None => None,
            GpuBooking::Whole(v) => v.first().copied(),
            GpuBooking::Mig { gpu, .. } => Some(*gpu),
        }
    }
}

#[cfg(test)]
mod tests;
