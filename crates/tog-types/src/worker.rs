//! Worker registration (TOG-SPEC-0001 §3.2, §4.2 step 0), `TxBody` variant 9, and the Hub's
//! record of a worker (TOG-SPEC-0000 §5.1).

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use alloc::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{ed25519_address, tagged_hash, Address, Amount, ChainId, Domain, Hash32, HubHeight};

use crate::eligibility::Region;
use crate::job::{ComputeCapability, CpuIsaLevel, DriverVersion, EnclavePolicyId, Interconnect, IsolationTier};
use crate::verifier::VrfProof;

/// A worker is identified by the address of its Ed25519 worker key.
pub type WorkerId = Address;

/// `gpu_index` of a CPU calibration kernel.
pub const CPU_KERNEL: u8 = 0xFF;

/// Registers a worker. Signed by the owner (the tx sender); the worker key proves
/// possession with `worker_sig` over [`WorkerRegistrationTx::bind_digest`], and the VRF key with
/// `vrf_pop`, its proof for [`vrf_bind_input`] (TOG-SPEC-0001 §3.2 "VRF key uniqueness").
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WorkerRegistrationTx {
    /// Replay domain, TOG-SPEC-0000 §13.2.
    pub chain_id: u64,
    /// Funds the bond and receives payments.
    pub owner: Address,
    /// Owner nonce.
    pub owner_nonce: u64,
    /// Ed25519 worker key; `WorkerId` is its address.
    pub worker_key: [u8; 32],
    /// Worker key signature over the bind digest.
    pub worker_sig: [u8; 64],
    /// ECVRF public key, never the same as `worker_key`, unique among all workers.
    pub vrf_key: [u8; 32],
    /// Proof of possession of `vrf_key`: its ECVRF proof for [`vrf_bind_input`].
    pub vrf_pop: VrfProof,
    /// Claimed machine.
    pub hw: HwSignature,
    /// Offered isolation tiers, strictly sorted.
    pub tiers: Vec<IsolationTier>,
    /// Vendor evidence; may be empty (consumer hardware).
    pub attestation: Vec<AttestationReport>,
    /// Recent Hub height whose block hash goes into every report's nonce.
    pub attestation_nonce_height: u64,
    /// The worker's own calibration run.
    pub calibration: SelfCalibration,
    /// At least the worker base bond (TOG-SPEC-0005 §8).
    pub bond: Amount,
    /// Declared country, latency-probed like storage workers (TOG-SPEC-0004 §3.3).
    pub region: Region,
    /// Worker sets to join (TOG-SPEC-0000 §5.2), strictly ascending, at most [`MAX_OPT_INS`], each
    /// with an `appchains.worker_set_rules` entry; becomes [`WorkerRecord::opted_in`].
    pub opt_in: Vec<ChainId>,
}

/// What the worker claims about its machine; challenge jobs check it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HwSignature {
    /// CPU ISA level.
    pub cpu_isa_level: CpuIsaLevel,
    /// Physical cores offered to jobs.
    pub cpu_cores: u16,
    /// NUMA nodes.
    pub numa_nodes: u8,
    /// RAM offered to jobs.
    pub ram_bytes: u64,
    /// Scratch disk offered to jobs.
    pub scratch_bytes: u64,
    /// In PCI bus order; the index is `gpu_index` elsewhere.
    pub gpus: Vec<GpuInfo>,
    /// Strongest link among all GPUs; `None` with fewer than 2.
    pub interconnect: Option<Interconnect>,
}

/// One GPU.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GpuInfo {
    /// NVML UUID.
    pub uuid: [u8; 16],
    /// PCI device id (the model).
    pub pci_device_id: u16,
    /// `sm_xx`.
    pub compute_capability: ComputeCapability,
    /// VRAM in bytes.
    pub vram_bytes: u64,
    /// Supports MIG.
    pub mig_capable: bool,
    /// Supports NVIDIA Confidential Computing (T3).
    pub cc_capable: bool,
    /// Installed driver.
    pub driver: DriverVersion,
    /// NUMA node the GPU is attached to.
    pub numa_node: u8,
}

/// Evidence the Hub checks natively against vendor roots. Each report's nonce is
/// [`attestation_nonce`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AttestationReport {
    /// NVIDIA SPDM attestation report of one GPU.
    NvidiaGpu {
        /// Index into `HwSignature.gpus`.
        gpu_index: u8,
        /// Raw report.
        report: Vec<u8>,
        /// Device certificate chain.
        cert_chain: Vec<Vec<u8>>,
    },
    /// TPM 2.0 quote over the measured-boot PCRs, including the tog-executor binary.
    TpmQuote {
        /// TPMS_ATTEST.
        quote: Vec<u8>,
        /// Quote signature.
        signature: Vec<u8>,
        /// Quoted PCRs.
        pcrs: Vec<(u8, [u8; 32])>,
        /// Attestation key certificate chain up to a TPM vendor root.
        ak_cert_chain: Vec<Vec<u8>>,
    },
}

/// Result of the deterministic calibration kernels, run by the worker itself.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SelfCalibration {
    /// Governance-registered kernel bundle.
    pub kernel_set: Hash32,
    /// Sorted by `(kernel, gpu_index)`.
    pub results: Vec<KernelResult>,
}

/// One kernel on one device.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KernelResult {
    /// Kernel number in the bundle.
    pub kernel: u16,
    /// GPU index, or [`CPU_KERNEL`].
    pub gpu_index: u8,
    /// Must equal the bundle's expected hash for the GPU's bucket.
    pub output_hash: Hash32,
    /// Work units per hour at this kernel's shape.
    pub throughput: u64,
}

/// Nonce of every attestation report: `H("TOG/v1/worker-attest" ‖ worker_id ‖ hub_block_hash)`,
/// where the block is at `attestation_nonce_height`, at most 300 blocks old.
pub fn attestation_nonce(worker_id: &WorkerId, hub_block_hash: &Hash32) -> Hash32 {
    tagged_hash(Domain::WorkerAttest, &[worker_id, hub_block_hash])
}

/// Maximum age of `attestation_nonce_height`, in Hub blocks.
pub const ATTESTATION_NONCE_MAX_AGE: u64 = 300;

/// Why a registration fails the stateless checks.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationError {
    /// `vrf_key == worker_key`.
    #[error("vrf_key must differ from worker_key")]
    SharedVrfKey,
    /// `vrf_key` is not a canonical point of large order (RFC 9381 §5.4.5).
    #[error("vrf_key is not a valid ECVRF public key")]
    VrfKey,
    /// `vrf_pop` does not verify under `vrf_key` for [`vrf_bind_input`].
    #[error("vrf_pop does not prove possession of vrf_key")]
    VrfPop,
    /// `tiers` is not strictly sorted.
    #[error("tiers must be strictly sorted")]
    TiersUnsorted,
    /// `interconnect` must be set iff there are at least two GPUs.
    #[error("interconnect must be set iff the machine has two or more GPUs")]
    Interconnect,
    /// A `gpu_index` names no GPU.
    #[error("gpu_index {0} out of range")]
    GpuIndex(u8),
    /// Calibration results are not strictly sorted by `(kernel, gpu_index)`.
    #[error("calibration results must be strictly sorted by (kernel, gpu_index)")]
    CalibrationUnsorted,
    /// The nonce height is in the future or older than [`ATTESTATION_NONCE_MAX_AGE`].
    #[error("attestation_nonce_height {0} is not within the last 300 blocks")]
    StaleNonce(u64),
    /// `region` is not two uppercase ASCII letters.
    #[error("region must be an uppercase ISO 3166-1 alpha-2 code")]
    Region,
    /// More than [`MAX_GPUS`] GPUs, [`MAX_ATTEST`] attestation reports or [`MAX_TIERS`] tiers.
    #[error("too many {0}")]
    TooMany(&'static str),
    /// A `TpmQuote` doesn't list exactly PCRs 0–7 and 10 in ascending order.
    #[error("TpmQuote must list PCRs 0-7 and 10 in order")]
    TpmPcrs,
    /// Two reports for one GPU, or two TPM quotes.
    #[error("more than one attestation report per GPU or TPM")]
    DuplicateAttestation,
    /// Worker-set opt-ins not strictly ascending.
    #[error("opt-ins must be strictly ascending")]
    OptInsUnsorted,
}

/// Opt-ins as [`WorkerRegistrationTx::opt_in`] and [`SetOptInsTx::opted_in`] need them: strictly
/// ascending and at most [`MAX_OPT_INS`].
pub fn check_opt_ins(opt_in: &[ChainId]) -> Result<(), RegistrationError> {
    if opt_in.len() > MAX_OPT_INS {
        return Err(RegistrationError::TooMany("opt-ins"));
    }
    if !opt_in.windows(2).all(|w| w[0] < w[1]) {
        return Err(RegistrationError::OptInsUnsorted);
    }
    Ok(())
}

/// `H("TOG/v1/worker-bind" ‖ u64 chain_id ‖ owner ‖ u64 owner_nonce ‖ vrf_key)`, the message of
/// the worker key's proof of possession (what `tog-signer` signs for `ProvePossession`).
pub fn bind_digest(chain_id: u64, owner: &Address, owner_nonce: u64, vrf_key: &[u8; 32]) -> Hash32 {
    tagged_hash(Domain::WorkerBind, &[&chain_id.to_le_bytes(), owner, &owner_nonce.to_le_bytes(), vrf_key])
}

/// The VRF input of the `vrf_key` proof of possession: `"TOG/v1/vrf-bind" ‖ u64_le(chain_id) ‖
/// worker_key`, 55 bytes. It names the worker key, so a proof can't be replayed for another worker
/// or network (TOG-SPEC-0001 §3.2 "VRF key uniqueness").
pub fn vrf_bind_input(chain_id: u64, worker_key: &[u8; 32]) -> [u8; 55] {
    let mut alpha = [0; 55];
    alpha[..15].copy_from_slice(Domain::VrfBind.tag().as_bytes());
    alpha[15..23].copy_from_slice(&chain_id.to_le_bytes());
    alpha[23..].copy_from_slice(worker_key);
    alpha
}

impl WorkerRegistrationTx {
    /// The worker's id, the address of `worker_key`.
    pub fn worker_id(&self) -> WorkerId {
        ed25519_address(&self.worker_key)
    }

    /// `H("TOG/v1/worker-bind" ‖ u64 chain_id ‖ owner ‖ u64 owner_nonce ‖ vrf_key)`, signed by the worker key.
    pub fn bind_digest(&self) -> Hash32 {
        bind_digest(self.chain_id, &self.owner, self.owner_nonce, &self.vrf_key)
    }

    /// Checks that need no Hub state beyond the current height. Signatures, attestation
    /// evidence, the kernel bundle and the bond are checked by the Hub.
    pub fn check_stateless(&self, height: u64) -> Result<(), RegistrationError> {
        if self.vrf_key == self.worker_key {
            return Err(RegistrationError::SharedVrfKey);
        }
        if !tog_primitives::ecvrf::valid_public_key(&self.vrf_key) {
            return Err(RegistrationError::VrfKey);
        }
        if self.vrf_pop.verify(&self.vrf_key, &vrf_bind_input(self.chain_id, &self.worker_key)).is_none() {
            return Err(RegistrationError::VrfPop);
        }
        if !self.tiers.windows(2).all(|w| w[0] < w[1]) {
            return Err(RegistrationError::TiersUnsorted);
        }
        // The record's bounds, so an oversized registration is refused before it reaches state.
        for (n, max, what) in [
            (self.hw.gpus.len(), MAX_GPUS, "gpus"),
            (self.attestation.len(), MAX_ATTEST, "attestation reports"),
            (self.tiers.len(), MAX_TIERS, "tiers"),
        ] {
            if n > max {
                return Err(RegistrationError::TooMany(what));
            }
        }
        const PCRS: [u8; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 10];
        for report in &self.attestation {
            if let AttestationReport::TpmQuote { pcrs, .. } = report {
                if !pcrs.iter().map(|p| p.0).eq(PCRS) {
                    return Err(RegistrationError::TpmPcrs);
                }
            }
        }
        let gpus = self.hw.gpus.len();
        if self.hw.interconnect.is_some() != (gpus >= 2) {
            return Err(RegistrationError::Interconnect);
        }
        let gpu_ok = |i: u8| (i as usize) < gpus;
        // At most one report per GPU and one TPM quote (TOG-SPEC-0001 §3.2).
        let mut reported = [false; 256];
        let mut tpm = false;
        for report in &self.attestation {
            match report {
                AttestationReport::NvidiaGpu { gpu_index, .. } => {
                    if !gpu_ok(*gpu_index) {
                        return Err(RegistrationError::GpuIndex(*gpu_index));
                    }
                    if core::mem::replace(&mut reported[usize::from(*gpu_index)], true) {
                        return Err(RegistrationError::DuplicateAttestation);
                    }
                }
                AttestationReport::TpmQuote { .. } => {
                    if core::mem::replace(&mut tpm, true) {
                        return Err(RegistrationError::DuplicateAttestation);
                    }
                }
            }
        }
        let results = &self.calibration.results;
        if let Some(r) = results.iter().find(|r| r.gpu_index != CPU_KERNEL && !gpu_ok(r.gpu_index)) {
            return Err(RegistrationError::GpuIndex(r.gpu_index));
        }
        if !results.windows(2).all(|w| (w[0].kernel, w[0].gpu_index) < (w[1].kernel, w[1].gpu_index)) {
            return Err(RegistrationError::CalibrationUnsorted);
        }
        if !self.region.is_well_formed() {
            return Err(RegistrationError::Region);
        }
        check_opt_ins(&self.opt_in)?;
        let h = self.attestation_nonce_height;
        if h > height || height - h > ATTESTATION_NONCE_MAX_AGE {
            return Err(RegistrationError::StaleNonce(h));
        }
        Ok(())
    }
}

/// Most isolation tiers in [`WorkerRecord::tiers`].
pub const MAX_TIERS: usize = 4;
/// Most attestation reports in [`WorkerRecord::attestation`] (`MaxGpus`).
pub const MAX_GPUS: usize = 16;
/// `MaxAttest`: most attestation reports, one per GPU plus one TPM quote (TOG-SPEC-0000 §5.1).
pub const MAX_ATTEST: usize = MAX_GPUS + 1;
/// Most worker sets in [`WorkerRecord::opted_in`].
pub const MAX_OPT_INS: usize = 64;
/// Most policies in [`WorkerRecord::enclave_policies`].
pub const MAX_POLICIES: usize = 32;

/// Hub state `hardware_registry.workers` (TOG-SPEC-0000 §5.1, TOG-SPEC-0002 §7.2). Light clients
/// decode it, so the Borsh layout is exact: fields in this order, bounded collections as a Vec with
/// a u32 length, sets strictly ascending. Decode state values with [`WorkerRecord::decode`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WorkerRecord {
    /// Address of the worker key.
    pub id: WorkerId,
    /// Owner account.
    pub owner: Address,
    /// ECVRF key for private sortition.
    pub vrf_key: [u8; 32],
    /// Registered machine.
    pub hw: HwSignature,
    /// Offered isolation tiers, strictly ascending, at most [`MAX_TIERS`].
    pub tiers: Vec<IsolationTier>,
    /// Verified NVIDIA / TPM evidence, at most [`MAX_ATTEST`]; may be empty.
    pub attestation: Vec<AttestationReport>,
    /// Network-issued challenge benchmark results.
    pub calibration: CalibrationResult,
    /// Probed bandwidth (TOG-SPEC-0004 §3.3, §7.4).
    pub net: NetProfile,
    /// Bond in atto-TOG.
    pub bond: Amount,
    /// Reputation; decays, drops sharply on slash.
    pub reputation: u32,
    /// Jobs settled as executor since the last slash, saturating; sets `p_min` (TOG-SPEC-0003 §8.2).
    pub clean_jobs: u32,
    /// Worker sets opted in to, at most [`MAX_OPT_INS`].
    pub opted_in: BTreeSet<ChainId>,
    /// Lifecycle.
    pub status: WorkerStatus,
    /// Declared and latency-probed country (TOG-SPEC-0004 §3.3).
    pub region: Region,
    /// Set by the region / ASN probe vote, cleared by the next clean probe.
    pub region_flagged: bool,
    /// Policies the worker's live enclave records satisfy (TOG-SPEC-0010 §3), at most [`MAX_POLICIES`].
    pub enclave_policies: BTreeSet<EnclavePolicyId>,
}

/// Results of the network-issued calibration challenges (TOG-SPEC-0001 §3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CalibrationResult {
    /// What assignment weight and bond sizing use; 0 until the first challenge passes.
    pub verified_wu_per_hour: u64,
    /// Height of the last challenge.
    pub last_challenge: HubHeight,
    /// Challenges passed.
    pub passed: u32,
    /// Challenges failed.
    pub failed: u32,
}

/// Probed bandwidth in bits per second.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NetProfile {
    /// Ingress.
    pub ingress_bps: u64,
    /// Egress.
    pub egress_bps: u64,
}

/// `TxBody` variant 43, user lane: starts unbonding the whole record (TOG-SPEC-0001 §4.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UnbondWorkerTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Owner; the signer.
    pub owner: Address,
    /// The owner's next nonce.
    pub owner_nonce: u64,
    /// The record.
    pub worker: WorkerId,
}

/// `TxBody` variant 68, user lane: moves `amount` from the owner's free balance into the record's
/// bond, for an `Active` or `Jailed` record (TOG-SPEC-0001 §4.2 "Adding to a worker's bond").
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BondWorkerTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Owner; the signer.
    pub owner: Address,
    /// The owner's next nonce.
    pub owner_nonce: u64,
    /// The record.
    pub worker: WorkerId,
    /// Added to the bond.
    pub amount: Amount,
}

/// `TxBody` variant 44, user lane: replaces a compute worker's worker-set opt-ins
/// ([`WorkerRecord::opted_in`]) from the next block on (TOG-SPEC-0001 §4.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SetOptInsTx {
    /// Replay domain.
    pub chain_id: u64,
    /// Owner; the signer.
    pub owner: Address,
    /// The owner's next nonce.
    pub owner_nonce: u64,
    /// The record.
    pub worker: WorkerId,
    /// The new set: strictly ascending, at most [`MAX_OPT_INS`], each with an
    /// `appchains.worker_set_rules` entry; may be empty.
    pub opted_in: Vec<ChainId>,
}

impl SetOptInsTx {
    /// The checks that need no Hub state.
    pub fn check_stateless(&self) -> Result<(), RegistrationError> {
        check_opt_ins(&self.opted_in)
    }
}

/// Worker lifecycle. Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum WorkerStatus {
    /// 0: takes jobs.
    Active,
    /// 1: excluded until this height (TOG-SPEC-0004 §3.1).
    Jailed {
        /// First height it may work again.
        until: HubHeight,
        /// A fraud jail; else a liveness jail.
        fraud: bool,
    },
    /// 2: leaving; takes no new jobs.
    Unbonding {
        /// Height the bond is released.
        until: HubHeight,
    },
}

/// Why a stored `WorkerRecord` is not in its exact layout.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// Bytes do not decode, have trailing data, or hold a set that is not strictly ascending
    /// (Borsh rejects those rather than reordering them).
    #[error("not a WorkerRecord")]
    Decode,
    /// A collection is over its bound.
    #[error("`{0}` over its bound")]
    TooMany(&'static str),
    /// `tiers` not strictly ascending.
    #[error("tiers not strictly ascending")]
    TiersNotSorted,
}

impl WorkerRecord {
    /// Checks the bounds and orderings of the exact layout.
    pub fn check(&self) -> Result<(), RecordError> {
        if self.tiers.len() > MAX_TIERS {
            return Err(RecordError::TooMany("tiers"));
        }
        if self.tiers.windows(2).any(|w| w[0] >= w[1]) {
            return Err(RecordError::TiersNotSorted);
        }
        if self.attestation.len() > MAX_ATTEST {
            return Err(RecordError::TooMany("attestation"));
        }
        if self.opted_in.len() > MAX_OPT_INS {
            return Err(RecordError::TooMany("opted_in"));
        }
        if self.enclave_policies.len() > MAX_POLICIES {
            return Err(RecordError::TooMany("enclave_policies"));
        }
        Ok(())
    }

    /// Decodes a state value and checks it, so only the exact layout the Hub writes is accepted.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let r: Self = borsh::from_slice(bytes).map_err(|_| RecordError::Decode)?;
        r.check()?;
        Ok(r)
    }

    /// A job it executed settled.
    pub fn settled_clean(&mut self) {
        self.clean_jobs = self.clean_jobs.saturating_add(1);
    }

    /// It was slashed: the clean record starts over.
    pub fn slashed(&mut self) {
        self.clean_jobs = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpu() -> GpuInfo {
        GpuInfo {
            uuid: [0; 16],
            pci_device_id: 0x2330,
            compute_capability: ComputeCapability { major: 9, minor: 0 },
            vram_bytes: 80 << 30,
            mig_capable: true,
            cc_capable: true,
            driver: DriverVersion { major: 550, minor: 0 },
            numa_node: 0,
        }
    }

    fn registration() -> WorkerRegistrationTx {
        WorkerRegistrationTx {
            chain_id: 1 << 32,
            owner: [1; 20],
            owner_nonce: 0,
            worker_key: [2; 32],
            worker_sig: [0; 64],
            vrf_key: tog_primitives::ecvrf::public_key(&[3; 32]),
            vrf_pop: VrfProof::prove(&[3; 32], &vrf_bind_input(1 << 32, &[2; 32])),
            hw: HwSignature {
                cpu_isa_level: CpuIsaLevel::X86_64V3,
                cpu_cores: 32,
                numa_nodes: 1,
                ram_bytes: 256 << 30,
                scratch_bytes: 1 << 40,
                gpus: vec![gpu(), gpu()],
                interconnect: Some(Interconnect::Pcie),
            },
            tiers: vec![IsolationTier::T1Runc, IsolationTier::T2MicroVm],
            attestation: vec![AttestationReport::NvidiaGpu { gpu_index: 1, report: vec![], cert_chain: vec![] }],
            attestation_nonce_height: 90,
            calibration: SelfCalibration {
                kernel_set: [4; 32],
                results: vec![
                    KernelResult { kernel: 0, gpu_index: 0, output_hash: [0; 32], throughput: 1 },
                    KernelResult { kernel: 0, gpu_index: 1, output_hash: [0; 32], throughput: 1 },
                    KernelResult { kernel: 1, gpu_index: CPU_KERNEL, output_hash: [0; 32], throughput: 1 },
                ],
            },
            bond: 0,
            region: Region(*b"DE"),
            opt_in: vec![ChainId(0), ChainId(5)],
        }
    }

    fn rejects(f: impl FnOnce(&mut WorkerRegistrationTx), err: RegistrationError) {
        let mut tx = registration();
        f(&mut tx);
        assert_eq!(tx.check_stateless(100), Err(err));
    }

    #[test]
    fn valid_registration_passes() {
        assert_eq!(registration().check_stateless(100), Ok(()));
        let mut unsorted = registration();
        unsorted.opt_in.reverse();
        assert_eq!(unsorted.check_stateless(100), Err(RegistrationError::OptInsUnsorted));
        let mut many = registration();
        many.opt_in = (0..=MAX_OPT_INS as u32).map(ChainId).collect();
        assert_eq!(many.check_stateless(100), Err(RegistrationError::TooMany("opt-ins")));
        let set = |opted_in| SetOptInsTx { chain_id: 1, owner: [1; 20], owner_nonce: 0, worker: [2; 20], opted_in };
        assert_eq!(set(vec![]).check_stateless(), Ok(()));
        assert_eq!(set(vec![ChainId(2), ChainId(2)]).check_stateless(), Err(RegistrationError::OptInsUnsorted));
        assert_eq!(registration().check_stateless(390), Ok(()));
    }

    #[test]
    fn stateless_rejections() {
        rejects(|t| t.vrf_key = t.worker_key, RegistrationError::SharedVrfKey);
        let mut identity = [0; 32];
        identity[0] = 1;
        rejects(|t| t.vrf_key = identity, RegistrationError::VrfKey);
        // A proof for another worker key or network, or under another key, proves nothing.
        rejects(|t| t.worker_key = [9; 32], RegistrationError::VrfPop);
        rejects(|t| t.chain_id = 2 << 32, RegistrationError::VrfPop);
        rejects(|t| t.vrf_key = tog_primitives::ecvrf::public_key(&[4; 32]), RegistrationError::VrfPop);
        rejects(|t| t.tiers.reverse(), RegistrationError::TiersUnsorted);
        rejects(|t| t.tiers.push(IsolationTier::T2MicroVm), RegistrationError::TiersUnsorted);
        rejects(|t| t.hw.interconnect = None, RegistrationError::Interconnect);
        rejects(
            |t| {
                t.hw.gpus.pop();
                t.calibration.results.remove(1);
                t.attestation.clear();
            },
            RegistrationError::Interconnect,
        );
        rejects(
            |t| t.attestation[0] = AttestationReport::NvidiaGpu { gpu_index: 2, report: vec![], cert_chain: vec![] },
            RegistrationError::GpuIndex(2),
        );
        rejects(|t| t.calibration.results[0].gpu_index = 5, RegistrationError::GpuIndex(5));
        rejects(|t| t.calibration.results.swap(0, 1), RegistrationError::CalibrationUnsorted);
        rejects(|t| t.attestation_nonce_height = 101, RegistrationError::StaleNonce(101));
        rejects(|t| t.region = Region(*b"de"), RegistrationError::Region);
        rejects(|t| t.hw.gpus = vec![t.hw.gpus[0].clone(); MAX_GPUS + 1], RegistrationError::TooMany("gpus"));
        rejects(
            |t| t.attestation = vec![t.attestation[0].clone(); MAX_ATTEST + 1],
            RegistrationError::TooMany("attestation reports"),
        );
        rejects(|t| t.attestation.push(t.attestation[0].clone()), RegistrationError::DuplicateAttestation);
        let tpm = |pcrs: Vec<u8>| AttestationReport::TpmQuote {
            quote: vec![],
            signature: vec![],
            pcrs: pcrs.into_iter().map(|i| (i, [0; 32])).collect(),
            ak_cert_chain: vec![],
        };
        let mut ok = registration();
        ok.attestation.push(tpm(vec![0, 1, 2, 3, 4, 5, 6, 7, 10]));
        assert_eq!(ok.check_stateless(100), Ok(()));
        rejects(move |t| t.attestation.push(tpm(vec![0, 1, 2, 3, 4, 5, 6, 7])), RegistrationError::TpmPcrs);
        let mut old = registration();
        old.attestation_nonce_height = 90;
        assert_eq!(old.check_stateless(391), Err(RegistrationError::StaleNonce(90)));
    }

    #[test]
    fn bind_digest_covers_vrf_key_and_nonce() {
        let a = registration();
        assert_ne!(a.bind_digest(), WorkerRegistrationTx { vrf_key: [9; 32], ..a.clone() }.bind_digest());
        assert_ne!(a.bind_digest(), WorkerRegistrationTx { owner_nonce: 1, ..a.clone() }.bind_digest());
        assert_eq!(a.worker_id(), ed25519_address(&[2; 32]));
    }

    #[test]
    fn vrf_bind_input_layout() {
        let alpha = vrf_bind_input(7, &[2; 32]);
        assert_eq!(&alpha[..15], b"TOG/v1/vrf-bind");
        assert_eq!((&alpha[15..23], &alpha[23..]), (&7u64.to_le_bytes()[..], &[2; 32][..]));
        // The proof follows `vrf_key` in the transaction.
        let r = registration();
        let b = borsh::to_vec(&r).unwrap();
        let at = 8 + 20 + 8 + 32 + 64;
        assert_eq!((&b[at..at + 32], &b[at + 32..at + 112]), (&r.vrf_key[..], &r.vrf_pop.0[..]));
    }

    #[test]
    fn is_tx_variant_9() {
        let body = crate::TxBody::RegisterWorker(Box::new(registration()));
        assert_eq!(borsh::to_vec(&body).unwrap()[0], 9);
    }

    fn record() -> WorkerRecord {
        let r = registration();
        WorkerRecord {
            id: r.worker_id(),
            owner: r.owner,
            vrf_key: r.vrf_key,
            hw: r.hw,
            tiers: r.tiers,
            attestation: r.attestation,
            calibration: CalibrationResult { verified_wu_per_hour: 1_000, last_challenge: 90, passed: 1, failed: 0 },
            net: NetProfile { ingress_bps: 10_000_000_000, egress_bps: 1_000_000_000 },
            bond: 5,
            reputation: 100,
            clean_jobs: 3,
            opted_in: [ChainId(1), ChainId(2)].into(),
            status: WorkerStatus::Jailed { until: 77, fraud: true },
            region: r.region,
            region_flagged: false,
            enclave_policies: [EnclavePolicyId([9; 32])].into(),
        }
    }

    #[test]
    fn record_layout() {
        let r = record();
        let b = borsh::to_vec(&r).unwrap();
        assert_eq!(&b[..20], &r.id);
        assert_eq!(&b[20..40], &r.owner);
        assert_eq!(&b[40..72], &r.vrf_key);
        // ... region, region_flagged, then the policy set as a u32 length and its ids.
        let tail = [&b"DE"[..], &[0], &1u32.to_le_bytes(), &[9; 32]].concat();
        assert!(b.ends_with(&tail));
        // opted_in as a u32 length, ascending; then status 1 Jailed { until, fraud }.
        let sets =
            [&2u32.to_le_bytes()[..], &1u32.to_le_bytes(), &2u32.to_le_bytes(), &[1], &77u64.to_le_bytes(), &[1]]
                .concat();
        assert!(b.windows(sets.len()).any(|w| w == sets));
        assert_eq!(borsh::to_vec(&WorkerStatus::Unbonding { until: 0 }).unwrap()[0], 2);
        assert_eq!(WorkerRecord::decode(&b), Ok(r));
    }

    #[test]
    fn record_decode_is_strict() {
        let b = borsh::to_vec(&record()).unwrap();
        // The same set with its two ids swapped is not the Hub's encoding.
        let asc = [&2u32.to_le_bytes()[..], &1u32.to_le_bytes(), &2u32.to_le_bytes()].concat();
        let desc = [&2u32.to_le_bytes()[..], &2u32.to_le_bytes(), &1u32.to_le_bytes()].concat();
        let at = b.windows(asc.len()).position(|w| w == asc).unwrap();
        let mut swapped = b.clone();
        swapped[at..at + asc.len()].copy_from_slice(&desc);
        assert_eq!(WorkerRecord::decode(&swapped), Err(RecordError::Decode));

        let mut trailing = b;
        trailing.push(0);
        assert_eq!(WorkerRecord::decode(&trailing), Err(RecordError::Decode));

        let bad = |f: fn(&mut WorkerRecord), e| {
            let mut r = record();
            f(&mut r);
            assert_eq!(WorkerRecord::decode(&borsh::to_vec(&r).unwrap()), Err(e));
        };
        bad(|r| r.tiers.reverse(), RecordError::TiersNotSorted);
        bad(|r| r.tiers = vec![IsolationTier::T1Runc; 5], RecordError::TooMany("tiers"));
        bad(|r| r.attestation = vec![r.attestation[0].clone(); MAX_ATTEST + 1], RecordError::TooMany("attestation"));
        bad(|r| r.opted_in = (0..=MAX_OPT_INS as u32).map(ChainId).collect(), RecordError::TooMany("opted_in"));
        bad(
            |r| r.enclave_policies = (0..=MAX_POLICIES as u8).map(|i| EnclavePolicyId([i; 32])).collect(),
            RecordError::TooMany("enclave_policies"),
        );
    }

    #[test]
    fn clean_jobs_count() {
        let mut r = record();
        r.clean_jobs = u32::MAX;
        r.settled_clean();
        assert_eq!(r.clean_jobs, u32::MAX);
        r.slashed();
        assert_eq!(r.clean_jobs, 0);
    }
}
