//! Confidential computing (T3) objects on the Hub (TOG-SPEC-0010 §2–5): enclave
//! registration, TEE collateral, enclave policies and key derivation from `K_conf`.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Domain, Hash32, HubHeight};

use crate::job::{DriverVersion, EnclavePolicyId};
use crate::verifier::VrfProof;
use crate::worker::WorkerId;

/// Maximum age of `nonce_height` in Hub blocks (`A_nonce`, TOG-SPEC-0010 §2.2).
pub const ENCLAVE_NONCE_MAX_AGE: u64 = 300;

/// Registers a CVM's enclave key with its attestation, `TxBody` variant 12. Signed by the worker key.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegisterEnclaveTx {
    /// Registered worker.
    pub worker: WorkerId,
    /// X25519 public key of the enclave; everything sent to it is HPKE-sealed to this key.
    pub enc_key: [u8; 32],
    /// Recent Hub height whose block hash is the attestation nonce.
    pub nonce_height: u64,
    /// CPU TEE evidence.
    pub cpu_evidence: CpuEvidence,
    /// Indices into the worker's `HwSignature.gpus` attached to the CVM, strictly ascending; empty for
    /// a CPU-only enclave.
    pub gpu_indices: Vec<u8>,
    /// One per entry of `gpu_indices`, same order.
    pub gpu_evidence: Vec<GpuEvidence>,
    /// Job capacity of the CVM in logical CPUs, self-declared and unattested (TOG-SPEC-0010 §1.4 "Size").
    pub cpu_cores: u16,
    /// RAM the CVM offers jobs, which holds a job's `ram_bytes + scratch_bytes`.
    pub ram_bytes: u64,
    /// In-CVM work storage for inputs and outputs.
    pub scratch_bytes: u64,
}

/// Most live enclave records per worker (`hardware_registry.enclaves`).
pub const MAX_ENCLAVES: usize = 8;

/// A registered enclave key (TOG-SPEC-0010 §2.2). Hub state `hardware_registry.enclaves[worker]` is a
/// `Vec<EnclaveRecord>` of at most [`MAX_ENCLAVES`], ordered by `registered_at` then `enc_key`
/// (TOG-SPEC-0000 §5.1); read it with [`decode_enclaves`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EnclaveRecord {
    /// Worker.
    pub worker: WorkerId,
    /// X25519 enclave key.
    pub enc_key: [u8; 32],
    /// CPU TEE.
    pub tee: TeeKind,
    /// The guest's measurement with its launch configuration (TOG-SPEC-0010 §1.4): SNP
    /// `SHA-384(MEASUREMENT ‖ POLICY)`, or TDX `SHA-384(MRTD ‖ RTMR0..2 ‖ TD_ATTRIBUTES ‖ XFAM)`.
    pub measurement: [u8; 48],
    /// SNP `REPORTED_TCB ‖ [0; 8]`, or TDX `TEE_TCB_SVN`: one SVN component per byte.
    pub cpu_tcb: [u8; 16],
    /// One per attested GPU.
    pub gpus: Vec<GpuAttested>,
    /// Registration height.
    pub registered_at: HubHeight,
    /// `registered_at` + one era.
    pub valid_until: HubHeight,
    /// `(issuer key hash, serial)` of every non-root certificate of the CPU and GPU chains,
    /// strictly ascending; at most [`MAX_ENCLAVE_CERTS`] (TOG-SPEC-0010 §2.4).
    pub certs: Vec<(Hash32, Vec<u8>)>,
    /// From `RegisterEnclaveTx`: the CVM's job capacity, unattested (TOG-SPEC-0010 §1.4 "Size").
    pub cpu_cores: u16,
    /// From `RegisterEnclaveTx`.
    pub ram_bytes: u64,
    /// From `RegisterEnclaveTx`.
    pub scratch_bytes: u64,
    /// TDX: the PCK certificate's `CPUSVN` and `PCESVN` (TOG-SPEC-0010 §2.2 rule 2); `None` for SNP.
    pub platform_tcb: Option<([u8; 16], u16)>,
    /// SNP `PLATFORM_INFO` as in the report (bit 0: SMT enabled); 0 for TDX (TOG-SPEC-0010 §2.2
    /// rule 3).
    pub platform_info: u64,
}

/// Most entries of [`EnclaveRecord::certs`]; a registration with more is invalid.
pub const MAX_ENCLAVE_CERTS: usize = 64;

impl EnclaveRecord {
    /// Revoked (TOG-SPEC-0010 §2.4 "Revocation of records"): some `(k, s)` of `certs` has `s` in
    /// `revoked(k)` (`tee_collateral.revoked[k]`), or is in `governance`, the `revoked_serials` of
    /// every vendor.
    pub fn is_revoked<'a>(
        &self,
        revoked: impl Fn(&Hash32) -> Option<&'a [Vec<u8>]>,
        governance: &[(Hash32, Vec<u8>)],
    ) -> bool {
        self.certs.iter().any(|(k, s)| {
            revoked(k).is_some_and(|list| list.binary_search(s).is_ok())
                || governance.iter().any(|(gk, gs)| gk == k && gs == s)
        })
    }
}

/// What the Hub recorded from one GPU's report (TOG-SPEC-0010 §2.2). An enclave record lists them
/// in ascending `gpu_index`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GpuAttested {
    /// Index into the worker's `HwSignature.gpus` (PCI bus order).
    pub gpu_index: u8,
    /// PCI device id; equals `HwSignature.gpus[gpu_index].pci_device_id`.
    pub pci_device_id: u16,
    /// VBIOS version, from [`GpuAttested::parse_vbios`].
    pub vbios_version: [u8; 5],
    /// Driver version, from [`GpuAttested::parse_driver`].
    pub driver: DriverVersion,
}

impl GpuAttested {
    /// NVML's VBIOS version: five dot-separated fields of exactly two hex digits, one byte each
    /// (`"96.00.89.00.01"` → `[0x96, 0x00, 0x89, 0x00, 0x01]`). Any other shape is `None`.
    pub fn parse_vbios(s: &str) -> Option<[u8; 5]> {
        let mut out = [0u8; 5];
        let mut fields = s.split('.');
        for b in &mut out {
            let f = fields.next()?;
            if f.len() != 2 || !f.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            *b = u8::from_str_radix(f, 16).ok()?;
        }
        fields.next().is_none().then_some(out)
    }

    /// The first two dot-separated decimal fields of a driver version, each fitting `u16`
    /// (`"550.90.07"` → `(550, 90)`); further fields are dropped.
    pub fn parse_driver(s: &str) -> Option<DriverVersion> {
        let mut fields = s.split('.');
        let mut field = || {
            let f = fields.next()?;
            if f.is_empty() || !f.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            f.parse::<u16>().ok()
        };
        Some(DriverVersion { major: field()?, minor: field()? })
    }
}

/// Why a stored enclave list is not in its exact layout.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnclavesError {
    /// Bytes do not decode, or have trailing data.
    #[error("not an enclave record list")]
    Decode,
    /// More than [`MAX_ENCLAVES`].
    #[error("too many enclave records")]
    TooMany,
    /// Not strictly ordered by `(registered_at, enc_key)`.
    #[error("enclave records out of order")]
    NotSorted,
    /// A record's GPUs are not in strictly ascending `gpu_index`.
    #[error("enclave GPUs out of order")]
    GpusNotSorted,
}

/// Decodes `hardware_registry.enclaves[worker]` and checks its bound and order.
pub fn decode_enclaves(bytes: &[u8]) -> Result<Vec<EnclaveRecord>, EnclavesError> {
    let v: Vec<EnclaveRecord> = borsh::from_slice(bytes).map_err(|_| EnclavesError::Decode)?;
    if v.len() > MAX_ENCLAVES {
        return Err(EnclavesError::TooMany);
    }
    if v.windows(2).any(|w| (w[0].registered_at, w[0].enc_key) >= (w[1].registered_at, w[1].enc_key)) {
        return Err(EnclavesError::NotSorted);
    }
    if v.iter().any(|e| e.gpus.windows(2).any(|w| w[0].gpu_index >= w[1].gpu_index)) {
        return Err(EnclavesError::GpusNotSorted);
    }
    Ok(v)
}

/// CPU TEE attestation.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CpuEvidence {
    /// AMD SEV-SNP.
    SevSnp {
        /// Attestation report.
        report: Vec<u8>,
        /// VCEK → ASK certificates (the ARK is in the collateral).
        vcek_chain: Vec<Vec<u8>>,
    },
    /// Intel TDX.
    Tdx {
        /// DCAP quote v4 with its PCK chain.
        quote: Vec<u8>,
    },
}

/// NVIDIA GPU attestation in CC mode.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GpuEvidence {
    /// SPDM attestation report.
    pub report: Vec<u8>,
    /// Device certificate chain up to the NVIDIA device root.
    pub cert_chain: Vec<Vec<u8>>,
}

/// What the CVM agent returns for an evidence request (TOG-SPEC-0010 §1.3), and the executor for
/// `NodeRequest::EnclaveEvidence` (TOG-SPEC-0001 §1.2): the `RegisterEnclaveTx` fields only the
/// enclave can fill.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EnclaveEvidence {
    /// X25519 public key of the enclave.
    pub enc_key: [u8; 32],
    /// CPU TEE evidence.
    pub cpu_evidence: CpuEvidence,
    /// Indices into the worker's `HwSignature.gpus` attached to the CVM, strictly ascending, filled by
    /// the executor; empty for a CPU-only enclave.
    pub gpu_indices: Vec<u8>,
    /// One per entry of `gpu_indices`, same order.
    pub gpu_evidence: Vec<GpuEvidence>,
    /// Job capacity of the CVM in logical CPUs, self-declared and unattested (TOG-SPEC-0010 §1.4 "Size").
    pub cpu_cores: u16,
    /// RAM the CVM offers jobs, which holds a job's `ram_bytes + scratch_bytes`.
    pub ram_bytes: u64,
    /// In-CVM work storage for inputs and outputs.
    pub scratch_bytes: u64,
}

impl EnclaveEvidence {
    /// The registration transaction for `worker` with the nonce at `nonce_height`; every field is
    /// copied unchanged.
    pub fn into_tx(self, worker: WorkerId, nonce_height: u64) -> RegisterEnclaveTx {
        RegisterEnclaveTx {
            worker,
            enc_key: self.enc_key,
            nonce_height,
            cpu_evidence: self.cpu_evidence,
            gpu_indices: self.gpu_indices,
            gpu_evidence: self.gpu_evidence,
            cpu_cores: self.cpu_cores,
            ram_bytes: self.ram_bytes,
            scratch_bytes: self.scratch_bytes,
        }
    }
}

impl RegisterEnclaveTx {
    /// The CVM report's user data:
    /// `H("TOG/v1/enclave" ‖ worker ‖ enc_key ‖ hub_block_hash ‖ H(borsh(gpu_evidence)))`, where `H(borsh(…))`
    /// is the plain BLAKE3 hash of the Borsh encoding.
    pub fn report_data(&self, hub_block_hash: &Hash32) -> Hash32 {
        let gpu = blake3::hash(&borsh::to_vec(&self.gpu_evidence).expect("in-memory borsh cannot fail"));
        tagged_hash(Domain::Enclave, &[&self.worker, &self.enc_key, hub_block_hash, gpu.as_bytes()])
    }

    /// SPDM nonce of every GPU report: `H("TOG/v1/enclave-gpu" ‖ enc_key ‖ hub_block_hash)`.
    pub fn gpu_nonce(&self, hub_block_hash: &Hash32) -> Hash32 {
        tagged_hash(Domain::EnclaveGpu, &[&self.enc_key, hub_block_hash])
    }

    /// The shape part of rule 5 of TOG-SPEC-0010 §2.2: one evidence per index, indices strictly
    /// ascending and below `registered_gpus`.
    pub fn gpu_indices_ok(&self, registered_gpus: usize) -> bool {
        self.gpu_evidence.len() == self.gpu_indices.len()
            && self.gpu_indices.windows(2).all(|w| w[0] < w[1])
            && self.gpu_indices.last().map_or(true, |&i| (i as usize) < registered_gpus)
    }

    /// Rule 1 of TOG-SPEC-0010 §2.2: `nonce_height` is at most [`ENCLAVE_NONCE_MAX_AGE`] blocks old.
    pub fn nonce_is_fresh(&self, height: u64) -> bool {
        self.nonce_height <= height && height - self.nonce_height <= ENCLAVE_NONCE_MAX_AGE
    }
}

/// CPU TEE kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum TeeKind {
    /// AMD SEV-SNP.
    SevSnp,
    /// Intel TDX.
    Tdx,
}

/// Collateral vendor; ordered by Borsh index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum TeeVendor {
    /// AMD.
    Amd,
    /// Intel.
    Intel,
    /// NVIDIA.
    Nvidia,
    /// TPM vendors.
    Tpm,
}

/// Kind of collateral document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CollateralKind {
    /// Intermediate certificate.
    Certificate,
    /// Certificate revocation list.
    Crl,
    /// TCB info table.
    TcbInfo,
    /// Intel QE identity.
    QeIdentity,
    /// NVIDIA reference integrity manifest.
    Rim,
    /// OCSP response.
    Ocsp,
}

impl CollateralKind {
    /// Whether v1 accepts this kind; the others are reserved and a tx with one is invalid.
    pub fn accepted_in_v1(self) -> bool {
        matches!(self, CollateralKind::Certificate | CollateralKind::Crl)
    }
}

/// Governance reference values for NVIDIA GPUs in CC mode, `tee_collateral.gpu_references[(driver,
/// vbios)]` (TOG-SPEC-0010 §2.4).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Reference {
    /// Driver version, exactly as the report gives it.
    pub driver_version: String,
    /// VBIOS version, exactly as the report gives it.
    pub vbios_version: String,
    /// Device ids covered, strictly ascending, non-empty.
    pub pci_device_ids: Vec<u16>,
    /// Accepted values per measurement index; indices ascending, each list non-empty.
    pub measurements: Vec<(u8, Vec<Vec<u8>>)>,
}

impl Reference {
    /// Whether a report's measurements match: every listed index is present with an accepted value.
    pub fn matches(&self, report: &[(u8, Vec<u8>)]) -> bool {
        self.measurements.iter().all(|(i, ok)| report.iter().any(|(j, v)| j == i && ok.contains(v)))
    }

    /// The layout rules: device ids strictly ascending and non-empty, indices strictly ascending,
    /// each value list non-empty.
    pub fn well_formed(&self) -> bool {
        !self.pci_device_ids.is_empty()
            && self.pci_device_ids.windows(2).all(|w| w[0] < w[1])
            && self.measurements.windows(2).all(|w| w[0].0 < w[1].0)
            && self.measurements.iter().all(|(_, v)| !v.is_empty())
    }
}

/// Posts vendor-signed TEE collateral (TOG-SPEC-0010 §2.4), `TxBody` variant 13. Anyone may post;
/// the Hub accepts it only if it verifies to a root and is newer than what it holds.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TeeCollateralTx {
    /// Vendor.
    pub vendor: TeeVendor,
    /// Kind.
    pub kind: CollateralKind,
    /// The vendor document, as published.
    pub document: Vec<u8>,
}

/// Enclaves a confidential job trusts (TOG-SPEC-0010 §3). Registered by governance.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EnclavePolicy {
    /// Accepted CPU TEEs.
    pub tees: Vec<TeeKind>,
    /// Accepted TOG confidential guest releases.
    pub measurements: Vec<[u8; 48]>,
    /// Minimum TCB per TEE, per SVN component as [`EnclaveRecord::cpu_tcb`].
    pub min_cpu_tcb: Vec<(TeeKind, [u8; 16])>,
    /// Accepted GPU models (`GpuInfo.pci_device_id`); empty = any.
    pub gpu_models: Vec<u16>,
    /// Minimum GPU driver, compared as `(major, minor)`.
    pub min_gpu_driver: DriverVersion,
    /// Allowlist of worker owners; `None` = any.
    pub operators: Option<Vec<Address>>,
    /// Whether Tolerance jobs may publish sketches (TOG-SPEC-0010 §6.3).
    pub allow_sketches: bool,
    /// Minimum PCK `CPUSVN` (per component) and `PCESVN` of a `Tdx` enclave (TOG-SPEC-0010 §2.2
    /// rule 2); `None` = any.
    pub min_tdx_platform: Option<([u8; 16], u16)>,
    /// Only SEV-SNP records with SMT off (`PLATFORM_INFO` bit 0 clear); TDX reports carry no SMT
    /// state, so no TDX record satisfies a policy that sets it.
    pub require_smt_off: bool,
}

impl EnclavePolicy {
    /// `EnclavePolicyId = H("TOG/v1/enclave-policy" ‖ borsh(policy))`.
    pub fn id(&self) -> EnclavePolicyId {
        EnclavePolicyId(tagged_hash(
            Domain::EnclavePolicy,
            &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")],
        ))
    }

    /// The ordering rules governance enforces, so one policy has one id (TOG-SPEC-0010 §3):
    /// `tees`, `measurements` and `gpu_models` strictly ascending; `min_cpu_tcb` strictly ascending
    /// by TEE, each TEE in `tees`. Empty `tees` or `measurements` are the registry's own errors.
    pub fn check(&self) -> Result<(), PolicyError> {
        fn ascending<T: Ord>(v: &[T]) -> bool {
            v.windows(2).all(|w| w[0] < w[1])
        }
        if !ascending(&self.tees) {
            return Err(PolicyError::Tees);
        }
        if !ascending(&self.measurements) {
            return Err(PolicyError::Measurements);
        }
        let tcb_tees: Vec<TeeKind> = self.min_cpu_tcb.iter().map(|(t, _)| *t).collect();
        if !ascending(&tcb_tees) || !tcb_tees.iter().all(|t| self.tees.contains(t)) {
            return Err(PolicyError::MinCpuTcb);
        }
        if !ascending(&self.gpu_models) {
            return Err(PolicyError::GpuModels);
        }
        // No TDX record satisfies `require_smt_off`: such a TEE entry would be dead.
        if self.require_smt_off && self.tees.contains(&TeeKind::Tdx) {
            return Err(PolicyError::SmtOffTdx);
        }
        Ok(())
    }

    /// True if enclave `r`, whose worker is owned by `owner`, satisfies this policy at height `h`
    /// (TOG-SPEC-0010 §3). Invalidation by collateral (§2.4) is the caller's check.
    pub fn satisfies(&self, r: &EnclaveRecord, owner: &Address, h: HubHeight) -> bool {
        h <= r.valid_until
            && self.tees.contains(&r.tee)
            && self.measurements.contains(&r.measurement)
            && self.min_cpu_tcb.iter().find(|(t, _)| *t == r.tee).map_or(true, |(_, min)| tcb_ge(r.cpu_tcb, *min))
            && r.gpus.iter().all(|g| self.gpu_models.is_empty() || self.gpu_models.contains(&g.pci_device_id))
            && r.gpus.iter().all(|g| g.driver >= self.min_gpu_driver)
            && self.operators.as_ref().map_or(true, |ops| ops.contains(owner))
            && self
                .min_tdx_platform
                .map_or(true, |min| r.tee != TeeKind::Tdx || r.platform_tcb.is_some_and(|p| platform_ge(p, min)))
            && (!self.require_smt_off || (r.tee == TeeKind::SevSnp && r.platform_info & SMT_ENABLED == 0))
    }
}

/// Each of the 16 `CPUSVN` components and the `PCESVN` is at least its minimum.
fn platform_ge((cpu, pce): ([u8; 16], u16), (min_cpu, min_pce): ([u8; 16], u16)) -> bool {
    cpu.iter().zip(min_cpu.iter()).all(|(a, b)| a >= b) && pce >= min_pce
}

/// SNP `PLATFORM_INFO.SMT_EN`.
const SMT_ENABLED: u64 = 1;

/// Each of the 16 SVN bytes of the TCB is at least the minimum's byte. An integer comparison would
/// let a high component hide a low one.
fn tcb_ge(tcb: [u8; 16], min: [u8; 16]) -> bool {
    tcb.iter().zip(min.iter()).all(|(a, b)| a >= b)
}

/// An [`EnclavePolicy`] that breaks the ordering rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// `tees` empty or not strictly ascending.
    #[error("tees must be non-empty, sorted without duplicates")]
    Tees,
    /// `measurements` empty or not strictly ascending.
    #[error("measurements must be non-empty, sorted without duplicates")]
    Measurements,
    /// `min_cpu_tcb` not strictly ascending by TEE, or names a TEE not in `tees`.
    #[error("min_cpu_tcb must be sorted by TEE, one entry each, every TEE in tees")]
    MinCpuTcb,
    /// `gpu_models` not strictly ascending.
    #[error("gpu_models must be sorted without duplicates")]
    GpuModels,
    /// `require_smt_off` with `Tdx` in `tees`: TDX reports carry no SMT state.
    #[error("require_smt_off admits SEV-SNP only; drop Tdx from tees")]
    SmtOffTdx,
}

/// An enclave asks validators for their decryption shares of a job's `K_conf` identity
/// (TOG-SPEC-0010 §4.2, `Hub` broker). Sent over [`CONF_SHARE_PROTOCOL`], not on-chain.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShareRequest {
    /// Job.
    pub job_id: Hash32,
    /// The requesting enclave's registered key; shares are HPKE-sealed to it.
    pub enc_key: [u8; 32],
    /// Why this enclave's worker may have the key.
    pub role_proof: RoleProof,
    /// The worker running the enclave, whose `hardware_registry.enclaves` hold `enc_key`.
    pub worker: WorkerId,
    /// Worker key signature over [`ShareRequest::signing_digest`].
    pub sig: [u8; 64],
    /// The worker key's Ed25519 public key, not signed: Hub state keeps only its address (`worker`),
    /// so the key travels with the request (TOG-SPEC-0010 §4.2, #487).
    pub worker_key: [u8; 32],
}

/// The role a share request claims. Validators check it against Hub state; the enclave checks nothing.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RoleProof {
    /// The executor or a resumed executor: its grant is already on-chain.
    Executor,
    /// A selected verifier of `segment` in draw `draw` (0 = V3, 1 = second draw).
    Verifier {
        /// Segment.
        segment: u32,
        /// Draw.
        draw: u8,
        /// Sortition VRF proof under the worker's `vrf_key`.
        proof: VrfProof,
    },
    /// A selected juror of round `round` (1 = R1, 2 = R2) of the dispute on `segment`.
    Juror {
        /// Segment.
        segment: u32,
        /// Jury round.
        round: u8,
        /// Jury VRF proof under the worker's `vrf_key`.
        proof: VrfProof,
    },
}

impl RoleProof {
    /// The VRF proof and its alpha string `"TOG/v1/verify" ‖ worker ‖ job_id ‖ u32 segment ‖ seed`, where `seed`
    /// is the draw's seed from Hub state. `None` for the executor, which proves nothing.
    pub fn vrf_claim(&self, worker: &Address, job_id: &Hash32, seed: &Hash32) -> Option<(&VrfProof, Vec<u8>)> {
        match self {
            RoleProof::Executor => None,
            RoleProof::Verifier { segment, proof, .. } | RoleProof::Juror { segment, proof, .. } => {
                Some((proof, crate::verifier::sortition_input(worker, job_id, *segment, seed)))
            }
        }
    }

    /// Verifies the VRF proof under the worker's `vrf_key` and returns its output, whose `y` the
    /// validator then tests against the draw's threshold. `None` for the executor or a bad proof.
    pub fn vrf_output(
        &self,
        worker: &Address,
        job_id: &Hash32,
        seed: &Hash32,
        vrf_key: &[u8; 32],
    ) -> Option<crate::verifier::VrfOutput> {
        let (proof, alpha) = self.vrf_claim(worker, job_id, seed)?;
        proof.verify(vrf_key, &alpha)
    }
}

impl ShareRequest {
    /// `H("TOG/v1/share-req" ‖ borsh((job_id, enc_key, role_proof, worker)))`, what the worker key signs.
    pub fn signing_digest(&self) -> Hash32 {
        let fields = borsh::to_vec(&(&self.job_id, &self.enc_key, &self.role_proof, &self.worker))
            .expect("in-memory borsh cannot fail");
        tagged_hash(Domain::ShareReq, &[&fields])
    }

    /// Builds a request signed by the worker key, for the worker it identifies.
    pub fn new_signed(
        job_id: Hash32,
        enc_key: [u8; 32],
        role_proof: RoleProof,
        worker_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        let public_key = worker_key.verifying_key().to_bytes();
        let worker = tog_primitives::ed25519_address(&public_key);
        let mut req = ShareRequest { job_id, enc_key, role_proof, worker, sig: [0; 64], worker_key: public_key };
        req.sig = worker_key.sign(&req.signing_digest()).to_bytes();
        req
    }

    /// Whether `sig` verifies under the worker key of the enclave's registered worker (`verify_strict`).
    pub fn verify_sig(&self, worker_key: &[u8; 32]) -> bool {
        ed25519_dalek::VerifyingKey::from_bytes(worker_key).is_ok_and(|k| {
            k.verify_strict(&self.signing_digest(), &ed25519_dalek::Signature::from_bytes(&self.sig)).is_ok()
        })
    }

    /// Whether `worker_key`'s address is `worker` and `sig` verifies under it (TOG-SPEC-0010 §4.2).
    pub fn verify_worker_sig(&self) -> bool {
        tog_primitives::ed25519_address(&self.worker_key) == self.worker && self.verify_sig(&self.worker_key)
    }
}

/// `KDF(K, x₁, …) = H("TOG/v1/conf-kdf" ‖ K ‖ borsh((x₁, …)))` (TOG-SPEC-0010 §5). Pass the
/// inputs as one tuple, e.g. `(job_id, n, "ckpt")`.
pub fn conf_kdf<T: BorshSerialize>(key: &[u8; 32], inputs: &T) -> Hash32 {
    tagged_hash(Domain::ConfKdf, &[key, &borsh::to_vec(inputs).expect("in-memory borsh cannot fail")])
}

/// Length of `ConfShare.sealed`: `HPKE_Seal` of a 96-byte G2 share (TOG-SPEC-0006 §2.3.2).
pub const CONF_SHARE_SEALED_LEN: usize = 144;

/// Length of `DeliverConfKey.sealed`: `HPKE_Seal` of the 32-byte `K_conf` (TOG-SPEC-0006 §2.4).
pub const CONF_KEY_SEALED_LEN: usize = 80;

/// Largest encoded [`DeliverConfKey`] (TOG-SPEC-0006 §2.4).
pub const DELIVER_CONF_KEY_MAX: usize = 512;

/// A validator's answer to a [`ShareRequest`] on `/tog/hub/1/conf-share` (TOG-SPEC-0006 §2.3.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ConfShare {
    /// The validator's index in the era's `ValidatorSet`.
    pub index: u16,
    /// `HPKE_Seal(enc_key, "TOG/v1/conf-share" ‖ job_id, d_id,i)`, [`CONF_SHARE_SEALED_LEN`] bytes.
    pub sealed: Vec<u8>,
}

/// HPKE `info` of a validator's decryption share (TOG-SPEC-0010 §4.2 step 3): `"TOG/v1/conf-share" ‖ job_id`.
pub fn conf_share_info(job_id: &Hash32) -> Vec<u8> {
    let mut v = Domain::ConfShare.tag().as_bytes().to_vec();
    v.extend_from_slice(job_id);
    v
}

/// Protocol id of the confidential key-share protocol (TOG-SPEC-0006 §2.3.2), served by every validator on the Hub plane.
pub const CONF_SHARE_PROTOCOL: &str = "/tog/hub/1/conf-share";
/// Type byte of a [`ShareRequest`] frame.
pub const CONF_SHARE_REQUEST_TYPE: u8 = 0x01;
/// Type byte of a [`ConfShare`] frame.
pub const CONF_SHARE_RESPONSE_TYPE: u8 = 0x81;
/// Largest request frame (TOG-SPEC-0006 §2.3.2).
pub const CONF_SHARE_MAX_REQUEST: usize = 4 * 1024;
/// Largest response frame (TOG-SPEC-0006 §2.3.2).
pub const CONF_SHARE_MAX_RESPONSE: usize = 1024;
/// Requests per second a validator accepts from one peer (TOG-SPEC-0006 §2.3.2).
pub const CONF_SHARE_REQUESTS_PER_SEC: u32 = 10;
/// How many times a validator answers one `(job_id, enc_key, role_proof)` (TOG-SPEC-0010 §4.2).
pub const CONF_SHARE_MAX_ANSWERS: u32 = 3;
/// How long `togd`'s fan-out waits for the validators, in milliseconds (TOG-SPEC-0006 §2.3.2).
pub const CONF_SHARE_FAN_OUT_TIMEOUT_MS: u64 = 10_000;
/// Most fan-outs `togd` makes of one `ShareRequest` before the run fails as a node fault
/// (TOG-SPEC-0010 §4.2 "Retries").
pub const CONF_SHARE_FAN_OUTS: u32 = 3;
/// Hub blocks from one fan-out's start before the next may start (TOG-SPEC-0010 §4.2 "Retries").
pub const CONF_SHARE_RETRY_BLOCKS: u64 = 3;

fn conf_share_message(ty: u8, body: &impl BorshSerialize) -> Vec<u8> {
    let mut out = vec![ty];
    body.serialize(&mut out).expect("in-memory borsh cannot fail");
    out
}

impl ShareRequest {
    /// The frame body: `0x01` then Borsh (TOG-SPEC-0006 §2.3.2, §8).
    pub fn encode_frame(&self) -> Vec<u8> {
        conf_share_message(CONF_SHARE_REQUEST_TYPE, self)
    }

    /// A request frame's body, if it is exactly a `ShareRequest` within [`CONF_SHARE_MAX_REQUEST`].
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        if msg.len() > CONF_SHARE_MAX_REQUEST {
            return None;
        }
        match msg.split_first() {
            Some((&CONF_SHARE_REQUEST_TYPE, body)) => borsh::from_slice(body).ok(),
            _ => None,
        }
    }

    /// What a validator counts its answers by: `(job_id, enc_key, role_proof)` (TOG-SPEC-0010 §4.2).
    pub fn answer_key(&self) -> (Hash32, [u8; 32], &RoleProof) {
        (self.job_id, self.enc_key, &self.role_proof)
    }
}

impl ConfShare {
    /// The frame body: `0x81` then Borsh (TOG-SPEC-0006 §2.3.2, §8).
    pub fn encode_frame(&self) -> Vec<u8> {
        conf_share_message(CONF_SHARE_RESPONSE_TYPE, self)
    }

    /// A response frame's body, if it is exactly a `ConfShare` within [`CONF_SHARE_MAX_RESPONSE`] whose
    /// sealed share is [`CONF_SHARE_SEALED_LEN`] bytes.
    pub fn decode_frame(msg: &[u8]) -> Option<Self> {
        if msg.len() > CONF_SHARE_MAX_RESPONSE {
            return None;
        }
        match msg.split_first() {
            Some((&CONF_SHARE_RESPONSE_TYPE, body)) => {
                borsh::from_slice::<ConfShare>(body).ok().filter(|s| s.sealed.len() == CONF_SHARE_SEALED_LEN)
            }
            _ => None,
        }
    }
}

/// `TxBody` variant 41 (user lane), signed by `job.sender`: the on-chain fallback of a
/// `Sender` broker's [`DeliverConfKey`] (TOG-SPEC-0010 §4.3). Written to
/// `compute_market.conf_keys[(job_id, enc_key)]`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeliverConfKeyTx {
    /// Replay domain.
    pub chain_id: u64,
    /// The job's sender; the signer.
    pub sender: Address,
    /// The sender's next nonce.
    pub nonce: u64,
    /// Job.
    pub job_id: Hash32,
    /// A registered enclave key.
    pub enc_key: [u8; 32],
    /// `HPKE_Seal(enc_key, "TOG/v1/conf-key" ‖ job_id, K_conf)`.
    pub sealed: [u8; CONF_KEY_SEALED_LEN],
}

/// Largest encoded [`ConfKeyRequest`] (TOG-SPEC-0006 §2.4).
pub const CONF_KEY_REQUEST_MAX: usize = 512;
/// Largest `ConfKeyRequest.sealed`.
pub const CONF_KEY_REQUEST_SEALED_MAX: usize = 480;
/// Gossip topic of [`ConfKeyRequest`]s.
pub const CONF_KEY_REQ_TOPIC: &str = "/tog/grid/1/conf-key-req";

/// A verifier's or juror's request for `K_conf` to a `Sender` broker, gossiped on
/// `/tog/grid/1/conf-key-req` (TOG-SPEC-0010 §4.3, TOG-SPEC-0006 §2.4).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ConfKeyRequest {
    /// Job.
    pub job_id: Hash32,
    /// `HPKE_Seal(request_key, "TOG/v1/conf-key-req" ‖ job_id, borsh(ShareRequest))`, at most
    /// [`CONF_KEY_REQUEST_SEALED_MAX`] bytes.
    pub sealed: Vec<u8>,
}

impl ConfKeyRequest {
    /// Decodes a gossiped request with the stateless checks a forwarding peer makes: exact
    /// decoding within [`CONF_KEY_REQUEST_MAX`] and the sealed length.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > CONF_KEY_REQUEST_MAX {
            return None;
        }
        borsh::from_slice::<Self>(bytes).ok().filter(|r| r.sealed.len() <= CONF_KEY_REQUEST_SEALED_MAX)
    }
}

/// A `Sender` broker's `K_conf` for one enclave, gossiped on `/tog/grid/1/conf-key` (TOG-SPEC-0010
/// §4.3, TOG-SPEC-0006 §2.4).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeliverConfKey {
    /// Job.
    pub job_id: Hash32,
    /// The granted enclave's key.
    pub enc_key: [u8; 32],
    /// `HPKE_Seal(enc_key, "TOG/v1/conf-key" ‖ job_id, K_conf)`, [`CONF_KEY_SEALED_LEN`] bytes.
    pub sealed: Vec<u8>,
    /// The job sender's signature over [`DeliverConfKey::digest`]; never EIP-712.
    pub sig: crate::tx::Signature,
}

impl DeliverConfKey {
    /// `H("TOG/v1/deliver-conf-key" ‖ job_id ‖ enc_key ‖ sealed)`.
    pub fn digest(job_id: &Hash32, enc_key: &[u8; 32], sealed: &[u8]) -> Hash32 {
        tagged_hash(Domain::DeliverConfKey, &[job_id, enc_key, sealed])
    }

    /// Decodes a gossiped message and runs the stateless checks every peer makes before
    /// forwarding: exact decoding within [`DELIVER_CONF_KEY_MAX`], the sealed length, and a well-formed
    /// signature of variant 0 or 1.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > DELIVER_CONF_KEY_MAX {
            return None;
        }
        let msg: Self = borsh::from_slice(bytes).ok()?;
        let variant_ok = !matches!(msg.sig, crate::tx::Signature::Secp256k1Eip712(_));
        (msg.sealed.len() == CONF_KEY_SEALED_LEN && variant_ok && msg.sig.well_formed()).then_some(msg)
    }

    /// The signer's address; the receiver compares it with the job's `sender`.
    pub fn signer(&self) -> Result<Address, crate::signing::SignatureError> {
        if matches!(self.sig, crate::tx::Signature::Secp256k1Eip712(_)) {
            return Err(crate::signing::SignatureError::Malformed);
        }
        self.sig.verify(&Self::digest(&self.job_id, &self.enc_key, &self.sealed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> RegisterEnclaveTx {
        RegisterEnclaveTx {
            worker: [1; 20],
            enc_key: [2; 32],
            nonce_height: 100,
            cpu_evidence: CpuEvidence::Tdx { quote: vec![3] },
            gpu_indices: vec![0],
            gpu_evidence: vec![GpuEvidence { report: vec![4], cert_chain: vec![] }],
            cpu_cores: 8,
            ram_bytes: 32 << 30,
            scratch_bytes: 64 << 30,
        }
    }

    #[test]
    fn gpu_indices_shape() {
        let mut t = tx();
        assert!(t.gpu_indices_ok(1) && !t.gpu_indices_ok(0));
        t.gpu_indices = vec![2, 2];
        t.gpu_evidence.push(t.gpu_evidence[0].clone());
        assert!(!t.gpu_indices_ok(4));
        t.gpu_indices = vec![1, 3];
        assert!(t.gpu_indices_ok(4));
        t.gpu_indices.pop();
        assert!(!t.gpu_indices_ok(4));
        // Borsh puts gpu_indices before gpu_evidence, then the capacity: u16 cores, u64 RAM, u64 scratch.
        let b = borsh::to_vec(&tx()).unwrap();
        let ev = borsh::to_vec(&tx().gpu_evidence).unwrap();
        let (cap, ev_end) = (b.len() - 18, b.len() - 18 - ev.len());
        assert_eq!(&b[ev_end - 5..ev_end], &[1, 0, 0, 0, 0]);
        let capacity =
            [8u16.to_le_bytes().as_slice(), &(32u64 << 30).to_le_bytes(), &(64u64 << 30).to_le_bytes()].concat();
        assert_eq!(&b[cap..], &capacity[..]);
    }

    #[test]
    fn references_match_every_listed_index() {
        let r = Reference {
            driver_version: "550.54".into(),
            vbios_version: "96.00".into(),
            pci_device_ids: vec![0x2330, 0x2331],
            measurements: vec![(1, vec![vec![1], vec![2]]), (4, vec![vec![9]])],
        };
        assert!(r.well_formed());
        assert!(r.matches(&[(1, vec![2]), (3, vec![0]), (4, vec![9])]));
        assert!(!r.matches(&[(1, vec![2])]));
        assert!(!r.matches(&[(1, vec![3]), (4, vec![9])]));
        assert!(!Reference { pci_device_ids: vec![], ..r.clone() }.well_formed());
        assert!(!Reference { measurements: vec![(4, vec![vec![1]]), (1, vec![vec![1]])], ..r }.well_formed());
        assert!(CollateralKind::Crl.accepted_in_v1() && !CollateralKind::Rim.accepted_in_v1());
        assert!(TeeVendor::Amd < TeeVendor::Tpm);
    }

    #[test]
    fn report_data_binds_gpu_evidence_and_nonce() {
        let a = tx();
        let mut b = tx();
        b.gpu_evidence[0].report = vec![5];
        assert_ne!(a.report_data(&[0; 32]), b.report_data(&[0; 32]));
        assert_ne!(a.report_data(&[0; 32]), a.report_data(&[1; 32]));
        // The GPU nonce binds the enclave key, not the worker.
        assert_eq!(a.gpu_nonce(&[0; 32]), RegisterEnclaveTx { worker: [9; 20], ..a.clone() }.gpu_nonce(&[0; 32]));
        assert_ne!(a.gpu_nonce(&[0; 32]), RegisterEnclaveTx { enc_key: [9; 32], ..a }.gpu_nonce(&[0; 32]));
    }

    #[test]
    fn nonce_age() {
        let t = tx();
        assert!(t.nonce_is_fresh(100));
        assert!(t.nonce_is_fresh(400));
        assert!(!t.nonce_is_fresh(401));
        assert!(!t.nonce_is_fresh(99));
    }

    #[test]
    fn kdf_separates_objects() {
        let k = [7; 32];
        let job = [1u8; 32];
        assert_ne!(conf_kdf(&k, &(job, 3u32, "ckpt")), conf_kdf(&k, &(job, 3u32, "metrics")));
        assert_ne!(conf_kdf(&k, &(job, 3u32, "ckpt")), conf_kdf(&k, &(job, 4u32, "ckpt")));
    }

    #[test]
    fn share_request_signature_binds_every_field() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let pk = key.verifying_key().to_bytes();
        let role = RoleProof::Verifier { segment: 3, draw: 0, proof: VrfProof([1; 80]) };
        let req = ShareRequest::new_signed([1; 32], [2; 32], role, &key);
        assert!(req.verify_sig(&pk));
        assert!(!req.verify_sig(&[9; 32]));
        assert!(!ShareRequest { enc_key: [3; 32], ..req.clone() }.verify_sig(&pk));
        let juror = RoleProof::Juror { segment: 3, round: 1, proof: VrfProof([1; 80]) };
        assert!(!ShareRequest { role_proof: juror, ..req.clone() }.verify_sig(&pk));
        assert_eq!(borsh::to_vec(&RoleProof::Executor).unwrap(), [0]);

        // `worker_key` is carried, not signed; its address must be `worker`.
        assert_eq!(req.worker_key, pk);
        assert!(req.verify_worker_sig());
        let other = ed25519_dalek::SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
        let swapped = ShareRequest { worker_key: other, ..req.clone() };
        assert_eq!(swapped.signing_digest(), req.signing_digest());
        assert!(!swapped.verify_worker_sig());
        let resigned = ShareRequest::new_signed([1; 32], [2; 32], RoleProof::Executor, &key);
        assert!(!ShareRequest { worker: [7; 20], ..resigned }.verify_worker_sig());
    }

    #[test]
    fn role_proof_vrf_input() {
        let w = [5; 20];
        assert_eq!(RoleProof::Executor.vrf_claim(&w, &[1; 32], &[2; 32]), None);
        let role = RoleProof::Juror { segment: 7, round: 2, proof: VrfProof([4; 80]) };
        let (proof, alpha) = role.vrf_claim(&w, &[1; 32], &[2; 32]).unwrap();
        assert_eq!(proof, &VrfProof([4; 80]));
        assert_eq!(alpha, crate::verifier::sortition_input(&w, &[1; 32], 7, &[2; 32]));

        let seed_key = [8u8; 32];
        let vrf_key = tog_primitives::ecvrf::public_key(&seed_key);
        let proof = VrfProof::prove(&seed_key, &crate::verifier::sortition_input(&w, &[1; 32], 7, &[2; 32]));
        let role = RoleProof::Verifier { segment: 7, draw: 0, proof };
        assert!(role.vrf_output(&w, &[1; 32], &[2; 32], &vrf_key).is_some());
        assert!(role.vrf_output(&w, &[1; 32], &[3; 32], &vrf_key).is_none());
        assert!(role.vrf_output(&[6; 20], &[1; 32], &[2; 32], &vrf_key).is_none(), "another worker's proof");
    }

    #[test]
    fn tx_variants_12_and_13() {
        let first = |b: crate::TxBody| borsh::to_vec(&b).unwrap()[0];
        assert_eq!(first(crate::TxBody::RegisterEnclave(Box::new(tx()))), 12);
        let c = TeeCollateralTx { vendor: TeeVendor::Amd, kind: CollateralKind::Crl, document: vec![] };
        assert_eq!(first(crate::TxBody::PostTeeCollateral(c)), 13);
    }

    /// A TCB of the leading SVN components `svns`, the rest 0.
    fn tcb(svns: &[u8]) -> [u8; 16] {
        let mut t = [0; 16];
        t[..svns.len()].copy_from_slice(svns);
        t
    }

    fn record(registered_at: u64, enc_key: u8) -> EnclaveRecord {
        EnclaveRecord {
            worker: [1; 20],
            enc_key: [enc_key; 32],
            tee: TeeKind::SevSnp,
            measurement: [3; 48],
            cpu_tcb: tcb(&[7]),
            gpus: vec![GpuAttested {
                gpu_index: 0,
                pci_device_id: 0x2330,
                vbios_version: [0x96, 0, 0x89, 0, 1],
                driver: DriverVersion { major: 550, minor: 54 },
            }],
            registered_at,
            valid_until: registered_at + 100,
            certs: vec![([4; 32], vec![1, 2])],
            cpu_cores: 8,
            ram_bytes: 32 << 30,
            scratch_bytes: 64 << 30,
            platform_tcb: None,
            platform_info: 0,
        }
    }

    #[test]
    fn a_record_is_revoked_by_a_crl_or_by_governance() {
        let r = record(1, 2);
        let crl = vec![vec![1, 1], vec![1, 2]];
        assert!(r.is_revoked(|k| (*k == [4; 32]).then_some(crl.as_slice()), &[]));
        assert!(!r.is_revoked(|k| (*k == [5; 32]).then_some(crl.as_slice()), &[]));
        assert!(r.is_revoked(|_| None, &[([4; 32], vec![1, 2])]));
        assert!(!r.is_revoked(|_| None, &[([5; 32], vec![1, 2])]));
        let bytes = borsh::to_vec(&r).unwrap();
        // certs, then the capacity (18 bytes), `platform_tcb: None` (1 byte) and `platform_info`
        // (8 bytes): u32 count, issuer, u32 length, serial.
        let bytes = &bytes[..bytes.len() - 27];
        assert_eq!(
            &bytes[bytes.len() - 42..],
            &[[1, 0, 0, 0].as_slice(), &[4; 32], &[2, 0, 0, 0], &[1, 2]].concat()[..]
        );
    }

    #[test]
    fn enclave_list_order_and_bound() {
        let ok = vec![record(5, 9), record(6, 1), record(6, 2)];
        assert_eq!(decode_enclaves(&borsh::to_vec(&ok).unwrap()), Ok(ok));
        let dup = vec![record(6, 1), record(6, 1)];
        assert_eq!(decode_enclaves(&borsh::to_vec(&dup).unwrap()), Err(EnclavesError::NotSorted));
        let back = vec![record(6, 1), record(5, 9)];
        assert_eq!(decode_enclaves(&borsh::to_vec(&back).unwrap()), Err(EnclavesError::NotSorted));
        let many: Vec<_> = (0..=MAX_ENCLAVES as u64).map(|h| record(h, 0)).collect();
        assert_eq!(decode_enclaves(&borsh::to_vec(&many).unwrap()), Err(EnclavesError::TooMany));
        assert_eq!(decode_enclaves(&[1]), Err(EnclavesError::Decode));
        let mut gpus = record(5, 9);
        gpus.gpus.push(gpus.gpus[0].clone());
        assert_eq!(decode_enclaves(&borsh::to_vec(&vec![gpus]).unwrap()), Err(EnclavesError::GpusNotSorted));
    }

    #[test]
    fn gpu_version_strings() {
        assert_eq!(GpuAttested::parse_vbios("96.00.89.00.01"), Some([0x96, 0, 0x89, 0, 1]));
        assert_eq!(GpuAttested::parse_vbios("86.04.5D.00.01"), Some([0x86, 4, 0x5d, 0, 1]));
        for bad in ["96.00.89.00", "96.00.89.00.01.02", "96.0.89.00.01", "96.00.8G.00.01", "+6.00.89.00.01", ""] {
            assert_eq!(GpuAttested::parse_vbios(bad), None, "{bad}");
        }
        assert_eq!(GpuAttested::parse_driver("550.90.07"), Some(DriverVersion { major: 550, minor: 90 }));
        assert_eq!(GpuAttested::parse_driver("535.104"), Some(DriverVersion { major: 535, minor: 104 }));
        for bad in ["550", "550.", "70000.1", "550.x", "+550.90", ".90"] {
            assert_eq!(GpuAttested::parse_driver(bad), None, "{bad}");
        }
    }

    fn policy() -> EnclavePolicy {
        EnclavePolicy {
            tees: vec![TeeKind::SevSnp, TeeKind::Tdx],
            measurements: vec![[3; 48], [4; 48]],
            min_cpu_tcb: vec![(TeeKind::SevSnp, tcb(&[5, 1]))],
            gpu_models: vec![0x2330, 0x2335],
            min_gpu_driver: DriverVersion { major: 550, minor: 54 },
            operators: None,
            allow_sketches: false,
            min_tdx_platform: None,
            require_smt_off: false,
        }
    }

    #[test]
    fn policy_ordering_rules() {
        assert_eq!(policy().check(), Ok(()));
        let bad = |f: fn(&mut EnclavePolicy)| {
            let mut p = policy();
            f(&mut p);
            p.check()
        };
        assert_eq!(bad(|p| p.tees.reverse()), Err(PolicyError::Tees));
        assert_eq!(bad(|p| p.measurements[1] = [3; 48]), Err(PolicyError::Measurements));
        assert_eq!(bad(|p| p.min_cpu_tcb.push((TeeKind::SevSnp, tcb(&[1])))), Err(PolicyError::MinCpuTcb));
        assert_eq!(
            bad(|p| {
                p.tees = vec![TeeKind::SevSnp];
                p.min_cpu_tcb = vec![(TeeKind::Tdx, tcb(&[1]))];
            }),
            Err(PolicyError::MinCpuTcb)
        );
        assert_eq!(bad(|p| p.gpu_models.reverse()), Err(PolicyError::GpuModels));
        assert_eq!(bad(|p| p.require_smt_off = true), Err(PolicyError::SmtOffTdx));
        let snp_only = |p: &mut EnclavePolicy| {
            p.require_smt_off = true;
            p.tees = vec![TeeKind::SevSnp];
        };
        assert_eq!(bad(snp_only), Ok(()));
        let driver = borsh::to_vec(&DriverVersion { major: 550, minor: 54 }).unwrap();
        assert!(borsh::to_vec(&policy()).unwrap().windows(4).any(|w| w == driver));
    }

    #[test]
    fn policy_satisfaction() {
        let mut r = record(5, 9);
        r.cpu_tcb = tcb(&[5, 2]);
        let p = policy();
        assert!(p.satisfies(&r, &[0; 20], 105));
        assert!(!p.satisfies(&r, &[0; 20], 106), "expired");

        // TCB components compare one by one: a higher byte does not hide a lower one.
        let low = EnclaveRecord { cpu_tcb: tcb(&[4, 3]), ..r.clone() };
        assert!(!p.satisfies(&low, &[0; 20], 10));
        // All 16 components count, TDX's upper half included.
        let p16 = EnclavePolicy { min_cpu_tcb: vec![(TeeKind::SevSnp, [1; 16])], ..policy() };
        assert!(!p16.satisfies(&EnclaveRecord { cpu_tcb: tcb(&[1; 15]), ..r.clone() }, &[0; 20], 10));
        assert!(p16.satisfies(&EnclaveRecord { cpu_tcb: [1; 16], ..r.clone() }, &[0; 20], 10));
        // SMT off only when the policy asks, and only SNP reports say.
        let smt_off = EnclavePolicy { require_smt_off: true, ..policy() };
        assert!(!smt_off.satisfies(&EnclaveRecord { platform_info: 1, ..r.clone() }, &[0; 20], 10));
        assert!(smt_off.satisfies(&EnclaveRecord { platform_info: 2, ..r.clone() }, &[0; 20], 10));
        // A TEE without a minimum is allowed if listed.
        let tdx = EnclaveRecord { tee: TeeKind::Tdx, cpu_tcb: [0; 16], ..r.clone() };
        assert!(p.satisfies(&tdx, &[0; 20], 10));
        assert!(!EnclavePolicy { tees: vec![TeeKind::SevSnp], min_cpu_tcb: vec![], ..policy() }
            .satisfies(&tdx, &[0; 20], 10));
        assert!(!EnclavePolicy { require_smt_off: true, ..policy() }.satisfies(&tdx, &[0; 20], 10), "no SMT state");

        let other = EnclaveRecord { measurement: [5; 48], ..r.clone() };
        assert!(!p.satisfies(&other, &[0; 20], 10));

        let mut old = r.clone();
        old.gpus[0].driver = DriverVersion { major: 550, minor: 53 };
        assert!(!p.satisfies(&old, &[0; 20], 10));
        let mut newer = r.clone();
        newer.gpus[0].driver = DriverVersion { major: 551, minor: 0 };
        assert!(p.satisfies(&newer, &[0; 20], 10));

        let mut model = r.clone();
        model.gpus[0].pci_device_id = 0x1234;
        assert!(!p.satisfies(&model, &[0; 20], 10));
        assert!(EnclavePolicy { gpu_models: vec![], ..policy() }.satisfies(&model, &[0; 20], 10));

        let ops = EnclavePolicy { operators: Some(vec![[7; 20]]), ..policy() };
        assert!(ops.satisfies(&r, &[7; 20], 10) && !ops.satisfies(&r, &[0; 20], 10));
    }

    #[test]
    fn deliver_conf_key_checks() {
        use crate::tx::Signature;
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let (job_id, enc_key, sealed) = ([1; 32], [2; 32], vec![3; CONF_KEY_SEALED_LEN]);
        let sig = key.sign(&DeliverConfKey::digest(&job_id, &enc_key, &sealed)).to_bytes();
        let public_key = key.verifying_key().to_bytes();
        let msg = DeliverConfKey { job_id, enc_key, sealed, sig: Signature::Ed25519 { public_key, sig } };
        let bytes = borsh::to_vec(&msg).unwrap();
        assert_eq!(DeliverConfKey::decode(&bytes), Some(msg.clone()));
        assert_eq!(msg.signer(), Ok(tog_primitives::ed25519_address(&public_key)));

        let mut short = msg.clone();
        short.sealed.pop();
        assert_eq!(DeliverConfKey::decode(&borsh::to_vec(&short).unwrap()), None);
        let mut eip = msg.clone();
        eip.sig = Signature::Secp256k1Eip712([1; 65]);
        assert_eq!(DeliverConfKey::decode(&borsh::to_vec(&eip).unwrap()), None);
        let mut bad_v = msg.clone();
        let mut v5 = [1; 65];
        v5[64] = 5;
        bad_v.sig = Signature::Secp256k1(v5);
        assert_eq!(DeliverConfKey::decode(&borsh::to_vec(&bad_v).unwrap()), None);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(DeliverConfKey::decode(&trailing), None);
        let mut forged = msg;
        forged.enc_key = [9; 32];
        assert_ne!(forged.signer(), Ok(tog_primitives::ed25519_address(&public_key)));
    }

    #[test]
    fn conf_share_frames() {
        let req = ShareRequest {
            job_id: [1; 32],
            enc_key: [2; 32],
            role_proof: RoleProof::Executor,
            worker: [4; 20],
            sig: [3; 64],
            worker_key: [5; 32],
        };
        let frame = req.encode_frame();
        assert_eq!(frame[0], 0x01);
        assert_eq!(ShareRequest::decode_frame(&frame), Some(req.clone()));
        assert_eq!(ConfShare::decode_frame(&frame), None);
        let mut long = frame.clone();
        long.resize(CONF_SHARE_MAX_REQUEST + 1, 0);
        assert_eq!(ShareRequest::decode_frame(&long), None);

        let share = ConfShare { index: 7, sealed: vec![9; CONF_SHARE_SEALED_LEN] };
        let frame = share.encode_frame();
        assert_eq!(frame[0], 0x81);
        assert_eq!(ConfShare::decode_frame(&frame), Some(share));
        let short = ConfShare { index: 7, sealed: vec![9; CONF_SHARE_SEALED_LEN - 1] }.encode_frame();
        assert_eq!(ConfShare::decode_frame(&short), None);
        assert_eq!(ShareRequest::decode_frame(&frame), None);

        let mut info = b"TOG/v1/conf-share".to_vec();
        info.extend_from_slice(&[5; 32]);
        assert_eq!(conf_share_info(&[5; 32]), info);
    }

    #[test]
    fn a_tdx_platform_meets_a_minimum_component_by_component() {
        let (mut r, owner) = (record(0, 1), [9; 20]);
        r.tee = TeeKind::Tdx;
        let mut p = policy();
        p.tees = vec![TeeKind::Tdx];
        p.measurements = vec![r.measurement];
        p.min_cpu_tcb = vec![];
        assert!(p.satisfies(&r, &owner, 0), "no minimum");
        let mut min = [1u8; 16];
        p.min_tdx_platform = Some((min, 3));
        assert!(!p.satisfies(&r, &owner, 0), "no recorded platform");
        let mut cpu = [2u8; 16];
        r.platform_tcb = Some((cpu, 3));
        assert!(p.satisfies(&r, &owner, 0));
        cpu[15] = 0;
        r.platform_tcb = Some((cpu, 3));
        assert!(!p.satisfies(&r, &owner, 0), "one low component");
        min[15] = 0;
        p.min_tdx_platform = Some((min, 4));
        assert!(!p.satisfies(&r, &owner, 0), "low PCESVN");
        r.tee = TeeKind::SevSnp;
        p.tees = vec![TeeKind::SevSnp];
        assert!(p.satisfies(&r, &owner, 0), "SNP has no platform minimum");
    }
}
