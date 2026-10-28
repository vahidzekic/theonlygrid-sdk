//! `JobTx` and the types it is built from (TOG-SPEC-0001 §3.2).

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Amount, ChainId, Domain, Hash32};

use crate::payload::PayloadCommitment;

/// Hub escrow that funds a job's `max_budget` (TOG-SPEC-0000 §13.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct EscrowRef(pub Hash32);

impl EscrowRef {
    /// `H("TOG/v1/escrow" ‖ borsh(origin))`, known to the requester before the Hub replies.
    pub fn derive(origin: &EscrowOrigin) -> Self {
        Self(tagged_hash(Domain::Escrow, &[&borsh::to_vec(origin).expect("in-memory borsh cannot fail")]))
    }
}

/// What opened an escrow.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum EscrowOrigin {
    /// A CGMP message; `index` is its position among the escrows that message opened.
    Cgmp {
        /// Source chain.
        source: ChainId,
        /// Message nonce on its channel.
        channel_nonce: u64,
        /// Position within the message.
        index: u16,
    },
    /// A Hub transaction.
    HubTx {
        /// Signer.
        sender: Address,
        /// Signer nonce.
        nonce: u64,
    },
}

/// Module of an AppChain runtime (TOG-SPEC-0007 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct ModuleId(pub [u8; 16]);

/// CGMP route on which the Hub delivers `ComputeResult` (TOG-SPEC-0000 §7.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CallbackRef {
    /// Chain that receives the result.
    pub chain: ChainId,
    /// Module on that chain that handles it.
    pub module: ModuleId,
    /// Call index inside the module.
    pub call: u16,
}

/// Verification module registered on the Hub (TOG-SPEC-0000 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct VerificationModuleId(pub [u8; 16]);

/// Hash of a governance-registered toolchain bundle (TOG-SPEC-0001 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct ToolchainProfileId(pub Hash32);

/// Enclave policy for confidential (T3) jobs (TOG-SPEC-0004 §9.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct EnclavePolicyId(pub Hash32);

/// A job as the Hub stores it (TOG-SPEC-0001 §3.2, §3.5). Submitted directly as a Hub
/// transaction, or built by the Hub from a CGMP `ComputeRequest`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct JobTx {
    // ---- replay protection / accounting ----
    /// Replay domain: `network_id << 32` (the Hub), TOG-SPEC-0000 §13.2.
    pub chain_id: u64,
    /// Paying account, or the origin chain's sovereign address for CGMP jobs.
    pub sender: Address,
    /// Sender account nonce, or the CGMP `channel_nonce`.
    pub nonce: u64,
    /// The transaction leaves the mempool after this height.
    pub valid_until_height: u64,

    // ---- Layer 0 routing supplied by the submitter ----
    /// AppChain (or the Hub) that requested the job.
    pub origin: ChainId,
    /// Hub escrow that funds `max_budget`.
    pub escrow: EscrowRef,
    /// CGMP route for `ComputeResult`.
    pub callback: Option<CallbackRef>,

    /// The job itself, identical to what an AppChain sends via CGMP.
    pub spec: JobSpec,
}

impl JobTx {
    /// `job_id = H("TOG/v1/job_id" ‖ borsh(self))`; binds every field, the routing included.
    pub fn job_id(&self) -> Hash32 {
        tagged_hash(Domain::JobId, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }
}

/// Everything about a job that does not depend on how it was submitted
/// (CGMP `ComputeRequest`, TOG-SPEC-0000 §7.2; SDK, TOG-SPEC-0007 §7.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct JobSpec {
    /// Worker set whose rules decide eligibility.
    pub worker_set: ChainId,
    /// Verification module registered on the Hub.
    pub verification_module: VerificationModuleId,

    // ---- WHAT to run ----
    /// Container image.
    pub image: ImageRef,
    /// Entrypoint, arguments and environment.
    pub command: CommandSpec,
    /// Read-only inputs, sorted by `mount_name`.
    pub inputs: Vec<InputRef>,
    /// Pinned CUDA/cuDNN/driver bundle.
    pub toolchain: ToolchainProfileId,
    /// What the result is and how long it is kept.
    pub outputs: OutputSpec,

    // ---- WHERE it can run ----
    /// Hardware the job needs.
    pub hw: HardwareRequirements,
    /// Weakest sandbox the sender accepts.
    pub min_isolation: IsolationTier,

    // ---- HOW it is verified ----
    /// Reproducibility class.
    pub determinism: DeterminismClass,
    /// Verification parameters.
    pub verification: VerificationPolicy,
    /// Required for long jobs.
    pub segmentation: Option<SegmentationSpec>,

    // ---- limits & economics ----
    /// Time budget.
    pub limits: ResourceLimits,
    /// Fees and escrow.
    pub fee: FeeSpec,

    // ---- optional confidentiality ----
    /// Requires `IsolationTier::T3Confidential`.
    pub confidential: Option<ConfidentialSpec>,
}

/// Content-addressed OCI image.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ImageRef {
    /// OCI manifest sha256: the root of trust.
    pub manifest_digest: [u8; 32],
    /// Target platform.
    pub platform: Platform,
    /// Compressed size in bytes; must equal the sum of `blobs[i].size`.
    pub total_size: u64,
    /// One payload per OCI blob (TOG-SPEC-0004 §2.3): manifest, config, then layers in
    /// manifest order. Each has kind `Image` and an `oci_digest`; `blobs[0]`'s is `manifest_digest`.
    pub blobs: Vec<PayloadCommitment>,
    /// Deal holding the blobs; `None` = fetched through locators only.
    pub deal: Option<DealId>,
    /// Hints only; never trusted.
    pub locators: Vec<Locator>,
}

/// A storage deal on the Hub (TOG-SPEC-0004 §11). Assigned in opening order, never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct DealId(pub u64);

/// A payload and, optionally, the deal that stores it (TOG-SPEC-0004 §2.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PayloadRef {
    /// The content.
    pub payload: PayloadCommitment,
    /// Deal storing it, if any.
    pub deal: Option<DealId>,
}

/// OCI platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Platform {
    /// linux/amd64
    LinuxAmd64,
    /// linux/arm64
    LinuxArm64,
}

/// Where an artifact may be fetched from. The content hash is always verified.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Locator {
    /// CAR of an OCI image layout, or a file.
    Ipfs {
        /// Raw CID bytes.
        cid: Vec<u8>,
    },
    /// Arweave transaction.
    Arweave {
        /// Transaction id.
        tx_id: [u8; 32],
    },
    /// Plain HTTPS.
    Https {
        /// URL.
        url: String,
    },
}

/// Command to run in the container.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CommandSpec {
    /// Overrides the image entrypoint; empty means the image default.
    pub entrypoint: Vec<String>,
    /// Arguments.
    pub args: Vec<String>,
    /// Environment, sorted by key; `TOG_*` keys are reserved.
    pub env: Vec<(String, String)>,
    /// Working directory.
    pub workdir: Option<String>,
}

/// A read-only input mounted at `/in/<mount_name>`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct InputRef {
    /// Mount name under `/in`.
    pub mount_name: String,
    /// Kind `Input`; `root` is the BLAKE3 root of a TDA v1 archive of the input directory (a
    /// single file is a one-entry archive, TOG-SPEC-0004 §2.1.1). Without a deal it is
    /// fetched through locators under the "k independent reports" rule (§5.3).
    pub content: PayloadRef,
    /// Fetch hints.
    pub locators: Vec<Locator>,
}

/// Result definition.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OutputSpec {
    /// Hard cap on `/out`.
    pub max_bytes: u64,
    /// Files under `/out` that form the result, sorted.
    pub paths: Vec<String>,
    /// How long outputs stay in TOG DA.
    pub publish: OutputRetention,
    /// Comparison rule per entry of `paths` (same length, same order).
    pub comparison: Vec<OutputComparison>,
}

/// Output retention (TOG-SPEC-0004 §4.1). Outputs are always published to TOG DA.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OutputRetention {
    /// `ChallengeWindow` or `LongTerm`; `Hot` is for images and datasets, not outputs.
    pub class: RetentionClass,
    /// `LongTerm` only (at most one year per deal); 0 for `ChallengeWindow`.
    pub duration_blocks: u64,
    /// `LongTerm` only: export hints, strictly sorted by Borsh encoding.
    pub external: Vec<ExternalBackend>,
}

/// DA retention class (TOG-SPEC-0004 §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RetentionClass {
    /// Images and shared datasets, renewed in rolling terms.
    Hot,
    /// Until the job is terminal plus the release grace period.
    ChallengeWindow,
    /// Declared duration, Reed-Solomon coded.
    LongTerm,
}

/// External storage a `LongTerm` deal may be exported to (TOG-SPEC-0004 §4.6). A hint only:
/// the Hub cannot verify it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ExternalBackend {
    /// Arweave.
    Arweave,
    /// Filecoin.
    Filecoin,
}

/// IEEE-754 `f32` carried as raw bits, so the encoding has no NaN ambiguity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct F32Bits(pub u32);

impl F32Bits {
    /// Bits of `v`.
    pub fn from_f32(v: f32) -> Self {
        Self(v.to_bits())
    }

    /// The `f32` value.
    pub fn to_f32(self) -> f32 {
        f32::from_bits(self.0)
    }
}

/// Tensor element type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum DType {
    /// 64-bit float.
    F64,
    /// 32-bit float.
    F32,
    /// IEEE half.
    F16,
    /// bfloat16.
    BF16,
    /// 8-bit float, e4m3.
    F8E4M3,
    /// 8-bit float, e5m2.
    F8E5M2,
    /// Signed 32-bit integer.
    I32,
    /// Signed 8-bit integer.
    I8,
}

/// How verifiers compare one output path.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum OutputComparison {
    /// Byte-exact hash match.
    Exact,
    /// Safetensors: per-tensor relative L2 error ≤ `rel_tol_ppm`, max-abs ≤ `abs_tol`.
    Tensor {
        /// Relative tolerance in parts per million.
        rel_tol_ppm: u32,
        /// Absolute tolerance.
        abs_tol: F32Bits,
        /// Element type.
        dtype: DType,
    },
    /// Scalar metric within tolerance.
    Metric {
        /// Metric key.
        key: String,
        /// Absolute tolerance.
        abs_tol: F32Bits,
    },
    /// Not compared; excluded from the result root.
    Ignore,
}

/// Hardware the job needs.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HardwareRequirements {
    /// `None` for a CPU-only job.
    pub gpu: Option<GpuRequirement>,
    /// Exact core count; sets the cpuset size.
    pub cpu_cores: u16,
    /// Minimum ISA level.
    pub cpu_isa_level: CpuIsaLevel,
    /// RAM in bytes.
    pub ram_bytes: u64,
    /// Scratch disk in bytes.
    pub scratch_bytes: u64,
}

/// CPU ISA level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum CpuIsaLevel {
    /// x86-64-v2
    X86_64V2,
    /// x86-64-v3
    X86_64V3,
    /// x86-64-v4
    X86_64V4,
    /// ARMv8.2-A
    Armv8_2,
}

/// CUDA compute capability, e.g. `sm_90` = `{ major: 9, minor: 0 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct ComputeCapability {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
}

/// Inclusive compute-capability range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CcRange {
    /// Lowest accepted.
    pub min: ComputeCapability,
    /// Highest accepted.
    pub max: ComputeCapability,
}

impl CcRange {
    /// True if `cc` lies in the range.
    pub fn contains(&self, cc: ComputeCapability) -> bool {
        self.min <= cc && cc <= self.max
    }
}

/// NVIDIA driver version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct DriverVersion {
    /// Major, e.g. 550.
    pub major: u16,
    /// Minor.
    pub minor: u16,
}

/// GPU-to-GPU link a multi-GPU job requires. A host satisfies a requirement if its link
/// is at least as strong: `Pcie < NvLink < NvSwitch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum Interconnect {
    /// PCIe only: the sender explicitly accepts no NVLink.
    Pcie,
    /// NVLink between all allocated GPUs.
    NvLink,
    /// NVSwitch fabric.
    NvSwitch,
}

/// GPU part of the hardware requirement.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GpuRequirement {
    /// Number of GPUs, 1..=8.
    pub count: u8,
    /// VRAM per GPU or MIG slice.
    pub min_vram_bytes: u64,
    /// Accepted compute capabilities.
    pub compute_capability: CcRange,
    /// Minimum driver, derived from the CUDA runtime in the image.
    pub min_driver: DriverVersion,
    /// Accept a MIG slice that meets `min_vram_bytes`.
    pub allow_mig: bool,
    /// `Some(_)` iff `count > 1`.
    pub interconnect: Option<Interconnect>,
    /// Attested dense FP16 performance floor.
    pub min_fp16_tflops_dense: Option<u32>,
}

/// Sandbox isolation tier (TOG-SPEC-0001 §2.1). Ordered from weakest to strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum IsolationTier {
    /// gVisor.
    T0Gvisor,
    /// runc with the hardened profile.
    T1Runc,
    /// Kata / Cloud Hypervisor with VFIO.
    T2MicroVm,
    /// T2 plus NVIDIA confidential computing.
    T3Confidential,
}

/// Reproducibility class of the job.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum DeterminismClass {
    /// Bitwise identical on any conforming node.
    Bitwise,
    /// Bitwise identical within one (sm_xx, driver_major, toolchain) bucket.
    BitwiseSameArch,
    /// Compared with `OutputSpec::comparison` rules.
    Tolerance,
    /// Verified only by a sender-supplied checker container.
    CheckerOnly {
        /// Checker image.
        checker: ImageRef,
    },
}

/// Verification parameters (TOG-SPEC-0003).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VerificationPolicy {
    /// Verifiers per sampled segment, 3..=7.
    pub replicas: u8,
    /// Optional floor on the sample rate in basis points; can only raise it.
    pub min_sample_rate_bp: Option<u16>,
    /// Optimistic challenge period after unanimous agreement.
    pub challenge_window_blocks: u32,
}

/// Checkpointing contract for long jobs.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SegmentationSpec {
    /// Steps between checkpoints.
    pub steps_per_segment: u64,
    /// Upper bound on segments.
    pub max_segments: u32,
    /// Upper bound on one checkpoint.
    pub checkpoint_max_bytes: u64,
    /// Which input pieces each segment reads (TOG-SPEC-0004 §7.4): a payload holding
    /// `borsh(Vec<SegmentInputs>)` sorted by segment. A segment missing from it reads all inputs.
    pub input_ranges: Option<PayloadRef>,
    /// Optimizer state is complete every `full_state_every` segments, weights every segment
    /// (TOG-SPEC-0004 §8); 1 = always.
    pub full_state_every: u32,
    /// When checkpoints are placed in storage (TOG-SPEC-0004 §4.5, §4.8).
    pub checkpoint_placement: CheckpointPlacement,
    /// Sub-checkpoints per segment for micro-bisection of disputes (TOG-SPEC-0003 §4.5):
    /// 0 = off, else a power of two ≤ 64, Bitwise classes only.
    pub substeps: u16,
}

/// Input pieces one segment reads.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SegmentInputs {
    /// Segment.
    pub segment: u32,
    /// `(index into JobSpec.inputs, first piece, last piece)`, inclusive, sorted.
    pub ranges: Vec<(u16, u64, u64)>,
}

/// `T_lazy(X)` in blocks for `bytes` (TOG-SPEC-0004 §4.8): 60 blocks plus the transfer at
/// `0.8 × B_lazy`, in 2 s blocks. `b_lazy` is `B_lazy` in bits per second,
/// `storage.params.challenge_window_min_egress_bps` (§3.1 "Egress floors"), at least 1.
pub fn t_lazy(bytes: u64, b_lazy: u64) -> u64 {
    // bytes × 8 / (0.8 × B_lazy) = bytes × 10 / B_lazy seconds.
    let secs = (u128::from(bytes) * 10).div_ceil(u128::from(b_lazy.max(1)));
    60 + u64::try_from(secs.div_ceil(2)).unwrap_or(u64::MAX)
}

/// Checkpoint placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CheckpointPlacement {
    /// Every checkpoint goes to `r` holders as it is sealed.
    Eager,
    /// Opt-in lazy upload (TOG-SPEC-0004 §4.8).
    Lazy {
        /// `k > 0`: segments `k − 1, 2k − 1, …` are still placed eagerly as resume points (§4.8 rule 8);
        /// 0 = none, so a crashed job restarts from segment 0.
        resume_every: u32,
    },
}

impl CheckpointPlacement {
    /// Whether segment `n`'s checkpoint is placed as soon as its `KeyEscrowTx` is included: every
    /// segment under `Eager`, only the resume points under `Lazy`.
    pub fn places_on_escrow(&self, segment: u32) -> bool {
        match *self {
            CheckpointPlacement::Eager => true,
            CheckpointPlacement::Lazy { resume_every: 0 } => false,
            CheckpointPlacement::Lazy { resume_every: k } => (u64::from(segment) + 1) % u64::from(k) == 0,
        }
    }
}

/// Time limits.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ResourceLimits {
    /// Whole job.
    pub max_wall_time_secs: u64,
    /// One segment.
    pub max_segment_wall_time_secs: u64,
    /// GPU-second budget ceiling.
    pub max_gpu_seconds: u64,
}

/// Fees and escrow.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeSpec {
    /// Locked in escrow at inclusion; remainder refunded at settlement.
    pub max_budget: Amount,
    /// Maximum price per Work Unit.
    pub max_price_per_wu: Amount,
    /// Tip to the executor per WU.
    pub tip_per_wu: Amount,
    /// Flat inclusion fee, burned.
    pub inclusion_fee: Amount,
    /// Escrow refunds if the job is not claimed by this height.
    pub claim_deadline_height: u64,
    /// Part of `max_budget` reserved for storage (TOG-SPEC-0004 §4.2).
    pub storage_fee: StorageBudget,
}

/// Storage part of the budget; the sum of its fields is at most `max_budget`.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StorageBudget {
    /// Placing inputs for this job (not pre-placed ones).
    pub inputs: Amount,
    /// The checkpoint deal.
    pub checkpoints: Amount,
    /// Outputs for `OutputSpec.publish`.
    pub outputs: Amount,
    /// Verifier and juror fetch reimbursements (TOG-SPEC-0004 §6.4).
    pub retrieval_allowance: Amount,
}

impl StorageBudget {
    /// Sum of all fields; `None` on overflow.
    pub fn total(&self) -> Option<Amount> {
        self.inputs.checked_add(self.checkpoints)?.checked_add(self.outputs)?.checked_add(self.retrieval_allowance)
    }
}

/// Default job-bond floor `β` in basis points (Hub parameter, TOG-SPEC-0001 §4.2 step 3).
pub const DEFAULT_BOND_BETA_BP: u16 = 5_000;

impl FeeSpec {
    /// Smallest bond `ClaimJob` may post: `⌈β · max_budget⌉`.
    pub fn min_bond(&self, beta_bp: u16) -> Amount {
        let bp = Amount::from(beta_bp);
        // max_budget ≤ u128::MAX, so split to avoid overflow in the multiplication.
        let (q, r) = (self.max_budget / 10_000, self.max_budget % 10_000);
        // A governance β above 100 % can push it past u128; it then saturates.
        q.saturating_mul(bp).saturating_add((r * bp).div_ceil(10_000))
    }
}

/// Confidential job parameters (T3 only, TOG-SPEC-0010 §3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ConfidentialSpec {
    /// Enclaves allowed to receive the job key.
    pub policy: EnclavePolicyId,
    /// Who hands `K_conf` to authorized enclaves.
    pub broker: KeyBroker,
}

/// How `K_conf` reaches an authorized enclave (TOG-SPEC-0010 §4).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum KeyBroker {
    /// `K_conf` encrypted to the Hub key under identity (`TOG/v1/conf-key`, escrow); validators
    /// send decryption shares to the enclave off-chain.
    Hub {
        /// `IBE_Enc(EK, ("TOG/v1/conf-key" ‖ escrow), K_conf)`.
        wrapped_key: crate::hub_key::IbeCiphertext,
    },
    /// The sender delivers `K_conf` itself.
    Sender {
        /// Blocks after the executor's grant starts before the executor may release the claim
        /// with `ConfKeyMissing` (TOG-SPEC-0010 §4.3).
        deliver_within: u32,
        /// The sender's X25519 HPKE key, to which verifiers and jurors seal `ConfKeyRequest`s.
        request_key: [u8; 32],
        /// [`conf_key_check`] of `K_conf`: an enclave keeps only the key that matches it, as
        /// anyone can seal a key to its public `enc_key` (TOG-SPEC-0010 §4.3 "Key check").
        key_check: Hash32,
    },
}

/// `key_check = H("TOG/v1/conf-key-check" ‖ K_conf)` of a `Sender`-broker job (TOG-SPEC-0010 §4.3).
/// It is deterministic, so a sender draws a fresh `K_conf` for every job: one key on two jobs would
/// make them linkable by their `key_check`.
pub fn conf_key_check(k_conf: &[u8; 32]) -> Hash32 {
    tagged_hash(Domain::ConfKeyCheck, &[k_conf])
}

#[cfg(test)]
mod tests {
    #[test]
    fn resume_points_of_lazy_placement() {
        let placed = |p: CheckpointPlacement| (0..9).filter(|&n| p.places_on_escrow(n)).collect::<Vec<_>>();
        assert_eq!(placed(CheckpointPlacement::Eager), (0..9).collect::<Vec<_>>());
        assert_eq!(placed(CheckpointPlacement::Lazy { resume_every: 0 }), Vec::<u32>::new());
        assert_eq!(placed(CheckpointPlacement::Lazy { resume_every: 4 }), vec![3, 7]);
        assert!(CheckpointPlacement::Lazy { resume_every: 1 }.places_on_escrow(u32::MAX));
        assert_eq!(borsh::to_vec(&CheckpointPlacement::Lazy { resume_every: 4 }).unwrap(), [1, 4, 0, 0, 0]);
    }

    use super::*;

    fn fee(max_budget: Amount) -> FeeSpec {
        FeeSpec {
            max_budget,
            max_price_per_wu: 0,
            tip_per_wu: 0,
            inclusion_fee: 0,
            claim_deadline_height: 0,
            storage_fee: StorageBudget::default(),
        }
    }

    #[test]
    fn min_bond_rounds_up_and_does_not_overflow() {
        assert_eq!(fee(2_160).min_bond(DEFAULT_BOND_BETA_BP), 1_080);
        assert_eq!(fee(3).min_bond(DEFAULT_BOND_BETA_BP), 2);
        assert_eq!(fee(0).min_bond(DEFAULT_BOND_BETA_BP), 0);
        assert_eq!(fee(Amount::MAX).min_bond(10_000), Amount::MAX);
        assert_eq!(fee(Amount::MAX).min_bond(20_000), Amount::MAX);
    }
}
