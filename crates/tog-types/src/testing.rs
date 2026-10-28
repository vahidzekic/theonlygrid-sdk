//! Fixtures for tests in this and downstream crates (feature `testing`).

use crate::job::*;
use crate::payload::{Encryption, PayloadCommitment, PayloadKind};
use tog_primitives::ChainId;

/// Network id the fixtures use.
pub const NETWORK_ID: u32 = 1;

/// A valid segmented single-GPU training job on the Hub of network 1, valid until height 200.
pub fn sample_job() -> JobTx {
    JobTx {
        chain_id: ChainId::HUB.replay_domain(NETWORK_ID),
        sender: [1; 20],
        nonce: 0,
        valid_until_height: 200,
        origin: ChainId(7),
        escrow: EscrowRef([2; 32]),
        callback: None,
        spec: sample_spec(),
    }
}

/// The spec of [`sample_job`].
pub fn sample_spec() -> JobSpec {
    JobSpec {
        worker_set: ChainId(7),
        verification_module: VerificationModuleId(*b"bitwise-v1\0\0\0\0\0\0"),
        image: ImageRef {
            manifest_digest: [3; 32],
            platform: Platform::LinuxAmd64,
            total_size: 1 << 30,
            blobs: vec![
                payload(PayloadKind::Image, 30, 1_000, Some([3; 32])),
                payload(PayloadKind::Image, 31, 1_000, Some([31; 32])),
                payload(PayloadKind::Image, 32, (1 << 30) - 2_000, Some([32; 32])),
            ],
            deal: None,
            locators: vec![Locator::Https { url: "https://example.org/img".into() }],
        },
        command: CommandSpec {
            entrypoint: vec![],
            args: vec!["train.py".into()],
            env: vec![("A".into(), "1".into()), ("B".into(), "2".into())],
            workdir: None,
        },
        inputs: vec![
            InputRef { mount_name: "data".into(), content: input(4, 10), locators: vec![] },
            InputRef { mount_name: "model".into(), content: input(5, 10), locators: vec![] },
        ],
        toolchain: ToolchainProfileId([6; 32]),
        outputs: OutputSpec {
            max_bytes: 1 << 30,
            paths: vec!["log.txt".into(), "weights.safetensors".into()],
            publish: OutputRetention { class: RetentionClass::ChallengeWindow, duration_blocks: 0, external: vec![] },
            comparison: vec![
                OutputComparison::Ignore,
                OutputComparison::Tensor { rel_tol_ppm: 100, abs_tol: F32Bits::from_f32(1e-5), dtype: DType::BF16 },
            ],
        },
        hw: HardwareRequirements {
            gpu: Some(GpuRequirement {
                count: 1,
                min_vram_bytes: 40 << 30,
                compute_capability: CcRange {
                    min: ComputeCapability { major: 8, minor: 0 },
                    max: ComputeCapability { major: 9, minor: 0 },
                },
                min_driver: DriverVersion { major: 550, minor: 0 },
                allow_mig: false,
                interconnect: None,
                min_fp16_tflops_dense: None,
            }),
            cpu_cores: 8,
            cpu_isa_level: CpuIsaLevel::X86_64V3,
            ram_bytes: 64 << 30,
            scratch_bytes: 100 << 30,
        },
        min_isolation: IsolationTier::T2MicroVm,
        determinism: DeterminismClass::Tolerance,
        verification: VerificationPolicy { replicas: 3, min_sample_rate_bp: None, challenge_window_blocks: 600 },
        segmentation: Some(SegmentationSpec {
            steps_per_segment: 1000,
            max_segments: 48,
            checkpoint_max_bytes: 1 << 30,
            input_ranges: None,
            full_state_every: 1,
            checkpoint_placement: CheckpointPlacement::Eager,
            substeps: 0,
        }),
        limits: ResourceLimits {
            max_wall_time_secs: 48 * 3600,
            max_segment_wall_time_secs: 3600,
            max_gpu_seconds: 48 * 3600,
        },
        fee: FeeSpec {
            max_budget: 1000 * tog_primitives::ONE_TOG,
            max_price_per_wu: tog_primitives::ONE_TOG,
            tip_per_wu: 0,
            inclusion_fee: tog_primitives::ONE_TOG / 100,
            claim_deadline_height: 150,
            storage_fee: StorageBudget {
                inputs: 0,
                checkpoints: 10 * tog_primitives::ONE_TOG,
                outputs: tog_primitives::ONE_TOG,
                retrieval_allowance: tog_primitives::ONE_TOG,
            },
        },
        confidential: None,
    }
}

/// An unencrypted payload whose root is `[root; 32]`.
pub fn payload(kind: PayloadKind, root: u8, size: u64, oci_digest: Option<[u8; 32]>) -> PayloadCommitment {
    PayloadCommitment {
        version: 1,
        root: [root; 32],
        size,
        piece_log2: 20,
        kind,
        oci_digest,
        encryption: Encryption::None,
    }
}

/// An input payload with no deal.
pub fn input(root: u8, size: u64) -> PayloadRef {
    PayloadRef { payload: payload(PayloadKind::Input, root, size, None), deal: None }
}

/// An active worker `[i; 20]` opted into the fixtures' worker set, with one GPU per `(cc major,
/// driver major)` in `gpus`.
pub fn sample_worker(i: u8, gpus: &[(u8, u16)]) -> crate::worker::WorkerRecord {
    use crate::eligibility::Region;
    use crate::worker::*;
    use crate::{ComputeCapability, CpuIsaLevel, DriverVersion, IsolationTier};
    let gpus = gpus
        .iter()
        .map(|&(cc, driver)| GpuInfo {
            uuid: [i; 16],
            pci_device_id: 0x20b0,
            compute_capability: ComputeCapability { major: cc, minor: 0 },
            vram_bytes: 80 << 30,
            mig_capable: true,
            cc_capable: false,
            driver: DriverVersion { major: driver, minor: 0 },
            numa_node: 0,
        })
        .collect();
    WorkerRecord {
        id: [i; 20],
        owner: [i; 20],
        vrf_key: [i; 32],
        hw: HwSignature {
            cpu_isa_level: CpuIsaLevel::X86_64V4,
            cpu_cores: 32,
            numa_nodes: 1,
            ram_bytes: 256 << 30,
            scratch_bytes: 1 << 40,
            gpus,
            interconnect: None,
        },
        tiers: vec![IsolationTier::T0Gvisor, IsolationTier::T2MicroVm],
        attestation: vec![],
        calibration: CalibrationResult { verified_wu_per_hour: 1_000, ..CalibrationResult::default() },
        net: NetProfile::default(),
        bond: 500_000,
        reputation: 50,
        clean_jobs: 0,
        opted_in: [sample_job().spec.worker_set].into(),
        status: WorkerStatus::Active,
        region: Region(*b"DE"),
        region_flagged: false,
        enclave_policies: Default::default(),
    }
}
