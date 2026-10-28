//! Types of worker eligibility (TOG-SPEC-0000 §5.2, TOG-SPEC-0001 §3.3, §4.2.1). The rules themselves
//! run on the Hub.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{Amount, Hash32};

use crate::job::{CcRange, CpuIsaLevel, DriverVersion, EnclavePolicyId, ToolchainProfileId};
use crate::worker::WorkerId;
use crate::IsolationTier;

/// Most entries in [`HwFilter::gpu_models`].
pub const MAX_GPU_MODELS: usize = 64;

/// ISO 3166-1 alpha-2 country code, uppercase ASCII. A set such as "EU-only" lists its countries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct Region(pub [u8; 2]);

impl Region {
    /// Two uppercase ASCII letters. Whether the code is assigned is not checked.
    pub fn is_well_formed(&self) -> bool {
        self.0.iter().all(u8::is_ascii_uppercase)
    }
}

/// Hardware filter of a worker set. A GPU passes the per-GPU part if every bound holds; a worker
/// passes if at least `min_gpus` of its GPUs pass and the CPU part holds (TOG-SPEC-0001 §4.2.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HwFilter {
    /// 0 = CPU-only workers are admitted.
    pub min_gpus: u8,
    /// Accepted compute capabilities.
    pub cc: Option<CcRange>,
    /// VRAM floor per GPU.
    pub min_vram_bytes: u64,
    /// Allowed PCI device ids, strictly sorted, at most [`MAX_GPU_MODELS`].
    pub gpu_models: Option<Vec<u16>>,
    /// NVIDIA Confidential Computing GPUs only.
    pub require_cc_capable: bool,
    /// CPU ISA floor.
    pub min_cpu_isa: Option<CpuIsaLevel>,
    /// RAM floor.
    pub min_ram_bytes: u64,
}

impl HwFilter {
    /// `gpu_models` is strictly sorted and within [`MAX_GPU_MODELS`].
    pub fn is_well_formed(&self) -> bool {
        self.gpu_models.as_ref().map_or(true, |m| m.len() <= MAX_GPU_MODELS && m.windows(2).all(|w| w[0] < w[1]))
    }
}

/// Datasheet entry of the governance table `GpuModels`, keyed by PCI device id (TOG-SPEC-0001 §3.3).
/// It serves `min_fp16_tflops_dense` and [`HwFilter::gpu_models`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GpuModel {
    /// Marketing name.
    pub name: String,
    /// VRAM from the vendor's datasheet.
    pub vram_bytes: u64,
    /// Dense FP16 TFLOPS from the datasheet.
    pub fp16_tflops_dense: u32,
}

impl GpuModel {
    /// A registration fails if a GPU's claimed `vram_bytes` differs from the table by more than 2%.
    pub fn vram_matches(&self, claimed: u64) -> bool {
        // |claimed − table| · 50 ≤ table, in u128 so nothing overflows.
        u128::from(claimed.abs_diff(self.vram_bytes)) * 50 <= u128::from(self.vram_bytes)
    }
}

/// A governance-registered toolchain bundle (TOG-SPEC-0001 §3.3); `ToolchainProfileId` is its hash.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ToolchainProfile {
    /// CUDA runtime version, e.g. "12.4".
    pub cuda_runtime: String,
    /// cuDNN version.
    pub cudnn: String,
    /// NCCL version.
    pub nccl: String,
    /// Digest of the framework wheels.
    pub framework_wheels_digest: Hash32,
    /// Supported drivers, inclusive.
    pub driver_range: (DriverVersion, DriverVersion),
    /// Supported compute capabilities; `None` for a CPU-only profile.
    pub cc_range: Option<CcRange>,
    /// Environment the profile requires.
    pub required_env: Vec<(String, String)>,
}

/// The measured cross-bucket spread of a toolchain profile, `compute_market.toolchain_spread`
/// (TOG-SPEC-0003 §4.1.1 "Spread table"): an R2 round under `Tolerance` rules widens the
/// checkpoint tolerance to at least twice it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ToolchainSpread {
    /// Relative spread, ppm, as `OutputComparison::Tensor.rel_tol_ppm`.
    pub rel_ppm: u32,
    /// Absolute spread in Q32.32, as the checkpoint `abs_q`.
    pub abs_q: u64,
}

impl ToolchainSpread {
    /// The R2 checkpoint tolerance for `(rel_tol_ppm, abs_q)`: each the larger of the job's and
    /// twice the spread, saturating.
    pub fn widen(&self, rel_tol_ppm: u32, abs_q: u64) -> (u32, u64) {
        (rel_tol_ppm.max(self.rel_ppm.saturating_mul(2)), abs_q.max(self.abs_q.saturating_mul(2)))
    }
}

impl ToolchainProfile {
    /// Whether a GPU with this compute capability and driver can run the profile. A CPU-only
    /// profile has no GPU condition.
    pub fn supports_gpu(&self, cc: crate::job::ComputeCapability, driver: DriverVersion) -> bool {
        let (lo, hi) = self.driver_range;
        self.cc_range.map_or(true, |r| r.contains(cc) && lo <= driver && driver <= hi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::ComputeCapability;

    #[test]
    fn region_format() {
        assert!(Region(*b"DE").is_well_formed());
        assert!(!Region(*b"de").is_well_formed());
        assert!(!Region(*b"D1").is_well_formed());
    }

    #[test]
    fn filter_models_sorted_and_bounded() {
        let mut f = HwFilter {
            min_gpus: 1,
            cc: None,
            min_vram_bytes: 0,
            gpu_models: Some(vec![1, 2]),
            require_cc_capable: false,
            min_cpu_isa: None,
            min_ram_bytes: 0,
        };
        assert!(f.is_well_formed());
        f.gpu_models = Some(vec![2, 2]);
        assert!(!f.is_well_formed());
        f.gpu_models = Some((0..65).collect());
        assert!(!f.is_well_formed());
    }

    #[test]
    fn vram_tolerance_is_two_percent() {
        let m = GpuModel { name: "H100".into(), vram_bytes: 5_000, fp16_tflops_dense: 989 };
        assert!(m.vram_matches(5_100) && m.vram_matches(4_900));
        assert!(!m.vram_matches(5_101) && !m.vram_matches(4_899));
    }

    #[test]
    fn profile_ranges_are_inclusive() {
        let cc = |major, minor| ComputeCapability { major, minor };
        let drv = |major| DriverVersion { major, minor: 0 };
        let p = ToolchainProfile {
            cuda_runtime: "12.4".into(),
            cudnn: "9.1".into(),
            nccl: "2.21".into(),
            framework_wheels_digest: [0; 32],
            driver_range: (drv(550), drv(560)),
            cc_range: Some(CcRange { min: cc(8, 0), max: cc(9, 0) }),
            required_env: vec![],
        };
        assert!(p.supports_gpu(cc(8, 0), drv(550)));
        assert!(p.supports_gpu(cc(9, 0), drv(560)));
        assert!(!p.supports_gpu(cc(7, 5), drv(555)));
        assert!(!p.supports_gpu(cc(8, 6), drv(561)));
        assert!(ToolchainProfile { cc_range: None, ..p }.supports_gpu(cc(1, 0), drv(1)));
    }
}

/// An L1's worker-set rules (TOG-SPEC-0000 §5.2), `appchains.worker_set_rules[chain]` (TOG-SPEC-0002
/// §7.2). Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WorkerSetRules {
    /// Weakest isolation the L1 accepts; a job may ask for stronger.
    pub min_isolation: IsolationTier,
    /// Hardware filter.
    pub hw_filter: HwFilter,
    /// Toolchain profiles every worker must support.
    pub required_toolchains: Vec<ToolchainProfileId>,
    /// Bond the L1 demands, on top of the Hub minimum.
    pub min_bond: Amount,
    /// Reputation floor.
    pub min_reputation: u32,
    /// Data-residency requirement.
    pub regions: Option<Vec<Region>>,
    /// Jobs from other ecosystems via the Gateway (TOG-SPEC-0008 §7).
    pub accepts_external_jobs: bool,
    /// If set, only these workers are assigned jobs; verification ignores it.
    pub allowlist: Option<Vec<WorkerId>>,
    /// If set, the only enclave policies its T3 jobs may name (TOG-SPEC-0010 §8, 0000 §5.2); a
    /// retired policy is rejected in new rules.
    pub allowed_policies: Option<Vec<EnclavePolicyId>>,
}
