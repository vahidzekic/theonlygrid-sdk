//! Work Unit metering (TOG-SPEC-0001 §5.4), shared by the executor, `togd` and the Hub.
//!
//! ```text
//! WU = ⌊ Σ_n t_n × (gpu_class_weight × g + 8 × cpu_weight × c) / 8 000 000 ⌋
//! ```
//!
//! `t_n` in milliseconds, weights in milli-WU per second, `g` the leased GPU eighths and `c` the
//! booked cores; one floor over the whole sum, in u128.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};

use crate::job::{ComputeCapability, HardwareRequirements};

/// `cpu_weight`: milli-WU per second of the reference core, 1 000 by definition (TOG-SPEC-0005 §5.1).
pub const CPU_WEIGHT: u64 = 1_000;

/// `compute_market.wu_weights` value (TOG-SPEC-0005 §5.1, TOG-SPEC-0002 §7.2), read at the claim
/// height for [`Lease::rate`] and `RunJob`. Borsh in field order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WuWeights {
    /// Per core; [`CPU_WEIGHT`].
    pub cpu_weight: u64,
    /// Per whole GPU, keyed by bucket `(cc, driver major)`, strictly ascending by key.
    pub gpu_class_weights: Vec<((ComputeCapability, u16), u64)>,
}

impl WuWeights {
    /// The weight of bucket `(cc, driver_major)`: the lease's GPU 0. A bucket missing from the
    /// table weighs 0 (a GPU job can't be claimed on it).
    pub fn gpu_class_weight(&self, cc: ComputeCapability, driver_major: u16) -> u64 {
        self.gpu_class_weights
            .binary_search_by_key(&(cc, driver_major), |(k, _)| *k)
            .map_or(0, |i| self.gpu_class_weights[i].1)
    }
}

/// What a claim booked: the lease is billed, not what the job used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    /// `g`: `8 × gpu.count` for whole GPUs, `e` for a MIG slice of `e` eighths, 0 for CPU-only.
    pub gpu_eighths: u64,
    /// `c = hw.cpu_cores`.
    pub cores: u16,
}

impl Lease {
    /// A lease of whole GPUs (or none) as `hw` asks for.
    pub fn whole(hw: &HardwareRequirements) -> Self {
        Lease { gpu_eighths: 8 * u64::from(hw.gpu.as_ref().map_or(0, |g| g.count)), cores: hw.cpu_cores }
    }

    /// A lease of `eighths` of one MIG-capable GPU (TOG-SPEC-0001 §4.2.1 rule 8).
    pub fn mig(hw: &HardwareRequirements, eighths: u8) -> Self {
        Lease { gpu_eighths: u64::from(eighths), cores: hw.cpu_cores }
    }

    /// `gpu_class_weight × g + 8 × cpu_weight × c`: milli-WU per second, times 8.
    pub fn rate(&self, gpu_class_weight: u64, cpu_weight: u64) -> u128 {
        u128::from(gpu_class_weight) * u128::from(self.gpu_eighths)
            + 8 * u128::from(cpu_weight) * u128::from(self.cores)
    }
}

/// `t_n` of a segment that ran `elapsed_ms`: at most `max_segment_wall_time_secs × 1000`.
pub fn segment_ms(elapsed_ms: u128, max_segment_wall_time_secs: u64) -> u128 {
    elapsed_ms.min(u128::from(max_segment_wall_time_secs) * 1000)
}

/// WUs of `total_ms = Σ t_n` at `rate` ([`Lease::rate`]); saturates at `u64::MAX`.
pub fn work_units(total_ms: u128, rate: u128) -> u64 {
    u64::try_from(total_ms.saturating_mul(rate) / 8_000_000).unwrap_or(u64::MAX)
}

/// The most a claim of `own_segments` segments may report: each at `max_segment_wall_time_secs`.
/// The Hub rejects a `CommitResult` or `KeyEscrowTx` above it.
pub fn max_claim_work_units(own_segments: u32, max_segment_wall_time_secs: u64, rate: u128) -> u64 {
    work_units(u128::from(own_segments) * u128::from(max_segment_wall_time_secs) * 1000, rate)
}

/// The billing ceiling over all claims of a job: `⌊ max_gpu_seconds × rate / 8 000 ⌋`.
pub fn billing_ceiling(max_gpu_seconds: u64, rate: u128) -> u64 {
    u64::try_from(u128::from(max_gpu_seconds).saturating_mul(rate) / 8_000).unwrap_or(u64::MAX)
}

/// Self-reported calibration throughput in WU per hour: `⌊ref_wu × 3 600 000 / wall_ms⌋`, with
/// `wall_ms` at least 1 (TOG-SPEC-0001 §4.2 step 0); saturates at `u64::MAX`. Advisory only.
pub fn calibration_throughput(ref_wu: u64, wall_ms: u128) -> u64 {
    let wu = u128::from(ref_wu) * 3_600_000 / wall_ms.max(1);
    u64::try_from(wu).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::sample_job;

    #[test]
    fn wu_weights_by_bucket() {
        let cc = |major| ComputeCapability { major, minor: 0 };
        let w = WuWeights {
            cpu_weight: CPU_WEIGHT,
            gpu_class_weights: vec![((cc(8), 535), 40_000), ((cc(9), 550), 90_000)],
        };
        assert_eq!(w.gpu_class_weight(cc(9), 550), 90_000);
        assert_eq!(w.gpu_class_weight(cc(8), 535), 40_000);
        // Another driver major is another bucket, and a missing bucket weighs 0.
        assert_eq!(w.gpu_class_weight(cc(9), 535), 0);
        let b = borsh::to_vec(&w).unwrap();
        assert_eq!(&b[..12], [&1_000u64.to_le_bytes()[..], &2u32.to_le_bytes()[..]].concat());
        assert_eq!(&b[12..24], [8, 0, 0x17, 0x02, 0x40, 0x9c, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn calibration_throughput_per_hour() {
        // 1 000 WU in 2 s is 1 800 000 WU per hour.
        assert_eq!(calibration_throughput(1_000, 2_000), 1_800_000);
        assert_eq!(calibration_throughput(1, 7), 514_285);
        assert_eq!(calibration_throughput(1, 0), 3_600_000);
        assert_eq!(calibration_throughput(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn one_floor_over_the_sum() {
        let mut hw = sample_job().spec.hw;
        hw.gpu.as_mut().unwrap().count = 2;
        hw.cpu_cores = 4;
        let lease = Lease::whole(&hw);
        assert_eq!(lease.gpu_eighths, 16);
        // 2 GPUs at 1 000 milli-WU/s each, 4 cores at 1 000: 6 WU per second.
        let rate = lease.rate(1_000, 1_000);
        assert_eq!(rate, 48_000);
        assert_eq!(work_units(1_000, rate), 6);
        // 3 × 100 ms is 1.8 WU: floored once, not per segment.
        assert_eq!(work_units(300, rate), 1);
        assert_eq!(work_units(100, rate) * 3, 0);
        assert_eq!(max_claim_work_units(2, 10, rate), 120);
        assert_eq!(billing_ceiling(10, rate), 60);
        assert_eq!(segment_ms(15_000, 10), 10_000);
    }

    #[test]
    fn mig_and_cpu_only() {
        let hw = sample_job().spec.hw;
        let mig = Lease::mig(&hw, 3);
        assert_eq!(mig.rate(8_000, 0), 24_000);
        let mut cpu = hw.clone();
        cpu.gpu = None;
        assert_eq!(Lease::whole(&cpu).gpu_eighths, 0);
        assert_eq!(work_units(u128::MAX, 2), u64::MAX);
    }
}
