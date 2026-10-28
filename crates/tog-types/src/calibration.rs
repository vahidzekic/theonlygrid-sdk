//! The calibration kernel bundle (TOG-SPEC-0001 §4.2 step 0, "Calibration bundle"): what a worker
//! runs for `SelfCalibration` and what the Hub checks its results against.
//!
//! The bundle is a TDA archive whose root is `SelfCalibration.kernel_set`. It holds `manifest`
//! (`borsh(KernelManifest)`), and per kernel `kernels/<id>/image/` (an OCI layout with one manifest)
//! and `kernels/<id>/input/`. Governance registers each bundle's expected outputs as a [`KernelSet`].

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::Hash32;

use crate::admission::{check_command, AdmissionError};
use crate::job::{CommandSpec, ComputeCapability, CpuIsaLevel};
use crate::worker::CPU_KERNEL;

/// The manifest version written: 2, with [`KernelSpec::ram_bytes`].
pub const MANIFEST_VERSION: u16 = 2;
/// The first version, whose kernels carry no `ram_bytes` and run with [`V1_KERNEL_RAM`].
pub const MANIFEST_V1: u16 = 1;
/// `hw.ram_bytes` of a kernel from a version-1 manifest: 4 GiB.
pub const V1_KERNEL_RAM: u64 = 4 << 30;
/// Upper bound of [`KernelSpec::wall_limit_secs`].
pub const MAX_KERNEL_WALL_SECS: u32 = 3600;
/// Path of the manifest in the bundle.
pub const MANIFEST_PATH: &str = "manifest";

/// The bundle's `manifest`. Borsh as written; a version-1 manifest's kernels have no `ram_bytes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelManifest {
    /// [`MANIFEST_VERSION`].
    pub version: u16,
    /// Strictly sorted by id.
    pub kernels: Vec<KernelSpec>,
}

/// One kernel.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KernelSpec {
    /// `KernelResult.kernel`; `<id>` of its bundle paths, in decimal.
    pub id: u16,
    /// What it runs on.
    pub target: KernelTarget,
    /// As in a job; env keys follow admission rule 1.
    pub command: CommandSpec,
    /// Cores booked for the run.
    pub cpu_cores: u16,
    /// Level whose environment the run gets; for a CPU kernel also its bucket.
    pub isa: CpuIsaLevel,
    /// The kernel's work in WU.
    pub ref_wu: u64,
    /// At most [`MAX_KERNEL_WALL_SECS`].
    pub wall_limit_secs: u32,
    /// `hw.ram_bytes` of the run; [`V1_KERNEL_RAM`] for a version-1 manifest.
    pub ram_bytes: u64,
}

/// A [`KernelSpec`] as a version-1 manifest has it.
#[derive(BorshSerialize, BorshDeserialize)]
struct KernelSpecV1 {
    id: u16,
    target: KernelTarget,
    command: CommandSpec,
    cpu_cores: u16,
    isa: CpuIsaLevel,
    ref_wu: u64,
    wall_limit_secs: u32,
}

impl BorshSerialize for KernelManifest {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        self.version.serialize(w)?;
        if self.version != MANIFEST_V1 {
            return self.kernels.serialize(w);
        }
        let v1: Vec<KernelSpecV1> = self
            .kernels
            .iter()
            .map(|k| KernelSpecV1 {
                id: k.id,
                target: k.target,
                command: k.command.clone(),
                cpu_cores: k.cpu_cores,
                isa: k.isa,
                ref_wu: k.ref_wu,
                wall_limit_secs: k.wall_limit_secs,
            })
            .collect();
        v1.serialize(w)
    }
}

impl BorshDeserialize for KernelManifest {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let version = u16::deserialize_reader(r)?;
        if version != MANIFEST_V1 {
            return Ok(Self { version, kernels: Vec::deserialize_reader(r)? });
        }
        let v1: Vec<KernelSpecV1> = Vec::deserialize_reader(r)?;
        let kernels = v1
            .into_iter()
            .map(|k| KernelSpec {
                id: k.id,
                target: k.target,
                command: k.command,
                cpu_cores: k.cpu_cores,
                isa: k.isa,
                ref_wu: k.ref_wu,
                wall_limit_secs: k.wall_limit_secs,
                ram_bytes: V1_KERNEL_RAM,
            })
            .collect();
        Ok(Self { version, kernels })
    }
}

/// What a kernel runs on. Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum KernelTarget {
    /// 0: once, with no GPU.
    Cpu,
    /// 1: once on each GPU, alone and whole.
    Gpu,
}

/// `hardware_registry.kernel_sets[kernel_set]`, registered by governance.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KernelSet {
    /// `(kernel id, bucket, output_hash)`, strictly sorted.
    pub expected: Vec<(u16, KernelBucket, Hash32)>,
}

/// Which outputs a kernel must match. Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum KernelBucket {
    /// 0: a CPU kernel at its ISA level.
    Cpu(CpuIsaLevel),
    /// 1: a GPU kernel on a GPU of this compute capability and driver major (the `BitwiseSameArch` key).
    Gpu {
        /// Compute capability.
        cc: ComputeCapability,
        /// Driver major version.
        driver_major: u16,
    },
}

/// Why a manifest or kernel set is not well-formed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum KernelError {
    /// Unknown manifest version.
    #[error("manifest version {0}")]
    Version(u16),
    /// Entries out of order or repeated.
    #[error("entries not strictly sorted")]
    NotSorted,
    /// A kernel's command breaks admission rule 1.
    #[error("kernel {0}: {1}")]
    Command(u16, AdmissionError),
    /// A wall limit of 0 or above [`MAX_KERNEL_WALL_SECS`].
    #[error("kernel {0}: wall limit")]
    WallLimit(u16),
    /// A kernel set entry mixes `Cpu` and `Gpu` buckets, or has two `Cpu` levels.
    #[error("kernel {0}: no single target")]
    Target(u16),
}

/// A kernel's target as the Hub derives it from a [`KernelSet`]: it never stores the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivedTarget {
    /// Exactly one entry, `Cpu(isa)`: the results are checked against that level.
    Cpu(CpuIsaLevel),
    /// Only `Gpu` entries.
    Gpu,
}

impl KernelManifest {
    /// Version, order, commands and wall limits.
    pub fn check(&self) -> Result<(), KernelError> {
        if self.version != MANIFEST_VERSION && self.version != MANIFEST_V1 {
            return Err(KernelError::Version(self.version));
        }
        if !self.kernels.windows(2).all(|w| w[0].id < w[1].id) {
            return Err(KernelError::NotSorted);
        }
        for k in &self.kernels {
            check_command(&k.command).map_err(|e| KernelError::Command(k.id, e))?;
            if k.wall_limit_secs == 0 || k.wall_limit_secs > MAX_KERNEL_WALL_SECS {
                return Err(KernelError::WallLimit(k.id));
            }
        }
        Ok(())
    }

    /// The `(kernel, gpu_index)` runs on a machine with `gpus` GPUs, in run order: a CPU kernel once
    /// with [`CPU_KERNEL`], a GPU kernel once per GPU. Also the results the Hub requires.
    pub fn runs(&self, gpus: u8) -> Vec<(u16, u8)> {
        let mut runs = Vec::new();
        for k in &self.kernels {
            match k.target {
                KernelTarget::Cpu => runs.push((k.id, CPU_KERNEL)),
                KernelTarget::Gpu => runs.extend((0..gpus).map(|g| (k.id, g))),
            }
        }
        runs
    }

    /// The kernel with `id`.
    pub fn kernel(&self, id: u16) -> Option<&KernelSpec> {
        self.kernels.binary_search_by_key(&id, |k| k.id).ok().map(|i| &self.kernels[i])
    }
}

impl KernelSet {
    /// Well-formed (TOG-SPEC-0001 §4.2 step 0): strictly sorted, and every kernel has exactly one
    /// `Cpu(isa)` entry or only `Gpu` entries.
    pub fn check(&self) -> Result<(), KernelError> {
        self.targets().map(|_| ())
    }

    /// Each kernel's derived target, ascending by kernel id.
    pub fn targets(&self) -> Result<Vec<(u16, DerivedTarget)>, KernelError> {
        let key = |e: &(u16, KernelBucket, Hash32)| (e.0, e.1);
        if !self.expected.windows(2).all(|w| key(&w[0]) < key(&w[1])) {
            return Err(KernelError::NotSorted);
        }
        let mut out: Vec<(u16, DerivedTarget)> = Vec::new();
        for (kernel, bucket, _) in &self.expected {
            let target = match bucket {
                KernelBucket::Cpu(isa) => DerivedTarget::Cpu(*isa),
                KernelBucket::Gpu { .. } => DerivedTarget::Gpu,
            };
            match out.last() {
                // Sorted: a kernel's entries are adjacent, and `Cpu` sorts before `Gpu`.
                Some((k, t)) if k == kernel => {
                    if !(*t == DerivedTarget::Gpu && target == DerivedTarget::Gpu) {
                        return Err(KernelError::Target(*kernel));
                    }
                }
                _ => out.push((*kernel, target)),
            }
        }
        Ok(out)
    }

    /// The output a run of `kernel` in `bucket` must produce; `None` if governance registered none.
    pub fn expected(&self, kernel: u16, bucket: KernelBucket) -> Option<Hash32> {
        self.expected.iter().find(|(k, b, _)| *k == kernel && *b == bucket).map(|(_, _, h)| *h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(id: u16, target: KernelTarget) -> KernelSpec {
        KernelSpec {
            id,
            target,
            command: CommandSpec { entrypoint: vec!["/bin/k".into()], args: vec![], env: vec![], workdir: None },
            cpu_cores: 4,
            isa: CpuIsaLevel::X86_64V3,
            ref_wu: 1000,
            wall_limit_secs: 600,
            ram_bytes: 8 << 30,
        }
    }

    #[test]
    fn a_version_1_manifest_has_no_ram_and_runs_with_4_gib() {
        let v2 = KernelManifest { version: MANIFEST_VERSION, kernels: vec![kernel(1, KernelTarget::Cpu)] };
        let b2 = borsh::to_vec(&v2).unwrap();
        assert_eq!(borsh::from_slice::<KernelManifest>(&b2).unwrap(), v2);
        let v1 = KernelManifest { version: MANIFEST_V1, ..v2.clone() };
        let b1 = borsh::to_vec(&v1).unwrap();
        assert_eq!((b1.len() + 8, &b2[2..b2.len() - 8]), (b2.len(), &b1[2..]));
        let back: KernelManifest = borsh::from_slice(&b1).unwrap();
        assert_eq!(back.kernels[0].ram_bytes, V1_KERNEL_RAM);
        assert!(back.check().is_ok());
        assert!(KernelManifest { version: 3, ..v2 }.check().is_err());
    }

    #[test]
    fn manifest_rules_and_runs() {
        let m =
            KernelManifest { version: 1, kernels: vec![kernel(1, KernelTarget::Cpu), kernel(2, KernelTarget::Gpu)] };
        m.check().unwrap();
        assert_eq!(m.runs(2), [(1, CPU_KERNEL), (2, 0), (2, 1)]);
        assert_eq!(m.kernel(2).map(|k| k.target), Some(KernelTarget::Gpu));
        assert!(m.kernel(3).is_none());

        let mut bad = m.clone();
        bad.kernels.swap(0, 1);
        assert_eq!(bad.check(), Err(KernelError::NotSorted));
        let mut bad = m.clone();
        bad.kernels[0].wall_limit_secs = MAX_KERNEL_WALL_SECS + 1;
        assert_eq!(bad.check(), Err(KernelError::WallLimit(1)));
        let mut bad = m.clone();
        bad.kernels[1].command.env = vec![("TOG_SEGMENT".into(), "0".into())];
        assert!(matches!(bad.check(), Err(KernelError::Command(2, AdmissionError::ReservedEnv(_)))));
        assert_eq!(KernelManifest { version: 3, ..m }.check(), Err(KernelError::Version(3)));
    }

    #[test]
    fn kernel_set_lookup() {
        let gpu = KernelBucket::Gpu { cc: ComputeCapability { major: 9, minor: 0 }, driver_major: 550 };
        let cpu = KernelBucket::Cpu(CpuIsaLevel::X86_64V3);
        let set = KernelSet { expected: vec![(1, cpu, [1; 32]), (2, gpu, [2; 32])] };
        set.check().unwrap();
        assert_eq!(set.expected(2, gpu), Some([2; 32]));
        assert_eq!(set.expected(1, KernelBucket::Cpu(CpuIsaLevel::X86_64V4)), None);
        assert_eq!(
            KernelSet { expected: vec![(2, gpu, [2; 32]), (1, cpu, [1; 32])] }.check(),
            Err(KernelError::NotSorted)
        );
        assert_eq!(borsh::to_vec(&KernelTarget::Gpu).unwrap(), [1]);
        assert_eq!(borsh::to_vec(&gpu).unwrap()[0], 1);
    }
}
