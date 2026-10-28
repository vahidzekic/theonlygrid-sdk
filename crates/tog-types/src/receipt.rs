//! Execution receipt and result commitment (TOG-SPEC-0001 §4.2 steps 7–8).

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Domain, Hash32};

use crate::job::{CommandSpec, ComputeCapability, DealId, DriverVersion, IsolationTier, ToolchainProfileId};

/// Sealed by the executor after the last segment.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionReceipt {
    /// Job this receipt is for.
    pub job_id: Hash32,
    /// Worker that ran it.
    pub executor: Address,
    /// Hub height at which the claim was included.
    pub claim_height: u64,
    /// `H("TOG/v1/env" ‖ borsh(EnvDescriptor))`, see [`EnvDescriptor::digest`].
    pub env_digest: Hash32,
    /// `S_{N-1}` of the segment chain; `S_{-1}` if the job died before segment 0 completed.
    pub segment_root: Hash32,
    /// BLAKE3 root of the output archive (TDA v1 of the non-`Ignore` output files); for an
    /// unsegmented job it equals the `plaintext_root` of `ckpt_0`.
    pub output_root: Hash32,
    /// Container exit code; non-zero is a deterministic job fault (§5.3).
    pub exit_status: i32,
    /// Metered Work Units (§5.4).
    pub work_units: u64,
    /// Output deal and checkpoint deal (TOG-SPEC-0004 §13).
    pub data_availability: Vec<DealId>,
}

impl ExecutionReceipt {
    /// Result commitment for `CommitResult`: `H("TOG/v1/result" ‖ borsh(receipt) ‖ salt)`.
    pub fn commitment(&self, salt: &[u8; 32]) -> Hash32 {
        tagged_hash(Domain::Result, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail"), salt])
    }
}

/// The environment a job ran in (TOG-SPEC-0001 §4.2 step 7).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EnvDescriptor {
    /// `tog-executor` version, `"major.minor.patch"`.
    pub runtime_version: String,
    /// The tier the job actually ran in.
    pub tier: IsolationTier,
    /// Bucket of GPU 0 of the lease; `None` for CPU-only jobs.
    pub gpu: Option<(ComputeCapability, DriverVersion)>,
    /// Toolchain profile.
    pub toolchain: ToolchainProfileId,
    /// [`oci_spec_hash`] of the job.
    pub oci_spec_hash: Hash32,
}

impl EnvDescriptor {
    /// `env_digest = H("TOG/v1/env" ‖ borsh(self))`.
    pub fn digest(&self) -> Hash32 {
        tagged_hash(Domain::Env, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }
}

/// `H("TOG/v1/oci-spec" ‖ borsh((manifest_digest, command)))`: what the executor builds the OCI
/// runtime spec from, together with the tier and runtime version.
pub fn oci_spec_hash(manifest_digest: &[u8; 32], command: &CommandSpec) -> Hash32 {
    let b = borsh::to_vec(&(manifest_digest, command)).expect("in-memory borsh cannot fail");
    tagged_hash(Domain::OciSpec, &[&b])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> ExecutionReceipt {
        ExecutionReceipt {
            job_id: [1; 32],
            executor: [2; 20],
            claim_height: 10,
            env_digest: [3; 32],
            segment_root: [4; 32],
            output_root: [5; 32],
            exit_status: 0,
            work_units: 1000,
            data_availability: vec![],
        }
    }

    #[test]
    fn commitment_binds_salt_and_receipt() {
        let r = receipt();
        assert_ne!(r.commitment(&[0; 32]), r.commitment(&[1; 32]));
        let mut other = receipt();
        other.work_units += 1;
        assert_ne!(r.commitment(&[0; 32]), other.commitment(&[0; 32]));
    }

    #[test]
    fn borsh_roundtrip() {
        let r = receipt();
        assert_eq!(borsh::from_slice::<ExecutionReceipt>(&borsh::to_vec(&r).unwrap()).unwrap(), r);
    }

    #[test]
    fn env_digest_binds_every_field() {
        let job = crate::testing::sample_job();
        let env = EnvDescriptor {
            runtime_version: "1.0.0".into(),
            tier: IsolationTier::T2MicroVm,
            gpu: Some((ComputeCapability { major: 9, minor: 0 }, DriverVersion { major: 550, minor: 54 })),
            toolchain: ToolchainProfileId([6; 32]),
            oci_spec_hash: oci_spec_hash(&job.spec.image.manifest_digest, &job.spec.command),
        };
        let mut other = env.clone();
        other.tier = IsolationTier::T1Runc;
        assert_ne!(env.digest(), other.digest());
        let mut other = env.clone();
        other.gpu = None;
        assert_ne!(env.digest(), other.digest());
        let mut cmd = job.spec.command.clone();
        cmd.args.push("x".into());
        assert_ne!(env.oci_spec_hash, oci_spec_hash(&job.spec.image.manifest_digest, &cmd));
        assert_eq!(env.digest(), tagged_hash(Domain::Env, &[&borsh::to_vec(&env).unwrap()]));
    }
}
