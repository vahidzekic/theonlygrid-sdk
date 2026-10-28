//! Verification modules (TOG-SPEC-0007 §7.2, 0000 §10.3): a chain's own rule for "same result",
//! compiled to a small Wasm blob that imports nothing.
//!
//! A chain implements [`VerificationModule`] in its own crate and exports it with
//! `tog_runtime_io::export_verification!` (built with `tog-runtime-io`'s `pure` feature). The blob
//! goes to the Hub with `UploadCode`, passes the pre-check and is bound with `SetVerificationModule`;
//! the chain's `verify` module mirrors the binding.
//!
//! Both functions can only tighten the protocol: `compare_sketch` is checked **after**
//! `sketch::within_tolerance` holds, so it can only turn a match into a mismatch, and `sample` only
//! adds segments. Hub validators run them with 10⁸ fuel and 64 MiB; a trap counts as `Mismatch` and
//! as no added segments.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use tog_types::checkpoint::Sketch;
use tog_types::job::JobSpec;

/// A comparison's result (indices 0, 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Verdict {
    /// The two outputs are the same result.
    Match,
    /// They differ.
    Mismatch,
}

/// A chain's verification rule. Must be deterministic and use integer (fixed-point) math only.
pub trait VerificationModule {
    /// Compare the executor's sketch with a verifier's (TOG-SPEC-0003 §5.2).
    fn compare_sketch(executor: &Sketch, verifier: &Sketch) -> Verdict;
    /// Segments to re-execute in addition to the protocol's plan, given the job and `ρ`
    /// (TOG-SPEC-0003 §8.2). Indices `≥ N` are ignored.
    fn sample(job: &JobSpec, randomness: &[u8; 32]) -> Vec<u32>;
}

/// The `tog_v1_compare_sketch` body: decode, compare, encode. Bad input traps, which the Hub
/// counts as `Mismatch`.
pub fn compare_sketch_entry<M: VerificationModule>(input: &[u8]) -> Vec<u8> {
    let (e, v): (Sketch, Sketch) = borsh::from_slice(input).expect("compare_sketch input decodes");
    borsh::to_vec(&M::compare_sketch(&e, &v)).expect("in-memory borsh")
}

/// The `tog_v1_sample` body: decode, sample, encode. Bad input traps, which adds nothing.
pub fn sample_entry<M: VerificationModule>(input: &[u8]) -> Vec<u8> {
    let (job, rho): (JobSpec, [u8; 32]) = borsh::from_slice(input).expect("sample input decodes");
    borsh::to_vec(&M::sample(&job, &rho)).expect("in-memory borsh")
}
