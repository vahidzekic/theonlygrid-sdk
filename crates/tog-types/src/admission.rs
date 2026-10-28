//! Mempool admission checks that need no chain state (TOG-SPEC-0001 §3.4, steps 1 and 3).
//!
//! Signature and nonce checks (step 2) need the account scheme, and the stateful
//! checks (step 4) need Hub state; both live with the mempool.

use crate::job::*;
use crate::payload::{Encryption, PayloadKind};
#[cfg(not(feature = "std"))]
use crate::prelude::*;
use tog_primitives::ChainId;

/// Maximum encoded size of a `JobTx` (§3.4 step 1).
pub const MAX_JOB_TX_BYTES: usize = 64 * 1024;
/// Maximum length of any string field, in bytes.
pub const MAX_STRING_BYTES: usize = 1024;
/// Longest a single unsegmented job, or one segment, may run. Longer jobs must segment.
pub const MAX_SEGMENT_WALL_TIME_SECS: u64 = 3600;

/// Largest `SegmentationSpec.substeps` (TOG-SPEC-0003 §4.5).
pub const MAX_SUBSTEPS: u16 = 64;
/// Most segments of a job (TOG-SPEC-0001 §3.4 rule 3), so a run's output fits one 1 MiB frame.
pub const MAX_SEGMENTS: u32 = 256;
/// Most GPUs one job may request (single host, NVLink-local; §6 item 4).
pub const MAX_GPUS: u8 = 8;
/// Largest `KeyBroker::Sender.deliver_within`, in blocks (TOG-SPEC-0010 §6.2).
pub const MAX_DELIVER_WITHIN: u32 = 600;
/// Allowed verifiers per sampled segment (TOG-SPEC-0003 §3.2).
pub const REPLICAS: core::ops::RangeInclusive<u8> = 3..=7;
/// `R_high`: jobs with `max_budget` at or above this need [`HIGH_VALUE_MIN_REPLICAS`] verifiers
/// (Hub parameter, genesis value 10 000 TOG; TOG-SPEC-0004 §7.5).
pub const R_HIGH: tog_primitives::Amount = 10_000 * tog_primitives::ONE_TOG;
/// Fewest verifiers per sampled segment on a job at or above [`R_HIGH`].
pub const HIGH_VALUE_MIN_REPLICAS: u8 = 5;
/// Environment prefix reserved for the executor.
pub const RESERVED_ENV_PREFIX: &str = "TOG_";
/// Keys the executor pins in every run besides `TOG_*` (TOG-SPEC-0001 §2.6); a job can't set them.
pub const PINNED_ENV: [&str; 11] = [
    "CUBLAS_WORKSPACE_CONFIG",
    "GLIBC_TUNABLES",
    "HOSTNAME",
    "LD_LIBRARY_PATH",
    "MKL_CBWR",
    "MKL_NUM_THREADS",
    "NVIDIA_VISIBLE_DEVICES",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "SOURCE_DATE_EPOCH",
    "TZ",
];

/// True if `key` is the executor's: a `TOG_` key or a pinned one.
pub fn is_reserved_env(key: &str) -> bool {
    key.starts_with(RESERVED_ENV_PREFIX) || PINNED_ENV.contains(&key)
}

/// Stateful rule 4 (§3.4): no `command.env` key is in the toolchain profile's `required_env`.
pub fn check_required_env(job: &JobTx, required_env: &[(String, String)]) -> Result<(), AdmissionError> {
    match job.spec.command.env.iter().find(|(k, _)| required_env.iter().any(|(r, _)| r == k)) {
        Some((k, _)) => Err(AdmissionError::ReservedEnv(k.clone())),
        None => Ok(()),
    }
}
/// Input mount the verifier path uses for the start checkpoint (§4.3).
pub const RESERVED_MOUNT: &str = "ckpt";
/// Further input mounts reserved in `CheckerOnly` jobs: the checker's `ckpt_n` and output
/// archive (TOG-SPEC-0003 §5.3).
pub const CHECKER_RESERVED_MOUNTS: [&str; 2] = ["result", "output"];

/// First components of `/out` paths the executor writes itself (TOG-SPEC-0001 §4.2 step 6).
pub const RESERVED_OUTPUT_DIRS: [&str; 3] = ["ckpt", "subckpt", "metrics"];
/// Smallest `hw.ram_bytes`.
pub const MIN_RAM_BYTES: u64 = 256 << 20;
/// Smallest non-zero `hw.scratch_bytes`.
pub const MIN_SCRATCH_BYTES: u64 = 1 << 20;

/// Why a job was rejected.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// Encoded transaction is too large.
    #[error("encoded job is {0} bytes, limit {MAX_JOB_TX_BYTES}")]
    TooLarge(usize),
    /// A string field is too long.
    #[error("string field `{0}` exceeds {MAX_STRING_BYTES} bytes")]
    StringTooLong(&'static str),
    /// A list that must be canonical is not sorted or has duplicates.
    #[error("`{0}` must be sorted and free of duplicates")]
    NotCanonical(&'static str),
    /// Environment uses a reserved key.
    #[error("environment key `{0}` uses the reserved TOG_ prefix")]
    ReservedEnv(String),
    /// A name or path is malformed.
    #[error("invalid {field}: `{value}`")]
    InvalidName {
        /// Which field.
        field: &'static str,
        /// Offending value.
        value: String,
    },
    /// T3 without confidential spec, or confidential spec below T3.
    #[error("confidential jobs require T3 and T3 requires a confidential spec")]
    ConfidentialMismatch,
    /// A confidential job with `input_ranges` (TOG-SPEC-0010 §6.3: no partial input views for T3 in v1).
    #[error("confidential jobs cannot have input_ranges")]
    ConfidentialInputRanges,
    /// An input is `Checkpoint`-encrypted, or `Confidential` other than under a T3 job's own
    /// policy (TOG-SPEC-0001 §5.1 rule 3, #372).
    #[error("input {0}: encryption must be None, or Confidential under the job's policy on T3")]
    InputEncryption(String),
    /// `KeyBroker::Sender.deliver_within` outside `1..=600` (TOG-SPEC-0010 §6.2).
    #[error("deliver_within {0} outside 1..={MAX_DELIVER_WITHIN}")]
    DeliverWithin(u32),
    /// GPU count outside 1..=8.
    #[error("gpu count {0} outside 1..={MAX_GPUS}")]
    GpuCount(u8),
    /// `allow_mig` with more than one GPU.
    #[error("allow_mig needs gpu.count = 1, got {0}")]
    MigCount(u8),
    /// `interconnect` must be set exactly when `count > 1`.
    #[error("interconnect must be set iff gpu count > 1")]
    Interconnect,
    /// Output retention is inconsistent with its class.
    #[error("invalid output retention: {0}")]
    Retention(&'static str),
    /// Compute-capability range is empty.
    #[error("compute capability range is empty")]
    EmptyCcRange,
    /// `replicas` outside 3..=7.
    #[error("replicas {0} outside 3..=7")]
    Replicas(u8),
    /// `max_budget ≥ R_high` with fewer than 5 replicas.
    #[error("replicas {0} below 5 for a job with max_budget >= R_high")]
    HighValueReplicas(u8),
    /// `challenge_window_blocks` outside `w_opt_min..=`[`W_OPT_MAX`].
    #[error("challenge_window_blocks {0} outside w_opt_min..=43200")]
    ChallengeWindow(u32),
    /// A `Locator::Https` url that isn't `https://` with a host, or `http://` on a chain without
    /// `compute_market.params.http_locators`.
    #[error("locator url {0:?} is not https:// with a host")]
    LocatorScheme(String),
    /// A `Bitwise` or `BitwiseSameArch` job on an (image, toolchain) pair flagged nondeterministic.
    #[error("image and toolchain flagged nondeterministic at block {0}: use Tolerance or CheckerOnly")]
    Nondeterministic(u64),
    /// Sample rate floor above 100 %.
    #[error("min_sample_rate_bp {0} exceeds 10000")]
    SampleRate(u16),
    /// `comparison` does not have one rule per output path.
    #[error("outputs.comparison has {rules} rules for {paths} paths")]
    ComparisonMismatch {
        /// Number of paths.
        paths: usize,
        /// Number of rules.
        rules: usize,
    },
    /// Job or segment runs too long without segmentation.
    #[error("wall time {0}s exceeds {MAX_SEGMENT_WALL_TIME_SECS}s; long jobs must segment")]
    MustSegment(u64),
    /// Segmentation fields are zero, `max_segments` is above [`MAX_SEGMENTS`], or `full_state_every`
    /// is not 1.
    #[error("segmentation needs steps_per_segment > 0, max_segments in 1..=256 and full_state_every = 1")]
    BadSegmentation,
    /// `Lazy { resume_every }` above [`crate::storage::MAX_PAYLOADS_PER_TX`]: a resume point appends
    /// up to `resume_every` leaves in one transaction (TOG-SPEC-0004 §4.8 rule 8).
    #[error("resume_every {0} exceeds {max}", max = crate::storage::MAX_PAYLOADS_PER_TX)]
    ResumeEvery(u32),
    /// An unsegmented job's `max_segment_wall_time_secs` differs from `max_wall_time_secs`.
    #[error("an unsegmented job's segment wall time must equal its wall time")]
    SegmentWall,
    /// Transaction is for another chain.
    #[error("wrong chain id {0}")]
    WrongChain(u64),
    /// Transaction expired.
    #[error("expired at height {0}")]
    Expired(u64),
    /// `image.blobs` is inconsistent with the image.
    #[error("invalid image blobs: {0}")]
    ImageBlobs(&'static str),
    /// An input is not a version-1 `Input` payload.
    #[error("input `{0}` is not a version 1 Input payload")]
    InputPayload(String),
    /// `fee.storage_fee` overflows or exceeds `max_budget`.
    #[error("storage_fee exceeds max_budget")]
    StorageFee,
    /// `substeps` is not 0 or a power of two ≤ 64 dividing `steps_per_segment`, or the class is not Bitwise.
    #[error("invalid substeps {0}")]
    Substeps(u16),
    /// An `abs_tol` is not finite and `≥ 0` (or is `−0.0`); carries the raw bits.
    #[error("abs_tol bits {0:#010x} are not a finite value ≥ +0.0")]
    AbsTol(u32),
    /// A segmented Tolerance job has no `Tensor` rule to set its checkpoint tolerance.
    #[error("a segmented Tolerance job needs a Tensor comparison rule")]
    NoTensorRule,
    /// A `Metric` comparison rule: v1 sketches compare tensors only (TOG-SPEC-0003 §5.2), so no
    /// verifier could hold a metric to its tolerance.
    #[error("Metric comparison rules are not supported in v1")]
    MetricRule,
    /// A T3 `Tolerance` job whose enclave policy has `allow_sketches = false` (TOG-SPEC-0010 §6.3).
    #[error("the enclave policy does not allow sketches, so a T3 job can't be Tolerance")]
    SketchesNotAllowed,
    /// A resource limit below its floor (TOG-SPEC-0001 §3.4 "Resource floors"): the OCI runtime
    /// reads a zero limit as unset.
    #[error("{0} below its floor")]
    ResourceFloor(&'static str),
    /// More output paths than a `ComputeResult` carries.
    #[error("{0} output paths, limit {max}", max = crate::cgmp::MAX_OUTPUTS)]
    TooManyOutputs(usize),
}

/// `W_opt`'s lower bound outside devnet: `compute_market.params.w_opt_min` (TOG-SPEC-0003 §10).
pub const W_OPT_MIN: u32 = 1_800;
/// `W_opt`'s upper bound.
pub const W_OPT_MAX: u32 = 43_200;

/// The `W_opt` rule (TOG-SPEC-0001 §3.4): `challenge_window_blocks` in `w_opt_min..=W_OPT_MAX`,
/// with `w_opt_min` from `compute_market.params`. Checked by the Hub's admission, not
/// [`check_job`].
pub fn check_challenge_window(job: &JobTx, w_opt_min: u32) -> Result<(), AdmissionError> {
    let w = job.spec.verification.challenge_window_blocks;
    if !(w_opt_min..=W_OPT_MAX).contains(&w) {
        return Err(AdmissionError::ChallengeWindow(w));
    }
    Ok(())
}

/// The scheme of a `Locator::Https` url, `Some(true)` for `https://` and `Some(false)` for
/// `http://`, when a non-empty host follows it (TOG-SPEC-0001 §3.4 "Locator scheme").
fn locator_scheme(url: &str) -> Option<bool> {
    let (tls, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (true, rest),
        (_, Some(rest)) => (false, rest),
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    let host = match host_port.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => host_port.split(':').next().unwrap_or_default(),
    };
    (!host.is_empty()).then_some(tls)
}

/// The `http_locators` rule (TOG-SPEC-0001 §3.4 step 4): an `http://` locator only on a chain
/// whose `compute_market.params.http_locators` is set. [`check_job`] already refused every other
/// scheme. Checked by the Hub's admission, not [`check_job`].
pub fn check_locator_scheme(job: &JobTx, http_locators: bool) -> Result<(), AdmissionError> {
    if http_locators {
        return Ok(());
    }
    let spec = &job.spec;
    let checker = match &spec.determinism {
        DeterminismClass::CheckerOnly { checker } => Some(checker),
        _ => None,
    };
    let locators = spec.image.locators.iter().chain(spec.inputs.iter().flat_map(|i| &i.locators));
    for l in locators.chain(checker.into_iter().flat_map(|c| &c.locators)) {
        if let Locator::Https { url } = l {
            if locator_scheme(url) != Some(true) {
                return Err(AdmissionError::LocatorScheme(url.clone()));
            }
        }
    }
    Ok(())
}

/// The rule on `compute_market.nondeterministic` (TOG-SPEC-0003 §5.4): `flagged_at` is the entry
/// for the job's `(image.manifest_digest, toolchain)`, if any.
pub fn check_nondeterministic(job: &JobTx, flagged_at: Option<u64>) -> Result<(), AdmissionError> {
    let bitwise = matches!(job.spec.determinism, DeterminismClass::Bitwise | DeterminismClass::BitwiseSameArch);
    match flagged_at {
        Some(h) if bitwise => Err(AdmissionError::Nondeterministic(h)),
        _ => Ok(()),
    }
}

/// What the stateless checks need to know about the Hub.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionContext {
    /// Network id from the Hub genesis; jobs carry `network_id << 32` (TOG-SPEC-0000 §13.2).
    pub network_id: u32,
    /// Current Hub height.
    pub height: u64,
}

/// Run §3.4 steps 1 and 3 plus the chain-id / expiry part of step 2.
pub fn check_stateless(job: &JobTx, ctx: &AdmissionContext) -> Result<(), AdmissionError> {
    if job.chain_id != ChainId::HUB.replay_domain(ctx.network_id) {
        return Err(AdmissionError::WrongChain(job.chain_id));
    }
    if job.valid_until_height < ctx.height {
        return Err(AdmissionError::Expired(job.valid_until_height));
    }
    check_job(job)
}

/// The admission rule that needs a T3 job's enclave policy (`hardware_registry.enclave_policies`
/// at the job's `confidential.policy`, TOG-SPEC-0010 §6.3): a `Tolerance` job needs a policy with
/// `allow_sketches`. Jobs without a confidential spec pass.
pub fn check_policy(job: &JobTx, policy: &crate::enclave::EnclavePolicy) -> Result<(), AdmissionError> {
    let tolerance = matches!(job.spec.determinism, DeterminismClass::Tolerance);
    if job.spec.confidential.is_some() && tolerance && !policy.allow_sketches {
        return Err(AdmissionError::SketchesNotAllowed);
    }
    Ok(())
}

/// Checks on the job alone (§3.4 steps 1 and 3). The executor re-runs these on
/// every `RunJob` because it never trusts `togd`'s parse (§4.3).
pub fn check_job(job: &JobTx) -> Result<(), AdmissionError> {
    let len = borsh::to_vec(job).expect("in-memory borsh cannot fail").len();
    if len > MAX_JOB_TX_BYTES {
        return Err(AdmissionError::TooLarge(len));
    }
    check_canonical(&job.spec)?;
    check_semantics(&job.spec)
}

/// Rule 1 (§3.4) on a command: string caps, well-formed env keys that are not the executor's,
/// env strictly sorted by key. Calibration kernels follow it too (§4.2 step 0).
pub fn check_command(cmd: &CommandSpec) -> Result<(), AdmissionError> {
    // execve and the OCI config can't carry a NUL, so no string here may hold one.
    let arg = |s: &String, field: &'static str| {
        cap(s, field)?;
        match s.contains('\0') {
            true => Err(AdmissionError::InvalidName { field, value: s.clone() }),
            false => Ok(()),
        }
    };
    for s in cmd.entrypoint.iter().chain(&cmd.args) {
        arg(s, "command")?;
    }
    if let Some(w) = &cmd.workdir {
        arg(w, "command.workdir")?;
    }
    for (k, v) in &cmd.env {
        cap(k, "command.env")?;
        arg(v, "command.env")?;
        if is_reserved_env(k) {
            return Err(AdmissionError::ReservedEnv(k.clone()));
        }
        if k.is_empty() || k.contains('=') || k.contains('\0') {
            return Err(AdmissionError::InvalidName { field: "command.env", value: k.clone() });
        }
    }
    strictly_sorted(cmd.env.iter().map(|(k, _)| k), "command.env")?;
    Ok(())
}

fn check_canonical(job: &JobSpec) -> Result<(), AdmissionError> {
    check_command(&job.command)?;
    let checker_image = match &job.determinism {
        DeterminismClass::CheckerOnly { checker } => Some(checker),
        _ => None,
    };
    let locators = job.image.locators.iter().chain(job.inputs.iter().flat_map(|i| &i.locators));
    for l in locators.chain(checker_image.into_iter().flat_map(|c| &c.locators)) {
        if let Locator::Https { url } = l {
            cap(url, "locators.url")?;
            if locator_scheme(url).is_none() {
                return Err(AdmissionError::LocatorScheme(url.clone()));
            }
        }
    }
    for c in &job.outputs.comparison {
        if let OutputComparison::Metric { key, .. } = c {
            cap(key, "outputs.comparison.key")?;
        }
    }

    let checker = matches!(job.determinism, crate::DeterminismClass::CheckerOnly { .. });
    for i in &job.inputs {
        cap(&i.mount_name, "inputs.mount_name")?;
        let reserved =
            i.mount_name == RESERVED_MOUNT || (checker && CHECKER_RESERVED_MOUNTS.contains(&i.mount_name.as_str()));
        if !is_plain_name(&i.mount_name) || reserved {
            return Err(AdmissionError::InvalidName { field: "inputs.mount_name", value: i.mount_name.clone() });
        }
    }
    strictly_sorted(job.inputs.iter().map(|i| &i.mount_name), "inputs")?;

    if job.outputs.paths.len() > crate::cgmp::MAX_OUTPUTS {
        return Err(AdmissionError::TooManyOutputs(job.outputs.paths.len()));
    }
    for p in &job.outputs.paths {
        cap(p, "outputs.paths")?;
        if !is_relative_path(p) || is_reserved_output(p) {
            return Err(AdmissionError::InvalidName { field: "outputs.paths", value: p.clone() });
        }
    }
    strictly_sorted(job.outputs.paths.iter(), "outputs.paths")?;

    let external: Vec<Vec<u8>> =
        job.outputs.publish.external.iter().map(|e| borsh::to_vec(e).expect("in-memory borsh cannot fail")).collect();
    if external.windows(2).any(|w| w[0] >= w[1]) {
        return Err(AdmissionError::NotCanonical("outputs.publish.external"));
    }
    Ok(())
}

fn check_semantics(job: &JobSpec) -> Result<(), AdmissionError> {
    check_image(&job.image)?;
    if let DeterminismClass::CheckerOnly { checker } = &job.determinism {
        check_image(checker)?;
    }
    for i in &job.inputs {
        if !i.content.payload.is_v1(PayloadKind::Input) {
            return Err(AdmissionError::InputPayload(i.mount_name.clone()));
        }
    }
    let f = &job.fee;
    if !f.storage_fee.total().is_some_and(|t| t <= f.max_budget) {
        return Err(AdmissionError::StorageFee);
    }

    check_floors(job)?;

    let t3 = job.min_isolation == IsolationTier::T3Confidential;
    if t3 != job.confidential.is_some() {
        return Err(AdmissionError::ConfidentialMismatch);
    }
    if t3 && job.segmentation.as_ref().is_some_and(|s| s.input_ranges.is_some()) {
        return Err(AdmissionError::ConfidentialInputRanges);
    }
    for i in &job.inputs {
        let ok = match (&i.content.payload.encryption, &job.confidential) {
            (Encryption::None, _) => true,
            (Encryption::Confidential { policy, .. }, Some(c)) => t3 && *policy == c.policy,
            _ => false,
        };
        if !ok {
            return Err(AdmissionError::InputEncryption(i.mount_name.clone()));
        }
    }
    if let Some(KeyBroker::Sender { deliver_within, .. }) = job.confidential.as_ref().map(|c| &c.broker) {
        if !(1..=MAX_DELIVER_WITHIN).contains(deliver_within) {
            return Err(AdmissionError::DeliverWithin(*deliver_within));
        }
    }

    if let Some(gpu) = &job.hw.gpu {
        if gpu.count == 0 || gpu.count > MAX_GPUS {
            return Err(AdmissionError::GpuCount(gpu.count));
        }
        if (gpu.count > 1) != gpu.interconnect.is_some() {
            return Err(AdmissionError::Interconnect);
        }
        if gpu.allow_mig && gpu.count != 1 {
            return Err(AdmissionError::MigCount(gpu.count));
        }
        let cc = gpu.compute_capability;
        if cc.min > cc.max {
            return Err(AdmissionError::EmptyCcRange);
        }
    }

    let v = &job.verification;
    if !REPLICAS.contains(&v.replicas) {
        return Err(AdmissionError::Replicas(v.replicas));
    }
    if job.fee.max_budget >= R_HIGH && v.replicas < HIGH_VALUE_MIN_REPLICAS {
        return Err(AdmissionError::HighValueReplicas(v.replicas));
    }
    if let Some(bp) = v.min_sample_rate_bp {
        if bp > 10_000 {
            return Err(AdmissionError::SampleRate(bp));
        }
    }

    let o = &job.outputs;
    if o.paths.len() != o.comparison.len() {
        return Err(AdmissionError::ComparisonMismatch { paths: o.paths.len(), rules: o.comparison.len() });
    }
    if o.comparison.iter().any(|c| matches!(c, OutputComparison::Metric { .. })) {
        return Err(AdmissionError::MetricRule);
    }
    for c in &o.comparison {
        if let OutputComparison::Tensor { abs_tol, .. } = c {
            // Sign bit clear rejects negatives and −0.0, so each tolerance has one encoding.
            if !abs_tol.to_f32().is_finite() || abs_tol.0 >> 31 != 0 {
                return Err(AdmissionError::AbsTol(abs_tol.0));
            }
        }
    }
    if job.segmentation.is_some()
        && job.determinism == DeterminismClass::Tolerance
        && !o.comparison.iter().any(|c| matches!(c, OutputComparison::Tensor { .. }))
    {
        return Err(AdmissionError::NoTensorRule);
    }

    let r = &o.publish;
    match r.class {
        RetentionClass::Hot => return Err(AdmissionError::Retention("outputs are not Hot")),
        RetentionClass::ChallengeWindow if r.duration_blocks != 0 || !r.external.is_empty() => {
            return Err(AdmissionError::Retention("duration and external are LongTerm only"))
        }
        RetentionClass::LongTerm if r.duration_blocks == 0 => {
            return Err(AdmissionError::Retention("LongTerm needs a duration"))
        }
        _ => {}
    }

    let l = &job.limits;
    match &job.segmentation {
        None if l.max_wall_time_secs > MAX_SEGMENT_WALL_TIME_SECS => {
            return Err(AdmissionError::MustSegment(l.max_wall_time_secs))
        }
        // Only the segment limit kills a run, so it must carry the 1 h cap.
        None if l.max_segment_wall_time_secs != l.max_wall_time_secs => return Err(AdmissionError::SegmentWall),
        Some(s)
            if s.steps_per_segment == 0 || !(1..=MAX_SEGMENTS).contains(&s.max_segments) || s.full_state_every != 1 =>
        {
            return Err(AdmissionError::BadSegmentation)
        }
        Some(s) if s.substeps != 0 && !substeps_valid(s.substeps, s.steps_per_segment, &job.determinism) => {
            return Err(AdmissionError::Substeps(s.substeps))
        }
        Some(_) if l.max_segment_wall_time_secs > MAX_SEGMENT_WALL_TIME_SECS => {
            return Err(AdmissionError::MustSegment(l.max_segment_wall_time_secs))
        }
        _ => {}
    }
    if let Some(CheckpointPlacement::Lazy { resume_every }) = job.segmentation.as_ref().map(|s| s.checkpoint_placement)
    {
        if resume_every as usize > crate::storage::MAX_PAYLOADS_PER_TX {
            return Err(AdmissionError::ResumeEvery(resume_every));
        }
    }
    Ok(())
}

/// Resource floors (TOG-SPEC-0001 §3.4): every limit the executor sets is real, and a segmented
/// job's checkpoint fits its output quota.
fn check_floors(job: &JobSpec) -> Result<(), AdmissionError> {
    let hw = &job.hw;
    let floor = |ok: bool, field| if ok { Ok(()) } else { Err(AdmissionError::ResourceFloor(field)) };
    floor(hw.cpu_cores >= 1, "hw.cpu_cores")?;
    floor(hw.ram_bytes >= MIN_RAM_BYTES, "hw.ram_bytes")?;
    floor(hw.scratch_bytes == 0 || hw.scratch_bytes >= MIN_SCRATCH_BYTES, "hw.scratch_bytes")?;
    floor(job.limits.max_segment_wall_time_secs >= 1, "limits.max_segment_wall_time_secs")?;
    floor(job.outputs.max_bytes >= 1, "outputs.max_bytes")?;
    let ckpt = job.segmentation.as_ref().map_or(0, |s| s.checkpoint_max_bytes);
    floor(ckpt <= job.outputs.max_bytes, "outputs.max_bytes (checkpoint_max_bytes)")
}

/// Blobs of TOG-SPEC-0001 §3.2: manifest first, every blob a version-1 `Image` payload with
/// an OCI digest, sizes summing to `total_size`.
fn check_image(image: &ImageRef) -> Result<(), AdmissionError> {
    let Some(manifest) = image.blobs.first() else { return Err(AdmissionError::ImageBlobs("no blobs")) };
    if manifest.oci_digest != Some(image.manifest_digest) {
        return Err(AdmissionError::ImageBlobs("blobs[0] is not the manifest"));
    }
    if !image.blobs.iter().all(|b| b.is_v1(PayloadKind::Image) && b.oci_digest.is_some()) {
        return Err(AdmissionError::ImageBlobs("every blob must be a version 1 Image payload with an OCI digest"));
    }
    let total = image.blobs.iter().try_fold(0u64, |acc, b| acc.checked_add(b.size));
    if total != Some(image.total_size) {
        return Err(AdmissionError::ImageBlobs("sizes must sum to total_size"));
    }
    Ok(())
}

/// Micro-bisection (TOG-SPEC-0003 §4.5): a power of two up to 64, Bitwise classes only. Sub-checkpoints
/// are written every `steps_per_segment / substeps` steps, so it must divide the segment.
fn substeps_valid(substeps: u16, steps_per_segment: u64, class: &DeterminismClass) -> bool {
    substeps.is_power_of_two()
        && substeps <= MAX_SUBSTEPS
        && steps_per_segment % u64::from(substeps) == 0
        && matches!(class, DeterminismClass::Bitwise | DeterminismClass::BitwiseSameArch)
}

fn cap(s: &str, field: &'static str) -> Result<(), AdmissionError> {
    if s.len() > MAX_STRING_BYTES {
        return Err(AdmissionError::StringTooLong(field));
    }
    Ok(())
}

fn strictly_sorted<'a>(mut it: impl Iterator<Item = &'a String>, field: &'static str) -> Result<(), AdmissionError> {
    let Some(mut prev) = it.next() else { return Ok(()) };
    for cur in it {
        if cur <= prev {
            return Err(AdmissionError::NotCanonical(field));
        }
        prev = cur;
    }
    Ok(())
}

/// Output names the executor writes itself in `/out` (TOG-SPEC-0001 §4.2 step 6): a path whose
/// first component is `ckpt`, `subckpt` or `metrics`, or that is `done`.
fn is_reserved_output(p: &str) -> bool {
    let first = p.split('/').next().unwrap_or(p);
    p == "done" || RESERVED_OUTPUT_DIRS.contains(&first)
}

/// One path component: non-empty, no `/`, not `.` or `..`, no NUL.
fn is_plain_name(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains('/') && !s.contains('\0')
}

/// Relative path of plain components, e.g. `model/weights.safetensors`.
fn is_relative_path(s: &str) -> bool {
    !s.is_empty() && s.split('/').all(is_plain_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: AdmissionContext = AdmissionContext { network_id: crate::testing::NETWORK_ID, height: 100 };

    fn job() -> JobTx {
        crate::testing::sample_job()
    }

    fn rejects(mutate: impl FnOnce(&mut JobTx)) -> AdmissionError {
        let mut j = job();
        mutate(&mut j);
        check_stateless(&j, &CTX).expect_err("should be rejected")
    }

    #[test]
    fn resource_floors_keep_every_limit_real() {
        use AdmissionError::ResourceFloor;
        assert_eq!(rejects(|j| j.spec.hw.cpu_cores = 0), ResourceFloor("hw.cpu_cores"));
        assert_eq!(rejects(|j| j.spec.hw.ram_bytes = MIN_RAM_BYTES - 1), ResourceFloor("hw.ram_bytes"));
        assert_eq!(rejects(|j| j.spec.hw.scratch_bytes = MIN_SCRATCH_BYTES - 1), ResourceFloor("hw.scratch_bytes"));
        assert_eq!(
            rejects(|j| j.spec.limits.max_segment_wall_time_secs = 0),
            ResourceFloor("limits.max_segment_wall_time_secs")
        );
        assert_eq!(rejects(|j| j.spec.outputs.max_bytes = 0), ResourceFloor("outputs.max_bytes"));
        let over =
            |j: &mut JobTx| j.spec.segmentation.as_mut().unwrap().checkpoint_max_bytes = j.spec.outputs.max_bytes + 1;
        assert_eq!(rejects(over), ResourceFloor("outputs.max_bytes (checkpoint_max_bytes)"));
        let mut j = job();
        j.spec.hw.ram_bytes = MIN_RAM_BYTES;
        j.spec.hw.scratch_bytes = 0;
        check_stateless(&j, &CTX).unwrap();
        j.spec.hw.scratch_bytes = MIN_SCRATCH_BYTES;
        check_stateless(&j, &CTX).unwrap();
    }

    #[test]
    fn outputs_never_name_the_executors_own_files() {
        for p in ["ckpt", "ckpt/a", "subckpt/0/1", "metrics", "metrics/x.json", "done"] {
            let e = rejects(|j| j.spec.outputs.paths[0] = p.into());
            assert_eq!(e, AdmissionError::InvalidName { field: "outputs.paths", value: p.into() });
        }
        assert!(!is_reserved_output("done/x") && !is_reserved_output("a/ckpt") && !is_reserved_output("ckpts"));
    }

    #[test]
    fn accepts_valid_job() {
        check_stateless(&job(), &CTX).unwrap();
    }

    #[test]
    fn job_id_is_stable_and_binds_fields() {
        let a = job();
        assert_eq!(a.job_id(), job().job_id());
        let mut b = job();
        b.nonce = 1;
        assert_ne!(a.job_id(), b.job_id());
    }

    #[test]
    fn borsh_roundtrip() {
        let j = job();
        let bytes = borsh::to_vec(&j).unwrap();
        assert_eq!(borsh::from_slice::<JobTx>(&bytes).unwrap(), j);
    }

    #[test]
    fn size_cap() {
        let e = rejects(|j| j.spec.image.locators = vec![Locator::Ipfs { cid: vec![0; MAX_JOB_TX_BYTES] }]);
        assert!(matches!(e, AdmissionError::TooLarge(_)));
    }

    #[test]
    fn output_count_cap() {
        let paths = |n: usize| (0..n).map(|i| format!("o{i:03}")).collect::<Vec<_>>();
        assert_eq!(rejects(|j| j.spec.outputs.paths = paths(257)), AdmissionError::TooManyOutputs(257));
    }

    #[test]
    fn canonical_lists() {
        assert_eq!(rejects(|j| j.spec.inputs.reverse()), AdmissionError::NotCanonical("inputs"));
        assert_eq!(rejects(|j| j.spec.command.env.reverse()), AdmissionError::NotCanonical("command.env"));
        assert_eq!(
            rejects(|j| j.spec.outputs.paths = vec!["a".into(), "a".into()]),
            AdmissionError::NotCanonical("outputs.paths")
        );
    }

    #[test]
    fn names_and_env() {
        assert!(matches!(rejects(|j| j.spec.command.env[0].0 = "TOG_SEGMENT".into()), AdmissionError::ReservedEnv(_)));
        assert!(matches!(rejects(|j| j.spec.command.env[1].0 = "TZ".into()), AdmissionError::ReservedEnv(_)));
        let required = [("B".to_string(), "x".to_string())];
        assert_eq!(check_required_env(&job(), &required), Err(AdmissionError::ReservedEnv("B".into())));
        assert_eq!(check_required_env(&job(), &[("C".into(), "x".into())]), Ok(()));
        assert!(matches!(rejects(|j| j.spec.inputs[0].mount_name = "ckpt".into()), AdmissionError::InvalidName { .. }));
        assert!(matches!(rejects(|j| j.spec.inputs[0].mount_name = "../x".into()), AdmissionError::InvalidName { .. }));
        // "result" and "output" are reserved in CheckerOnly jobs only.
        let checker = |j: &mut JobTx, name: &str| {
            j.spec.determinism = crate::DeterminismClass::CheckerOnly { checker: j.spec.image.clone() };
            j.spec.inputs[0].mount_name = name.into();
        };
        for name in CHECKER_RESERVED_MOUNTS {
            assert!(matches!(rejects(|j| checker(j, name)), AdmissionError::InvalidName { .. }));
        }
        let mut j = job();
        checker(&mut j, "a");
        check_stateless(&j, &CTX).unwrap();
        let mut j = job();
        j.spec.inputs[1].mount_name = "output".into();
        check_stateless(&j, &CTX).unwrap();
        assert!(matches!(
            rejects(|j| j.spec.outputs.paths[0] = "/etc/passwd".into()),
            AdmissionError::InvalidName { .. }
        ));
        assert!(matches!(rejects(|j| j.spec.command.args[0] = "x".repeat(2000)), AdmissionError::StringTooLong(_)));
    }

    #[test]
    fn chain_and_expiry() {
        assert_eq!(rejects(|j| j.chain_id = 2), AdmissionError::WrongChain(2));
        assert!(matches!(rejects(|j| j.chain_id = ChainId(7).replay_domain(1)), AdmissionError::WrongChain(_)));
        assert_eq!(rejects(|j| j.valid_until_height = 99), AdmissionError::Expired(99));
    }

    #[test]
    fn a_t3_tolerance_job_needs_a_policy_that_allows_sketches() {
        use crate::enclave::EnclavePolicy;
        let mut policy = EnclavePolicy {
            tees: vec![],
            measurements: vec![],
            min_cpu_tcb: vec![],
            gpu_models: vec![],
            min_gpu_driver: crate::job::DriverVersion { major: 0, minor: 0 },
            operators: None,
            allow_sketches: false,
            min_tdx_platform: None,
            require_smt_off: false,
        };
        let mut job = crate::testing::sample_job();
        assert_eq!(check_policy(&job, &policy), Ok(()), "not confidential");
        job.spec.min_isolation = IsolationTier::T3Confidential;
        job.spec.confidential = Some(ConfidentialSpec {
            policy: EnclavePolicyId([0; 32]),
            broker: KeyBroker::Sender { deliver_within: 10, request_key: [0; 32], key_check: [0; 32] },
        });
        assert_eq!(check_policy(&job, &policy), Err(AdmissionError::SketchesNotAllowed));
        policy.allow_sketches = true;
        assert_eq!(check_policy(&job, &policy), Ok(()));
        job.spec.determinism = DeterminismClass::Bitwise;
        policy.allow_sketches = false;
        assert_eq!(check_policy(&job, &policy), Ok(()));
    }

    #[test]
    fn inputs_are_plain_or_confidential_under_the_jobs_policy_and_sender_delivery_is_bounded() {
        fn t3(j: &mut JobTx, deliver_within: u32) {
            j.spec.min_isolation = IsolationTier::T3Confidential;
            j.spec.confidential = Some(ConfidentialSpec {
                policy: EnclavePolicyId([4; 32]),
                broker: KeyBroker::Sender { deliver_within, request_key: [0; 32], key_check: [0; 32] },
            });
        }
        fn check(f: impl FnOnce(&mut JobTx)) -> Result<(), AdmissionError> {
            let mut j = job();
            f(&mut j);
            check_stateless(&j, &CTX)
        }
        let enc = |j: &mut JobTx, e: Encryption| j.spec.inputs[0].content.payload.encryption = e;
        let confidential = |p: u8| Encryption::Confidential { inner_root: [1; 32], policy: EnclavePolicyId([p; 32]) };
        let input = |r: Result<(), AdmissionError>| matches!(r, Err(AdmissionError::InputEncryption(_)));
        let checkpoint = Encryption::Checkpoint { plaintext_root: [1; 32], key_commitment: [2; 32] };
        assert!(input(check(|j| enc(j, checkpoint))));
        assert!(input(check(|j| enc(j, confidential(4)))), "Confidential below T3");
        assert!(!input(check(|j| t3(j, 10))));
        assert!(input(check(|j| {
            t3(j, 10);
            enc(j, confidential(5));
        })));
        assert!(!input(check(|j| {
            t3(j, 10);
            enc(j, confidential(4));
        })));
        for (d, ok) in [(0, false), (1, true), (600, true), (601, false)] {
            let r = check(|j| t3(j, d));
            assert_eq!(matches!(r, Err(AdmissionError::DeliverWithin(_))), !ok, "{d}: {r:?}");
        }
    }

    #[test]
    fn confidential_needs_t3_and_back() {
        assert_eq!(
            rejects(|j| j.spec.min_isolation = IsolationTier::T3Confidential),
            AdmissionError::ConfidentialMismatch
        );
        assert_eq!(
            rejects(|j| {
                j.spec.confidential = Some(ConfidentialSpec {
                    policy: EnclavePolicyId([0; 32]),
                    broker: KeyBroker::Sender { deliver_within: 10, request_key: [0; 32], key_check: [0; 32] },
                })
            }),
            AdmissionError::ConfidentialMismatch
        );
        let t3_with_ranges = |j: &mut JobTx| {
            j.spec.min_isolation = IsolationTier::T3Confidential;
            j.spec.confidential = Some(ConfidentialSpec {
                policy: EnclavePolicyId([0; 32]),
                broker: KeyBroker::Sender { deliver_within: 10, request_key: [0; 32], key_check: [0; 32] },
            });
            j.spec.segmentation.as_mut().unwrap().input_ranges = Some(j.spec.inputs[0].content.clone());
        };
        assert_eq!(rejects(t3_with_ranges), AdmissionError::ConfidentialInputRanges);
    }

    #[test]
    fn gpu_rules() {
        assert_eq!(rejects(|j| j.spec.hw.gpu.as_mut().unwrap().count = 9), AdmissionError::GpuCount(9));
        assert_eq!(rejects(|j| j.spec.hw.gpu.as_mut().unwrap().count = 2), AdmissionError::Interconnect);
        let mig_pair = |j: &mut JobTx| {
            let g = j.spec.hw.gpu.as_mut().unwrap();
            g.count = 2;
            g.interconnect = Some(Interconnect::NvLink);
            g.allow_mig = true;
        };
        assert_eq!(rejects(mig_pair), AdmissionError::MigCount(2));
        assert_eq!(
            rejects(|j| j.spec.hw.gpu.as_mut().unwrap().interconnect = Some(Interconnect::NvLink)),
            AdmissionError::Interconnect
        );
        let mut ok = job();
        let g = ok.spec.hw.gpu.as_mut().unwrap();
        g.count = 2;
        g.interconnect = Some(Interconnect::Pcie);
        check_stateless(&ok, &CTX).unwrap();
        assert_eq!(
            rejects(|j| j.spec.hw.gpu.as_mut().unwrap().compute_capability.min.major = 10),
            AdmissionError::EmptyCcRange
        );
    }

    #[test]
    fn verification_rules() {
        assert_eq!(rejects(|j| j.spec.verification.replicas = 2), AdmissionError::Replicas(2));
        assert_eq!(rejects(|j| j.spec.fee.max_budget = R_HIGH), AdmissionError::HighValueReplicas(3));
        let mut high = job();
        high.spec.fee.max_budget = R_HIGH;
        high.spec.verification.replicas = 5;
        check_stateless(&high, &CTX).unwrap();
        high.spec.fee.max_budget = R_HIGH - 1;
        high.spec.verification.replicas = 3;
        check_stateless(&high, &CTX).unwrap();
        assert_eq!(
            rejects(|j| j.spec.verification.min_sample_rate_bp = Some(10_001)),
            AdmissionError::SampleRate(10_001)
        );
        let mut w = job();
        for (blocks, ok) in [(1_799, false), (1_800, true), (43_200, true), (43_201, false)] {
            w.spec.verification.challenge_window_blocks = blocks;
            assert_eq!(check_challenge_window(&w, W_OPT_MIN).is_ok(), ok, "{blocks}");
        }
        w.spec.verification.challenge_window_blocks = 10;
        assert!(check_challenge_window(&w, 10).is_ok());
        // A flagged pair stops bitwise jobs only.
        let mut j = job();
        j.spec.determinism = DeterminismClass::Bitwise;
        assert_eq!(check_nondeterministic(&j, Some(9)), Err(AdmissionError::Nondeterministic(9)));
        assert_eq!(check_nondeterministic(&j, None), Ok(()));
        j.spec.determinism = DeterminismClass::Tolerance;
        assert_eq!(check_nondeterministic(&j, Some(9)), Ok(()));
        assert_eq!(
            rejects(|j| {
                j.spec.outputs.comparison.pop();
            }),
            AdmissionError::ComparisonMismatch { paths: 2, rules: 1 }
        );
    }

    #[test]
    fn tolerance_rules() {
        let abs = |v: f32| {
            move |j: &mut JobTx| {
                j.spec.outputs.comparison[1] =
                    OutputComparison::Tensor { rel_tol_ppm: 0, abs_tol: F32Bits::from_f32(v), dtype: DType::BF16 }
            }
        };
        for v in [-0.0, -1.0, f32::NAN, f32::INFINITY] {
            assert_eq!(rejects(abs(v)), AdmissionError::AbsTol(v.to_bits()));
        }
        check_stateless(
            &{
                let mut j = job();
                abs(0.5)(&mut j);
                j
            },
            &CTX,
        )
        .unwrap();
    }

    #[test]
    fn metric_rules_are_refused() {
        let metric = |j: &mut JobTx| {
            j.spec.outputs.comparison[1] =
                OutputComparison::Metric { key: "loss".into(), abs_tol: F32Bits::from_f32(0.5) }
        };
        assert_eq!(rejects(metric), AdmissionError::MetricRule);
        for class in [DeterminismClass::Tolerance, DeterminismClass::BitwiseSameArch, DeterminismClass::Bitwise] {
            let mut j = job();
            metric(&mut j);
            j.spec.determinism = class;
            j.spec.segmentation = None;
            j.spec.limits.max_wall_time_secs = MAX_SEGMENT_WALL_TIME_SECS;
            assert_eq!(check_stateless(&j, &CTX), Err(AdmissionError::MetricRule));
        }
    }

    #[test]
    fn retention_rules() {
        let long = |j: &mut JobTx| {
            j.spec.outputs.publish =
                OutputRetention { class: RetentionClass::LongTerm, duration_blocks: 1000, external: vec![] }
        };
        let mut ok = job();
        long(&mut ok);
        ok.spec.outputs.publish.external = vec![ExternalBackend::Arweave, ExternalBackend::Filecoin];
        check_stateless(&ok, &CTX).unwrap();

        assert_eq!(
            rejects(|j| {
                long(j);
                j.spec.outputs.publish.external = vec![ExternalBackend::Filecoin, ExternalBackend::Arweave];
            }),
            AdmissionError::NotCanonical("outputs.publish.external")
        );
        assert!(matches!(
            rejects(|j| {
                long(j);
                j.spec.outputs.publish.duration_blocks = 0;
            }),
            AdmissionError::Retention(_)
        ));
        assert!(matches!(rejects(|j| j.spec.outputs.publish.duration_blocks = 5), AdmissionError::Retention(_)));
        assert!(matches!(
            rejects(|j| j.spec.outputs.publish.class = RetentionClass::Hot),
            AdmissionError::Retention(_)
        ));
    }

    #[test]
    fn every_string_is_capped_and_args_hold_no_nul() {
        let long = "x".repeat(MAX_STRING_BYTES + 1);
        let url = long.clone();
        assert_eq!(
            rejects(move |j| j.spec.inputs[0].locators = vec![Locator::Https { url }]),
            AdmissionError::StringTooLong("locators.url")
        );
        let key = long.clone();
        assert_eq!(
            rejects(move |j| j.spec.outputs.comparison[0] =
                OutputComparison::Metric { key, abs_tol: crate::job::F32Bits(0) }),
            AdmissionError::StringTooLong("outputs.comparison.key")
        );
        assert!(matches!(rejects(|j| j.spec.command.args = vec!["a\0b".into()]), AdmissionError::InvalidName { .. }));
        assert!(matches!(
            rejects(|j| j.spec.command.workdir = Some("/w\0".into())),
            AdmissionError::InvalidName { .. }
        ));
        // A checker image follows the image rules.
        let mut checker = job().spec.image;
        checker.total_size += 1;
        assert!(matches!(
            rejects(move |j| j.spec.determinism = DeterminismClass::CheckerOnly { checker }),
            AdmissionError::ImageBlobs(_)
        ));
    }

    #[test]
    fn long_jobs_must_segment() {
        assert_eq!(rejects(|j| j.spec.segmentation = None), AdmissionError::MustSegment(48 * 3600));
        assert_eq!(
            rejects(|j| j.spec.segmentation.as_mut().unwrap().max_segments = 0),
            AdmissionError::BadSegmentation
        );
        assert_eq!(rejects(|j| j.spec.limits.max_segment_wall_time_secs = 7200), AdmissionError::MustSegment(7200));
        assert_eq!(
            rejects(|j| j.spec.segmentation.as_mut().unwrap().full_state_every = 0),
            AdmissionError::BadSegmentation
        );
        assert_eq!(
            rejects(|j| j.spec.segmentation.as_mut().unwrap().full_state_every = 2),
            AdmissionError::BadSegmentation
        );
        assert_eq!(
            rejects(|j| j.spec.segmentation.as_mut().unwrap().max_segments = MAX_SEGMENTS + 1),
            AdmissionError::BadSegmentation
        );
        let lazy = |k| {
            move |j: &mut JobTx| {
                j.spec.segmentation.as_mut().unwrap().checkpoint_placement =
                    CheckpointPlacement::Lazy { resume_every: k }
            }
        };
        assert_eq!(rejects(lazy(257)), AdmissionError::ResumeEvery(257));
        let mut j = job();
        lazy(256)(&mut j);
        check_stateless(&j, &CTX).unwrap();
        // Unsegmented: the segment limit is the run's kill limit and must equal the wall time.
        let short = |j: &mut JobTx| {
            j.spec.segmentation = None;
            j.spec.limits.max_wall_time_secs = 3600;
        };
        assert_eq!(
            rejects(move |j| {
                short(j);
                j.spec.limits.max_segment_wall_time_secs = u64::MAX;
            }),
            AdmissionError::SegmentWall
        );
    }

    #[test]
    fn substeps_rules() {
        let set = |n: u16| move |j: &mut JobTx| j.spec.segmentation.as_mut().unwrap().substeps = n;
        // The sample job is Tolerance: micro-bisection is Bitwise only.
        assert_eq!(rejects(set(8)), AdmissionError::Substeps(8));
        let bitwise = |n: u16| {
            move |j: &mut JobTx| {
                j.spec.determinism = DeterminismClass::Bitwise;
                j.spec.segmentation.as_mut().unwrap().substeps = n;
            }
        };
        let mut ok = job();
        bitwise(8)(&mut ok);
        assert_eq!(check_stateless(&ok, &CTX), Ok(()));
        let over = |j: &mut JobTx| {
            bitwise(128)(j);
            j.spec.segmentation.as_mut().unwrap().steps_per_segment = 1024;
        };
        assert_eq!(rejects(over), AdmissionError::Substeps(128));
        assert_eq!(rejects(bitwise(12)), AdmissionError::Substeps(12));
        // 1000 steps are not divisible by 16.
        assert_eq!(rejects(bitwise(16)), AdmissionError::Substeps(16));
    }

    #[test]
    fn locators_are_https_with_a_host_and_http_only_where_the_chain_allows_it() {
        let with = |url: &str| {
            let mut j = job();
            j.spec.inputs[0].locators = vec![Locator::Https { url: url.into() }];
            j
        };
        for url in
            ["https://example.org", "https://u@example.org:8443/a?b#c", "https://[::1]/x", "http://example.org/x"]
        {
            assert_eq!(check_job(&with(url)), Ok(()), "{url}");
        }
        for url in [
            "ftp://example.org/x",
            "file:///etc/passwd",
            "https://",
            "https:///x",
            "https://u@:443/x",
            "HTTPS://x",
            "example.org",
        ] {
            assert_eq!(check_job(&with(url)), Err(AdmissionError::LocatorScheme(url.into())), "{url}");
        }
        // http:// passes the stateless check; the chain's `http_locators` decides (0001 §3.4 step 4).
        let http = with("http://example.org/x");
        assert_eq!(
            check_locator_scheme(&http, false),
            Err(AdmissionError::LocatorScheme("http://example.org/x".into()))
        );
        assert_eq!(check_locator_scheme(&http, true), Ok(()));
        assert_eq!(check_locator_scheme(&with("https://example.org/x"), false), Ok(()));
        let mut checker = job().spec.image;
        checker.locators = vec![Locator::Https { url: "http://example.org/c".into() }];
        let mut j = job();
        j.spec.determinism = DeterminismClass::CheckerOnly { checker };
        assert!(matches!(check_locator_scheme(&j, false), Err(AdmissionError::LocatorScheme(_))));
    }

    #[test]
    fn image_blobs_must_match_the_image() {
        assert!(matches!(rejects(|j| j.spec.image.blobs.clear()), AdmissionError::ImageBlobs(_)));
        assert!(matches!(rejects(|j| j.spec.image.blobs.swap(0, 1)), AdmissionError::ImageBlobs(_)));
        assert!(matches!(rejects(|j| j.spec.image.total_size += 1), AdmissionError::ImageBlobs(_)));
        assert!(matches!(rejects(|j| j.spec.image.blobs[2].oci_digest = None), AdmissionError::ImageBlobs(_)));
        assert!(matches!(
            rejects(|j| j.spec.image.blobs[1].kind = crate::payload::PayloadKind::Input),
            AdmissionError::ImageBlobs(_)
        ));
        assert!(matches!(rejects(|j| j.spec.image.blobs[1].size = u64::MAX), AdmissionError::ImageBlobs(_)));
    }

    #[test]
    fn inputs_and_storage_fee() {
        assert_eq!(
            rejects(|j| j.spec.inputs[1].content.payload.kind = crate::payload::PayloadKind::Output),
            AdmissionError::InputPayload("model".into())
        );
        assert_eq!(
            rejects(|j| j.spec.inputs[0].content.payload.version = 2),
            AdmissionError::InputPayload("data".into())
        );
        for log2 in [0, 19, 23, 64] {
            assert_eq!(
                rejects(move |j| j.spec.inputs[0].content.payload.piece_log2 = log2),
                AdmissionError::InputPayload("data".into())
            );
            assert!(matches!(rejects(move |j| j.spec.image.blobs[0].piece_log2 = log2), AdmissionError::ImageBlobs(_)));
        }
        assert_eq!(rejects(|j| j.spec.fee.storage_fee.outputs = j.spec.fee.max_budget), AdmissionError::StorageFee);
        assert_eq!(
            rejects(|j| j.spec.fee.storage_fee.inputs = tog_primitives::Amount::MAX),
            AdmissionError::StorageFee
        );
    }
}
