//! Shared pieces of random-projection sketches of tensor checkpoints (TOG-SPEC-0003 §5.2).
//!
//! The sketch itself (manifest, dtype decoding, projection) is computed by `tog-executor` per
//! TOG-SPEC-0003 §5.2.1; this module holds the projection seed, the fixed-point conversions and
//! the exact tolerance test that verifiers and the Hub share.

use tog_primitives::{tagged_hash, Domain, Hash32};

use crate::checkpoint::{Sketch, TensorSketch};
use crate::job::{F32Bits, OutputComparison, OutputSpec};

/// Projections per tensor.
pub const SKETCH_K: usize = 64;

/// Most entries in a checkpoint manifest, so in a [`Sketch`] (TOG-SPEC-0003 §5.2.1).
pub const MAX_SKETCH_TENSORS: usize = 1_024;

/// Longest tensor name in bytes (TOG-SPEC-0003 §5.2.1).
pub const MAX_TENSOR_NAME: usize = 128;

impl Sketch {
    /// At most [`MAX_SKETCH_TENSORS`] tensors, names of at most [`MAX_TENSOR_NAME`] bytes and exactly
    /// [`SKETCH_K`] projections each; the Hub rejects any other sketch (TOG-SPEC-0003 §5.2.1).
    pub fn well_formed(&self) -> bool {
        self.tensors.len() <= MAX_SKETCH_TENSORS
            && self.tensors.iter().all(|t| t.name.len() <= MAX_TENSOR_NAME && t.projection.len() == SKETCH_K)
    }
}

/// `seed_t = H("TOG/v1/sketch-proj" ‖ ρ ‖ job_id ‖ u32 n ‖ t.name)`.
pub fn projection_seed(rho: &Hash32, job_id: &Hash32, segment: u32, name: &str) -> Hash32 {
    tagged_hash(Domain::SketchProj, &[rho, job_id, &segment.to_le_bytes(), name.as_bytes()])
}

/// `x` as signed Q32.32: round half to even, saturating; NaN saturates high so it always
/// compares out of tolerance.
pub fn to_q32_32(x: f64) -> i64 {
    if x.is_nan() {
        return i64::MAX;
    }
    // `as` saturates at the type's range.
    round_ties_even(x * 4_294_967_296.0) as i64
}

/// `f64::round_ties_even`, which needs `std`. IEEE arithmetic rounds to nearest, ties to even, so
/// adding and removing 2⁵² rounds any `|y| < 2⁵²`; larger values (and infinities) are integers.
fn round_ties_even(y: f64) -> f64 {
    const TWO_52: f64 = 4_503_599_627_370_496.0;
    if y.abs() >= TWO_52 {
        y
    } else if y.is_sign_positive() {
        (y + TWO_52) - TWO_52
    } else {
        -((-y + TWO_52) - TWO_52)
    }
}

/// `x ≥ 0` as unsigned Q32.32, with the same rounding and saturation.
pub fn to_uq32_32(x: f64) -> u64 {
    if x.is_nan() {
        return u64::MAX;
    }
    round_ties_even(x * 4_294_967_296.0) as u64
}

/// `⌊abs_tol · 2^32⌋`, exact and saturating at `u64::MAX`. Admission makes `abs_tol` finite and
/// `≥ 0`; anything else maps to 0.
pub fn abs_q(abs_tol: F32Bits) -> u64 {
    // f32 → f64 and the scale by 2^32 are exact; `as` truncates toward zero and saturates.
    (f64::from(abs_tol.to_f32()) * 4_294_967_296.0) as u64
}

/// `(rel_tol_ppm, abs_q)` for checkpoint sketches: the strictest `Tensor` entry of `outputs` (smallest
/// `rel_tol_ppm`, then smallest `abs_tol`), or `(0, 0)` without one (TOG-SPEC-0003 §5.2).
pub fn checkpoint_tolerance(outputs: &OutputSpec) -> (u32, u64) {
    outputs
        .comparison
        .iter()
        .filter_map(|c| match c {
            OutputComparison::Tensor { rel_tol_ppm, abs_tol, .. } => Some((*rel_tol_ppm, *abs_tol)),
            _ => None,
        })
        .min_by(|x, y| x.0.cmp(&y.0).then(x.1.to_f32().total_cmp(&y.1.to_f32())))
        .map_or((0, 0), |(rel, abs)| (rel, abs_q(abs)))
}

/// Whether `ver` is within tolerance of the executor's sketch `exec` (TOG-SPEC-0003 §5.2 "Sketch
/// comparison"). Asymmetric: the norm comes from `exec`. Sketches with different tensor counts, a name
/// differing at the same position, or a projection without exactly [`SKETCH_K`] entries are out of
/// tolerance ("Shape").
pub fn within_tolerance(exec: &Sketch, ver: &Sketch, rel_tol_ppm: u32, abs_q: u64) -> bool {
    exec.tensors.len() == ver.tensors.len()
        && exec.tensors.iter().zip(&ver.tensors).all(|(a, b)| tensor_within(a, b, rel_tol_ppm, abs_q))
}

/// Two non-executor sketches agree iff each is within tolerance of the other (jury clustering).
pub fn within_tolerance_mutual(a: &Sketch, b: &Sketch, rel_tol_ppm: u32, abs_q: u64) -> bool {
    within_tolerance(a, b, rel_tol_ppm, abs_q) && within_tolerance(b, a, rel_tol_ppm, abs_q)
}

/// `d2 · 10^12 ≤ (rel_tol_ppm · n + abs_q · 10^6)²` in 256-bit integers.
fn tensor_within(a: &TensorSketch, b: &TensorSketch, rel_tol_ppm: u32, abs_q: u64) -> bool {
    if a.name != b.name {
        return false;
    }
    let (a, b) = (&a.projection, &b.projection);
    if a.len() != SKETCH_K || b.len() != SKETCH_K || a.iter().chain(b).any(|&x| x == i64::MIN || x == i64::MAX) {
        return false;
    }
    let (mut d2, mut aa) = (U256::ZERO, U256::ZERO);
    for (&x, &y) in a.iter().zip(b) {
        let d = (i128::from(x) - i128::from(y)).unsigned_abs();
        d2 = d2.add(U256::mul(d, d));
        let x = i128::from(x).unsigned_abs();
        aa = aa.add(U256::mul(x, x));
    }
    // rel < 2^32, n < 2^67, abs_q · 10^6 < 2^84: the sum fits u128.
    let rhs = u128::from(rel_tol_ppm) * aa.isqrt() + u128::from(abs_q) * 1_000_000;
    d2.mul_small(1_000_000_000_000) <= U256::mul(rhs, rhs)
}

/// Unsigned 256-bit integer, just enough for [`tensor_within`]; field order makes the derived `Ord`
/// numeric.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    const ZERO: Self = Self { hi: 0, lo: 0 };

    /// `a · b`, exact.
    fn mul(a: u128, b: u128) -> Self {
        let (a0, a1) = (a as u64 as u128, a >> 64);
        let (b0, b1) = (b as u64 as u128, b >> 64);
        let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
        let mid = (p00 >> 64) + (p01 as u64 as u128) + (p10 as u64 as u128);
        Self { hi: p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64), lo: (p00 as u64 as u128) | (mid << 64) }
    }

    /// `self + o`; callers keep sums below 2^256.
    fn add(self, o: Self) -> Self {
        let (lo, carry) = self.lo.overflowing_add(o.lo);
        Self { hi: self.hi + o.hi + u128::from(carry), lo }
    }

    /// `self · m`; callers keep the product below 2^256.
    fn mul_small(self, m: u64) -> Self {
        let low = Self::mul(self.lo, u128::from(m));
        Self { hi: self.hi * u128::from(m) + low.hi, lo: low.lo }
    }

    /// `⌊√self⌋`, for values below 2^256 whose root fits u128.
    fn isqrt(self) -> u128 {
        let mut r = 0u128;
        for bit in (0..128).rev() {
            let c = r | (1 << bit);
            if Self::mul(c, c) <= self {
                r = c;
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_ties_even_matches_std() {
        let mut xs = vec![0.0, -0.0, 0.5, -0.5, 1.5, -1.5, 2.5, 4503599627370495.5, 9e15, -9e15, 1e300];
        xs.extend([f64::INFINITY, f64::NEG_INFINITY, f64::MIN_POSITIVE, 0.49999999999999994]);
        xs.extend((0..2000).map(|i| (i as f64 - 1000.0) * 0.25 + 1e-3 * (i % 7) as f64));
        for x in xs {
            let (a, b) = (round_ties_even(x), x.round_ties_even());
            assert_eq!(a.to_bits(), b.to_bits(), "{x}");
        }
    }

    #[test]
    fn fixed_point_rounding_and_saturation() {
        assert_eq!(to_q32_32(1.0), 1 << 32);
        assert_eq!(to_q32_32(-0.5), -(1 << 31));
        // Half an ulp of Q32.32 rounds to even.
        assert_eq!(to_q32_32(0.5 / 4_294_967_296.0), 0);
        assert_eq!(to_q32_32(1.5 / 4_294_967_296.0), 2);
        assert_eq!(to_q32_32(3e9), i64::MAX);
        assert_eq!(to_q32_32(-3e9), i64::MIN);
        assert_eq!(to_q32_32(f64::NAN), i64::MAX);
        assert_eq!(to_uq32_32(5e9), u64::MAX);
    }

    fn sketch(projection: Vec<i64>) -> Sketch {
        Sketch { tensors: vec![TensorSketch { name: "w".into(), projection, norm: 0 }] }
    }

    #[test]
    fn spec_vectors() {
        let a = sketch(vec![1 << 32; SKETCH_K]);
        let mut b = a.clone();
        b.tensors[0].projection[0] = (1 << 32) + (1 << 28);
        assert!(!within_tolerance(&a, &b, 1_000, 0));
        assert!(within_tolerance(&a, &b, 100_000, 0));
        assert!(within_tolerance(&a, &a, 0, 0));
        // d2 = 2^56 exactly: √d2 = 2^28 raw units, so abs_q = 2^28 alone is the boundary.
        assert!(within_tolerance(&a, &b, 0, 1 << 28));
        assert!(!within_tolerance(&a, &b, 0, (1 << 28) - 1));
    }

    #[test]
    fn saturation_and_shape_are_out_of_tolerance() {
        let a = sketch(vec![i64::MAX; SKETCH_K]);
        assert!(!within_tolerance(&a, &a, u32::MAX, u64::MAX));
        let a = sketch(vec![i64::MIN + 1; SKETCH_K]);
        let b = sketch(vec![i64::MAX - 1; SKETCH_K]);
        // Largest differences and norms stay exact in 256 bits.
        assert!(!within_tolerance(&a, &b, 1_000_000, 0));
        assert!(within_tolerance(&a, &b, 2_000_000, 0));
        assert!(!within_tolerance(&a, &sketch(vec![0; 3]), u32::MAX, u64::MAX));
        let short = sketch(vec![0; SKETCH_K - 1]);
        assert!(!short.well_formed() && sketch(vec![0; SKETCH_K]).well_formed());
        assert!(!within_tolerance(&short, &short, u32::MAX, u64::MAX));
        let zero = sketch(vec![0; SKETCH_K]);
        let mut renamed = zero.clone();
        renamed.tensors[0].name = "v".into();
        assert!(within_tolerance(&zero, &zero, 0, 0));
        assert!(!within_tolerance(&zero, &renamed, u32::MAX, u64::MAX));
        assert!(!within_tolerance(&a, &Sketch { tensors: vec![] }, u32::MAX, u64::MAX));
    }

    #[test]
    fn asymmetric_norm_and_mutual() {
        // n comes from the first argument: a large executor norm admits a small sketch, not vice versa.
        let big = sketch(vec![1 << 40; SKETCH_K]);
        let small = sketch(vec![1 << 32; SKETCH_K]);
        assert!(within_tolerance(&big, &small, 999_000, 0));
        assert!(!within_tolerance(&small, &big, 999_000, 0));
        assert!(!within_tolerance_mutual(&big, &small, 999_000, 0));
    }

    #[test]
    fn abs_q_and_strictest_entry() {
        assert_eq!(abs_q(F32Bits::from_f32(0.0)), 0);
        assert_eq!(abs_q(F32Bits::from_f32(1.0)), 1 << 32);
        assert_eq!(abs_q(F32Bits::from_f32(1e-5)), 42_949);
        assert_eq!(abs_q(F32Bits::from_f32(f32::MAX)), u64::MAX);
        let tensor = |rel, abs| OutputComparison::Tensor {
            rel_tol_ppm: rel,
            abs_tol: F32Bits::from_f32(abs),
            dtype: crate::job::DType::F32,
        };
        let mut o = crate::testing::sample_job().spec.outputs;
        o.comparison = vec![OutputComparison::Exact];
        assert_eq!(checkpoint_tolerance(&o), (0, 0));
        o.comparison = vec![tensor(200, 0.0), tensor(100, 2.0), OutputComparison::Ignore, tensor(100, 1.0)];
        assert_eq!(checkpoint_tolerance(&o), (100, 1 << 32));
    }
}
