//! ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381, suite `0x03`), the sortition VRF of TOG-SPEC-0001 §3.2
//! and TOG-SPEC-0003 §3.2.
//!
//! **Unaudited.** No maintained, reviewed crate implements this suite, so it is written here on top
//! of `curve25519-dalek` and `sha2`, following RFC 9381 §5 step by step, and checked against the
//! RFC's test vectors (Appendix B.3). Keep it isolated; replace it with a reviewed implementation
//! when one exists.
//!
//! A VRF secret key is a 32-byte seed expanded as in Ed25519 (RFC 8032 §5.1.5), so `public_key(seed)`
//! is the Ed25519 public key of the same seed. A worker still registers a separate `vrf_key`.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// `Γ (32 B) ‖ c (16 B) ‖ s (32 B)`.
pub type Proof = [u8; 80];
/// VRF output β.
pub type Output = [u8; 64];

const SUITE: u8 = 0x03;

/// Public key of a VRF secret seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let (mut x, mut prefix) = expand(seed);
    let y = (B * x).compress().to_bytes();
    x.zeroize();
    prefix.zeroize();
    y
}

/// `ECVRF_prove(SK, alpha)`.
pub fn prove(seed: &[u8; 32], alpha: &[u8]) -> Proof {
    let (mut x, mut prefix) = expand(seed);
    let y = (B * x).compress().to_bytes();
    let h = encode_to_curve(&y, alpha);
    let h_string = h.compress().to_bytes();
    let gamma = h * x;
    let mut wide: [u8; 64] = Sha512::new().chain_update(prefix).chain_update(h_string).finalize().into();
    let mut k = Scalar::from_bytes_mod_order_wide(&wide);
    let c = challenge(&[
        y,
        h_string,
        gamma.compress().to_bytes(),
        (B * k).compress().to_bytes(),
        (h * k).compress().to_bytes(),
    ]);
    let s = k + c * x;
    // The secret scalar, its nonce prefix and the nonce leave no copies behind (K10).
    x.zeroize();
    prefix.zeroize();
    k.zeroize();
    wide.zeroize();
    let mut pi = [0u8; 80];
    pi[..32].copy_from_slice(gamma.compress().as_bytes());
    pi[32..48].copy_from_slice(&c.to_bytes()[..16]);
    pi[48..].copy_from_slice(s.as_bytes());
    pi
}

/// RFC 9381 §5.4.5 `ECVRF_validate_key`: a canonical point encoding not of small order.
pub fn valid_public_key(public_key: &[u8; 32]) -> bool {
    decode_point(public_key).is_some_and(|y| !y.mul_by_cofactor().is_identity())
}

/// `ECVRF_verify(PK, alpha, pi)`: β if the proof is valid, `None` otherwise. Rejects public keys of
/// small order (`validate_key`), non-canonical point encodings and `s ≥ q`.
pub fn verify(public_key: &[u8; 32], alpha: &[u8], proof: &Proof) -> Option<Output> {
    if !valid_public_key(public_key) {
        return None;
    }
    let y = decode_point(public_key)?;
    let (gamma, c, s) = decode_proof(proof)?;
    let h = encode_to_curve(public_key, alpha);
    let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(&-c, &y, &s);
    let v = h * s - gamma * c;
    let expected = challenge(&[
        *public_key,
        h.compress().to_bytes(),
        proof[..32].try_into().expect("32"),
        u.compress().to_bytes(),
        v.compress().to_bytes(),
    ]);
    (expected == c).then(|| gamma_to_hash(&gamma))
}

/// `ECVRF_proof_to_hash(pi)`: β without verifying. Use only on a proof already verified.
pub fn proof_to_hash(proof: &Proof) -> Option<Output> {
    decode_proof(proof).map(|(gamma, _, _)| gamma_to_hash(&gamma))
}

/// Ed25519 key expansion: the clamped scalar `x` and the nonce prefix.
fn expand(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let mut h: [u8; 64] = Sha512::digest(seed).into();
    let mut lo: [u8; 32] = h[..32].try_into().expect("32");
    lo[0] &= 248;
    lo[31] &= 127;
    lo[31] |= 64;
    let out = (Scalar::from_bytes_mod_order(lo), h[32..].try_into().expect("32"));
    h.zeroize();
    lo.zeroize();
    out
}

/// RFC 8032 `string_to_point`: rejects non-canonical `y` and a set sign bit on `x = 0`.
fn decode_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let p = CompressedEdwardsY(*bytes).decompress()?;
    (p.compress().to_bytes() == *bytes).then_some(p)
}

/// `ECVRF_encode_to_curve_try_and_increment` (RFC 9381 §5.4.1.1).
fn encode_to_curve(public_key: &[u8; 32], alpha: &[u8]) -> EdwardsPoint {
    for ctr in 0..=u8::MAX {
        let hash = Sha512::new()
            .chain_update([SUITE, 0x01])
            .chain_update(public_key)
            .chain_update(alpha)
            .chain_update([ctr, 0x00])
            .finalize();
        if let Some(p) = decode_point(hash[..32].try_into().expect("32")) {
            return p.mul_by_cofactor();
        }
    }
    // Each try succeeds with probability about 1/2; 256 failures do not happen.
    unreachable!("encode_to_curve failed 256 times")
}

/// `ECVRF_challenge_generation`: the first 16 bytes of the hash, as a scalar.
fn challenge(points: &[[u8; 32]; 5]) -> Scalar {
    let mut h = Sha512::new().chain_update([SUITE, 0x02]);
    for p in points {
        h.update(p);
    }
    let hash = h.chain_update([0x00]).finalize();
    let mut c = [0u8; 32];
    c[..16].copy_from_slice(&hash[..16]);
    Scalar::from_bytes_mod_order(c)
}

fn decode_proof(proof: &Proof) -> Option<(EdwardsPoint, Scalar, Scalar)> {
    let gamma = decode_point(proof[..32].try_into().expect("32"))?;
    let mut c = [0u8; 32];
    c[..16].copy_from_slice(&proof[32..48]);
    let s = Option::from(Scalar::from_canonical_bytes(proof[48..].try_into().expect("32")))?;
    Some((gamma, Scalar::from_bytes_mod_order(c), s))
}

fn gamma_to_hash(gamma: &EdwardsPoint) -> Output {
    Sha512::new()
        .chain_update([SUITE, 0x03])
        .chain_update(gamma.mul_by_cofactor().compress().as_bytes())
        .chain_update([0x00])
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// RFC 9381 Appendix B.3, examples 16–18: (SK, PK, alpha, pi, beta).
    const VECTORS: [[&str; 5]; 3] = [
        [
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
        ],
        [
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
        ],
        [
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
        ],
    ];

    #[test]
    fn rfc9381_vectors() {
        for [sk, pk, alpha, pi, beta] in VECTORS {
            let seed: [u8; 32] = hex(sk).try_into().unwrap();
            let pk: [u8; 32] = hex(pk).try_into().unwrap();
            let alpha = hex(alpha);
            assert_eq!(public_key(&seed), pk);
            let proof = prove(&seed, &alpha);
            assert_eq!(proof.to_vec(), hex(pi));
            let out = verify(&pk, &alpha, &proof).expect("valid proof");
            assert_eq!(out.to_vec(), hex(beta));
            assert_eq!(proof_to_hash(&proof), Some(out));
        }
    }

    #[test]
    fn rejects_tampering() {
        let seed = [1u8; 32];
        let pk = public_key(&seed);
        let proof = prove(&seed, b"alpha");
        assert!(verify(&pk, b"alpha", &proof).is_some());
        assert!(verify(&pk, b"alphb", &proof).is_none());
        assert!(verify(&public_key(&[2; 32]), b"alpha", &proof).is_none());
        for i in [0, 40, 60] {
            let mut bad = proof;
            bad[i] ^= 1;
            assert!(verify(&pk, b"alpha", &bad).is_none(), "byte {i}");
        }
        // s ≥ q is rejected even though s mod q would verify.
        let mut big = proof;
        let s = Scalar::from_canonical_bytes(proof[48..].try_into().unwrap()).unwrap();
        let q_plus_s = add_order(&s.to_bytes());
        if let Some(b) = q_plus_s {
            big[48..].copy_from_slice(&b);
            assert!(verify(&pk, b"alpha", &big).is_none());
        }
    }

    #[test]
    fn rejects_small_order_key() {
        // The identity point encodes as y = 1.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(verify(&identity, b"", &prove(&[1; 32], b"")).is_none());
        assert!(!valid_public_key(&identity));
        assert!(valid_public_key(&public_key(&[1; 32])));
        // A non-canonical y (p + 1 encodes as 1 again) and a point off the curve.
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xee;
        non_canonical[31] = 0x7f;
        assert!(!valid_public_key(&non_canonical));
    }

    /// `s + q` as 32 little-endian bytes, if it fits in 256 bits.
    fn add_order(s: &[u8; 32]) -> Option<[u8; 32]> {
        const Q: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(s[i]) + u16::from(Q[i]) + carry;
            out[i] = v as u8;
            carry = v >> 8;
        }
        (carry == 0).then_some(out)
    }
}
