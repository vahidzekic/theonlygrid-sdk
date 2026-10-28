//! Boneh–Franklin `FullIdent` IBE under the Hub key `EK` (TOG-SPEC-0009 §1.2).
//!
//! **Not audited.** The curve arithmetic comes from the `bls12_381` crate, and hash-to-G2 and
//! the pairing whose value is hashed from `blst`, which is constant-time and exposes the
//! canonical `Fp12` coefficients [`pairing_bytes`] needs (`ark-bls12-381` for both without
//! `std`); this module only composes them as the spec describes, with the byte rules of
//! [`scalar_from_hash`] and [`pairing_bytes`].
//!
//! ```text
//! σ ← random 32 bytes
//! r = scalar_from_hash(σ ‖ m)           (redraw σ if r = 0)
//! U = r · g1
//! V = σ ⊕ H("TOG/v1/ibe-mask" ‖ gt_bytes(e(EK, Q_id)^r))
//! W = m ⊕ H("TOG/v1/ibe-msg" ‖ σ)
//! ```
//!
//! Decryption with `d_id = s · Q_id` recomputes `σ` from `e(U, d_id)`, then `m`, and rejects
//! unless `U ≠ O` and `U = r · g1` for the recomputed `r`.

use bls12_381::{G1Affine, G2Affine, Scalar};
use tog_primitives::{tagged_hash, Domain, Hash32};

use crate::hub_key::IbeCiphertext;

/// Why an IBE operation failed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum IbeError {
    /// `EK`, `U` or `d_id` is not a valid compressed point (or is the identity).
    #[error("malformed point")]
    Malformed,
    /// The Fujisaki–Okamoto check failed: wrong key or tampered ciphertext.
    #[error("ciphertext does not open with this key")]
    Invalid,
    /// `σ` gives `r = 0`; draw a fresh `σ` (probability about 2^-255).
    #[error("sigma gives r = 0, draw another")]
    RedrawSigma,
}

/// `Q_id = hash_to_G2(fields, DST = tag)` (RFC 9380, `BLS12381G2_XMD:SHA-256_SSWU_RO_`).
pub fn identity_point(tag: Domain, fields: &[u8]) -> G2Affine {
    hash_to_g2(fields, tag.tag().as_bytes())
}

/// RFC 9380 `hash_to_curve` with the suite `BLS12381G2_XMD:SHA-256_SSWU_RO_`, in `blst`
/// (`bls12_381` has it only behind its unaudited `experimental` feature). `blst` hashes
/// to G2 only on the way to a signature, so this signs with the secret key 1, whose signature is
/// the hashed point itself.
#[cfg(feature = "std")]
pub fn hash_to_g2(msg: &[u8], dst: &[u8]) -> G2Affine {
    let mut one = [0u8; 32];
    one[31] = 1;
    let one = blst::min_pk::SecretKey::from_bytes(&one).expect("1 is a valid secret key");
    let p = one.sign(msg, dst, &[]).serialize();
    // `blst` and `bls12_381` share the ZCash encoding, and the point is in G2.
    Option::from(G2Affine::from_uncompressed_unchecked(&p)).expect("blst serializes a valid point")
}

/// [`hash_to_g2`] without `std`, in `ark-bls12-381` (the same suite: SSWU onto the 3-isogenous
/// curve, then the isogeny and cofactor clearing).
#[cfg(not(feature = "std"))]
pub fn hash_to_g2(msg: &[u8], dst: &[u8]) -> G2Affine {
    ark_hash_to_g2(msg, dst)
}

#[cfg(any(test, not(feature = "std")))]
fn ark_hash_to_g2(msg: &[u8], dst: &[u8]) -> G2Affine {
    use ark_ec::hashing::curve_maps::wb::WBMap;
    use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
    use ark_ec::hashing::HashToCurve;
    use ark_ec::short_weierstrass::Projective;
    use ark_ec::AffineRepr;
    use ark_ff::field_hashers::DefaultFieldHasher;
    use ark_ff::{BigInteger, PrimeField};
    type Hasher = MapToCurveBasedHasher<
        Projective<ark_bls12_381::g2::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<ark_bls12_381::g2::Config>,
    >;
    let p = Hasher::new(dst).and_then(|h| h.hash(msg)).expect("the suite's parameters are valid");
    let Some((x, y)) = p.xy() else { return G2Affine::identity() };
    // The ZCash encoding: each `Fp2` coordinate `c1 ‖ c0`, each `Fp` 48 bytes big-endian.
    let mut b = [0u8; 192];
    for (chunk, c) in b.chunks_mut(48).zip([x.c1, x.c0, y.c1, y.c0]) {
        chunk.copy_from_slice(&c.into_bigint().to_bytes_be());
    }
    Option::from(G2Affine::from_uncompressed_unchecked(&b)).expect("arkworks hashes to a valid point")
}

/// Identity of the escrowed checkpoint key `k_n`: (`TOG/v1/key-escrow`, `job_id`, `n`).
pub fn key_escrow_point(job_id: &Hash32, segment: u32) -> G2Affine {
    identity_point(Domain::KeyEscrow, &[&job_id[..], &segment.to_le_bytes()].concat())
}

/// Identity of the body keys of height `h`: (`TOG/v1/mempool`, `h`).
pub fn mempool_point(target_height: u64) -> G2Affine {
    identity_point(Domain::Mempool, &target_height.to_le_bytes())
}

/// Encrypt `m` to `q_id` under `ek`. `sigma` must be fresh randomness; it is the only
/// secret input. On [`IbeError::RedrawSigma`] call again with a new `sigma`.
pub fn encrypt(
    ek_epoch: u32,
    ek: &[u8; 48],
    q_id: &G2Affine,
    m: &[u8; 32],
    sigma: &[u8; 32],
) -> Result<IbeCiphertext, IbeError> {
    let ek = g1(ek)?;
    let r = scalar_from_hash(&[sigma, m]);
    if r == Scalar::zero() {
        return Err(IbeError::RedrawSigma);
    }
    let u = G1Affine::from(G1Affine::generator() * r);
    // e(EK, Q_id)^r = e(r·EK, Q_id).
    let mask = tagged_hash(Domain::IbeMask, &[&pairing_bytes(&G1Affine::from(ek * r), q_id)?]);
    Ok(IbeCiphertext {
        ek_epoch,
        u: u.to_compressed(),
        v: xor(sigma, &mask),
        w: xor(m, &tagged_hash(Domain::IbeMsg, &[sigma])),
    })
}

/// Decrypt with the released key `d_id` (96 bytes, compressed G2). The caller checks
/// `d_id` against `EK` and the identity; this function checks the ciphertext.
pub fn decrypt(ct: &IbeCiphertext, d_id: &[u8; 96]) -> Result<[u8; 32], IbeError> {
    let u = g1(&ct.u)?;
    let d = Option::<G2Affine>::from(G2Affine::from_compressed(d_id)).ok_or(IbeError::Malformed)?;
    let sigma = xor(&ct.v, &tagged_hash(Domain::IbeMask, &[&pairing_bytes(&u, &d)?]));
    let m = xor(&ct.w, &tagged_hash(Domain::IbeMsg, &[&sigma]));
    let r = scalar_from_hash(&[&sigma, &m]);
    if G1Affine::from(G1Affine::generator() * r) != u {
        return Err(IbeError::Invalid);
    }
    Ok(m)
}

/// `scalar_from_hash(x)`: the first 64 bytes of the BLAKE3 XOF of
/// `derive_key("TOG/v1/ibe-r", x)`, read as a little-endian integer and reduced mod `r_Fr`
/// (0009 §1.2). The wide input makes the bias about 2^-257.
pub fn scalar_from_hash(parts: &[&[u8]]) -> Scalar {
    let mut h = blake3::Hasher::new_derive_key(Domain::IbeR.tag());
    for p in parts {
        h.update(p);
    }
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_wide(&wide)
}

/// `gt_bytes(e(p, q))`: the canonical 576-byte encoding of the pairing value, its twelve `Fp`
/// coefficients, each 48 bytes big-endian of its canonical value in `[0, p)`, in tower order
/// `c0.c0.c0, c0.c0.c1, c0.c1.c0, …, c1.c2.c1` for `Fp12 = Fp6[w]`, `Fp6 = Fp2[v]`,
/// `Fp2 = Fp[u]` (0009 §1.2). `bls12_381` exposes no `Fp12` coefficients, so the pairing is
/// computed in `blst`, whose Miller loop and final exponentiation are constant-time: one input
/// is secret, `d_id` in [`decrypt`] and `r · EK` in [`encrypt`]. The
/// known-answer vectors pin the value, and a test checks it against `ark-bls12-381`, which
/// computes it without `std`.
#[cfg(feature = "std")]
pub fn pairing_bytes(p: &G1Affine, q: &G2Affine) -> Result<[u8; 576], IbeError> {
    if bool::from(p.is_identity() | q.is_identity()) {
        let mut one = [0u8; 576];
        one[47] = 1;
        return Ok(one);
    }
    let p = blst::min_pk::PublicKey::deserialize(&p.to_uncompressed()).map_err(|_| IbeError::Malformed)?;
    let q = blst::min_pk::Signature::deserialize(&q.to_uncompressed()).map_err(|_| IbeError::Malformed)?;
    let be = blst::blst_fp12::miller_loop(&q.into(), &p.into()).final_exp().to_bendian();
    // `blst` writes `c_j.c_i.c_k` with `i` (Fp2 in Fp6) outermost; the spec's order has `j`
    // (Fp6 in Fp12) outermost.
    let mut out = [0u8; 576];
    for (j, i, k) in (0..2).flat_map(|j| (0..3).flat_map(move |i| (0..2).map(move |k| (j, i, k)))) {
        let (to, from) = ((j * 3 + i) * 2 + k, (i * 2 + j) * 2 + k);
        out[to * 48..][..48].copy_from_slice(&be[from * 48..][..48]);
    }
    Ok(out)
}

/// [`pairing_bytes`] without `std`, in `ark-bls12-381` (the same tower and value), from the
/// points' affine coordinates. It is not constant-time.
#[cfg(not(feature = "std"))]
pub fn pairing_bytes(p: &G1Affine, q: &G2Affine) -> Result<[u8; 576], IbeError> {
    ark_pairing_bytes(p, q)
}

#[cfg(any(test, not(feature = "std")))]
fn ark_pairing_bytes(p: &G1Affine, q: &G2Affine) -> Result<[u8; 576], IbeError> {
    use ark_ec::pairing::Pairing;
    use ark_ff::{BigInteger, PrimeField};
    let gt = ark_bls12_381::Bls12_381::pairing(ark_g1(p)?, ark_g2(q)?).0;
    let mut out = [0u8; 576];
    let coefficients = [gt.c0, gt.c1].into_iter().flat_map(|c6| [c6.c0, c6.c1, c6.c2]).flat_map(|c2| [c2.c0, c2.c1]);
    for (chunk, c) in out.chunks_mut(48).zip(coefficients) {
        let be = c.into_bigint().to_bytes_be();
        chunk.copy_from_slice(be.get(..48).ok_or(IbeError::Malformed)?);
    }
    Ok(out)
}

/// An `Fp` element from 48 big-endian bytes below the modulus.
#[cfg(any(test, not(feature = "std")))]
fn ark_fp(bytes: &[u8]) -> Result<ark_bls12_381::Fq, IbeError> {
    use ark_ff::{BigInteger, PrimeField};
    let fp = ark_bls12_381::Fq::from_be_bytes_mod_order(bytes);
    (fp.into_bigint().to_bytes_be() == bytes).then_some(fp).ok_or(IbeError::Malformed)
}

/// `p` in `ark-bls12-381`, from its uncompressed ZCash encoding (flags in the top three bits).
#[cfg(any(test, not(feature = "std")))]
fn ark_g1(p: &G1Affine) -> Result<ark_bls12_381::G1Affine, IbeError> {
    if bool::from(p.is_identity()) {
        return Ok(ark_bls12_381::G1Affine::identity());
    }
    let mut b = p.to_uncompressed();
    b[0] &= 0x1f;
    Ok(ark_bls12_381::G1Affine::new_unchecked(ark_fp(&b[..48])?, ark_fp(&b[48..])?))
}

/// `q` in `ark-bls12-381`: each `Fp2` coordinate is encoded `c1 ‖ c0`.
#[cfg(any(test, not(feature = "std")))]
fn ark_g2(q: &G2Affine) -> Result<ark_bls12_381::G2Affine, IbeError> {
    if bool::from(q.is_identity()) {
        return Ok(ark_bls12_381::G2Affine::identity());
    }
    let mut b = q.to_uncompressed();
    b[0] &= 0x1f;
    let fp2 = |c1: &[u8], c0: &[u8]| Ok::<_, IbeError>(ark_bls12_381::Fq2::new(ark_fp(c0)?, ark_fp(c1)?));
    Ok(ark_bls12_381::G2Affine::new_unchecked(fp2(&b[..48], &b[48..96])?, fp2(&b[96..144], &b[144..])?))
}

fn g1(bytes: &[u8; 48]) -> Result<G1Affine, IbeError> {
    Option::<G1Affine>::from(G1Affine::from_compressed(bytes))
        .filter(|p| !bool::from(p.is_identity()))
        .ok_or(IbeError::Malformed)
}

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    core::array::from_fn(|i| a[i] ^ b[i])
}

#[cfg(test)]
mod tests {
    use bls12_381::{pairing, G2Projective};

    use super::*;

    fn key(seed: u8) -> (Scalar, [u8; 48]) {
        let s = Scalar::from_bytes_wide(&[seed; 64]);
        (s, G1Affine::from(G1Affine::generator() * s).to_compressed())
    }

    fn extract(s: &Scalar, q_id: &G2Affine) -> [u8; 96] {
        G2Affine::from(q_id * s).to_compressed()
    }

    #[test]
    fn roundtrip() {
        let (s, ek) = key(1);
        let q = key_escrow_point(&[7; 32], 3);
        let ct = encrypt(0, &ek, &q, &[42; 32], &[9; 32]).unwrap();
        assert_eq!(decrypt(&ct, &extract(&s, &q)).unwrap(), [42; 32]);
    }

    #[test]
    fn deterministic_in_sigma() {
        let (_, ek) = key(1);
        let q = mempool_point(10);
        assert_eq!(encrypt(0, &ek, &q, &[1; 32], &[2; 32]), encrypt(0, &ek, &q, &[1; 32], &[2; 32]));
        assert_ne!(encrypt(0, &ek, &q, &[1; 32], &[2; 32]), encrypt(0, &ek, &q, &[1; 32], &[3; 32]));
    }

    #[test]
    fn wrong_identity_or_key_is_rejected() {
        let (s, ek) = key(1);
        let q = key_escrow_point(&[7; 32], 3);
        let ct = encrypt(0, &ek, &q, &[42; 32], &[9; 32]).unwrap();
        let other_segment = extract(&s, &key_escrow_point(&[7; 32], 4));
        assert_eq!(decrypt(&ct, &other_segment), Err(IbeError::Invalid));
        let (s2, _) = key(2);
        assert_eq!(decrypt(&ct, &extract(&s2, &q)), Err(IbeError::Invalid));
    }

    #[test]
    fn tampering_is_rejected() {
        let (s, ek) = key(1);
        let q = mempool_point(10);
        let d = extract(&s, &q);
        let ct = encrypt(0, &ek, &q, &[42; 32], &[9; 32]).unwrap();
        for f in [|c: &mut IbeCiphertext| c.v[0] ^= 1, |c: &mut IbeCiphertext| c.w[31] ^= 1] {
            let mut bad = ct.clone();
            f(&mut bad);
            assert_eq!(decrypt(&bad, &d), Err(IbeError::Invalid));
        }
        let mut bad = ct.clone();
        bad.u = G1Affine::generator().to_compressed();
        assert_eq!(decrypt(&bad, &d), Err(IbeError::Invalid));
    }

    #[test]
    fn malformed_points() {
        let (_, ek) = key(1);
        let q = mempool_point(1);
        assert_eq!(encrypt(0, &G1Affine::identity().to_compressed(), &q, &[0; 32], &[0; 32]), Err(IbeError::Malformed));
        let ct = encrypt(0, &ek, &q, &[0; 32], &[0; 32]).unwrap();
        assert_eq!(decrypt(&ct, &[0xff; 96]), Err(IbeError::Malformed));
        let zero_u = IbeCiphertext { u: G1Affine::identity().to_compressed(), ..ct.clone() };
        assert_eq!(decrypt(&zero_u, &G2Affine::generator().to_compressed()), Err(IbeError::Malformed));
        let bad_u = IbeCiphertext { u: [0xff; 48], ..ct };
        assert_eq!(decrypt(&bad_u, &G2Affine::generator().to_compressed()), Err(IbeError::Malformed));
    }

    #[test]
    fn identity_points_match_bls_signatures() {
        // d_id is the BLS signature on the identity: e(g1, d_id) = e(EK, Q_id).
        let (s, ek) = key(5);
        let q = key_escrow_point(&[1; 32], 0);
        let d = G2Affine::from_compressed(&extract(&s, &q)).unwrap();
        let ek = G1Affine::from_compressed(&ek).unwrap();
        assert_eq!(pairing(&G1Affine::generator(), &d), pairing(&ek, &q));
        assert_ne!(q, key_escrow_point(&[1; 32], 1));
        assert_ne!(G2Projective::from(q), G2Projective::identity());
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Known-answer vectors (0009 §1.2): `gt_bytes(e(g1, g2))` and a full `encrypt`.
    const GT_G1_G2: &str = "1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafabf1a8943e50439f1d59882a98eaa0170f1368bb445c7c2d209703f239689ce34c0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934f01b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b23f7dacaa35c8ca78beae9624045b4b619f26337d205fb469cd6bd15c3d5a04dc88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89d06fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1a11b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba5703350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad360829107ba810c5a09ffdd9be2291a0c25a99a204c581234d086a9902249b64728ffd21a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3ef0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b676631";
    const KAT_EK: &str =
        "afb98569c797d3ce0dcc2fd84da6460a1fa60aba50b6bf349b75f611f5fbfd80b3d7551c5112ddcee43ccc7124c8d2af";
    const KAT_U: &str =
        "a13f7679dec70f624adf618dfd100d8490bc036777118c1d8f9ece98045e4c3a6b64cc671bcd30288bd2e2ed8ce40a81";
    const KAT_V: &str = "bc037f497218f291184b04a4fd1a1500133c44e3d2eddf479d75b3d6f4439f88";
    const KAT_W: &str = "7b484ae8811b88055aed71dabcb5ccec06ec0ec70b21f9866053969e54529534";

    #[test]
    fn blst_and_arkworks_give_the_same_pairing_bytes() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        for i in 1..=8u64 {
            let p = G1Affine::from(g1 * Scalar::from(i * 7 + 3));
            let q = G2Affine::from(G2Projective::from(g2) * Scalar::from(i * 11 + 5));
            assert_eq!(pairing_bytes(&p, &q).unwrap(), ark_pairing_bytes(&p, &q).unwrap(), "{i}");
        }
        let q = key_escrow_point(&[4; 32], 2);
        assert_eq!(pairing_bytes(&g1, &q).unwrap(), ark_pairing_bytes(&g1, &q).unwrap());
        for (p, q) in [(G1Affine::identity(), g2), (g1, G2Affine::identity())] {
            assert_eq!(pairing_bytes(&p, &q).unwrap(), ark_pairing_bytes(&p, &q).unwrap());
        }
    }

    /// RFC 9380 Appendix J.10.1 (BLS12381G2_XMD:SHA-256_SSWU_RO_): `blst` and `ark-bls12-381`
    /// give the standard's points.
    #[test]
    fn hash_to_g2_matches_rfc_9380() {
        const DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        let a512 = [b"a512_".as_slice(), &[b'a'; 512]].concat();
        let q128 = [b"q128_".as_slice(), &[b'q'; 128]].concat();
        // msg, then P.x.c1 ‖ P.x.c0 ‖ P.y.c1 ‖ P.y.c0 (uncompressed encoding order).
        let cases: [(&[u8], &str); 5] = [
            (b"", "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d60503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92"),
            (b"abc", "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd802c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e600aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd161787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48"),
            (b"abcdef0123456789", "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd00bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8"),
            (&q128, "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb9119a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e566214f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192"),
            (&a512, "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d0156901a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f6253403a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab520b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e"),
        ];
        for (msg, expected) in cases {
            let label = String::from_utf8_lossy(&msg[..msg.len().min(16)]).into_owned();
            assert_eq!(hash_to_g2(msg, DST).to_uncompressed().to_vec(), unhex(expected), "blst {label}");
            assert_eq!(ark_hash_to_g2(msg, DST).to_uncompressed().to_vec(), unhex(expected), "arkworks {label}");
        }
        for h in 0..16u64 {
            assert_eq!(mempool_point(h), ark_hash_to_g2(&h.to_le_bytes(), Domain::Mempool.tag().as_bytes()));
        }
    }

    #[test]
    fn known_answer_vectors() {
        let gt = pairing_bytes(&G1Affine::generator(), &G2Affine::generator()).unwrap();
        assert_eq!(gt.to_vec(), unhex(GT_G1_G2));
        // EK = s·g1 for s = from_bytes_wide([1; 64]); identity ("TOG/v1/mempool", 10); m = [42; 32];
        // σ = [9; 32].
        let (s, ek) = key(1);
        assert_eq!(ek.to_vec(), unhex(KAT_EK));
        let q = mempool_point(10);
        let ct = encrypt(0, &ek, &q, &[42; 32], &[9; 32]).unwrap();
        assert_eq!((ct.u.to_vec(), ct.v.to_vec(), ct.w.to_vec()), (unhex(KAT_U), unhex(KAT_V), unhex(KAT_W)));
        assert_eq!(decrypt(&ct, &extract(&s, &q)).unwrap(), [42; 32]);
    }

    #[test]
    fn gt_encoding() {
        // e(g1, O) is the identity of GT, Fp12 one: only c0.c0.c0 = 1.
        let one = pairing_bytes(&G1Affine::generator(), &G2Affine::identity()).unwrap();
        let mut expected = [0u8; 576];
        expected[47] = 1;
        assert_eq!(one, expected);
        // Bilinear, and injective on distinct elements.
        let g2 = G2Affine::generator();
        let two = G1Affine::from(G1Affine::generator() * Scalar::from(2u64));
        let e = pairing_bytes(&G1Affine::generator(), &g2).unwrap();
        assert_ne!(e, pairing_bytes(&two, &g2).unwrap());
        assert_eq!(
            pairing_bytes(&two, &g2).unwrap(),
            pairing_bytes(&G1Affine::generator(), &G2Affine::from(g2 * Scalar::from(2u64))).unwrap()
        );
        // Every coefficient is a canonical Fp (below the modulus, whose top byte is 0x1a).
        for c in e.chunks(48) {
            assert!(c[0] <= 0x1a);
        }
    }

    #[test]
    fn scalar_from_wide_xof() {
        let mut wide = [0u8; 64];
        let mut h = blake3::Hasher::new_derive_key("TOG/v1/ibe-r");
        h.update(b"ab");
        h.update(b"c");
        h.finalize_xof().fill(&mut wide);
        assert_eq!(scalar_from_hash(&[b"ab", b"c"]), Scalar::from_bytes_wide(&wide));
        // Little-endian: the low byte is first.
        let mut one = [0u8; 64];
        one[0] = 1;
        assert_eq!(Scalar::from_bytes_wide(&one), Scalar::one());
    }
}
