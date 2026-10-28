//! Crypto host functions (§3.2). Hashing runs natively in the host, which is much faster than in
//! Wasm and is charged as one host call.

use tog_runtime_core::tx::SignatureCheck;
use tog_runtime_core::{AccountId, Hash32};

use crate::ffi;

/// BLAKE3-256.
pub fn blake3(data: &[u8]) -> Hash32 {
    ffi::hash(0, data)
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> Hash32 {
    ffi::hash(1, data)
}

/// Keccak-256 (Ethereum's).
pub fn keccak256(data: &[u8]) -> Hash32 {
    ffi::hash(2, data)
}

/// Ed25519 (`verify_strict`) of `sig` by `pk` over `msg`.
pub fn ed25519_verify(pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> bool {
    ffi::ed25519(pk, sig, msg)
}

/// sr25519 (schnorrkel, signing context `b"substrate"`) of `sig` by `pk` over `msg`. For
/// applications only: sr25519 is not an account scheme (§4.5).
pub fn sr25519_verify(pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> bool {
    ffi::sr25519(pk, sig, msg)
}

/// `FastAggregateVerify` of `sig` (compressed G2) by every key of `keys` (compressed G1) over
/// `msg`, in the Hub's min-pk scheme (0002 §3.1). An empty list, or a key or signature that
/// doesn't decode, is invalid. The caller must hold a proof of possession of every key.
pub fn bls12_381_verify_aggregate(keys: &[[u8; 48]], sig: &[u8; 96], msg: &[u8]) -> bool {
    let keys = borsh::to_vec(&keys).expect("in-memory borsh");
    ffi::bls_aggregate(&keys, sig, msg)
}

/// The uncompressed public key `x ‖ y` that produced `r ‖ s ‖ v` over `digest` (Ethereum rules:
/// `v ∈ {0, 1, 27, 28}`, low `s`), or `None`.
pub fn secp256k1_recover(digest: &Hash32, sig: &[u8; 65]) -> Option<[u8; 64]> {
    ffi::secp256k1(digest, sig)
}

/// Transaction signature checks through the host (0007 §4.5).
#[derive(Clone, Copy, Debug, Default)]
pub struct HostCheck;

impl SignatureCheck for HostCheck {
    fn ed25519_verify(&self, pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> bool {
        ed25519_verify(pk, sig, msg)
    }

    fn secp256k1_signer(&self, digest: &Hash32, sig: &[u8; 65]) -> Option<AccountId> {
        let xy = secp256k1_recover(digest, sig)?;
        keccak256(&xy)[12..].try_into().ok()
    }
}
