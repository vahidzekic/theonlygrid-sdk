//! Transaction signatures (TOG-SPEC-0001 §3.2, TOG-SPEC-0000 §13.2): signing and signer recovery.
//!
//! Ed25519 is verified with `verify_strict` (no small-order keys, canonical `s`). secp256k1 follows
//! Ethereum: `r ‖ s ‖ v` with `v ∈ {0, 1, 27, 28}` and, as in EIP-2, only low `s` is accepted, so a
//! signature has one valid encoding.

use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, SigningKey as SecpSigningKey, VerifyingKey};
use tog_primitives::{ed25519_address, secp256k1_address, Address};

use crate::tx::{Signature, SignedTx, TxBody};

/// Why a signature does not verify.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// Malformed key or signature bytes.
    #[error("malformed signature")]
    Malformed,
    /// secp256k1 `s` in the upper half of the curve order.
    #[error("secp256k1 signature must have low s")]
    HighS,
    /// The signature does not verify over the digest.
    #[error("signature does not verify")]
    Invalid,
}

impl SignedTx {
    /// Signs `body` with an Ed25519 key over the TOG digest.
    pub fn sign_ed25519(body: TxBody, key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let sig = key.sign(&body.signing_hash()).to_bytes();
        SignedTx { body, sig: Signature::Ed25519 { public_key: key.verifying_key().to_bytes(), sig } }
    }

    /// Signs `body` with a secp256k1 key: over the TOG digest, or over the EIP-712 digest under
    /// `eip712_chain_id` when it is `Some`.
    pub fn sign_secp256k1(body: TxBody, key: &SecpSigningKey, eip712_chain_id: Option<u64>) -> Self {
        let digest = match eip712_chain_id {
            Some(chain) => crate::eip712::digest(&body, chain),
            None => body.signing_hash(),
        };
        let (sig, recid) = key.sign_prehash_recoverable(&digest).expect("32-byte digest is a valid prehash");
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = recid.to_byte();
        let sig = match eip712_chain_id {
            Some(_) => Signature::Secp256k1Eip712(bytes),
            None => Signature::Secp256k1(bytes),
        };
        SignedTx { body, sig }
    }

    /// Verifies the signature and returns the signer's address. `chain_id` is the executing chain's
    /// replay domain, used only by the EIP-712 digest. The caller checks the address against the
    /// body's sender.
    pub fn signer(&self, chain_id: u64) -> Result<Address, SignatureError> {
        self.sig.verify(&self.body.digest_for(&self.sig, chain_id))
    }
}

impl Signature {
    /// Verifies the signature over `digest` and returns the signer's address. The variant only
    /// picks how the digest was built; callers that accept one digest only check the variant.
    pub fn verify(&self, digest: &[u8; 32]) -> Result<Address, SignatureError> {
        match self {
            Signature::Ed25519 { public_key, sig } => {
                let key = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|_| SignatureError::Malformed)?;
                key.verify_strict(digest, &ed25519_dalek::Signature::from_bytes(sig))
                    .map_err(|_| SignatureError::Invalid)?;
                Ok(ed25519_address(public_key))
            }
            Signature::Secp256k1(bytes) | Signature::Secp256k1Eip712(bytes) => recover_secp256k1(digest, bytes),
        }
    }

    /// Whether the bytes could be a valid signature, checked without a digest: an Ed25519 key that
    /// decodes, or a secp256k1 `(r, s)` in range with low `s` and `v ∈ {0, 1, 27, 28}`.
    pub fn well_formed(&self) -> bool {
        match self {
            Signature::Ed25519 { public_key, .. } => ed25519_dalek::VerifyingKey::from_bytes(public_key).is_ok(),
            Signature::Secp256k1(bytes) | Signature::Secp256k1Eip712(bytes) => {
                EcdsaSignature::from_slice(&bytes[..64]).is_ok_and(|sig| sig.normalize_s().is_none())
                    && matches!(bytes[64], 0 | 1 | 27 | 28)
            }
        }
    }
}

fn recover_secp256k1(digest: &[u8; 32], bytes: &[u8; 65]) -> Result<Address, SignatureError> {
    let sig = EcdsaSignature::from_slice(&bytes[..64]).map_err(|_| SignatureError::Malformed)?;
    if sig.normalize_s().is_some() {
        return Err(SignatureError::HighS);
    }
    let v = match bytes[64] {
        v @ (0 | 1) => v,
        v @ (27 | 28) => v - 27,
        _ => return Err(SignatureError::Malformed),
    };
    let recid = RecoveryId::from_byte(v).ok_or(SignatureError::Malformed)?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, recid).map_err(|_| SignatureError::Invalid)?;
    let point = key.to_encoded_point(false);
    let xy: &[u8; 64] = point.as_bytes()[1..].try_into().expect("uncompressed point is 65 bytes");
    Ok(secp256k1_address(xy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{ClaimTx, TransferTx};

    const CHAIN: u64 = 1 << 32;

    fn body() -> TxBody {
        TxBody::ClaimJob(ClaimTx { job_id: [1; 32], bond: 5 })
    }

    fn secp_key() -> SecpSigningKey {
        SecpSigningKey::from_slice(&[7; 32]).unwrap()
    }

    fn secp_address(key: &SecpSigningKey) -> Address {
        let p = key.verifying_key().to_encoded_point(false);
        secp256k1_address(p.as_bytes()[1..].try_into().unwrap())
    }

    #[test]
    fn ed25519_roundtrip_and_tamper() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let tx = SignedTx::sign_ed25519(body(), &key);
        assert_eq!(tx.signer(CHAIN), Ok(ed25519_address(&key.verifying_key().to_bytes())));
        let tampered = SignedTx { body: TxBody::ClaimJob(ClaimTx { job_id: [1; 32], bond: 6 }), ..tx };
        assert_eq!(tampered.signer(CHAIN), Err(SignatureError::Invalid));
    }

    #[test]
    fn secp256k1_recovers_ethereum_address() {
        let key = secp_key();
        let addr = secp_address(&key);
        for eip712 in [None, Some(CHAIN)] {
            let tx = SignedTx::sign_secp256k1(body(), &key, eip712);
            assert_eq!(tx.signer(CHAIN), Ok(addr));
        }
        // An EIP-712 signature is bound to its chain.
        let tx = SignedTx::sign_secp256k1(body(), &key, Some(CHAIN));
        assert_ne!(tx.signer(CHAIN + 1), Ok(addr));
    }

    #[test]
    fn secp256k1_accepts_legacy_v_and_rejects_high_s() {
        let key = secp_key();
        let addr = secp_address(&key);
        let SignedTx { body, sig: Signature::Secp256k1(mut bytes) } = SignedTx::sign_secp256k1(body(), &key, None)
        else {
            unreachable!()
        };
        let legacy = |b: [u8; 65]| SignedTx { body: body.clone(), sig: Signature::Secp256k1(b) };
        let mut v27 = bytes;
        v27[64] += 27;
        assert_eq!(legacy(v27).signer(CHAIN), Ok(addr));
        let mut bad_v = bytes;
        bad_v[64] = 2;
        assert_eq!(legacy(bad_v).signer(CHAIN), Err(SignatureError::Malformed));

        // s' = n − s with the parity flipped is the same signature in its high-s form.
        let sig = EcdsaSignature::from_slice(&bytes[..64]).unwrap();
        let (r, s) = sig.split_scalars();
        let high = EcdsaSignature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
        bytes[..64].copy_from_slice(&high.to_bytes());
        bytes[64] ^= 1;
        assert_eq!(legacy(bytes).signer(CHAIN), Err(SignatureError::HighS));
    }

    #[test]
    fn known_ethereum_vector() {
        // Private key 1 has the well-known address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf.
        let mut sk = [0u8; 32];
        sk[31] = 1;
        let key = SecpSigningKey::from_slice(&sk).unwrap();
        let t = TransferTx { chain_id: CHAIN, from: [0; 20], to: [2; 20], amount: 1, nonce: 0 };
        let tx = SignedTx::sign_secp256k1(TxBody::Transfer(t), &key, Some(CHAIN));
        let expected: Address = [
            0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90, 0x29, 0x39,
            0x5b, 0xdf,
        ];
        assert_eq!(tx.signer(CHAIN), Ok(expected));

        // eth_account's `Account.sign_message(encode_typed_data(...), key 1)` gives the same RFC 6979
        // signature, with v = 27 + recovery id.
        let Signature::Secp256k1Eip712(bytes) = tx.sig else { unreachable!() };
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "c61505722e4727463f391fb73f719a31cd8d34e6264e7393f167ed9aee4283fc\
             0d512ae7fc5aca1a15ad986c4a418b28f90d1f374b8f84d6e76b576abcf95992\
             01"
        );
    }
}
