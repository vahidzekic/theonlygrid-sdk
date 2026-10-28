//! The Hub's Groth21 resharing vectors (TOG-SPEC-0009 §2.2): this crate's `ResharingDealing` must
//! decode them, encode them back bit for bit, and hash and verify their signature the same way.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tog_types::consensus::ResharingDealing;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn hub_dealings_round_trip_and_verify() {
    let v: serde_json::Value = serde_json::from_str(include_str!("data/groth21-vectors.json")).unwrap();
    let s = |k: &str| v[k].as_str().unwrap().to_string();
    let bytes = hex(&s("dealing_borsh"));
    let d: ResharingDealing = borsh::from_slice(&bytes).unwrap();
    assert_eq!(borsh::to_vec(&d).unwrap(), bytes);
    assert_eq!(blake3::hash(&bytes).as_bytes().to_vec(), hex(&s("dealing_blake3")));
    assert_eq!((d.era, d.ek_epoch, d.dealer.0), (3, 1, 0));
    assert_eq!(d.ciphertexts.chunks.len(), 4);
    // The vector is a resharing dealing: kind 1 (TOG-SPEC-0009 §2.2 "Dealing kind").
    assert_eq!(v["kind"].as_u64(), Some(1));
    let digest = d.signing_hash(v["chain_id"].as_u64().unwrap(), tog_types::consensus::DealingKind::Reshare);
    assert_eq!(digest.to_vec(), hex(&s("signing_digest")));
    let key = VerifyingKey::from_bytes(&hex(&s("dealer_consensus_key")).try_into().unwrap()).unwrap();
    key.verify(&digest, &Signature::from_bytes(&d.sig)).unwrap();
    // The invalid dealing differs only in a proof; its encoding is still well-formed.
    let bad = hex(&s("invalid_dealing_borsh"));
    let b: ResharingDealing = borsh::from_slice(&bad).unwrap();
    assert_eq!(borsh::to_vec(&b).unwrap(), bad);
    assert_ne!(b.chunking_proof, d.chunking_proof);
}
