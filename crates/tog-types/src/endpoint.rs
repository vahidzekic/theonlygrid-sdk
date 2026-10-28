//! Where a worker or storage worker can be reached: a signed record in the Grid DHT (TOG-SPEC-0006
//! §4). It maps a `WorkerId` or `StorageWorkerId` from Hub state to a libp2p `PeerId` and addresses,
//! and is that peer's binding on the Grid plane.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::hash::{tagged_hash, Domain};
use tog_primitives::{Address, Hash32};

use crate::tx::Signature;

/// Largest record value.
pub const ENDPOINT_MAX: usize = 1024;
/// Most addresses in a record.
pub const ENDPOINT_MAX_ADDRS: usize = 8;
/// How far `seq` may be ahead of the reader's clock, in seconds.
pub const ENDPOINT_MAX_SKEW: u64 = 600;
/// How far `seq` may be behind the reader's clock, in seconds: the record lifetime plus the skew,
/// so a stale record replayed after it expired is refused (TOG-SPEC-0006 §4).
pub const ENDPOINT_MAX_AGE: u64 = 87_000;
/// Republish interval, in seconds.
pub const ENDPOINT_REPUBLISH: u64 = 3_600;
/// A stored record expires this long after it is stored, in seconds.
pub const ENDPOINT_TTL: u64 = 24 * 3_600;

/// Everything but the signature: what the role key signs.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EndpointBody {
    /// Address of the worker key or the storage key.
    pub role: Address,
    /// libp2p `PeerId` bytes of the node's network key.
    pub peer_id: Vec<u8>,
    /// Multiaddr bytes, at most [`ENDPOINT_MAX_ADDRS`].
    pub addrs: Vec<Vec<u8>>,
    /// Unix seconds at signing.
    pub seq: u64,
}

/// The DHT value; Borsh is the body's fields, then `sig`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EndpointRecord {
    /// Body.
    pub body: EndpointBody,
    /// By the role key: variant 0 (Ed25519) or 1 (secp256k1) over [`EndpointBody::digest`], or
    /// variant 2 (secp256k1) over its EIP-712 `TogEndpoint` digest ([`crate::eip712::endpoint_digest`]).
    /// A bonded worker or storage key signs with variant 0.
    pub sig: Signature,
}

/// The DHT key of `role`'s record: `H("TOG/v1/endpoint" ‖ role)`.
pub fn endpoint_key(role: &Address) -> Hash32 {
    tagged_hash(Domain::Endpoint, &[role])
}

impl EndpointBody {
    /// `H("TOG/v1/endpoint" ‖ borsh(body))`.
    pub fn digest(&self) -> Hash32 {
        tagged_hash(Domain::Endpoint, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }
}

impl EndpointRecord {
    /// The checks a DHT server makes before storing `value` under `key`, and a reader makes on
    /// every record it gets: exact decoding within [`ENDPOINT_MAX`], at most
    /// [`ENDPOINT_MAX_ADDRS`] addresses, a signature by `role`'s key, `key` equal to
    /// [`endpoint_key`] of `role`, and `now − ENDPOINT_MAX_AGE ≤ seq ≤ now + ENDPOINT_MAX_SKEW`
    /// (unix seconds).
    /// `chain_id` is the Hub's replay domain, used only by a variant-2 signature. Whether `role` is a
    /// bonded key, which must use variant 0 ([`Self::is_ed25519`]), is for the caller to check
    /// against Hub state.
    pub fn check(key: &[u8], value: &[u8], now: u64, chain_id: u64) -> Option<Self> {
        if value.len() > ENDPOINT_MAX {
            return None;
        }
        let r: Self = borsh::from_slice(value).ok()?;
        let ok = r.body.addrs.len() <= ENDPOINT_MAX_ADDRS
            && key == endpoint_key(&r.body.role)
            && r.body.seq <= now.saturating_add(ENDPOINT_MAX_SKEW)
            && r.body.seq >= now.saturating_sub(ENDPOINT_MAX_AGE)
            && r.signer(chain_id) == Some(r.body.role);
        ok.then_some(r)
    }

    /// The address `sig` verifies to, over the digest its variant signs.
    pub fn signer(&self, chain_id: u64) -> Option<Address> {
        let digest = match self.sig {
            Signature::Secp256k1Eip712(_) => crate::eip712::endpoint_digest(&self.body.digest(), chain_id),
            _ => self.body.digest(),
        };
        self.sig.verify(&digest).ok()
    }

    /// Whether `sig` is variant 0, the only one a bonded worker or storage key may use.
    pub fn is_ed25519(&self) -> bool {
        matches!(self.sig, Signature::Ed25519 { .. })
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const CHAIN: u64 = 1 << 32;

    fn record(key: &SigningKey, body: EndpointBody) -> Vec<u8> {
        let sig =
            Signature::Ed25519 { public_key: key.verifying_key().to_bytes(), sig: key.sign(&body.digest()).to_bytes() };
        borsh::to_vec(&EndpointRecord { body, sig }).unwrap()
    }

    #[test]
    fn records_are_checked_against_their_key_signer_and_clock() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let role = tog_primitives::ed25519_address(&key.verifying_key().to_bytes());
        let body = EndpointBody { role, peer_id: vec![1, 2], addrs: vec![vec![4, 127, 0, 0, 1]], seq: 1_000 };
        let k = endpoint_key(&role);
        let ok = record(&key, body.clone());
        assert_eq!(EndpointRecord::check(&k, &ok, 1_000, CHAIN).unwrap().body, body);
        // Wrong key, another signer, too far ahead, too many addresses, trailing bytes.
        assert!(EndpointRecord::check(&endpoint_key(&[0; 20]), &ok, 1_000, CHAIN).is_none());
        assert!(
            EndpointRecord::check(&k, &record(&SigningKey::from_bytes(&[6; 32]), body.clone()), 1_000, CHAIN).is_none()
        );
        assert!(EndpointRecord::check(&k, &ok, 1_000 - ENDPOINT_MAX_SKEW - 1, CHAIN).is_none());
        assert!(EndpointRecord::check(&k, &ok, 1_000 - ENDPOINT_MAX_SKEW, CHAIN).is_some());
        // Too old: a record past its lifetime, replayed.
        assert!(EndpointRecord::check(&k, &ok, 1_000 + ENDPOINT_MAX_AGE, CHAIN).is_some());
        assert!(EndpointRecord::check(&k, &ok, 1_000 + ENDPOINT_MAX_AGE + 1, CHAIN).is_none());
        let many = EndpointBody { addrs: vec![vec![0]; ENDPOINT_MAX_ADDRS + 1], ..body.clone() };
        assert!(EndpointRecord::check(&k, &record(&key, many), 1_000, CHAIN).is_none());
        assert!(EndpointRecord::check(&k, &[ok, vec![0]].concat(), 1_000, CHAIN).is_none());
        let big = EndpointBody { addrs: vec![vec![0; 200]; 6], ..body };
        assert!(EndpointRecord::check(&k, &record(&key, big), 1_000, CHAIN).is_none());
    }

    #[test]
    fn secp256k1_records_verify_over_their_variant_digest() {
        let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let p = key.verifying_key().to_encoded_point(false);
        let role = tog_primitives::secp256k1_address(p.as_bytes()[1..].try_into().unwrap());
        let body = EndpointBody { role, peer_id: vec![1], addrs: vec![], seq: 1_000 };
        let sign = |digest: Hash32| {
            let (sig, recid) = key.sign_prehash_recoverable(&digest).unwrap();
            let mut b = [0u8; 65];
            b[..64].copy_from_slice(&sig.to_bytes());
            b[64] = recid.to_byte();
            b
        };
        let k = endpoint_key(&role);
        let rec = |sig| borsh::to_vec(&EndpointRecord { body: body.clone(), sig }).unwrap();
        let plain = sign(body.digest());
        let typed = sign(crate::eip712::endpoint_digest(&body.digest(), CHAIN));
        let v1 = EndpointRecord::check(&k, &rec(Signature::Secp256k1(plain)), 1_000, CHAIN).unwrap();
        assert!(!v1.is_ed25519());
        assert!(EndpointRecord::check(&k, &rec(Signature::Secp256k1Eip712(typed)), 1_000, CHAIN).is_some());
        // Each digest only under its own variant, and the typed one only under its chain.
        assert!(EndpointRecord::check(&k, &rec(Signature::Secp256k1Eip712(plain)), 1_000, CHAIN).is_none());
        assert!(EndpointRecord::check(&k, &rec(Signature::Secp256k1(typed)), 1_000, CHAIN).is_none());
        assert!(EndpointRecord::check(&k, &rec(Signature::Secp256k1Eip712(typed)), 1_000, CHAIN + 1).is_none());
    }
}
