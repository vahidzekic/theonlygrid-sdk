//! Protocol ids of the planes' discovery and validator-plane gossip, and the validator-plane address
//! record (TOG-SPEC-0006 §2, §4), shared by `togd` and the Hub node.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::hash::{tagged_hash, Domain};
use tog_primitives::{Address, ChainId, Hash32};

use crate::tx::Signature;

/// Validator-plane Kademlia: validator nodes and their bound sentries, all in server mode (§4).
pub const VAL_KAD_PROTOCOL: &str = "/tog/val/1/kad";
/// Public Hub-plane Kademlia: Hub full nodes and validator nodes serve it; `togd` and light clients
/// query it in client mode (§4). Validators are found here by peer lookup (§2.3.2).
pub const HUB_KAD_PROTOCOL: &str = "/tog/hub/1/kad";
/// Grid-plane Kademlia (§4).
pub const GRID_KAD_PROTOCOL: &str = "/tog/grid/1/kad";

/// An AppChain plane's Kademlia protocol id, `/tog/app/<chain_id>/1/kad` (§4).
pub fn app_kad_protocol(chain: ChainId) -> String {
    format!("/tog/app/{}/1/kad", chain.0)
}

/// Validator-plane gossipsub protocol id, so it never meshes with Hub-plane gossip (§2.1).
pub const VAL_MESHSUB_PROTOCOL: &str = "/tog/val/1/meshsub";
/// Validator-plane topic of proposal parts (§2.1).
pub const VAL_PROPOSAL_TOPIC: &str = "/tog/val/1/proposal";
/// Validator-plane topic of prevotes and precommits with their vote extensions (§2.1).
pub const VAL_VOTES_TOPIC: &str = "/tog/val/1/votes";
/// Validator-plane topic of approval and dispute votes (§2.1).
pub const VAL_APPROVALS_TOPIC: &str = "/tog/val/1/approvals";
/// Validator-plane topic of availability bitfields (§2.1, TOG-SPEC-0002 §4.6).
pub const VAL_BITFIELDS_TOPIC: &str = "/tog/val/1/bitfields";
/// Validator-plane topic of code pre-check votes, one `borsh(PreCheckVote)` per message (§2.1, TOG-SPEC-0007 §8.2).
pub const VAL_PRECHECK_TOPIC: &str = "/tog/val/1/precheck";
/// Largest pre-check vote message (§2.1).
pub const VAL_PRECHECK_MAX: usize = 256;
/// Hub-plane topic of decided blocks, one `borsh((HubHeader, CommitCertificate))` per message (§2.1).
pub const BLOCKS_ANNOUNCE_TOPIC: &str = "/tog/hub/1/blocks/announce";
/// Largest block announcement (§2.1).
pub const BLOCKS_ANNOUNCE_MAX: usize = 2 * 1024;
/// Size of a proposal part, the last one shorter (§2.1, §11).
pub const PROPOSAL_PART_SIZE: usize = 64 * 1024;
/// Validator-plane gossipsub mesh degree (§11).
pub const VAL_MESH_DEGREE: usize = 12;

/// libp2p `PeerId` bytes of an Ed25519 network key (TOG-SPEC-0006 §1.2): the identity multihash of
/// its protobuf `PublicKey` (`KeyType::Ed25519`).
pub fn ed25519_peer_id(network_key: &[u8; 32]) -> Vec<u8> {
    [&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20][..], network_key].concat()
}

/// Largest [`ValidatorAddrRecord`] value (TOG-SPEC-0006 §2.1).
pub const VAL_ADDR_MAX: usize = 1024;
/// Most addresses in a [`ValidatorAddrRecord`].
pub const VAL_ADDR_MAX_ADDRS: usize = 8;
/// Republish interval, in seconds.
pub const VAL_ADDR_REPUBLISH: u64 = 3_600;
/// A stored record expires this long after it is stored, in seconds.
pub const VAL_ADDR_TTL: u64 = 24 * 3_600;

/// Everything but the signature of a [`ValidatorAddrRecord`]: what the network key signs.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ValidatorAddrBody {
    /// The validator's stash, as in `ValidatorRecord` (TOG-SPEC-0002 §7.2).
    pub stash: Address,
    /// libp2p `PeerId` bytes of `ValidatorRecord.network_key`.
    pub peer_id: Vec<u8>,
    /// Multiaddr bytes, at most [`VAL_ADDR_MAX_ADDRS`]; sentry addresses if the validator hides its host.
    pub addrs: Vec<Vec<u8>>,
    /// The era whose set it is published for.
    pub era: u64,
}

/// A validator's address in the validator-plane DHT (TOG-SPEC-0006 §2.1), stored under
/// [`val_addr_key`]; Borsh is the body's fields, then `sig`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ValidatorAddrRecord {
    /// Body.
    pub body: ValidatorAddrBody,
    /// Variant 0 (Ed25519), by the network key, over [`ValidatorAddrBody::digest`].
    pub sig: Signature,
}

/// The DHT key of `stash`'s record for `era`: `H("TOG/v1/val-addr" ‖ stash ‖ u64 era (LE))`.
pub fn val_addr_key(stash: &Address, era: u64) -> Hash32 {
    tagged_hash(Domain::ValAddr, &[stash, &era.to_le_bytes()])
}

impl ValidatorAddrBody {
    /// `H("TOG/v1/val-addr" ‖ borsh(body))`.
    pub fn digest(&self) -> Hash32 {
        tagged_hash(Domain::ValAddr, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }
}

impl ValidatorAddrRecord {
    /// The record-only checks a DHT server makes before storing `value` under `key`, and a reader on
    /// every record it gets: exact decoding within [`VAL_ADDR_MAX`], at most [`VAL_ADDR_MAX_ADDRS`]
    /// addresses, a variant-0 signature by `network_key`, `peer_id` that key's `PeerId`, and `key`
    /// equal to [`val_addr_key`] of the record's stash and era. The caller passes
    /// `ValidatorRecord[stash].network_key` from Hub state for the stash it decoded
    /// ([`ValidatorAddrRecord::stash_of`]) and still checks that `era` is the current or next era and
    /// `stash` is in `staking.elected[era]`.
    pub fn check(key: &[u8], value: &[u8], network_key: &[u8; 32]) -> Option<Self> {
        if value.len() > VAL_ADDR_MAX {
            return None;
        }
        let r: Self = borsh::from_slice(value).ok()?;
        let signed = match &r.sig {
            Signature::Ed25519 { public_key, .. } => public_key == network_key,
            _ => false,
        };
        let ok = signed
            && r.body.addrs.len() <= VAL_ADDR_MAX_ADDRS
            && r.body.peer_id == ed25519_peer_id(network_key)
            && key == val_addr_key(&r.body.stash, r.body.era)
            && r.sig.verify(&r.body.digest()).is_ok();
        ok.then_some(r)
    }

    /// The stash a stored value claims, to look up its `network_key` before [`ValidatorAddrRecord::check`].
    pub fn stash_of(value: &[u8]) -> Option<Address> {
        if value.len() > VAL_ADDR_MAX {
            return None;
        }
        borsh::from_slice::<Self>(value).ok().map(|r| r.body.stash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{Signer, SigningKey};

    fn record(key: &SigningKey, body: ValidatorAddrBody) -> Vec<u8> {
        let sig =
            Signature::Ed25519 { public_key: key.verifying_key().to_bytes(), sig: key.sign(&body.digest()).to_bytes() };
        borsh::to_vec(&ValidatorAddrRecord { body, sig }).unwrap()
    }

    #[test]
    fn validator_addr_records_are_checked_against_the_network_key() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let nk = key.verifying_key().to_bytes();
        let body = ValidatorAddrBody { stash: [3; 20], peer_id: ed25519_peer_id(&nk), addrs: vec![vec![4, 1]], era: 9 };
        let k = val_addr_key(&[3; 20], 9);
        let ok = record(&key, body.clone());
        assert_eq!(ValidatorAddrRecord::stash_of(&ok), Some([3; 20]));
        assert_eq!(ValidatorAddrRecord::check(&k, &ok, &nk).unwrap().body, body);
        // Another era's key, another network key, a foreign peer id, too many addresses, trailing bytes, too big.
        assert!(ValidatorAddrRecord::check(&val_addr_key(&[3; 20], 10), &ok, &nk).is_none());
        let other = SigningKey::from_bytes(&[6; 32]);
        assert!(ValidatorAddrRecord::check(&k, &ok, &other.verifying_key().to_bytes()).is_none());
        assert!(ValidatorAddrRecord::check(&k, &record(&other, body.clone()), &nk).is_none());
        let foreign = ValidatorAddrBody { peer_id: vec![1, 2], ..body.clone() };
        assert!(ValidatorAddrRecord::check(&k, &record(&key, foreign), &nk).is_none());
        let many = ValidatorAddrBody { addrs: vec![vec![0]; VAL_ADDR_MAX_ADDRS + 1], ..body.clone() };
        assert!(ValidatorAddrRecord::check(&k, &record(&key, many), &nk).is_none());
        assert!(ValidatorAddrRecord::check(&k, &[ok, vec![0]].concat(), &nk).is_none());
        let big = ValidatorAddrBody { addrs: vec![vec![0; 200]; 6], ..body };
        assert!(ValidatorAddrRecord::check(&k, &record(&key, big), &nk).is_none());
    }

    #[test]
    fn val_addr_key_layout() {
        let mut want = blake3::Hasher::new_derive_key("TOG/v1/val-addr");
        want.update(&[3; 20]);
        want.update(&9u64.to_le_bytes());
        assert_eq!(val_addr_key(&[3; 20], 9), *want.finalize().as_bytes());
    }

    #[test]
    fn app_kad() {
        assert_eq!(app_kad_protocol(ChainId(7)), "/tog/app/7/1/kad");
    }
}

/// The trust anchor of Hub snapshot sync in place of the genesis header (TOG-SPEC-0006 §2.3.3
/// "Trust anchor", weak subjectivity): a recent finalized header taken out of band. The set that
/// signs it is fetched with `SetRequest`, never configured.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TrustedCheckpoint {
    /// Its height, at most the era boundary the node syncs to.
    pub height: u64,
    /// `hub_block_hash(height)` (TOG-SPEC-0002 §3.1).
    pub header_hash: Hash32,
}
