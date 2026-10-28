//! Base types and hashing conventions shared by every TOG component.
//!
//! Everything here is consensus-critical: a change to any encoding or domain tag
//! changes `job_id`s, segment roots and commitments, so it needs a spec change first.
//!
//! Without the default `std` feature the crate is `no_std` with `alloc`, for wasm32 runtimes
//! (TOG-SPEC-0007 §0).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// What the std prelude adds over `core`, for the `no_std` build.
#[allow(unused_imports)]
pub(crate) mod prelude {
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec::Vec;
    pub use alloc::{format, vec};
}

pub mod ecvrf;
pub mod hash;
pub mod payload;
pub mod segment;
pub mod vote;

pub use hash::{tagged_hash, Domain, Hash32};

/// 20-byte account address.
pub type Address = [u8; 20];

/// Amount of atto-TOG. 1 TOG = 10^18 atto-TOG (TOG-SPEC-0001 §3.2).
pub type Amount = u128;

/// Hub block height.
pub type HubHeight = u64;

/// One $TOG in atto-TOG.
pub const ONE_TOG: Amount = 1_000_000_000_000_000_000;

/// Identifier of a chain in the TOG network. `ChainId::HUB` (0) is the Hub itself
/// (TOG-SPEC-0000 §7.2); AppChains get their id from the Hub at registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ChainId(pub u32);

impl ChainId {
    /// The Hub.
    pub const HUB: ChainId = ChainId(0);
    /// The Gateway system chain (TOG-SPEC-0008 §2.2).
    pub const GATEWAY: ChainId = ChainId(1);

    /// True for the Hub.
    pub fn is_hub(self) -> bool {
        self == Self::HUB
    }

    /// Replay domain of transactions executed on this chain:
    /// `(network_id << 32) | chain` (TOG-SPEC-0000 §13.2).
    pub fn replay_domain(self, network_id: u32) -> u64 {
        (u64::from(network_id) << 32) | u64::from(self.0)
    }

    /// This chain's sovereign account on the Hub: first 20 bytes of
    /// `H("TOG/v1/sovereign" ‖ u32_le(chain))`.
    pub fn sovereign_address(self) -> Address {
        truncate(&tagged_hash(Domain::Sovereign, &[&self.0.to_le_bytes()]))
    }
}

/// Signature schemes; the value is the scheme byte of address derivation and the
/// variant index of `Signature` (TOG-SPEC-0000 §13.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Scheme {
    /// Ed25519, 32-byte public key.
    Ed25519 = 0,
    /// secp256k1; the address uses the 64-byte uncompressed key `x ‖ y`.
    Secp256k1 = 1,
}

/// Address of an Ed25519 key: first 20 bytes of `H("TOG/v1/address" ‖ 0 ‖ pubkey)`.
pub fn ed25519_address(public_key: &[u8; 32]) -> Address {
    truncate(&tagged_hash(Domain::Address, &[&[Scheme::Ed25519 as u8], public_key]))
}

/// Address of a secp256k1 key: its Ethereum address, the last 20 bytes of
/// `keccak256(x ‖ y)` over the uncompressed key without the `0x04` prefix (TOG-SPEC-0000 §13.2).
pub fn secp256k1_address(public_key: &[u8; 64]) -> Address {
    keccak256(&[public_key])[12..].try_into().expect("32 - 12 = 20")
}

/// Ethereum's Keccak-256 over the concatenation of `parts` (addresses, EIP-712).
pub fn keccak256(parts: &[&[u8]]) -> Hash32 {
    use tiny_keccak::{Hasher, Keccak};
    let mut digest = [0u8; 32];
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    k.finalize(&mut digest);
    digest
}

fn truncate(h: &Hash32) -> Address {
    h[..20].try_into().expect("32 >= 20")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_domain_layout() {
        assert_eq!(ChainId::HUB.replay_domain(1), 1 << 32);
        assert_eq!(ChainId(7).replay_domain(2), (2 << 32) | 7);
    }

    #[test]
    fn ed25519_address_layout() {
        let key = [5u8; 32];
        assert_eq!(ed25519_address(&key), tagged_hash(Domain::Address, &[&[0], &key])[..20]);
        assert_ne!(ChainId(1).sovereign_address(), ChainId(2).sovereign_address());
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn secp256k1_address_matches_ethereum() {
        // Private key 1: the public key is the generator G; its Ethereum address is well known.
        let g = unhex::<64>(concat!(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ));
        assert_eq!(secp256k1_address(&g), unhex::<20>("7e5f4552091a69125d5dfcb7b8c2659029395bdf"));
    }
}
