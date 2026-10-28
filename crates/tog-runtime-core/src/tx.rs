//! Signed transactions of an AppChain and the pool's view of them (TOG-SPEC-0007 §3.1, §4.5).
//!
//! A block's extrinsics are `borsh(AppTx)`: an [`AppTxBody`], the signer's address and a
//! signature (0001 §3.2) over the TOG digest `H("TOG/v1/tx" ‖ borsh(body))`, Ed25519 or secp256k1,
//! so one key has one address on the Hub and on every chain. The body carries the chain's replay
//! domain, so a transaction signed for one chain or for the Hub is never valid on another. A
//! secp256k1 key may instead sign the EIP-712 digest ([`AppTxBody::eip712_digest`], §4.5):
//! `TogTransaction(string kind, bytes32 bodyHash)` with `kind = "<module>.<call>"`, the module's and
//! the call's names in the runtime metadata, which the runtime derives from `call`'s indices.
//!
//! The runtime checks signatures with the host's crypto ([`SignatureCheck`]); native code and tests
//! use [`NativeCheck`].

use alloc::string::String;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{ed25519_address, keccak256, tagged_hash, Domain};
use tog_types::eip712::domain_separator;
use tog_types::tx::Signature;

use crate::{AccountId, Address, Amount, Hash32};

/// What the signer signs (§4.5, exact).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppTxBody {
    /// Replay domain of the chain it is for: `(network_id << 32) | ChainId` (0000 §13.2).
    pub chain_id: u64,
    /// The signer's `system` nonce, incremented at `pre_dispatch`.
    pub nonce: u64,
    /// Added to the fee (§4.3).
    pub tip: Amount,
    /// The last block number of this chain that may include it.
    pub valid_until: u64,
    /// Module index, call index (positions in the runtime's lists) and `borsh(args)`.
    pub call: (u8, u8, Vec<u8>),
}

impl AppTxBody {
    /// The TOG digest, `H("TOG/v1/tx" ‖ borsh(body))`.
    pub fn signing_hash(&self) -> Hash32 {
        tagged_hash(Domain::Tx, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }

    /// The EIP-712 digest of `TogTransaction { kind, bodyHash: signing_hash() }` under the domain
    /// `{ "TOG", "1", chain_id }`; `kind` is the call's `"<module>.<call>"`.
    pub fn eip712_digest(&self, kind: &str) -> Hash32 {
        const GENERIC_TYPE: &[u8] = b"TogTransaction(string kind,bytes32 bodyHash)";
        let message = keccak256(&[&keccak256(&[GENERIC_TYPE]), &keccak256(&[kind.as_bytes()]), &self.signing_hash()]);
        keccak256(&[&[0x19, 0x01], &domain_separator(self.chain_id), &message])
    }
}

/// A signed transaction, a block extrinsic (§4.5, exact).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppTx {
    /// Body.
    pub body: AppTxBody,
    /// The signer's address; the signature must yield it.
    pub signer: Address,
    /// Signature over [`AppTxBody::signing_hash`], or over the EIP-712 digest.
    pub sig: Signature,
}

/// Where the pool got a transaction (§3.1, exact).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum TxSource {
    /// 0: re-check of a block's transaction.
    InBlock,
    /// 1: submitted to this node.
    Local,
    /// 2: from gossip.
    External,
}

/// A valid transaction, as the pool keeps it (§3.1, exact).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ValidTx {
    /// The signer.
    pub sender: Address,
    /// The pool holds the transaction until the sender's `system::nonce` reaches it.
    pub nonce: u64,
    /// Higher first.
    pub priority: u128,
    /// Blocks it stays valid: `valid_until + 1` minus the number of the next block.
    pub longevity: u64,
}

/// Why a transaction is invalid (§3.1, exact); indices are positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum TxError {
    /// 0: it doesn't decode, names no call, or is EIP-712 signed over a call the runtime can't name.
    BadFormat,
    /// 1: the signature doesn't verify, or yields another address than `signer`.
    BadSignature,
    /// 2: the body is for another chain.
    WrongChain,
    /// 3: its nonce is below the signer's.
    StaleNonce,
    /// 4: the signer can't pay its fee.
    CannotPay,
    /// 5: `valid_until` is below the block's number.
    Expired,
    /// 6: it doesn't fit a block.
    ExhaustsResources,
    /// 7: the call's own pre-dispatch check failed, with a module-defined code.
    Call(u8),
}

/// `tog_v1_validate_tx`'s result.
pub type TxValidity = Result<ValidTx, TxError>;

/// Signature primitives: the host's in the runtime, [`NativeCheck`] natively.
pub trait SignatureCheck {
    /// Ed25519 (`verify_strict`) of `sig` by `pk` over `msg`.
    fn ed25519_verify(&self, pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> bool;
    /// The address (Ethereum's, `keccak256(x ‖ y)[12..]`) of the key behind `r ‖ s ‖ v` over
    /// `digest` (low `s`, `v ∈ {0, 1, 27, 28}`).
    fn secp256k1_signer(&self, digest: &Hash32, sig: &[u8; 65]) -> Option<AccountId>;
}

/// [`SignatureCheck`] in Rust, for native code and tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeCheck;

impl SignatureCheck for NativeCheck {
    fn ed25519_verify(&self, pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> bool {
        let Ok(msg) = <&Hash32>::try_from(msg) else { return false };
        Signature::Ed25519 { public_key: *pk, sig: *sig }.verify(msg).is_ok()
    }

    fn secp256k1_signer(&self, digest: &Hash32, sig: &[u8; 65]) -> Option<AccountId> {
        Signature::Secp256k1(*sig).verify(digest).ok()
    }
}

impl AppTx {
    /// Check the body is for `chain_id` and the signature is `signer`'s; returns the signer. `kind`
    /// is the call's `"<module>.<call>"`, which an EIP-712 signature covers; `None` refuses one.
    pub fn check(&self, chain_id: u64, kind: Option<&str>, c: &impl SignatureCheck) -> Result<Address, TxError> {
        if self.body.chain_id != chain_id {
            return Err(TxError::WrongChain);
        }
        let digest = self.body.signing_hash();
        let signer = match &self.sig {
            Signature::Ed25519 { public_key, sig } => {
                c.ed25519_verify(public_key, sig, &digest).then(|| ed25519_address(public_key))
            }
            Signature::Secp256k1(sig) => c.secp256k1_signer(&digest, sig),
            Signature::Secp256k1Eip712(sig) => {
                let kind = kind.ok_or(TxError::BadFormat)?;
                c.secp256k1_signer(&self.body.eip712_digest(kind), sig)
            }
        };
        match signer {
            Some(a) if a == self.signer => Ok(a),
            _ => Err(TxError::BadSignature),
        }
    }

    /// `Err(Expired)` if a block numbered `number` may not include it.
    pub fn check_expiry(&self, number: u64) -> Result<(), TxError> {
        if self.body.valid_until < number {
            return Err(TxError::Expired);
        }
        Ok(())
    }

    /// [`ValidTx::longevity`] for a transaction checked for block `next`.
    pub fn longevity(&self, next: u64) -> u64 {
        self.body.valid_until.saturating_add(1).saturating_sub(next)
    }
}

/// `tog_v1_version`'s result (§3.1, exact).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RuntimeVersion {
    /// Runtime name.
    pub name: String,
    /// Raised by every runtime upgrade.
    pub spec_version: u32,
    /// 1 for the `tog_v1_*` exports.
    pub abi_version: u32,
    /// SDK-defined hash of the runtime's calls, events and storage; informative.
    pub api_hash: Hash32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    const CHAIN: u64 = (1 << 32) | 7;
    const KIND: Option<&str> = Some("balances.transfer");

    fn body() -> AppTxBody {
        AppTxBody { chain_id: CHAIN, nonce: 3, tip: 1_000, valid_until: 50, call: (1, 0, vec![1, 2, 3]) }
    }

    fn ed25519(seed: u8, body: AppTxBody) -> AppTx {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        let sig = key.sign(&body.signing_hash()).to_bytes();
        AppTx { body, signer: ed25519_address(&public_key), sig: Signature::Ed25519 { public_key, sig } }
    }

    fn secp256k1_sign(seed: u8, digest: Hash32) -> (Address, [u8; 65]) {
        let key = k256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let signer = tog_primitives::secp256k1_address(point.as_bytes()[1..].try_into().unwrap());
        let (sig, rec) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = rec.to_byte();
        (signer, bytes)
    }

    fn secp256k1(seed: u8, body: AppTxBody) -> AppTx {
        let (signer, bytes) = secp256k1_sign(seed, body.signing_hash());
        AppTx { body, signer, sig: Signature::Secp256k1(bytes) }
    }

    fn eip712(seed: u8, body: AppTxBody, kind: &str) -> AppTx {
        let (signer, bytes) = secp256k1_sign(seed, body.eip712_digest(kind));
        AppTx { body, signer, sig: Signature::Secp256k1Eip712(bytes) }
    }

    fn all() -> [AppTx; 3] {
        [ed25519(1, body()), secp256k1(1, body()), eip712(1, body(), "balances.transfer")]
    }

    #[test]
    fn every_scheme_yields_the_signer() {
        for x in all() {
            assert_eq!(x.check(CHAIN, KIND, &NativeCheck), Ok(x.signer));
            let decoded: AppTx = borsh::from_slice(&borsh::to_vec(&x).unwrap()).unwrap();
            assert_eq!(decoded, x);
        }
    }

    #[test]
    fn refuses_another_chain_a_changed_body_or_another_signer() {
        for x in all() {
            assert_eq!(x.check(CHAIN + 1, KIND, &NativeCheck), Err(TxError::WrongChain));
            let mut changed = x.clone();
            changed.body.tip += 1;
            assert_eq!(changed.check(CHAIN, KIND, &NativeCheck), Err(TxError::BadSignature));
            let mut other = x.clone();
            other.signer = [9; 20];
            assert_eq!(other.check(CHAIN, KIND, &NativeCheck), Err(TxError::BadSignature));
        }
    }

    #[test]
    fn eip712_covers_the_kind_and_needs_one() {
        let x = eip712(1, body(), "balances.transfer");
        // The wallet showed another call than the body holds.
        assert_eq!(x.check(CHAIN, Some("staking.bond"), &NativeCheck), Err(TxError::BadSignature));
        assert_eq!(x.check(CHAIN, None, &NativeCheck), Err(TxError::BadFormat));
        // The TOG-digest signature doesn't pass as EIP-712.
        let mut swapped = secp256k1(1, body());
        let Signature::Secp256k1(bytes) = swapped.sig else { unreachable!() };
        swapped.sig = Signature::Secp256k1Eip712(bytes);
        assert_eq!(swapped.check(CHAIN, KIND, &NativeCheck), Err(TxError::BadSignature));
    }

    #[test]
    fn eip712_digest_uses_the_hub_domain_and_struct() {
        // Same domain and `TogTransaction` struct as the Hub's (tog_types::eip712), so one wallet
        // template covers both.
        let b = body();
        let message = keccak256(&[
            &keccak256(&[b"TogTransaction(string kind,bytes32 bodyHash)"]),
            &keccak256(&[b"balances.transfer"]),
            &b.signing_hash(),
        ]);
        assert_eq!(
            b.eip712_digest("balances.transfer"),
            keccak256(&[&[0x19, 0x01], &domain_separator(CHAIN), &message])
        );
    }

    #[test]
    fn expiry_and_longevity() {
        let x = ed25519(1, body());
        assert_eq!(x.check_expiry(50), Ok(()));
        assert_eq!(x.check_expiry(51), Err(TxError::Expired));
        assert_eq!((x.longevity(48), x.longevity(51)), (3, 0));
    }

    #[test]
    fn tx_error_indices_are_positions() {
        assert_eq!(borsh::to_vec(&TxError::ExhaustsResources).unwrap(), [6]);
        assert_eq!(borsh::to_vec(&TxError::Call(9)).unwrap(), [7, 9]);
        assert_eq!(borsh::to_vec(&TxSource::External).unwrap(), [2]);
    }
}
