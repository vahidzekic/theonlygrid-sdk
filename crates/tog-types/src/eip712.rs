//! EIP-712 digest of a transaction body (TOG-SPEC-0007 §4.5), signed by `Signature::Secp256k1Eip712`
//! so that `eth_signTypedData_v4` in a browser wallet shows what is signed.
//!
//! ```text
//! domain   = EIP712Domain(string name, string version, uint256 chainId) { "TOG", "1", replay domain }
//! Transfer = Transfer(address to, uint256 amount, uint64 nonce)      // `from` is the recovered signer
//! Generic  = TogTransaction(string kind, bytes32 bodyHash)           // every other kind
//! Endpoint = TogEndpoint(bytes32 recordHash)                         // an `EndpointRecord`, TOG-SPEC-0006 §4
//! digest   = keccak256(0x19 ‖ 0x01 ‖ hashStruct(domain) ‖ hashStruct(message))
//! ```

use tog_primitives::{keccak256, Hash32};

use crate::tx::TxBody;

const DOMAIN_TYPE: &[u8] = b"EIP712Domain(string name,string version,uint256 chainId)";
const TRANSFER_TYPE: &[u8] = b"Transfer(address to,uint256 amount,uint64 nonce)";
const GENERIC_TYPE: &[u8] = b"TogTransaction(string kind,bytes32 bodyHash)";
const ENDPOINT_TYPE: &[u8] = b"TogEndpoint(bytes32 recordHash)";

/// `hashStruct(EIP712Domain { name: "TOG", version: "1", chainId })`.
pub fn domain_separator(chain_id: u64) -> Hash32 {
    keccak256(&[&keccak256(&[DOMAIN_TYPE]), &keccak256(&[b"TOG"]), &keccak256(&[b"1"]), &word(u128::from(chain_id))])
}

/// `hashStruct` of the typed message for `body`: `Transfer` for a transfer, `TogTransaction` otherwise.
pub fn message_hash(body: &TxBody) -> Hash32 {
    match body {
        TxBody::Transfer(t) => {
            let mut to = [0u8; 32];
            to[12..].copy_from_slice(&t.to);
            keccak256(&[&keccak256(&[TRANSFER_TYPE]), &to, &word(t.amount), &word(u128::from(t.nonce))])
        }
        _ => generic_hash(body.kind(), &body.signing_hash()),
    }
}

fn generic_hash(kind: &str, body_hash: &Hash32) -> Hash32 {
    keccak256(&[&keccak256(&[GENERIC_TYPE]), &keccak256(&[kind.as_bytes()]), body_hash])
}

/// The EIP-712 digest a `Secp256k1Eip712` signature covers.
pub fn digest(body: &TxBody, chain_id: u64) -> Hash32 {
    keccak256(&[&[0x19, 0x01], &domain_separator(chain_id), &message_hash(body)])
}

/// The EIP-712 digest a variant-2 `EndpointRecord` signature covers: `record_hash` is
/// [`crate::endpoint::EndpointBody::digest`], `chain_id` the Hub's replay domain.
pub fn endpoint_digest(record_hash: &Hash32, chain_id: u64) -> Hash32 {
    let msg = keccak256(&[&keccak256(&[ENDPOINT_TYPE]), record_hash]);
    keccak256(&[&[0x19, 0x01], &domain_separator(chain_id), &msg])
}

/// A `uint256` word, big-endian.
fn word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::TransferTx;

    const CHAIN: u64 = 1 << 32;

    fn hex(h: &Hash32) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Vectors from eth_account's `encode_typed_data` with the same domain and message.
    #[test]
    fn transfer_matches_reference() {
        let t = TransferTx {
            chain_id: CHAIN,
            from: [0; 20],
            to: [0xab; 20],
            amount: 5 * tog_primitives::ONE_TOG,
            nonce: 7,
        };
        assert_eq!(
            hex(&digest(&TxBody::Transfer(t), CHAIN)),
            "413e2552979fd21f469563cd9b7d2a1e287cd1b4fa599a6d6fa7d61917f26eda"
        );
    }

    #[test]
    fn generic_matches_reference() {
        let msg = generic_hash("SubmitJob", &[0x11; 32]);
        assert_eq!(
            hex(&keccak256(&[&[0x19, 0x01], &domain_separator(CHAIN), &msg])),
            "90d2f864fc884fddced0aaf518a70c8b70e1a6446a89c18a7358697bde40bae1"
        );
    }

    #[test]
    fn endpoint_matches_reference() {
        assert_eq!(
            hex(&endpoint_digest(&[0x22; 32], CHAIN)),
            "1fb8b945b75588a6f913827a42a9371de530568d3b43227dfef3ccee09d845ee"
        );
        assert_ne!(endpoint_digest(&[0x22; 32], CHAIN), endpoint_digest(&[0x22; 32], CHAIN + 1));
    }

    #[test]
    fn digest_binds_chain_and_kind() {
        let claim = TxBody::ClaimJob(crate::tx::ClaimTx { job_id: [1; 32], bond: 1 });
        let release = TxBody::ReleaseClaim(crate::tx::ReleaseClaimTx {
            job_id: [1; 32],
            reason: Default::default(),
            claim_height: 1,
        });
        assert_ne!(digest(&claim, CHAIN), digest(&claim, CHAIN + 1));
        assert_ne!(digest(&claim, CHAIN), digest(&release, CHAIN));
        assert_eq!(message_hash(&claim), generic_hash("ClaimJob", &claim.signing_hash()));
        let sig = crate::Signature::Secp256k1Eip712([0; 65]);
        assert_eq!(claim.digest_for(&sig, CHAIN), digest(&claim, CHAIN));
        assert_eq!(claim.digest_for(&crate::Signature::Secp256k1([0; 65]), CHAIN), claim.signing_hash());
    }
}
