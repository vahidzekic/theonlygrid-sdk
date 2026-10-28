//! Temporal checkpoint cipher (TOG-SPEC-0004 §9.1):
//!
//! ```text
//! c_i = p_i ⊕ ChaCha20(key = k_n, nonce = le96(i), counter = 0..)    // per 4 KiB chunk i
//! ```
//!
//! Length-preserving and random-access, so chunk `i` of the ciphertext opens with the key alone.
//! Encryption and decryption are the same operation. Integrity comes from `ciphertext_root` and
//! `plaintext_root`, not from a MAC. The executor seals with it; the Hub's chunk audit, verifiers
//! and readers of a sealed output archive open with it.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use tog_primitives::payload::CHUNK_4K;
use tog_primitives::{tagged_hash, Domain};

use crate::checkpoint::CheckpointKey;

/// `le96(i)`: the chunk index as a 12-byte little-endian nonce.
fn nonce(index: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&index.to_le_bytes());
    n
}

/// Encrypt or decrypt `bytes`, a whole payload from its first chunk, in place under `key`.
pub fn apply(key: &CheckpointKey, bytes: &mut [u8]) {
    for (i, chunk) in bytes.chunks_mut(CHUNK_4K).enumerate() {
        apply_chunk(key, i as u64, chunk);
    }
}

/// Encrypt or decrypt chunk `index` alone (at most [`CHUNK_4K`] bytes) in place under `key`.
pub fn apply_chunk(key: &CheckpointKey, index: u64, chunk: &mut [u8]) {
    ChaCha20::new(&key.0.into(), &nonce(index).into()).apply_keystream(chunk);
}

/// `k_out = H("TOG/v1/output-key" ‖ k_{N−1})`: the key of a sealed output archive that isn't
/// `ckpt_{N−1}` itself, for a segmented or a T3 job (TOG-SPEC-0004 §9.1 "Output archive").
pub fn output_key(last: &CheckpointKey) -> CheckpointKey {
    CheckpointKey(tagged_hash(Domain::OutputKey, &[&last.0]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn roundtrip_and_length() {
        let key = CheckpointKey([7; 32]);
        let plain: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let mut c = plain.clone();
        apply(&key, &mut c);
        assert_eq!(c.len(), plain.len());
        assert_ne!(c, plain);
        apply(&key, &mut c);
        assert_eq!(c, plain);
    }

    #[test]
    fn chunks_decrypt_independently() {
        let key = CheckpointKey([1; 32]);
        let plain = vec![0xabu8; 3 * CHUNK_4K + 5];
        let mut c = plain.clone();
        apply(&key, &mut c);
        // Chunk 2 on its own, with nonce 2.
        let mut chunk = c[2 * CHUNK_4K..3 * CHUNK_4K].to_vec();
        apply_chunk(&key, 2, &mut chunk);
        assert_eq!(chunk, plain[2 * CHUNK_4K..3 * CHUNK_4K]);
        // Equal plaintext chunks encrypt differently at different indices.
        assert_ne!(c[..CHUNK_4K], c[CHUNK_4K..2 * CHUNK_4K]);
    }

    #[test]
    fn nonce_is_little_endian_96() {
        assert_eq!(nonce(0x0102), [2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn output_key_is_tagged() {
        let k = CheckpointKey([3; 32]);
        assert_eq!(output_key(&k).0, tagged_hash(Domain::OutputKey, &[&[3; 32]]));
        assert_ne!(output_key(&k).0, k.0);
    }
}
