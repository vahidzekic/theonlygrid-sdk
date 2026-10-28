//! Payload roots (TOG-SPEC-0004 §2.1).
//!
//! A payload root is the plain BLAKE3 hash of the byte string, identical to `b3sum`.
//! BLAKE3 is itself a tree over 1 KiB chunks, so 4 KiB leaves can be opened later with
//! Bao-style proofs. `plaintext_root` and `ciphertext_root` of a checkpoint are both
//! payload roots in this sense.

use crate::Hash32;

/// Leaf size of payload and checkpoint chunk trees.
pub const CHUNK_4K: usize = 4096;

/// Root of a payload.
pub fn payload_root(bytes: &[u8]) -> Hash32 {
    *blake3::hash(bytes).as_bytes()
}

/// Number of 4 KiB leaves in a payload of `size` bytes. The last leaf may be short;
/// an empty payload has no leaves.
pub fn leaf_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_4K as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_b3sum() {
        // b3sum of the empty input.
        let empty = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let hex: String = payload_root(b"").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, empty);
    }

    #[test]
    fn leaf_counts() {
        assert_eq!(leaf_count(0), 0);
        assert_eq!(leaf_count(1), 1);
        assert_eq!(leaf_count(4096), 1);
        assert_eq!(leaf_count(4097), 2);
    }
}
