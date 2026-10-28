//! Domain-separated hashing, `H("TOG/v1/<tag>" ‖ x)` = BLAKE3 in `derive_key` mode with the tag as
//! context (TOG-SPEC-0000 §13.1), the same function as `tog_primitives::tagged_hash`.

use alloc::vec::Vec;

use borsh::BorshSerialize;

use crate::Hash32;

/// `H(tag ‖ parts[0] ‖ parts[1] ‖ …)`, parts concatenated without length prefixes.
pub fn tagged(tag: &str, parts: &[&[u8]]) -> Hash32 {
    let mut h = blake3::Hasher::new_derive_key(tag);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// `H(tag ‖ borsh(v))`.
pub fn tagged_borsh<T: BorshSerialize + ?Sized>(tag: &str, v: &T) -> Hash32 {
    let bytes: Vec<u8> = borsh::to_vec(v).unwrap_or_default();
    tagged(tag, &[&bytes])
}

/// Tag of a lane-tree leaf (TOG-SPEC-0002 §3.1).
pub const TX_LEAF: &str = "TOG/v1/tx-leaf";
/// Tag of a lane-tree inner node (TOG-SPEC-0002 §3.1).
pub const TX_NODE: &str = "TOG/v1/tx-node";
/// Tag of an AppChain head hash (TOG-SPEC-0007 §3.4).
pub const APPCHAIN_HEADER: &str = "TOG/v1/appchain-header";

/// Root over already hashed leaves, in order: pairs left to right, an unpaired last node moves up
/// unchanged; `[0; 32]` with no leaves (`lane_root` of TOG-SPEC-0002 §3.1).
pub fn root_of_leaves(mut level: Vec<Hash32>) -> Hash32 {
    if level.is_empty() {
        return [0; 32];
    }
    while level.len() > 1 {
        level = level.chunks(2).map(|c| if let [a, b] = c { tagged(TX_NODE, &[a, b]) } else { c[0] }).collect();
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tog_primitives::{tagged_hash, Domain};

    #[test]
    fn same_function_as_tog_primitives() {
        assert_eq!(tagged(TX_LEAF, &[b"ab", b"c"]), tagged_hash(Domain::TxLeaf, &[b"abc"]));
        assert_eq!(tagged(TX_NODE, &[&[1; 32], &[2; 32]]), tagged_hash(Domain::TxNode, &[&[1; 32], &[2; 32]]));
    }
}
