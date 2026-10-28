//! AppChain block, head, PoV and validation result (TOG-SPEC-0007 §3.4, exact). All Borsh in field
//! order; enum indices are positions.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use tog_types::cgmp::{CgmpMessage, OutboxChannel};

use crate::hash::{root_of_leaves, tagged, tagged_borsh, APPCHAIN_HEADER, TX_LEAF};
use crate::storage::{StorageKey, StorageValue};
use crate::{Address, BlockNumber, Hash32, HubHeight};

/// Header of an AppChain block.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Header {
    /// Head hash of the parent block; block 1's parent is the genesis head.
    pub parent: Hash32,
    /// Block number.
    pub number: BlockNumber,
    /// JMT root after the block (§5).
    pub state_root: Hash32,
    /// `lane_root` (TOG-SPEC-0002 §3.1) over the block's inherents then extrinsics.
    pub extrinsics_root: Hash32,
    /// The Hub block this block was built on: height and hash.
    pub relay_parent: (HubHeight, Hash32),
    /// CGMP outbox root after the block (TOG-SPEC-0000 §7.2).
    pub outbox_root: Hash32,
    /// Total CGMP messages this chain has processed, after the block.
    pub inbox_processed: u64,
    /// Collator-selection data (e.g. Aura slot and seal); opaque to the Hub.
    pub digest: Vec<u8>,
}

/// `borsh(Header)`, as the Hub stores a chain's pending and final heads.
pub type HeadData = Vec<u8>;

impl Header {
    /// The genesis header (§3.4 "Genesis head", exact): `number = 0`, `state_root` = the root of the
    /// genesis state, every other field zero and `digest` empty. `RegisterAppChain` (§8.1) requires
    /// a chain's `genesis_head` to decode as this.
    pub fn genesis(state_root: Hash32) -> Self {
        Header {
            parent: [0; 32],
            number: 0,
            state_root,
            extrinsics_root: [0; 32],
            relay_parent: (0, [0; 32]),
            outbox_root: [0; 32],
            inbox_processed: 0,
            digest: Vec::new(),
        }
    }

    /// Whether this is a genesis header for its own `state_root`.
    pub fn is_genesis(&self) -> bool {
        *self == Header::genesis(self.state_root)
    }

    /// `borsh(self)`.
    pub fn head_data(&self) -> HeadData {
        borsh::to_vec(self).unwrap_or_default()
    }

    /// The head hash `H("TOG/v1/appchain-header" ‖ HeadData)`.
    pub fn hash(&self) -> Hash32 {
        head_hash(&self.head_data())
    }
}

/// The head hash of encoded head data.
pub fn head_hash(head: &[u8]) -> Hash32 {
    tagged(APPCHAIN_HEADER, &[head])
}

/// An inherent: data the block author puts in the block and the runtime checks.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Inherent {
    /// 0: must equal `header.relay_parent`.
    RelayParent {
        /// Hub height.
        height: HubHeight,
        /// Hub block hash.
        hash: Hash32,
    },
    /// 1: the block author, as `collator_selection` requires.
    Collator {
        /// Its account.
        account: Address,
    },
}

/// A block.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Block {
    /// Header.
    pub header: Header,
    /// Exactly `[RelayParent, Collator]`, in this order (§3.4 "Inherents"); the host rejects any
    /// other count, order or variant before running the block.
    pub inherents: Vec<Inherent>,
    /// SDK-encoded signed transactions.
    pub extrinsics: Vec<Vec<u8>>,
}

/// `extrinsics_root`: leaves `H("TOG/v1/tx-leaf" ‖ borsh(x))` of every inherent, then every
/// extrinsic (each a `Vec<u8>`, so its leaf hashes its length prefix too).
pub fn extrinsics_root(inherents: &[Inherent], extrinsics: &[Vec<u8>]) -> Hash32 {
    let leaves =
        inherents.iter().map(|i| tagged_borsh(TX_LEAF, i)).chain(extrinsics.iter().map(|x| tagged_borsh(TX_LEAF, x)));
    root_of_leaves(leaves.collect())
}

impl Block {
    /// [`extrinsics_root`] of this block's body.
    pub fn extrinsics_root(&self) -> Hash32 {
        extrinsics_root(&self.inherents, &self.extrinsics)
    }
}

/// Hub state read by a block: `(Hub storage key, value, borsh(StateProof))`, proven against the
/// relay parent's state root (TOG-SPEC-0002 §7.1).
pub type HubProof = (Vec<u8>, Option<Vec<u8>>, Vec<u8>);

/// `MinDrain`: a block that leaves more than `max_lag` messages of a channel pending must take at
/// least this many of them (§3.4 "`max_lag`"). The `cgmp` module enforces it; collators fill
/// blocks by it.
pub const MIN_DRAIN: u64 = 64;

/// PoV bytes a block keeps free while some source owes [`MIN_DRAIN`]: an entry is then taken only
/// if its need and this much more fit, so the peek the PoV carries where the block stops (§3.4
/// "max_lag (exact)") stays inside the PoV limit. It holds the largest entry: a `Call` of
/// `MAX_CALL_LEN` or a `ComputeResult` of `MAX_JOB_TX_BYTES` of paths, with a proof over
/// `MAX_BACKLOG` messages.
pub const PEEK_ROOM: u64 = 128 * 1024;

/// An inbox entry: a message and, on the last message of each source in a block, its inbox proof
/// (§3.4 "Inbox proofs"): the `msg_hash` of every later message of the channel up to its
/// `last_nonce` at the relay parent.
pub type InboxEntry = (CgmpMessage, Option<Vec<Hash32>>);

/// `cgmp.outbox`: the chain's outgoing channels, ascending by `dest`, one per destination it has
/// ever sent to; `header.outbox_root` is their [`outbox_root`](tog_types::cgmp::outbox_root). A
/// Hub validator reads it from the witness: each block's pushes must continue these channels
/// (TOG-SPEC-0007 §3.4).
pub const OUTBOX: StorageValue<Vec<OutboxChannel>> = StorageValue::new("cgmp", "outbox");

/// Proof of validity: everything a Hub validator needs to run `validate_block` statelessly.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Pov {
    /// Head of the parent block.
    pub parent_head: HeadData,
    /// The block.
    pub block: Block,
    /// Every state item the block reads or writes.
    pub witness: Witness,
    /// Messages processed by the block, in order; the inbox proof on each source's last one.
    pub inbox: Vec<InboxEntry>,
    /// Hub state the block reads.
    pub hub_proofs: Vec<HubProof>,
}

/// The state a block reads or writes, with its proof.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Witness {
    /// (`storage_key` of §5, value before the block), strictly ascending by key.
    pub entries: Vec<(StorageKey, Option<Vec<u8>>)>,
    /// `borsh(Vec<StateProof>)` (TOG-SPEC-0002 §7.1): one per entry, same order, against the
    /// parent head's `state_root`.
    pub proof: Vec<u8>,
}

/// What `validate_block` returns to the Hub: the shared type of `tog-types` (§3.4), with the
/// block's outbox and inbox commitments.
pub use tog_types::appchain::ValidationResult;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_header_is_zero_but_the_root() {
        let g = Header::genesis([5; 32]);
        assert!(g.is_genesis());
        // 32·4 hash bytes + u64 number + (u64, 32) relay parent + u64 inbox + empty digest (u32 0).
        assert_eq!(g.head_data().len(), 32 * 4 + 8 + 8 + 32 + 8 + 4);
        let mut h = g.clone();
        h.digest = alloc::vec![1];
        assert!(!h.is_genesis());
    }

    fn header() -> Header {
        Header {
            parent: [1; 32],
            number: 2,
            state_root: [3; 32],
            extrinsics_root: [4; 32],
            relay_parent: (5, [6; 32]),
            outbox_root: [7; 32],
            inbox_processed: 8,
            digest: alloc::vec![9],
        }
    }

    #[test]
    fn header_layout_is_field_order() {
        let b = header().head_data();
        assert_eq!(b.len(), 32 + 8 + 32 + 32 + 8 + 32 + 32 + 8 + 4 + 1);
        assert_eq!(&b[..32], &[1; 32]);
        assert_eq!(&b[32..40], &2u64.to_le_bytes());
        assert_eq!(*b.last().unwrap(), 9);
        assert_eq!(header().hash(), head_hash(&b));
        assert_ne!(header().hash(), tagged("TOG/v1/tx-leaf", &[&b]));
    }

    #[test]
    fn inherent_indices() {
        let rp = Inherent::RelayParent { height: 1, hash: [0; 32] };
        assert_eq!(borsh::to_vec(&rp).unwrap()[0], 0);
        assert_eq!(borsh::to_vec(&Inherent::Collator { account: [0; 20] }).unwrap()[0], 1);
    }

    #[test]
    fn extrinsics_root_covers_inherents_then_extrinsics() {
        let i = alloc::vec![Inherent::RelayParent { height: 1, hash: [0; 32] }];
        let x = alloc::vec![alloc::vec![1u8, 2]];
        let want = root_of_leaves(alloc::vec![tagged_borsh(TX_LEAF, &i[0]), tagged_borsh(TX_LEAF, &x[0])]);
        assert_eq!(extrinsics_root(&i, &x), want);
        assert_ne!(extrinsics_root(&i, &[]), want);
        assert_eq!(extrinsics_root(&[], &[]), [0; 32]);
    }

    #[test]
    fn pov_layout_is_field_order() {
        let block = Block { header: header(), inherents: alloc::vec![], extrinsics: alloc::vec![] };
        let witness = Witness { entries: alloc::vec![([2; 96], None)], proof: alloc::vec![3] };
        let pov = Pov {
            parent_head: alloc::vec![1],
            block: block.clone(),
            witness: witness.clone(),
            inbox: alloc::vec![],
            hub_proofs: alloc::vec![(alloc::vec![4], Some(alloc::vec![5]), alloc::vec![6])],
        };
        let b = borsh::to_vec(&pov).unwrap();
        let mut want = borsh::to_vec(&alloc::vec![1u8]).unwrap();
        want.extend(borsh::to_vec(&block).unwrap());
        // Keys are fixed 96-byte arrays: no length prefix.
        want.extend([1, 0, 0, 0]);
        want.extend([2; 96]);
        want.extend([0, 1, 0, 0, 0, 3]);
        want.extend([0, 0, 0, 0]);
        want.extend([1, 0, 0, 0, 1, 0, 0, 0, 4, 1, 1, 0, 0, 0, 5, 1, 0, 0, 0, 6]);
        assert_eq!(b, want);
        assert_eq!(borsh::from_slice::<Pov>(&b).unwrap(), pov);
    }
}
