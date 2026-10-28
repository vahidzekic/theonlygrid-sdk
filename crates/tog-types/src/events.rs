//! Block events (TOG-SPEC-0002 §3.3): changes no signed transaction states, and the outcomes of
//! decrypted inner transactions. Not in the state tree; header `h + 1` commits to block `h`'s
//! events by `events_root`.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Address, Domain, Hash32};

/// What was executing when an event was emitted; Borsh indices 0–4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub enum EventSource {
    /// Index of the item in the block's system lane.
    System(u32),
    /// Index in the compute lane.
    Compute(u32),
    /// Index in the user lane.
    User(u32),
    /// Start-of-block steps (ticks, deadlines, era payouts).
    BlockStart,
    /// Steps after the lanes, including those that close the system lane (AppChain and
    /// coretime end-of-lane work).
    BlockEnd,
}

/// An event; Borsh indices 0, 1.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Event {
    /// An account's balance changed.
    Balance {
        /// The account.
        account: Address,
        /// Signed change of its free balance.
        free_delta: i128,
        /// Signed change of its reserved balance.
        reserved_delta: i128,
        /// One of [`reason`].
        reason: u16,
        /// What caused it: a job_id, a deal id or era as [`subject_of`], or `[0; 32]` when
        /// nothing more specific applies.
        subject: Hash32,
    },
    /// The inner transaction of the `SubmitEncrypted` `outer_tx_id` (two blocks earlier) was
    /// handled while the `ReleasedKeys` item at this source ran (TOG-SPEC-0009 §4.2).
    EncryptedInner {
        /// The `SubmitEncrypted`'s transaction id.
        outer_tx_id: Hash32,
        /// The inner transaction's id; `[0; 32]` when the body didn't decrypt or decode.
        inner_tx_id: Hash32,
        /// Whether it executed; false when it didn't decrypt, decode or succeed.
        executed: bool,
    },
    /// A reservation changed (TOG-SPEC-0015 §6).
    Reservation {
        /// The reservation.
        id: u64,
        /// What happened.
        kind: crate::reservation::ReservationEventKind,
    },
}

/// An event and its source. A `Balance` event is one per `(source, account, reason, subject)`,
/// its deltas summed, in the order each key first changes (TOG-SPEC-0002 §3.3).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EventRecord {
    /// What emitted it.
    pub source: EventSource,
    /// The event.
    pub event: Event,
}

/// `reason` codes of [`Event::Balance`] (TOG-SPEC-0002 §3.3). A new reason needs a spec change.
pub mod reason {
    /// A transfer.
    pub const TRANSFER: u16 = 0;
    /// A fee.
    pub const FEE: u16 = 1;
    /// Issuance or era payout.
    pub const ISSUANCE: u16 = 2;
    /// A slash.
    pub const SLASH: u16 = 3;
    /// A job settlement payment.
    pub const SETTLEMENT: u16 = 4;
    /// A refund.
    pub const REFUND: u16 = 5;
    /// A bond (or deposit) locked.
    pub const BOND_LOCK: u16 = 6;
    /// A bond (or deposit) unlocked.
    pub const BOND_UNLOCK: u16 = 7;
    /// A storage fee or payment.
    pub const STORAGE: u16 = 8;
    /// A penalty (release, non-reveal and the like).
    pub const PENALTY: u16 = 9;
    /// A genesis or faucet mint.
    pub const MINT: u16 = 10;
    /// A burn.
    pub const BURN: u16 = 11;
    /// Other; never used once a specific code fits.
    pub const OTHER: u16 = 65535;
}

/// `subject` of a number (a deal id or an era): its u64_le, padded with zeros.
pub fn subject_of(n: u64) -> Hash32 {
    let mut s = [0; 32];
    s[..8].copy_from_slice(&n.to_le_bytes());
    s
}

/// `hleaf(x) = H("TOG/v1/hdr-leaf" ‖ borsh(x))` (TOG-SPEC-0002 §3.1).
pub fn hleaf(record: &EventRecord) -> Hash32 {
    tagged_hash(Domain::HdrLeaf, &[&borsh::to_vec(record).expect("in-memory borsh cannot fail")])
}

/// `hnode(a, b) = H("TOG/v1/hdr-node" ‖ a ‖ b)`.
pub fn hnode(a: &Hash32, b: &Hash32) -> Hash32 {
    tagged_hash(Domain::HdrNode, &[a, b])
}

/// The next level up: pairs left to right, an unpaired last node moves up unchanged.
fn up(level: &[Hash32]) -> Vec<Hash32> {
    level.chunks(2).map(|c| if let [a, b] = c { hnode(a, b) } else { c[0] }).collect()
}

/// `hroot` over already hashed leaves: `[0; 32]` if there are none.
pub fn hroot_of_leaves(leaves: Vec<Hash32>) -> Hash32 {
    let mut level = leaves;
    if level.is_empty() {
        return [0; 32];
    }
    while level.len() > 1 {
        level = up(&level);
    }
    level[0]
}

/// `events_root`: `hroot` of a block's events in emission order.
pub fn events_root(records: &[EventRecord]) -> Hash32 {
    hroot_of_leaves(records.iter().map(hleaf).collect())
}

/// The `hroot` nodes outside leaves `start..end` that rebuilding the root from them needs, left
/// to right in the order [`root_from_range`] uses them (TOG-SPEC-0006 §2.3.1 `EventsResponse`).
/// Empty if the range is all the leaves; `None` if it is empty or out of bounds.
pub fn range_proof(leaves: &[Hash32], start: usize, end: usize) -> Option<Vec<Hash32>> {
    if start >= end || end > leaves.len() {
        return None;
    }
    let mut proof = vec![];
    let (mut level, mut lo, mut hi) = (leaves.to_vec(), start, end);
    while level.len() > 1 {
        if lo % 2 == 1 {
            proof.push(level[lo - 1]);
        }
        if hi % 2 == 1 && hi < level.len() {
            proof.push(level[hi]);
        }
        level = up(&level);
        (lo, hi) = (lo / 2, hi.div_ceil(2));
    }
    Some(proof)
}

/// The root over `total` leaves rebuilt from `page`, the leaves from `start` on, and `proof`
/// from [`range_proof`]; `None` if they don't fit together.
pub fn root_from_range(page: &[Hash32], start: usize, total: usize, proof: &[Hash32]) -> Option<Hash32> {
    let end = start.checked_add(page.len())?;
    if page.is_empty() || end > total {
        return None;
    }
    let mut proof = proof.iter();
    let (mut known, mut lo, mut hi, mut n) = (page.to_vec(), start, end, total);
    while n > 1 {
        let mut row = vec![];
        if lo % 2 == 1 {
            row.push(*proof.next()?);
        }
        row.extend(known);
        if hi % 2 == 1 && hi < n {
            row.push(*proof.next()?);
        }
        known = up(&row);
        (lo, hi, n) = (lo / 2, hi.div_ceil(2), n.div_ceil(2));
    }
    match (proof.next(), known.as_slice()) {
        (None, [root]) => Some(*root),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(i: u32) -> EventRecord {
        EventRecord {
            source: EventSource::User(i),
            event: Event::EncryptedInner { outer_tx_id: [0; 32], inner_tx_id: [i as u8; 32], executed: true },
        }
    }

    #[test]
    fn every_page_of_every_list_rebuilds_the_root_and_nothing_else_does() {
        assert_eq!(events_root(&[]), [0; 32]);
        let one = record(0);
        assert_eq!(events_root(core::slice::from_ref(&one)), hleaf(&one));
        for total in 1..=13 {
            let leaves: Vec<Hash32> = (0..total).map(|i| hleaf(&record(i))).collect();
            let root = events_root(&(0..total).map(record).collect::<Vec<_>>());
            let total = total as usize;
            assert_eq!(hroot_of_leaves(leaves.clone()), root);
            for start in 0..total {
                for end in start + 1..=total {
                    let proof = range_proof(&leaves, start, end).unwrap();
                    let page = &leaves[start..end];
                    assert_eq!(root_from_range(page, start, total, &proof), Some(root), "{total} {start}..{end}");
                    if start == 0 && end == total {
                        assert!(proof.is_empty());
                    }
                    // A changed leaf, a shifted start or a short or long proof doesn't rebuild it. `total` isn't
                    // bound by the root (3 and 4 leaves share page 0's path), but no wrong total turns a
                    // node into a leaf: hleaf and hnode have their own domains.
                    let mut wrong = page.to_vec();
                    wrong[0][0] ^= 1;
                    assert_ne!(root_from_range(&wrong, start, total, &proof), Some(root));
                    if start > 0 {
                        assert_ne!(root_from_range(page, start - 1, total, &proof), Some(root));
                    }
                    if let Some((_, short)) = proof.split_last() {
                        assert_eq!(root_from_range(page, start, total, short), None);
                    }
                    let mut long = proof.clone();
                    long.push([0; 32]);
                    assert_eq!(root_from_range(page, start, total, &long), None);
                }
            }
        }
        assert_eq!(range_proof(&[[0; 32]], 0, 0), None);
        assert_eq!(root_from_range(&[], 0, 0, &[]), None);
    }

    #[test]
    fn borsh_indices_follow_the_spec() {
        let b = |s: EventSource| borsh::to_vec(&s).unwrap()[0];
        assert_eq!(
            [
                b(EventSource::System(0)),
                b(EventSource::Compute(0)),
                b(EventSource::User(0)),
                b(EventSource::BlockStart),
                b(EventSource::BlockEnd)
            ],
            [0, 1, 2, 3, 4]
        );
        let balance =
            Event::Balance { account: [0; 20], free_delta: 0, reserved_delta: 0, reason: 0, subject: [0; 32] };
        assert_eq!(borsh::to_vec(&balance).unwrap()[0], 0);
        assert_eq!(
            borsh::to_vec(&Event::EncryptedInner { outer_tx_id: [0; 32], inner_tx_id: [0; 32], executed: false })
                .unwrap()[0],
            1
        );
        assert_eq!(subject_of(7)[..9], [7, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
