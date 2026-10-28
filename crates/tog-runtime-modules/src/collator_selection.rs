//! `collator_selection`: which collator may author a block (TOG-SPEC-0007 §7, §8.5, §9).
//!
//! This is `Aura` (§7.4): a fixed set of authorities, set at genesis and changed by the chain's
//! governance, taking turns by Hub height. The block built on relay parent height `h` is authored
//! by `authorities[h mod n]`, named by the block's `Inherent::Collator`; `h` must be above the
//! parent's, so each slot is used at most once, and the header's `digest` is empty (no seal: backers
//! authenticate the author by its Hub `CollatorRecord`). A collator asks [`slot_author`] whether a
//! Hub height is its turn; the runtime checks the block with [`check_author`] before anything else
//! runs, so a new set applies from the next block.
//!
//! An authority without a Hub `CollatorRecord` just leaves its slots empty (§8.5). `Staked` and
//! `PouwWeighted` are v2 and not specified (0007 §7).

use alloc::vec::Vec;
use tog_runtime_core::block::Inherent;
use tog_runtime_core::{AccountId, HubHeight, Origin, Storage, StorageError, StorageValue};

/// `MaxAuthorities`: the Hub's `MaxCollators` per chain (§8.5).
pub const MAX_AUTHORITIES: usize = 64;

/// Call index of [`set_authorities`].
pub const SET_AUTHORITIES: u8 = 0;

/// The module's metadata. Errors: 0 `BadOrigin` (`DispatchError::BadOrigin`), 1
/// [`SetError::Size`], 2 [`SetError::Unsorted`].
pub fn metadata() -> tog_runtime_core::metadata::ModuleMetadata {
    tog_runtime_core::metadata::ModuleMetadata::from_names(
        "collator_selection",
        &[(SET_AUTHORITIES, "set_authorities", &[("authorities", "Vec<AccountId>")])],
        &["authorities"],
        &[],
        &["BadOrigin", "Size", "Unsorted"],
    )
}

/// `collator_selection.authorities`: the Aura set, ascending, without duplicates.
pub const AUTHORITIES: StorageValue<Vec<AccountId>> = StorageValue::new("collator_selection", "authorities");

/// Why a set was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetError {
    /// Only the chain's governance (`Root`) may change the set.
    BadOrigin,
    /// The set is empty or has more than [`MAX_AUTHORITIES`].
    Size,
    /// The set isn't strictly ascending.
    Unsorted,
    /// Stored state doesn't decode.
    Storage,
}

impl From<StorageError> for SetError {
    fn from(_: StorageError) -> Self {
        SetError::Storage
    }
}

/// Why a block's author was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorError {
    /// The chain has no authorities.
    NoAuthorities,
    /// The block has no `Collator` inherent, or more than one.
    Inherent,
    /// The relay parent height isn't above the parent block's: the slot was used.
    SlotUsed,
    /// The header's digest isn't empty.
    Digest,
    /// The named author isn't the one whose turn it is.
    NotItsTurn {
        /// The authority for the relay parent height.
        expected: AccountId,
        /// The author the block names.
        got: AccountId,
    },
    /// Stored state doesn't decode.
    Storage,
}

impl From<StorageError> for AuthorError {
    fn from(_: StorageError) -> Self {
        AuthorError::Storage
    }
}

/// The genesis set.
pub fn genesis(s: &mut impl Storage, authorities: Vec<AccountId>) -> Result<(), SetError> {
    set_authorities(s, &Origin::Root, authorities)
}

/// `collator_selection::set_authorities(authorities)`: replace the set from the next block.
pub fn set_authorities(s: &mut impl Storage, origin: &Origin, authorities: Vec<AccountId>) -> Result<(), SetError> {
    if *origin != Origin::Root {
        return Err(SetError::BadOrigin);
    }
    if authorities.is_empty() || authorities.len() > MAX_AUTHORITIES {
        return Err(SetError::Size);
    }
    if authorities.windows(2).any(|w| w[0] >= w[1]) {
        return Err(SetError::Unsorted);
    }
    AUTHORITIES.put(s, &authorities)?;
    Ok(())
}

/// The current set (empty before genesis sets one).
pub fn authorities(s: &mut impl Storage) -> Result<Vec<AccountId>, StorageError> {
    AUTHORITIES.get_or_default(s)
}

/// The authority whose turn it is for a block on relay parent height `h`; `None` without a set.
pub fn slot_author(s: &mut impl Storage, h: HubHeight) -> Result<Option<AccountId>, StorageError> {
    let set = authorities(s)?;
    if set.is_empty() {
        return Ok(None);
    }
    Ok(Some(set[(h % set.len() as u64) as usize]))
}

/// Check a block on relay parent height `h` whose parent was built on `parent_h` (0 for the genesis
/// head): `h > parent_h`, an empty `digest`, and exactly one `Collator` inherent naming the
/// authority whose turn it is; returns that author.
pub fn check_author(
    s: &mut impl Storage,
    h: HubHeight,
    parent_h: HubHeight,
    digest: &[u8],
    inherents: &[Inherent],
) -> Result<AccountId, AuthorError> {
    if h <= parent_h {
        return Err(AuthorError::SlotUsed);
    }
    if !digest.is_empty() {
        return Err(AuthorError::Digest);
    }
    let mut named = inherents.iter().filter_map(|i| match i {
        Inherent::Collator { account } => Some(*account),
        _ => None,
    });
    let (Some(got), None) = (named.next(), named.next()) else {
        return Err(AuthorError::Inherent);
    };
    let expected = slot_author(s, h)?.ok_or(AuthorError::NoAuthorities)?;
    if got != expected {
        return Err(AuthorError::NotItsTurn { expected, got });
    }
    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use tog_runtime_core::memory::MemoryStorage;

    const A: AccountId = [1; 20];
    const B: AccountId = [2; 20];
    const C: AccountId = [3; 20];

    fn author(a: AccountId) -> Inherent {
        Inherent::Collator { account: a }
    }

    #[test]
    fn authorities_take_turns_by_hub_height() {
        let mut s = MemoryStorage::default();
        assert_eq!(slot_author(&mut s, 7).unwrap(), None);
        assert_eq!(check_author(&mut s, 7, 0, &[], &[author(A)]), Err(AuthorError::NoAuthorities));

        genesis(&mut s, vec![A, B, C]).unwrap();
        let turns: Vec<_> = (9..13).map(|h| slot_author(&mut s, h).unwrap().unwrap()).collect();
        assert_eq!(turns, [A, B, C, A]);

        let relay = Inherent::RelayParent { height: 10, hash: [0; 32] };
        assert_eq!(check_author(&mut s, 10, 9, &[], &[relay.clone(), author(B)]), Ok(B));
        assert_eq!(
            check_author(&mut s, 10, 9, &[], &[relay.clone(), author(A)]),
            Err(AuthorError::NotItsTurn { expected: B, got: A })
        );
        assert_eq!(check_author(&mut s, 10, 9, &[], core::slice::from_ref(&relay)), Err(AuthorError::Inherent));
        assert_eq!(
            check_author(&mut s, 10, 9, &[], &[relay.clone(), author(B), author(B)]),
            Err(AuthorError::Inherent)
        );
        assert_eq!(check_author(&mut s, 10, 10, &[], &[relay.clone(), author(B)]), Err(AuthorError::SlotUsed));
        assert_eq!(check_author(&mut s, 10, 9, &[0], &[relay, author(B)]), Err(AuthorError::Digest));
        assert_eq!(check_author(&mut s, 1, 0, &[], &[author(B)]), Ok(B), "block 1 on Hub height 1");
        assert_eq!(check_author(&mut s, 0, 0, &[], &[author(A)]), Err(AuthorError::SlotUsed));
    }

    #[test]
    fn only_governance_sets_a_bounded_ascending_set() {
        let mut s = MemoryStorage::default();
        genesis(&mut s, vec![A, B]).unwrap();
        assert_eq!(set_authorities(&mut s, &Origin::Signed(A), vec![C]), Err(SetError::BadOrigin));
        assert_eq!(set_authorities(&mut s, &Origin::Root, vec![]), Err(SetError::Size));
        let many: Vec<AccountId> = (0..=MAX_AUTHORITIES as u8).map(|i| [i; 20]).collect();
        assert_eq!(set_authorities(&mut s, &Origin::Root, many), Err(SetError::Size));
        assert_eq!(set_authorities(&mut s, &Origin::Root, vec![B, A]), Err(SetError::Unsorted));
        assert_eq!(set_authorities(&mut s, &Origin::Root, vec![A, A]), Err(SetError::Unsorted));
        assert_eq!(authorities(&mut s).unwrap(), [A, B], "refused sets change nothing");

        set_authorities(&mut s, &Origin::Root, vec![C]).unwrap();
        assert_eq!(slot_author(&mut s, 10).unwrap(), Some(C));
    }
}
