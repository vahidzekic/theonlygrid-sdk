//! `governance`: an optional council with the chain's `Root` origin (TOG-SPEC-0007 §7, §7.5).
//!
//! A council of at most [`MAX_MEMBERS`] accounts, from the genesis config or set by `Root`. A member
//! proposes a call ([`propose`]); members vote aye or nay ([`vote`]); anyone closes the motion
//! ([`close`]), which runs the call as `Root` once more than two thirds of the members voted aye,
//! and drops it once that can no longer happen or the motion is past its end. Setting the members
//! drops every open motion, since their votes were counted against the old council.
//!
//! It is the `Root` source a chain hands control to before `sudo.remove_key()` (§7.5): the council
//! then authorizes runtime upgrades and sets its own members. Token-weighted referenda are not part
//! of this module.
//!
//! [`close`] takes the call again, and refuses one that isn't the motion's: the runtime prices a
//! `close` from its arguments (`CLOSE` plus the inner call's weight, as for `sudo.call`), so the
//! call's weight is known before it runs.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use tog_runtime_core::dispatch::{ensure_signed, DispatchError, DispatchResult, Origin};
use tog_runtime_core::BlockNumber;
use tog_runtime_core::{AccountId, Storage, StorageError, StorageMap, StorageValue};

use crate::sudo::InnerCall;
use crate::system::Failure;

/// Most council members.
pub const MAX_MEMBERS: usize = 16;
/// Most motions open at once.
pub const MAX_MOTIONS: usize = 16;
/// Blocks a motion stays open: about a day at 6-second blocks.
pub const MOTION_BLOCKS: BlockNumber = 14_400;

/// `governance.members`: the council, strictly ascending.
pub const MEMBERS: StorageValue<Vec<AccountId>> = StorageValue::new("governance", "members");
/// `governance.motions`: each open motion by id.
pub const MOTIONS: StorageMap<u32, Motion> = StorageMap::new("governance", "motions");
/// `governance.open`: the ids of the open motions, ascending.
pub const OPEN: StorageValue<Vec<u32>> = StorageValue::new("governance", "open");
/// `governance.next_motion`: the next motion's id.
pub const NEXT_MOTION: StorageValue<u32> = StorageValue::new("governance", "next_motion");

/// Call index of [`set_members`].
pub const SET_MEMBERS: u8 = 0;
/// Call index of [`propose`].
pub const PROPOSE: u8 = 1;
/// Call index of [`vote`].
pub const VOTE: u8 = 2;
/// Call index of [`close`].
pub const CLOSE: u8 = 3;

/// An open motion.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Motion {
    /// The member who proposed it.
    pub proposer: AccountId,
    /// The call it runs as `Root`.
    pub call: InnerCall,
    /// Members who voted aye, ascending.
    pub ayes: Vec<AccountId>,
    /// Members who voted nay, ascending.
    pub nays: Vec<AccountId>,
    /// The last block it may pass in.
    pub end: BlockNumber,
}

/// The module's events, `borsh` in the block's events under module `"governance"`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Event {
    /// The council is now `members`; every open motion was dropped.
    MembersSet {
        /// The new council.
        members: Vec<AccountId>,
    },
    /// Motion `id` was proposed, with the proposer's aye.
    Proposed {
        /// The motion.
        id: u32,
        /// Its proposer.
        proposer: AccountId,
    },
    /// `who` voted on motion `id`, replacing any earlier vote.
    Voted {
        /// The motion.
        id: u32,
        /// The member.
        who: AccountId,
        /// Aye or nay.
        aye: bool,
    },
    /// Motion `id` passed and its call ran as `Root`, with this result.
    Executed {
        /// The motion.
        id: u32,
        /// The call's result; its changes are discarded on failure.
        result: Result<(), Failure>,
    },
    /// Motion `id` can no longer pass, or ended, and was dropped.
    Rejected {
        /// The motion.
        id: u32,
    },
}

/// Why a call failed; [`Error::into_dispatch`] numbers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The origin may not make this call.
    BadOrigin,
    /// Only a council member may propose or vote.
    NotMember,
    /// No open motion has the id.
    UnknownMotion,
    /// [`MAX_MOTIONS`] are open.
    TooManyMotions,
    /// The council must be 1 to [`MAX_MEMBERS`] accounts, strictly ascending.
    BadMembers,
    /// The motion has neither passed nor become impossible, and hasn't ended.
    Undecided,
    /// `close` named another call than the motion's.
    WrongCall,
    /// Stored state doesn't decode.
    Storage(StorageError),
}

impl From<StorageError> for Error {
    fn from(e: StorageError) -> Self {
        Error::Storage(e)
    }
}

impl Error {
    /// The `DispatchError` for this module at index `module` in the runtime: `Module` errors 0
    /// [`Error::NotMember`] to 5 [`Error::WrongCall`], in declaration order.
    pub fn into_dispatch(self, module: u8) -> DispatchError {
        let error = match self {
            Error::BadOrigin => return DispatchError::BadOrigin,
            Error::Storage(e) => return DispatchError::Storage(e),
            Error::NotMember => 0,
            Error::UnknownMotion => 1,
            Error::TooManyMotions => 2,
            Error::BadMembers => 3,
            Error::Undecided => 4,
            Error::WrongCall => 5,
        };
        DispatchError::Module { module, error }
    }
}

/// The module's metadata; its errors as [`Error::into_dispatch`] numbers them.
pub fn metadata() -> tog_runtime_core::metadata::ModuleMetadata {
    tog_runtime_core::metadata::ModuleMetadata::from_names(
        "governance",
        &[
            (SET_MEMBERS, "set_members", &[("members", "Vec<AccountId>")]),
            (PROPOSE, "propose", &[("call", "InnerCall")]),
            (VOTE, "vote", &[("id", "u32"), ("aye", "bool")]),
            (CLOSE, "close", &[("id", "u32"), ("call", "InnerCall")]),
        ],
        &["members", "motions", "open", "next_motion"],
        &["MembersSet", "Proposed", "Voted", "Executed", "Rejected"],
        &["NotMember", "UnknownMotion", "TooManyMotions", "BadMembers", "Undecided", "WrongCall"],
    )
}

fn check_members(members: &[AccountId]) -> Result<(), Error> {
    let ascending = members.windows(2).all(|w| w[0] < w[1]);
    if members.is_empty() || members.len() > MAX_MEMBERS || !ascending {
        return Err(Error::BadMembers);
    }
    Ok(())
}

/// Genesis: the council, if the chain starts with one; an empty list starts it without.
pub fn genesis(s: &mut impl Storage, members: Vec<AccountId>) -> Result<(), Error> {
    if members.is_empty() {
        return Ok(());
    }
    check_members(&members)?;
    Ok(MEMBERS.put(s, &members)?)
}

/// The council.
pub fn members(s: &mut impl Storage) -> Result<Vec<AccountId>, StorageError> {
    MEMBERS.get_or_default(s)
}

/// Open motion `id`, if any.
pub fn motion(s: &mut impl Storage, id: u32) -> Result<Option<Motion>, StorageError> {
    MOTIONS.get(s, &id)
}

fn ensure_member(s: &mut impl Storage, origin: Origin) -> Result<AccountId, Error> {
    let who = ensure_signed(origin).map_err(|_| Error::BadOrigin)?;
    if members(s)?.binary_search(&who).is_err() {
        return Err(Error::NotMember);
    }
    Ok(who)
}

fn drop_motion(s: &mut impl Storage, id: u32) -> Result<(), Error> {
    MOTIONS.remove(s, &id);
    let mut open = OPEN.get_or_default(s)?;
    open.retain(|m| *m != id);
    Ok(OPEN.put(s, &open)?)
}

/// `set_members(members)`, by `Root`: the new council; every open motion is dropped.
pub fn set_members(s: &mut impl Storage, origin: &Origin, members: Vec<AccountId>) -> Result<Event, Error> {
    if *origin != Origin::Root {
        return Err(Error::BadOrigin);
    }
    check_members(&members)?;
    for id in OPEN.get_or_default(s)? {
        MOTIONS.remove(s, &id);
    }
    OPEN.kill(s);
    MEMBERS.put(s, &members)?;
    Ok(Event::MembersSet { members })
}

/// `propose(call)`, by a member at block `now`: a new motion with the proposer's aye, open until
/// `now + MOTION_BLOCKS`.
pub fn propose(s: &mut impl Storage, origin: Origin, now: BlockNumber, call: InnerCall) -> Result<Event, Error> {
    let proposer = ensure_member(s, origin)?;
    let mut open = OPEN.get_or_default(s)?;
    if open.len() >= MAX_MOTIONS {
        return Err(Error::TooManyMotions);
    }
    let id = NEXT_MOTION.get_or_default(s)?;
    let end = now.saturating_add(MOTION_BLOCKS);
    MOTIONS.insert(s, &id, &Motion { proposer, call, ayes: alloc::vec![proposer], nays: Vec::new(), end })?;
    open.push(id);
    OPEN.put(s, &open)?;
    NEXT_MOTION.put(s, &id.wrapping_add(1))?;
    Ok(Event::Proposed { id, proposer })
}

/// `vote(id, aye)`, by a member: replaces the member's earlier vote on the motion.
pub fn vote(s: &mut impl Storage, origin: Origin, id: u32, aye: bool) -> Result<Event, Error> {
    let who = ensure_member(s, origin)?;
    let mut m = MOTIONS.get(s, &id)?.ok_or(Error::UnknownMotion)?;
    m.ayes.retain(|a| *a != who);
    m.nays.retain(|a| *a != who);
    let side = if aye { &mut m.ayes } else { &mut m.nays };
    let at = side.binary_search(&who).unwrap_err();
    side.insert(at, who);
    MOTIONS.insert(s, &id, &m)?;
    Ok(Event::Voted { id, who, aye })
}

/// Whether `ayes` of `members` is more than two thirds.
fn passes(ayes: usize, members: usize) -> bool {
    ayes * 3 > members * 2
}

/// `close(id, call)`, by anyone signed at block `now`: runs the motion's call as `Root` through
/// `dispatch` once it has passed, drops it once it can't or has ended, and fails otherwise. `call`
/// must be the motion's. The result of a run call, success or not, is in [`Event::Executed`].
pub fn close<S: Storage>(
    s: &mut S,
    origin: Origin,
    now: BlockNumber,
    id: u32,
    call: InnerCall,
    dispatch: impl FnOnce(&mut S, Origin, InnerCall) -> DispatchResult,
) -> Result<Event, Error> {
    ensure_signed(origin).map_err(|_| Error::BadOrigin)?;
    let m = MOTIONS.get(s, &id)?.ok_or(Error::UnknownMotion)?;
    if m.call != call {
        return Err(Error::WrongCall);
    }
    let council = members(s)?.len();
    if passes(m.ayes.len(), council) && now <= m.end {
        drop_motion(s, id)?;
        let result = dispatch(s, Origin::Root, call).map_err(Failure::from);
        return Ok(Event::Executed { id, result });
    }
    let possible = passes(council.saturating_sub(m.nays.len()), council);
    if !possible || now > m.end {
        drop_motion(s, id)?;
        return Ok(Event::Rejected { id });
    }
    Err(Error::Undecided)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tog_runtime_core::memory::MemoryStorage;

    const A: AccountId = [1; 20];
    const B: AccountId = [2; 20];
    const C: AccountId = [3; 20];
    const D: AccountId = [4; 20];
    const UPGRADE: InnerCall = (2, 0, Vec::new());

    fn council() -> MemoryStorage {
        let mut s = MemoryStorage::default();
        genesis(&mut s, vec![A, B, C, D]).unwrap();
        s
    }

    fn run(_: &mut MemoryStorage, o: Origin, call: InnerCall) -> DispatchResult {
        assert_eq!((o, call), (Origin::Root, UPGRADE));
        Ok(())
    }

    fn never(_: &mut MemoryStorage, _: Origin, _: InnerCall) -> DispatchResult {
        panic!("ran a call that didn't pass")
    }

    #[test]
    fn more_than_two_thirds_of_the_council_run_a_call_as_root() {
        let mut s = council();
        assert_eq!(propose(&mut s, Origin::Signed(A), 10, UPGRADE), Ok(Event::Proposed { id: 0, proposer: A }));
        vote(&mut s, Origin::Signed(B), 0, true).unwrap();
        // 2 of 4 isn't enough, 3 of 4 is.
        assert_eq!(close(&mut s, Origin::Signed(D), 11, 0, UPGRADE, never), Err(Error::Undecided));
        vote(&mut s, Origin::Signed(C), 0, true).unwrap();
        assert_eq!(close(&mut s, Origin::Signed(D), 11, 0, (2, 0, vec![1]), never), Err(Error::WrongCall));
        assert_eq!(
            close(&mut s, Origin::Signed(D), 11, 0, UPGRADE, run),
            Ok(Event::Executed { id: 0, result: Ok(()) })
        );
        assert_eq!(motion(&mut s, 0).unwrap(), None);
        assert!(OPEN.get_or_default(&mut s).unwrap().is_empty());
        assert_eq!(close(&mut s, Origin::Signed(D), 11, 0, UPGRADE, never), Err(Error::UnknownMotion));
    }

    #[test]
    fn a_failed_call_is_the_motions_result() {
        let mut s = MemoryStorage::default();
        genesis(&mut s, vec![A]).unwrap();
        propose(&mut s, Origin::Signed(A), 1, UPGRADE).unwrap();
        let fail = |_: &mut MemoryStorage, _: Origin, _: InnerCall| Err(DispatchError::Module { module: 2, error: 1 });
        let closed = close(&mut s, Origin::Signed(B), 1, 0, UPGRADE, fail).unwrap();
        assert_eq!(closed, Event::Executed { id: 0, result: Err(Failure::Module { module: 2, error: 1 }) });
    }

    #[test]
    fn a_motion_that_cannot_pass_or_has_ended_is_dropped() {
        let mut s = council();
        propose(&mut s, Origin::Signed(A), 10, UPGRADE).unwrap();
        // Two nays of four leave at most two ayes.
        vote(&mut s, Origin::Signed(B), 0, false).unwrap();
        assert_eq!(close(&mut s, Origin::Signed(A), 11, 0, UPGRADE, never), Err(Error::Undecided));
        vote(&mut s, Origin::Signed(C), 0, false).unwrap();
        assert_eq!(close(&mut s, Origin::Signed(A), 11, 0, UPGRADE, never), Ok(Event::Rejected { id: 0 }));

        propose(&mut s, Origin::Signed(A), 10, UPGRADE).unwrap();
        for who in [B, C] {
            vote(&mut s, Origin::Signed(who), 1, true).unwrap();
        }
        let late = 10 + MOTION_BLOCKS + 1;
        assert_eq!(close(&mut s, Origin::Signed(A), late, 1, UPGRADE, never), Ok(Event::Rejected { id: 1 }));
    }

    #[test]
    fn votes_change_and_only_members_vote() {
        let mut s = council();
        propose(&mut s, Origin::Signed(A), 1, UPGRADE).unwrap();
        vote(&mut s, Origin::Signed(B), 0, false).unwrap();
        vote(&mut s, Origin::Signed(B), 0, true).unwrap();
        let m = motion(&mut s, 0).unwrap().unwrap();
        assert_eq!((m.ayes, m.nays), (vec![A, B], vec![]));
        let outsider = Origin::Signed([9; 20]);
        assert_eq!(vote(&mut s, outsider, 0, true), Err(Error::NotMember));
        assert_eq!(propose(&mut s, outsider, 1, UPGRADE), Err(Error::NotMember));
        assert_eq!(propose(&mut s, Origin::Root, 1, UPGRADE), Err(Error::BadOrigin));
        assert_eq!(vote(&mut s, Origin::Signed(A), 7, true), Err(Error::UnknownMotion));
    }

    #[test]
    fn root_sets_the_council_and_drops_open_motions() {
        let mut s = council();
        for _ in 0..MAX_MOTIONS {
            propose(&mut s, Origin::Signed(A), 1, UPGRADE).unwrap();
        }
        assert_eq!(propose(&mut s, Origin::Signed(A), 1, UPGRADE), Err(Error::TooManyMotions));
        assert_eq!(set_members(&mut s, &Origin::Signed(A), vec![B]), Err(Error::BadOrigin));
        for bad in [vec![], vec![B, A], vec![A, A], (0..=MAX_MEMBERS as u8).map(|i| [i; 20]).collect()] {
            assert_eq!(set_members(&mut s, &Origin::Root, bad), Err(Error::BadMembers));
        }
        assert_eq!(set_members(&mut s, &Origin::Root, vec![B, C]), Ok(Event::MembersSet { members: vec![B, C] }));
        assert_eq!(motion(&mut s, 0).unwrap(), None);
        assert!(OPEN.get_or_default(&mut s).unwrap().is_empty());
        assert_eq!(propose(&mut s, Origin::Signed(A), 1, UPGRADE), Err(Error::NotMember));
        assert_eq!(propose(&mut s, Origin::Signed(B), 1, UPGRADE), Ok(Event::Proposed { id: 16, proposer: B }));
    }

    #[test]
    fn a_chain_may_start_without_a_council() {
        let mut s = MemoryStorage::default();
        genesis(&mut s, vec![]).unwrap();
        assert!(members(&mut s).unwrap().is_empty());
        assert_eq!(propose(&mut s, Origin::Signed(A), 1, UPGRADE), Err(Error::NotMember));
        assert_eq!(genesis(&mut s, vec![B, A]), Err(Error::BadMembers));
    }

    #[derive(Clone, Debug)]
    enum Step {
        Propose(u8),
        Vote(u8, u32, bool),
        Close(u8, u32),
        SetMembers(Vec<u8>),
        Wait(BlockNumber),
    }

    fn step() -> impl proptest::strategy::Strategy<Value = Step> {
        use proptest::prelude::*;
        prop_oneof![
            (0..6u8).prop_map(Step::Propose),
            (0..6u8, 0..24u32, any::<bool>()).prop_map(|(w, id, aye)| Step::Vote(w, id, aye)),
            (0..6u8, 0..24u32).prop_map(|(w, id)| Step::Close(w, id)),
            proptest::collection::vec(0..6u8, 0..5).prop_map(Step::SetMembers),
            (0..MOTION_BLOCKS).prop_map(Step::Wait),
        ]
    }

    proptest::proptest! {
        /// Whatever members, motions and votes happen, the open list is exactly the stored motions,
        /// at most `MAX_MOTIONS`; votes come only from current members, on one side each; and a
        /// call runs as `Root` only from a motion with more than two thirds of the council's ayes.
        #[test]
        fn the_council_keeps_its_invariants(steps in proptest::collection::vec(step(), 1..120)) {
            let who = |w: u8| [w + 1; 20];
            let mut s = MemoryStorage::default();
            genesis(&mut s, vec![who(0), who(1), who(2)]).unwrap();
            let mut now: BlockNumber = 1;
            for st in steps {
                match st {
                    Step::Propose(w) => {
                        let _ = propose(&mut s, Origin::Signed(who(w)), now, UPGRADE);
                    }
                    Step::Vote(w, id, aye) => {
                        let _ = vote(&mut s, Origin::Signed(who(w)), id, aye);
                    }
                    Step::Close(w, id) => {
                        let before = motion(&mut s, id).unwrap();
                        let council = members(&mut s).unwrap().len();
                        let mut ran = false;
                        let r = close(&mut s, Origin::Signed(who(w)), now, id, UPGRADE, |_, o, _| {
                            ran = o == Origin::Root;
                            Ok(())
                        });
                        if ran {
                            let m = before.expect("only an open motion runs");
                            proptest::prop_assert!(passes(m.ayes.len(), council) && now <= m.end);
                            proptest::prop_assert_eq!(r, Ok(Event::Executed { id, result: Ok(()) }));
                        }
                    }
                    Step::SetMembers(ws) => {
                        let mut list: Vec<AccountId> = ws.into_iter().map(who).collect();
                        list.sort();
                        list.dedup();
                        let _ = set_members(&mut s, &Origin::Root, list);
                    }
                    Step::Wait(n) => now += n,
                }
                let open = OPEN.get_or_default(&mut s).unwrap();
                proptest::prop_assert!(open.len() <= MAX_MOTIONS);
                proptest::prop_assert!(open.windows(2).all(|w| w[0] < w[1]));
                let council = members(&mut s).unwrap();
                for id in &open {
                    let m = motion(&mut s, *id).unwrap().expect("an open id has its motion");
                    for v in m.ayes.iter().chain(&m.nays) {
                        proptest::prop_assert!(council.binary_search(v).is_ok(), "a vote from a non-member");
                    }
                    proptest::prop_assert!(m.ayes.iter().all(|a| !m.nays.contains(a)));
                }
                for id in 0..NEXT_MOTION.get_or_default(&mut s).unwrap() {
                    proptest::prop_assert_eq!(motion(&mut s, id).unwrap().is_some(), open.contains(&id));
                }
            }
        }
    }
}
