//! `sudo`: an optional single key with the chain's `Root` origin (TOG-SPEC-0007 §7.5, exact).
//!
//! `sudo.key` is set from the genesis config's `root_key` (`Some` in the SDK templates). Its holder
//! can run any call as `Root` ([`call`]), hand the key on ([`set_key`]) or drop it for good
//! ([`remove_key`]): no call sets a key again, so after that the chain's only `Root` source is
//! `governance`, if it has one. A chain with neither has no `Root` origin, so it can never upgrade
//! its runtime; that is allowed and permanent.

use tog_runtime_core::dispatch::{ensure_signed, DispatchError, DispatchResult, Origin};
use tog_runtime_core::{AccountId, Storage, StorageError, StorageValue};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// `sudo.key`: the account that may act as `Root`, if any.
pub const KEY: StorageValue<AccountId> = StorageValue::new("sudo", "key");

/// Call index of [`call`].
pub const CALL: u8 = 0;
/// Call index of [`set_key`].
pub const SET_KEY: u8 = 1;
/// Call index of [`remove_key`].
pub const REMOVE_KEY: u8 = 2;
/// Most [`call`]s one call may nest (R-1). A runtime weighs a call before any fee or key check,
/// decoding each level, so deeper nesting would let any signed transaction make every node decode
/// it level by level, quadratic in its length and as deep as the stack. The template refuses a
/// deeper call as unknown.
pub const MAX_NESTING: u32 = 4;

/// The module's metadata. Its calls fail only with `BadOrigin`.
pub fn metadata() -> tog_runtime_core::metadata::ModuleMetadata {
    tog_runtime_core::metadata::ModuleMetadata::from_names(
        "sudo",
        &[
            (CALL, "call", &[("call", "InnerCall")]),
            (SET_KEY, "set_key", &[("new", "AccountId")]),
            (REMOVE_KEY, "remove_key", &[]),
        ],
        &["key"],
        &["Sudid"],
        &[],
    )
}

/// The `sudo` module's events.
#[derive(Clone, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum Event {
    /// [`call`] ran its inner call as `Root`, with this result (§7.5: it is in the block's events).
    Sudid(Result<(), crate::system::Failure>),
}

/// A call of the runtime, as in `AppTxBody.call` (§4.5): module index, call index, `borsh(args)`.
pub type InnerCall = (u8, u8, Vec<u8>);

/// Genesis: `sudo.key = root_key`.
pub fn genesis(s: &mut impl Storage, root_key: Option<AccountId>) -> Result<(), StorageError> {
    match root_key {
        Some(k) => KEY.put(s, &k),
        None => {
            KEY.kill(s);
            Ok(())
        }
    }
}

/// The current key.
pub fn key(s: &mut impl Storage) -> Result<Option<AccountId>, StorageError> {
    KEY.get(s)
}

/// `BadOrigin` unless `origin` is signed by the key.
fn ensure_key(s: &mut impl Storage, origin: Origin) -> DispatchResult {
    let who = ensure_signed(origin)?;
    match key(s)? {
        Some(k) if k == who => Ok(()),
        _ => Err(DispatchError::BadOrigin),
    }
}

/// `sudo.call(inner)`: run `inner` as `Root` through `dispatch`. The outer call fails only when the
/// signer isn't the key; `inner`'s result, success or not, is returned for the block's events (its
/// state changes are discarded on failure by `dispatch`, as for any call).
pub fn call<S: Storage>(
    s: &mut S,
    origin: Origin,
    inner: InnerCall,
    dispatch: impl FnOnce(&mut S, Origin, InnerCall) -> DispatchResult,
) -> Result<DispatchResult, DispatchError> {
    ensure_key(s, origin)?;
    Ok(dispatch(s, Origin::Root, inner))
}

/// `sudo.set_key(new)`: replace the key.
pub fn set_key(s: &mut impl Storage, origin: Origin, new: AccountId) -> DispatchResult {
    ensure_key(s, origin)?;
    Ok(KEY.put(s, &new)?)
}

/// `sudo.remove_key()`: drop the key, irreversibly.
pub fn remove_key(s: &mut impl Storage, origin: Origin) -> DispatchResult {
    ensure_key(s, origin)?;
    KEY.kill(s);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tog_runtime_core::memory::MemoryStorage;

    const ROOT: AccountId = [1; 20];
    const OTHER: AccountId = [2; 20];

    fn run_as_root(_: &mut MemoryStorage, o: Origin, inner: InnerCall) -> DispatchResult {
        assert_eq!(o, Origin::Root);
        if inner.0 == 0 {
            Ok(())
        } else {
            Err(DispatchError::Other("inner failed"))
        }
    }

    #[test]
    fn only_the_key_runs_calls_as_root_and_inner_failures_are_results() {
        let mut s = MemoryStorage::default();
        genesis(&mut s, Some(ROOT)).unwrap();
        assert_eq!(call(&mut s, Origin::Signed(ROOT), (0, 0, vec![]), run_as_root), Ok(Ok(())));
        assert_eq!(
            call(&mut s, Origin::Signed(ROOT), (1, 0, vec![]), run_as_root),
            Ok(Err(DispatchError::Other("inner failed")))
        );
        assert_eq!(call(&mut s, Origin::Signed(OTHER), (0, 0, vec![]), run_as_root), Err(DispatchError::BadOrigin));
        assert_eq!(call(&mut s, Origin::Root, (0, 0, vec![]), run_as_root), Err(DispatchError::BadOrigin));
    }

    #[test]
    fn the_key_moves_and_once_removed_is_gone_for_good() {
        let mut s = MemoryStorage::default();
        genesis(&mut s, Some(ROOT)).unwrap();
        assert_eq!(set_key(&mut s, Origin::Signed(OTHER), OTHER), Err(DispatchError::BadOrigin));
        set_key(&mut s, Origin::Signed(ROOT), OTHER).unwrap();
        assert_eq!(key(&mut s).unwrap(), Some(OTHER));
        assert_eq!(remove_key(&mut s, Origin::Signed(ROOT)), Err(DispatchError::BadOrigin));
        remove_key(&mut s, Origin::Signed(OTHER)).unwrap();
        assert_eq!(key(&mut s).unwrap(), None);
        for who in [ROOT, OTHER] {
            assert_eq!(set_key(&mut s, Origin::Signed(who), who), Err(DispatchError::BadOrigin));
            assert_eq!(call(&mut s, Origin::Signed(who), (0, 0, vec![]), run_as_root), Err(DispatchError::BadOrigin));
        }
    }

    #[test]
    fn a_chain_may_start_without_a_key() {
        let mut s = MemoryStorage::default();
        genesis(&mut s, None).unwrap();
        assert_eq!(key(&mut s).unwrap(), None);
    }
}
