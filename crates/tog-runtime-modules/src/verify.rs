//! `verify`: the chain's verification modules (TOG-SPEC-0007 §7.2).
//!
//! The Hub is the authority: the chain's manager binds a blob with `SetVerificationModule` (Hub
//! TxBody 55). This module only mirrors the list `id → code_hash` under `Root`, for the chain's own
//! tools, with the Hub's rules: at most 16 ids, ascending, and write-once. A new version is a new
//! id; a bound id is never rebound or removed.
//!
//! A module's code is a separate import-free blob built with
//! `tog_runtime_core::verification::VerificationModule` and `tog_runtime_io::export_verification!`.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_runtime_core::dispatch::DispatchError;
use tog_runtime_core::env::Env;
use tog_runtime_core::{Hash32, Origin, Storage, StorageError, StorageValue};
use tog_types::job::VerificationModuleId;

use crate::executive::Scoped;

/// The Hub's limit of modules per chain.
pub const MAX_MODULES: usize = 16;

/// `verify.modules`: `(id, code_hash)`, ascending by id.
pub const MODULES: StorageValue<Vec<(VerificationModuleId, Hash32)>> = StorageValue::new("verify", "modules");

/// Why a binding was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Only the chain's governance (`Root`) may bind.
    BadOrigin,
    /// The id is already bound (write-once).
    AlreadyBound,
    /// The chain already has [`MAX_MODULES`].
    TooMany,
    /// Stored state doesn't decode.
    Storage,
}

impl From<StorageError> for Error {
    fn from(_: StorageError) -> Self {
        Error::Storage
    }
}

/// `verify::bind(id, code_hash)`: record a binding the manager made on the Hub.
pub fn bind(s: &mut impl Storage, origin: &Origin, id: VerificationModuleId, code_hash: Hash32) -> Result<(), Error> {
    if *origin != Origin::Root {
        return Err(Error::BadOrigin);
    }
    let mut list = modules(s)?;
    let i = match list.binary_search_by(|(x, _)| x.0.cmp(&id.0)) {
        Ok(_) => return Err(Error::AlreadyBound),
        Err(i) => i,
    };
    if list.len() >= MAX_MODULES {
        return Err(Error::TooMany);
    }
    list.insert(i, (id, code_hash));
    MODULES.put(s, &list)?;
    Ok(())
}

/// The bound modules, ascending by id.
pub fn modules(s: &mut impl Storage) -> Result<Vec<(VerificationModuleId, Hash32)>, StorageError> {
    MODULES.get_or_default(s)
}

/// The code bound to `id`, if any.
pub fn code_of(s: &mut impl Storage, id: &VerificationModuleId) -> Result<Option<Hash32>, StorageError> {
    Ok(modules(s)?.into_iter().find(|(x, _)| x == id).map(|(_, h)| h))
}

/// A call of the `verify` module: `borsh(Call)` inside the runtime's call enum.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Call {
    /// 0: [`bind`] `id` to `code_hash`, as the manager did on the Hub (`Root`).
    Bind {
        /// The module's id.
        id: VerificationModuleId,
        /// Its blob's hash.
        code_hash: Hash32,
    },
}

/// The module's call index of `bind`.
pub const BIND: u8 = 0;

/// The module's events, `borsh` in the block's events under module `"verify"`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Event {
    /// [`Call::Bind`] recorded a binding.
    Bound {
        /// The module's id.
        id: VerificationModuleId,
        /// Its blob's hash.
        code_hash: Hash32,
    },
}

/// The module's metadata; its errors as [`dispatch_error`] numbers them.
pub fn metadata() -> tog_runtime_core::metadata::ModuleMetadata {
    tog_runtime_core::metadata::ModuleMetadata::from_names(
        "verify",
        &[(BIND, "bind", &[("id", "VerificationModuleId"), ("code_hash", "Hash32")])],
        &["modules"],
        &["Bound"],
        &["AlreadyBound", "TooMany"],
    )
}

/// The `DispatchError` of `e` for this module at index `module` in the runtime: `Module` errors
/// 0 [`Error::AlreadyBound`], 1 [`Error::TooMany`].
pub fn dispatch_error(e: Error, module: u8) -> DispatchError {
    match e {
        Error::BadOrigin => DispatchError::BadOrigin,
        Error::AlreadyBound => DispatchError::Module { module, error: 0 },
        Error::TooMany => DispatchError::Module { module, error: 1 },
        Error::Storage => DispatchError::Other("verify storage"),
    }
}

/// Dispatch `call` from `origin` and deposit [`Event::Bound`]; `module` is this module's index in
/// the runtime.
pub fn dispatch<E: Env>(e: &mut Scoped<'_, E>, module: u8, origin: Origin, call: Call) -> Result<(), DispatchError> {
    let Call::Bind { id, code_hash } = call;
    bind(e, &origin, id, code_hash).map_err(|err| dispatch_error(err, module))?;
    e.deposit_event("verify", &Event::Bound { id, code_hash });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tog_runtime_core::memory::MemoryStorage;

    fn id(n: u8) -> VerificationModuleId {
        VerificationModuleId([n; 16])
    }

    #[test]
    fn root_binds_each_id_once_up_to_sixteen() {
        let mut s = MemoryStorage::default();
        assert_eq!(bind(&mut s, &Origin::Signed([1; 20]), id(1), [1; 32]), Err(Error::BadOrigin));
        bind(&mut s, &Origin::Root, id(2), [2; 32]).unwrap();
        bind(&mut s, &Origin::Root, id(1), [1; 32]).unwrap();
        assert_eq!(bind(&mut s, &Origin::Root, id(1), [9; 32]), Err(Error::AlreadyBound));
        assert_eq!(modules(&mut s).unwrap(), [(id(1), [1; 32]), (id(2), [2; 32])], "ascending, first binding kept");
        assert_eq!(code_of(&mut s, &id(2)).unwrap(), Some([2; 32]));
        assert_eq!(code_of(&mut s, &id(3)).unwrap(), None);

        for n in 3..=16 {
            bind(&mut s, &Origin::Root, id(n), [n; 32]).unwrap();
        }
        assert_eq!(bind(&mut s, &Origin::Root, id(17), [17; 32]), Err(Error::TooMany));
    }
}
