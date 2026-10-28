//! Origins and dispatch results (TOG-SPEC-0007 §4.2, §4.3).

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::storage::StorageError;
use crate::{AccountId, ChainId};

/// Who is calling. A call declares which origins it accepts; there is no implicit "sudo".
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Origin {
    /// A user transaction, by its signer.
    Signed(AccountId),
    /// The chain's own governance.
    Root,
    /// A message from the Hub (compute results, coretime notices), proven through CGMP.
    Hub,
    /// A CGMP message from another AppChain.
    Chain(ChainId),
    /// An inherent, created by the block author and checked by the runtime.
    None,
}

/// Why a call failed. A failed call's state changes are discarded; its fee is still charged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchError {
    /// The call doesn't accept this origin.
    BadOrigin,
    /// An error a module declared: the module's index in the runtime and the error's index.
    Module {
        /// Index of the module in the runtime definition.
        module: u8,
        /// Index of the error in the module's `Error` enum.
        error: u8,
    },
    /// Stored state doesn't decode or a value is too large.
    Storage(StorageError),
    /// The call would exceed the weight or PoV left in the block.
    Exhausted,
    /// Arithmetic overflow or underflow.
    Arithmetic,
    /// Anything else, with a static reason.
    Other(&'static str),
}

/// A call's error as the runtime reports it, given the module's index in the runtime: what a
/// `#[tog_module]` call may return.
pub trait ModuleError {
    /// The [`DispatchError`] for this error of module `module`.
    fn into_dispatch(self, module: u8) -> DispatchError;
}

impl ModuleError for DispatchError {
    fn into_dispatch(self, _: u8) -> DispatchError {
        self
    }
}

impl From<StorageError> for DispatchError {
    fn from(e: StorageError) -> Self {
        DispatchError::Storage(e)
    }
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DispatchError::BadOrigin => f.write_str("bad origin"),
            DispatchError::Module { module, error } => write!(f, "module {module} error {error}"),
            DispatchError::Storage(e) => write!(f, "storage: {e}"),
            DispatchError::Exhausted => f.write_str("block weight exhausted"),
            DispatchError::Arithmetic => f.write_str("arithmetic overflow"),
            DispatchError::Other(s) => f.write_str(s),
        }
    }
}

/// Result of dispatching a call.
pub type DispatchResult = Result<(), DispatchError>;

/// The signer of a `Signed` origin, or `BadOrigin`.
pub fn ensure_signed(o: Origin) -> Result<AccountId, DispatchError> {
    match o {
        Origin::Signed(a) => Ok(a),
        _ => Err(DispatchError::BadOrigin),
    }
}

/// `Ok` only for `Root`.
pub fn ensure_root(o: Origin) -> DispatchResult {
    match o {
        Origin::Root => Ok(()),
        _ => Err(DispatchError::BadOrigin),
    }
}

/// `Ok` only for `Hub`.
pub fn ensure_hub(o: Origin) -> DispatchResult {
    match o {
        Origin::Hub => Ok(()),
        _ => Err(DispatchError::BadOrigin),
    }
}

/// The sending chain of a `Chain` origin, or `BadOrigin`.
pub fn ensure_chain(o: Origin) -> Result<ChainId, DispatchError> {
    match o {
        Origin::Chain(c) => Ok(c),
        _ => Err(DispatchError::BadOrigin),
    }
}

/// `Ok` only for `None` (inherents).
pub fn ensure_none(o: Origin) -> DispatchResult {
    match o {
        Origin::None => Ok(()),
        _ => Err(DispatchError::BadOrigin),
    }
}

/// Return `Err(e.into())` unless `cond` holds.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr $(,)?) => {
        if !$cond {
            return Err($e.into());
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_checks() {
        let a = [7; 20];
        assert_eq!(ensure_signed(Origin::Signed(a)), Ok(a));
        assert_eq!(ensure_signed(Origin::Root), Err(DispatchError::BadOrigin));
        assert!(ensure_root(Origin::Root).is_ok());
        assert!(ensure_root(Origin::Hub).is_err());
        assert!(ensure_hub(Origin::Hub).is_ok());
        assert_eq!(ensure_chain(Origin::Chain(ChainId(5))), Ok(ChainId(5)));
        assert!(ensure_none(Origin::None).is_ok());
        assert!(ensure_none(Origin::Signed(a)).is_err());
    }

    #[test]
    fn ensure_macro_returns_early() {
        fn f(x: u8) -> DispatchResult {
            ensure!(x < 3, DispatchError::Other("big"));
            Ok(())
        }
        assert!(f(1).is_ok());
        assert_eq!(f(5), Err(DispatchError::Other("big")));
    }

    #[test]
    fn origin_encoding_is_stable() {
        assert_eq!(borsh::to_vec(&Origin::Root).unwrap(), [1]);
        assert_eq!(borsh::to_vec(&Origin::Chain(ChainId(2))).unwrap(), [3, 2, 0, 0, 0]);
    }
}
