//! The optional `remark` module: a note on the chain, from a signed account or from another
//! AppChain's CGMP `Call` (TOG-SPEC-0007 §4.6), written with [`tog_module`](crate::tog_module).
//!
//! It keeps nothing in state: a note is only its `Remarked` event, so it takes no storage deposit.
//! It is how a chain's team sees a message from another chain arrive before writing a module of
//! its own that acts on one. Its CGMP name is [`CGMP_NAME`], `tog/remark`; a `Call` to it is
//! `borsh((0u8, data))`, and the event records the sending chain and its `CgmpOrigin`, which this
//! chain may trust only as that chain's claim about its own account (§4.6).

use crate::tog_module;

#[tog_module]
mod remark {
    use alloc::vec::Vec;

    use tog_runtime_core::env::Env;
    use tog_runtime_core::{AccountId, ChainId, Origin, Weight};
    use tog_types::cgmp::CgmpOrigin;
    use tog_types::job::ModuleId;

    use crate::executive::{Context, Scoped};

    /// The call index of `remark`.
    pub const REMARK: u8 = 0;

    /// The longest note, in bytes.
    pub const MAX_LEN: usize = 256;

    /// The module's name in CGMP messages (0000 §13.2): `tog/remark`, zero-padded.
    pub const CGMP_NAME: ModuleId = ModuleId(*b"tog/remark\0\0\0\0\0\0");

    /// The module's events, `borsh` in the block's events under module `"remark"`.
    #[event]
    pub enum Event {
        /// A note from `by` on chain `source`: this chain for a signed `remark`, the sender for a
        /// CGMP `Call`, whose `by` is that chain's claim.
        Remarked {
            /// The chain the note was sent from.
            source: ChainId,
            /// Who sent it there.
            by: CgmpOrigin,
            /// The note.
            data: Vec<u8>,
        },
    }

    /// Why a note was refused.
    #[error]
    pub enum Error {
        /// `remark` needs a signer; another chain's note comes through CGMP.
        BadOrigin,
        /// The note is longer than [`MAX_LEN`].
        TooLong,
        /// A CGMP `Call` that isn't `remark(data)`.
        BadCall,
    }

    /// `remark(data)`: a note from the signer.
    #[call(index = 0, weight = Weight::from_parts(68_000_000, 0))]
    pub fn remark<E: Env>(e: &mut Scoped<'_, E>, cx: &Context, origin: Origin, data: Vec<u8>) -> Result<(), Error> {
        let Origin::Signed(account) = origin else { return Err(Error::BadOrigin) };
        noted(e, cx.chain, CgmpOrigin::Account { chain: cx.chain, account }, data)
    }

    /// A CGMP `Call` `call` from chain `source`, whose message names `by` (§4.6): `remark(data)`
    /// is its only call.
    pub fn received<E: Env>(e: &mut Scoped<'_, E>, source: ChainId, by: &CgmpOrigin, call: &[u8]) -> Result<(), Error> {
        match call.split_first() {
            Some((&REMARK, args)) => {
                let (data,): (Vec<u8>,) = borsh::from_slice(args).map_err(|_| Error::BadCall)?;
                noted(e, source, by.clone(), data)
            }
            _ => Err(Error::BadCall),
        }
    }

    /// Whether `call` is a CGMP `Call` this module runs: `remark` with a note of at most
    /// [`MAX_LEN`] bytes.
    pub fn accepts(call: &[u8]) -> bool {
        matches!(call.split_first(), Some((&REMARK, args))
            if borsh::from_slice::<(Vec<u8>,)>(args).is_ok_and(|(d,)| d.len() <= MAX_LEN))
    }

    fn noted<E: Env>(e: &mut Scoped<'_, E>, source: ChainId, by: CgmpOrigin, data: Vec<u8>) -> Result<(), Error> {
        if data.len() > MAX_LEN {
            return Err(Error::TooLong);
        }
        Event::Remarked { source, by, data }.deposit(e);
        Ok(())
    }

    // Benchmark (§6): the longest note.
    #[benchmark(remark)]
    fn bench_remark<E: Env>(_e: &mut Scoped<'_, E>, _caller: AccountId) -> Result<Call, Error> {
        Ok(Call::Remark { data: alloc::vec![0xbe; MAX_LEN] })
    }
}

pub use remark::*;
