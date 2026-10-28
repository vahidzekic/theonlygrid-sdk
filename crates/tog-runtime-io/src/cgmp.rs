//! CGMP queues (§3.2): the next inbound message with its proof, and the outbox. Messages are passed
//! as their Borsh bytes; the `cgmp` module decodes them into `CgmpMessage` (TOG-SPEC-0000 §7.2).

use alloc::vec::Vec;

use crate::{ffi, read_var};

/// The next inbound entry in order, `borsh((CgmpMessage, Option<Vec<Hash32>>))`: the message and,
/// on a source's last message in the block, its inbox proof, which the runtime's `cgmp` module
/// checks (§3.4); `None` when none is left.
pub fn inbox_next() -> Option<Vec<u8>> {
    read_var(1024, ffi::inbox)
}

/// Append a Borsh `CgmpMessage` to the outbox.
pub fn outbox_push(msg: &[u8]) {
    ffi::outbox(msg)
}
