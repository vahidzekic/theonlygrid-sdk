//! The `tog_v1` imports and the only `unsafe` code of the crate. Each wrapper passes pointers to
//! live Rust buffers with their exact lengths; the host bounds-checks every access and traps on
//! a bad one, so a wrong pointer can't corrupt memory, only fail the call.

#![allow(unsafe_code)]

use alloc::vec::Vec;

#[link(wasm_import_module = "tog_v1")]
extern "C" {
    fn storage_get(kp: i32, kl: i32, out: i32, cap: i32) -> i64;
    fn storage_set(kp: i32, kl: i32, vp: i32, vl: i32);
    fn storage_clear(kp: i32, kl: i32);
    fn storage_exists(kp: i32, kl: i32) -> i32;
    fn storage_next_key(kp: i32, kl: i32, out: i32) -> i32;
    fn storage_root(out: i32);
    fn blake3(p: i32, n: i32, out: i32);
    fn sha256(p: i32, n: i32, out: i32);
    fn keccak256(p: i32, n: i32, out: i32);
    fn ed25519_verify(kp: i32, kl: i32, sp: i32, sl: i32, mp: i32, ml: i32) -> i32;
    fn sr25519_verify(kp: i32, kl: i32, sp: i32, sl: i32, mp: i32, ml: i32) -> i32;
    fn bls12_381_verify_aggregate(kp: i32, kl: i32, sp: i32, sl: i32, mp: i32, ml: i32) -> i32;
    fn secp256k1_recover(dp: i32, dl: i32, sp: i32, sl: i32, out: i32) -> i32;
    fn chain_context(out: i32);
    fn hub_relay_parent(out: i32);
    fn hub_read_proof(kp: i32, kl: i32, out: i32, cap: i32) -> i64;
    fn inbox_next(out: i32, cap: i32) -> i64;
    fn outbox_push(p: i32, n: i32);
    fn log(p: i32, n: i32);
    #[cfg(feature = "runtime")]
    fn panic_message(p: i32, n: i32);
}

fn p(b: &[u8]) -> (i32, i32) {
    (b.as_ptr() as i32, b.len() as i32)
}

fn m(b: &mut [u8]) -> (i32, i32) {
    (b.as_mut_ptr() as i32, b.len() as i32)
}

pub(crate) fn get(key: &[u8; 96], out: &mut [u8]) -> i64 {
    let ((kp, kl), (op, oc)) = (p(key), m(out));
    unsafe { storage_get(kp, kl, op, oc) }
}
pub(crate) fn set(key: &[u8; 96], value: &[u8]) {
    let ((kp, kl), (vp, vl)) = (p(key), p(value));
    unsafe { storage_set(kp, kl, vp, vl) }
}
pub(crate) fn clear(key: &[u8; 96]) {
    let (kp, kl) = p(key);
    unsafe { storage_clear(kp, kl) }
}
pub(crate) fn exists(key: &[u8; 96]) -> bool {
    let (kp, kl) = p(key);
    unsafe { storage_exists(kp, kl) == 1 }
}
pub(crate) fn next_key(key: &[u8; 96]) -> Option<[u8; 96]> {
    let mut out = [0u8; 96];
    let (kp, kl) = p(key);
    (unsafe { storage_next_key(kp, kl, out.as_mut_ptr() as i32) } == 1).then_some(out)
}
pub(crate) fn root() -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { storage_root(out.as_mut_ptr() as i32) };
    out
}
pub(crate) fn hash(kind: u8, data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let ((dp, dl), o) = (p(data), out.as_mut_ptr() as i32);
    unsafe {
        match kind {
            0 => blake3(dp, dl, o),
            1 => sha256(dp, dl, o),
            _ => keccak256(dp, dl, o),
        }
    }
    out
}
pub(crate) fn ed25519(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let ((kp, kl), (sp, sl), (mp, ml)) = (p(pk), p(sig), p(msg));
    unsafe { ed25519_verify(kp, kl, sp, sl, mp, ml) == 1 }
}
pub(crate) fn sr25519(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let ((kp, kl), (sp, sl), (mp, ml)) = (p(pk), p(sig), p(msg));
    unsafe { sr25519_verify(kp, kl, sp, sl, mp, ml) == 1 }
}
pub(crate) fn bls_aggregate(keys: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let ((kp, kl), (sp, sl), (mp, ml)) = (p(keys), p(sig), p(msg));
    unsafe { bls12_381_verify_aggregate(kp, kl, sp, sl, mp, ml) == 1 }
}
pub(crate) fn secp256k1(digest: &[u8], sig: &[u8]) -> Option<[u8; 64]> {
    let mut out = [0u8; 64];
    let ((dp, dl), (sp, sl)) = (p(digest), p(sig));
    (unsafe { secp256k1_recover(dp, dl, sp, sl, out.as_mut_ptr() as i32) } == 0).then_some(out)
}
pub(crate) fn context() -> [u8; 12] {
    let mut out = [0u8; 12];
    unsafe { chain_context(out.as_mut_ptr() as i32) };
    out
}
pub(crate) fn relay_parent() -> [u8; 40] {
    let mut out = [0u8; 40];
    unsafe { hub_relay_parent(out.as_mut_ptr() as i32) };
    out
}
pub(crate) fn hub_read(key: &[u8], out: &mut [u8]) -> i64 {
    let ((kp, kl), (op, oc)) = (p(key), m(out));
    unsafe { hub_read_proof(kp, kl, op, oc) }
}
pub(crate) fn inbox(out: &mut [u8]) -> i64 {
    let (op, oc) = m(out);
    unsafe { inbox_next(op, oc) }
}
pub(crate) fn outbox(msg: &[u8]) {
    let (mp, ml) = p(msg);
    unsafe { outbox_push(mp, ml) }
}
pub(crate) fn log_line(line: &[u8]) {
    let (lp, ll) = p(line);
    unsafe { log(lp, ll) }
}
#[cfg(feature = "runtime")]
pub(crate) fn report_panic(msg: &[u8]) {
    let (mp, ml) = p(msg);
    unsafe { panic_message(mp, ml) }
}

/// The entry-point input the host wrote at `ptr..ptr + len` (memory it got from `tog_v1_alloc`).
pub fn entry_input(ptr: i32, len: i32) -> Vec<u8> {
    if len <= 0 {
        return Vec::new();
    }
    // SAFETY: the host wrote `len` bytes at `ptr`, memory it got from `tog_v1_alloc` just before
    // the call, and nothing else holds a reference to it.
    unsafe { core::slice::from_raw_parts(ptr as u32 as usize as *const u8, len as usize) }.to_vec()
}

/// Leak `out` and return `(ptr << 32) | len` for the host to read.
pub fn entry_output(out: Vec<u8>) -> i64 {
    let out = out.leak();
    ((out.as_ptr() as u32 as i64) << 32) | out.len() as i64
}
