//! Native stand-ins for the `tog_v1` imports: there is no host outside Wasm, so every call panics.

use alloc::vec::Vec;

fn no_host() -> ! {
    panic!("tog_v1 host functions exist only in a wasm32 runtime")
}

pub(crate) fn get(_: &[u8; 96], _: &mut [u8]) -> i64 {
    no_host()
}
pub(crate) fn set(_: &[u8; 96], _: &[u8]) {
    no_host()
}
pub(crate) fn clear(_: &[u8; 96]) {
    no_host()
}
pub(crate) fn exists(_: &[u8; 96]) -> bool {
    no_host()
}
pub(crate) fn next_key(_: &[u8; 96]) -> Option<[u8; 96]> {
    no_host()
}
pub(crate) fn root() -> [u8; 32] {
    no_host()
}
pub(crate) fn hash(_: u8, _: &[u8]) -> [u8; 32] {
    no_host()
}
pub(crate) fn ed25519(_: &[u8], _: &[u8], _: &[u8]) -> bool {
    no_host()
}
pub(crate) fn sr25519(_: &[u8], _: &[u8], _: &[u8]) -> bool {
    no_host()
}
pub(crate) fn bls_aggregate(_: &[u8], _: &[u8], _: &[u8]) -> bool {
    no_host()
}
pub(crate) fn secp256k1(_: &[u8], _: &[u8]) -> Option<[u8; 64]> {
    no_host()
}
pub(crate) fn context() -> [u8; 12] {
    no_host()
}
pub(crate) fn relay_parent() -> [u8; 40] {
    no_host()
}
pub(crate) fn hub_read(_: &[u8], _: &mut [u8]) -> i64 {
    no_host()
}
pub(crate) fn inbox(_: &mut [u8]) -> i64 {
    no_host()
}
pub(crate) fn outbox(_: &[u8]) {
    no_host()
}
pub(crate) fn log_line(_: &[u8]) {
    no_host()
}
#[allow(dead_code)]
pub(crate) fn report_panic(_: &[u8]) {
    no_host()
}
/// See the wasm32 version.
pub fn entry_input(_: i32, _: i32) -> Vec<u8> {
    no_host()
}
/// See the wasm32 version.
pub fn entry_output(_: Vec<u8>) -> i64 {
    no_host()
}
