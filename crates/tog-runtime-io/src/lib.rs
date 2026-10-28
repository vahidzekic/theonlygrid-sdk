//! The runtime side of the host ABI v1 (TOG-SPEC-0007 §3.1, §3.2).
//!
//! On `wasm32` every function here calls the `tog_v1` host imports. On other targets the host
//! functions don't exist: the code still compiles (so it is checked natively) but panics if called;
//! native tests run modules against `tog_runtime_core::memory` instead.
//!
//! - [`HostStorage`]: [`tog_runtime_core::Storage`] over `storage_*`;
//! - [`crypto`], [`hub`], [`cgmp`], [`log`]: the other host groups;
//! - [`export_entry!`]: glue from a `fn(&[u8]) -> Vec<u8>` to a `tog_v1_*(ptr, len) -> i64` export;
//! - with feature `runtime`: the `tog_v1_alloc` export, a bump allocator and a panic handler that
//!   reports through `panic_message`. A call gets a fresh instance, so memory is never freed;
//! - with feature `pure` instead: the same without any import, for a verification-module blob
//!   (§7.2), whose exports [`export_verification!`] writes.
//!
//! All `unsafe` is in the private `ffi` module and, with feature `runtime` or `pure`, the
//! allocator in `runtime`.

#![no_std]

extern crate alloc;

#[cfg(target_arch = "wasm32")]
mod ffi;
#[cfg(not(target_arch = "wasm32"))]
#[path = "ffi_native.rs"]
mod ffi;

pub mod cgmp;
pub mod crypto;
pub mod hub;
pub mod log;
mod storage;

#[cfg(all(any(feature = "runtime", feature = "pure"), target_arch = "wasm32"))]
mod runtime;

pub use storage::{HostEnv, HostStorage};

#[doc(hidden)]
pub mod __private {
    pub use crate::ffi::{entry_input, entry_output};
    pub use alloc::vec::Vec;
    pub use tog_runtime_core::verification::{compare_sketch_entry, sample_entry};
}

/// Export `$f: fn(&[u8]) -> Vec<u8>` as the entry point `$name` (`(ptr, len) -> i64`, §3.1).
///
/// ```ignore
/// tog_runtime_io::export_entry!(tog_v1_version, version);
/// ```
#[macro_export]
macro_rules! export_entry {
    ($name:ident, $f:path) => {
        #[cfg(target_arch = "wasm32")]
        #[doc = concat!("Entry point `", stringify!($name), "`.")]
        #[no_mangle]
        pub extern "C" fn $name(ptr: i32, len: i32) -> i64 {
            let input = $crate::__private::entry_input(ptr, len);
            let out: $crate::__private::Vec<u8> = $f(&input);
            $crate::__private::entry_output(out)
        }
    };
}

/// Export `$m: VerificationModule` as `tog_v1_compare_sketch` and `tog_v1_sample` (§7.2). Build
/// the blob with feature `pure` and call no host function, so it imports nothing.
///
/// ```ignore
/// tog_runtime_io::export_verification!(MyVerifier);
/// ```
#[macro_export]
macro_rules! export_verification {
    ($m:ty) => {
        #[cfg(target_arch = "wasm32")]
        #[doc = "Entry point `tog_v1_compare_sketch`."]
        #[no_mangle]
        pub extern "C" fn tog_v1_compare_sketch(ptr: i32, len: i32) -> i64 {
            let input = $crate::__private::entry_input(ptr, len);
            $crate::__private::entry_output($crate::__private::compare_sketch_entry::<$m>(&input))
        }

        #[cfg(target_arch = "wasm32")]
        #[doc = "Entry point `tog_v1_sample`."]
        #[no_mangle]
        pub extern "C" fn tog_v1_sample(ptr: i32, len: i32) -> i64 {
            let input = $crate::__private::entry_input(ptr, len);
            $crate::__private::entry_output($crate::__private::sample_entry::<$m>(&input))
        }
    };
}

/// Read a variable-length host result: try a buffer of `guess` bytes, retry with the reported
/// length if it was too small (§3.2 host calling convention).
pub(crate) fn read_var(guess: usize, mut call: impl FnMut(&mut [u8]) -> i64) -> Option<alloc::vec::Vec<u8>> {
    let mut buf = alloc::vec![0u8; guess];
    loop {
        let n = call(&mut buf);
        if n < 0 {
            return None;
        }
        let n = n as usize;
        if n <= buf.len() {
            buf.truncate(n);
            return Some(buf);
        }
        buf = alloc::vec![0u8; n];
    }
}
