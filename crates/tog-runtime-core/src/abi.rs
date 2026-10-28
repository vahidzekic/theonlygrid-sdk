//! Names of the runtime's exports and the host's imports, version 1 (TOG-SPEC-0007 §3.1, §3.2, §12).
//!
//! The ABI version is part of every name. A new ABI version adds a new set of names next to these;
//! the old set stays supported for at least 12 months (§12). Registration pre-check (§8.2) uses
//! these lists: a runtime must export every entry point of [`ENTRY_POINTS`], [`EXPORT_ALLOC`] and
//! [`EXPORT_MEMORY`], and may import only the functions of [`HOST_FUNCTIONS`] from [`HOST_MODULE`],
//! with exactly the signatures listed there.

/// The host ABI version these names belong to.
pub const ABI_VERSION: u32 = 1;

/// Wasm import module the host functions live in.
pub const HOST_MODULE: &str = "tog_v1";

/// Export: runtime name, spec version, ABI version, code hash of the declared API.
pub const EXPORT_VERSION: &str = "tog_v1_version";
/// Export: stateless execution of one block from its PoV (Hub validators).
pub const EXPORT_VALIDATE_BLOCK: &str = "tog_v1_validate_block";
/// Export: stateful block import (collators, full nodes).
pub const EXPORT_EXECUTE_BLOCK: &str = "tog_v1_execute_block";
/// Export: apply inherents and transactions until a weight or PoV limit (block author).
pub const EXPORT_BUILD_BLOCK: &str = "tog_v1_build_block";
/// Export: cheap transaction validity check (tx pool).
pub const EXPORT_VALIDATE_TX: &str = "tog_v1_validate_tx";
/// Export: build the genesis state.
pub const EXPORT_GENESIS: &str = "tog_v1_genesis";
/// Export: read-only runtime API call (RPC).
pub const EXPORT_QUERY: &str = "tog_v1_query";

/// Export: `tog_v1_alloc(len: i32) -> i32`, memory for the host to write entry-point arguments into.
pub const EXPORT_ALLOC: &str = "tog_v1_alloc";

/// Every entry point a runtime must export (§3.1), each `(ptr: i32, len: i32) -> i64`.
pub const ENTRY_POINTS: [&str; 7] = [
    EXPORT_VERSION,
    EXPORT_VALIDATE_BLOCK,
    EXPORT_EXECUTE_BLOCK,
    EXPORT_BUILD_BLOCK,
    EXPORT_VALIDATE_TX,
    EXPORT_GENESIS,
    EXPORT_QUERY,
];

/// Verification-module export (§7.2): `borsh((Sketch, Sketch))` → `borsh(Verdict)`.
pub const EXPORT_COMPARE_SKETCH: &str = "tog_v1_compare_sketch";
/// Verification-module export (§7.2): `borsh((JobSpec, [u8; 32]))` → `borsh(Vec<u32>)`.
pub const EXPORT_SAMPLE: &str = "tog_v1_sample";

/// Every entry point a verification-module blob must export (§7.2), each `(ptr, len) -> i64`. A
/// blob imports nothing.
pub const VERIFY_ENTRY_POINTS: [&str; 2] = [EXPORT_COMPARE_SKETCH, EXPORT_SAMPLE];

/// Name of the exported linear memory the host reads arguments and results through.
pub const EXPORT_MEMORY: &str = "memory";

/// A Wasm value type in the ABI. Pointers and lengths are `i32`; lengths of variable results `i64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiType {
    /// `i32`.
    I32,
    /// `i64`.
    I64,
}

use AbiType::{I32, I64};

/// Groups of host functions (§3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostGroup {
    /// Storage: on validators reads come from the PoV witness, in collators from the database.
    Storage,
    /// Hash and signature primitives.
    Crypto,
    /// The chain's identity, the Hub relay parent and proven reads of Hub state.
    HubContext,
    /// CGMP inbox and outbox.
    Cgmp,
    /// Logging and panic reporting.
    Misc,
}

/// A host function: name in [`HOST_MODULE`], group and Wasm signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostFn {
    /// Import name.
    pub name: &'static str,
    /// Group of §3.2.
    pub group: HostGroup,
    /// Parameter types.
    pub params: &'static [AbiType],
    /// Result type, if any.
    pub result: Option<AbiType>,
}

const fn f(name: &'static str, group: HostGroup, params: &'static [AbiType], result: Option<AbiType>) -> HostFn {
    HostFn { name, group, params, result }
}

/// Every host function a runtime may import (§3.2), with its signature under the host calling
/// convention: each argument is `(ptr, len)`; a fixed-size result goes to an `out` pointer or is
/// the `i32` return; a variable-length result takes `(out_ptr, out_cap)` and returns its length
/// as `i64` (`-1` = none). Time, randomness and networking are deliberately absent.
///
/// | Function | Parameters | Result |
/// |---|---|---|
/// | `storage_get` | key, out, cap | length / −1 |
/// | `storage_set` | key, value | — |
/// | `storage_clear`, `storage_exists` | key | — / 1 or 0 |
/// | `storage_next_key` | key, out (96 bytes) | 1 found / 0 none |
/// | `storage_root` | out (32 bytes) | — |
/// | `blake3`, `sha256`, `keccak256` | data, out (32 bytes) | — |
/// | `ed25519_verify`, `sr25519_verify` | public key, signature, message | 1 valid / 0 |
/// | `secp256k1_recover` | 32-byte digest, 65-byte `r ‖ s ‖ v`, out (64-byte `x ‖ y`) | 0 ok / 1 invalid |
/// | `bls12_381_verify_aggregate` | Borsh public keys, signature, message | 1 valid / 0 |
/// | `chain_context` | out (12 bytes: `u32` chain id, `u32` network id, `u32` 0) | — |
/// | `hub_relay_parent` | out (40 bytes: `u64` height, 32-byte state root) | — |
/// | `hub_read_proof` | Hub key, out, cap | length / −1 |
/// | `inbox_next` | out, cap | length / −1 |
/// | `outbox_push`, `log`, `panic_message` | bytes | — |
pub const HOST_FUNCTIONS: [HostFn; 20] = [
    f("storage_get", HostGroup::Storage, &[I32, I32, I32, I32], Some(I64)),
    f("storage_set", HostGroup::Storage, &[I32, I32, I32, I32], None),
    f("storage_clear", HostGroup::Storage, &[I32, I32], None),
    f("storage_exists", HostGroup::Storage, &[I32, I32], Some(I32)),
    f("storage_next_key", HostGroup::Storage, &[I32, I32, I32], Some(I32)),
    f("storage_root", HostGroup::Storage, &[I32], None),
    f("blake3", HostGroup::Crypto, &[I32, I32, I32], None),
    f("sha256", HostGroup::Crypto, &[I32, I32, I32], None),
    f("keccak256", HostGroup::Crypto, &[I32, I32, I32], None),
    f("ed25519_verify", HostGroup::Crypto, &[I32, I32, I32, I32, I32, I32], Some(I32)),
    f("sr25519_verify", HostGroup::Crypto, &[I32, I32, I32, I32, I32, I32], Some(I32)),
    f("secp256k1_recover", HostGroup::Crypto, &[I32, I32, I32, I32, I32], Some(I32)),
    f("bls12_381_verify_aggregate", HostGroup::Crypto, &[I32, I32, I32, I32, I32, I32], Some(I32)),
    f("chain_context", HostGroup::HubContext, &[I32], None),
    f("hub_relay_parent", HostGroup::HubContext, &[I32], None),
    f("hub_read_proof", HostGroup::HubContext, &[I32, I32, I32, I32], Some(I64)),
    f("inbox_next", HostGroup::Cgmp, &[I32, I32], Some(I64)),
    f("outbox_push", HostGroup::Cgmp, &[I32, I32], None),
    f("log", HostGroup::Misc, &[I32, I32], None),
    f("panic_message", HostGroup::Misc, &[I32, I32], None),
];

/// The host function `(module, name)` names, if a runtime may import it.
pub fn host_function(module: &str, name: &str) -> Option<&'static HostFn> {
    if module != HOST_MODULE {
        return None;
    }
    HOST_FUNCTIONS.iter().find(|h| h.name == name)
}

/// Whether `(module, name)` is an import a runtime may declare.
pub fn is_allowed_import(module: &str, name: &str) -> bool {
    host_function(module, name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_names_carry_the_abi_version() {
        for name in ENTRY_POINTS.iter().chain([&EXPORT_ALLOC]) {
            assert!(name.starts_with("tog_v1_"), "{name}");
        }
    }

    #[test]
    fn host_function_names_are_unique() {
        for (i, a) in HOST_FUNCTIONS.iter().enumerate() {
            assert!(HOST_FUNCTIONS[i + 1..].iter().all(|b| a.name != b.name), "{}", a.name);
        }
    }

    #[test]
    fn only_host_module_imports_are_allowed() {
        assert!(is_allowed_import("tog_v1", "storage_get"));
        assert!(!is_allowed_import("env", "storage_get"));
        assert!(!is_allowed_import("tog_v1", "clock_now"));
        // No VRF in v1 (§3.2).
        assert!(!is_allowed_import("tog_v1", "vrf_verify"));
    }
}
