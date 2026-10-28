//! What a module tells clients about itself (TOG-SPEC-0007 §4.1): its calls with their indices
//! and arguments, its storage items, events and errors. `#[tog_module]` generates it, and the
//! standard modules write theirs by hand. A runtime's `query("metadata")` returns
//! `borsh(RuntimeMetadata)`: each module's metadata under its index in the runtime (§12; the
//! format is provisional until v2 fixes it, so clients check [`RuntimeMetadata::format`]).

use alloc::string::String;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

/// One call of a module.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CallMetadata {
    /// The call's index in the module.
    pub index: u8,
    /// Lower snake case, as in `<module>.<call>`.
    pub name: String,
    /// Each argument's name and Rust type, in order; the call's bytes are `borsh` of the tuple.
    pub args: Vec<(String, String)>,
}

/// One module.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ModuleMetadata {
    /// The module's name, its storage prefix.
    pub name: String,
    /// Its calls, ascending by index.
    pub calls: Vec<CallMetadata>,
    /// Its storage items, each under `storage_key(name, item, ..)`.
    pub storage: Vec<String>,
    /// Its `Event` variants, in encoding order.
    pub events: Vec<String>,
    /// Its `Error` variants, in index order.
    pub errors: Vec<String>,
}

/// A call as names: index, name, each argument's name and type.
pub type CallNames<'a> = (u8, &'a str, &'a [(&'a str, &'a str)]);

impl ModuleMetadata {
    /// Metadata from names: `calls` as `(index, name, [(arg, type)])`, the rest as lists.
    pub fn from_names(name: &str, calls: &[CallNames<'_>], storage: &[&str], events: &[&str], errors: &[&str]) -> Self {
        let strings = |v: &[&str]| v.iter().map(|s| String::from(*s)).collect();
        ModuleMetadata {
            name: name.into(),
            calls: calls
                .iter()
                .map(|(index, name, args)| CallMetadata {
                    index: *index,
                    name: (*name).into(),
                    args: args.iter().map(|(n, t)| (String::from(*n), String::from(*t))).collect(),
                })
                .collect(),
            storage: strings(storage),
            events: strings(events),
            errors: strings(errors),
        }
    }
}

/// [`RuntimeMetadata::format`] of this SDK: provisional, before v2 fixes the format.
pub const FORMAT: u32 = 0;

/// A runtime's metadata, `query("metadata")`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RuntimeMetadata {
    /// [`FORMAT`]; a client that doesn't know the format shouldn't read the rest.
    pub format: u32,
    /// The runtime's name.
    pub name: String,
    /// Its `spec_version`.
    pub spec_version: u32,
    /// Each module under its index in the runtime, ascending by index.
    pub modules: Vec<(u8, ModuleMetadata)>,
}

impl RuntimeMetadata {
    /// Metadata of runtime `name` at `spec_version` with `modules`, sorted by index.
    pub fn new(name: &str, spec_version: u32, mut modules: Vec<(u8, ModuleMetadata)>) -> Self {
        modules.sort_by_key(|(i, _)| *i);
        RuntimeMetadata { format: FORMAT, name: name.into(), spec_version, modules }
    }

    /// The module at `index`.
    pub fn module(&self, index: u8) -> Option<&ModuleMetadata> {
        self.modules.iter().find(|(i, _)| *i == index).map(|(_, m)| m)
    }

    /// `<module>.<call>` of call `call` of module `module`.
    pub fn call_name(&self, module: u8, call: u8) -> Option<(&str, &str)> {
        let m = self.module(module)?;
        let c = m.calls.iter().find(|c| c.index == call)?;
        Some((&m.name, &c.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_metadata_finds_calls_by_index() {
        let balances = ModuleMetadata::from_names(
            "balances",
            &[(0, "transfer", &[("to", "AccountId"), ("amount", "Balance")])],
            &["accounts"],
            &["Transfer"],
            &["InsufficientBalance"],
        );
        let sudo = ModuleMetadata::from_names("sudo", &[(1, "set_key", &[("new", "AccountId")])], &["key"], &[], &[]);
        let m = RuntimeMetadata::new("r", 3, vec![(4, sudo), (0, balances)]);
        assert_eq!(m.modules.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 4]);
        assert_eq!(m.call_name(0, 0), Some(("balances", "transfer")));
        assert_eq!(m.call_name(4, 1), Some(("sudo", "set_key")));
        assert_eq!(m.call_name(4, 0), None);
        assert_eq!(m.module(0).unwrap().calls[0].args[1], ("amount".into(), "Balance".into()));
        let back: RuntimeMetadata = borsh::from_slice(&borsh::to_vec(&m).unwrap()).unwrap();
        assert_eq!((back.format, back), (FORMAT, m));
    }
}
