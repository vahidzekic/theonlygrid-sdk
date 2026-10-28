//! `#[tog_module]`: writes the parts of an AppChain runtime module that only repeat what the module
//! already says (TOG-SPEC-0007 §4.1): the storage key layout, call dispatch, event and error
//! encoding, call weights, client metadata and the genesis config's encoding.
//!
//! ```ignore
//! #[tog_module]
//! pub mod counter {
//!     use tog_runtime_core::env::Env;
//!     use tog_runtime_core::{AccountId, Origin, StorageMap, StorageValue, Weight};
//!     use tog_runtime_modules::executive::{Context, Scoped};
//!
//!     #[storage]
//!     pub type Total = StorageValue<u64>;          // TOTAL, at storage_key("counter", "total")
//!     #[storage]
//!     pub type ByAccount = StorageMap<AccountId, u64>;
//!
//!     #[event]
//!     pub enum Event { Added { who: AccountId, by: u64 } }
//!
//!     #[error]
//!     pub enum Error { BadOrigin, Overflow, Storage(StorageError) }
//!
//!     #[genesis]
//!     pub struct GenesisConfig { pub start: u64 }
//!
//!     #[call(index = 0, weight = Weight::from_parts(1_000_000, 100))]
//!     pub fn add<E: Env>(e: &mut Scoped<'_, E>, _cx: &Context, origin: Origin, by: u64) -> Result<(), Error> {
//!         /* ... */
//!     }
//! }
//! ```
//!
//! What it generates, inside the module:
//!
//! - **Storage.** Each `#[storage] pub type Name = StorageValue<V>;` (or `StorageMap<K, V>`,
//!   `StorageDoubleMap<K1, K2, V>`, `StorageNMap<(K1, .., Kn), V>`) becomes `pub const NAME: StorageValue<V>` under
//!   `storage_key("<module>", "<name in snake case>", ..)`.
//! - **Events.** `#[event] enum Event` gets the Borsh derives and `Event::deposit(self, e)`, which
//!   deposits it under the module's name.
//! - **Errors.** `#[error] enum Error` (unit variants) gets the derives and
//!   [`ModuleError`](tog_runtime_core::ModuleError): a variant named `BadOrigin` is
//!   `DispatchError::BadOrigin`, any other is `DispatchError::Module { module, error: <its index> }`.
//!   An optional `Storage(StorageError)` variant is `DispatchError::Storage` and gets
//!   `From<StorageError>`, so storage reads take `?`.
//! - **Calls.** A function with `#[call(index = N, weight = W)]` takes the block's env, the
//!   `Context` and the `Origin`, then its arguments, and returns `Result<(), Error>` (or any
//!   `ModuleError`). The module gets `enum Call` (one variant per call, its arguments as fields)
//!   with `Call::encode` and `Call::into_call` to the runtime's `(module, index, borsh(args))`,
//!   and `call_name(index)`, `call_weight(index, args)` and
//!   `dispatch(e, cx, module, origin, index, args)` for the runtime's `Runtime` implementation. A
//!   call's bytes are `borsh` of its arguments as a tuple.
//! - **Hooks.** A function with `#[hook(<name>)]` is the module's block hook `<name>` (§4.4); it
//!   takes the env and the `Context`, then the hook's own arguments:
//!
//!   | Hook | Its arguments | Returns |
//!   |---|---|---|
//!   | `on_runtime_upgrade` | `from: u32`, the `spec_version` before | `Weight` used |
//!   | `on_initialize` | | `Weight` used |
//!   | `on_idle` | `remaining: Weight` | `Weight` used |
//!   | `#[hook(on_finalize, weight = W)]` | | `()`, within `W` |
//!   | `#[hook(on_compute_result, limit = W)]` | `call: u16`, `done: &compute::Completed` | `Result<Weight, Error>` |
//!   | `#[hook(on_worker_slashed, limit = W)]` | `notice: &WorkerSlashed` | `Result<Weight, Error>` |
//!
//!   The module gets `struct Hooks` with every hook under its own name, the ones it doesn't write
//!   doing nothing, and `Hooks::FINALIZE_WEIGHT`, `Hooks::COMPUTE_RESULT_LIMIT` and
//!   `Hooks::WORKER_SLASHED_LIMIT`, so the runtime's `Runtime` implementation calls each module's
//!   hooks the same way. `on_compute_result` and `on_worker_slashed` take the module's index, for
//!   its errors; without the hook they return an error, as the executive's defaults do.
//! - **Benchmarks.** A function with `#[benchmark(<call>)]` (or `#[benchmark(<call>, root)]` for a
//!   `Root` call) sets up the worst case of call `<call>` (§6): it takes the env and the account
//!   that will sign the call, writes what the call will find, and returns the call
//!   (`Result<Call, Error>`). The module gets `BENCHMARKS`, `(call index, root)` for each, and
//!   `bench_setup(e, module, index, caller)` for the runtime's `Runtime::benchmarks` and
//!   `Runtime::bench_setup`; `tog bench` measures each one on the runtime.
//! - **Genesis.** `#[genesis] struct GenesisConfig` gets the Borsh derives and `Default`; the
//!   module writes its own function that applies it.
//! - **Metadata.** `metadata()` returns the module's `ModuleMetadata`: its calls with their
//!   arguments, storage items, events and errors.
//!
//! The generated code reaches Borsh, `tog_runtime_core` and `alloc` through
//! `::tog_runtime_modules`, the one crate the module's crate depends on for it.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as Tokens};
use quote::{format_ident, quote};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Expr, Fields, FnArg, GenericArgument, Ident, Item, ItemEnum, ItemFn, ItemMod, ItemStruct,
    ItemType, Lit, Meta, Pat, PathArguments, Token, Type,
};

/// Turns an inline `mod` into a runtime module; see the crate documentation.
#[proc_macro_attribute]
pub fn tog_module(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return Error::new(Span::call_site(), "#[tog_module] takes no arguments").to_compile_error().into();
    }
    match syn::parse::<ItemMod>(item).and_then(expand) {
        Ok(t) => t.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// One `#[call]`.
struct CallFn {
    index: u8,
    weight: Expr,
    name: Ident,
    args: Vec<(Ident, Type)>,
}

/// The hooks `#[hook]` knows (§4.4): name, arguments after `(e, cx)`, and the bound it needs
/// (`weight` for `on_finalize`, `limit` for the fallible ones).
const HOOKS: [(&str, usize, Option<&str>); 6] = [
    ("on_runtime_upgrade", 1, None),
    ("on_initialize", 0, None),
    ("on_idle", 1, None),
    ("on_finalize", 0, Some("weight")),
    ("on_compute_result", 2, Some("limit")),
    ("on_worker_slashed", 1, Some("limit")),
];

/// One `#[benchmark]`.
struct BenchFn {
    call: Ident,
    root: bool,
    name: Ident,
}

/// One `#[hook]`.
struct HookFn {
    hook: Ident,
    bound: Option<Expr>,
    name: Ident,
}

fn expand(mut module: ItemMod) -> syn::Result<Tokens> {
    let module_name = module.ident.to_string();
    let Some((_, items)) = module.content.take() else {
        return Err(Error::new(module.span(), "#[tog_module] needs an inline module: `mod name { .. }`"));
    };

    let mut out: Vec<Item> = Vec::new();
    let mut storage: Vec<String> = Vec::new();
    let mut events: Option<Vec<Ident>> = None;
    let mut errors: Option<Vec<Ident>> = None;
    let mut calls: Vec<CallFn> = Vec::new();
    let mut hooks: Vec<HookFn> = Vec::new();
    let mut benches: Vec<BenchFn> = Vec::new();

    for item in items {
        match item {
            Item::Type(mut t) => {
                if take_marker(&mut t.attrs, "storage")? {
                    let (konst, name) = storage_item(&module_name, t)?;
                    storage.push(name);
                    out.push(konst);
                } else {
                    out.push(Item::Type(t));
                }
            }
            Item::Enum(mut e) => {
                if take_marker(&mut e.attrs, "event")? {
                    events = Some(e.variants.iter().map(|v| v.ident.clone()).collect());
                    derive_borsh(&mut e.attrs);
                } else if take_marker(&mut e.attrs, "error")? {
                    errors = Some(error_variants(&e)?);
                    e.attrs.push(syn::parse_quote!(#[derive(Clone, Copy, Debug, PartialEq, Eq)]));
                }
                out.push(Item::Enum(e));
            }
            Item::Struct(mut s) => {
                if take_marker(&mut s.attrs, "genesis")? {
                    genesis_struct(&mut s)?;
                }
                out.push(Item::Struct(s));
            }
            Item::Fn(mut f) => {
                if let Some(c) = take_call(&mut f)? {
                    calls.push(c);
                } else if let Some(b) = take_benchmark(&mut f)? {
                    benches.push(b);
                } else if let Some(h) = take_hook(&mut f)? {
                    if hooks.iter().any(|x| x.hook == h.hook) {
                        return Err(Error::new(h.hook.span(), format!("hook {} written twice", h.hook)));
                    }
                    hooks.push(h);
                }
                out.push(Item::Fn(f));
            }
            other => out.push(other),
        }
    }

    calls.sort_by_key(|c| c.index);
    for w in calls.windows(2) {
        if w[0].index == w[1].index {
            return Err(Error::new(w[1].name.span(), format!("call index {} used twice", w[1].index)));
        }
    }

    let generated = generate(&module_name, &calls, &storage, events.as_deref(), errors.as_deref());
    let hooks = generate_hooks(&hooks);
    let benches = generate_benchmarks(&calls, &benches)?;
    let ItemMod { attrs, vis, unsafety, mod_token, ident, semi, .. } = module;
    let _ = (unsafety, semi);
    Ok(quote! {
        #(#attrs)*
        #vis #mod_token #ident {
            #(#out)*
            #generated
            #hooks
            #benches
        }
    })
}

/// Removes `#[name]` from `attrs`, saying whether it was there.
fn take_marker(attrs: &mut Vec<Attribute>, name: &str) -> syn::Result<bool> {
    let Some(i) = attrs.iter().position(|a| a.path().is_ident(name)) else { return Ok(false) };
    let a = attrs.remove(i);
    if !matches!(a.meta, Meta::Path(_)) {
        return Err(Error::new(a.span(), format!("#[{name}] takes no arguments")));
    }
    Ok(true)
}

fn derive_borsh(attrs: &mut Vec<Attribute>) {
    attrs.push(syn::parse_quote!(
        #[derive(Clone, Debug, PartialEq, Eq, ::tog_runtime_modules::__private::borsh::BorshSerialize, ::tog_runtime_modules::__private::borsh::BorshDeserialize)]
    ));
    attrs.push(syn::parse_quote!(#[borsh(crate = "::tog_runtime_modules::__private::borsh")]));
}

/// `pub type Name = StorageValue<V>;` → `pub const NAME: StorageValue<V> = StorageValue::new(..)`.
fn storage_item(module: &str, t: ItemType) -> syn::Result<(Item, String)> {
    let Type::Path(path) = &*t.ty else {
        return Err(Error::new(
            t.ty.span(),
            "#[storage] needs StorageValue, StorageMap, StorageDoubleMap or StorageNMap",
        ));
    };
    let last = path.path.segments.last().expect("a path has a segment");
    let kind = last.ident.to_string();
    let n_params = match &last.arguments {
        PathArguments::AngleBracketed(a) => a.args.iter().filter(|g| matches!(g, GenericArgument::Type(_))).count(),
        _ => 0,
    };
    let want = match kind.as_str() {
        "StorageValue" => 1,
        "StorageMap" => 2,
        "StorageDoubleMap" => 3,
        "StorageNMap" => 2,
        _ => {
            return Err(Error::new(
                last.ident.span(),
                "#[storage] needs StorageValue, StorageMap, StorageDoubleMap or StorageNMap",
            ))
        }
    };
    if n_params != want || !t.generics.params.is_empty() {
        return Err(Error::new(t.span(), format!("{kind} takes {want} type parameters and the alias none")));
    }
    let name = snake(&t.ident.to_string());
    let konst = format_ident!("{}", name.to_uppercase(), span = t.ident.span());
    let ty = &t.ty;
    let ctor = &last.ident;
    let vis = &t.vis;
    let docs = t.attrs.iter().filter(|a| a.path().is_ident("doc"));
    let item: Item = syn::parse_quote! {
        #(#docs)*
        #vis const #konst: #ty = ::tog_runtime_modules::__private::tog_runtime_core::storage::#ctor::new(#module, #name);
    };
    Ok((item, name))
}

fn error_variants(e: &ItemEnum) -> syn::Result<Vec<Ident>> {
    if e.variants.len() > 256 {
        return Err(Error::new(e.span(), "at most 256 errors"));
    }
    e.variants
        .iter()
        .map(|v| match (&v.fields, &v.discriminant) {
            (Fields::Unit, None) => Ok(v.ident.clone()),
            (Fields::Unnamed(f), None) if v.ident == "Storage" && f.unnamed.len() == 1 => Ok(v.ident.clone()),
            _ => Err(Error::new(
                v.span(),
                "#[error] variants carry no data and no discriminant, except `Storage(StorageError)`",
            )),
        })
        .collect()
}

fn genesis_struct(s: &mut ItemStruct) -> syn::Result<()> {
    if !s.generics.params.is_empty() {
        return Err(Error::new(s.generics.span(), "#[genesis] config takes no generics"));
    }
    s.attrs.push(syn::parse_quote!(
        #[derive(Clone, Debug, Default, PartialEq, Eq, ::tog_runtime_modules::__private::borsh::BorshSerialize, ::tog_runtime_modules::__private::borsh::BorshDeserialize)]
    ));
    s.attrs.push(syn::parse_quote!(#[borsh(crate = "::tog_runtime_modules::__private::borsh")]));
    Ok(())
}

/// Takes `#[call(index = N, weight = W)]` off `f`, if present.
fn take_call(f: &mut ItemFn) -> syn::Result<Option<CallFn>> {
    let Some(i) = f.attrs.iter().position(|a| a.path().is_ident("call")) else { return Ok(None) };
    let a = f.attrs.remove(i);
    let Meta::List(list) = &a.meta else {
        return Err(Error::new(a.span(), "#[call(index = N, weight = W)]"));
    };
    let pairs = Punctuated::<syn::MetaNameValue, Token![,]>::parse_terminated.parse2(list.tokens.clone())?;
    let (mut index, mut weight) = (None, None);
    for p in pairs {
        if p.path.is_ident("index") {
            let Expr::Lit(syn::ExprLit { lit: Lit::Int(n), .. }) = &p.value else {
                return Err(Error::new(p.value.span(), "index is an integer literal"));
            };
            index = Some(n.base10_parse::<u8>()?);
        } else if p.path.is_ident("weight") {
            weight = Some(p.value);
        } else {
            return Err(Error::new(p.path.span(), "#[call] takes index and weight"));
        }
    }
    let index = index.ok_or_else(|| Error::new(a.span(), "#[call] needs index = N"))?;
    let weight = weight.ok_or_else(|| Error::new(a.span(), "#[call] needs weight = W"))?;

    let inputs: Vec<&FnArg> = f.sig.inputs.iter().collect();
    if inputs.len() < 3 || inputs.iter().any(|i| matches!(i, FnArg::Receiver(_))) {
        return Err(Error::new(f.sig.span(), "a call takes (e, cx, origin, args..)"));
    }
    let mut args = Vec::new();
    for input in &inputs[3..] {
        let FnArg::Typed(t) = input else { unreachable!("no receiver") };
        let Pat::Ident(p) = &*t.pat else {
            return Err(Error::new(t.pat.span(), "call arguments are plain names"));
        };
        args.push((p.ident.clone(), (*t.ty).clone()));
    }
    Ok(Some(CallFn { index, weight, name: f.sig.ident.clone(), args }))
}

/// Takes `#[benchmark(call)]` (or `#[benchmark(call, root)]`) off `f`, if present.
fn take_benchmark(f: &mut ItemFn) -> syn::Result<Option<BenchFn>> {
    let Some(i) = f.attrs.iter().position(|a| a.path().is_ident("benchmark")) else { return Ok(None) };
    let a = f.attrs.remove(i);
    let Meta::List(list) = &a.meta else {
        return Err(Error::new(a.span(), "#[benchmark(call)]"));
    };
    let parts: Vec<Ident> =
        Punctuated::<Ident, Token![,]>::parse_terminated.parse2(list.tokens.clone())?.into_iter().collect();
    let root = match parts.as_slice() {
        [_] => false,
        [_, r] if r == "root" => true,
        _ => return Err(Error::new(list.span(), "#[benchmark(call)] or #[benchmark(call, root)]")),
    };
    if f.sig.inputs.len() != 2 || f.sig.inputs.iter().any(|i| matches!(i, FnArg::Receiver(_))) {
        return Err(Error::new(f.sig.span(), "a benchmark takes (e, caller)"));
    }
    Ok(Some(BenchFn { call: parts[0].clone(), root, name: f.sig.ident.clone() }))
}

fn generate_benchmarks(calls: &[CallFn], benches: &[BenchFn]) -> syn::Result<Tokens> {
    let core = quote!(::tog_runtime_modules::__private::tog_runtime_core);
    let exec = quote!(::tog_runtime_modules::executive);
    let mut seen = Vec::new();
    let mut entries = Vec::new();
    let mut arms = Vec::new();
    for b in benches {
        let Some(c) = calls.iter().find(|c| c.name == b.call) else {
            return Err(Error::new(b.call.span(), format!("no #[call] named {}", b.call)));
        };
        if seen.contains(&c.index) {
            return Err(Error::new(b.call.span(), format!("{} has two benchmarks", b.call)));
        }
        seen.push(c.index);
        let (index, root, f) = (c.index, b.root, &b.name);
        entries.push(quote!((#index, #root)));
        arms.push(quote! {
            #index => ::core::option::Option::Some(
                #f(e, caller)
                    .map_err(|err| #core::ModuleError::into_dispatch(err, module))
                    .and_then(|call| match call.encode() {
                        (#index, args) => ::core::result::Result::Ok(args),
                        _ => ::core::result::Result::Err(#core::DispatchError::Other("the benchmark set up another call")),
                    }),
            ),
        });
    }
    Ok(quote! {
        /// The module's benchmarks (§6): `(call index, root)` for each call one sets up.
        pub const BENCHMARKS: &[(u8, bool)] = &[#(#entries),*];

        /// Runs the benchmark of call `index` for signer `caller` (`module` is the module's index, for
        /// its errors): it writes the call's worst case and returns the call's arguments. `None` if
        /// the call has none.
        pub fn bench_setup<E: #core::env::Env>(
            e: &mut #exec::Scoped<'_, E>,
            module: u8,
            index: u8,
            caller: #core::AccountId,
        ) -> ::core::option::Option<::core::result::Result<::tog_runtime_modules::__private::alloc::vec::Vec<u8>, #core::DispatchError>> {
            let _ = (&e, module, &caller);
            match index {
                #(#arms)*
                _ => ::core::option::Option::None,
            }
        }
    })
}

/// Takes `#[hook(name)]` (or `#[hook(name, weight|limit = W)]`) off `f`, if present.
fn take_hook(f: &mut ItemFn) -> syn::Result<Option<HookFn>> {
    let Some(i) = f.attrs.iter().position(|a| a.path().is_ident("hook")) else { return Ok(None) };
    let a = f.attrs.remove(i);
    let Meta::List(list) = &a.meta else {
        return Err(Error::new(a.span(), "#[hook(name)]"));
    };
    let parts = Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())?;
    let mut parts = parts.into_iter();
    let Some(Meta::Path(hook)) = parts.next() else {
        return Err(Error::new(list.span(), "#[hook(name)] names the hook first"));
    };
    let hook = hook.require_ident()?.clone();
    let Some(&(_, n_args, needs)) = HOOKS.iter().find(|(h, ..)| hook == h) else {
        let known: Vec<&str> = HOOKS.iter().map(|(h, ..)| *h).collect();
        return Err(Error::new(hook.span(), format!("unknown hook; one of {}", known.join(", "))));
    };
    let mut bound = None;
    for p in parts {
        match (&p, needs) {
            (Meta::NameValue(nv), Some(key)) if nv.path.is_ident(key) && bound.is_none() => {
                bound = Some(nv.value.clone());
            }
            _ => {
                return Err(Error::new(p.span(), format!("#[hook({hook})] takes {}", needs.unwrap_or("nothing else"))))
            }
        }
    }
    if let (Some(key), None) = (needs, &bound) {
        return Err(Error::new(a.span(), format!("#[hook({hook}, {key} = W)] needs its {key}")));
    }
    if f.sig.inputs.len() != 2 + n_args || f.sig.inputs.iter().any(|i| matches!(i, FnArg::Receiver(_))) {
        return Err(Error::new(f.sig.span(), format!("{hook} takes (e, cx) and {n_args} more")));
    }
    Ok(Some(HookFn { hook, bound, name: f.sig.ident.clone() }))
}

fn generate_hooks(hooks: &[HookFn]) -> Tokens {
    let core = quote!(::tog_runtime_modules::__private::tog_runtime_core);
    let exec = quote!(::tog_runtime_modules::executive);
    let weight = quote!(#core::Weight);
    let find = |name: &str| hooks.iter().find(|h| h.hook == name);
    let infallible = |name: &str, args: &[(Ident, Tokens)]| {
        let hook = format_ident!("{name}");
        let names: Vec<&Ident> = args.iter().map(|(n, _)| n).collect();
        let params = args.iter().map(|(n, t)| quote!(#n: #t));
        let body = match find(name) {
            Some(h) => {
                let f = &h.name;
                quote!(#f(e, cx, #(#names),*))
            }
            None => quote! {
                let _ = (e, cx, #(#names),*);
                ::core::default::Default::default()
            },
        };
        let ret = if name == "on_finalize" { quote!(()) } else { quote!(#weight) };
        let doc = format!("The module's `{name}` hook (§4.4); nothing if it has none.");
        quote! {
            #[doc = #doc]
            pub fn #hook<E: #core::env::Env>(e: &mut #exec::Scoped<'_, E>, cx: &#exec::Context, #(#params),*) -> #ret {
                #body
            }
        }
    };
    let fallible = |name: &str, args: &[(Ident, Tokens)], none: &str| {
        let hook = format_ident!("{name}");
        let names: Vec<&Ident> = args.iter().map(|(n, _)| n).collect();
        let params = args.iter().map(|(n, t)| quote!(#n: #t));
        let body = match find(name) {
            Some(h) => {
                let f = &h.name;
                quote!(#f(e, cx, #(#names),*).map_err(|err| #core::ModuleError::into_dispatch(err, module)))
            }
            None => quote! {
                let _ = (e, cx, module, #(#names),*);
                ::core::result::Result::Err(#core::DispatchError::Other(#none))
            },
        };
        let doc = format!("The module's `{name}` hook (§4.4), at module index `module`; an error if it has none.");
        quote! {
            #[doc = #doc]
            pub fn #hook<E: #core::env::Env>(
                e: &mut #exec::Scoped<'_, E>,
                cx: &#exec::Context,
                module: u8,
                #(#params),*
            ) -> ::core::result::Result<#weight, #core::DispatchError> {
                #body
            }
        }
    };
    let bound = |name: &str| find(name).and_then(|h| h.bound.clone());
    let finalize_weight = bound("on_finalize").map_or_else(|| quote!(#weight::ZERO), |w| quote!(#w));
    let limit = |name: &str| {
        bound(name).map_or_else(|| quote!(::core::option::Option::None), |w| quote!(::core::option::Option::Some(#w)))
    };
    let (compute_limit, slashed_limit) = (limit("on_compute_result"), limit("on_worker_slashed"));
    let arg = |n: &str, t: Tokens| (format_ident!("{n}"), t);
    let upgrade = infallible("on_runtime_upgrade", &[arg("from", quote!(u32))]);
    let initialize = infallible("on_initialize", &[]);
    let idle = infallible("on_idle", &[arg("remaining", weight.clone())]);
    let finalize = infallible("on_finalize", &[]);
    let compute = fallible(
        "on_compute_result",
        &[arg("call", quote!(u16)), arg("done", quote!(&::tog_runtime_modules::compute::Completed))],
        "no compute callback",
    );
    let slashed = fallible(
        "on_worker_slashed",
        &[arg("notice", quote!(&::tog_runtime_modules::__private::WorkerSlashed))],
        "no worker slash hook",
    );
    quote! {
        /// The module's block hooks (§4.4), each under its own name; the runtime calls them from its
        /// `Runtime` implementation.
        pub struct Hooks;

        impl Hooks {
            /// Most weight [`Hooks::on_finalize`] uses.
            pub const FINALIZE_WEIGHT: #weight = #finalize_weight;
            /// The weight limit of [`Hooks::on_compute_result`]; `None` without the hook.
            pub const COMPUTE_RESULT_LIMIT: ::core::option::Option<#weight> = #compute_limit;
            /// The weight limit of [`Hooks::on_worker_slashed`]; `None` without the hook.
            pub const WORKER_SLASHED_LIMIT: ::core::option::Option<#weight> = #slashed_limit;

            #upgrade
            #initialize
            #idle
            #finalize
            #compute
            #slashed
        }
    }
}

fn generate(
    module: &str,
    calls: &[CallFn],
    storage: &[String],
    events: Option<&[Ident]>,
    errors: Option<&[Ident]>,
) -> Tokens {
    let private = quote!(::tog_runtime_modules::__private);
    let core = quote!(#private::tog_runtime_core);
    let borsh = quote!(#private::borsh);
    let alloc = quote!(#private::alloc);
    let exec = quote!(::tog_runtime_modules::executive);

    let variants = calls.iter().map(|c| {
        let v = camel(&c.name);
        let doc = format!("[`{}`]: call {}.", c.name, c.index);
        let fields = c.args.iter().map(|(n, t)| {
            let doc = format!("Its `{n}`.");
            quote!(#[doc = #doc] #n: #t)
        });
        quote!(#[doc = #doc] #v { #(#fields),* })
    });
    let encode_arms = calls.iter().map(|c| {
        let v = camel(&c.name);
        let index = c.index;
        let names: Vec<&Ident> = c.args.iter().map(|(n, _)| n).collect();
        quote! {
            Call::#v { #(#names),* } => (#index, #borsh::to_vec(&(#(#names,)*)).expect("in-memory borsh")),
        }
    });
    let name_arms = calls.iter().map(|c| {
        let (index, name) = (c.index, c.name.to_string());
        quote!(#index => ::core::option::Option::Some(#name),)
    });
    let weight_arms = calls.iter().map(|c| {
        let (index, w) = (c.index, &c.weight);
        let types = c.args.iter().map(|(_, t)| t);
        quote!(#index => #borsh::from_slice::<(#(#types,)*)>(args).ok().map(|_| #w),)
    });
    let dispatch_arms = calls.iter().map(|c| {
        let (index, f, w) = (c.index, &c.name, &c.weight);
        let names: Vec<&Ident> = c.args.iter().map(|(n, _)| n).collect();
        let types: Vec<&Type> = c.args.iter().map(|(_, t)| t).collect();
        quote! {
            #index => {
                let (#(#names,)*): (#(#types,)*) = #borsh::from_slice(args)
                    .map_err(|_| #core::DispatchError::Other("call arguments"))?;
                #f(e, cx, origin, #(#names),*).map_err(|err| #core::ModuleError::into_dispatch(err, module))?;
                ::core::result::Result::Ok(#w)
            }
        }
    });
    let call_meta = calls.iter().map(|c| {
        let (index, name) = (c.index, c.name.to_string());
        let args = c.args.iter().map(|(n, t)| {
            let (n, t) = (n.to_string(), quote!(#t).to_string().replace(' ', ""));
            quote!((#alloc::string::String::from(#n), #alloc::string::String::from(#t)))
        });
        quote! {
            #core::metadata::CallMetadata {
                index: #index,
                name: #alloc::string::String::from(#name),
                args: #alloc::vec![#(#args),*],
            }
        }
    });
    let strings = |xs: Vec<String>| quote!(#alloc::vec![#(#alloc::string::String::from(#xs)),*]);
    let storage_meta = strings(storage.to_vec());
    let event_meta = strings(events.unwrap_or_default().iter().map(Ident::to_string).collect());
    let error_meta = strings(errors.unwrap_or_default().iter().map(Ident::to_string).collect());

    let event_impl = events.map(|_| {
        quote! {
            impl Event {
                /// Deposits this event in the block's events under the module's name.
                pub fn deposit<E: #core::env::Env>(self, e: &mut #exec::Scoped<'_, E>) {
                    e.deposit_event(MODULE, &self);
                }
            }
        }
    });
    let error_impl = errors.map(|vs| {
        let storage_error = vs.iter().any(|v| v == "Storage");
        let arms = vs.iter().enumerate().map(|(i, v)| {
            let i = i as u8;
            match v.to_string().as_str() {
                "BadOrigin" => quote!(Error::#v => #core::DispatchError::BadOrigin,),
                "Storage" => quote!(Error::#v(err) => #core::DispatchError::Storage(err),),
                _ => quote!(Error::#v => #core::DispatchError::Module { module, error: #i },),
            }
        });
        // `From<StorageError>`, so `?` works on storage reads, needs a `Storage` variant.
        let from_storage = storage_error.then(|| {
            quote! {
                impl ::core::convert::From<#core::StorageError> for Error {
                    fn from(err: #core::StorageError) -> Self {
                        Error::Storage(err)
                    }
                }
            }
        });
        quote! {
            impl #core::ModuleError for Error {
                fn into_dispatch(self, module: u8) -> #core::DispatchError {
                    match self { #(#arms)* }
                }
            }

            #from_storage
        }
    });

    quote! {
        /// The module's name: its storage prefix and the name its events are deposited under.
        pub const MODULE: &str = #module;

        /// The module's calls, each with its arguments.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum Call {
            #(#variants),*
        }

        impl Call {
            /// The call's index and bytes, `borsh` of its arguments as a tuple.
            pub fn encode(&self) -> (u8, #alloc::vec::Vec<u8>) {
                match self { #(#encode_arms)* }
            }

            /// The runtime's call for this module at index `module`.
            pub fn into_call(self, module: u8) -> #exec::Call {
                let (index, args) = self.encode();
                (module, index, args)
            }
        }

        /// The name of call `index`.
        pub fn call_name(index: u8) -> ::core::option::Option<&'static str> {
            match index { #(#name_arms)* _ => ::core::option::Option::None }
        }

        /// The declared weight of call `index` with `args`; `None` for an unknown call or arguments
        /// that don't decode.
        pub fn call_weight(index: u8, args: &[u8]) -> ::core::option::Option<#core::Weight> {
            let _ = args;
            match index { #(#weight_arms)* _ => ::core::option::Option::None }
        }

        /// Runs call `index` with `args` (its encoded arguments) for `origin`; `module` is the
        /// module's index in the runtime, for its errors. Returns the call's declared weight.
        pub fn dispatch<E: #core::env::Env>(
            e: &mut #exec::Scoped<'_, E>,
            cx: &#exec::Context,
            module: u8,
            origin: #core::Origin,
            index: u8,
            args: &[u8],
        ) -> ::core::result::Result<#core::Weight, #core::DispatchError> {
            let _ = (&e, &cx, module, &origin, args);
            match index {
                #(#dispatch_arms)*
                _ => ::core::result::Result::Err(#core::DispatchError::Other("unknown call")),
            }
        }

        /// What the module tells clients about itself.
        pub fn metadata() -> #core::metadata::ModuleMetadata {
            #core::metadata::ModuleMetadata {
                name: #alloc::string::String::from(#module),
                calls: #alloc::vec![#(#call_meta),*],
                storage: #storage_meta,
                events: #event_meta,
                errors: #error_meta,
            }
        }

        #event_impl
        #error_impl
    }
}

/// `ByAccount` → `by_account`.
fn snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// `set_key` → `SetKey`.
fn camel(i: &Ident) -> Ident {
    let s: String = i
        .to_string()
        .split('_')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect::<String>()).unwrap_or_default()
        })
        .collect();
    Ident::new(&s, i.span())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand_err(module: ItemMod) -> String {
        expand(module).expect_err("refused").to_string()
    }

    #[test]
    fn names() {
        assert_eq!(snake("ByAccount"), "by_account");
        assert_eq!(snake("Total"), "total");
        assert_eq!(camel(&format_ident!("set_key")), "SetKey");
        assert_eq!(camel(&format_ident!("add")), "Add");
    }

    #[test]
    fn refuses_what_it_cannot_generate() {
        assert!(expand_err(syn::parse_quote!(
            mod m;
        ))
        .contains("inline module"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[storage]
                type T = Vec<u8>;
            }
        ))
        .contains("StorageValue"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[storage]
                type T = StorageMap<u8>;
            }
        ))
        .contains("takes 2 type parameters"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[error]
                enum Error {
                    Bad(u8),
                }
            }
        ))
        .contains("carry no data"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[call(index = 0, weight = W)]
                fn a(e: E, cx: C, o: O) {}
                #[call(index = 0, weight = W)]
                fn b(e: E, cx: C, o: O) {}
            }
        ))
        .contains("used twice"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[call(index = 0)]
                fn a(e: E, cx: C, o: O) {}
            }
        ))
        .contains("weight"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[call(index = 0, weight = W)]
                fn a(e: E, o: O) {}
            }
        ))
        .contains("(e, cx, origin, args..)"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[hook(on_lunch)]
                fn a(e: E, cx: C) {}
            }
        ))
        .contains("unknown hook"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[hook(on_finalize)]
                fn a(e: E, cx: C) {}
            }
        ))
        .contains("needs its weight"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[hook(on_initialize, limit = W)]
                fn a(e: E, cx: C) {}
            }
        ))
        .contains("takes nothing else"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[hook(on_idle)]
                fn a(e: E, cx: C) {}
            }
        ))
        .contains("(e, cx) and 1 more"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[hook(on_initialize)]
                fn a(e: E, cx: C) {}
                #[hook(on_initialize)]
                fn b(e: E, cx: C) {}
            }
        ))
        .contains("written twice"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[benchmark(nope)]
                fn a(e: E, caller: A) {}
            }
        ))
        .contains("no #[call] named nope"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[call(index = 0, weight = W)]
                fn a(e: E, cx: C, o: O) {}
                #[benchmark(a, sudo)]
                fn b(e: E, caller: A) {}
            }
        ))
        .contains("#[benchmark(call, root)]"));
        assert!(expand_err(syn::parse_quote!(
            mod m {
                #[call(index = 0, weight = W)]
                fn a(e: E, cx: C, o: O) {}
                #[benchmark(a)]
                fn b(e: E, caller: A) {}
                #[benchmark(a)]
                fn c(e: E, caller: A) {}
            }
        ))
        .contains("two benchmarks"));
    }
}
