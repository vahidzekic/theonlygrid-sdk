# The Only Grid AppChain SDK

[Srpska verzija](README.sr.md)

The Only Grid (TOG) is a network of independent operators selling compute, storage and bandwidth
through one settlement chain, the **Hub**. An **AppChain** is your own blockchain on top of it: you
write its logic in Rust, it compiles to one deterministic WebAssembly runtime, a collator you run
authors its blocks, and the Hub's validators check and finalize every one of them. Your chain
gets the Hub's security, messaging to other AppChains and direct access to the Hub's compute and
storage markets, without running a validator set of its own.

This repository is the SDK such a chain is built with: the runtime framework, the standard
modules, the module macro, a test harness and four ready templates. Everything here is
`no_std` Rust and builds for `wasm32-unknown-unknown` as well as natively.

> **Status: public testnet.** The SDK runs on the TOG public testnet, where tokens are test-TOG
> with no value. The code is not audited yet; an audit of the standard modules is planned before
> mainnet. Interfaces may still change between testnet releases.

## Contents

- [What you can build](#what-you-can-build)
- [Crates](#crates)
- [Standard modules](#standard-modules)
- [Writing a module: `#[tog_module]`](#writing-a-module-tog_module)
- [Templates](#templates)
- [Testing: `tog-runtime-test`](#testing-tog-runtime-test)
- [Tools](#tools)
- [How a chain runs](#how-a-chain-runs)
- [Getting started](#getting-started)
- [Building this repository](#building-this-repository)
- [Documentation](#documentation)
- [License](#license)

## What you can build

- **An application chain with its own logic and state**: accounts and balances in $TOG, your own
  fungible assets, your own modules with storage, calls, events and errors.
- **A chain that buys compute**: modules request jobs on the Hub compute market (a container
  image, inputs, a fee and a deadline) and get the result back in a hook, `on_compute_result`,
  inside a later block. Results can be settled or failed, and the chain decides what to do with
  each.
- **A chain that uses decentralized storage**: modules read Hub storage deals at the block's relay
  parent and only accept files that a held deal really keeps.
- **A chain with reserved capacity**: someone books a slice of a worker for the chain on the Hub,
  and the chain's jobs run on that slice ahead of the open market.
- **A chain that talks to other chains**: CGMP (Cross-Grid Message Passing) carries $TOG between
  the chain and the Hub and calls modules on other AppChains, with fees, timeouts and refunds.
- **A chain that upgrades itself**: governance (a `sudo` key or a council) authorizes a new
  runtime by its code hash, and the chain switches to it without a fork.

## Crates

| Crate | What it is |
|---|---|
| `tog-runtime-core` | The `no_std` framework: storage key layout and typed storage items (`StorageValue`, `StorageMap`, `StorageDoubleMap`, `StorageNMap`), bounded collections, two-dimensional weights (`ref_time`, `proof_size`), origins and dispatch results, blocks, inherents, PoV and witnesses, signed transactions, domain-separated hashing, module metadata, and an in-memory storage backend that records the witness. |
| `tog-runtime-io` | The runtime side of host ABI v1: storage, crypto, Hub reads, CGMP and logging imports, the export glue, a bump allocator and a panic handler for the Wasm build, and a `pure` mode for verification-module blobs. |
| `tog-runtime-macros` | `#[tog_module]`, which writes a module's storage layout, dispatch, events, errors, weights, hooks, benchmarks, genesis config and metadata from its plain Rust definition. |
| `tog-runtime-modules` | The standard modules and the executive (below). |
| `tog-runtime-test` | The test harness: your runtime on an in-memory chain with a simulated Hub, other chains and the compute market. |
| `tog-runtime-template` | The minimal template runtime. |
| `tog-runtime-template-compute` | Template with a model registry that fine-tunes models through the compute market. |
| `tog-runtime-template-storage` | Template with a file registry over Hub storage deals. |
| `tog-runtime-template-reserved` | Template whose jobs run on a Hub reservation booked for the chain. |
| `tog-primitives`, `tog-types` | The protocol's shared types: ids, amounts, hashes, Hub transactions, compute job specs and results, storage deals, CGMP messages. A runtime reads the Hub through them. |

## Standard modules

Each module is plain functions over any `Storage` backend, so the same code runs in the Wasm
runtime, in the collator and in native tests.

| Module | What it does |
|---|---|
| `system` | Account nonces, the block number and `authorize_upgrade(code_hash)` for runtime upgrades. |
| `balances` | $TOG accounts and transfers, with the account layout the Hub reads when users exit the chain. |
| `assets` | Optional fungible assets besides $TOG, ERC-20 style: `create`, `mint`, `burn`, `transfer`, `approve`, `transfer_from`, `set_owner`. |
| `transaction_payment` | Fees of signed transactions: charged from the call's benchmarked weight plus a tip, the unused weight refunded after dispatch, paid to the block's collator. A chain can set its own prices or fee handler. |
| `storage_deposit` | Per-byte deposits for the state a call adds, returned when that state is removed, so state can't grow for free. |
| `collator_selection` | Which collator authors each block (Aura), set by `Root`. |
| `sudo` | An optional key with the `Root` origin: `call`, `set_key`, `remove_key`. |
| `governance` | An optional council with the `Root` origin, instead of or after `sudo`. |
| `cgmp` | Both ends of message channels: $TOG to the Hub (`withdraw`), calls to modules of other AppChains (`send`), acknowledgements, timeouts and refunds of what the Hub refuses, and `prune` of finished messages. |
| `compute` | Jobs on the Hub compute market (`request`) and their results, delivered to the requesting module's `on_compute_result` hook; `on_worker_slashed` notices. |
| `verify` | The chain's mirror of the verification modules bound to it on the Hub, which check job results. |
| `executive` | The runtime's entry points over these modules: block building and import, transaction validation, inherents, hooks in order, and weight accounting. Your own modules plug into it. |

## Writing a module: `#[tog_module]`

A module is an inline Rust module; the macro generates what only repeats what the module already
says:

```rust
#[tog_module]
pub mod counter {
    use tog_runtime_core::env::Env;
    use tog_runtime_core::{AccountId, Origin, StorageMap, StorageValue, Weight};
    use tog_runtime_modules::executive::{Context, Scoped};

    #[storage]
    pub type Total = StorageValue<u64>;
    #[storage]
    pub type ByAccount = StorageMap<AccountId, u64>;

    #[event]
    pub enum Event { Added { who: AccountId, by: u64 } }

    #[error]
    pub enum Error { BadOrigin, Overflow, Storage(StorageError) }

    #[genesis]
    pub struct GenesisConfig { pub start: u64 }

    #[call(index = 0, weight = Weight::from_parts(1_000_000, 100))]
    pub fn add<E: Env>(e: &mut Scoped<'_, E>, _cx: &Context, origin: Origin, by: u64) -> Result<(), Error> {
        /* ... */
    }
}
```

What it generates:

- **Storage**: typed constants under `storage_key("<module>", "<item>")`, the same key layout the
  Hub uses, so light clients and the Hub can prove your state.
- **Calls**: `enum Call` with encoding, `call_name`, `call_weight` and `dispatch` for the runtime.
- **Events and errors**: Borsh encoding, `Event::deposit`, and error conversion to
  `DispatchError` (with `?` on storage reads).
- **Hooks**: `on_runtime_upgrade`, `on_initialize`, `on_idle`, `on_finalize`,
  `on_compute_result` and `on_worker_slashed`, each with its own weight limit.
- **Benchmarks**: `#[benchmark(<call>)]` sets up a call's worst case; `tog bench` measures it on
  the Wasm runtime and writes `weights.rs`.
- **Genesis**: a Borsh, `Default` genesis config.
- **Metadata**: calls with arguments, storage items, events and errors, so tools such as
  `tog events` and `tog send call` decode and encode them by name.

## Templates

`tog new` copies one of these into a new workspace. Each one builds, tests and runs as is.

| Template | `tog new --template` | Adds to the standard modules |
|---|---|---|
| `tog-runtime-template` | `minimal` | `remark`, a note recorded as an event, also reachable from other AppChains over CGMP (`tog/remark`). |
| `tog-runtime-template-compute` | `compute` | `model_registry`: register a model, `fine_tune` it through a compute job, and `publish` the result as the next version. |
| `tog-runtime-template-storage` | `storage` | `file_registry`: name files kept in Hub storage deals, refresh them as deals renew, remove them. |
| `tog-runtime-template-reserved` | `reserved` | `reserved_compute`: bind a Hub reservation to the chain and `run` jobs on it ahead of the open market. |

Each template's `lib.rs` starts with its full call table: module indices, call indices and
which origin each call needs.

## Testing: `tog-runtime-test`

`TestChain` runs your runtime natively, block by block, through the executive's own block
builder, so a test sees what a collator would:

- transactions are signed with development signatures and included or left out as the runtime
  decides; each block's events and outcomes are readable;
- every block is imported again on its parent state and must reach the same state root, which
  catches a runtime that isn't deterministic;
- **CGMP harness**: `send_from` delivers a message from the Hub or another chain with real inbox
  proofs, `take_sent` returns what the chain sent, and `ack` answers it;
- **compute harness**: `take_compute_requests` returns the jobs the chain asked for,
  `complete` settles or fails one in any way a job can end, and `refuse` has the Hub refuse it;
- `dispatch` runs a call under any origin (`Root`, `Hub`, `Chain`).

```rust
let mut chain = TestChain::<Template>::new(ChainId(5), |author| genesis(author));
chain.submit(ALICE, transfer(BOB, 10));
chain.block();
assert_eq!(chain.outcomes(), vec![Ok(..)]);
```

## Tools

The tools come as Linux x86-64 binaries with each testnet release; this repository holds the
crates a chain builds against.

**`tog`**, the developer tool:

| Command | What it does |
|---|---|
| `tog new <name> --template …` | Create a chain workspace from a template, with the SDK pinned. |
| `tog build --release` | Build the runtime's Wasm, pre-check it, write it with its Zstd upload, and print its code hash. With `--image` it builds in a pinned container so anyone can reproduce the same code hash. |
| `tog test` | Run the chain's tests natively against `tog-runtime-test`. |
| `tog bench` | Measure call weights on the Wasm runtime and write `weights.rs`. |
| `tog chain-spec` | Write the chain spec (runtime, genesis config and `chain-spec.toml`) that registration needs: authorities, initial balances, `sudo` key, verification modules and the worker requirements for the chain's jobs. |
| `tog dev` | A local devnet with Hub validators, your chain registered, a collator authoring and a funded account; with `--workers` also workers and storage nodes for compute jobs. |
| `tog account` | An account's nonce and balances on a running chain. |
| `tog send transfer / withdraw / remark / call` | Sign and send a transaction and print its events. |
| `tog events` | Decoded events of a range of blocks. |

**`tog-collator`** runs the chain: it authors blocks, sends them with their proofs to the Hub,
serves JSON-RPC to clients, and registers the chain and uploads runtimes
(`tog-collator tx register-appchain`, `tog-collator tx …`).

## How a chain runs

1. You build the runtime and write its chain spec.
2. You register the chain on the Hub. The Hub gives it the next chain id and holds its runtime's
   code hash.
3. You buy **coretime** on the Hub: on-demand blocks paid per block, or a longer reservation.
4. Your collator authors blocks. For each one it sends the Hub a proof of validity (the block and
   a storage witness); Hub validators re-execute the runtime on it and the Hub finalizes the
   chain's head.
5. Messages between your chain, the Hub and other AppChains travel through CGMP lanes whose roots
   are part of the finalized state, so each side can prove what it received.
6. Compute jobs a module requests leave in the block's outbox, run on Hub workers, and come back
   as results to the module's hook.

## Getting started

The [tutorial](docs/appchain-tutorial.md) takes a chain from `tog new` to blocks finalized on the
public testnet and a CGMP note sent to another chain. The [guide](docs/appchain-guide.md)
explains each part in more depth.

`tog new` takes the SDK from git. To build against this repository:

```sh
tog new my-chain --template minimal --sdk-git https://github.com/vahidzekic/theonlygrid-sdk
cd my-chain
tog test
tog build --release
tog dev            # local devnet with your chain on it
```

`TOG_SDK_REPO` sets the same repository for every `tog new`; `--sdk-rev` pins a tag or commit.

## Building this repository

You need Rust with the `wasm32-unknown-unknown` target.

```sh
rustup target add wasm32-unknown-unknown
cargo test --workspace
```

## Documentation

- [AppChain tutorial](docs/appchain-tutorial.md) ([srpski](docs/appchain-tutorial.sr.md))
- [AppChain guide](docs/appchain-guide.md) ([srpski](docs/appchain-guide.sr.md))
- Every crate is documented in its source; `cargo doc --workspace --open` builds the API docs.

Code comments refer to the protocol specifications by number (for example TOG-SPEC-0007, the
AppChain specification). The specifications are not published yet.

## License

Apache License 2.0, see [LICENSE](LICENSE).
