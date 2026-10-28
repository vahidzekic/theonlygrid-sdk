# Building and launching an AppChain on the TOG testnet

This guide is for developers who want their own chain on TOG: an AppChain. It covers the whole path,
from an empty directory to a chain whose blocks the Hub finalizes on the testnet. Every command and
configuration key below is what the code on `main` accepts. Values that are not published yet are
written as `<PLACEHOLDER>`.

For a first chain, step by step, start with the [tutorial](appchain-tutorial.md).

Test-TOG, the token of the testnet, has no value. It pays for code upload, coretime and collator
bonds on the testnet, and nothing it buys or earns there carries over to mainnet.

## 1. What an AppChain is

An AppChain is a blockchain with its own runtime and state, secured by the TOG Hub (TOG-SPEC-0007).

- **The runtime** is a Wasm module built with the TOG SDK (`tog-runtime-*` crates): modules for
  balances, assets, fees, governance (`sudo`), messages (CGMP), compute jobs and your own logic.
- **Collators** run the chain's node, `tog-collator`. They build blocks and send them to the Hub
  validators as candidates.
- **The Hub** validators re-execute each candidate against the chain's registered code, and make
  its head final. Users of the chain trust the Hub, not the collators.
- **Coretime** is what the chain pays the Hub to have its blocks included: on-demand (a prepaid
  balance charged per block) or a region (a period bought ahead). Without coretime, blocks are
  built but never included, and the chain stands still (section 8).
- **CGMP** messages move test-TOG and calls between the chain, the Hub and other AppChains
  (TOG-SPEC-0007 §4.6). Through them a chain can request compute jobs and storage deals, and pay
  for them.

## 2. Requirements

| | |
|---|---|
| OS | Linux or macOS for development; Linux on x86-64 for a collator on the testnet |
| Rust | stable, with the `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`) |
| Disk | about 15 GB for a build of the SDK and the binaries |
| Docker | optional, for `tog build --image`: a code hash anyone can reproduce from the source |

The tools, `tog` (the SDK's developer tool), `tog-collator` and `tog-cli`, come as Linux x86-64
binaries with each testnet release, at `<RELEASE_URL>`. The runtime crates come from this
repository; `tog new` pins them.

## 3. Create a chain

```sh
tog new mychain --template minimal
cd mychain
```

`tog new` writes a Cargo workspace: `runtime/src/lib.rs` (the runtime), `runtime/src/weights.rs`
(its call weights), `runtime/tests/runtime.rs` (its tests) and a `README.md`. The SDK comes from its git
repository, pinned by the workspace's `Cargo.lock`: `--sdk-git <url>` (or `TOG_SDK_REPO`) names
another repository or a mirror, `--sdk-rev` a commit or tag, and `--sdk <checkout>` builds against a
local checkout instead.

Each template is one of the four reference chains running on the testnet, ready to copy:

| Template | What it has | Reference chain |
|---|---|---|
| `minimal` | the standard modules: balances, assets, `sudo`, CGMP (test-TOG to and from the Hub, calls to other chains), compute requests | token chain |
| `compute` | a module that requests jobs and handles their verified results in `on_compute_result` | compute chain |
| `storage` | a file registry: users name content kept in Hub storage deals | storage chain |
| `reserved` | binds a reservation of worker capacity booked for the chain (TOG-SPEC-0015) and runs jobs on it | reserved-capacity chain |

Start from the template closest to your idea, then change `runtime/src/lib.rs`. Every module is
plain Rust: calls, storage and events, with the dispatch rules of TOG-SPEC-0007 §4.

## 4. Test

```sh
tog test
```

This runs `cargo test` natively against `tog-runtime-test`'s in-memory chain. The Hub, other chains
and compute results are simulated: a test can set a Hub state entry, deliver a CGMP message or
script a job's result, including failures. The template's tests show each of these. Arguments after
`--` go to `cargo test`.

## 5. Run it locally

```sh
tog dev                 # Hub validators, the chain registered, one collator
tog dev --workers       # also three workers and three storage nodes, for compute and storage
```

`tog dev` builds the runtime, starts a local devnet and keeps it running until Ctrl-C. It prints
the chain id, the collator's JSON-RPC address (`rpc=http://…`) and a funded development account
with its secret key. The devnet directory is removed on exit.

The JSON-RPC answers `tog_heads`, `tog_header`, `tog_block`, `tog_blockHash`,
`tog_events`, `tog_query`, `tog_chain` and `tog_submitTx`, and streams heads with
`tog_subscribeHeads` as `tog_head` notifications (TOG-SPEC-0007 §9).

## 6. Build and weigh

```sh
tog build --release
tog bench --runtime target/tog/mychain_runtime.wasm --out runtime/src/weights.rs
```

`tog build --release` pre-checks the Wasm the way Hub validators will (TOG-SPEC-0007 §8.2), and
writes it to `target/tog/` with its Zstd upload. It prints `code_hash`, the hash the Hub registers.
With `--image <name>@sha256:<digest>` the build runs in that container image, so anyone can rebuild
the same code hash from your source.

Run `tog bench` again after changing a call. A block's weight is checked against the weights in
`weights.rs`, and a call that costs more than declared can be refused by validators.

## 7. Launch on the testnet

The chain needs three accounts, all secp256k1 keys made with `tog-collator new-author-key --out
<file>`. Keep the key files with mode 0600: the collator refuses a key others can read.

| Account | Does | Needs |
|---|---|---|
| manager | uploads the code, registers the chain, buys coretime | the code deposit (0.0001 test-TOG per byte of the upload), the genesis head deposit, and the coretime you prepay |
| collator bond | bonds the collator (`RegisterCollator`); the chain's Aura authority | `CollatorBond`, 100 test-TOG (TOG-SPEC-0007 §8.5) |
| session key | seals the collator's blocks and signs `DeliverCgmp` | at least 0.1 test-TOG (the Hub's `MinSenderBalance`) |

Test-TOG comes from the faucet at `<FAUCET_URL>`.

**1. Collator configuration.** The commands below run in the chain's workspace (`mychain/`), next to
`collator.toml`:

```toml
chain_id = 0                     # set in step 2
network_id = <NETWORK_ID>
runtime = "target/tog/mychain_runtime.wasm"  # from `tog build --release`
genesis = "spec/genesis.bin"
network_key = "network.key"      # created if missing
session_key = "session.key"
collator = "0x<BOND_ACCOUNT>"
data_dir = "chain"
listen = ["/ip4/0.0.0.0/tcp/30700"]
rpc = "127.0.0.1:9944"
peers = []

[hub]
era_length = <ERA_LENGTH>
session_length = <SESSION_LENGTH>
genesis = "hub-genesis.borsh"
peers = [
  { addr = "<HUB_PEER_1>", asn = <ASN_1> },
  { addr = "<HUB_PEER_2>", asn = <ASN_2> },
]
```

Keep `data_dir` set. The node keeps its chain there and resumes from it after a restart. It also
keeps its last verified Hub header in `data_dir/hub-checkpoint`, and `status`, `send` and `output`
start from that file instead of following the Hub from its genesis.

List Hub peers in at least two different ASNs. The light client accepts a new validator set (an era
hand-off) only when peers in two ASNs serve the same one. With every peer in one ASN, the collator
stops following the Hub at the first era end.

**2. The chain spec.** Ask the Hub which id the chain will get, then write the chain's runtime,
genesis and spec with that id:

```sh
tog-collator --config collator.toml status | grep next_chain_id
tog chain-spec --runtime target/tog/mychain_runtime.wasm --chain-id <NEXT_CHAIN_ID> \
  --network-id <NETWORK_ID> --authority <BOND_ACCOUNT> \
  --balance <ACCOUNT>=<BASE_UNITS> --root <SUDO_ACCOUNT> --out spec/
```

Set `chain_id = <NEXT_CHAIN_ID>` in `collator.toml`. Without `--root` the chain has no `sudo` key
and changes only through upgrades its own governance sends. The spec also carries the worker-set
rules (`--min-isolation`, `--min-bond`, `--min-reputation`, `--min-gpus`): what workers running the
chain's jobs must have. If another chain registers first and takes the id, write the spec again
with the new one.

**3. Upload the code.** Each command below signs with `--key`, reads the nonce from the Hub, sends
and waits until the Hub includes the transaction:

```sh
tog-collator --config collator.toml send --key manager.key upload-code
```

A large runtime goes up in several transactions. Then wait until `status` prints
`code_status=accepted`: validators pre-check the code first (TOG-SPEC-0007 §8.2).

**4. Register the chain and buy coretime.**

```sh
tog-collator --config collator.toml send --key manager.key register-appchain --spec spec/chain-spec.toml
tog-collator --config collator.toml send --key manager.key fund-on-demand --amount <BASE_UNITS>
```

`status` then prints `chain_registered=true`. Section 8 says how much coretime to buy.

**5. Register the collator and start it.**

```sh
tog-collator --config collator.toml send --key bond.key register-collator
tog-collator --config collator.toml run
```

`register-collator` bonds the bond account under the node's `network_key` and session key. Run the
node under systemd, so it restarts with the machine.

**6. Check.**

```sh
tog-collator --config collator.toml status
```

`collator=ok` means this node may author. `final_number` grows as the Hub finalizes the chain's
blocks.

## 8. Coretime

On the testnet a block costs the on-demand price, `od_price`, which never falls below 0.001 test-TOG
(mainnet: 0.1 TOG). The price rises when many chains buy on-demand blocks at once. At 2-second
blocks, one test-TOG pays for about 1 000 blocks at the floor price, roughly half an hour, and 50
test-TOG for about a day.

A region is a whole period (28 eras) bought ahead. While the chain holds one, its blocks in that
period cost nothing more. At the testnet's prices a region costs more than on-demand:

```sh
tog-collator --config collator.toml send --key manager.key purchase-region \
  --period <CORETIME_PERIOD> --max-price <BASE_UNITS>
```

`--period` is `status`'s `coretime_period` for the current period, or one more for the next. The
Hub refuses the purchase if the price is above `--max-price`. In the first 7 eras of a period, the
next period's region is sold only to chains holding a region of the current one, as a renewal at no
more than 105% of what they paid. After that anyone can buy it, with a premium that shrinks to
nothing over the following 7 eras. `next_region_price` is what it costs now.

`status` shows what the chain holds:

| Field | Means |
|---|---|
| `coretime_region` | `true` while the chain holds a region of the current period |
| `on_demand_balance` | the prepaid balance left, in base units |
| `od_price` | what one included block costs now |
| `on_demand_blocks` | blocks the balance still pays for |
| `coretime_period` | the current sale period |
| `next_coretime_region` | `true` once the chain holds a region of the next period |
| `region_price` | what a region of the current period costs |
| `next_region_price` | what a region of the next period costs now; `not_on_sale` while this chain can't buy it |

The collator warns in its log once fewer than 600 blocks are left, and reports an error when none
are. A chain with no coretime keeps building blocks that the Hub doesn't include. Its final head
stops, and it resumes on its own after the next `fund-on-demand` is included. An empty block costs
as much as a full one, so a quiet chain spends coretime too. A chain holding a region gets a
warning while its renewal window is open and the next period's region isn't bought yet.

## 9. Operating the chain

- **Upgrades.** Build the new runtime and try it on the chain's current state with the node's
  `tog_tryUpgrade` (served only with `rpc_unsafe = true`, so keep that RPC private). Then upload the
  code and send the upgrade through the chain's governance (TOG-SPEC-0007 §8.3). Collators fetch
  the new code from the Hub.
- **Session keys.** To rotate the session key, put the new key in `next_session_key`, then send
  `set-collator-keys` signed with the bond key. The node switches once the Hub's final state names
  the new key.
- **More collators.** Each collator has its own bond account, network key and session key, and is
  an Aura authority in the chain's state.
- **Messages from other chains.** List the planes of the chains this one receives from under
  `[sources]`. This is optional and only makes delivery faster: without it the node takes the
  messages from the sending chain's candidates.
- **Indexing.** `indexer = "events.jsonl"` appends every block, its events and head changes as JSON
  lines.

## 10. Troubleshooting

| `status` or the log says | Cause | Fix |
|---|---|---|
| `chain holds no coretime: PurchaseRegion or FundOnDemand` | on-demand balance below `od_price` | `fund-on-demand` (section 8) |
| `none of the N Hub peers answered` | the Hub peers are unreachable, or each takes at most 4 connections from one IP and other nodes on this host hold them all | check the addresses; run fewer TOG nodes behind one IP |
| `the hand-off at height H is served by N peers all in one network group` | every Hub peer has the same `asn` | list peers in two ASNs (section 7) |
| `the Hub light client stays at height H …, S s behind` | no peer serves the blocks after H: the node started far behind the Hub | keep `data_dir` set, or set `[hub] trusted` to a recent header |
| `collator=not_registered`, or `collator not registered: send RegisterCollator` | the bond account isn't a collator of this chain | step 5 |
| `collator=no_coretime` | as the first row | `fund-on-demand` |
| `the collator's record names another session key` | the Hub's record and `session_key` differ | `set-collator-keys`, or the right key file |
| `code_status=rejected` | the pre-check refused the Wasm | `tog build --release` reports the same check locally |
