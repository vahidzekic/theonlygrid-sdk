# Tutorial: your first AppChain on the public testnet

This tutorial takes a team from nothing to a running AppChain on the TOG public testnet, one step
at a time. By the end you will have test-TOG from the faucet, a registered chain with coretime, a
collator on your own machine, test-TOG moved between the Hub and your chain, and a CGMP message
delivered to one of the testnet's demo chains. The [AppChain guide](appchain-guide.md) explains
each part in more depth; this page is the shortest path that works.

Every step was run on a local devnet with the commands below. Eras of 1800 Hub blocks and sessions of
300 are the closed testnet's values until the public testnet launches. Values that are published
with the launch, the network id among them, are written as `<PLACEHOLDER>` (table in step 4).

Test-TOG has no value. Nothing bought or earned on the testnet carries over to mainnet.

## 0. What you need

- A Linux x86-64 machine for the collator, reachable by the Hub peers you list, with about 15 GB of
  free disk. Development also works on macOS.
- Rust stable with the Wasm target: `rustup target add wasm32-unknown-unknown`.
The tools, `tog` (the SDK's developer tool), `tog-collator` and `tog-cli`, come as Linux x86-64
binaries with each testnet release, at `<RELEASE_URL>`. The runtime crates come from this
repository; `tog new` pins them.

Amounts on the command line are in base units: 1 test-TOG = 10^18 base units, so 50 test-TOG is
`50000000000000000000`.

## 1. Create the chain

```sh
tog new mychain --template minimal
cd mychain
tog test
tog build --release
```

`tog build --release` writes `target/tog/mychain_runtime.wasm` and prints its `code_hash`. The
`minimal` template is the testnet's token chain: balances, assets, `sudo`, CGMP and the
`tog/remark` module used in step 10. Change `runtime/src/lib.rs` later; for this tutorial build it
as it is.

## 2. Keys

```sh
tog-collator new-author-key --out owner.key     # prints the owner's address, 0x...
tog-collator new-author-key --out session.key   # prints the session key's address
chmod 600 owner.key session.key
```

To keep the tutorial to one faucet drip, the owner key does two jobs: it is the chain's manager
(uploads code, registers the chain, buys coretime) and its collator bond account. On a real chain
you can keep them apart (guide, section 7). The session key seals blocks and signs the messages
the collator delivers to the Hub. Back up both files; nobody can recover a lost key.

## 3. Test-TOG from the faucet

Open https://faucet.theonlygrid.com and paste the owner's address, or ask the faucet API directly:

```sh
curl -X POST --data <OWNER_ADDRESS> https://faucet-api.theonlygrid.com/drip
# sent 10100 TOG to 0x… (in by height N)
```

The faucet sends 10 100 test-TOG, once every 24 hours per address and per IP address. A second
request from the same IP, even for another address, gets `429` with `limited: try again in …`.
That is why the session key gets its test-TOG from the owner (step 7), not from the faucet. If the
web page shows a check (a captcha), use the page: the API then refuses requests without it.

One drip covers the whole tutorial:

| What | test-TOG | Step |
|---|---|---|
| code deposit, 0.0001 per byte of the upload (the minimal template is about 128 000 bytes) | about 13 | 6 |
| genesis head deposit | about 0.02 | 6 |
| on-demand coretime: 0.001 per block, about a day of blocks | 50 | 6 |
| session key: the Hub's `MinSenderBalance` is 0.1 | 1 | 7 |
| collator bond, `CollatorBond` | 100 | 7 |
| deposit to the chain | 20 | 9 |
| region, optional | 1000 | 11 |

The deposits and the bond stay reserved in the owner's account while the code, the chain and the
collator exist. Coretime is spent.

Check the Hub balance with `tog-cli account <OWNER_ADDRESS> --config client.toml --data-dir ~/tog/cli` (the
`client.toml` of the worker guide, section 6).

## 4. Testnet files

```sh
curl -fsSL -o hub-genesis.borsh <GENESIS_URL>
```

| Placeholder | What |
|---|---|
| `<NETWORK_ID>` | the public testnet's network id |
| `<RELEASE_URL>` | the testnet release with `tog`, `tog-collator` and `tog-cli` |
| `<GENESIS_URL>` | the public testnet's `genesis.borsh` |
| `<BOOTNODE_1>`, `<BOOTNODE_2>`, ... | Hub full nodes, `/ip4/.../tcp/.../p2p/<peer id>` |
| `<ASN_1>`, `<ASN_2>`, ... | each bootnode's network (ASN), from `asn.txt` in the testnet kit |
| `<TOKEN_CHAIN_ID>` | the chain id of the demo token chain |
| `<TOKEN_CHAIN_RPC>` | the demo token chain's public JSON-RPC, `host:port` |

## 5. Collator configuration

Write `collator.toml` in `mychain/`:

```toml
chain_id = 0                     # set in step 6
network_id = <NETWORK_ID>
runtime = "target/tog/mychain_runtime.wasm"
genesis = "spec/genesis.bin"
network_key = "network.key"      # created if missing
session_key = "session.key"
collator = "<OWNER_ADDRESS>"
data_dir = "chain"
listen = ["/ip4/0.0.0.0/tcp/30700"]
rpc = "127.0.0.1:9944"
peers = []

[hub]
era_length = 1800
session_length = 300
genesis = "hub-genesis.borsh"
peers = [
  { addr = "<BOOTNODE_1>", asn = <ASN_1> },
  { addr = "<BOOTNODE_2>", asn = <ASN_2> },
]
```

List peers in at least two different ASNs. The collator accepts each new validator set only when
peers in two networks serve the same one; with every peer in one ASN it stops following the Hub at
the end of the first era. Open TCP port 30700 in the firewall. Keep `rpc` on `127.0.0.1` unless you
mean to serve the chain to others.

Check that the collator reaches the Hub:

```sh
tog-collator --config collator.toml status
```

It prints `hub_height=…` and, among others, `next_chain_id=N`: the id your chain will get.

## 6. Register the chain

Write the chain spec with that id. `--balance` gives an account test-TOG on your chain from its
first block; `--root` makes the owner the chain's `sudo` key.

```sh
tog chain-spec --runtime target/tog/mychain_runtime.wasm --chain-id <N> --network-id <NETWORK_ID> \
  --authority <OWNER_ADDRESS> --balance <OWNER_ADDRESS>=1000000000000000000000 \
  --root <OWNER_ADDRESS> --out spec/
```

Set `chain_id = <N>` in `collator.toml`. Then upload the code, wait for the validators' pre-check,
register and prepay coretime. Each `send` signs with `--key`, waits for the Hub to include the
transaction and prints the height:

```sh
tog-collator --config collator.toml send --key owner.key upload-code
tog-collator --config collator.toml status | grep code_status    # repeat until code_status=accepted
tog-collator --config collator.toml send --key owner.key register-appchain --spec spec/chain-spec.toml
tog-collator --config collator.toml send --key owner.key fund-on-demand --amount 50000000000000000000
```

`upload-code` sends a large runtime in several transactions. The pre-check takes a few Hub blocks.
After `register-appchain`, `status` prints `chain_registered=true`. The Hub gives a new chain the
next free id, whatever the spec says. So run `status` right before `register-appchain` and check
that `next_chain_id` is still N. If another team registered in between, write the spec again with
the new id M, set `chain_id = M`, and only then register; the uploaded code stays.

## 7. Start the collator

```sh
tog-collator --config collator.toml send --key owner.key transfer --to <SESSION_ADDRESS> --amount 1000000000000000000
tog-collator --config collator.toml send --key owner.key register-collator
```

`transfer` gives the session key 1 test-TOG on the Hub, above the 0.1 it needs to deliver
messages. `register-collator` bonds 100 test-TOG and names this node's network key and session key.

Run the node under systemd, so it restarts with the machine. `RUST_LOG=info` turns on its log;
without it the node writes nothing.

```ini
# /etc/systemd/system/mychain-collator.service
[Unit]
Description=mychain collator
After=network-online.target
Wants=network-online.target

[Service]
User=<YOU>
WorkingDirectory=/home/<YOU>/mychain
Environment=RUST_LOG=info
ExecStart=/home/<YOU>/.cargo/bin/tog-collator --config collator.toml run
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now mychain-collator
journalctl -u mychain-collator -f
```

Within a minute `status` shows, among others:

```
chain_registered=true
final_number=7
coretime_region=false
on_demand_balance=49993000000000000000
od_price=1000000000000000
collator=ok
```

`collator=ok` means this node may author blocks, and `final_number` grows as the Hub finalizes
them, by about one every 4 seconds on the devnet. The on-demand balance falls by `od_price` for every included block.

## 8. Use the chain

`tog` signs and reads transactions on your chain through the collator's JSON-RPC (`--rpc`, default
`127.0.0.1:9944`):

```sh
tog account <OWNER_ADDRESS>
# nonce=0
# free=1000000000000000000000
# reserved=0

tog send --key owner.key transfer --to <ANY_ADDRESS> --amount 1000000000000000
# submitted 0x3fab… (nonce 0)
# included in block 96 (0x5dab…) as transaction 0
#   extrinsic 0    balances   Transfer { from: 0xa167…, to: 0x7d4d…, amount: 1000000000000000 }
#   extrinsic 0    system     {"extrinsic_success":{…}}

tog events                 # the last 20 blocks' events; --from and --to for others
tog send --key owner.key remark "hello from mychain"   # a note, as an event of your chain
```

`tog send call <module>.<call> --args <hex>` sends any call of the runtime, with its arguments
in the bytes the runtime decodes.

A new account, or a message your chain sends out, reserves a small deposit from the sender: it
shows as `reserved` in `tog account`.

## 9. Move test-TOG between the Hub and the chain

Test-TOG on your chain is backed by the chain's sovereign account on the Hub. Test-TOG given at
genesis (`--balance`) has no such backing, so it can't leave the chain. To bring test-TOG in, send
it from the Hub:

```sh
tog-collator --config collator.toml send --key owner.key deposit-to-chain --to <OWNER_ADDRESS> --amount 20000000000000000000
```

A few blocks later `tog account <OWNER_ADDRESS>` shows 20 test-TOG more. To take it back out:

```sh
tog send --key owner.key withdraw --to <OWNER_ADDRESS> --amount 5000000000000000000
```

`withdraw` pays the Hub's message fee (about 0.0011 test-TOG) from your chain balance on top of
the amount. Once the Hub executes the message, the owner's Hub balance grows by 5 test-TOG.

## 10. A CGMP message to a demo chain

The testnet's demo chains accept calls to the `tog/remark` module from any chain, and record each
note with the chain and account that sent it. Send one to the token chain:

```sh
tog send --key owner.key remark "hello from mychain" --dest <TOKEN_CHAIN_ID>
#   extrinsic 0    cgmp       Sent { sender: 0xa167…, dest: ChainId(<TOKEN_CHAIN_ID>), nonce: 0 }
```

The message leaves with your chain's next finalized block. The destination's collators fetch its
body from your chain's candidates; on the devnet that took about two minutes. Then look at the
destination's events:

```sh
tog events --rpc <TOKEN_CHAIN_RPC>
#      31 inbox 0        remark     Remarked { source: <your chain id>, by: Account { chain: ChainId(<your chain id>), account: 0xa167… }, note: "hello from mychain" }
#      31 inbox 0        system     {"message":{"nonce":0,"outcome":"executed","source":<your chain id>}}
```

`outcome` is `executed` when the call ran, or the reason it failed. For your own chains, the
receiving collator can fetch messages faster from the sending chain's collator: list it under
`[sources]` in the receiving collator's `collator.toml` (guide, section 9). It is optional; without
it messages still arrive. You can't change the demo chains' collators, and you don't need to.

## 11. A region instead of on-demand (optional)

A region is a whole sale period (28 eras) of inclusion bought ahead. It costs 1000 test-TOG on the testnet, more than the same blocks on demand,
and is there to try the mechanism:

```sh
tog-collator --config collator.toml status | grep -E 'coretime_period|region_price'
tog-collator --config collator.toml send --key owner.key purchase-region \
  --period <CORETIME_PERIOD> --max-price 1000000000000000000000
```

`--period` is `coretime_period` for the current period, or one more for the next. The Hub refuses
the purchase above `--max-price`. Afterwards `status` shows `coretime_region=true`, and blocks in
that period don't draw on the on-demand balance. The guide's section 8 explains renewals and the
next period's price.

## 12. When something doesn't work

| What you see | Why | What to do |
|---|---|---|
| faucet: `429`, `limited: try again in …` | one drip per 24 h per address and per IP | wait, or ask a team member who already has test-TOG to `transfer` some |
| `send upload-code` waits 120 s and fails with `… last publish: Duplicate` | this exact code is already on the Hub | if `status` shows your `code_hash` with `code_status=accepted`, it is your own earlier upload: go on with `register-appchain`; otherwise change the runtime, or give the chain its own name in `tog new`, so its code hash differs |
| `code_status=rejected` | the validators' pre-check refused the Wasm | `tog build --release` runs the same check locally and says why |
| `chain_registered=false` after `register-appchain` was included | another chain registered since you wrote the spec, and the Hub gave yours the next free id | `status` shows `next_chain_id`; ask the testnet's operators which id your chain got, then write the spec and `chain_id` for it (step 6) |
| `collator=not_registered` | `register-collator` not included yet, or sent with a different key | step 7, with the key named in `collator =` |
| `collator=no_coretime`, `final_number` stops | the on-demand balance is below `od_price` | `fund-on-demand`; the chain resumes by itself |
| `the hand-off at height H is served by N peers all in one network group` | every Hub peer has the same ASN | list peers in two ASNs (step 5) |
| `none of the N Hub peers answered` | the peers are unreachable, or other TOG nodes on the same IP hold their connections | check the addresses and the firewall; run fewer nodes behind one IP |
| the node runs but `journalctl` shows nothing | `RUST_LOG` is not set | `Environment=RUST_LOG=info` (step 7) |
| `tog`: `too many requests` | the collator's RPC limits requests per second | `tog` retries for 10 s; send fewer requests in a row |
| `withdraw` included, but no test-TOG on the Hub | the chain had no backing for it (genesis balance), so the Hub refunded it on your chain | `deposit-to-chain` first (step 9) |
| a CGMP message never shows up at the destination | your chain's block with the message isn't final yet, or the destination is out of coretime | check your `final_number` grows; wait a few minutes |
| `tog`: `a note is at most 256 bytes` | the note is too long; nothing was sent | shorten the note |
| `outcome` names an error at the destination | the call was refused there: an unknown module, or not enough weight | `tog send remark` sets the weight for you |

If something else goes wrong, post the `status` output and the last lines of `journalctl -u
mychain-collator` where the testnet's operators can see them.
