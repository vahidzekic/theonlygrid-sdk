# Pravljenje i pokretanje AppChain-a na TOG testnetu

Ovaj vodič je za programere koji žele svoj lanac na TOG-u: AppChain. Pokriva ceo put, od prazne
fascikle do lanca čije blokove Hub finalizuje na testnetu. Svaka komanda i svaki ključ konfiguracije
ispod je ono što kod na `main` prihvata. Vrednosti koje još nisu objavljene napisane su kao
`<PLACEHOLDER>`.

Za prvi lanac, korak po korak, počnite od [tutorijala](appchain-tutorial.sr.md).

Test-TOG, token testneta, nema vrednost. Njime se na testnetu plaćaju otpremanje koda, coretime i
bond kolatora. Ništa što se njime kupi ili zaradi ne prelazi na mainnet.

## 1. Šta je AppChain

AppChain je blockchain sa sopstvenim runtime-om i stanjem, koji obezbeđuje TOG Hub (TOG-SPEC-0007).

- **Runtime** je Wasm modul napravljen TOG SDK-om (crate-ovi `tog-runtime-*`): moduli za balanse,
  asset-e, upravljanje (`sudo`), poruke (CGMP), compute poslove i vašu logiku.
- **Kolatori** pokreću čvor lanca, `tog-collator`. Prave blokove i šalju ih Hub validatorima kao
  kandidate.
- **Hub** validatori ponovo izvršavaju svaki kandidat nad registrovanim kodom lanca i finalizuju
  njegovu glavu. Korisnici lanca veruju Hub-u, ne kolatorima.
- **Coretime** je ono što lanac plaća Hub-u da bi mu blokovi bili uključeni: on-demand (unapred
  uplaćen balans koji se troši po bloku) ili region (period kupljen unapred). Bez coretime-a
  blokovi se prave, ali se nikad ne uključuju, i lanac stoji (odeljak 8).
- **CGMP** poruke prenose test-TOG i pozive između lanca, Hub-a i drugih AppChain-ova
  (TOG-SPEC-0007 §4.6). Preko njih lanac može da traži compute poslove i storage deal-ove i da ih
  plati.

## 2. Zahtevi

| | |
|---|---|
| OS | Linux ili macOS za razvoj; Linux na x86-64 za kolator na testnetu |
| Rust | stable, sa target-om `wasm32-unknown-unknown` (`rustup target add wasm32-unknown-unknown`) |
| Disk | oko 15 GB za build SDK-a i binarnih fajlova |
| Docker | opciono, za `tog build --image`: code hash koji svako može da ponovi iz izvora |

Alati, `tog` (razvojni alat SDK-a), `tog-collator` i `tog-cli`, dolaze kao Linux x86-64
binarni fajlovi uz svako izdanje testneta, na `<RELEASE_URL>`. Runtime crate-ovi dolaze iz ovog
repozitorijuma; `tog new` ih zakucava.

## 3. Novi lanac

```sh
tog new mychain --template minimal
cd mychain
```

`tog new` pravi Cargo workspace: `runtime/src/lib.rs` (runtime), `runtime/src/weights.rs` (težine
poziva), `runtime/tests/runtime.rs` (testovi) i `README.md`. SDK dolazi iz svog git
repozitorijuma, a commit drži `Cargo.lock` workspace-a: `--sdk-git <url>` (ili `TOG_SDK_REPO`) bira
drugi repozitorijum ili mirror, `--sdk-rev` commit ili tag, a sa `--sdk <checkout>` build ide nad
lokalnom kopijom.

Svaki šablon je jedan od četiri referentna lanca koji rade na testnetu, spreman za kopiranje:

| Šablon | Šta ima | Referentni lanac |
|---|---|---|
| `minimal` | standardne module: balanse, asset-e, `sudo`, CGMP (test-TOG ka Hub-u i nazad, pozivi drugim lancima), compute zahteve | token lanac |
| `compute` | modul koji traži poslove i obrađuje njihove verifikovane rezultate u `on_compute_result` | compute lanac |
| `storage` | registar fajlova: korisnici imenuju sadržaj koji se čuva u Hub storage deal-ovima | skladišni lanac |
| `reserved` | vezuje rezervaciju kapaciteta radnika zakupljenu za lanac (TOG-SPEC-0015) i na njoj pokreće poslove | lanac za rezervisani kapacitet |

Krenite od šablona koji je najbliži vašoj ideji, pa menjajte `runtime/src/lib.rs`. Svaki modul je
običan Rust: pozivi, stanje i događaji, sa pravilima dispečovanja iz TOG-SPEC-0007 §4.

## 4. Testiranje

```sh
tog test
```

Ovo pokreće `cargo test` nativno, nad lancem u memoriji iz `tog-runtime-test`. Hub, drugi lanci i
rezultati poslova su simulirani: test može da postavi unos u Hub stanju, isporuči CGMP poruku ili
zada rezultat posla, uključujući greške. Testovi šablona pokazuju svaki od ovih slučajeva.
Argumenti posle `--` idu u `cargo test`.

## 5. Lokalno pokretanje

```sh
tog dev                 # Hub validatori, registrovan lanac, jedan kolator
tog dev --workers       # još tri radnika i tri storage čvora, za compute i skladište
```

`tog dev` pravi runtime, pokreće lokalni devnet i drži ga dok ne pritisnete Ctrl-C. Ispisuje id
lanca, JSON-RPC adresu kolatora (`rpc=http://…`) i razvojni nalog sa sredstvima i tajnim ključem.
Fascikla devneta se briše na izlazu.

JSON-RPC odgovara na `tog_heads`, `tog_header`, `tog_block`, `tog_blockHash`,
`tog_events`, `tog_query`, `tog_chain` i `tog_submitTx`, a glave šalje kroz
`tog_subscribeHeads` kao `tog_head` obaveštenja (TOG-SPEC-0007 §9).

## 6. Build i težine

```sh
tog build --release
tog bench --runtime target/tog/mychain_runtime.wasm --out runtime/src/weights.rs
```

`tog build --release` proverava Wasm onako kako će ga proveriti Hub validatori (TOG-SPEC-0007
§8.2) i upisuje ga u `target/tog/` zajedno sa Zstd verzijom za otpremanje. Ispisuje `code_hash`,
hash koji Hub registruje. Sa `--image <ime>@sha256:<digest>` build ide u tom kontejner image-u, pa
svako može iz vašeg izvora da dobije isti code hash.

`tog bench` pokrenite ponovo posle svake izmene poziva. Težina bloka se proverava prema težinama iz
`weights.rs`, a validatori mogu da odbiju poziv koji košta više nego što je prijavljeno.

## 7. Pokretanje na testnetu

Lancu trebaju tri naloga, svi secp256k1 ključevi napravljeni sa `tog-collator new-author-key --out
<fajl>`. Fajlove ključeva držite sa dozvolama 0600: kolator odbija ključ koji drugi mogu da čitaju.

| Nalog | Radi | Treba mu |
|---|---|---|
| menadžer | otprema kod, registruje lanac, kupuje coretime | depozit za kod (0,0001 test-TOG po bajtu otpremanja), depozit za genesis glavu i coretime koji uplaćujete unapred |
| bond kolatora | vezuje kolatora (`RegisterCollator`); Aura autoritet lanca | `CollatorBond`, 100 test-TOG (TOG-SPEC-0007 §8.5) |
| ključ sesije | pečati blokove kolatora i potpisuje `DeliverCgmp` | najmanje 0,1 test-TOG (Hub-ov `MinSenderBalance`) |

Test-TOG se dobija sa faucet-a na `<FAUCET_URL>`.

**1. Konfiguracija kolatora.** Komande ispod se pokreću u workspace-u lanca (`mychain/`), pored
`collator.toml`:

```toml
chain_id = 0                     # postavlja se u koraku 2
network_id = <NETWORK_ID>
runtime = "target/tog/mychain_runtime.wasm"  # iz `tog build --release`
genesis = "spec/genesis.bin"
network_key = "network.key"      # pravi se ako ne postoji
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

Ostavite `data_dir` postavljen. Čvor tu čuva lanac i posle restarta nastavlja odatle. Tu čuva i
poslednje provereno Hub zaglavlje, u `data_dir/hub-checkpoint`, a `status`, `send` i `output`
kreću od tog fajla umesto da prate Hub od njegovog genesis-a.

Navedite Hub peer-ove u najmanje dva različita ASN-a. Light client prihvata novi set validatora
(predaju ere) tek kad isti set posluže peer-ovi iz dva ASN-a. Ako su svi peer-ovi u jednom ASN-u,
kolator prestaje da prati Hub na kraju prve ere.

**2. Chain spec.** Pitajte Hub koji id će lanac dobiti, pa napravite runtime, genesis i spec lanca
sa tim id-jem:

```sh
tog-collator --config collator.toml status | grep next_chain_id
tog chain-spec --runtime target/tog/mychain_runtime.wasm --chain-id <NEXT_CHAIN_ID> \
  --network-id <NETWORK_ID> --authority <BOND_ACCOUNT> \
  --balance <ACCOUNT>=<BASE_UNITS> --root <SUDO_ACCOUNT> --out spec/
```

Upišite `chain_id = <NEXT_CHAIN_ID>` u `collator.toml`. Bez `--root` lanac nema `sudo` ključ i menja
se samo nadogradnjama koje šalje njegovo upravljanje. Spec nosi i pravila za skup radnika
(`--min-isolation`, `--min-bond`, `--min-reputation`, `--min-gpus`): šta moraju da imaju radnici
koji izvršavaju poslove lanca. Ako neki drugi lanac prvi zauzme taj id, napravite spec ponovo sa
novim.

**3. Otpremanje koda.** Svaka komanda ispod potpisuje sa `--key`, čita nonce sa Hub-a, šalje i čeka
dok Hub ne uključi transakciju:

```sh
tog-collator --config collator.toml send --key manager.key upload-code
```

Veliki runtime ide u više transakcija. Zatim sačekajte da `status` ispiše
`code_status=accepted`: validatori prvo proveravaju kod (TOG-SPEC-0007 §8.2).

**4. Registracija lanca i kupovina coretime-a.**

```sh
tog-collator --config collator.toml send --key manager.key register-appchain --spec spec/chain-spec.toml
tog-collator --config collator.toml send --key manager.key fund-on-demand --amount <BASE_UNITS>
```

`status` tada ispisuje `chain_registered=true`. Odeljak 8 kaže koliko coretime-a da kupite.

**5. Registracija i pokretanje kolatora.**

```sh
tog-collator --config collator.toml send --key bond.key register-collator
tog-collator --config collator.toml run
```

`register-collator` vezuje bond nalog uz `network_key` čvora i ključ sesije. Čvor pokrećite preko
systemd-a, da bi se podigao sa mašinom.

**6. Provera.**

```sh
tog-collator --config collator.toml status
```

`collator=ok` znači da ovaj čvor sme da pravi blokove. `final_number` raste kako Hub finalizuje
blokove lanca.

## 8. Coretime

Na testnetu blok košta on-demand cenu, `od_price`, koja nikad ne pada ispod 0,001 test-TOG
(mainnet: 0,1 TOG). Cena raste kad mnogo lanaca istovremeno kupuje on-demand blokove. Sa blokovima
od 2 sekunde, jedan test-TOG po najnižoj ceni plaća oko 1 000 blokova, otprilike pola sata, a 50
test-TOG oko jednog dana.

Region je ceo period (28 era) kupljen unapred. Dok ga lanac ima, njegovi blokovi u tom periodu ne
koštaju ništa više. Po cenama testneta region košta više od on-demand-a:

```sh
tog-collator --config collator.toml send --key manager.key purchase-region \
  --period <CORETIME_PERIOD> --max-price <BASE_UNITS>
```

`--period` je `coretime_period` iz `status`-a za tekući period, ili jedan više za sledeći. Hub odbija
kupovinu ako je cena veća od `--max-price`. Region sledećeg perioda se u prvih 7 era perioda prodaje
samo lancima koji imaju region tekućeg, kao produženje po najviše 105% plaćene cene. Posle toga ga
kupuje svako, uz dodatak na cenu koji tokom sledećih 7 era pada na nulu. `next_region_price` je
cena u tom trenutku.

`status` pokazuje šta lanac ima:

| Polje | Znači |
|---|---|
| `coretime_region` | `true` dok lanac ima region tekućeg perioda |
| `on_demand_balance` | preostali uplaćeni balans, u osnovnim jedinicama |
| `od_price` | koliko sada košta jedan uključen blok |
| `on_demand_blocks` | koliko još blokova balans plaća |
| `coretime_period` | tekući period prodaje |
| `next_coretime_region` | `true` kad lanac već ima region sledećeg perioda |
| `region_price` | koliko košta region tekućeg perioda |
| `next_region_price` | koliko sada košta region sledećeg perioda; `not_on_sale` dok ga ovaj lanac ne može kupiti |

Kolator upozorava u logu kad ostane manje od 600 blokova, a prijavljuje grešku kad ne ostane
nijedan. Lanac bez coretime-a i dalje pravi blokove, ali ih Hub ne uključuje. Njegova finalna glava
stoji, a lanac sam nastavlja kad se uključi sledeći `fund-on-demand`. Prazan blok košta kao i pun,
pa i lanac bez saobraćaja troši coretime. Lanac sa regionom dobija upozorenje dok je prozor za
produženje otvoren, a region sledećeg perioda još nije kupljen.

## 9. Održavanje lanca

- **Nadogradnje.** Napravite novi runtime i probajte ga nad trenutnim stanjem lanca preko
  `tog_tryUpgrade` čvora (dostupan samo sa `rpc_unsafe = true`, pa taj RPC držite privatnim). Zatim
  otpremite kod i pošaljite nadogradnju kroz upravljanje lanca (TOG-SPEC-0007 §8.3). Kolatori nov
  kod preuzimaju sa Hub-a.
- **Ključevi sesije.** Za zamenu ključa sesije upišite novi ključ u `next_session_key`, pa pošaljite
  `set-collator-keys` potpisan bond ključem. Čvor prelazi na novi ključ kad ga Hub-ovo finalno
  stanje navede.
- **Više kolatora.** Svaki kolator ima svoj bond nalog, mrežni ključ i ključ sesije, i Aura je
  autoritet u stanju lanca.
- **Poruke iz drugih lanaca.** Ravni lanaca od kojih ovaj prima poruke navedite pod `[sources]`.
  To je opciono i samo ubrzava isporuku: bez toga čvor preuzima poruke iz kandidata lanca koji
  šalje.
- **Indeksiranje.** `indexer = "events.jsonl"` dopisuje svaki blok, njegove događaje i promene
  glave kao JSON redove.

## 10. Rešavanje problema

| `status` ili log kaže | Uzrok | Rešenje |
|---|---|---|
| `chain holds no coretime: PurchaseRegion or FundOnDemand` | on-demand balans je ispod `od_price` | `fund-on-demand` (odeljak 8) |
| `none of the N Hub peers answered` | Hub peer-ovi nisu dostupni, ili svaki prima najviše 4 konekcije sa jedne IP adrese, a drugi čvorovi na ovoj mašini drže sve | proverite adrese; držite manje TOG čvorova iza jedne IP adrese |
| `the hand-off at height H is served by N peers all in one network group` | svi Hub peer-ovi imaju isti `asn` | navedite peer-ove u dva ASN-a (odeljak 7) |
| `the Hub light client stays at height H …, S s behind` | nijedan peer ne služi blokove posle H: čvor je krenuo daleko iza Hub-a | ostavite `data_dir` postavljen, ili postavite `[hub] trusted` na skorije zaglavlje |
| `collator=not_registered` ili `collator not registered: send RegisterCollator` | bond nalog nije kolator ovog lanca | korak 5 |
| `collator=no_coretime` | kao u prvom redu | `fund-on-demand` |
| `the collator's record names another session key` | zapis na Hub-u i `session_key` se razlikuju | `set-collator-keys`, ili pravi fajl ključa |
| `code_status=rejected` | provera je odbila Wasm | `tog build --release` lokalno pokazuje istu proveru |
