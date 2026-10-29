# Tutorijal: vaš prvi AppChain na javnom testnetu

Ovaj tutorijal vodi tim od nule do AppChain-a koji radi na javnom TOG testnetu, korak po korak. Na
kraju ćete imati test-TOG sa faucet-a, registrovan lanac sa coretime-om, kolator na sopstvenoj
mašini, test-TOG prebačen između Hub-a i vašeg lanca i CGMP poruku isporučenu jednom od demo
lanaca testneta. [Vodič za AppChain](appchain-guide.sr.md) detaljnije objašnjava svaki deo; ova
stranica je najkraći put koji radi.

Svaki korak je izvršen na lokalnom devnetu komandama ispod. Ere od 1800 Hub blokova i sesije od 300
su vrednosti zatvorenog testneta dok se javni testnet ne pokrene. Vrednosti koje se objavljuju sa
pokretanjem, među njima i network id, napisane su kao `<PLACEHOLDER>` (tabela u koraku 4).

Test-TOG nema vrednost. Ništa što se kupi ili zaradi na testnetu ne prelazi na mainnet.

## 0. Šta vam treba

- Linux x86-64 mašina za kolator, dostupna Hub peer-ovima koje navedete, sa oko 15 GB slobodnog
  diska. Razvoj radi i na macOS-u.
- Rust stable sa Wasm target-om: `rustup target add wasm32-unknown-unknown`.
Alati, `tog` (razvojni alat SDK-a), `tog-collator` i `tog-cli`, dolaze kao Linux x86-64
binarni fajlovi uz svako izdanje testneta, na `<RELEASE_URL>`. Runtime crate-ovi dolaze iz ovog
repozitorijuma; `tog new` ih zakucava.

Iznosi na komandnoj liniji su u osnovnim jedinicama: 1 test-TOG = 10^18 osnovnih jedinica, pa je
50 test-TOG `50000000000000000000`.

## 1. Napravite lanac

```sh
tog new mychain --template minimal
cd mychain
tog test
tog build --release
```

`tog build --release` piše `target/tog/mychain_runtime.wasm` i ispisuje njegov `code_hash`.
Templejt `minimal` je token lanac testneta: balansi, asset-i, `sudo`, CGMP i modul `tog/remark`
koji se koristi u koraku 10. `runtime/src/lib.rs` menjajte kasnije; za ovaj tutorijal izgradite ga
kakav jeste.

## 2. Ključevi

```sh
tog-collator new-author-key --out owner.key     # ispisuje adresu vlasnika, 0x...
tog-collator new-author-key --out session.key   # ispisuje adresu session ključa
chmod 600 owner.key session.key
```

Da bi tutorijalu bio dovoljan jedan zahtev faucet-u, ključ vlasnika radi dva posla: on je menadžer
lanca (otprema kod, registruje lanac, kupuje coretime) i bond nalog kolatora. Na pravom lancu
možete da ih razdvojite (vodič, odeljak 7). Session ključ potpisuje blokove i poruke koje kolator
isporučuje Hub-u. Napravite rezervnu kopiju oba fajla; izgubljen ključ niko ne može da povrati.

## 3. Test-TOG sa faucet-a

Otvorite https://faucet.theonlygrid.com i nalepite adresu vlasnika, ili pitajte API faucet-a
direktno:

```sh
curl -X POST --data <OWNER_ADDRESS> https://faucet-api.theonlygrid.com/drip
# sent 10100 TOG to 0x… (in by height N)
```

Faucet šalje 10 100 test-TOG, jednom u 24 sata po adresi i po IP adresi. Drugi zahtev sa iste IP
adrese, čak i za drugu adresu, dobija `429` sa `limited: try again in …`. Zato session ključ dobija
test-TOG od vlasnika (korak 7), a ne sa faucet-a. Ako veb stranica prikazuje proveru (captcha),
koristite stranicu: API tada odbija zahteve bez nje.

Jedan zahtev pokriva ceo tutorijal:

| Šta | test-TOG | Korak |
|---|---|---|
| depozit za kod, 0,0001 po bajtu otpremanja (templejt minimal ima oko 128 000 bajtova) | oko 13 | 6 |
| depozit za genesis glavu | oko 0,02 | 6 |
| on-demand coretime: 0,001 po bloku, blokovi za oko jedan dan | 50 | 6 |
| session ključ: `MinSenderBalance` Hub-a je 0,1 | 1 | 7 |
| bond kolatora, `CollatorBond` | 100 | 7 |
| depozit na lanac | 20 | 9 |
| region, opciono | 1000 | 11 |

Depoziti i bond ostaju rezervisani na nalogu vlasnika dok postoje kod, lanac i kolator. Coretime se
troši.

Balans na Hub-u proverite sa `tog-cli account <OWNER_ADDRESS> --config client.toml --data-dir
~/tog/cli` (`client.toml` iz vodiča za workere, odeljak 6).

## 4. Fajlovi testneta

```sh
curl -fsSL -o hub-genesis.borsh <GENESIS_URL>
```

| Placeholder | Šta |
|---|---|
| `<NETWORK_ID>` | network id javnog testneta |
| `<RELEASE_URL>` | izdanje testneta sa `tog`, `tog-collator` i `tog-cli` |
| `<GENESIS_URL>` | `genesis.borsh` javnog testneta |
| `<BOOTNODE_1>`, `<BOOTNODE_2>`, ... | Hub full čvorovi, `/ip4/.../tcp/.../p2p/<peer id>` |
| `<ASN_1>`, `<ASN_2>`, ... | mreža (ASN) svakog bootnode-a, iz `asn.txt` u kitu testneta |
| `<TOKEN_CHAIN_ID>` | chain id demo token lanca |
| `<TOKEN_CHAIN_RPC>` | javni JSON-RPC demo token lanca, `host:port` |

## 5. Konfiguracija kolatora

Napišite `collator.toml` u `mychain/`:

```toml
chain_id = 0                     # postavlja se u koraku 6
network_id = <NETWORK_ID>
runtime = "target/tog/mychain_runtime.wasm"
genesis = "spec/genesis.bin"
network_key = "network.key"      # pravi se ako ne postoji
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

Navedite peer-ove u najmanje dva različita ASN-a. Kolator prihvata svaki novi skup validatora samo
kada mu peer-ovi iz dve mreže serviraju isti; ako su svi peer-ovi u jednom ASN-u, prestaje da prati
Hub na kraju prve ere. Otvorite TCP port 30700 u firewall-u. Držite `rpc` na `127.0.0.1` osim ako
želite da lanac servirate drugima.

Proverite da kolator dopire do Hub-a:

```sh
tog-collator --config collator.toml status
```

Ispisuje `hub_height=…` i, između ostalog, `next_chain_id=N`: id koji će vaš lanac dobiti.

## 6. Registrujte lanac

Napišite chain spec sa tim id-jem. `--balance` daje nalogu test-TOG na vašem lancu od prvog bloka;
`--root` čini vlasnika `sudo` ključem lanca.

```sh
tog chain-spec --runtime target/tog/mychain_runtime.wasm --chain-id <N> --network-id <NETWORK_ID> \
  --authority <OWNER_ADDRESS> --balance <OWNER_ADDRESS>=1000000000000000000000 \
  --root <OWNER_ADDRESS> --out spec/
```

Postavite `chain_id = <N>` u `collator.toml`. Zatim otpremite kod, sačekajte pre-check validatora,
registrujte lanac i unapred platite coretime. Svaki `send` potpisuje sa `--key`, čeka da Hub uključi
transakciju i ispisuje visinu:

```sh
tog-collator --config collator.toml send --key owner.key upload-code
tog-collator --config collator.toml status | grep code_status    # ponavljajte dok ne bude code_status=accepted
tog-collator --config collator.toml send --key owner.key register-appchain --spec spec/chain-spec.toml
tog-collator --config collator.toml send --key owner.key fund-on-demand --amount 50000000000000000000
```

`upload-code` šalje veliki runtime u više transakcija. Pre-check traje nekoliko Hub blokova. Posle
`register-appchain`, `status` ispisuje `chain_registered=true`. Hub daje novom lancu sledeći slobodan
id, bez obzira na to šta piše u spec-u, pa `register-appchain` prvo proverava da je `next_chain_id`
na Hub-u i dalje vaš `chain_id`. Ako je drugi tim u međuvremenu registrovao lanac, staje sa
`the Hub's next chain id is M, not N: write the chain spec and chain_id again with it`: ponovo
napišite spec sa M, postavite `chain_id = M` i ponovo registrujte; otpremljen kod ostaje.

## 7. Pokrenite kolator

```sh
tog-collator --config collator.toml send --key owner.key transfer --to <SESSION_ADDRESS> --amount 1000000000000000000
tog-collator --config collator.toml send --key owner.key register-collator
```

`transfer` daje session ključu 1 test-TOG na Hub-u, iznad 0,1 koliko mu treba da isporučuje poruke.
`register-collator` zalaže 100 test-TOG i imenuje mrežni ključ i session ključ ovog čvora.

Pokrenite čvor pod systemd-om, da se pokreće zajedno sa mašinom. `RUST_LOG=info` uključuje njegov
log; bez toga čvor ne piše ništa.

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

Za minut `status` pokazuje, između ostalog:

```
chain_registered=true
final_number=7
coretime_region=false
on_demand_balance=49993000000000000000
od_price=1000000000000000
collator=ok
```

`collator=ok` znači da ovaj čvor sme da pravi blokove, a `final_number` raste kako ih Hub
finalizuje, na devnetu otprilike jedan na svake 4 sekunde. On-demand balans se smanjuje za `od_price` za svaki uključen blok.

## 8. Koristite lanac

`tog` potpisuje i čita transakcije na vašem lancu preko JSON-RPC-a kolatora (`--rpc`, podrazumevano
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

tog events                 # događaji poslednjih 20 blokova; --from i --to za druge
tog send --key owner.key remark "hello from mychain"   # beleška, kao događaj vašeg lanca
```

`tog send call <module>.<call> --args <hex>` šalje bilo koji poziv runtime-a, sa argumentima u
bajtovima koje runtime dekodira.

Nov nalog, ili poruka koju vaš lanac šalje napolje, rezerviše mali depozit od pošiljaoca: vidi se
kao `reserved` u `tog account`.

## 9. Prebacite test-TOG između Hub-a i lanca

Test-TOG na vašem lancu pokriven je suverenim nalogom lanca na Hub-u. Test-TOG dat u genezi
(`--balance`) nema takvo pokriće, pa ne može da napusti lanac. Da biste uneli test-TOG, pošaljite ga
sa Hub-a:

```sh
tog-collator --config collator.toml send --key owner.key deposit-to-chain --to <OWNER_ADDRESS> --amount 20000000000000000000
```

Nekoliko blokova kasnije `tog account <OWNER_ADDRESS>` pokazuje 20 test-TOG više. Da ga vratite:

```sh
tog send --key owner.key withdraw --to <OWNER_ADDRESS> --amount 5000000000000000000
```

`withdraw` plaća naknadu Hub-a za poruku (oko 0,0011 test-TOG) iz balansa na vašem lancu, pored
iznosa. Kada Hub izvrši poruku, balans vlasnika na Hub-u poraste za 5 test-TOG.

## 10. CGMP poruka demo lancu

Demo lanci testneta prihvataju pozive modulu `tog/remark` sa bilo kog lanca i beleže svaku belešku
sa lancem i nalogom koji ju je poslao. Pošaljite jednu token lancu:

```sh
tog send --key owner.key remark "hello from mychain" --dest <TOKEN_CHAIN_ID>
#   extrinsic 0    cgmp       Sent { sender: 0xa167…, dest: ChainId(<TOKEN_CHAIN_ID>), nonce: 0 }
```

Poruka odlazi sa sledećim finalizovanim blokom vašeg lanca. Kolatori odredišta preuzimaju njeno
telo iz kandidata vašeg lanca; na devnetu je to trajalo oko dva minuta. Zatim pogledajte događaje
odredišta:

```sh
tog events --rpc <TOKEN_CHAIN_RPC>
#      31 inbox 0        remark     Remarked { source: <id vašeg lanca>, by: Account { chain: ChainId(<id vašeg lanca>), account: 0xa167… }, note: "hello from mychain" }
#      31 inbox 0        system     {"message":{"nonce":0,"outcome":"executed","source":<id vašeg lanca>}}
```

`outcome` je `executed` kada se poziv izvršio, ili razlog zbog kog nije uspeo. Za vaše sopstvene
lance, kolator koji prima poruke može brže da ih preuzme od kolatora lanca koji šalje: navedite ga
pod `[sources]` u `collator.toml` kolatora koji prima (vodič, odeljak 9). To je opciono; bez toga
poruke i dalje stižu. Kolatore demo lanaca ne možete da menjate, a i ne morate.

## 11. Region umesto on-demand-a (opciono)

Region je ceo prodajni period (28 era) uključivanja kupljen unapred. Na testnetu košta 1000
test-TOG, više nego isti blokovi on-demand, i služi da se mehanizam isproba:

```sh
tog-collator --config collator.toml status | grep -E 'coretime_period|region_price'
tog-collator --config collator.toml send --key owner.key purchase-region \
  --period <CORETIME_PERIOD> --max-price 1000000000000000000000
```

`--period` je `coretime_period` za tekući period, ili za jedan više za sledeći. Hub odbija kupovinu
iznad `--max-price`. Posle toga `status` pokazuje `coretime_region=true`, a blokovi u tom periodu ne
troše on-demand balans. Odeljak 8 vodiča objašnjava obnove i cenu sledećeg perioda.

## 12. Kada nešto ne radi

| Šta vidite | Zašto | Šta da radite |
|---|---|---|
| faucet: `429`, `limited: try again in …` | jedan zahtev u 24 h po adresi i po IP adresi | sačekajte, ili zamolite člana tima koji već ima test-TOG da vam pošalje `transfer`-om |
| `send upload-code` čeka 120 s i ne prolazi sa `… last publish: Duplicate` | baš ovaj kod je već na Hub-u | ako `status` pokazuje vaš `code_hash` sa `code_status=accepted`, to je vaše ranije otpremanje: nastavite sa `register-appchain`; inače promenite runtime, ili dajte lancu sopstveno ime u `tog new`, da mu se code hash razlikuje |
| `code_status=rejected` | pre-check validatora je odbio Wasm | `tog build --release` lokalno pokreće istu proveru i kaže zašto |
| `register-appchain`: `the Hub's next chain id is M, not N` | drugi lanac je registrovan pošto ste napisali spec | napišite spec sa M i postavite `chain_id = M` (korak 6), pa ponovo registrujte |
| `chain_registered=false` posle uključenog `register-appchain` | drugi lanac je registrovan pošto ste napisali spec, pa je Hub vašem dao sledeći slobodan id | `status` pokazuje `next_chain_id`; pitajte operatere testneta koji id je vaš lanac dobio, pa napišite spec i `chain_id` za njega (korak 6) |
| `collator=not_registered` | `register-collator` još nije uključen, ili je poslat drugim ključem | korak 7, sa ključem navedenim u `collator =` |
| `collator=no_coretime`, `final_number` stoji | on-demand balans je ispod `od_price` | `fund-on-demand`; lanac nastavlja sam |
| `the hand-off at height H is served by N peers all in one network group` | svi Hub peer-ovi imaju isti ASN | navedite peer-ove u dva ASN-a (korak 5) |
| `none of the N Hub peers answered` | peer-ovi su nedostupni, ili drugi TOG čvorovi na istoj IP adresi drže njihove konekcije | proverite adrese i firewall; pokrenite manje čvorova iza jedne IP adrese |
| čvor radi, ali `journalctl` ne pokazuje ništa | `RUST_LOG` nije postavljen | `Environment=RUST_LOG=info` (korak 7) |
| `tog`: `too many requests` | RPC kolatora ograničava broj zahteva u sekundi | `tog` ponavlja 10 s; šaljite manje zahteva zaredom |
| `withdraw` je uključen, ali nema test-TOG na Hub-u | lanac nije imao pokriće za njega (balans iz geneze), pa ga je Hub vratio na vaš lanac | prvo `deposit-to-chain` (korak 9) |
| CGMP poruka se nikad ne pojavi na odredištu | blok vašeg lanca sa porukom još nije finalan, ili odredište nema coretime | proverite da vaš `final_number` raste; sačekajte nekoliko minuta |
| `tog`: `a note is at most 256 bytes` | beleška je preduga; ništa nije poslato | skratite belešku |
| `outcome` na odredištu navodi grešku | poziv je tamo odbijen: nepoznat modul ili premalo weight-a | `tog send remark` sam postavlja weight |

Ako nešto drugo ne radi, objavite izlaz `status`-a i poslednje linije `journalctl -u
mychain-collator` tamo gde ih operateri testneta vide.
