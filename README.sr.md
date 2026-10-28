# The Only Grid AppChain SDK

[English version](README.md)

The Only Grid (TOG) je mreža nezavisnih operatera koji prodaju računarsku snagu, skladište i
protok preko jednog lanca za poravnanje, **Hub-a**. **AppChain** je vaš sopstveni blockchain nad
njim: logiku pišete u Rust-u, ona se prevodi u jedan deterministički WebAssembly runtime, kolator
koji vi pokrećete pravi blokove, a validatori Hub-a proveravaju i finalizuju svaki od njih. Vaš
lanac dobija bezbednost Hub-a, poruke ka drugim AppChain-ovima i direktan pristup tržištima
računarske snage i skladišta na Hub-u, bez sopstvenog skupa validatora.

Ovaj repozitorijum je SDK kojim se takav lanac pravi: runtime okvir, standardni moduli, makro za
module, okruženje za testove i četiri gotova šablona. Sve je `no_std` Rust i gradi se i za
`wasm32-unknown-unknown` i nativno.

> **Status: javni testnet.** SDK radi na javnom TOG testnetu, gde su tokeni test-TOG bez
> vrednosti. Kod još nije auditovan; audit standardnih modula je planiran pre mainneta.
> Interfejsi se mogu menjati između izdanja testneta.

## Sadržaj

- [Šta možete da napravite](#šta-možete-da-napravite)
- [Crate-ovi](#crate-ovi)
- [Standardni moduli](#standardni-moduli)
- [Pisanje modula: `#[tog_module]`](#pisanje-modula-tog_module)
- [Šabloni](#šabloni)
- [Testiranje: `tog-runtime-test`](#testiranje-tog-runtime-test)
- [Alati](#alati)
- [Kako lanac radi](#kako-lanac-radi)
- [Prvi koraci](#prvi-koraci)
- [Gradnja ovog repozitorijuma](#gradnja-ovog-repozitorijuma)
- [Dokumentacija](#dokumentacija)
- [Licenca](#licenca)

## Šta možete da napravite

- **Aplikacioni lanac sa sopstvenom logikom i stanjem**: nalozi i balansi u $TOG, sopstvena
  zamenljiva sredstva (assets), sopstveni moduli sa skladištem, pozivima, događajima i greškama.
- **Lanac koji kupuje računarsku snagu**: moduli traže poslove na tržištu računarske snage Hub-a
  (container image, ulazi, naknada i rok) i dobijaju rezultat u hook-u `on_compute_result`, u
  nekom kasnijem bloku. Rezultat može biti poravnat ili neuspešan, a lanac odlučuje šta radi sa
  svakim.
- **Lanac koji koristi decentralizovano skladište**: moduli čitaju ugovore o skladištenju na Hub-u
  na relay parent-u bloka i prihvataju samo fajlove koje važeći ugovor zaista čuva.
- **Lanac sa rezervisanim kapacitetom**: neko na Hub-u rezerviše deo jednog workera za lanac, a
  poslovi lanca se izvršavaju na tom delu pre otvorenog tržišta.
- **Lanac koji razgovara sa drugim lancima**: CGMP (Cross-Grid Message Passing) prenosi $TOG
  između lanca i Hub-a i poziva module na drugim AppChain-ovima, sa naknadama, rokovima i
  povraćajem.
- **Lanac koji sam sebe nadograđuje**: upravljanje (`sudo` ključ ili savet) odobrava novi runtime
  po njegovom code hash-u i lanac prelazi na njega bez fork-a.

## Crate-ovi

| Crate | Šta je |
|---|---|
| `tog-runtime-core` | `no_std` okvir: raspored ključeva stanja i tipizirane stavke skladišta (`StorageValue`, `StorageMap`, `StorageDoubleMap`, `StorageNMap`), ograničene kolekcije, dvodimenzionalne težine (`ref_time`, `proof_size`), origin-i i rezultati poziva, blokovi, inherenti, PoV i svedoci, potpisane transakcije, heširanje sa razdvojenim domenima, metapodaci modula i skladište u memoriji koje beleži svedoka. |
| `tog-runtime-io` | Runtime strana host ABI v1: uvozi za skladište, kriptografiju, čitanje Hub-a, CGMP i logove, lepak za izvoze, bump alokator i panic handler za Wasm build, i `pure` režim za verifikacione module. |
| `tog-runtime-macros` | `#[tog_module]`, koji iz običnog Rust opisa modula piše raspored skladišta, dispatch, događaje, greške, težine, hook-ove, benchmark-e, genesis konfiguraciju i metapodatke. |
| `tog-runtime-modules` | Standardni moduli i executive (ispod). |
| `tog-runtime-test` | Okruženje za testove: vaš runtime na lancu u memoriji sa simuliranim Hub-om, drugim lancima i tržištem računarske snage. |
| `tog-runtime-template` | Minimalni šablon runtime-a. |
| `tog-runtime-template-compute` | Šablon sa registrom modela koji se dotreniravaju preko tržišta računarske snage. |
| `tog-runtime-template-storage` | Šablon sa registrom fajlova nad ugovorima o skladištenju na Hub-u. |
| `tog-runtime-template-reserved` | Šablon čiji se poslovi izvršavaju na rezervaciji na Hub-u za lanac. |
| `tog-primitives`, `tog-types` | Zajednički tipovi protokola: identifikatori, iznosi, heševi, transakcije Hub-a, specifikacije i rezultati poslova, ugovori o skladištenju, CGMP poruke. Runtime preko njih čita Hub. |

## Standardni moduli

Svaki modul su obične funkcije nad bilo kojim `Storage` backend-om, pa isti kod radi u Wasm
runtime-u, u kolatoru i u nativnim testovima.

| Modul | Šta radi |
|---|---|
| `system` | Nonce-ovi naloga, broj bloka i `authorize_upgrade(code_hash)` za nadogradnju runtime-a. |
| `balances` | $TOG nalozi i prenosi, sa rasporedom naloga koji Hub čita kada korisnici izlaze sa lanca. |
| `assets` | Opciona zamenljiva sredstva pored $TOG, u stilu ERC-20: `create`, `mint`, `burn`, `transfer`, `approve`, `transfer_from`, `set_owner`. |
| `transaction_payment` | Naknade potpisanih transakcija: naplaćuju se po benchmark težini poziva plus napojnica, neiskorišćena težina se vraća posle izvršenja, a naknada ide kolatoru bloka. Lanac može da postavi svoje cene ili svoj obračun naknada. |
| `storage_deposit` | Depozit po bajtu za stanje koje poziv dodaje, vraća se kada se to stanje ukloni, pa stanje ne raste besplatno. |
| `collator_selection` | Koji kolator pravi koji blok (Aura), postavlja `Root`. |
| `sudo` | Opcioni ključ sa `Root` origin-om: `call`, `set_key`, `remove_key`. |
| `governance` | Opcioni savet sa `Root` origin-om, umesto `sudo` ili posle njega. |
| `cgmp` | Oba kraja kanala poruka: $TOG ka Hub-u (`withdraw`), pozivi modula na drugim AppChain-ovima (`send`), potvrde, istek roka i povraćaj onoga što Hub odbije, i `prune` završenih poruka. |
| `compute` | Poslovi na tržištu računarske snage Hub-a (`request`) i njihovi rezultati, isporučeni hook-u `on_compute_result` modula koji je tražio posao; obaveštenja `on_worker_slashed`. |
| `verify` | Ogledalo verifikacionih modula koji su na Hub-u vezani za lanac i proveravaju rezultate poslova. |
| `executive` | Ulazne tačke runtime-a nad ovim modulima: pravljenje i uvoz bloka, provera transakcija, inherenti, hook-ovi po redu i obračun težine. Vaši moduli se uključuju u njega. |

## Pisanje modula: `#[tog_module]`

Modul je ugnežđeni Rust modul; makro generiše ono što samo ponavlja ono što modul već kaže:

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

Šta generiše:

- **Skladište**: tipizirane konstante pod `storage_key("<modul>", "<stavka>")`, isti raspored
  ključeva kao na Hub-u, pa light klijenti i Hub mogu da dokažu vaše stanje.
- **Pozivi**: `enum Call` sa kodiranjem, `call_name`, `call_weight` i `dispatch` za runtime.
- **Događaji i greške**: Borsh kodiranje, `Event::deposit` i pretvaranje grešaka u
  `DispatchError` (sa `?` na čitanjima skladišta).
- **Hook-ovi**: `on_runtime_upgrade`, `on_initialize`, `on_idle`, `on_finalize`,
  `on_compute_result` i `on_worker_slashed`, svaki sa svojim ograničenjem težine.
- **Benchmark-i**: `#[benchmark(<poziv>)]` priprema najgori slučaj poziva; `tog bench` ga meri na
  Wasm runtime-u i piše `weights.rs`.
- **Genesis**: Borsh, `Default` genesis konfiguracija.
- **Metapodaci**: pozivi sa argumentima, stavke skladišta, događaji i greške, pa ih alati kao
  `tog events` i `tog send call` dekodiraju i kodiraju po imenu.

## Šabloni

`tog new` kopira jedan od njih u novi workspace. Svaki se gradi, testira i pokreće takav kakav je.

| Šablon | `tog new --template` | Dodaje standardnim modulima |
|---|---|---|
| `tog-runtime-template` | `minimal` | `remark`, beleška zapisana kao događaj, dostupna i drugim AppChain-ovima preko CGMP (`tog/remark`). |
| `tog-runtime-template-compute` | `compute` | `model_registry`: registracija modela, `fine_tune` preko posla na tržištu računarske snage i `publish` rezultata kao sledeće verzije. |
| `tog-runtime-template-storage` | `storage` | `file_registry`: imena fajlova koje čuvaju ugovori o skladištenju na Hub-u, osvežavanje kada se ugovori obnove, uklanjanje. |
| `tog-runtime-template-reserved` | `reserved` | `reserved_compute`: vezivanje rezervacije na Hub-u za lanac i `run` poslova na njoj pre otvorenog tržišta. |

`lib.rs` svakog šablona počinje punom tabelom poziva: indeksi modula, indeksi poziva i origin
koji svaki poziv traži.

## Testiranje: `tog-runtime-test`

`TestChain` pokreće vaš runtime nativno, blok po blok, kroz executive-ov sopstveni graditelj
blokova, pa test vidi isto što i kolator:

- transakcije se potpisuju razvojnim potpisima i ulaze u blok ili ne, kako runtime odluči;
  događaji i ishodi svakog bloka se mogu pročitati;
- svaki blok se ponovo uvozi na stanju roditelja i mora da dođe do istog state root-a, što hvata
  runtime koji nije deterministički;
- **CGMP okruženje**: `send_from` isporučuje poruku sa Hub-a ili drugog lanca sa pravim dokazima
  inbox-a, `take_sent` vraća ono što je lanac poslao, a `ack` odgovara na to;
- **okruženje za poslove**: `take_compute_requests` vraća poslove koje je lanac tražio,
  `complete` poravna ili obori posao na bilo koji način na koji posao može da se završi, a
  `refuse` čini da ga Hub odbije;
- `dispatch` izvršava poziv pod bilo kojim origin-om (`Root`, `Hub`, `Chain`).

```rust
let mut chain = TestChain::<Template>::new(ChainId(5), |author| genesis(author));
chain.submit(ALICE, transfer(BOB, 10));
chain.block();
assert_eq!(chain.outcomes(), vec![Ok(..)]);
```

## Alati

Alati dolaze kao Linux x86-64 binarni fajlovi uz svako izdanje testneta; ovaj repozitorijum sadrži
crate-ove nad kojima se lanac gradi.

**`tog`**, razvojni alat:

| Komanda | Šta radi |
|---|---|
| `tog new <ime> --template …` | Pravi workspace lanca iz šablona, sa zakucanom verzijom SDK-a. |
| `tog build --release` | Gradi Wasm runtime-a, proverava ga, zapisuje ga sa Zstd verzijom za upload i ispisuje code hash. Sa `--image` gradi u zakucanom kontejneru, pa svako može da dobije isti code hash. |
| `tog test` | Pokreće testove lanca nativno nad `tog-runtime-test`. |
| `tog bench` | Meri težine poziva na Wasm runtime-u i piše `weights.rs`. |
| `tog chain-spec` | Piše chain spec (runtime, genesis konfiguracija i `chain-spec.toml`) koji traži registracija: autori blokova, početni balansi, `sudo` ključ, verifikacioni moduli i uslovi za workere koji izvršavaju poslove lanca. |
| `tog dev` | Lokalni devnet sa validatorima Hub-a, vašim registrovanim lancem, kolatorom koji pravi blokove i nalogom sa sredstvima; sa `--workers` i workeri i čvorovi za skladište za poslove. |
| `tog account` | Nonce i balansi naloga na lancu koji radi. |
| `tog send transfer / withdraw / remark / call` | Potpisuje i šalje transakciju i ispisuje njene događaje. |
| `tog events` | Dekodirani događaji niza blokova. |

**`tog-collator`** pokreće lanac: pravi blokove, šalje ih sa dokazima Hub-u, služi JSON-RPC
klijentima, registruje lanac i postavlja runtime-ove (`tog-collator tx register-appchain`,
`tog-collator tx …`).

## Kako lanac radi

1. Izgradite runtime i napišete njegov chain spec.
2. Registrujete lanac na Hub-u. Hub mu daje sledeći chain id i čuva code hash njegovog runtime-a.
3. Kupite **coretime** na Hub-u: blokove na zahtev, plaćene po bloku, ili dužu rezervaciju.
4. Vaš kolator pravi blokove. Za svaki šalje Hub-u dokaz validnosti (blok i svedoka skladišta);
   validatori Hub-a ponovo izvršavaju runtime nad njim, a Hub finalizuje glavu lanca.
5. Poruke između vašeg lanca, Hub-a i drugih AppChain-ova putuju CGMP trakama čiji su koreni deo
   finalizovanog stanja, pa svaka strana može da dokaže šta je primila.
6. Poslovi koje modul zatraži izlaze u outbox bloka, izvršavaju se na workerima Hub-a i vraćaju
   se kao rezultati hook-u modula.

## Prvi koraci

[Tutorijal](docs/appchain-tutorial.sr.md) vodi lanac od `tog new` do blokova finalizovanih na
javnom testnetu i CGMP beleške poslate drugom lancu. [Vodič](docs/appchain-guide.sr.md) detaljnije
objašnjava svaki deo.

`tog new` uzima SDK iz git-a. Da biste gradili nad ovim repozitorijumom:

```sh
tog new moj-lanac --template minimal --sdk-git https://github.com/vahidzekic/theonlygrid-sdk
cd moj-lanac
tog test
tog build --release
tog dev            # lokalni devnet sa vašim lancem
```

`TOG_SDK_REPO` postavlja isti repozitorijum za svaki `tog new`; `--sdk-rev` zakucava tag ili
commit.

## Gradnja ovog repozitorijuma

Potreban je Rust sa ciljem `wasm32-unknown-unknown`.

```sh
rustup target add wasm32-unknown-unknown
cargo test --workspace
```

## Dokumentacija

- [AppChain tutorijal](docs/appchain-tutorial.sr.md) ([English](docs/appchain-tutorial.md))
- [AppChain vodič](docs/appchain-guide.sr.md) ([English](docs/appchain-guide.md))
- Svaki crate je dokumentovan u svom izvornom kodu; `cargo doc --workspace --open` gradi API
  dokumentaciju.

Komentari u kodu pominju specifikacije protokola po broju (na primer TOG-SPEC-0007, specifikacija
AppChain-a). Specifikacije još nisu objavljene.

## Licenca

Apache License 2.0, vidi [LICENSE](LICENSE).
