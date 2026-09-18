# Cordiale — memoria persistente di progetto

> Documento operativo e storico del progetto. Aggiornare questo file quando
> cambiano architettura, requisiti, confini del repository, workflow o stato
> verificato. Le affermazioni sullo stato devono distinguere fatti osservati,
> decisioni concordate, ipotesi e attività ancora da verificare.

## 0. Stato sintetico

- **Nome del progetto e dell’app:** Cordiale.
- **Scopo:** client desktop nativo multipiattaforma per il server Grappa.
- **Stato corrente:** scaffold iniziale Rust/Slint presente; repository GitHub
  privato creato e primo commit pubblicato; compilazione e packaging demandati
  ai workflow GitHub Actions.
- **Implementazione applicativa:** ancora iniziale; il networking Grappa, il
  bootstrap, l’autenticazione e la messaggistica non sono ancora implementati.
- **Working tree Git:** `F:\Dev\Cordiale\git\`.
- **Repository remoto:** `https://github.com/Sythos/Cordiale`.
- **Branch principale:** `main`, con tracking di `origin/main`.
- **Commit iniziale pubblicato:**
  `7392f72b5d39ff59391097e4af70becff49cdc30`.
- **Ultimo aggiornamento di questa memoria:** 2026-09-18.

## 1. Visione e scopo

Cordiale deve offrire una GUI desktop nativa, semplice e mantenibile per
connettersi a Grappa, autenticarsi, visualizzare lo stato realtime, leggere e
inviare messaggi. Il client deve seguire il contratto esposto da Grappa senza
duplicare il server e senza parlare direttamente il protocollo IRC.

Cordiale deve:

1. permettere di scegliere un server Grappa all’avvio;
2. gestire più server e più profili/account per server;
3. autenticare profili esistenti con username/password o per-client token,
   secondo il protocollo reale;
4. stabilire la sessione REST e Phoenix Channels/WebSocket;
5. mostrare network, channel, query, messaggi e stato realtime;
6. fornire Settings essenziali, tema e predisposizione i18n;
7. mantenere una distribuzione nativa senza WebView o runtime esterni.

Cordiale non deve inventare capability lato client. Il codice e il
comportamento effettivo del server Grappa restano l’autorità finale per
versioni, endpoint, ruoli, autenticazione, guest e compatibilità.

## 2. Fonti e autorità tecniche

### 2.1 Contratto client Grappa

Fonte primaria da studiare e seguire:

<https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>

La documentazione è il punto di partenza per REST, bootstrap, autenticazione,
Phoenix Channels, eventi e compatibilità. Prima di dichiarare implementata una
capability occorre verificare sia il contratto documentato sia il comportamento
del server reale.

### 2.2 Cicchetto

Fonte funzionale di riferimento:

<https://github.com/vjt/grappa-irc/tree/main/cicchetto>

Cicchetto serve a raccogliere funzionalità e opzioni da valutare, ma non è la
base architetturale di Cordiale. Prima delle funzionalità estese va prodotta e
mantenuta `docs/feature-matrix.md`, con almeno:

- funzionalità/opzione osservata;
- disponibilità nel protocollo Grappa;
- supporto previsto in Cordiale;
- fase prevista;
- note su differenze UX, limiti e compatibilità.

## 3. Decisioni architetturali concordate

### 3.1 Stack

- Linguaggio: Rust.
- GUI: Slint.
- Workspace Rust con core condivisibile e crate UI/eseguibile separato.
- Nessun WebView, Chromium, Node.js o runtime esterno nel prodotto.
- `cordiale-core` deve contenere modello, protocollo, persistenza e servizi
  condivisibili; la GUI dipende dal core, non il contrario.

### 3.2 Protocollo e rete

- REST per configurazione, login e bootstrap secondo il contratto Grappa.
- Phoenix Channels/WebSocket per la sessione realtime.
- Prima tranche funzionale: `/api/config`, autenticazione, `/boot`, `/me`,
  `network`, `channel`, `query`, invio/ricezione messaggi e stato realtime.
- Parser wire permissivo e forward-compatible:
  - ignorare campi sconosciuti;
  - ignorare eventi sconosciuti quando non bloccanti;
  - rispettare `protocol_version`;
  - rispettare `min_protocol_version`;
  - produrre errori espliciti quando la compatibilità minima non è rispettata.
- Riconnessione, errori di rete, timeout e chiusure di channel devono essere
  modellati nel core e non nascosti dalla GUI.

### 3.3 Server, profili e identità

- Server predefinito iniziale: `irc.sindro.me`.
- All’avvio: server selezionato in modo esplicito, poi identità/profilo.
- Modello previsto:

  ```text
  Server
    ├── profilo autenticato 1
    ├── profilo autenticato 2
    └── accesso guest (solo se il server lo espone davvero)
  ```

- Il ruolo admin è assegnato dal server dopo l’autenticazione; Cordiale non lo
  deduce da campi locali.
- Il percorso `Continue as guest` è ammesso solo dopo aver verificato nel
  codice Grappa e nel contratto effettivo che l’istanza supporti davvero
  accesso guest/visitor. La documentazione client esaminata finora descrive
  chiaramente account/client-token, ma non congela da sola un contratto guest.

### 3.4 GUI, tema e lingua

- Fase 1: interfaccia in English.
- Predisposizione interna i18n in `resources/i18n/en/`.
- Settings deve avere un dropdown `Language`, inizialmente con il solo valore
  English.
- Temi iniziali tramite design token Slint:
  - Light classico bianco;
  - Dark scuro.
- La GUI iniziale deve privilegiare stato di connessione leggibile, errori
  espliciti, selezione server/profilo e percorso di login semplice.

### 3.5 Persistenza locale

- Non usare `localStorage`.
- Directory preferita: `~/.cordiale/`.
- File previsti:
  - `settings.json` per preferenze non sensibili;
  - `servers.json` per server, profili e selezione corrente;
  - archivio credenziali separato dal JSON delle impostazioni.
- Un profilo ricordato identifica server, username e riferimento alla
  credenziale, non una password in chiaro.

### 3.6 Credenziali

Astrarre un `CredentialStore` con backend per piattaforma:

- Windows: DPAPI, legata all’account Windows corrente;
- Linux: Secret Service/libsecret quando disponibile;
- fallback eventuale: reversibile/offuscato, esplicitamente limitato a
  protezione casuale e leggibilità immediata, non a sicurezza reale.

Regole:

- non salvare password in chiaro in `settings.json`;
- non stampare token o password nei log;
- non introdurre una master password implicita senza una decisione esplicita;
- documentare sempre il limite del fallback locale;
- mantenere distinto il token per-client dalla password se il protocollo lo
  distingue, anche quando il server li accetta nello stesso campo.

## 4. Requisiti di distribuzione

### Windows

- Target x64 e ARM64.
- Installer unsigned NSIS 2.
- La compilazione e la generazione dell’installer devono avvenire in un
  runner GitHub Actions; non si costruisce localmente.
- La toolchain NSIS esatta da fissare nel runner è ancora un’attività aperta.
  Lo scaffold workflow produce intanto un archivio Windows verificabile.

### Linux

- Target x64 e ARM64.
- `.tar.gz` standalone.
- `.deb` multiarch.
- Distribuzioni di riferimento: Debian 13 Trixie e Ubuntu 26.04 LTS.
- Build, cross-linker e generazione `.deb` devono avvenire su runner GitHub;
  la macchina di sviluppo non deve produrre artefatti di release.

## 5. Confini delle directory

### 5.1 Working tree del client

`F:\Dev\Cordiale\git\` contiene esclusivamente materiale del client:

- sorgenti Rust e Slint;
- workspace e manifest del client;
- risorse runtime/i18n;
- documentazione del client e della sua architettura;
- file di packaging e workflow GitHub Actions necessari al client;
- `MEMORY.md`, richiesto come documento persistente nella root della working
  tree;
- file Git essenziali del repository.

Struttura attuale:

```text
git/
├── .github/workflows/
│   ├── ci.yml
│   └── packages.yml
├── crates/
│   ├── cordiale-core/
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   └── cordiale-ui/
│       ├── Cargo.toml
│       ├── build.rs
│       ├── src/main.rs
│       └── ui/appwindow.slint
├── docs/feature-matrix.md
├── packaging/
│   ├── linux/README.md
│   └── windows/README.md
├── resources/i18n/en/README.md
├── .gitignore
├── Cargo.toml
├── MEMORY.md
└── README.md
```

### 5.2 Materiale fuori repository

Tool, harness, fixture, suite operative e materiale ausiliario non devono
entrare in `git\`. Le aree predisposte sono:

- `F:\Dev\Cordiale\tools\` — script operativi, generatori, utility e
  strumenti di packaging/verifica non distribuiti con il client;
- `F:\Dev\Cordiale\tests\` — suite operative/end-to-end, fixture e harness;
- `F:\Dev\Cordiale\git_refresh.ps1` — helper interattivo per il refresh
  dell’autenticazione GitHub e del credential helper Git.

I test unitari strettamente necessari a un crate possono vivere accanto al
codice Rust e viaggiare con il client; i test operativi e le fixture restano
fuori dalla working tree.

## 6. Scaffold creato

### Workspace

Il `Cargo.toml` root definisce un workspace resolver 2 con due membri:

- `crates/cordiale-core` (`cordiale-core`, libreria, Rust 2021);
- `crates/cordiale-ui` (`cordiale-ui`, eseguibile, Rust 2021).

Il core contiene solo il perimetro iniziale, il nome applicativo stabile e un
segnaposto per la policy di compatibilità. La UI contiene:

- dipendenza locale dal core;
- dipendenze Slint (`slint` e `slint-build`);
- `build.rs` per compilare `ui/appwindow.slint`;
- finestra minima con titolo Cordiale e testo di scaffold.

Il codice è intenzionalmente piccolo: non deve essere interpretato come
implementazione già completata di rete, autenticazione o protocollo.

### Risorse e packaging

- `resources/i18n/en/` è il punto d’ingresso per le stringhe English.
- `packaging/linux/` documenta i futuri `.tar.gz` e `.deb`.
- `packaging/windows/` documenta l’installer unsigned NSIS 2.
- `docs/feature-matrix.md` è il template della matrice Cicchetto → Cordiale.

## 7. Workflow GitHub-only

### `ci.yml`

Trigger:

- push su `main`;
- pull request.

Runner:

- `ubuntu-latest`;
- `windows-latest`.

Controlli previsti:

1. installazione del toolchain Rust stable nel runner;
2. `cargo fmt --all -- --check`;
3. `cargo check --workspace`;
4. `cargo test --workspace`.

### `packages.yml`

Trigger:

- avvio manuale (`workflow_dispatch`);
- tag `v*`.

Matrice iniziale:

| Target | Runner | Artefatti previsti |
|---|---|---|
| `x86_64-unknown-linux-gnu` | Ubuntu | `.tar.gz`, `.deb` `amd64` |
| `aarch64-unknown-linux-gnu` | Ubuntu + linker cross | `.tar.gz`, `.deb` `arm64` |
| `x86_64-pc-windows-msvc` | Windows | archivio Windows |
| `aarch64-pc-windows-msvc` | Windows | archivio Windows |

Il workflow:

- installa Rust stable e il target nel runner;
- installa `gcc-aarch64-linux-gnu` per il target Linux ARM64;
- compila `cordiale-ui` in release nel runner;
- crea `.tar.gz` e `.deb` Linux con `dpkg-deb`;
- crea archivi Windows;
- carica gli artefatti come output del workflow.

L’installer NSIS 2 non è ancora attivato: la versione e il provisioning del
builder Windows devono essere fissati prima di dichiarare completato quel
deliverable. Nessun artefatto locale deve essere considerato release.

## 8. Git e GitHub: regole vincolanti

- Repository: privato, nome esatto `Cordiale`, owner `Sythos`.
- Remote previsto e pubblicato: `origin -> https://github.com/Sythos/Cordiale.git`.
- Branch iniziale: `main`.
- Identità obbligatoria per ogni commit e operazione attribuibile:
  `Sythos <sythos@gmail.com>`.
- Non aggiungere altre identità, trailer, firme, coautori o attribuzioni nei
  commit, issue, release, workflow metadata o testi GitHub.
- I messaggi Git/GitHub devono descrivere solo il progetto e il cambiamento.
- Non inserire token, password, cookie o output sensibile nei file, nei log o
  nei messaggi.
- Stage ristretto ai file del client richiesti; non includere `tools\`,
  `tests\` o fixture esterne.
- Evitare riscritture distruttive della storia pubblicata; ogni correzione
  successiva deve essere un commit nuovo, salvo autorizzazione esplicita.

### Helper `git_refresh.ps1`

`F:\Dev\Cordiale\git_refresh.ps1`:

- richiede `git` e `gh` nel `PATH`;
- esegue il refresh interattivo per `github.com`;
- può avviare un login web solo con `-LoginOnRefreshFailure`;
- configura il credential helper tramite `gh auth setup-git`;
- verifica lo stato finale tramite `gh auth status`;
- non stampa né salva valori segreti;
- non modifica l’identità Git `Sythos <sythos@gmail.com>`.

La sintassi dello script è stata verificata con il parser PowerShell; lo
script non è stato eseguito durante la preparazione per non avviare un flusso
di login interattivo senza necessità.

## 9. Piano di lavoro

### Fase 0 — Fondazioni e compatibilità

- [x] Creare `F:\Dev\Cordiale\` e `git\` come working tree.
- [x] Inizializzare Git sul branch `main`.
- [x] Configurare l’identità locale `Sythos <sythos@gmail.com>`.
- [x] Creare il repository GitHub privato `Sythos/Cordiale`.
- [x] Collegare `origin` e pubblicare il commit iniziale.
- [x] Aggiungere lo scaffold Rust/Slint.
- [x] Aggiungere workflow GitHub-only per verifica e packaging iniziale.
- [x] Separare tools e test operativi fuori da `git\`.
- [ ] Studiare integralmente `CLIENT_PROTOCOL.md` e annotare il contratto.
- [ ] Analizzare Cicchetto e completare la matrice delle funzionalità.
- [ ] Fissare la strategia finale di packaging NSIS 2.

### Fase 1 — Client minimo funzionante

- [ ] Implementare modello server/profili e selezione all’avvio.
- [ ] Implementare persistenza `~/.cordiale/` e migrazioni/versionamento.
- [ ] Implementare `CredentialStore` con DPAPI e Secret Service/libsecret.
- [ ] Implementare `/api/config`, autenticazione, `/boot` e `/me`.
- [ ] Implementare Phoenix Channels/WebSocket, join, heartbeat e
  riconnessione.
- [ ] Implementare `network`, `channel`, `query`, messaggi e stato realtime.
- [ ] Implementare Settings, Light/Dark e selettore Language English.
- [ ] Aggiungere parser permissivo e test di compatibilità.
- [ ] Eseguire tutti i test nel workflow GitHub, non localmente.

### Fase 2 — Parità e rifinitura

- [ ] Aggiungere lingue oltre English.
- [ ] Valutare le opzioni Cicchetto una per una tramite la matrice.
- [ ] Rifinire UX, accessibilità, performance e diagnostica.
- [ ] Verificare il percorso guest/visitor nel server prima di implementarlo.

### Fase 3 — Release

- [ ] Pin della toolchain NSIS 2 nel workflow Windows.
- [ ] Installer unsigned Windows x64/ARM64.
- [ ] `.tar.gz` Linux x64/ARM64.
- [ ] `.deb` Linux `amd64`/`arm64` per Debian 13 Trixie e Ubuntu 26.04 LTS.
- [ ] Smoke test, manifest, checksum e documentazione installazione.

## 10. Decision log dettagliato

| Data | Decisione | Stato | Conseguenza |
|---|---|---|---|
| 2026-09-18 | Nome app/progetto: Cordiale. | Confermata | Nome usato in workspace, GUI e repository. |
| 2026-09-18 | Client nativo, non client IRC diretto. | Confermata | La logica parla con Grappa tramite il suo contratto client. |
| 2026-09-18 | Rust + Slint. | Confermata | GUI nativa senza WebView/Chromium/Node/runtime esterni. |
| 2026-09-18 | Core separato dalla UI. | Confermata | Testabilità e minore accoppiamento. |
| 2026-09-18 | REST + Phoenix Channels/WebSocket. | Confermata | Aderenza alla documentazione client Grappa. |
| 2026-09-18 | Grappa è autorità finale. | Confermata | Nessuna capability guest/admin inventata localmente. |
| 2026-09-18 | Parser permissivo. | Confermata | Forward compatibility con campi/eventi sconosciuti. |
| 2026-09-18 | Default server `irc.sindro.me`. | Confermata | Selezione iniziale precompilata, modificabile. |
| 2026-09-18 | Multi-server e multi-profilo. | Confermata | Il server precede la scelta dell’identità. |
| 2026-09-18 | Guest solo se supportato realmente. | Aperta/verifica | Serve analisi del codice Grappa e del contratto effettivo. |
| 2026-09-18 | Config sotto `~/.cordiale/`. | Confermata | Niente `localStorage`; settings/server separati. |
| 2026-09-18 | CredentialStore astratto. | Confermata | DPAPI Windows, Secret Service/libsecret Linux. |
| 2026-09-18 | Fallback offuscato solo come protezione casuale. | Confermata | Mai presentarlo come sicurezza crittografica reale. |
| 2026-09-18 | Fase 1 solo English con i18n predisposto. | Confermata | Risorse in `resources/i18n/en/`, Language nei Settings. |
| 2026-09-18 | Light/Dark tramite design token Slint. | Confermata | Due temi iniziali, estendibili. |
| 2026-09-18 | Cicchetto solo riferimento funzionale. | Confermata | Nessun vincolo architetturale derivato dal codice. |
| 2026-09-18 | `git\` solo materiale client. | Confermata | Tools, harness e test operativi fuori working tree. |
| 2026-09-18 | Build e packaging GitHub-only. | Confermata | Nessuna compilazione o release locale. |
| 2026-09-18 | Repository GitHub privato `Sythos/Cordiale`. | Confermata | Origin e push configurati. |
| 2026-09-18 | Identità unica `Sythos <sythos@gmail.com>`. | Vincolo | Nessun’altra attribuzione o trailer. |

## 11. Traccia operativa verificata

1. La directory `F:\Dev\Cordiale\` era presente e priva di progetto
   applicativo; `git\` non esisteva.
2. È stata creata `F:\Dev\Cordiale\git\`.
3. È stato scritto il primo `MEMORY.md`, poi ampliato con i confini tra
   client e materiale operativo.
4. È stato creato `F:\Dev\Cordiale\git_refresh.ps1` e verificato con il
   parser PowerShell.
5. Sono state create `tools\` e `tests\` fuori dalla working tree, ciascuna
   con README di confine.
6. È stato inizializzato Git con branch `main` e identità locale esatta.
7. È stato aggiunto lo scaffold Rust/Slint e la documentazione iniziale.
8. È stato creato il commit iniziale `7392f72b...`, autore e committer
   `Sythos <sythos@gmail.com>`.
9. Il repository privato `Sythos/Cordiale` è stato creato e il commit è stato
   inviato a `origin/main`.
10. Sono stati aggiunti `ci.yml` e `packages.yml` per spostare verifiche,
    compilazione e packaging sui runner GitHub.
11. La verifica locale con `cargo metadata`/`cargo fmt` non è stata eseguita:
    `cargo` non è disponibile nel PATH della macchina corrente e la policy
    concordata vieta compilazioni locali.

## 12. Verifiche ancora necessarie

- Verificare dal workflow GitHub che lo scaffold Slint compili su Ubuntu e
  Windows.
- Verificare la sintassi e l’esecuzione reale dei workflow sul repository.
- Aggiungere e validare `Cargo.lock` tramite il runner quando lo scaffold
  dipendenze sarà stabilizzato.
- Fissare toolchain/versione NSIS 2 e generare installer unsigned nei runner.
- Verificare il packaging Debian su entrambe le distribuzioni richieste.
- Studiare il codice server Grappa per guest/visitor e capability admin.
- Validare endpoint, payload, eventi e reconnection contro il server reale.
- Aggiungere test di parser e wire protocol in `crates/` o nell’area test
  prevista, senza spostare harness operativi dentro `git\`.

## 13. Rischi e limiti dichiarati

- Lo scaffold attuale non è un client Grappa funzionante.
- La dipendenza Slint è dichiarata con major version `1`; il lockfile e la
  versione esatta saranno fissati dal workflow quando il progetto inizierà la
  verifica riproducibile.
- La compatibilità Linux ARM64 richiede linker e dipendenze cross nel runner.
- Un fallback locale delle credenziali non protegge da un attaccante con pieno
  accesso al profilo utente.
- Guest/visitor non va implementato per analogia con Cicchetto senza prova nel
  server Grappa.
- Una build verde dello scaffold non equivale a compatibilità completa del
  protocollo né a una release pronta.

## 14. Prossima sequenza raccomandata

1. Lasciare che `ci.yml` verifichi lo scaffold sul repository remoto.
2. Correggere eventuali errori di build esclusivamente tramite commit e
   workflow GitHub.
3. Leggere `CLIENT_PROTOCOL.md` e il codice Grappa con una matrice di endpoint,
   payload ed eventi.
4. Analizzare Cicchetto e completare `docs/feature-matrix.md`.
5. Implementare nel core prima modello/protocollo, poi persistenza e rete.
6. Collegare la GUI al core con stati espliciti e testabili.
7. Aggiungere credential backend nativi senza esporre segreti.
8. Stabilizzare i workflow prima di dichiarare pronti `.deb`, tarball e NSIS.
