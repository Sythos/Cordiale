# Cordiale — memoria persistente di progetto

## Identità, visione e scopo

- **Nome del progetto e dell’app:** Cordiale.
- Cordiale è un client desktop nativo multipiattaforma per il server Grappa.
- Lo scopo è offrire una GUI desktop semplice, affidabile e mantenibile per
  connettersi a Grappa, autenticarsi, seguire lo stato realtime e leggere o
  inviare messaggi.
- Cordiale **non parla IRC direttamente**: usa le API e il protocollo client
  esposti da Grappa.
- Il codice e il comportamento del server Grappa sono l’autorità finale per
  capability, autenticazione e compatibilità.

## Decisioni architetturali

### Stack e distribuzione

- Linguaggio: Rust.
- GUI: Slint.
- Non usare WebView, Chromium, Node.js o runtime esterni.
- Target Windows: x64 e ARM64, installer unsigned NSIS 2.
- Target Linux: x64 e ARM64, pacchetto `.tar.gz` standalone e `.deb` per
  Debian 13 Trixie e Ubuntu 26.04 LTS, entrambe multiarch.

### Confini del sistema

- Workspace separato tra protocollo/core e interfaccia, indicativamente:
  `cordiale-core` per modello, protocollo e networking; `cordiale-ui` o un
  eseguibile separato per la GUI.
- `F:\Dev\Cordiale\git\` contiene esclusivamente il materiale del client:
  sorgenti Rust/Slint, risorse runtime, documentazione del client e file di
  packaging/versionamento necessari al progetto.
- Tool operativi, script ausiliari, harness, fixture e suite di test esterne
  restano fuori dalla working tree, sotto `F:\Dev\Cordiale\tools\` e
  `F:\Dev\Cordiale\tests\` (o directory sorelle analoghe).
- I test unitari indispensabili e distribuiti insieme a un crate possono
  vivere accanto al relativo codice Rust; i test operativi/end-to-end e le
  fixture non entrano in `git\`.
- Protocollo basato su REST + Phoenix Channels/WebSocket secondo la
  documentazione upstream:
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>.
- Prima di implementare funzionalità estese analizzare
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto> e produrre una
  matrice `Cicchetto -> Cordiale`. Cicchetto è riferimento per funzionalità e
  opzioni, non per l’architettura.
- Parser wire permissivo e forward-compatible: ignorare campi ed eventi
  sconosciuti e rispettare `protocol_version` / `min_protocol_version`.

### GUI, temi e internazionalizzazione

- Fase 1 in inglese.
- Predisporre internamente i18n con `resources/i18n/en/` e un dropdown
  `Language` nei Settings; inizialmente disponibile solo English.
- Temi iniziali tramite design token Slint:
  - Light classico bianco;
  - Dark scuro.

### Server, profili e autenticazione

- All’avvio mostrare la selezione del server Grappa; default iniziale:
  `irc.sindro.me`.
- Supportare più server e più profili/account per server.
- Per utenti con profilo o ruolo admin usare username/password oppure
  per-client token, secondo il protocollo reale del server.
- Prevedere il percorso guest/visitor solo se è realmente supportato e
  dichiarato dal server; verificare prima il codice Grappa e il contratto
  effettivo dell’accesso guest.
- Il ruolo admin è determinato dal server dopo l’autenticazione, non dalla
  GUI.

### Configurazione e credenziali locali

- Non usare `localStorage`.
- Preferire `~/.cordiale/` con:
  - `settings.json` per preferenze non sensibili;
  - `servers.json` per server e profili selezionabili;
  - gestione credenziali separata dal JSON delle impostazioni.
- Astrarre un `CredentialStore`:
  - Windows: DPAPI;
  - Linux: Secret Service/libsecret quando disponibile;
  - eventuale fallback locale reversibile/offuscato solo come protezione
    casuale, dichiarata esplicitamente come **non sicurezza reale**.
- Non memorizzare password in chiaro in `settings.json` e non introdurre una
  master password implicita senza una decisione futura esplicita.

## Requisiti funzionali prioritari

La Fase 1 deve fornire un client funzionante con almeno:

1. configurazione e selezione dei server;
2. chiamata a `/api/config`;
3. autenticazione e bootstrap (`/boot` + `/me`);
4. Phoenix Channels/WebSocket;
5. gestione `network`, `channel` e `query`;
6. invio e ricezione dei messaggi;
7. stato realtime;
8. Settings essenziali, inclusi tema e lingua predisposta.

La Fase 2 comprende i18n multilingua, maggiore parità con le opzioni di
Cicchetto, ulteriori temi e rifiniture UX.

## Piano e fasi

### Fase 0 — Fondazioni e compatibilità

- [x] Creare la working tree Git in `F:\Dev\Cordiale\git`.
- [x] Definire questa memoria persistente e registrare le decisioni iniziali.
- [x] Aggiungere `F:\Dev\Cordiale\git_refresh.ps1` per il refresh interattivo
  dell’autenticazione GitHub e del credential helper Git.
- [x] Creare lo scaffold client Rust/Slint, le risorse i18n iniziali e gli
  spazi di packaging sotto `git\`.
- [x] Creare le aree esterne `tools\` e `tests\` per materiale non client.
- [ ] Creare il repository GitHub privato `Cordiale` e collegare `origin`.
- [ ] Leggere e annotare il contratto `CLIENT_PROTOCOL.md`.
- [ ] Analizzare Cicchetto e produrre la matrice delle funzionalità.
- [x] Definire workspace Rust, crate core/UI e strategia iniziale di packaging.

### Fase 1 — Client minimo funzionante

- [ ] Scaffolding Rust + Slint senza runtime esterni.
- [ ] Modello server/profili e persistenza locale.
- [ ] CredentialStore con backend nativi e fallback esplicitamente limitato.
- [ ] `/api/config`, autenticazione, `/boot`, `/me`.
- [ ] Client Phoenix Channels/WebSocket e gestione riconnessione.
- [ ] Network/channel/query, messaggi e stato realtime.
- [ ] Schermata iniziale, Settings, temi Light/Dark e lingua English.
- [ ] Test di protocollo, parsing permissivo e casi di errore.

### Fase 2 — Parità e rifinitura

- [ ] i18n multilingua.
- [ ] Parità selettiva delle funzionalità/opzioni di Cicchetto.
- [ ] Rifiniture UX, accessibilità e performance.
- [ ] Verifica reale del percorso guest/visitor prima dell’implementazione.

### Fase 3 — Packaging e release

- [ ] Build Windows x64/ARM64 e installer unsigned NSIS 2.
- [ ] Build Linux x64/ARM64 `.tar.gz` standalone.
- [ ] Build `.deb` per Debian 13 Trixie e Ubuntu 26.04 LTS, multiarch.
- [ ] Smoke test su ogni target e documentazione di installazione.

## Decision log

| Data | Decisione | Motivazione / conseguenza |
|---|---|---|
| 2026-09-18 | Il nome del progetto/app è Cordiale. | Identità stabile per codice, GUI e repository. |
| 2026-09-18 | Client nativo Rust + Slint. | Evitare WebView/Chromium/Node e runtime esterni. |
| 2026-09-18 | Grappa è l’autorità del protocollo. | Evitare di duplicare o inventare capability lato client. |
| 2026-09-18 | REST + Phoenix Channels/WebSocket. | Aderenza a `CLIENT_PROTOCOL.md`. |
| 2026-09-18 | Core/protocollo separato dalla GUI. | Testabilità, manutenzione e futura evoluzione. |
| 2026-09-18 | Configurazione in `~/.cordiale/`; credenziali separate. | Nessun `localStorage` e nessuna password in chiaro nel settings JSON. |
| 2026-09-18 | DPAPI su Windows, Secret Service/libsecret su Linux. | Protezione nativa senza credenziali aggiuntive. |
| 2026-09-18 | Guest solo dopo verifica nel codice/server Grappa. | Non assumere un contratto guest non documentato. |
| 2026-09-18 | Cicchetto è riferimento funzionale, non architetturale. | Riutilizzare conoscenza di prodotto senza vincolare il design. |
| 2026-09-18 | Fase 1 solo English, i18n predisposto. | Ridurre lo scope iniziale mantenendo l’estensibilità. |
| 2026-09-18 | `git\` contiene solo materiale del client. | Tenere tools, harness, fixture e test operativi fuori dal repository. |
| 2026-09-18 | Identità Git/GitHub vincolata a Sythos. | Usare esclusivamente `Sythos <sythos@gmail.com>`; vietati riferimenti a Codex, Claude, AI e `Co-authored-by`. |

## Avanzamento corrente

- Stato: **scaffold client iniziale pronto; repository remoto in attesa di autenticazione valida**.
- Directory radice: `F:\Dev\Cordiale\`.
- Working tree prevista: `F:\Dev\Cordiale\git\`.
- `MEMORY.md`: presente in questa root e contiene visione, decisioni,
  requisiti, piano, log e avanzamento.
- Helper autenticazione: `F:\Dev\Cordiale\git_refresh.ps1`, verificato con
  parser PowerShell; non eseguito durante questa preparazione.
- Aree operative esterne: `F:\Dev\Cordiale\tools\` e
  `F:\Dev\Cordiale\tests\`, entrambe con README di confine.
- Repository remoto GitHub privato e primo push: da completare dopo la
  disponibilità di credenziali GitHub valide.
- Codice applicativo: non ancora implementato.
- Ultimo aggiornamento: 2026-09-18.

## Note operative

- Ogni modifica deve mantenere separati core/protocollo, UI e persistenza.
- Prima di dichiarare una capability supportata verificare il comportamento
  reale del server Grappa e il protocollo documentato.
- I commit pubblici devono usare esclusivamente l’identità Git dell’utente:
  `Sythos <sythos@gmail.com>`.
- Non inserire mai nei messaggi, trailer o metadati Git/GitHub riferimenti a
  Codex, Claude, AI, bot o `Co-authored-by`.
