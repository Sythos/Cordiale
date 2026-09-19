# Note sul contratto client Grappa

Documento tecnico di riferimento per l'implementazione di Cordiale, prodotto
studiando la fonte primaria `CLIENT_PROTOCOL.md` di Grappa e, come
riferimento solo funzionale, la struttura del client `cicchetto`.

Fonti:
- **Primaria (autorevole):** <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>.
- **Riferimento funzionale (solo funzionalità, non architettura):** <https://github.com/vjt/grappa-irc/tree/main/cicchetto>.

Convenzione: "la documentazione dice" = contenuto verificato del
`CLIENT_PROTOCOL.md`; "sto inferendo" = deduzione non scritta esplicitamente
nella fonte. Il codice server Grappa resta l'autorità finale in caso di
dubbio o disaccordo con questo documento.

---

## 1. REST API

Il documento è dichiaratamente una guida, non una spec OpenAPI completa
("the source is authoritative... where they disagree, the code wins").
Molti endpoint sono citati per nome/scopo senza schema JSON integrale.

### Bootstrap
- **`GET /api/config`** — primo contatto, non autenticato, cacheable, va
  chiamato prima di autenticarsi o aprire il socket. Campi documentati:
  - `server` (string, sempre `"grappa"` per questa implementazione)
  - `version` (stringa release software; solo diagnostico, mai da usare per
    compatibilità)
  - `protocol_version` (int, protocollo attuale del server)
  - `min_protocol_version` (int, floor minimo accettato)
  - `push_content_encoding` (string, es. `"aes128gcm"`; capability separata
    dal `protocol_version` — vedi §3)

- **`GET /boot`** — endpoint di boot aggregato, evita fan-out di richieste al
  cold-start:
  ```
  { "networks": [...],                 // = GET /networks
    "channels": { "<slug>": [...] },   // = GET /networks/:network_id/channels
    "heads": { "<slug>": { "<chan>": [...] } } } // ultima pagina di history per canale
  ```
  `channels` ha una chiave per network posseduto; `heads` ha una chiave solo
  per i canali che hanno storia (assente, non `[]`, se non c'è storia).

- **`GET /me`** — risponde in bulk `read_cursors`, `unread_counts`,
  `badge_count`. Abbinato a `/boot`, un boot a freddo è due richieste, flat
  rispetto alla dimensione dell'account.

### Autenticazione
- **`POST /auth/login`** — body `{ "identifier": "...", "password": "..." }`.
  - Successo: `200 { "token": "...", "subject": {...} }`.
  - 2FA armato (TOTP o passkey): `202 two_factor_required` — non risolvibile
    da un client non presidiato come Cordiale, serve un browser.
  - Credenziali errate: `401 invalid_credentials`.
  - Throttling: `429 too_many_attempts` dopo 10 fallimenti da un indirizzo in
    15 minuti.

- **Token per-client** — pensato esattamente per un client come Cordiale che
  non può gestire TOTP/WebAuthn:
  - Si invia nello stesso campo `password` di `POST /auth/login`.
  - Il token è il bearer stesso: si può saltare `/auth/login` e presentarlo
    direttamente come `Authorization: Bearer <token>` (REST) o via
    subprotocollo WS (vedi §2).
  - Non scade per inattività (una sessione browser sì, dopo 7 giorni). Solo
    la revoca la termina.
  - Armare/disarmare/cambiare un secondo fattore sull'account **non** revoca
    i token già emessi.
  - **È scoped**: legge e invia come l'account, ma NON può toccare
    `/admin/*`, `/me/totp*`, `/me/passkeys*`, `DELETE /me`, né le route dei
    token stessi — quelle rispondono `403 client_token_scope` (errore di
    scope, non di credenziali: non va ritentato con retry).
  - Gestione token (lato owner, da sessione browser, non da Cordiale):
    `POST /me/client-tokens {label, password}` → `token` (una sola volta);
    `GET /me/client-tokens` → lista; `DELETE /me/client-tokens/:handle`.
  - Un token errato è indistinguibile da una password errata: stesso
    `401 invalid_credentials`, stesso throttle.

### Messaggi e canali
- **`POST /networks/:network_id/channels/:channel_id/messages`** — invia un
  PRIVMSG a `:channel_id` (e lo fa eco lì). Due campi opzionali mutuamente
  esclusivi (entrambi presenti → `400 bad_request`):
  - `ctcp_target` → eco come `kind: "privmsg"` con `meta.ctcp_target`.
  - `notice_target` (nick o canale) → eco come `kind: "notice"` con
    `meta.notice_target`.
  - Il destinatario va letto da `meta`, mai da `channel` (che resta la
    finestra sorgente).
- Backlog/paginazione per canale: `?before=`, `?after=`, `/messages/count`.
- **`GET /networks/:network_id/archive`** — `{target, kind, last_activity}`.
  Il campo `row_count` è stato **rimosso** alla v8 (unico caso di rimozione
  documentato — vedi §3).

### Network e canali
- **`GET /networks`** — include un oggetto `connection` con almeno
  `registered` (bool, identità ai servizi — twin REST dell'evento
  `session_identity_changed`, vedi §2).
- **`GET /networks/:network_id/channels`** — elenco canali per network.
- `:network_id` nel path è sempre uno **slug**, non un id numerico.

### Liste canale (mode tipo A: ban, ecc.)
- Nessun endpoint REST dedicato: query via verbo WebSocket `"banlist"`
  (campo opzionale `"mode"`, default `"b"`), risposta come evento
  `banlist_bundle`. Le lettere interrogabili sono esposte via
  `isupport_changed` (`chanmodes_a`, `list_modes_queryable`).

### DCC (trasferimento file peer-to-peer)
- `POST .../dcc_offers/:offer_id/accept` → `202 {"ok": true}`.
- `DELETE .../dcc_offers/:offer_id` → `200 {"ok": true}` (rifiuta; non
  invia nulla al peer).
- `GET .../dcc_offers` → `{"offers": [...]}`.
- `GET /dcc_files/:slug[.ext]` — top-level, **nessuna autenticazione**; lo
  slug (26 char base32) è di per sé il token d'accesso. Sempre
  `application/octet-stream` + `Content-Disposition: attachment` +
  `X-Content-Type-Options: nosniff`.
- `GET/PUT .../dcc-auto-accept` — `{"enabled": true|false}`.

### Impostazioni
- `GET`/`PUT /me/settings/display-prefs` — 7 chiavi (v24): `time_format`,
  `colored_nicklist`, `presence_filter`, `show_bottom_bar`,
  `strip_formatting`, `show_event_badge`, `bold_mentions`. Absent-tolerant in
  entrambe le direzioni.
- `GET /api/server-settings`, `GET /admin/settings` — dalla v26 espone anche
  `per_user_cap_bytes` e `per_visitor_cap_bytes`, leggibili ma non
  azionabili (rifiuto quota = `507 insufficient_storage` generico).

### Superfici solo-account (non accessibili da token per-client)
`/admin/*`, `/me/totp*`, `/me/passkeys*`, `DELETE /me` — richiedono sessione
browser piena; nessuno schema dettagliato nel documento.

---

## 2. Phoenix Channels / WebSocket

### Handshake
- Endpoint realtime: Phoenix Channels su `/socket/websocket`.
- **Autenticazione**: il bearer viaggia nell'header `Sec-WebSocket-Protocol`
  come `base64url.bearer.phx.<token>` — non nell'URL, per tenerlo fuori dagli
  access log. Bearer mancante/invalido → `403`.
- **Versione protocollo**: dichiarata via query param `client_proto`
  sull'URL di upgrade (va messo nei `params` del `Socket`, non nel path).
  - Sotto `min_protocol_version` → `426 Upgrade Required`, body
    `{"error": "upgrade_required", "protocol_version": N, "min_protocol_version": M}`.
  - Omesso → trattato come "current".
  - Non leggibile come intero → anche questo trattato come current, il
    connect ha successo ma la dichiarazione viene scartata silenziosamente.
  - Nessun limite superiore: non esiste (né esisterà) un
    `max_protocol_version`.
  - Il controllo versione avviene **prima** dell'autenticazione.
- **Payload iniziale**: il primo topic da joinare è il topic utente
  `grappa:user:{user}`; la risposta di join porta `protocol_version`:
  `join "grappa:user:vjt" → {:ok, {"protocol_version": 2}}` — un client che
  ha saltato `GET /api/config` lo impara comunque al connect.

### Topic
| topic | shape |
|---|---|
| user | `grappa:user:{user}` |
| network | `grappa:user:{user}/network:{slug}` |
| channel | `grappa:user:{user}/network:{slug}/channel:{chan}` |

- Il segmento canale è ASCII-folded lato server (solo A-Z): casing diverso
  atterra sulla stessa finestra, ma `#foo[1]` e `#foo{1}` sono topic
  **diversi**; il casing non-ASCII (`#CAFÉ` vs `#café`) **non** viene
  foldato.
- Una finestra query/DM usa come segmento il nick del peer, foldato allo
  stesso modo.
- I `kind` di evento non riconosciuti vanno ignorati (regola
  additive-only, §3).

### Eventi principali
- **Stato finestra** — `window_pending`, `window_invited`, e i terminali
  `joined`, `join_failed`, `kicked`: broadcast sul topic **utente**, non
  canale (il topic canale li emette solo come snapshot al join). Lo stato
  finestra va guidato dal topic utente fin dal connect.
- **Risposte solo-alla-connessione-richiedente**: `who_reply`,
  `names_reply`, `whois_bundle`, `whowas_bundle`, `server_reply`,
  `banlist_bundle`, `links_bundle` — sul topic utente ma solo al socket
  che ha inviato il comando. Eccezione: `lusers_bundle` fa fan-out a tutte
  le connessioni (anche non richiesto, al connect) — va consumato una volta.
- **Identità ai servizi**: `session_identity_changed` =
  `{"kind": "session_identity_changed", "network_id": N, "identified": bool, "account": string|null}`.
  `identified` è l'unico campo su cui basarsi (mai derivarlo da umode).
  `account` è solo display, può essere `null` anche con `identified: true`.
- **Muting presenza**: join sul topic canale con `{"presence": false}`
  sopprime `join`/`part`/`quit` per quel canale; mai soppressi:
  `nick_change`, `mode`, il proprio `join`/`part`/`quit`. Letto una sola
  volta al join (per cambiare va rifatto il join). Richiede
  `protocol_version >= 7`.
- **DCC**: `dcc_offer` = `{"kind", "network", "channel", "offer_id", "from", "filename", "size"}`;
  `dcc_offer_resolved` = `{"kind", "network", "channel", "offer_id", "resolution": "accepted"|"refused"|"expired"}`.
  Nessun campo `state`. Snapshot a freddo re-inviato al reconnect sul topic
  utente, o via `GET .../dcc_offers`.
- **Reason personalizzati** (v23): `quit_part_reason_changed`
  `{"quit_part_reason": string|null}`, `auto_away_reason_changed`
  `{"auto_away_reason": string|null}` — chiave sempre presente, `null` è
  significativo.
- **Liste canale**: `isupport_changed` porta `chanmodes_a` e
  `list_modes_queryable` — usare quest'ultimo per l'UI.
- **Modifiche di modo strutturali** (v25): righe `:mode` portano
  `meta.structural: true` quando il token cambia il canale (non un prefisso
  membro); assente su storico pre-v25 = "non noto, tratta come prima".
- **Rate limiting**: su un verbo WS oltre budget →
  `{"error": "rate_limited", "retry_after_ms": N}` (socket resta aperto).
  Flood sostenuto → `web_session_severed` `{"code": "rate_limit_flood"}` sul
  topic utente → bearer revocato → socket chiuso. La sessione IRC (bouncer)
  non viene toccata, solo quella web.

### Heartbeat / riconnessione
- **Non specificato esplicitamente** nel documento: nessun intervallo di
  heartbeat Phoenix né policy di backoff dichiarata. Consiglio implicito:
  `GET /boot` al cold-start e `?after=` per colmare i gap per canale al
  resume, per evitare un burst equivalente a un boot a freddo. Da verificare
  sul codice server (`GrappaWeb.UserSocket` / config `Grappa.Endpoint`) o sul
  comportamento di default di `phoenix.js` prima di implementare la
  riconnessione in Cordiale.

---

## 3. Versioning e compatibilità

- **`protocol_version`**: cosa parla il server ORA. Dal 2026-08-21 si muove
  per OGNI cambiamento di wire-shape, incluso quello additivo — inversione
  esplicita di una regola precedente. Motivo: l'additività descrive cosa
  EMETTE il server, non cosa RICHIEDE un client; un client che smette di
  tollerare un campo mancante può rompersi contro un server vecchio.
- **`min_protocol_version`**: il floor, si alza solo quando i client vecchi
  non possono più essere serviti (asse diverso, non segue i bump additivi).
- Esposti da `GET /api/config` e dalla risposta di join del topic utente.
- Il WS handshake applica il floor: sotto `min_protocol_version` via
  `client_proto` → `426 upgrade_required`.
- **Regola wire additive-only**: nuovi frame/eventi/campi possono comparire
  in qualsiasi momento; un verbo o campo sconosciuto non è mai fatale in
  nessuna delle due direzioni; i campi esistenti non vengono mai
  ripropositi con un significato diverso.
- **Rimozione = evento raro, non "mai"**: un solo caso documentato —
  `row_count` rimosso dall'entry di archivio alla v8.
- **Linee guida per un client**:
  - Un bump non è di per sé un avviso di rottura — solo
    `min_protocol_version` può rifiutare la connessione.
  - Confrontare con `>=`, mai `==`; mai usare la stringa `version` per il
    gating (solo diagnostica/CTCP VERSION).
  - Continuare a ignorare ciò che non si riconosce.
  - Se Cordiale rende un campo server obbligatorio, si è auto-alzato un
    floor interno: va registrato il `protocol_version` che ha introdotto
    quel campo e va rifiutato/degradato sotto quella soglia — mai inventare
    un valore per un campo che un server vecchio non ha mai mandato.
- **`push_content_encoding`** è una capability, non una versione: è cambiata
  senza muovere `protocol_version`. Un server senza questo campo va trattato
  come "troppo vecchio per push cifrato", non come un bug del client.

---

## 4. Entità di dominio

Il documento non fornisce schemi JSON completi entità-per-entità; quanto
segue è ricostruito da frammenti sparsi (marcato dove è inferenza).

- **network**: identificato da uno slug in ogni path `:network_id`. Ha un
  oggetto `connection` con almeno `registered` (bool). Elencati da
  `GET /networks` (e dentro `GET /boot`).
- **channel**: identificato da `:channel_id` (slug, presumibilmente stesso
  folding ASCII usato per i topic — *inferenza*). Ha: membri, topic, modes,
  read cursor, `window_counts`. Elencati da `GET /networks/:network_id/channels`.
- **query/DM**: stessa entità "channel" a livello di topic — il segmento è
  il nick del peer, foldato come un nome canale.
- **message/riga di scrollback**: ha un `kind` (`privmsg`, `notice`, `mode`,
  `server_event` almeno), un oggetto `meta` (`ctcp_target`,
  `notice_target`, `statusmsg`, `structural`), e `channel` = finestra
  sorgente (non il vero destinatario con `ctcp_target`/`notice_target`).
  Paginabile con `?before=`/`?after=`, contabile con `/messages/count`.
- **archive entry**: `{target, kind, last_activity}`.
- **presence/status**: `join`/`part`/`quit` per canale (sopprimibili);
  `session_identity_changed` per l'identità ai servizi; reason personalizzati
  per il subject stesso. Stato "away" dei **peer** non descritto
  esplicitamente — *punto aperto*, vedi §7.
- **dcc offer**: `{network, channel, offer_id, from, filename, size}` +
  `resolution` quando risolta.
- **display_prefs**: 7 chiavi (vedi §1).

## 4bis. Modello di persistenza confermato dal manutentore (2026-09-18)

Fonte: `vjt-claude` (manutentore di Grappa/Cicchetto), risposta diretta su
IRC a una domanda esplicita di Sythos, non il contratto client documentato
— riportato qui perché autorevole e perché risolve punti aperti del
documento ufficiale, non perché sostituisce il contratto.

- **Persistito lato server (SQLite di Grappa)**: `networks` +
  `network_servers` (catalogo reti/host) e `network_credentials` — una riga
  per utente-per-rete con nick/ident/SASL e la lista `autojoin_channels`.
  Per i visitatori l'equivalente è `last_joined_channels`, uno snapshot
  cappato a 200 voci.
- **Non persistito**: i canali **attualmente** joinati. Vivono solo nella
  sessione live (`Session.Server`, interrogato via
  `Networks.session_channels/2`), non nel DB.
- **L'albero canali di Cicchetto è l'unione delle due fonti**: ogni voce è
  marcata `source: :autojoin | :joined` (funzione interna
  `merge_channel_sources/2`) — dettaglio implementativo di Cicchetto
  (Elixir), non un campo REST/WS documentato che Cordiale possa leggere
  per nome con certezza. **Una rete "parcheggiata"** (lista autojoin piena,
  zero canali joined) **è uno stato normale, non un errore** — Cordiale
  non deve trattarlo come un caso da segnalare o gestire diversamente.
- **`localStorage` di Cicchetto, contenuto confermato completo**:
  `grappa-token` (il token di sessione, **mai la password**),
  `grappa-subject`, `grappa-client-id`, più preferenze locali di comodo
  (larghezze pannelli, font, formato ora, tema, nicklist colorata, bozze
  di messaggio non spedite in `cicchetto.composeDrafts`). `IndexedDB` non
  usato. Tutto il resto — reti, canali, autojoin, storico — è
  server-side: svuotare il browser e riprendere identico da un altro
  device funziona.

**Conseguenze per Cordiale**: conferma diretta (non più solo inferenza
dalla direttiva "BNC-like" dell'utente) che l'architettura scelta è
corretta — `~/.cordiale/` deve restare limitato a preferenze locali di
comodo (lingua, tema — già così) più credenziali via `CredentialStore`
(scelta più sicura di un token in chiaro, non un problema: Cordiale è un
client nativo con accesso al keychain di sistema, non una PWA in
sandbox browser), mai reti/canali/storico, che restano sempre e solo
lato server. Uniche azioni dirette intraprese: aggiunte le bozze di
composizione per-canale (`WorkerState::drafts` in
`crates/cordiale-ui/src/main.rs`, callback `compose-text-changed`),
equivalente diretto di `cicchetto.composeDrafts` — prima mancavano del
tutto e il campo compose-text perdeva/mischiava il contenuto passando da
un canale all'altro. Non modificata l'estrazione di `boot.channels`:
il campo `source: :autojoin | :joined` è un dettaglio interno di
Cicchetto, non un nome di campo REST verificato — inventarlo violerebbe
la disciplina "mai un campo non confermato", quindi Cordiale continua a
trattare ogni voce di `boot.channels` come un canale selezionabile e la
joina in modo lazy al click, comportamento già corretto sia per un
canale già joined sia per uno solo in autojoin.

## 4ter. `/admin/*` e comandi slash — contratto reale (2026-09-19)

Fonte: lettura diretta del sorgente Elixir di `grappa-irc` (commit
`382108e`) e del client di riferimento Cicchetto, via subagent di
ricerca — non il contratto documentato, che su `/admin/*` dice solo che
esiste dietro un flag `is_admin`, senza schema. Riportato qui perché è
l'unica fonte esistente e Cordiale ora ne implementa un sottoinsieme
reale.

### Gating

- REST: scope `/admin` (`router.ex`), pipeline `:admin_authn` — richiede
  `is_admin: true` **e** sessione web piena (`RequireFullSession`): un
  token per-client riceve `403` anche se l'account è admin.
- WebSocket: canale `GrappaWeb.AdminChannel`, topic
  `"grappa:admin:events"`, stesso doppio requisito (`is_admin` +
  `session_kind == :web`).

### Endpoint catalogati (elenco completo, non tutti implementati in Cordiale)

`GET /admin/overview`, `GET/DELETE /admin/visitors[/:id]`,
`POST /admin/visitors/:id/share-token`, `GET /admin/sessions`,
`POST /admin/sessions/:id/disconnect`,
`POST /admin/sessions/:id/reconnect`, `DELETE /admin/sessions/:id`,
`GET/POST /admin/db_latency[/reset]` (mai usato da Cicchetto — solo
`curl`/CLI operatore), `GET/POST/PATCH/DELETE /admin/networks[/:id]`,
`POST/PUT/DELETE .../servers[/:id]`,
`GET/POST/PUT/DELETE .../featured_channels[/:id]`,
`POST /admin/reaper/run`, `POST /admin/circuit/:network_id/reset`,
`GET/PATCH/POST/DELETE /admin/users[/:id]`,
`PUT /admin/users/:id/password`,
`GET/PATCH/POST/DELETE /admin/credentials[/:user_id/:network_id]`,
`GET/PUT /admin/settings`, `GET/DELETE /admin/uploads[/:id]` (mai usato
da Cicchetto), `GET /admin/session_log[/sessions]`,
`GET /admin/ws_presence` (mai usato da Cicchetto),
`GET/POST/PATCH/DELETE /admin/vhosts[/:id]`,
`GET /admin/vhosts/subject_search`,
`POST/DELETE /admin/vhosts/:id/grants[/:grant_id]`.

**Implementato in Cordiale** (`cordiale_core::admin` + `client.rs`,
Settings → Admin): `GET /admin/overview`, `GET /admin/sessions`,
`POST /admin/sessions/:id/disconnect`. Anche presenti a livello di
client ma non ancora collegati alla UI: `GET /admin/users`,
`GET /admin/networks`. **Tutto il resto è deliberatamente fuori
perimetro per ora** (networks/vhosts/credentials/settings write,
visitors, reaper/circuit, session log, il canale WS
`grappa:admin:events` per aggiornamenti live) — la superficie reale è
troppo ampia per una singola sessione di lavoro; Settings → Admin lo
dichiara esplicitamente all'utente invece di fingere completezza.

Ogni entry (`AdminSession`/`AdminUser`/`AdminNetwork`) è tenuta come
JSON opaco: i nomi dei campi sono confermati dal sorgente, non ogni
tipo nidificato — stessa disciplina di `boot.channels`.

### `/links` — comandi slash e ricostruzione ad albero

Porta unica: `GrappaWeb.GrappaChannel.handle_in/3`
(`lib/grappa_web/channels/grappa_channel.ex`). Catalogo completo dei
comandi (nome, payload, evento di risposta) verificato leggendo ogni
clausola — non riportato per intero qui, solo `/links` perché
esplicitamente richiesto dall'utente per la parità con Cicchetto:

- **Payload**: `{"network_id": int, "mask"?: string}`. **`network_id` è
  un vero intero** (chiave primaria `Grappa.Networks.Network.id`), MAI
  lo slug — verificato sia lato guardia Elixir (`is_integer/1`, nessun
  fallback su slug) sia leggendo Cicchetto stesso, che risolve
  esplicitamente slug→id (`networkIdBySlug`) prima di ogni comando WS.
  Cordiale costruisce questa mappa da `boot.networks` (`slug`+`id`) al
  login (`network_ids_from_boot`); se l'id manca per una rete, il
  comando semplicemente non parte (mai un id inventato/sbagliato).
- **Risposta**: evento `links_bundle` — `{kind: :links_bundle, network,
  mask, entries: [{server, linked_to, hopcount, description}]}`.
  `linked_to` è l'uplink (padre) di ogni server; la radice si
  auto-collega (`server == linked_to`, `hopcount 0`). È uno spanning
  tree per costruzione del protocollo IRC (niente loop), non una lista
  piatta — e Cicchetto lo tratta esplicitamente come tale
  (`linksLayout.ts`: layout radiale, non forza-diretto, "un albero è
  più leggibile con un layout deterministico che con una simulazione
  fisica").
- **Ricostruzione**: `cordiale_core::links::build_links_tree` replica
  la stessa semantica di `buildTree()` di Cicchetto — selezione radice
  (auto-collegata > hopcount minimo > primo elemento), riparenting
  degli orfani (uplink mancante dalla risposta) sulla radice, sicurezza
  sui cicli (mai un nodo perso), `depth` ricostruita tenuta
  esplicitamente distinta da `hopcount` riportato dal server (possono
  differire su una risposta mascherata/parziale) — testato con 7 casi
  unitari puri, nessun bisogno di un server reale.
- **Resa visiva**: Cicchetto disegna un layout radiale SVG interattivo
  (pan/zoom, colore per profondità, `cicchetto/src/lib/linksLayout.ts` +
  `LinksModal.tsx`). Cordiale ha entrambe le rese: una lista testuale
  indentata per profondità (schermata `"links"`) sempre disponibile, e
  un bottone "Show graph" che apre una **seconda finestra OS**
  (`LinksGraphWindow`, componente Slint `export` separato nello stesso
  file, pattern confermato da fonte primaria — vedi §0septies) con un
  layout radiale reale: `cordiale_core::links::radial_layout` posiziona
  ogni nodo per angolo (foglie = fette angolari uguali, nodo interno =
  media angolare dei figli, stesso principio di `assignAngles()` di
  Cicchetto) e raggio (`depth * ring_gap`, non `hopcount`), disegnato
  con l'elemento nativo Slint `Path` (proprietà `commands`, sintassi SVG
  path standard) per gli archi e `Rectangle`/`Text` posizionati per
  coordinate assolute per i nodi — niente caricamento SVG runtime,
  niente dipendenza da rendering esterno. Nessun pan/zoom interattivo
  (limite di questa sessione, non del meccanismo) e colore fisso per
  nodo invece che per profondità (evitato il tipo `color` come campo di
  struct, non verificato con certezza — vedi §0septies). `hopcount` è
  mostrato accanto al nome server nella lista testuale, mai confuso con
  la profondità che guida il layout.
- **Instradamento non confermato**: non è specificato con certezza su
  quale topic Grappa si aspetti il comando `links` in arrivo (topic
  utente vs topic rete) — Cordiale lo invia sul topic utente
  (`grappa:user:{user}`, sempre joinato), la scelta più plausibile dato
  che le risposte "bundle" sono descritte come pushate sul topic
  utente nella maggioranza dei casi. Da confermare col test sul campo.
- **Nome evento non confermato**: idem, non è certo se il nome Phoenix
  `event` della risposta sia letteralmente `"links_bundle"` oppure se
  il vero discriminante sia il campo `kind` dentro il payload (il
  moduledoc del canale dice solo che "ogni push condivide un
  discriminante `kind:`"). Cordiale riconosce **entrambe** le
  interpretazioni (`frame.event == "links_bundle" || payload.kind ==
  "links_bundle"`), per non scommettere su una sola lettura non
  verificabile senza un server reale.

---

## 5. Guest/visitor e ruolo admin

### Guest/visitor
La documentazione **non descrive alcun meccanismo di accesso guest/visitor**
in modo esplicito:
- L'unica occorrenza di "Guest" è `Guest87449`, un nickname di esempio
  illustrativo nella spiegazione del folding ASCII dei topic — non un
  flusso di autenticazione guest.
- L'unica occorrenza di "visitor" è il campo `per_visitor_cap_bytes` (v26)
  nella proiezione delle impostazioni server, accanto a
  `per_user_cap_bytes`. Questo implica (inferenza) che lato server esista
  una categoria di subject distinta da un "user" pieno, con una propria
  quota di upload — ma il documento non descrive come un visitor viene
  creato/autenticato, quali permessi ha, o se è raggiungibile da un client
  come Cordiale. I due campi sono esplicitamente "leggibili ma non
  azionabili" (pensati per la UI admin).
- **Conclusione (contratto documentato)**: se un vero meccanismo
  guest/visitor esiste lato server, non è nel contratto documentato — è,
  nella migliore delle ipotesi, teorico/implicito da un solo campo di
  configurazione.

### Aggiornamento: verifica empirica contro `irc.sindro.me` (2026-09-18)

Su richiesta esplicita dell'utente, testato direttamente contro il server
reale (non contro un mock) con `curl`. **Il meccanismo esiste davvero**,
ma non è quello documentato nel contratto client — è stato osservato, non
letto in una spec:

- `POST /auth/login` con `{"identifier": "guest", "password": "guest"}` ha
  risposto `200` con un token reale e
  `"subject": {"id": "...", "registered": false, "kind": "visitor", "incognito": false}`.
- Un secondo tentativo identico con `identifier: "guest"` ma una password
  diversa ha risposto **non** con `401 invalid_credentials` (come da
  contratto documentato per credenziali errate) ma con
  `{"error": "anon_collision"}` — un codice errore **non presente nel
  contratto documentato**. Ipotesi non verificata: l'identifier `"guest"`
  è un varco riservato per sessioni anonime, e la collisione nasce perché
  la prima sessione anonima era ancora attiva (le sessioni visitor hanno
  un `expires_at`, osservato ~2 giorni nel futuro), non da un problema di
  password.
- Con il token ottenuto, `GET /boot` e `GET /me` hanno risposto
  regolarmente (non `403`): il token visitor ha accesso a boot/me come un
  token normale. `GET /boot` ha assegnato automaticamente un network
  (`slug: "azzurra"`, `nick: "guest"`, `connection_state: "connected"`).
  `GET /me` ha mostrato `"kind": "visitor"`, `"registered": false`,
  `"home_data": {"available_networks": [...]}` con un elenco di altri
  network selezionabili (`efnet`, `ircnet`, `libera`, `oftc`, `rizon`,
  `undernet`).
- **Bonus utile**: questa stessa chiamata ha confermato in pratica la
  forma reale di `networks[]` in `/boot` — campi osservati: `id`
  (numerico, non lo `slug` ipotizzato altrove come identificatore),
  `location`, `connection` (`port`, `registered`, `server`, `tls`,
  `connected_at`), `custom`, `kind`, `inserted_at`, `updated_at`, `age`,
  `nick`, `slug`, `connection_state`, `ident`, `realname`,
  `connection_state_changed_at`, `connection_state_reason`,
  `services_flavor`, `avatar_url`, `gender`, `languages`. `channels` è
  confermato chiavato per slug network. Tutto compatibile con i tipi
  opachi già usati in `cordiale-core::rest::BootResponse`/`MeResponse`
  (nessuna modifica di codice necessaria: i campi extra sconosciuti
  vengono ignorati da `serde` come previsto).
- **Cosa resta NON verificato**: se `"guest"` è un identifier
  universale del protocollo Grappa o una particolarità di configurazione
  di questa specifica istanza; cosa determina realmente il campo
  `password` in questo flusso (valore libero? nickname richiesto?
  ignorato?); se è possibile scegliere il network invece di quello
  assegnato automaticamente; se esistono limiti di rate specifici per le
  sessioni anonime oltre a quelli generali già documentati.
- **Implicazione per Cordiale**: il meccanismo è confermato reale su
  questa istanza, ma resta troppo poco compreso per costruire una UI
  "Continue as guest" affidabile adesso — servirebbe altro testing mirato
  (più tentativi controllati, verifica su un'altra istanza Grappa se
  disponibile) prima di considerarlo pronto per il codice. Non
  implementato in questa sessione, coerente con la policy di non inventare
  capability senza prova solida — qui la prova solida c'è ma è ancora
  incompleta.

### Ruolo admin
- `/admin/*` (REST) e `AdminChannel` (WS) sono gated da un flag `is_admin`,
  esenti dal rate limiting condiviso.
- Un token per-client non può mai accedere a `/admin/*`
  (`403 client_token_scope`) — richiede sessione browser piena.
- **Il documento non spiega come un subject diventi admin**: nessun
  endpoint, campo o evento documentato per assegnare/revocare `is_admin`.
  Citato solo come gate esistente, mai come procedura — coerente con
  `MEMORY.md` §3.3 ("Il ruolo admin è assegnato dal server... Cordiale non
  lo deduce da campi locali").

---

## 6. Domande aperte / punti non chiari

1. **Heartbeat e riconnessione WebSocket** — nessun intervallo/policy di
   backoff dichiarati esplicitamente. Da verificare sul codice server o sul
   default di `phoenix.js` prima di implementare la riconnessione.
2. **Meccanismo guest/visitor** — nessun endpoint/flusso documentato; unico
   indizio `per_visitor_cap_bytes`. Da verificare sul codice server.
3. **Assegnazione ruolo admin** — nessuna procedura documentata.
4. **Endpoint di registrazione/signup** — assente dal documento, ma
   cicchetto ha un wizard di registrazione lato UI: o è un gap di
   documentazione, o cicchetto usa un provisioning lato operatore diverso.
   Da chiarire prima di decidere se Cordiale deve offrire un percorso di
   registrazione.
5. **Endpoint di upload generico (POST)** — solo `GET /uploads/:slug`
   citato per analogia col pattern DCC file; nessun endpoint di upload
   (metodo, campo multipart, limiti) documentato.
6. **Schema completo delle entità** — §4 di questo documento è una
   ricostruzione da menzioni sparse, non una trascrizione di uno schema
   pubblicato.
7. **Stato "away" dei peer** — un componente del client di riferimento
   suggerisce che esista, ma nessun evento/campo documentato per l'away
   status di un peer (solo il proprio, via `auto_away_reason_changed`).
8. **`presence_filter` in `display_prefs`** — non chiaro se collegato
   meccanicamente al join-param `{"presence": false}` (§2) o se siano due
   funzionalità distinte; il documento non li mette mai in relazione
   esplicita.
9. Alcune superfici (schema completo `/admin/*`, TOTP, passkey, recovery
   codes, upload) non sono nel contratto client documentato: non rilevanti
   per il perimetro Fase 1 di Cordiale (autenticazione username/password o
   token per-client, non gestione 2FA/admin), ma da riconsiderare se il
   perimetro si estende in Fase 2.

---

## 7. Implicazioni dirette per il design di Cordiale (Fase 1)

- Il modello `Profilo` deve trattare password e token per-client come lo
  stesso campo wire (`password` in `POST /auth/login`), ma va mantenuta una
  distinzione interna esplicita (vedi `MEMORY.md` §3.6) per permettere una
  UX diversa (es. "Password" vs "Client token") e per gestire
  correttamente `403 client_token_scope` come errore di scope e non di
  credenziali (niente retry, niente "riprova la password").
  - **Nota importante**: `403 client_token_scope` implica che alcune
    operazioni account-only (2FA, passkey, eliminazione account) **non
    possono essere svolte da Cordiale con un token per-client** — vanno
    escluse dal perimetro applicativo o esplicitamente segnalate come "vai
    sul browser" quando rilevanti.
- Il bootstrap REST va sequenziato come: `GET /api/config` (verifica
  versione) → `POST /auth/login` (o bearer diretto se token già noto) →
  `GET /boot` + `GET /me` in parallelo → join topic utente WS (che conferma
  di nuovo `protocol_version`).
- Il parser deve confrontare `protocol_version` con `>=`, mai `==`, e
  ignorare sempre campi/eventi sconosciuti — coerente con la policy già
  decisa in `MEMORY.md` §3.2.
- Guest/visitor **non va implementato in Fase 1**: nessuna evidenza di un
  flusso client-side nel contratto documentato.
- Il modello dominio iniziale (network/channel/query/message) può basarsi
  sui campi qui documentati; i campi non documentati vanno trattati come
  opachi/opzionali, mai assunti.
