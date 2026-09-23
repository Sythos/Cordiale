# Matrice Cicchetto → Cordiale

Compilata dopo lo studio di `CLIENT_PROTOCOL.md` (fonte primaria) e della
struttura di `cicchetto` (solo riferimento funzionale, non architetturale).
Dettagli e fonti in [`protocol-notes.md`](./protocol-notes.md). Cicchetto
resta una fonte di funzionalità/opzioni da valutare, non un vincolo
architetturale per Cordiale.

Colonna "Nel protocollo Grappa?": `Sì` = documentato esplicitamente in
`CLIENT_PROTOCOL.md`; `Parziale` = citato ma senza schema completo; `Incerto`
= menzionato solo indirettamente o per analogia; `No / non documentato` =
assente dal contratto, presumibilmente client-side o fuori perimetro.

Colonna "Fase Cordiale": fase prevista di valutazione/implementazione;
`—` = non ancora decisa, richiede verifica aggiuntiva sul codice server
prima di pianificare.

| Funzionalità (cicchetto) | Nel protocollo Grappa? | Fase Cordiale | Note |
|---|---|---|---|
| Login username/password | Sì | Fase 1 | `POST /auth/login` |
| Token per-client come alternativa a TOTP/passkey | Sì | Fase 1 | Stesso campo `password`; scoped, `403 client_token_scope` fuori scope |
| Bootstrap `/api/config` + `/boot` + `/me` | Sì | Fase 1 | Sequenza di avvio |
| Phoenix Channels realtime (user/network/channel topic) | Sì | Fase 1 | Vedi protocol-notes §2 |
| network/channel/query, messaggi, stato realtime | Sì | Fase 1 | Perimetro Fase 1 |
| TOTP (2FA) | Parziale | — | Richiede sessione browser piena, fuori scope token per-client |
| Passkey/WebAuthn (2FA) | Parziale | — | Come sopra |
| Recovery codes | Incerto | — | Nessun endpoint documentato |
| Eliminazione account | Sì (`DELETE /me`) | — | Superficie solo-account, fuori scope token per-client |
| Registrazione nuovo account | No / non documentato | — | Nessun endpoint di signup nel contratto; da chiarire (protocol-notes §6.4) |
| Condivisione sessione via QR | Incerto | — | Non menzionato nel contratto |
| Console amministrativa | Parziale | — | Gate `is_admin`, nessuna procedura di assegnazione documentata |
| Vhost settings | No / non documentato | — | Non citato |
| Directory canali | Incerto | — | Non documentato esplicitamente |
| Archivio/scrollback | Sì | Fase 1/2 | `GET /networks/:network_id/archive` |
| Banlist | Sì | Fase 2 | Verbo WS `"banlist"` |
| Modifica modi canale | Parziale | Fase 2 | Righe `:mode` documentate, nessun verbo dedicato oltre banlist |
| User mode | Parziale | Fase 2 | Solo citato come approccio scorretto per identità servizi |
| Names/Who/Whois/Whowas/Links/Server info | Sì | Fase 2 | Eventi per-connessione documentati |
| Lusers | Sì | Fase 2 | Unico evento della famiglia con fan-out a tutte le connessioni |
| Offerte DCC | Sì | Fase 2 | Endpoint ed eventi completamente documentati |
| Upload/drag&drop file | Parziale | — | Solo `GET /uploads/:slug` per analogia; nessun endpoint POST documentato |
| Media viewer | No / non documentato | — | Rendering client-side, protocollo consegna solo byte grezzi |
| Audio dock/mini player | No | — | Puramente client-side |
| Editor/galleria temi | No | Fase 1/2 (nativo) | Cordiale gestisce temi via design token Slint, non wire protocol |
| Barra inferiore, nicklist colorata, badge eventi, bold mentions, strip formatting | Sì | Fase 2 | Chiavi `display_prefs` |
| Filtro presenza | Sì (probabile collegamento) | Fase 2 | Possibile legame con join-param `presence: false`, non esplicito nel doc |
| Finestra menzioni | Incerto | — | Presumibilmente derivato client-side |
| Ignore list, watchlist, alias comandi, perform on connect | Sì, non-admin self-service | Fase 2 (2026-09-19) | **Corretto**: la nota "presumibilmente client-local" era sbagliata, mai verificata — ignores/aliases/perform sono REST server-persistiti (`GET/POST/PUT /networks/:slug/{ignores,perform}`, `GET/PUT /me/settings/aliases`), la watchlist di presenza è REST (`/networks/:slug/notify`), quella per parola chiave è WS (`ch.push("watchlist", ...)`). Tutti e quattro ora implementati in Cordiale (Settings → Ignore List/Aliases/On-Connect Commands/Watch Lists) — dettaglio completo in `docs/protocol-notes.md` §4quater |
| Inviti | Sì (parziale) | Fase 2 | `window_invited` tra i kind di stato-finestra |
| Kick | Sì | Fase 1/2 | Kind terminale di stato-finestra |
| Statusmsg (ops/voice-only) | Sì | Fase 2 | `meta.statusmsg` |
| CTCP action/query | Sì | Fase 2 | Campo `ctcp_target` |
| Notice/relay a terzi | Sì | Fase 2 | Campo `notice_target` |
| Identità ai servizi | Sì | Fase 1 | Evento `session_identity_changed` |
| Away/auto-away (proprio) | Parziale | Fase 2 | `auto_away_reason_changed` documentato solo per il subject stesso |
| Away dei peer | Incerto | — | Nessun evento documentato (protocol-notes §6.7) |
| Reason di quit/part personalizzati | Sì | Fase 2 | Evento `quit_part_reason_changed` |
| Casemapping/chantypes | Sì | Fase 1 | Folding ASCII dei topic, necessario per il modello canale |
| List modes query | Sì | Fase 2 | `chanmodes_a`/`list_modes_queryable` |
| Gestione flood/rate limit | Sì | Fase 1 | `web_session_severed`, va gestito nel core rete |
| Captcha | No / non documentato | — | Non menzionato |
| Notifiche push web | Sì (capability) | — | `push_content_encoding`, capability separata da `protocol_version`; fuori perimetro Fase 1 (nessun runtime esterno/service worker previsto) |

## Struttura Settings — mappatura da Cicchetto (2026-09-18)

Steer utente: le schermate Settings di Cordiale devono restare
concettualmente vicine a quelle di Cicchetto (stesse categorie, stesso
raggruppamento), per rendere la transizione degli utenti esistenti meno
spiazzante possibile — non stesso codice (Cicchetto è una PWA
TypeScript/SolidJS, Cordiale un client nativo Rust/Slint), stessa
organizzazione concettuale. Mappatura verificata leggendo
`cicchetto/src/SettingsDrawer.tsx` e `cicchetto/src/AdminPane.tsx` su
`vjt/grappa-irc`:

**Sezioni utente normale** (ordine reale nel drawer di Cicchetto):
`general` (identità per-network, ritenzione upload, auto-away, quit/part
reason; contiene `profile` come sub-page) · `security` (cambio password,
TOTP, passkey — solo per `kind: "user"`) · `display` (dimensione testo,
formato timestamp, nicklist colorata) · `themes` (galleria + editor) ·
`push`/notifiche · `watchlists` (presenza + keyword highlight) ·
`ignores` · `aliases` (comandi personalizzati) · `perform` (comandi
on-connect) · `vhost` (solo se il server lo espone). Fuori dall'indice:
share session, delete account, credits, build info.

**Sezioni admin** (`AdminPane.tsx`, 3 gruppi): *Live* (Sessions, Events,
Session Log) · *Configuration* (Networks, Vhosts, Users, Settings —
limiti upload/spool server-wide) · *Diagnostics* (Debug).

**Nota storica (2026-09-18, Fase 2)**: quando fu introdotta la shell di
navigazione completa a 10+8 sezioni in `appwindow.slint`/`main.rs`, solo
`general` e `display` erano funzionali; le altre sezioni erano segnaposto.
Le implementazioni successive sono riportate nella matrice qui sopra e
negli aggiornamenti cronologici sotto: questa nota descrive lo stato di
quel giorno, non quello corrente.

**Aggiornamento (2026-09-19)**: la superficie admin reale di Grappa
(catalogata per intero in `docs/protocol-notes.md` §4ter, letta dal
sorgente Elixir + da Cicchetto) è molto più ampia di quanto stimato
inizialmente — oltre 30 endpoint `/admin/*` su 8 aree (overview,
visitors, sessions, networks+servers+featured-channels, reaper/circuit,
users, credentials, settings, uploads, session log, ws_presence,
vhosts) più un canale WS dedicato (`grappa:admin:events`). **Esteso
(2026-09-19)** oltre al gruppo *Live → Sessions* iniziale: ora reali
anche Users (lista + toggle admin + delete), Networks (lista + reset
circuit), Visitors (lista + delete), Session Log (lettura), Reaper
(run) — tutti azionabili in Settings → Admin con sotto-navigazione a
bottoni. Resta fuori (lato **admin**, gestione di vhost/credenziali
altrui — distinto dal self-service sul proprio profilo, vedi
`docs/protocol-notes.md` §4quater, ora implementato): Vhosts grants,
Credentials, scrittura di Settings server-wide (confermato non
necessario: Grappa è standalone), creazione/modifica-password utente,
creazione/modifica/eliminazione rete, il canale WS
`grappa:admin:events` per aggiornamenti live — ciascuna di quelle aree
è a sua volta un sottoinsieme con azioni distruttive reali (elimina
rete, cambia password) o form multi-campo, non qualcosa da
implementare alla cieca senza un server di test. Anche `/links`
(comando slash, non endpoint REST/admin, ma richiesto esplicitamente
per parità con Cicchetto) è implementato: ricostruzione dell'albero di
rete identica a `buildTree()` di Cicchetto (`cordiale_core::links`),
con **doppia resa** — lista indentata sempre disponibile, più un
bottone "Show graph" che apre una seconda finestra con un vero layout
radiale (stesso principio angolo/raggio di Cicchetto, disegnato con
l'elemento nativo Slint `Path`, niente pan/zoom per ora) — dettaglio
completo in `docs/protocol-notes.md` §4ter.

**Aggiornamento (2026-09-23)**: Cordiale gestisce tutti i 56 kind evento
del protocollo. Oltre a quanto sopra sono ora implementati, con i
rispettivi comandi slash: schermata risposte per WHO/WHOIS/WHOWAS/MOTD/
INFO/VERSION/ADMIN/banlist/LUSERS, directory canali (`/list`, sola
lettura), archivio con cancellazione dello storico (`/archive`), offerte
DCC con Accetta/Rifiuta, recupero identità (`/recover`), `/invite`,
presenza della watchlist per rete, banner di away dei peer, riepilogo
menzioni al rientro dall'away (`/mentions`) e righe in sola lettura per le
preferenze e i limiti di upload del server. Restano fuori, tra gli altri:
join dalla directory (Cordiale non ha `/join`), upload di file e la
sezione admin degli upload.

## Voci ancora da chiarire prima di poter classificare

- Guest/visitor: il contratto client non definisce un flusso universale.
  Cordiale applica la decisione approvata di usare la password vuota per
  tentare il login guest osservato (`guest`/`guest`), verificato su
  `irc.sindro.me`; altre istanze possono rifiutarlo. Semantica e portabilità
  restano da confermare, come dettagliato in `protocol-notes.md` §5.
- Assegnazione ruolo admin: nessuna procedura documentata.
- Heartbeat/backoff WebSocket: il contratto non fissa intervalli; Cordiale
  usa un heartbeat da 30 s e un ritardo fisso di riconnessione da 5 s.
  Restano parametri scelti dal client da verificare su altre istanze e
  condizioni di rete (`protocol-notes.md` §2 e §6).

## Fonti upstream Grappa (`vjt/grappa-irc`, branch `main`)

- **Repository e codice server originali:**
  <https://github.com/vjt/grappa-irc/tree/main>.
- **Contratto client autorevole:**
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>.
- **Cicchetto**, usato solo come riferimento funzionale e non architetturale:
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto>.
