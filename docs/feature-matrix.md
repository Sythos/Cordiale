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
| TOTP (2FA) | Parziale nel documento, schema verificato nel sorgente Grappa/Cicchetto | Fase 2, implementato | Login 202 → /auth/totp/verify; gestione /me/totp con sessione password piena; vedi protocol-notes.md §autenticazione e §superfici solo-account |
| Passkey/WebAuthn (2FA) | Parziale nel documento, schema verificato nel sorgente Grappa/Cicchetto/Wax | Fase 2, parziale (issue #147) | Contratto tipizzato di tutte le route passkey con test su server simulato; Settings → Security mostra modo e passkey e le elimina con la password (sessione password piena). Su Windows (issue #160, via `webauthn.dll`) anche login con passkey (secondo fattore e passwordless), aggiunta, cambio modo e attivazione passwordless; gli stessi flussi su Linux e macOS con chiavette USB e PIN nei build con la feature cargo `ctap-hid` (spenta di default, issue #161); altrove restano in Cicchetto. Fattibilità per piattaforma in [`passkey-spike.md`](./passkey-spike.md); non provato su un'istanza reale né con un autenticatore |
| Recovery codes | Verificato nel sorgente Grappa/Cicchetto | Fase 2, implementato | /auth/totp/verify accetta anche recovery code; codici nuovi mostrati una volta dopo /me/totp/enrollment/confirm; un account passwordless accede con un recovery code da `/auth/passkeys/recover` (schermata di connessione, issue #162; non provato su un'istanza reale); vedi protocol-notes.md |
| Eliminazione account | Sì (`DELETE /me`) | — | Superficie solo-account, fuori scope token per-client |
| Registrazione nuovo account | No / non documentato | — | Nessun endpoint di signup nel contratto; da chiarire (protocol-notes §6.4) |
| Avviso `http://` in chiaro | N/A (scelta del client) | Implementato (issue #201), non provato a mano | Con un server `http://` non loopback (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`) la schermata di connessione, quella del token di condivisione e quella del recovery code mostrano un avviso e chiedono una conferma esplicita prima di inviare le credenziali; la conferma vive solo in memoria e vale per quell'origine; vale anche per l'override dell'origine passkey; non blocca i server locali; vedi protocol-notes.md §2 |
| Condivisione sessione (link/QR) | Sì (sorgente Grappa/Cicchetto) | Implementato, non verificato su un server reale | `POST /me/share-token` (sessione piena) e `POST /auth/share/consume`; in Settings → Security si crea il link con QR, dalla schermata di connessione si entra incollando token o link; vedi protocol-notes.md §autenticazione |
| Console amministrativa | Parziale nel documento (solo il gate `is_admin`), schema dal sorgente Grappa/Cicchetto | Fase 2, implementato | Settings → Admin: sessioni, utenti, visitatori, reti e server, credenziali, vhost e grant, impostazioni server-wide, upload, feed live; vedi la riga Admin della tabella del 2026-09-25 e protocol-notes §4ter. Nessuna procedura di assegnazione di `is_admin` documentata. Non provato contro un server reale |
| Vhost settings | Sì (sorgente Grappa/Cicchetto, non in `CLIENT_PROTOCOL.md`) | Fase 2, implementato | Self-service `GET`/`PUT /me/settings/vhost` in Settings → Source Address; i grant lato admin stanno in Settings → Admin (protocol-notes §4quater) |
| Directory canali | Sì (sorgente Grappa/Cicchetto) | Fase 2, implementato | Voce "Canali" per rete nella sidebar e `/list`: ricerca, refresh, totale, età dell'elenco, join o apertura con un clic (issue #121) |
| Archivio/scrollback | Sì | Fase 1/2 | `GET /networks/:network_id/archive` |
| Banlist | Sì | Fase 2 | Verbo WS `"banlist"` |
| Modifica modi canale | Parziale | Fase 2 | Righe `:mode` documentate, nessun verbo dedicato oltre banlist |
| User mode | Parziale | Fase 2 | Solo citato come approccio scorretto per identità servizi |
| Names/Who/Whois/Whowas/Links/Server info | Sì | Fase 2 | Eventi per-connessione documentati |
| Lusers | Sì | Fase 2 | Unico evento della famiglia con fan-out a tutte le connessioni |
| Offerte DCC | Sì | Fase 2 | Endpoint ed eventi completamente documentati |
| Upload/drag&drop file | Sì (sorgente Grappa, non in `CLIENT_PROTOCOL.md`) | Fase 2, implementato | `POST /api/uploads` (protocol-notes §6.5): graffetta, trascinamento, incolla. Riduzione dei video prima dell'invio (issue #243): interruttore nel popup di conferma e default locale in Settings (`shrink_videos`, spento; il popup vale solo per quell'upload e non lo riscrive). Ricodifica in un MP4 temporaneo (VP9, audio copiato, al massimo 720p) con FFmpeg dietro la feature `video-shrink`, spenta di default come `ctap-hid`: nei pacchetti non è ancora attiva. Il risultato è controllato sul tetto video del server prima dell'invio; se non è disponibile, fallisce o non è più piccolo, il video non parte. Non provato con video e server reali |
| Media viewer | No / non documentato | Implementato (client-side) | Rendering client-side, protocollo consegna solo byte grezzi |
| Audio dock/mini player | No | Implementato (client-side) | Puramente client-side: player e radio, vedi la tabella del 2026-09-25 |
| Editor/galleria temi | No | Fase 1/2 (nativo) | Cordiale gestisce temi via design token Slint, non wire protocol |
| Barra inferiore, nicklist colorata, badge eventi, bold mentions, strip formatting, formato data | Sì | Fase 2 | Chiavi `display_prefs` (8 dalla v29, protocol-notes §1); `date_format` (v29: `auto`/`dmy`/`mdy`/`ymd`, 422 fuori insieme) applicato da un solo percorso di rendering (`cordiale-ui/src/dates.rs`) |
| Filtro presenza | Sì (probabile collegamento) | Fase 2 | Possibile legame con join-param `presence: false`, non esplicito nel doc |
| Finestra menzioni | Sì (`mentions_bundle`) | Fase 2, implementato | Riepilogo cross-canale al rientro dall'away (`/mentions`); l'evidenziazione delle menzioni in chat è client-side |
| Ignore list, watchlist, alias comandi, perform on connect | Sì, non-admin self-service | Fase 2 (2026-09-19) | **Corretto**: la nota "presumibilmente client-local" era sbagliata, mai verificata — ignores/aliases/perform sono REST server-persistiti (`GET/POST/PUT /networks/:slug/{ignores,perform}`, `GET/PUT /me/settings/aliases`), la watchlist di presenza è REST (`/networks/:slug/notify`), quella per parola chiave è WS (`ch.push("watchlist", ...)`). Tutti e quattro ora implementati in Cordiale (Settings → Ignore List/Aliases/On-Connect Commands/Watch Lists) — dettaglio completo in `docs/protocol-notes.md` §4quater. Dalla v31 una regola ignore è la coppia `(mask, text_pattern)`: Cordiale legge `entries` (ripiegando su `masks` coi server vecchi), aggiunge e rimuove la coppia esatta, `/ignore <mask> [pattern]` |
| Inviti | Sì (parziale) | Fase 2 | `window_invited` tra i kind di stato-finestra; il banner ha Entra e Rifiuta: Rifiuta chiama `DELETE /networks/:slug/invites/:channel` (nulla viene inviato a IRC) e il banner sparisce solo con `window_invite_declined`, così vale anche per una decisione presa su un altro dispositivo (non ancora provato su un server reale) |
| Kick | Sì | Fase 1/2 | Kind terminale di stato-finestra |
| Statusmsg (ops/voice-only) | Sì | Fase 2 | `meta.statusmsg` |
| CTCP action/query | Sì | Fase 2 | Campo `ctcp_target` |
| Notice/relay a terzi | Sì | Fase 2 | Campo `notice_target` |
| Identità ai servizi | Sì | Fase 1 | Evento `session_identity_changed` |
| Away/auto-away (proprio) | Parziale | Fase 2 | Cordiale dichiara a Grappa quando è in primo piano (`visibility` ogni 30 s, `client_closing` a chiusura e sign-out; non verificato contro un server reale, vedi `docs/protocol-notes.md`); `auto_away_reason_changed` documentato solo per il subject stesso; suffisso del nick in auto-away (v32, `GET/PUT /me/settings/away-nick-suffix`, push `away_nick_suffix_changed`, `null` = rinomina spenta) in Settings: il nick mostrato resta quello degli eventi nick, mai `nick + suffisso` |
| Away dei peer | Sì (evento `peer_away`) | Fase 2, implementato | `{network, peer, message}` sul topic utente, mostrato come banner sopra la finestra privata del peer (protocol-notes §6.7) |
| Reason di quit/part personalizzati | Sì | Fase 2, implementato | Evento `quit_part_reason_changed`; si modificano in Settings → General con auto-away reason e debounce |
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

**Aggiornamento (2026-09-19)** (stato di quel giorno: l'elenco di ciò che
"resta fuori" è superato, vedi la riga Admin della tabella del 2026-09-25 e
`docs/protocol-notes.md` §4ter): la superficie admin reale di Grappa
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

**Aggiornamento (2026-09-23)**: Cordiale gestisce tutti i kind evento
del protocollo (56 allora, 57 dalla v32 con `away_nick_suffix_changed`).
Oltre a quanto sopra sono ora implementati, con i
rispettivi comandi slash: schermata risposte per WHO/WHOIS/WHOWAS/MOTD/
INFO/VERSION/ADMIN/banlist/LUSERS, directory canali (`/list`, sola
lettura), archivio con cancellazione dello storico (`/archive`), offerte
DCC con Accetta/Rifiuta, recupero identità (`/recover`), `/invite`,
presenza della watchlist per rete, banner di away dei peer, riepilogo
menzioni al rientro dall'away (`/mentions`) e righe in sola lettura per le
preferenze e i limiti di upload del server. Restano fuori, tra gli altri:
join dalla directory e la sezione admin degli upload.

**Aggiornamento (2026-09-24)**: upload di file (`POST /api/uploads`) e
parser dei comandi slash (`cordiale_core::slash`) con la grammatica di
Cicchetto: `/me`, `/msg`, `/notice`, `/query`, `/join`, `/part`, `/cycle`,
`/topic`, `/nick`, `/away`, `/ctcp`, `/ping`, op/voice/kick/ban/mode,
`/names`, `/quote`, `/oper`, `/kill`, `/stats`, `/rehash`,
`/connect`/`/disconnect`/`/reconnect`/`/quit`, `/ignore`, `/notify`,
`/hilight` e le scorciatoie dei servizi. Un comando sconosciuto non viene
più inviato come testo; `//` invia un messaggio che inizia con `/`.

**Aggiornamento (2026-09-25) — parità con Cicchetto**: chiusi tutti i gap
funzionali elencati nel README, tranne quelli lasciati a Cicchetto per
scelta. Stato per area:

| Area | Stato in Cordiale | Note |
|---|---|---|
| Temi | Fatto | Galleria, abbinamento giorno/notte che segue lo schema del sistema, sfondi (built-in e caricati), colori dei ruoli, editor dei 27 colori con anteprima, copia, eliminazione, pubblicazione |
| Impostazioni sincronizzate | Fatto | Nick di rete riletto, watchlist di parole chiave dal server, comandi on-connect multilinea |
| Notifiche push | Fatto | Interruttori, liste per canale/nick, conversazioni silenziate con durata, suono e `/beep`; sopra il campo messaggio una barra mostra la silenziazione della conversazione aperta (con orario locale e tempo residuo) e un pulsante per toglierla subito. Grappa conserva solo la scadenza, non l'ora della silenziazione: quella vive in `settings.json` di questo dispositivo, quindi le silenziazioni fatte altrove mostrano la barra senza orario. Non verificato contro un server reale |
| Upload | Fatto | Graffetta, trascinamento file (non su Wayland), incolla immagini, testo lungo come `paste.txt` |
| Link e visualizzatore media | Fatto | Link cliccabili come il linkify di Cicchetto; immagini e testo nel visualizzatore, audio nel player, il resto nel browser; nessuna anteprima inline, come Cicchetto. Si aprono solo link http, https e ftp, senza utente/password né spazi o caratteri di controllo, e al browser va l'URL normalizzato (niente `file:`, `javascript:`, `mailto:`). Il download per il visualizzatore è solo http/https e segue al massimo 5 redirect e rifiuta il passaggio da https a http o da un host pubblico a un indirizzo locale (loopback, rete privata, link-local; solo IP letterali e `localhost`, nessuna risoluzione DNS) |
| Radio | Fatto | Stazioni di Cicchetto più stazioni personalizzate salvate solo in locale; MP3, Ogg Vorbis, FLAC; `/np` |
| Comandi | Fatto | `/np`, `/beep`, vista di `/umode` senza argomenti |
| Chat e roster | Fatto | mIRC multicolore a capo, MODE secondo PREFIX/CHANMODES, DM prima dello snapshot recuperati, evidenziazione delle menzioni |
| Home | Fatto | Come la HomePane di Cicchetto: benvenuto con la durata della sessione per utente/visitatore, righe dei network (connesse: vai a `$server`, Disconnect con conferma; parcheggiate o fallite: Reconnect, Remove con conferma via `DELETE /session/networks/:slug`, v28, mai offerto ai visitatori), canali in evidenza, "Available to connect" via `POST /session/networks`, Recover identity per i visitatori |
| Debug | Fatto (da provare a mano su Windows, macOS e Linux) | Pagina prima di Impostazioni con testo di sola lettura, selezionabile e copiabile: versione e build, sistema operativo, CPU, RAM, schermo, locale, fuso orario, cartelle dei dati; niente viene inviato, niente segreti né percorsi personali. Layout tastiera solo su Windows, metodo di input non rilevato: "Not available" |
| Menu Azioni | Fatto | Stanze, archivio, modi utente, silenzia conversazione, radio, cambia account |
| Admin | Fatto | Compresi i grant dei vhost ai visitatori; tab Uploads (`GET /admin/uploads`, `DELETE /admin/uploads/:id`): registro con le righe eliminate come storico, budget globale, eliminazione anticipata di un upload attivo con conferma. Nessuna eliminazione per l’utente normale, nessun indicatore di quota personale. Issue #143: l'eliminazione di una rete chiede prima `GET /admin/networks/:id/message_count` (dalla v33 cancella anche tutto lo scrollback) e mostra il numero nella conferma, o dice che non può confermarlo (404 o errore), mai zero; terminate di una sessione account (`DELETE /admin/sessions/:id`) e reconnect di un visitatore (`POST /admin/sessions/:id/reconnect`); featured channels (elenco, aggiunta, abilita/disabilita, elimina); modifica di un server IRC (`PUT`) e di una credenziale (`PATCH`: nick, ident, realname, sasl_user, password). Tutto verificato contro i test wiremock e il sorgente del server, non contro un server reale |
| Presentazione | Fatto | Avatar GIF/WebP/BMP, badge nativo sulla taskbar di Windows |
| Token client, eliminazione account; registrazione di passkey, cambio modo e login con passkey fuori da Windows | Lasciato a Cicchetto | Cicchetto è integrato in Grappa, Cordiale no. TOTP (con recovery code), condivisione di sessione ed elenco/eliminazione delle passkey ci sono (righe sopra); la ceremonia WebAuthn c'è solo su Windows (#160, non provata); altrove una passkey-only entra con un link di condivisione o un token client, o con un recovery code se ne ha (`passkey-spike.md`) |

Limiti di piattaforma restanti: niente trascinamento di file su Wayland,
badge solo su Windows, pulsanti e menu con lo stile dei widget di Slint;
ident e realname non sono più esposti da Grappa.

**Aggiornamento (2026-10-02) — allineamento a `protocol_version` da 34 a 37.**
Cordiale dichiara `client_proto=37` sull'URL del WebSocket e su un `426
upgrade_required` si ferma invece di ritentare (non verificato contro un
server che alzi il floor). Stato delle novità: quelle che parlano col server
sono coperte da test con server simulato e dal suo sorgente, **non ancora
provate contro un server reale**:

| Area | Stato in Cordiale | Note |
|---|---|---|
| `dm_conversation_id` (v34 a v36) | Implementato, solo per server 34-36 | Letto da `query_windows_list` (non dalle righe di scrollback), usato per riconoscere la stessa finestra privata dopo un NICK del peer; il merge di due conversazioni non è rilevato. Dal v37 il server non lo invia più e un NICK non sposta nulla: la finestra vecchia resta con la sua storia e il prossimo messaggio del peer ne apre una nuova col nick nuovo, senza inferenza di rename, senza seguire la selezione, senza portare con sé silenziamenti o cursori di lettura. Forma verificata sul sorgente del tag `v1.5.12` (prima release col protocollo 37); non provato in una sessione reale |
| `dm_with` sulle righe di scrollback (v36) | Non usato | Cordiale instrada le righe per topic e mittente e non classifica mai un DM confrontando `channel` col proprio nick, quindi non ne ha bisogno; `dm_with` resta letto solo nelle menzioni (v35) |
| `dm_with` e `id` nelle menzioni (v35) | Fatto | `dm_with` etichetta la finestra di una menzione di DM (altrimenti `channel`, che per un DM in ingresso è il proprio nick); un clic su una riga del riepilogo apre quella finestra, carica `?around=<id>`, scorre al messaggio e lo evidenzia per un attimo (issue 238). Senza `id` (server più vecchio) si ferma alla finestra. Forma verificata sul sorgente del tag `v1.5.12`; scorrimento e `?around=` non provati in una sessione reale |
| Self-KICK e rientro (Grappa 2321) | Nessuna modifica necessaria | Solo server: il canale resta nello snapshot di rientro e un 474 lo porta in `join_failed`. Cordiale mostra `kicked`, `joined` e `join_failed` come stati di finestra, con riga sbiadita nella sidebar anche da snapshot di riconnessione, quindi il canale non sparisce. Non provato con un server reale |
| Righe molto larghe (Cicchetto 2310) | Implementato (issue #242), da vedere a occhio su desktop | Cicchetto ritaglia le righe oltre il pannello (block art mIRC) senza far scorrere il pannello di lato. In Cordiale ogni riga della `ListView` ha `clip: true` e il `StyledText` ha `min-width: 0px`: una riga troppo larga viene ritagliata a destra e il testo normale va a capo come prima. Non provato a mano (nessuna build locale): controllare block art, una riga lunga senza spazi e una normale, in finestra stretta e larga su Windows e Linux |
| Catch-up dopo un reconnect | Implementato | Sonda `messages/count?after=<id>&cap=201` per canale; fino a 200 righe con `?after=`, oltre ricarica la coda e lascia una nota del buco |
| Presenza in primo piano | Implementato | `visibility` ogni 30 s mentre la finestra è attiva, `client_closing` a chiusura e sign-out |
| Profilo proprio per rete | Implementato | Campi CTCP USERINFO e avatar in Settings → General (`PATCH /networks/:slug/profile`, `PUT`/`DELETE .../avatar`) |
| Rifiuto di un invito | Implementato | Vedi la riga Inviti sopra |
| Condivisione di sessione | Implementato | Vedi la riga sopra |
| Passkey | Parziale | Elenco ed eliminazione con la password; ceremonia WebAuthn su Windows (#160) e, con la feature `ctap-hid`, con chiavette USB su Linux e macOS (#161); nessuna delle due provata con un autenticatore |
| Pagina Debug | Implementato | Vedi la tabella del 2026-09-25; da provare a mano su Windows, macOS e Linux |

## Voci ancora da chiarire prima di poter classificare

- Guest/visitor: il contratto client non definisce un flusso universale.
  Cordiale applica la decisione approvata di usare la password vuota per
  tentare il login guest osservato (`guest`/`guest`), verificato su
  `irc.sindro.me`; altre istanze possono rifiutarlo. Semantica e portabilità
  restano da confermare, come dettagliato in `protocol-notes.md` §5.
- Assegnazione ruolo admin: nessuna procedura documentata.
- Heartbeat/backoff WebSocket: il contratto non fissa intervalli; Cordiale
  usa un heartbeat da 30 s e una riconnessione con backoff esponenziale
  (1 s, 2 s, 4 s... fino a 60 s, jitter ±25%, `Retry-After` rispettato).
  Restano parametri scelti dal client da verificare su altre istanze e
  condizioni di rete (`protocol-notes.md` §2 e §6).

## Fonti upstream Grappa (`vjt/grappa-irc`, branch `main`)

- **Repository e codice server originali:**
  <https://github.com/vjt/grappa-irc/tree/main>.
- **Contratto client autorevole:**
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>.
- **Cicchetto**, usato solo come riferimento funzionale e non architetturale:
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto>.

**Aggiornamento (2026-09-27)**: la directory canali (issue #121) non è più
una schermata a parte in sola lettura. Ogni rete connessa ha la voce
"📇 Canali" nella sidebar, sopra i suoi canali (come la riga "channels" di
Cicchetto); il pannello prende il posto della chat lasciando la sidebar
visibile: ricerca con debounce e Refresh in alto, totale dei canali e età
dell'elenco ("5 min fa", aggiornata ogni 30 s; se stantio diventa un
bottone "aggiorna ora"), ordinamento utenti/nome, righe con nome, badge
"dentro"/"in evidenza", topic senza codici mIRC e numero di utenti a
destra. Clic, Invio o Spazio su una riga entrano nel canale (o lo aprono se
già dentro) e chiudono il pannello.

**Aggiornamento (2026-09-27)**: i bottoni a sola icona del menu in alto a
sinistra (Home, Admin per gli admin, Impostazioni, Disconnetti; issue #120)
mostrano il loro nome tradotto, lo stesso dell'etichetta accessibile, nel
tooltip nativo di Slint 1.18 al passaggio del mouse: un popup che non
intercetta clic, leggibile nel tema chiaro e scuro. Con la tastiera il nome
del bottone che ha il focus compare su una riga sotto le icone, senza
coprire nulla.

**Aggiornamento (2026-09-28)**: lo storico più vecchio di un canale o di
una query si carica da solo (issue #125): quando chi legge arriva, con la
rotella, la scrollbar o PgSu dal campo di scrittura, entro un terzo di
schermo dalla riga più vecchia caricata, Cordiale chiede la pagina
precedente a Grappa (`?before=<id più vecchio>&limit=100`), una alla volta
per finestra e mai due volte lo stesso cursore, fino all'inizio dello
storico. La riga che chi legge aveva in cima resta al suo posto, allo stesso
scostamento. Se una pagina fallisce si riprova solo tornando in cima (o con
PgSu), mai in un ciclo. Il bottone "Carica messaggi più vecchi" non c'è
più; PgSu/PgGiù dal campo di scrittura scorrono la chat di una schermata.

**Aggiornamento (2026-10-01)**: una riga di canale espulso (kick), in attesa
di join, invitata o con join rifiutato non sparisce più dalla sidebar quando
Grappa manda `channels_changed` o dopo un attach/detach di rete (issue #184).
`GET /networks/:slug/channels` non elenca un canale non-autojoin da cui si è
stati espulsi, quindi la sostituzione dell'elenco lo perdeva subito dopo il
banner "kicked". Ora la riga resta, grigia, con chi ha espulso e il motivo,
insieme alla sua sottoscrizione al topic, finché non la chiudi con la x o
non rientri; dopo un refresh di rete si conservano anche stato e metadati
delle finestre delle reti che restano, a meno che `/boot` non le dia di nuovo
come entrate.

**Aggiornamento (2026-10-02)**: le righe di chat tenute in memoria per
finestra hanno un tetto (issue #205). Una finestra non aperta (o lasciata)
oltre 5.500 righe torna a 5.000 scartando le più vecchie; quella aperta lo
fa solo mentre il pannello segue l'ultima riga, quindi chi sta rileggendo lo
storico non perde niente sotto gli occhi. Dopo lo scarto lo storico non è
più "arrivato all'inizio" e i cursori già chiesti sono dimenticati, così
scorrere in alto ricarica le righe scartate con `?before=` come prima. Un
messaggio privato in tempo reale che si ordina per ultimo si aggiunge come
una riga sola, come nei canali, invece di ricostruire tutto il pannello; il
pannello si ricostruisce solo se l'ordine cambia o se non corrisponde più
alle righe salvate. La pagina Debug mostra le righe tenute (totale e
finestra più grande). Non misurato su una finestra da 50k righe e mai
provato a mano contro un server reale.

**Aggiornamento (2026-10-07)**: tipo di ban predefinito per `/kb` e
`/kickban` (issue 247), in Settings > Display: `nick` (`nick!*@*`), `host`
(`*!*@host`, il predefinito, come prima) o `user_host` (`*!user@host`, con
l'ident come lo restituisce `resolve_userhost`, tilde compresa). Il tipo è
fissato quando parte il comando, quindi cambiarlo durante l'attesa della
risposta non altera la richiesta. Se manca una parte necessaria alla forma
scelta (per esempio `not_cached`) non parte né il ban né il kick, la barra di
stato lo dice e non si ripiega mai su una maschera diversa; prima il kick
partiva comunque. Ordine ban poi kick invariato, comandi senza conferma del
server. La preferenza è ora
un'impostazione di account (`GET/PUT /me/settings/ban-mask-form`, protocollo
38, `ban_mask_form`): si legge all'accesso, si salva con PUT e il valore
attivo cambia solo a risposta riuscita; assente o 404 (server pre-38) vale
`host`. Il vecchio campo locale `default_ban_type` è ritirato e ignorato in
`settings.json`, senza caricarlo sul server. Cordiale dichiara ancora
`client_proto=37`: il bump a 38 va riletto sul sorgente di Grappa. Limiti: la grafia `*!user@host` è quella IRC usuale, non
riletta sul sorgente upstream (issue upstream 2347), e va riallineata quando
Cicchetto fissa dove salva l'impostazione. Il menu Kickban e le voci Ban nick
/ Ban host (issue 246) non ci sono ancora: potranno usare `BanType::mask`.
