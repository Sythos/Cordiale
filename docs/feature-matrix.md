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

Colonna "Fase Cordiale": fase prevista di valutazione/implementazione
secondo la roadmap in `MEMORY.md` §9; `—` = non ancora decisa, richiede
verifica aggiuntiva sul codice server prima di pianificare.

| Funzionalità (cicchetto) | Nel protocollo Grappa? | Fase Cordiale | Note |
|---|---|---|---|
| Login username/password | Sì | Fase 1 | `POST /auth/login` |
| Token per-client come alternativa a TOTP/passkey | Sì | Fase 1 | Stesso campo `password`; scoped, `403 client_token_scope` fuori scope |
| Bootstrap `/api/config` + `/boot` + `/me` | Sì | Fase 1 | Sequenza di avvio |
| Phoenix Channels realtime (user/network/channel topic) | Sì | Fase 1 | Vedi protocol-notes §2 |
| network/channel/query, messaggi, stato realtime | Sì | Fase 1 | Perimetro Fase 1 dichiarato in `MEMORY.md` |
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
| Ignore list, watchlist, alias comandi, perform on connect | No / non documentato | — | Presumibilmente puramente client-local |
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

## Voci ancora da chiarire prima di poter classificare

- Guest/visitor: non documentato nel contratto client, ma **confermato
  reale** con un test diretto contro `irc.sindro.me` il 2026-09-18
  (`identifier: "guest"` → sessione `kind: "visitor"` funzionante). Il
  meccanismo esiste ma è ancora troppo poco compreso (semantica del campo
  `password` in questo flusso, portabilità tra istanze Grappa) per
  costruire una UI affidabile — vedi `protocol-notes.md` §5 per il dettaglio
  completo del test e `MEMORY.md` §3.3.
- Assegnazione ruolo admin: nessuna procedura documentata.
- Heartbeat/backoff WebSocket: da verificare sul codice server o sul default
  di `phoenix.js` prima di fissare la strategia di riconnessione.
