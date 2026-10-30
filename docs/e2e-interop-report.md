# Rapporto di interoperabilità E2E v2

Rapporto del cancello di accettazione (issue 390, aggiornato dalla fetta 37
dell'ombrello 416). Il contratto finale è in `docs/e2e-contract.md`.

## Revisioni

- Fixture in `crates/cordiale-core/tests/fixtures/e2e/`: `wire_v2.json`
  revisione 4, `send_request.json` e `send_dropped.json` revisione 3,
  `pairing_v1.json`, `irc_olm_v2.json` e `lifecycle_v1.json` revisione 1. Il test
  `every_fixture_file_has_the_revision_of_the_interop_report` tiene allineati
  file e rapporto.
- Pin MD-3 di irc-olm: PR 4 unita (merge `1606c85`). Il motore (`e2e_engine.rs`)
  segue il suo formato di KEYS, `pkmsg`, `msg` e messaggio interno. Nessun test
  usa il vecchio pin v1 come prova v2.
- Protocolli 46-50: il testo completo di Grappa (`CLIENT_PROTOCOL.md`, sezioni
  1-9) è riletto nel secondo passaggio della fetta 37. I testi firmati e i
  messaggi di accoppiamento non sono più candidati. `CLIENT_PROTOCOL_VERSION` è 50.

## Controlli eseguiti (test senza server)

- `e2e_wire_fixtures`: `did` (due vettori), certificato, lista firmata, frame,
  righe di inbox con `own`, rifiuti del relay, testo interno `copy` di S1.
- `e2e_irc_olm_interop`: vettori nel formato di irc-olm PR 4 nelle due direzioni.
  KEYS, `pkmsg`, `msg` e messaggi interni di irc-olm si leggono e si verificano con
  Cordiale. I testi firmati di Cordiale (lista, id, certificato, chiave monouso,
  `fb`) sono uguali a quelli di irc-olm e le firme di irc-olm si verificano su di
  essi. I payload non validi hanno lo stesso errore.
- `e2e_engine`: i payload `pkmsg` e `msg` scritti dal motore passano i controlli di
  forma di irc-olm; il testo interno è uguale ai vettori.
- `e2e_lifecycle_fixtures`: revoca (lista più alta, lista con dispositivo revocato,
  lista vecchia, stessa versione con altre chiavi, altro master), replay di primo
  messaggio e di sessione, finestra di 256 id, scadenza di 7 giorni, stati di una
  copia (in coda, consegnata, scaduta, mancante), limiti dell'inbox, svuotamento
  dell'inbox.
- `e2e_engine`: la risposta 202 dà solo lo stato "accettato"; un invio accettato
  può cadere e non diventa mai "consegnato".
- `e2e_engine`: copie S1 solo dopo il 202, solo per i dispositivi della lista
  firmata, scadenza, liste vecchie, dispositivo non elencato; un `pkmsg` ripetuto
  o per un altro dispositivo non dà righe.
- `e2e_pairing_flow`: canale di accoppiamento di 4g (`hello`, `offer`, `join`,
  `signed`, `done`), codice errato, firma id errata, rifiuti, ripetizioni,
  payload troppo grande, scadenza, lista piena, certificato errato.
- `cordiale-ui`: due voci per peer (`<user>` e `🔒<user>`) con chiavi, cronologie
  e bozze separate.

## Prove con un server

- **Blocco esterno:** nessun server di test o di staging con protocollo 50 è
  raggiungibile da questo ambiente. Nessuna prova bidirezionale con un server
  è stata eseguita.
- I test con server simulato (`wiremock` in `e2e_engine.rs`) provano la logica
  del client. Non sono interoperabilità reale.
- I vettori di irc-olm PR 4 sono letti dal sorgente di riferimento. Nessun processo
  irc-olm è collegato ai test: i corpi cifrati dei vettori sono byte di prova.
  Le prove nelle due direzioni controllano la forma comune sul filo e i testi
  firmati, non uno scambio dal vivo con sessioni Olm di irc-olm.

## Come eseguire le prove dal vivo

Servono un server Grappa con protocollo 50, un account di prova e (per lo scambio
con irc-olm) un processo irc-olm PR 4 collegato alla stessa rete.

1. Server: imposta `CORDIALE_LIVE_SERVER`, `CORDIALE_LIVE_TOKEN` e
   `CORDIALE_LIVE_NETWORK`. Poi esegui
   `cargo test -p cordiale-core --test e2e_live_server -- --ignored`.
   I test sono `#[ignore]`: la CI non li esegue e non risultano mai «verdi» senza
   un server. Leggono soltanto (protocollo, rotte dispositivi e lista).
2. irc-olm: avvia irc-olm PR 4 con un account di prova, accoppia Cordiale con
   `/e2e` e scambia un messaggio in ogni direzione dalla voce `🔒<user>`.
   Controlla che il 202 mostri «accettato» e che la copia S1 compaia una volta.
   Questo scambio è manuale: non ha un test automatico.

Fino a quando qualcuno non esegue questi passi, la riga «Prove con un server» sopra
resta un blocco esterno.

## Lacune note

- Scambio dal vivo con irc-olm PR 4 (sessioni Olm reali) e prove con un server
  protocollo 50: servono un server e un processo irc-olm raggiungibili.
- L'accoppiamento segue 4g per una rete per volta. Un `offer` con più reti si
  legge per la rete scelta; le altre vanno in `skipped`. L'accoppiamento con
  Cicchetto non è provato con un server reale.
- Non eseguito in questo ambiente: build e test Rust (il compilatore locale è
  troppo vecchio per le dipendenze). La CI della PR li esegue.
