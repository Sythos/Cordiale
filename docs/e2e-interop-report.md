# Rapporto di interoperabilità E2E v2

Rapporto del cancello di accettazione (issue 390, aggiornato dalla fetta 37
dell'ombrello 416). Il contratto finale è in `docs/e2e-contract.md`.

## Revisioni

- Fixture in `crates/cordiale-core/tests/fixtures/e2e/`: `wire_v2.json`
  revisione 4, `send_request.json` e `send_dropped.json` revisione 3,
  `pairing_v1.json` revisione 1.
- Pin MD-3 di irc-olm: PR 4 unita (merge `1606c85`). Il motore (`e2e_engine.rs`)
  segue il suo formato di KEYS, `pkmsg`, `msg` e messaggio interno. Nessun test
  usa il vecchio pin v1 come prova v2.
- Protocolli 46-50: il testo di Grappa (`CLIENT_PROTOCOL.md`, sezioni 4f e 4g) è
  riletto nella fetta 37. I testi firmati e i messaggi di accoppiamento non sono
  più candidati.

## Controlli eseguiti (test senza server)

- `e2e_wire_fixtures`: `did` (due vettori), certificato, lista firmata, frame,
  righe di inbox con `own`, rifiuti del relay, testo interno `copy` di S1.
- `e2e_engine`: la risposta 202 dà solo lo stato "accettato"; un invio accettato
  può cadere e non diventa mai "consegnato".
- `e2e_engine`: copie S1 solo dopo il 202, solo per i dispositivi della lista
  firmata, scadenza, liste vecchie, dispositivo non elencato.
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
- I vettori di irc-olm PR 4 sono letti dal sorgente di riferimento. Non c'è un
  processo irc-olm collegato ai test: le prove nelle due direzioni restano da
  eseguire.

## Lacune note

- Prove bidirezionali con irc-olm PR 4 e con un server reale.
- Fixture di chiavi, sessioni e revoche: coperte da test unitari, non da file di
  fixture condivisi.
- L'accoppiamento segue 4g per una rete per volta. Un `offer` con più reti si
  legge per la rete scelta; le altre vanno in `skipped`. L'accoppiamento con
  Cicchetto non è provato con un server reale.
- Non eseguito in questo ambiente: build e test Rust (il compilatore locale è
  troppo vecchio per le dipendenze). La CI della PR li esegue.
