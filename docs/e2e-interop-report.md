# Rapporto di interoperabilità E2E v2

Rapporto breve del cancello di accettazione (issue 390). È **parziale**: il
cancello completo non può chiudersi finché i contratti a monte non sono finali.

## Revisioni

- Fixture: `crates/cordiale-core/tests/fixtures/e2e/wire_v2.json`, revisione 1
  (più `send_request.json`, già in uso da `rest.rs`).
- Pin MD-3 di irc-olm: PR 4 unita (merge `1606c85`). Il motore (`e2e_engine.rs`)
  segue il suo formato di KEYS, `pkmsg`, `msg` e messaggio interno; vedi
  `docs/protocol-notes.md`, issue 453 passo 4. Nessun test usa il vecchio pin v1
  come prova v2.
- Protocolli: 46, 47 e 48 hanno modifiche unite a monte. Il protocollo 49 è il
  candidato della PR 2452 di Grappa (bozza): non è definitivo.

## Controlli eseguiti (test `e2e_wire_fixtures`, nessun server)

- `did`: due vettori approvati, compreso quello con `-` e `_`.
- Certificato di dispositivo: testo firmato esatto, lettura inversa, rifiuto di
  zero iniziale, versione 0, versione oltre il limite, chiave corta, prefisso v1.
- Lista firmata: testo esatto, ordine delle chiavi indipendente da chi chiama,
  rifiuto di lista vuota, doppioni, versione 0 e chiave non valida.
- Frame: cinque verbi validi con ritorno identico a `format_frame`; rifiuto di
  frame senza campi `from`/`to` (forma v1), verbo sconosciuto, coppie di
  indirizzi non ammesse, frammenti non validi e testo non ASCII.

## Lacune note

- Nessuna prova bidirezionale con il pin MD-3 finale.
- Nessuna prova contro un server di staging o di test.
- Fixture mancanti: chiavi, sessioni, esiti di invio, accoppiamento (X1),
  cambi di dispositivo, copie proprie (S1).
- Il testo firmato, l'ordine delle chiavi e le rotte, i campi e gli errori del
  protocollo 49 restano da ricontrollare dopo l'unione della PR 2452.
- Da verificare: nessuna risposta 202 va riportata come consegna.
- Il documento `docs/e2e-contract.md` citato nella issue non esiste.
