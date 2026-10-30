# Contratto E2E di Cordiale (protocolli 46-50)

Questo documento è il contratto finale del client per l'E2E (ombrello 416, fetta
37). Ogni punto cita una fonte e una prova nel codice. In caso di divergenza
prevale il sorgente di Grappa.

## Fonti

- **G-2430**: discussione della issue 2430 di Grappa (formato wire v2).
- **G-PROTO**: `docs/CLIENT_PROTOCOL.md` di Grappa, sezioni 4f (relay) e 4g
  (accoppiamento), ramo `main`.
- **G-PR**: PR 2446, 2448, 2451, 2452, 2459 e 2460 di Grappa (modifiche dei
  protocolli 46-50, confluite in G-PROTO).
- **OLM-4**: PR 4 di irc-olm (merge `1606c85`), motore e README.
- **CIC**: `cicchetto/src/lib/e2e/` di Grappa (`wire.ts`, `pairing*.ts`).

## Contratto

1. **Frame.** `\x01E2E <verb> <msgid> <i>/<n> <from> <to> <chunk>\x01`. Il client
   non vede le righe IRC: riceve `e2e_message`. Fonte: G-PROTO 4f.
   Codice: `e2e_wire.rs` (`format_frame`, `parse_frame`). Prova:
   `tests/e2e_wire_fixtures.rs` con `tests/fixtures/e2e/wire_v2.json`.
2. **Dispositivi.** `did` = primi 8 byte di SHA-256 della chiave, base64url senza
   riempimento, 11 caratteri; fino a 4 dispositivi per identità. Fonte: G-PROTO
   4f. Prova: i due vettori in `wire_v2.json` (`fixture_did_vectors_match`).
3. **Testi firmati.** Id: `irc-e2e:v2:id:<curve25519>:<master>`. Lista:
   `irc-e2e:v2:list:<ver>:<chiavi ordinate, separate da ",">`. Certificato:
   `irc-e2e:v2:dev:<ver>:<ed25519>`, con `<ver>` = versione della lista che porta
   il dispositivo. Fonte: G-PROTO 4f e 4g (messaggio `signed`); CIC `wire.ts`;
   OLM-4 `devices.py`. Codice: `e2e_wire.rs`, `e2e_device.rs`, `e2e_trust.rs`.
   Prova: `fixture_certificates_match`, `fixture_signed_lists_match`.
4. **Invio.** `POST .../e2e/send`: la risposta 202 è una **accettazione**, mai una
   consegna. Lo stato `Accepted` può passare a "caduto" con `e2e_send_dropped`,
   mai a "consegnato". Fonte: G-PROTO 4f (porta di invio, `too_late`,
   `e2e_send_dropped`). Prove: `e2e_engine.rs`
   `a_202_answer_sets_the_accepted_state_only` e
   `an_accepted_send_can_become_a_dropped_send_and_never_a_delivered_one`;
   `tests/fixtures/e2e/send_dropped.json`.
5. **Copie S1 (v50).** Le porte `claim` e `copies` agiscono solo dentro l'account,
   mai su IRC. Una copia si crea solo dopo il 202 dell'originale e solo per i
   dispositivi della lista firmata al momento del 202. Il testo interno è
   `{"t":"copy","peer":…,"body":…}`. Una copia `own` di un dispositivo non
   elencato o con firma non valida si scarta; con un certificato per una lista
   più nuova si rilegge la lista e si riprova. Fonte: G-PROTO 4f; CIC `wire.ts`
   (`CopyInner`). Prove: `e2e_engine.rs`
   `a_claimed_key_gives_one_copy_per_sibling_and_none_goes_over_irc`,
   `a_server_list_that_adds_a_device_gives_that_device_no_copy`,
   `a_copy_of_a_device_that_the_own_list_does_not_name_is_not_read`,
   `a_copy_from_a_newer_list_waits_until_the_own_list_syncs`,
   `the_accepted_original_that_is_dropped_leaves_a_sent_copy_and_a_failed_row`;
   fixture `copy_inner` di `wire_v2.json` (`fixture_copy_inner_messages_read`).
6. **Scadenza e pacing.** Valori di `e2e_pacing.rs` (`md3_pacing`) da OLM-4 e
   G-PROTO 4f (`expires_at`, 7 giorni, 1 MiB per le copie). Una copia scaduta si
   scarta senza avviso. Prova: `e2e_engine.rs`
   `a_copy_that_waited_longer_than_the_inbox_lifetime_is_dropped`.
7. **Accoppiamento (G-PROTO 4g, v48).** Canale ECIES con info `irc-e2e:v2:pair` e
   modo cifre `AllowLeadingZero`. Il primo payload del joiner è base64url di
   `InitialMessage.encode()`. Messaggi in chiaro (JSON compatto, `"v":1`):
   `hello`, `offer`, `join`, `signed`, `done`. Il codice a due cifre lo mostra il
   nuovo dispositivo e lo digita il detentore, che poi manda `offer`; solo dopo
   la conferma sul nuovo dispositivo (in Cordiale `/e2e code`) parte `join`;
   il detentore firma solo dopo `join` e chiude il rendezvous dopo `done`.
   Cordiale accoppia una rete per volta: le altre reti dell'`offer` vanno in
   `skipped`. Codice: `e2e_pairing_flow.rs`. Prove: fixture
   `tests/fixtures/e2e/pairing_v1.json`
   (`the_fixture_messages_read_and_the_invalid_ones_do_not`) e i test di
   sessione nello stesso file (ordine dei messaggi, codice errato, firma id
   errata, rifiuti, ripetizione, payload troppo grande, scadenza).
8. **Due voci per peer.** `<user>` resta la query legacy in chiaro. `🔒<user>` è
   una voce locale, aperta quando ci sono capacità E2E e un canale cifrato. Il
   lucchetto è solo UI: non entra mai in una chiave di fiducia, sessione o
   replay. Le due cronologie non si mescolano. Le righe in chiaro vanno solo alla
   voce legacy; le righe decifrate e le copie S1 solo alla voce bloccata; dalla
   voce bloccata non c'è ripiego in chiaro. Fonte: G-2430 (decisione sulle due
   voci). Prove: `cordiale-ui/src/e2e_view.rs`
   `the_two_lanes_of_one_peer_have_two_keys_and_one_real_nick`,
   `cordiale-ui/src/e2e_runtime.rs` `one_peer_has_two_entries_with_separate_keys`,
   `e2e_engine.rs` `a_copy_shows_as_sent_in_the_locked_query_and_once_only`.
9. **Decisioni su Grappa 2453, 2454, 2456 e 2457.**
   - **2453**: il fix JavaScript non è un requisito del client; il guard di
     replay resta nel file cifrato (`set_replay`). Fonte: G-2430.
   - **2454**: una riga `server_event` con `meta.e2e_undeliverable` è un avviso
     per questo dispositivo solo se `meta.e2e_device` è un `did` proprio; per un
     altro dispositivo il testo cita il `did`. Senza `e2e_device` vale per
     questo dispositivo.
   - **2456**: rinviata. Il motore invia un solo corpo per messaggio a un solo
     dispositivo del peer, quindi non c'è un gruppo da ridurre.
   - **2457**: non si applica. Cordiale non ha un messaggio SAS a più
     dispositivi.
   Dettagli: `docs/protocol-notes.md`, issue 453 e 458.

## Regola di replay

La finestra di 256 id per dispositivo in `e2e_peer.rs` è una scelta del client.
Il controllo "sessione già vista" segue il motore di irc-olm (OLM-4,
`engine.py`). Nessun requisito del relay lo impone.

## Versione del protocollo

`CLIENT_PROTOCOL_VERSION` non cambia in questa fetta. Il testo completo del
protocollo 50 non è stato riletto: sono state rilette solo le sezioni 4f e 4g.

## Prove con un server

Nessun server di test o di staging con protocollo 50 è raggiungibile da questo
ambiente. Le prove con server simulato (`wiremock`) non sono interoperabilità
reale. Vedi `docs/e2e-interop-report.md` per il blocco esterno.

## Lista di approvazione finale

Il corpo della PR elenca ogni casella con la sua prova. Nessun deploy in
produzione fa parte di questa fetta.
