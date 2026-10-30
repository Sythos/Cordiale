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
   **Invio a più dispositivi.** Il motore cifra un corpo per dispositivo e tiene
   separati `msg` e `pkmsg`. Prima del primo invio pianifica tutte le richieste:
   ognuna ha al massimo 4 corpi e rispetta il limite di byte (32 KiB), di righe
   (64) e di frame (64). I frame si contano come Cicchetto (`linesNeeded`): la
   testa del frame (verbo, msgid, `i/n`, `from`, `to`) più il payload, con
   `frame_budget_base` di ISUPPORT meno i byte del nick. Un gruppo troppo grande
   si divide in modo goloso. `to` è il `did` se la richiesta ha un solo corpo,
   `*` se ne ha più d'uno. Se un corpo non sta da solo, la chiamata fallisce con
   `PayloadTooLarge` prima di ogni richiesta e il testo non esce mai in chiaro.
   Senza `frame_budget_base` noto il motore non conta i frame e lascia quel limite
   al server. Ogni corpo usa il proprio messaggio Olm: nessuno si riusa per un
   altro dispositivo. Una richiesta non accettata non diventa `Accepted`; dopo la
   prima richiesta accettata, il fallimento di una successiva lascia quel gruppo
   senza il messaggio. Fonte: CIC `wire.ts` (`linesNeeded`, `MAX_FRAGMENTS`);
   OLM-4 `engine.py` (`_emit_group`). Codice: `e2e_wire.rs` (`frames_needed`),
   `e2e_engine.rs` (`split_by_limits`, `request_fits`). Prove: `e2e_engine.rs`
   `a_pre_key_send_uses_one_request_when_the_frames_fit`,
   `a_pre_key_send_splits_when_the_group_is_above_the_frame_limit`,
   `a_body_that_does_not_fit_alone_fails_before_any_request`,
   `both_message_kinds_split_by_the_frame_limit`.
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
   `skipped`. Le rotte `/e2e/pairings`, i token di errore e i push
   `e2e_pairing_message` e `e2e_pairing_closed` sono riletti sul testo 4g
   (`client.rs`, `e2e_pairing.rs`, `session.rs`). Codice: `e2e_pairing_flow.rs`. Prove: fixture
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
   - **2456**: il motore invia un corpo per ogni dispositivo del peer e divide il
     gruppo per byte, righe e frame (vedi punto 4, «Invio a più dispositivi»).
   - **2457**: non si applica. Cordiale non ha un messaggio SAS a più
     dispositivi.
   Dettagli: `docs/protocol-notes.md`, issue 453 e 458.

## Regola di replay

La finestra di 256 id per dispositivo in `e2e_peer.rs` è una scelta del client.
Il controllo "sessione già vista" segue il motore di irc-olm (OLM-4,
`engine.py`). Nessun requisito del relay lo impone.

## Versione del protocollo

`CLIENT_PROTOCOL_VERSION` è 50. Il testo completo di G-PROTO (sezioni 1-9, dal
`protocol_version` 37 al 50) è stato riletto per intero nel secondo passaggio
della fetta 37. Le funzioni dei protocolli 38-41 erano già nel client (vedi
`docs/feature-matrix.md`); le funzioni 42-50 sono quelle di questo contratto.
Il numero resta un intero semplice sull'URL del WebSocket. Un server sotto il 49
non parla il formato per dispositivo: il client non fa E2E con quel server.

## Fixture

Tutti i file stanno in `crates/cordiale-core/tests/fixtures/e2e/`. Sono JSON
semplice, leggibili da un'altra implementazione. Revisione corrente: la riga
`fixture_revision` di ogni file, controllata dal test
`every_fixture_file_has_the_revision_of_the_interop_report`.

| Area | File (revisione) | Test |
|---|---|---|
| testi firmati, `did`, certificati, liste, frame, righe di inbox, rifiuti, copie S1 | `wire_v2.json` (4) | `tests/e2e_wire_fixtures.rs` |
| corpo dell'invio | `send_request.json` (3) | `rest.rs` |
| `e2e_send_dropped` | `send_dropped.json` (3) | `e2e_pacing.rs` |
| accoppiamento | `pairing_v1.json` (1) | `e2e_pairing_flow.rs` |
| vettori nel formato di irc-olm PR 4 | `irc_olm_v2.json` (1) | `tests/e2e_irc_olm_interop.rs` |
| revoca, sessioni (replay), scadenza, copie S1 consegnate o scadute | `lifecycle_v1.json` (1) | `tests/e2e_lifecycle_fixtures.rs` |

## Interoperabilità con irc-olm (OLM-4)

`irc_olm_v2.json` ha firme e testi nel formato di `devices.py` e `engine.py` di
irc-olm (merge `1606c85`). Le due direzioni sono provate in
`tests/e2e_irc_olm_interop.rs`:

- **irc-olm verso Cordiale:** KEYS (chiave monouso e di ripiego), `pkmsg`, `msg`
  (uno e due dispositivi) e messaggi interni si leggono e si verificano con il
  codice di Cordiale; i payload non validi sono rifiutati con lo stesso errore.
- **Cordiale verso irc-olm:** i testi firmati di Cordiale (lista, id, certificato,
  chiave monouso, `fb`) sono uguali byte per byte a quelli di irc-olm, le firme
  di irc-olm si verificano su di essi, e i payload di Cordiale si riscrivono
  uguali ai vettori. Il test `the_payloads_that_cordiale_sends_pass_the_shape_checks_of_irc_olm`
  (`e2e_engine.rs`) applica a `pkmsg` e `msg` scritti dal motore i controlli di
  forma di `_on_pkmsg`, `_on_msg` e `_own_body`; `the_inner_text_of_cordiale_equals_the_bytes_of_irc_olm`
  confronta i messaggi interni.

I corpi cifrati dei vettori sono byte di prova: nessun processo irc-olm gira nei
test. È un controllo della forma comune sul filo, non uno scambio dal vivo.

## Ingressi non validi

Casi di input malformato, vecchio, ripetuto, duplicato, scaduto, revocato o per
un altro dispositivo: `wire_v2.json` (frame, liste, certificati, righe),
`lifecycle_v1.json` (revoca, replay, scadenza), `irc_olm_v2.json` (payload),
`e2e_engine.rs` (`a_replayed_pkmsg_gives_no_second_row_under_any_row_id_or_msgid`,
`a_message_for_another_device_gives_no_row`,
`a_repeated_event_or_inbox_item_gives_one_row`).

## Prove con un server

Nessun server di test o di staging con protocollo 50 è raggiungibile da questo
ambiente. Le prove con server simulato (`wiremock`) non sono interoperabilità
reale. Vedi `docs/e2e-interop-report.md` per il blocco esterno. Il file
`tests/e2e_live_server.rs` ha due prove in sola lettura, `#[ignore]`, per un server
reale (variabili `CORDIALE_LIVE_*`); il rapporto spiega come eseguirle e come
provare a mano lo scambio con irc-olm.

## Lista di approvazione finale

Nessun deploy in produzione fa parte di questa fetta. Ogni casella ha la sua prova;
il corpo della PR riporta la stessa tabella.

| Casella | Prova |
|---|---|
| `docs/e2e-contract.md` esiste e cita le fonti | questo documento, sezioni «Fonti» e «Contratto» |
| nessun marcatore «candidato» nei moduli E2E senza fonte finale | test `no_e2e_module_keeps_a_candidate_marker` (`tests/e2e_contract_guard.rs`); formati confermati in `docs/protocol-notes.md` («Contratto finale E2E») |
| fixture per ogni area, con revisione corrente | tabella «Fixture»; `every_fixture_file_has_the_revision_of_the_interop_report` |
| due voci per peer, senza righe né cronologia incrociate | punto 8 del contratto; `plain_and_locked_sends_stay_in_their_own_entries`, `a_copy_shows_as_sent_in_the_locked_query_and_once_only` |
| il 202 non è una consegna; le copie S1 seguono il caso accettato | punti 4 e 5 del contratto; `a_202_answer_sets_the_accepted_state_only`, `the_accepted_original_that_is_dropped_leaves_a_sent_copy_and_a_failed_row` |
| prove in due direzioni con irc-olm | sezione «Interoperabilità con irc-olm» (forma sul filo) |
| prove con un server protocollo 50 | **non eseguite**: blocco esterno in `docs/e2e-interop-report.md` |
| decisioni su Grappa 2453, 2454, 2456 e 2457 | punto 9 del contratto |
| `CLIENT_PROTOCOL_VERSION` dopo la rilettura completa | sezione «Versione del protocollo»; `protocol.rs` |
| CI e controlli di sicurezza sul commit finale | verdi sullo SHA della PR (controllo del merge) |
