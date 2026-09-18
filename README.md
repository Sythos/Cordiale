# Cordiale

Cordiale è un client desktop nativo per Grappa, sviluppato in Rust con Slint.
Non parla IRC direttamente: usa REST e Phoenix Channels/WebSocket secondo il
contratto client di Grappa.

## Stato

Il repository contiene lo scaffold iniziale del workspace e non implementa
ancora il client di rete. La priorità della Fase 1 è il percorso completo di
configurazione server, autenticazione, bootstrap, realtime e messaggistica.

## Workspace

- `crates/cordiale-core` — modello, protocollo e logica condivisibile;
- `crates/cordiale-ui` — eseguibile Slint e punto di ingresso della GUI;
- `resources/i18n/{en,it,fr,de,es}` — risorse per l'internazionalizzazione;
- `packaging/windows` e `packaging/linux` — spazio per i deliverable futuri
  (note di packaging in `docs/packaging-windows.md` e
  `docs/packaging-linux.md`);
- `docs/` — documentazione tecnica: contratto protocollo Grappa
  (`protocol-notes.md`), matrice funzionalità (`feature-matrix.md`), note
  di packaging.

## Riferimenti

- Protocollo client Grappa:
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>
- Cicchetto, riferimento funzionale:
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto>
