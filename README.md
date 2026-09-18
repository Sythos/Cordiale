# Cordiale

Cordiale is a native desktop client for Grappa, written in Rust with Slint.
It doesn't speak IRC directly: it uses REST and Phoenix Channels/WebSocket
per Grappa's documented client protocol.

## Status

Phase 1 (minimal functional client) is in progress. `cordiale-core` already
has a domain model, local persistence under `~/.cordiale/`, a credential
store (OS keychain with an explicitly insecure fallback), a REST client for
the bootstrap sequence (`/api/config`, `/auth/login`, `/boot`, `/me`) with a
documented status-code contract, and a hand-rolled Phoenix Channels
transport over `tokio-tungstenite` — none of it exercised against a real or
mocked Grappa server yet. The GUI in `cordiale-ui` is still a placeholder
window.

## Workspace

- `crates/cordiale-core` — domain model, protocol, persistence, credentials,
  REST/WebSocket clients, and other shareable logic;
- `crates/cordiale-ui` — Slint executable and GUI entry point;
- `resources/i18n/{en,it,fr,de,es}` — internationalization resources;
- `packaging/windows` and `packaging/linux` — space for future deliverables
  (packaging notes in `docs/packaging-windows.md` and
  `docs/packaging-linux.md`);
- `docs/` — technical documentation: Grappa protocol contract
  (`protocol-notes.md`), feature matrix (`feature-matrix.md`), packaging
  notes.

## References

- Grappa client protocol:
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>
- Cicchetto, functional reference:
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto>
