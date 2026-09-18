# Cordiale

![Cordiale](resources/branding/cordiale.png)

Cordiale is a native desktop client for Grappa, written in Rust with Slint.
It doesn't speak IRC directly: it uses REST and Phoenix Channels/WebSocket
per Grappa's documented client protocol.

## Why Cordiale

Some of us just want to sit on Grappa without hauling a full browser engine along for the ride. Gecko, WebKit, Chromium — doesn't matter which one, even the "vanilla" build with zero bloatware still helps itself to 700–800MB of RAM just to render some chat. Cordiale's whole pitch is being the cheap-on-resources alternative: Rust and Slint give it enough cross-compile flexibility to cover Windows on both x64 and ARM64 (yes, Surface people, you're covered), a handful of popular Linux distros as proper native packages, and the usual adaptable `.tar.gz` for whichever distro didn't make the automated build lineup.

## Status

Phase 1 (minimal functional client) is in progress. `cordiale-core` has a
domain model, local persistence under `~/.cordiale/`, a credential store
(OS keychain with an explicitly insecure fallback), a REST client for the
bootstrap sequence (`/api/config`, `/auth/login`, `/boot`, `/me`) with a
documented status-code contract, and a hand-rolled Phoenix Channels
transport over `tokio-tungstenite`.

`cordiale-ui` has a splash screen, a first-launch language picker, a
connect screen (server URL, username, password/client token) that runs
the actual bootstrap sequence on a background thread, and a post-login
screen listing the account's networks. The REST layer's request/response
shapes have been checked against the real `irc.sindro.me` server (not just
mocks) and match, including an undocumented guest/visitor login mode —
see `docs/protocol-notes.md` §5. What's still missing: saved
multi-server/profile management, Light/Dark theming, translated UI
strings (only the language *picker* works today, the labels are still
English), the fuller Settings screens (mapped from Cicchetto's structure
in `docs/feature-matrix.md`, not yet built), and an actual channel/message
view — the WebSocket/Phoenix Channels side hasn't been exercised against a
real server yet, only the REST bootstrap has.

Packaging is ahead of the app itself: releases already build and publish
cleanly for every target below, even though there isn't much of a client
in them yet.

## Download

Packaged releases (installers, distro packages, source archive) are on the
[Releases page](https://github.com/Sythos/Cordiale/releases) — see
[docs/installation.md](docs/installation.md) for per-platform instructions.

## Workspace

- `crates/cordiale-core` — domain model, protocol, persistence, credentials,
  REST/WebSocket clients, and other shareable logic;
- `crates/cordiale-ui` — Slint executable and GUI entry point;
- `resources/i18n/{en,it,fr,de,es}` — internationalization resources;
- `resources/branding/` — project image and app icon source;
- `packaging/windows` and `packaging/linux` — space for future deliverables
  (packaging notes in `docs/packaging-windows.md` and
  `docs/packaging-linux.md`);
- `docs/` — technical documentation: Grappa protocol contract
  (`protocol-notes.md`), feature matrix (`feature-matrix.md`), packaging
  notes, and how to [install a release](docs/installation.md).

## References

- Grappa client protocol:
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>
- Cicchetto, functional reference:
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto>
