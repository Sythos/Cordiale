# Cordiale

![Cordiale](resources/branding/cordiale.png)

Cordiale is a native desktop client for Grappa, written in Rust with Slint.
It doesn't speak IRC directly: it uses REST and Phoenix Channels/WebSocket
per Grappa's documented client protocol.

## Why Cordiale

Some of us just want to sit on Grappa without hauling a full browser engine along for the ride. Gecko, WebKit, Chromium — doesn't matter which one, even the "vanilla" build with zero bloatware still helps itself to 700–800MB of RAM just to render some chat. Cordiale's whole pitch is being the cheap-on-resources alternative: Rust and Slint give it enough cross-compile flexibility to cover Windows on both x64 and ARM64 (yes, Surface people, you're covered), a handful of popular Linux distros as proper native packages, and the usual adaptable `.tar.gz` for whichever distro didn't make the automated build lineup.

## The wider Grappa ecosystem

Cordiale isn't the only way to sit on a Grappa server, and it's worth knowing what else is out there:

- **["Grappa"](https://github.com/vjt/grappa-irc)** itself is the always-on bouncer/server this whole thing revolves around — REST + Phoenix Channels, no raw IRC on the wire unless you go through Shottino below. Own repo, own maintainer, own history.
- **"Cicchetto"** is Grappa's own web PWA — installable on a phone home screen, speaks pure REST/WebSocket, never touches raw IRC. It lives inside the `grappa-irc` repo itself (`cicchetto/`), not a separate project, so it shares Grappa's maintainer and contributors rather than having its own.
- **"Shottino"** is also inside `grappa-irc` (`frontends/shottino/`): a standalone terminal client that, run with `--ircd`, turns into a bridge server so old-school IRC clients — irssi, WeeChat, HexChat, whatever you're already attached to — can point at a Grappa network like it's a normal ircd.
- **["Resentin"](https://github.com/LucentW/resentin)** is the odd one out in a good way: a native Android client for Grappa, written in Kotlin/Compose, and an entirely separate project with its own owner and contributors, unrelated to the `grappa-irc` repo.
- **["Bicchierino"](https://github.com/Essency/bicchierino)** is another separate, standalone project (maintained by Sonic): a stateless IRC-facade bridge to Grappa, in the same spirit as Shottino but its own codebase and its own repo.

Each of the above has its own maintainer(s) and its own issue tracker — if something's broken in Grappa, Cicchetto, Shottino, Resentin, or Bicchierino, that's the place to report it, not here.

## Status

Phase 2 (parity and polish) is in progress. `cordiale-core` has a domain
model, local persistence under `~/.cordiale/`, a credential store (OS
keychain with an explicitly insecure fallback), a REST client for the
bootstrap sequence (`/api/config`, `/auth/login`, `/boot`, `/me`,
sending a message, reading/writing display preferences) with a documented
status-code contract, a hand-rolled Phoenix Channels transport over
`tokio-tungstenite`, and a realtime session layer on top of it (user-topic
join, heartbeat, reconnect-with-rejoin).

`cordiale-ui` runs everything from a single persistent background worker
thread: a splash screen, a first-launch language picker, a connect screen,
a two-pane connected screen (channel list sidebar, message history, a
compose box wired to the real send-message endpoint, live updates pushed
over the WebSocket session), and a Settings screen whose navigation
mirrors Cicchetto's own Settings drawer (`docs/feature-matrix.md`) —
General (language, Light/Dark) and Display (five real preferences, synced
with the server) work today; the remaining sections say plainly that they
need server endpoints Cordiale doesn't implement yet, rather than either
hiding or faking functionality. The REST layer's request/response shapes
have been checked against the real `irc.sindro.me` server (not just
mocks) and match, including an undocumented guest/visitor login mode —
see `docs/protocol-notes.md` §5. The UI is fully translated into Italian,
French, German and Spanish (bundled at build time, switchable live, no
runtime gettext dependency), and the compose box, server list and channel
list carry explicit accessibility labels for screen readers. Settings →
Admin is real for `is_admin` accounts: overview, sessions (+ disconnect),
users (+ toggle admin, delete), networks (+ circuit reset), visitors
(+ delete), session log, and a reaper-sweep trigger — Grappa's actual
admin surface turned out to be considerably larger than initially scoped
(30+ endpoints across eight areas, see `docs/protocol-notes.md` §4ter),
so vhosts, credentials, server-wide settings, and the live admin event
stream are deliberately not built yet rather than attempted half-blind.
`/links` reconstructs the same network-topology tree Cicchetto does
(same root-selection and orphan-handling logic, tested independently of
any server) and offers both an indented-list view and a "Show graph"
button that opens a second window with a real radial layout, drawn with
Slint's native `Path` element — same depth-driven radius and angular-
slice logic as Cicchetto's own layout, no pan/zoom yet. What's still
missing: performance profiling, deliberately deferred to after field
testing. The one gap nobody but a live server can close is field testing
against a real Grappa instance through the actual GUI — that's next.

## Download

No packaged release yet: an earlier `v0.1.2` was pulled after shipping
before the client actually worked end to end (websocket, channel view,
message send — none of it was there). The next tag goes out once the
client is functional with the whole test suite green, not before. Until
then, build from `main`:

```bash
git clone https://github.com/Sythos/Cordiale.git
cd Cordiale
cargo build --release --package cordiale-ui
./target/release/cordiale-ui
```

Once packaged releases resume, see
[docs/installation.md](docs/installation.md) for per-platform instructions.

## Workspace

- `crates/cordiale-core` — domain model, protocol, persistence, credentials,
  REST/WebSocket clients, and other shareable logic;
- `crates/cordiale-ui` — Slint executable and GUI entry point;
- `crates/cordiale-ui/lang/{it,fr,de,es}/LC_MESSAGES/cordiale-ui.po` — UI
  translations, bundled into the binary at build time by `slint-build`
  (no runtime gettext dependency); English is the untranslated source
  text, no `en/` file needed;
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
