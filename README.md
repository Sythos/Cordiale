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

## Known gaps

Cordiale is functional end to end (REST bootstrap, realtime WebSocket
session, channel/message view, self-service settings, admin panel for
`is_admin` accounts), but hasn't yet been field-tested against a live
server through the actual GUI — that's what this release is for. Before
you file an issue, here's what's already known to be incomplete rather
than broken:

- **Admin panel** covers overview, sessions, users, networks, visitors,
  session log and a reaper trigger — vhost grants, credentials,
  server-wide settings, and the live admin event stream aren't built.
- **Settings** has no way to read back your *current* per-network
  identity (nick/ident/realname): the fields start blank, and saving
  them blank leaves your existing values untouched.
- **Watch Lists** (presence and keyword highlights) reset on every
  reconnect or relaunch — Grappa has no read-back endpoint for either,
  so Cordiale only tracks them for the current session.
- **On-Connect Commands** is a single-line field, not a multi-line
  editor — separate multiple commands yourself.
- The **`/links` graph window** has no pan/zoom yet.
- **Attachments**: the paperclip icon in the compose bar is there, but
  sending doesn't do anything yet — Grappa's contract doesn't document a
  plain REST upload (attachments look DCC-based), so this needs its own
  protocol research pass.
- **mIRC color codes** render per-segment, but a line with multiple color
  runs doesn't wrap as one paragraph — Slint's layout doesn't do inline
  text flow across separately-colored spans, so a long multi-color line
  can overflow sideways instead of wrapping.
- **Channel topic** is read from `boot` at connect time and updated live
  if a frame happens to carry a `topic` field — there's no confirmed
  `topic_changed`-style event name in the protocol notes, so a server that
  pushes topic changes under some other shape won't update it live.
- **Channel members list** (the right-hand column with `@`/`%`/`+` role
  prefixes): the `boot`-time snapshot is best-effort (the field/shape
  isn't documented, so it's parsed defensively and may come back empty),
  but the list also builds up live from join/part/quit/nick-change
  traffic, so it fills in correctly over time even when the snapshot
  doesn't. What it does **not** track yet is role changes: a `MODE +o`/
  `+v`/etc. on someone already in the list doesn't update their `@`/`+`
  prefix (mode-change frame shape isn't confirmed yet), so a prefix shown
  can go stale after a promotion/demotion until the channel is reselected
  or Cordiale reconnects. This also means the context-menu's op-only
  actions (Op/Deop/Voice/Devoice/Kick/Ban) are gated on your *last-known*
  role, not necessarily your current one.
- Performance hasn't been profiled — deliberately deferred until after
  field testing surfaces real usage patterns.

## Download

Packaged releases (installers, distro packages, source archive) are on
the [Releases page](https://github.com/Sythos/Cordiale/releases) — see
[docs/installation.md](docs/installation.md) for per-platform
instructions. Prefer building from source? `main` always builds:

```bash
git clone https://github.com/Sythos/Cordiale.git
cd Cordiale
cargo build --release --package cordiale-ui
./target/release/cordiale-ui
```

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
