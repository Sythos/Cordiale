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
`is_admin` accounts). It has been exercised through the GUI against a live
Grappa instance during development, but that does not amount to exhaustive
validation across server versions, configurations, or every feature. The
known limitations are:

- **Admin panel** implements overview; session listing/disconnect; user
  listing, `is_admin` toggle, and deletion; network listing/circuit reset;
  visitor listing/deletion; session-log reading; and a reaper trigger.
  Vhost grants, credentials, server-wide settings writes, network
  create/edit/delete, user creation/password changes, and the live admin
  event stream are out of scope.
- **Settings** has no way to read back your *current* per-network
  identity (nick/ident/realname): the fields start blank, and saving
  them blank leaves your existing values untouched.
- **Watch Lists** can send presence and keyword additions/removals, but the
  UI does not restore their server-side state: Cordiale currently ignores
  the presence `notify_list` snapshot, and the keyword-list reply has no
  confirmed shape. The displayed lists are session-local and are cleared
  by an explicit disconnect or app restart; an automatic WebSocket
  reconnect can leave stale local entries.
- **On-Connect Commands** is a single-line field, not a multi-line
  editor — separate multiple commands yourself.
- The **`/links` graph window** has no pan/zoom yet.
- **Guest/visitor access**: connecting with a blank password tries the
  empirically observed `guest`/`guest` login. This works on
  `irc.sindro.me`, but the client protocol does not define a universal
  guest flow, so other Grappa instances may reject it.
- **Attachments** are not implemented: the paperclip displays an explicit
  unsupported status. The client protocol does not define a plain upload
  endpoint; DCC/file transfer needs separate implementation work.
- **mIRC color codes** render per-segment, but a line with multiple color
  runs doesn't wrap as one paragraph — Slint's layout doesn't do inline
  text flow across separately-colored spans, so a long multi-color line
  can overflow sideways instead of wrapping.
- **Channel members list** (the right-hand column with `@`/`%`/`+` role
  prefixes) is populated from `members_seeded`/`names_reply` pushes and
  updated from live join/part/quit/nick-change/mode traffic. The `boot`
  snapshot remains best-effort. Cordiale has no ISUPPORT `CHANMODES`
  table, so a `MODE` string that mixes a tracked prefix mode with another
  argument-taking mode (for example, a ban and an op together) can
  misalign arguments and leave a stale prefix; broader validation across
  server configurations is still needed.
- **Realtime event coverage**: the current upstream inventory has 56
  top-level event kinds. Cordiale handles `links_bundle`,
  `members_seeded`, `names_reply`, `topic_changed`, and `message`; its
  other 51 current kinds are explicitly ignored. This is a feature-parity
  gap, not a lack of upstream precedent: Cicchetto has dispatch cases for
  all 51 across its [user-topic handler](https://github.com/vjt/grappa-irc/blob/main/cicchetto/src/lib/userTopic.ts)
  and [channel handler](https://github.com/vjt/grappa-irc/blob/main/cicchetto/src/lib/subscribe.ts).
  Cordiale still needs a native-feature-by-native-feature review before
  porting them. A genuinely unknown future kind can also fall through to a
  raw `event: payload` chat line, although Grappa's protocol says unknown
  kinds should be ignored. Within message envelopes, `topic`, `kick`, and
  `server_event` use generic system-message rendering rather than dedicated
  text.
- Performance hasn't been profiled — deliberately deferred until after
  broader field testing surfaces real usage patterns.

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
