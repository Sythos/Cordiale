# Cordiale

![Cordiale](resources/branding/cordiale.png)

Cordiale is a native desktop client for Grappa, written in Rust with Slint.
It doesn't speak IRC directly: it uses REST and Phoenix Channels/WebSocket
per Grappa's documented client protocol.

## Why Cordiale

Some of us just want to sit on Grappa without hauling a full browser engine along for the ride. Gecko, WebKit, Chromium — doesn't matter which one, even the "vanilla" build with zero bloatware still helps itself to 700–800MB of RAM just to render some chat. Cordiale's whole pitch is being the cheap-on-resources alternative: Rust and Slint give it enough cross-compile flexibility to cover Windows on both x64 and ARM64 (yes, Surface people, you're covered), a handful of popular Linux distros as proper native packages, macOS on Apple Silicon, and the usual adaptable `.tar.gz` for whichever distro didn't make the automated build lineup.

## The wider Grappa ecosystem

Cordiale isn't the only way to sit on a Grappa server, and it's worth knowing what else is out there:

- **["Grappa"](https://github.com/vjt/grappa-irc)** itself is the always-on bouncer/server this whole thing revolves around — REST + Phoenix Channels, no raw IRC on the wire unless you go through Shottino below. Own repo, own maintainer, own history.
- **"Cicchetto"** is Grappa's own web PWA — installable on a phone home screen, speaks pure REST/WebSocket, never touches raw IRC. It lives inside the `grappa-irc` repo itself (`cicchetto/`), not a separate project, so it shares Grappa's maintainer and contributors rather than having its own.
- **"Shottino"** is also inside `grappa-irc` (`frontends/shottino/`): a standalone terminal client that, run with `--ircd`, turns into a bridge server so old-school IRC clients — irssi, WeeChat, HexChat, whatever you're already attached to — can point at a Grappa network like it's a normal ircd.
- **["Resentin"](https://github.com/LucentW/resentin)** is the odd one out in a good way: a native Android client for Grappa, written in Kotlin/Compose, and an entirely separate project with its own owner and contributors, unrelated to the `grappa-irc` repo.
- **["Bicchierino"](https://github.com/Essency/bicchierino)** is another separate, standalone project (maintained by Sonic): a stateless IRC-facade bridge to Grappa, in the same spirit as Shottino but its own codebase and its own repo.

Each of the above has its own maintainer(s) and its own issue tracker — if something's broken in Grappa, Cicchetto, Shottino, Resentin, or Bicchierino, that's the place to report it, not here.

## Known gaps

Compared with [Cicchetto on Grappa's main branch](https://github.com/vjt/grappa-irc/tree/main/cicchetto),
Cordiale still has these user-visible or behavioral gaps:

- **Themes:** Cordiale has local Light/Dark styling, but not Cicchetto's
  server-backed theme gallery, day/night pairing, custom-theme editor, or
  theme synchronization. The Themes menu entry opens only local controls.
- **Sign-in and account security:** a remembered Grappa bearer can be reused
  after pressing Connect, but Cordiale does not connect automatically. It
  does not retain the login password for reuse or expose Cicchetto's
  TOTP/passkey management.
- **Admin tools:** the panel lacks vhost grants, credentials, server-wide
  settings writes, network creation/editing/deletion, user creation/password
  changes, and the live admin event stream.
- **Settings and watch lists:** current per-network nick/ident/realname are
  not read back into the identity editor, so its fields start blank.
  Watch-list keywords are session-local rather than reconciled with the
  server. On-Connect Commands uses one line instead of Cicchetto's multiline
  editor; some server-owned preferences and upload limits are read-only.
- **Uploads and attachments:** the paperclip reports that upload is
  unsupported. Cicchetto supports Grappa's upload/media flow and previews;
  Cordiale does not yet send or render those attachments.
- **Chat and roster edge cases:** a message with multiple differently colored
  mIRC runs may overflow instead of wrapping as one paragraph. Channel MODE
  parsing does not yet use the advertised ISUPPORT CHANMODES argument rules,
  so mixed mode strings can misassign a role prefix. A bounded pre-snapshot
  DM queue can drop messages if the authoritative query snapshot is absent
  or late.
- **Remaining presentation gaps:** the `/links` graph has no pan/zoom; a
  WHOIS avatar is reported but not drawn; the account-wide unread count does
  not set an OS taskbar/dock badge. Join-failure and kick reason metadata
  are retained but not fully surfaced in their window rows, and a rejected
  `/recover` command lacks a direct error notice.

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
