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

The channel sidebar and member list have resizable columns with content-based
minimum widths. Channel rows sit directly below their network row, member
roles appear in brackets (for example, `[@] Sythos`), and the member list's
Actions menu includes a shortcut to the Themes settings.

The Actions menu opens the radio: Cicchetto's stations (SomaFM and a few
other Icecast streams) play in Cordiale itself, with the same player on
every platform for MP3, Ogg Vorbis and FLAC streams, a volume control and
the current track read from the station's feed or the stream's own titles;
`/np` shares it in the open window. Settings > Radio adds, edits and
removes your own stations (stream or `.pls`/`.m3u` URLs), kept on this
device only.

Settings > Themes lists Grappa's theme gallery, including the irssi-derived
`irssi-dark` and `sux`, each shown with its color set. Picking one makes it
the account's active theme on Grappa (`PUT /me/theme`) and restyles Cordiale:
window background, monospace font, nick and timestamp colors, channel header
and topic box. Without server themes, built-in copies (irssi-dark, sux,
mirc-light, solarized dark/light) are applied locally; the classic look
follows the light/dark switch. As in Cicchetto, a gallery theme can be paired
with a night theme, which Cordiale switches to while the operating system is
in dark mode. A theme's wallpaper (uploaded or one of Grappa's built-in ones)
is drawn behind the window, full-bleed or tiled at the theme's opacity, and
the member list colors op, halfop and voice markers with the theme's role
colors.

At launch Cordiale signs in automatically with the last remembered profile,
using its Grappa bearer or the login password kept in the OS keyring if the
bearer is rejected. It restores the last selected channel when that channel
is still joined. The login password stays in the native keyring (Windows
Credential Manager, macOS Keychain, or Linux Secret Service), never in
Cordiale's own files; without a keyring it is not stored. The eject button
at the top of the sidebar, or Switch account in the Actions menu, signs out
and turns off automatic sign-in until the next successful sign-in.

## Known gaps

Compared with [Cicchetto on Grappa's main branch](https://github.com/vjt/grappa-irc/tree/main/cicchetto),
Cordiale still has these user-visible or behavioral gaps:

- **Themes:** Cordiale applies Grappa's gallery themes (or built-in copies)
  with their day/night pairing and wallpapers, and edits, copies, deletes and
  publishes the account's own themes. Buttons and menus keep Slint's own widget
  style in its dark or light variant.
- **Sign-in and account security:** Cordiale does not expose Cicchetto's
  TOTP/passkey management.
- **Admin tools:** the panel (which needs a password sign-in; a client
  token is refused on `/admin`) creates accounts, resets passwords and
  creates, edits and deletes networks and their IRC servers, edits the
  server-wide upload, DCC and addressing settings, binds and unbinds
  credentials, manages vhosts and their grants to accounts and visitors,
  and follows the live admin event feed.
- **Settings and watch lists:** the identity editor reads back the nick in
  use on each network, but Grappa no longer reports ident and realname, so
  those start blank; the server's upload limits are shown read-only. Settings >
  Notifications edits the push switches, the per-channel and per-nick lists,
  muted conversations (muted from the Actions menu, for an hour, eight hours
  or for good) and the sound other devices play, also set with `/beep`.
- **Uploads and attachments:** the paperclip uploads a picked file through
  Grappa (`POST /api/uploads`) and posts its link with the category emoji,
  as Cicchetto does, after checking the file type and the advertised size
  cap. Settings > General sets how long uploads are kept and whether to ask
  before each one. Files dropped on the window (Windows, macOS and X11; not
  on Wayland) and images pasted into the compose box go through the same
  flow, and pasting several lines of text offers to upload them as
  `paste.txt`. Links in messages are clickable, as in Cicchetto: image and text
  uploads on Grappa, and https images elsewhere, open in the media viewer
  (fit or actual size; text read-only, with Copy), MP3, Ogg and FLAC links
  play in the radio's player, and the rest opens in the browser.
  Like Cicchetto, Cordiale shows no inline previews.
- **Slash commands:** Cordiale handles the everyday IRC verbs (`/me`,
  `/msg`, `/notice`, `/query`, `/join`, `/part`, `/cycle`, `/topic`, `/nick`,
  `/away`, `/ctcp`, `/ping`, op/voice/kick/ban/mode, `/quote`, `/oper`,
  `/connect`/`/disconnect`/`/reconnect`/`/quit`, `/ignore`, `/notify`,
  `/hilight`, `/ame`/`/amsg`, `/alias`/`/unalias` with Cicchetto's alias
  expansion, `/kb`, the services shortcuts, `/np` for the radio, and a bare
  `/umode` that opens the user-mode toggles; a bare `/topic` or `/mode`
  shows the channel's topic or modes in the status bar).
- **Remaining presentation gaps:** WHOIS avatars are drawn when Grappa
  serves them as PNG, JPEG, GIF, WebP or BMP. The account-wide unread count
  shows in the window title and, on Windows, as a badge on the taskbar
  button; macOS and Linux have no badge.

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
