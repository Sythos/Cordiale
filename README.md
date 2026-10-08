# Cordiale

![Cordiale](resources/branding/cordiale.png)

Cordiale is a native desktop client for Grappa, written in Rust with Slint.
It doesn't speak IRC directly: it uses REST and Phoenix Channels/WebSocket
per Grappa's documented client protocol. It keeps pace with Cicchetto's
everyday features without bringing a browser engine to chat.

## Why Cordiale

Some of us just want to sit on Grappa without hauling a full browser engine along for the ride. Gecko, WebKit, Chromium — doesn't matter which one, even the "vanilla" build with zero bloatware still helps itself to 700–800MB of RAM just to render some chat. Cordiale's whole pitch is being the cheap-on-resources alternative: Rust and Slint give it enough cross-compile flexibility to cover Windows on both x64 and ARM64 (yes, Surface people, you're covered), a handful of popular Linux distros as proper native packages, macOS on both Apple Silicon and Intel, and the usual adaptable `.tar.gz` for whichever distro didn't make the automated build lineup.

## The wider Grappa ecosystem

Fair warning: the Grappa biome is spreading, and it is **not** slowing down. What started as one humble bouncer now sprouts web apps, terminal bridges, Android clients and native desktop apps faster than you can say "just one more glass", and at this rate it'll have colonized every device in the known universe before your IRC client of choice finishes reconnecting. Resistance is futile. Pick a client and pour yourself a drink.

Cordiale isn't the only way to sit on a Grappa server, and it's worth knowing what else is out there:

- **["Grappa"](https://github.com/vjt/grappa-irc)** itself is the always-on bouncer/server this whole thing revolves around — REST + Phoenix Channels, no raw IRC on the wire unless you go through Shottino below. Own repo, own maintainer, own history.
- **"Cicchetto"** is Grappa's own web PWA — installable on a phone home screen, speaks pure REST/WebSocket, never touches raw IRC. It lives inside the `grappa-irc` repo itself (`cicchetto/`), not a separate project, so it shares Grappa's maintainer and contributors rather than having its own.
- **"Shottino"** is also inside `grappa-irc` (`frontends/shottino/`): a standalone terminal client that, run with `--ircd`, turns into a bridge server so old-school IRC clients — irssi, WeeChat, HexChat, whatever you're already attached to — can point at a Grappa network like it's a normal ircd.
- **["Resentin"](https://github.com/LucentW/resentin)** is the odd one out in a good way: a native Android client for Grappa, written in Kotlin/Compose, and an entirely separate project with its own owner and contributors, unrelated to the `grappa-irc` repo.
- **["Bicchierino"](https://github.com/Essency/bicchierino)** is another separate, standalone project (maintained by Sonic): a stateless IRC-facade bridge to Grappa, in the same spirit as Shottino but its own codebase and its own repo.

Each of the above has its own maintainer(s) and its own issue tracker — if something's broken in Grappa, Cicchetto, Shottino, Resentin, or Bicchierino, that's the place to report it, not here.

## Features

The channel sidebar and member list have resizable columns with content-based
minimum widths. Channel rows sit directly below their network row, under
a **Channels** entry that opens the network's channel list, member
roles appear in brackets (for example, `[@] Sythos`), and the member list's
Actions menu includes a shortcut to the Themes settings. As in Cicchetto, a
message that mentions you (your nick on that network or a `/hilight`
pattern, as a whole word) gets the mention background, and is bold unless
"bold mentions" is off in Settings > Display. Scrolling up (or PgUp in
the message box) past the oldest loaded line fetches the previous page of
history from Grappa, page by page, keeping the line you were reading in
place. On a channel window the Actions menu has a **Denoise** toggle that
leaves join, part, quit, nick-change and mode lines out of that channel's
transcript (a mode that changes the channel itself, like a ban, stays); the
events are still kept, so turning it off brings them back. The choice is
saved per network and channel, synced with Grappa's `presence_filter`
preference, and a channel with 200 or more members starts denoised until you
pick, as in Cicchetto.

Right-click a sender in the chat and **Reply** drops a Cicchetto-style quote
into that window's draft, ready to edit before sending; the same nick menu in
the member list stays message-free. Settings > Display now has a live
**50–150% font size** control with a one-click reset. The choice is kept on
this device, and the unread count sits centered alongside its channel row
instead of wandering into the row below.

The Actions menu opens the radio: Cicchetto's stations (SomaFM and a few
other Icecast streams) play in Cordiale itself, with the same player on
every platform for MP3, Ogg Vorbis and **FLAC** streams (yes, lossless radio
gets a seat at the table). You also get a volume control and the current
track, read from the station's feed or the stream's own titles;
`/np` shares it in the open window. Settings > Radio adds, edits and
removes your own stations (stream or `.pls`/`.m3u` URLs), kept on this
device only.

The Debug page (the bug icon before Settings, or the Actions menu) shows
selectable, copyable details about your system: Cordiale version and build,
operating system, CPU, RAM, how many chat rows Cordiale holds in memory,
display, locale, time zone, and where Cordiale keeps its files. Paste them into a bug report. They are generated locally
and never uploaded, and the text leaves out account names, server addresses,
tokens and your user name in paths. Anything the platform can't report
reliably says "Not available"; the keyboard layout is only read on Windows,
and the input method isn't detected yet.

Cordiale keeps its files where each platform expects them: settings and
servers in the config folder (`~/.config/cordiale`, `%APPDATA%\Cordiale`,
`~/Library/Application Support/Cordiale`), the keyring fallback in the local
data folder and the log in the state or log folder (`~/.local/state/cordiale`,
`%LOCALAPPDATA%\Cordiale`, `~/Library/Logs/Cordiale`). An older `~/.cordiale`
folder is copied across on the first start (each file is checked, then the old
ones are removed; if that fails the old folder stays in use and the Debug page
says so). Files are written atomically and, on Unix, privately (folders 0700,
files 0600), and a settings or servers file that no longer parses is kept as
`.corrupt` instead of being overwritten. The log is capped at 1 MiB with one
rotated copy (`cordiale.log.1`).

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
and turns off automatic sign-in until the next successful sign-in. The
icons at the top of the sidebar (Home, Admin, Settings, Disconnect) show
their name in a tooltip on hover, and under the icons on keyboard focus.
On Windows, launching the desktop app opens its UI without an extra console
window; the release workflow checks the GUI subsystem in both x64 and ARM64
executables before packaging them.

### Parity with Cicchetto

Compared with [Cicchetto on Grappa's main branch](https://github.com/vjt/grappa-irc/tree/main/cicchetto),
Cordiale also covers:

- **Home and network state:** a Cicchetto-style home view shows active,
  parked and failed networks, featured channels and networks available to
  connect. Reconnect or remove a binding there, and see the current network
  and channel modes above the topic instead of having to guess.
- **Account security:** password sign-in can finish Grappa's TOTP challenge
  with an authenticator code or one-time recovery code. Full-session users
  can enable or disable TOTP in Settings > Security and see new recovery
  codes once. On Windows, Cordiale runs the passkey ceremony itself through
  `webauthn.dll` (Windows Hello, security keys, a phone): passkey as second
  factor, passwordless sign-in from the connect screen, and in Settings >
  Security adding a passkey, changing the passkey mode and turning on
  passwordless (not yet tried with a real authenticator). Builds made with
  the optional `ctap-hid` cargo feature do the same on Linux and macOS with
  a USB security key and its PIN (CI builds and lints it on Linux and macOS,
  but it hasn't been tried with a real key yet; the release packages leave
  it off). Elsewhere,
  passkey-only sign-in still needs a share link or client token from
  Cicchetto; an account whose passkey is backed by recovery codes can sign
  in with one of those, and a passwordless account can sign in from the
  connect screen with a one-time recovery code (not yet checked against a
  live server). Settings > Security also lists the account's passkeys and
  deletes them with the password.
- **Cleartext warning:** an `http://` server address that isn't this device
  (anything but `localhost`, `*.localhost`, `127.0.0.0/8` and `::1`) shows a
  warning on the connect, share-token and recovery-code screens and keeps the
  sign-in buttons disabled until you confirm sending your credentials
  unencrypted. The confirmation is kept only in memory and is asked again
  when the address changes; a remembered `http://` server also skips the
  automatic sign-in at launch. A passkey origin override with the same kind
  of address gets the same warning. Local development servers are never
  blocked.
- **TLS trust:** REST and the realtime socket verify the server's
  certificate against the operating system's store, so a server behind a
  private or corporate CA works once that CA is installed. A rejected
  certificate stops the session with a message in the status bar (this
  computer doesn't trust it, with the reason) instead of retrying forever;
  sign in again after fixing the trust.
- **Session sharing:** Settings > Security makes a single-use link and QR
  code (valid ten minutes) that signs another device into the same account,
  and the connect screen signs in with such a link or token from another
  device, for example one made in Cicchetto after a passkey sign-in. Not yet
  checked against a live server.
- **Connection and presence:** Cordiale declares the protocol revision it
  was checked against (`client_proto=37`) and, if Grappa refuses the
  upgrade with `426`, stops and asks you to update instead of retrying.
  A dropped connection is retried after 1 s, then 2 s, 4 s and so on up to
  a minute (each wait varied by up to a quarter, so clients that dropped
  together don't return together), honouring a `Retry-After` from the server;
  the status bar says when the next attempt is due, and a rate-limited send
  says how long to wait. After a reconnect it catches up each channel's
  missed messages (a short gap is paged in, a long one reloads the latest
  messages and leaves a note where
  the hole is), and it tells Grappa while the window is in the foreground so
  auto-away and push notifications follow. A channel invite offers Join and
  Decline. On a server that renames private windows itself (protocol 34 to
  36) a peer's nick change keeps the same window; from protocol 37 a nick
  change moves nothing and the peer's next message opens a new window beside
  the old one.
- **Channel directory:** each network's Channels entry (or `/list`) opens
  its channel list beside the sidebar: search, Refresh, the channel count
  and how old the list is, then name, topic and user count per channel.
  One click (or Enter) joins a channel, or opens it if you're already in.
- **The newer Grappa preferences:** date order follows your language or
  your explicit choice; auto-away nick suffixes are server-backed; ignore
  rules pair an IRC mask with an optional text pattern.
- **Your own profile:** per network, Settings > General edits the CTCP
  USERINFO fields (age, gender, location, languages, custom) and uploads or
  removes your avatar.
- **Themes:** Grappa's gallery themes (or built-in copies) with their
  day/night pairing and wallpapers; the account's own themes can be created,
  edited (27 colors with a live preview, font, wallpaper), copied, deleted
  and published.
- **Admin tools:** the panel (which needs a password sign-in; a client
  token is refused on `/admin`) creates accounts, resets passwords and
  creates, edits and deletes networks and their IRC servers, edits the
  server-wide upload, DCC and addressing settings, binds and unbinds
  credentials, manages vhosts and their grants to accounts and visitors,
  and follows the live admin event feed. Deleting a network first asks the
  server how many messages that removes with it (protocol v33 deletes the
  whole scrollback along with the network) and says so in the confirmation;
  if the server can't say, the confirmation says that instead of showing
  zero. The panel also terminates an account's live session, reconnects a
  visitor's, edits a network's featured channels, an IRC server and a
  credential's nick, ident, real name, SASL user and password. Its Uploads tab can inspect the
  upload budget and remove an active upload early; that is admin-only,
  not a secret delete button for everyone else.
- **Settings and watch lists:** the identity editor reads back the nick in
  use on each network, watch-list keywords are read from Grappa, and
  On-Connect Commands take one IRC command per line. Settings >
  Notifications edits the push switches, the per-channel and per-nick lists,
  muted conversations (muted from the Actions menu, for an hour, eight hours
  or for good) and the sound other devices play, also set with `/beep`. A
  muted conversation shows a bar above the compose box with the time it was
  muted at (when this device did it) and the time left, plus a button to
  unmute it right away.
- **Uploads and attachments:** the paperclip uploads a picked file through
  Grappa (`POST /api/uploads`) and posts its link with the category emoji,
  as Cicchetto does, after checking the file type and the advertised size
  cap. Settings > General sets how long uploads are kept and whether to ask
  before each one. Files dropped on the window and images pasted into the
  compose box go through the same flow, and pasting several lines of text
  offers to upload them as `paste.txt`. The upload popup (and Settings, as
  a device-local default that the popup never writes back) has a "Shrink
  videos before sending" switch for videos: the video is re-encoded into a
  temporary MP4 (VP9, audio copied, at most 720p), and the result is checked
  against the server's cap before it goes up. The original is never touched,
  and a video that can't be shrunk or comes out no smaller is not uploaded.
  It needs a build with the `video-shrink` feature (FFmpeg with libvpx);
  other builds show the switch disabled. Links in messages are clickable:
  image and text uploads on Grappa, and https images elsewhere, open in the
  media viewer (fit or actual size; text read-only, with Copy), MP3, Ogg and
  FLAC links play in the radio's player, and the rest opens in the browser.
  Like Cicchetto, Cordiale shows no inline previews. Only http, https and
  ftp links open (not `file:`, `javascript:`, `mailto:` or links with a user
  name or password), and the browser gets the normalised URL. A download for the
  viewer follows at most five redirects and refuses one that goes from
  https to http or from a public host into the local network.
- **Slash commands:** the everyday IRC verbs (`/me`, `/msg`, `/notice`,
  `/query`, `/join`, `/part`, `/cycle`, `/topic`, `/nick`, `/away`, `/ctcp`,
  `/ping`, op/voice/kick/ban/mode, `/quote`, `/oper`,
  `/connect`/`/disconnect`/`/reconnect`/`/quit`, `/ignore`, `/notify`,
  `/hilight`, `/ame`/`/amsg`, `/alias`/`/unalias` with Cicchetto's alias
  expansion, `/kb` with a default ban type of nick, host or user@host
  chosen in Settings and kept on the device, `/beep`, the services
  shortcuts), `/np` for the radio,
  and a bare `/umode` that opens the user-mode toggles; a bare `/topic` or
  `/mode` shows the channel's topic or modes in the status bar.
- **Chat:** multi-colored mIRC messages wrap as one paragraph, channel MODE
  changes follow the network's ISUPPORT PREFIX and CHANMODES, and direct
  messages that arrive before the query snapshot are recovered from
  Grappa's history. Each window keeps its newest 5,000 rows in memory (older
  ones are fetched again when you scroll back), and a new direct-message line
  is appended in place instead of rebuilding the whole list.
- **Presentation:** WHOIS avatars in PNG, JPEG, GIF, WebP or BMP; the
  account-wide unread count in the window title and, on Windows, as a
  badge on the taskbar button.

## Known gaps

- **Account security:** outside Windows, registering a passkey, signing in
  with one and changing the passkey mode (no WebAuthn ceremony there unless
  built with the `ctap-hid` feature for USB keys, see
  `docs/passkey-spike.md`), and everywhere creating or managing client
  tokens and account deletion, still live in Cicchetto. TOTP, the passkey list and session
  sharing work in Cordiale with a full password-backed session; a scoped
  client token cannot use Grappa's account-security endpoints.
- **Not yet tried against a live server:** passkey listing and deletion,
  the Windows passkey ceremonies (no real authenticator either),
  session-sharing links, channel-history catch-up after a reconnect, the
  reconnect back-off and the `Retry-After` handling, the TLS trust against a
  private CA, the move of the files out of `~/.cordiale` on real Windows and
  macOS machines, the history cap in a long-running window, the
  foreground presence reports, the `client_proto` declaration and its `426`
  handling, DM renames by conversation id (servers below protocol 37), the
  coexisting old and new private windows after a peer's nick change on
  protocol 37, declining an invite, your own
  profile and avatar, and the newer admin operations. They follow the server's
  source and pass tests against a mock server; expect rough edges.
- **Platform limits:**
  - Files dropped on the window reach Cordiale on Windows, macOS and X11,
    not on Wayland, where the windowing layer doesn't report them.
  - The unread badge is drawn only on the Windows taskbar; macOS and Linux
    show the count in the window title.
  - Themes restyle the window, chat and member list, while buttons and
    menus keep Slint's own widget style in its dark or light variant.
- **Server data:** Grappa no longer reports a network's ident and realname,
  so the identity editor starts those two fields blank.

## Download

Packaged releases (installers, distro packages, source archive) are on
the [Releases page](https://github.com/Sythos/Cordiale/releases) — see
[docs/installation.md](docs/installation.md) for per-platform
instructions. The Debian, Ubuntu, AlmaLinux and Arch packages declare the
libraries they need (`libasound`, fontconfig, the X11 and Wayland ones, GL
and xkbcommon), and a CI check fails if a new shared library isn't covered.
Prefer building from source? `main` always builds:

```bash
git clone https://github.com/Sythos/Cordiale.git
cd Cordiale
cargo build --release --package cordiale-ui
./target/release/cordiale-ui
```

## Workspace

- `crates/cordiale-core` — domain model, protocol, persistence, credentials,
  REST/WebSocket clients, and other shareable logic;
- `crates/cordiale-ui` — Slint executable and GUI entry point. `main.rs`
  holds the setup and the shared state (`WorkerState`, grouped in sub-structs
  by area), the handlers live in modules (`frames`, `slash`, `admin_handlers`,
  `history`, `channels`, `queries`, `worker_commands`, `ui_callbacks` and the
  smaller ones), and the unit tests are in `tests.rs`;
- `crates/cordiale-ui/lang/{it,fr,de,es}/LC_MESSAGES/cordiale-ui.po` — UI
  translations, bundled into the binary at build time by `slint-build`
  (no runtime gettext dependency); English is the untranslated source
  text, no `en/` file needed;
- `resources/branding/` — project image and app icon source;
- `packaging/windows` and `packaging/linux` — space for future deliverables
  (packaging notes in `docs/packaging-windows.md` and
  `docs/packaging-linux.md`), and `packaging/check-linux-deps.sh`, which
  maps the binary's shared libraries to each distro's package names;
- `.github/workflows` — CI (formatting, clippy and tests on Linux, Windows and
  macOS, plus the `ctap-hid` feature) and the release packaging;
- `docs/` — technical documentation: Grappa protocol contract
  (`protocol-notes.md`), feature matrix (`feature-matrix.md`), packaging
  notes, and how to [install a release](docs/installation.md).

## References

- Grappa client protocol:
  <https://github.com/vjt/grappa-irc/blob/main/docs/CLIENT_PROTOCOL.md>
- Cicchetto, functional reference:
  <https://github.com/vjt/grappa-irc/tree/main/cicchetto>
