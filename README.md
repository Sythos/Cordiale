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
- **Guest/visitor access**: leave the password blank to enter the guest flow.
  Whether guest access is available is up to the selected Grappa server;
  Cordiale doesn't send a made-up shared guest password.
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
- **Realtime event coverage (0.1.4 tester build)**: the current Grappa
  protocol lists 56 top-level event kinds. Cordiale handles 15 of them:
  `links_bundle`,
  `members_seeded`, `names_reply`, `topic_changed`, `channel_modes_changed`,
  `query_windows_list`, `own_nick_changed`, `read_cursor_set`,
  `away_confirmed`, `window_counts`, `channels_changed`, `joined`,
  `join_failed`, `kicked`, and `message`; the remaining 41 kinds are
  deliberately ignored for this tester
  release. They won't appear as fake `event: payload` chat messages. Query
  snapshots replace the full query-window map, map network IDs to native
  sidebar rows, subscribe via Cicchetto's channel-shaped/ASCII-folded topic,
  and load/deduplicate history around join acknowledgements. The own-nick
  event updates only its mapped network; Cordiale leaves the old listener
  before joining the new topic unless that canonical topic is still owned by
  an open query, keeps case-only changes on the same canonical topic, and
  accepts inbound listener messages only after a successful join ACK and only
  when their nested kind is `privmsg` or `action`. A small
  FIFO holds messages whose sender is not in the current query snapshot; a
  valid `query_windows_list` drains it only for queries the server actually
  lists, dropping unmatched entries rather than inventing rows. The queue is
  capped at 32 messages and evicts the oldest on overflow. `read_cursor_set`
  seeds per-window cursors and the account-wide unread badge from `/me`, then
  applies live channel-topic cursor pushes last-write-wins (including a
  backward cursor from an authoritative event), clamping the badge to 0..99.
  Cordiale currently retains that badge in session state but does not yet map
  it to an OS taskbar/dock icon badge. `window_counts` seeds per-window
  mention badges from `/me` and successful joins, then updates them from
  server pushes; message and event totals remain locally derived, matching
  Cicchetto. Peer queries update on their own topics, while the own-nick
  listener targets the self-message window. This is not complete
  DM parity: overflow or an invalid/missing authoritative query snapshot can
  still lose realtime DMs.
  Cicchetto is the behavior reference, and native parity work is still in
  progress. A failed
  join keeps a muted pseudo-row, hides its roster, and retains `reason` and
  `numeric` only in session state. A kick also keeps a muted, accessible,
  selectable pseudo-row without a roster; its `by` and `reason` metadata stay
  in session state, and its close control sends a server-side PART before
  removing the row locally. Away confirmations validate the user-topic
  carrier and known network, then update only that network's state; the
  still-ignored `mentions_bundle` remains a separate event gap. Known gaps are
  grouped below.
  `channels_changed` validates the user-topic signal, refetches the
  authoritative channel list, and reconciles sidebar rows and subscriptions
  idempotently while preserving topics still owned by a query or own-nick
  listener. A failed refresh keeps the existing state.
  - **Window, channel, and scrollback state**: `channel_created`,
    `window_pending`, `window_invited`,
    `window_invite_declined`, `archive_changed`,
    `archive_purged`.
  - **Network, connection, identity, and settings**: `network_attached`,
    `network_detached`, `connection_progress`,
    `connection_state_changed`, `isupport_changed`,
    `umode_changed`, `supported_umodes_changed`, `session_identity_changed`,
    `peer_away`, `auto_away_debounce_changed`,
    `auto_away_reason_changed`, `quit_part_reason_changed`,
    `server_settings_changed`, `web_session_severed`.
  - **Presence, queries, and server replies**: `presence_changed`,
    `presence_error`, `presence_snapshot`, `notify_list`, `who_reply`,
    `whois_bundle`, `whois_avatar_ready`, `whowas_bundle`, `lusers_bundle`,
    `banlist_bundle`, `server_reply`, `invite_ack`, `mentions_bundle`.
  - **Transfers and other asynchronous work**: `dcc_offer`,
    `dcc_offer_resolved`, `directory_progress`, `directory_complete`,
    `directory_failed`, `recover_progress`, `recover_result`, `bundle_hash`.
  - Unknown future event kinds are also silently dropped, as Grappa's
    protocol requires. Within message envelopes, `topic`, `kick`, and
    `server_event` still use generic system-message rendering rather than
    dedicated text.
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
