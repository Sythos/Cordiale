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

Cordiale is functional end to end (REST bootstrap, realtime WebSocket
session, channel/message view, self-service settings, admin panel for
`is_admin` accounts). It has been exercised through the GUI against a live
Grappa instance during development, but that does not amount to exhaustive
validation across server versions, configurations, or every feature.

The channel sidebar has a close button for joined channels. It sends Grappa's
PART request and removes the window after a successful server response; a
failed request leaves the window open. The selected channel header shows the
network and channel above a separate, three-line topic panel.

Parked networks collapse their channel and query rows and show an italic
`[PARKED]` label; their group can still be expanded manually. An authoritative
`/boot` refresh after network removal clears that network and its windows from
the sidebar and leaves its obsolete realtime subscriptions.

In channel chat, a speaker's nick uses the role prefix currently shown in
that channel's member list. Changes to the roster or user modes update visible
lines without rewriting message history; private conversations remain unprefixed.

Settings > Themes (also in the Actions menu) lists Grappa's theme gallery,
including the irssi-derived `irssi-dark` and `sux`, each shown with its color
set. Picking one makes it the account's active theme on Grappa
(`PUT /me/theme`) and restyles Cordiale irssi-style: window background,
monospace font, nick and timestamp colors, channel header and topic box.
Without server themes, built-in copies (irssi-dark, sux, mirc-light,
solarized dark/light) are applied locally; the classic look follows the
light/dark switch. Buttons and menus keep Slint's own widget style in its
dark or light variant.

The known limitations are:

- **Admin panel** implements overview; session listing/disconnect; user
  listing, `is_admin` toggle, and deletion; network listing/circuit reset;
  visitor listing/deletion; session-log reading; and a reaper trigger.
  Vhost grants, credentials, server-wide settings writes, network
  create/edit/delete, user creation/password changes, and the live admin
  event stream are out of scope.
- **Settings** has no way to read back your *current* per-network
  identity (nick/ident/realname): the fields start blank, and saving
  them blank leaves your existing values untouched.
- **Watch Lists**: the presence (notify) list shown for the network
  selected in Settings comes from the server's `notify_list` snapshot, sent
  after joining and after every change, with each nick's presence from
  `presence_snapshot` (online, offline, or plain when unknown), updated by
  `presence_changed`, which also announces each later transition in the
  status bar (never the initial report after connecting); a
  `presence_error` (watch list full) names the nicks that could not be
  watched. The keyword list still has no confirmed reply shape, so it stays
  session-local: cleared by an explicit disconnect or app restart, and an
  automatic WebSocket reconnect can leave stale local entries.
- **On-Connect Commands** is a single-line field, not a multi-line
  editor — separate multiple commands yourself.
- The **`/links` graph window** has no pan/zoom yet.
- **Guest/visitor access**: leave the password blank to try the guest flow:
  Cordiale signs in as `guest`/`guest`, the credentials observed for
  Grappa's visitor login. Whether guest access is accepted is up to the
  selected Grappa server; it is not a capability the protocol guarantees.
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
  snapshot remains best-effort. Cordiale now retains the complete per-network
  ISUPPORT snapshot, including the `CHANMODES` groups and prefix ordering, but
  the channel-mode parser does not yet use that table. A `MODE` string that
  mixes a tracked prefix mode with another argument-taking mode (for example,
  a ban and an op together) can therefore still misalign arguments and leave a
  stale prefix; broader validation across server configurations is still
  needed.
- **Realtime event coverage (0.1.6 BETA (WIP))**: the current Grappa protocol
  lists 56 top-level event kinds, and Cordiale handles all of them:
  `links_bundle`,
  `members_seeded`, `names_reply`, `topic_changed`, `channel_modes_changed`,
  `query_windows_list`, `own_nick_changed`, `read_cursor_set`,
  `away_confirmed`, `window_counts`, `channels_changed`,
  `session_identity_changed`, `isupport_changed`, `umode_changed`,
  `supported_umodes_changed`, `joined`, `join_failed`, `kicked`,
  `window_pending`, `window_invited`, `window_invite_declined`,
  `network_attached`, `network_detached`, `connection_state_changed`,
  `connection_progress`, `recover_progress`, `recover_result`,
  `web_session_severed`, `who_reply`, `server_reply`, `whois_bundle`,
  `whois_avatar_ready`, `whowas_bundle`, `banlist_bundle`,
  `auto_away_debounce_changed`, `quit_part_reason_changed`,
  `auto_away_reason_changed`, `lusers_bundle`, `invite_ack`,
  `directory_progress`, `directory_complete`, `directory_failed`,
  `dcc_offer`, `dcc_offer_resolved`, `archive_changed`, `archive_purged`,
  `notify_list`, `presence_snapshot`, `presence_changed`, `presence_error`,
  `peer_away`, `mentions_bundle`, `server_settings_changed`, `bundle_hash`,
  `channel_created` (consumed without UI, as Cicchetto does), and `message`.
  Only `message` envelopes become chat lines, so no event appears as a fake
  `event: payload` chat message. Query
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
  back-from-away `mentions_bundle` summary is handled separately (see
  below). Known gaps are grouped below.
  `channels_changed` validates the user-topic signal, refetches the
  authoritative channel list, and reconciles sidebar rows and subscriptions
  idempotently while preserving topics still owned by a query or own-nick
  listener. A failed refresh keeps the existing state.
  `window_pending` creates an idempotent pending row from the live user-topic
  signal and subscribes to the channel topic so the subsequent `joined` or
  `join_failed` event is not lost. `window_invited` accepts the required
  `inviter` field from both live and replayed user-topic events, creates an
  invited row, ensures the channel-topic subscription, and shows a Join banner
  without stealing focus. Neither event is seeded from a channel snapshot:
  pending is live-only, while invited is replayed on the user topic. They are
  distinct from one another. `window_invite_declined` is a user-topic terminal
  removal: it clears the invited/pending lifecycle state, Join banner, and
  sidebar row idempotently, without inventing an IRC DECLINE command. The
  channel sidebar also displays
  server-authoritative unread message counts and separates network groups
  visually. `session_identity_changed` stores the per-network `identified`
  verdict separately from its optional display account, including the valid
  `identified=true, account=null` case.
  `isupport_changed` validates the exact user-topic carrier and a known
  positive network ID, then replaces only that network's complete typed
  capability snapshot. It preserves ordered/string collections, maps,
  nullable positive limits, the case-mapping enum, and frame budget while
  tolerating future additive fields.
  `umode_changed` likewise accepts only the exact user-topic carrier and a
  known positive network ID. It replaces only that network's ordered set of
  active unsigned user modes, including empty snapshots and replayed frames.
  `supported_umodes_changed` uses a separate per-network store for the modes
  advertised by 004, preserving order and allowing empty/replayed snapshots;
  it never overwrites the active-mode store.
  `network_attached` and `network_detached` validate the exact user-topic
  carrier and the matching positive network id/slug, then refresh `/boot` and
  `/me` before replacing the network, channel, unread, cursor, roster, topic,
  and history projections. The existing Phoenix session is retained while
  channel and self-listener subscriptions are reconciled; a failed REST
  refresh leaves the old state untouched. The events themselves are never
  treated as complete state snapshots. Replaying an identical attach event is
  idempotent: it reuses the same authoritative snapshot without duplicating
  channel or self-listener subscriptions.
  `connection_state_changed` validates the user-topic carrier and matching
  network identity, applies its home-network row immediately, then refreshes
  `GET /networks`; initial state is seeded from `/boot` plus `/networks` so
  an already parked connection is not mistaken for a new transition. It
  updates only that network's IRC connection state in the
  sidebar, distinguishing retrying `failing` from terminal `failed` and
  leaving Phoenix socket reconnects and network attachment state alone. A
  transition to `parked` or `failed` returns a selected window on that network
  to the connected overview, but an initially parked/failed snapshot does not
  steal the user's selection.
  `connection_progress` is a live-only user-topic overlay: `connecting` shows
  a transient `connecting` label on that network's sidebar row (taking
  precedence over the durable connection label), and `connected` clears it
  and refreshes `GET /networks`. The overlay is dropped whenever the Phoenix
  socket disconnects, because the event is never replayed and a missed
  `connected` would otherwise leave the label stuck.
  `/recover` asks Grappa to run its guided NickServ identity recovery on the
  active network. Nothing is shown optimistically: the first live
  `recover_progress` opens a sidebar panel bound to that event's network,
  later steps replace their own row in place, events for another network are
  ignored while it is open, and unknown future reason tokens are shown
  verbatim. The panel closes only when dismissed. `recover_result` records the
  terminal outcome and reason on that open panel only; it is a no-op when the
  panel was dismissed or belongs to another network. A server rejection of the
  command itself (for example, nothing to recover) is not surfaced yet.
  `web_session_severed` (Grappa's flood protection) signs Cordiale out for any
  string `code`: the Phoenix session is stopped so it never retries with the
  revoked bearer, a remembered copy of that bearer is forgotten, and the
  sign-in screen returns. `rate_limit_flood` gets a dedicated notice explaining
  that the IRC session is still running; other codes show the generic
  sign-in-again message. Because the event is best-effort, a WebSocket
  upgrade refused with 401/403 now ends the session the same way instead of
  retrying forever, and a shut-down session no longer keeps reconnecting in
  the background during its back-off.
  Replies to commands this client issued (requester events) open a reply
  screen instead of a chat line; the latest reply replaces the previous one
  and the selected window is left alone. `/who [target]` (defaulting to the
  open window) shows `who_reply` one user per line; the bundle is validated
  row by row and dropped entirely if any row is malformed. A reply-producing
  command missing a required argument shows a usage hint instead of being sent
  as chat text. `/motd [server]`, `/info`, `/version` and `/admin [server]`
  show `server_reply` lines in wire order; its `source` is validated against
  the closed `info | version | motd | admin` set. The connection-time MOTD is
  unaffected: it still arrives as ordinary server-window scrollback.
  `/whois <nick> [server]` and the member menu's WHOIS show a `whois_bundle`
  card; every field is validated (absent `source` means `user`, absent
  `avatar_url` means none), nullable values are omitted, flags become rows,
  and extra numerics keep their wire order. A cached avatar is only noted,
  not drawn. `whois_avatar_ready` patches only the card for the same network
  and nick (compared with the network's ISUPPORT casemapping, RFC1459 until
  known) and refreshes it in place without reopening the reply screen; a late
  completion for another or replaced card is ignored. `/whowas <nick>` shows
  the most recent `whowas_bundle` record, or a "no history" line when the
  server reports `not_found`; a malformed bundle is dropped instead.
  `/banlist [#channel] [mode]` (the open channel and the server's default `b`
  list unless given; `+e` and `e` are equivalent) shows `banlist_bundle`
  entries in the ircd's order, with the setter and timestamp when known. The
  list letter comes from the reply and is never assumed to be `b`.
  `/lusers [mask [server]]` shows the next `lusers_bundle` for that network
  as twelve counters (unknown ones as `—`); the unsolicited LUSERS burst an
  ircd sends at registration is dropped, and a new connection attempt
  cancels a pending request. `/invite <nick> [#channel]` (the open channel
  by default) is confirmed in the status bar only when the ircd's
  `invite_ack` arrives. `/list [search]` opens a read-only channel directory
  for the active network, paged from Grappa's last `LIST` snapshot
  (`GET /networks/:slug/directory`, sort by users or name, search, load
  more); Refresh asks for a new capture, `directory_progress` refetches the
  first page while it streams and `directory_complete` once the new
  snapshot has replaced the old one; `directory_failed` shows the server's
  reason while keeping the previous list. A `dcc_offer` (a file a peer
  offered, held by Grappa until you consent) appears in the sidebar with
  Accept and Refuse, sent over REST; the offer is never dropped locally,
  only when the server resolves it, and an offer re-sent on subscribe
  replaces the held one. `dcc_offer_resolved` (accepted, refused or
  expired, from any device) removes it and says which in the status bar.
  `/archive` lists the active network's archived windows (left channels
  and closed queries that still have history on the bouncer), with a
  confirmed "Delete history" per entry; `archive_changed` refetches the
  list while it is open (the listing is rate limited upstream, so it is
  never polled). `archive_purged` forgets the cached rows and unread counts
  of the deleted target (matched with the network's casemapping), so a
  later re-join never shows deleted history, and refreshes the open list.
  A `peer_away` (a standalone 301 away reply) is remembered per network and
  peer and shown as a dismissible banner above that peer's private window
  when it is open; a newer message replaces the older one. Coming back
  from away, `mentions_bundle` opens a summary of the messages that
  mentioned you (away period, away message, then each line in order);
  `/mentions` reopens the last one for the active network.
  Settings > General shows a read-only copy of preferences Grappa stores and
  applies itself, updated live from their `*_changed` pushes and hidden until
  announced: `auto_away_debounce_changed` keeps `null` (server default) and
  `0` (off) distinct from a number of seconds, and `quit_part_reason_changed`
  shows the remembered QUIT/PART text or, for `null`, that the server uses its
  own default; `auto_away_reason_changed` does the same for the auto-away
  text, whose `null` keeps Grappa's built-in message. The same section
  shows the per-file upload limits from `server_settings_changed`; Cordiale
  does not upload files yet, so they are informational only.
  `bundle_hash` names the deployed Cicchetto web build: it is validated
  and logged when it changes, and never downloads or updates anything.
  Unknown future event kinds are silently dropped, as Grappa's protocol
  requires. Within message envelopes, `kick` and `topic` rows get their own
  sentences, PART/QUIT/KICK reasons are read from the row body, and
  `server_event` lines render like notices.
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
