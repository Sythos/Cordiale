// MIT License
//
// Copyright (c) 2026 Sythos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Inventory and routing metadata for Grappa's documented client-push events.
//!
//! This is deliberately not a closed deserializer for the payload object:
//! Grappa's client protocol is additive, so event consumers decode only the
//! fields they need and ignore extra fields. Unknown future `kind` values are
//! represented by `None` and must be dropped silently, never rendered as raw
//! JSON in chat. The inventory and carrier table mirror §9 of
//! `docs/CLIENT_PROTOCOL.md` on Grappa `main`.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventCarrier {
    User,
    Channel,
    Requester,
}

/// The complete set of 56 client event kinds documented by Grappa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientEventKind {
    ArchiveChanged,
    ArchivePurged,
    AutoAwayDebounceChanged,
    AutoAwayReasonChanged,
    AwayConfirmed,
    BanlistBundle,
    BundleHash,
    ChannelCreated,
    ChannelModesChanged,
    ChannelsChanged,
    ConnectionProgress,
    ConnectionStateChanged,
    DccOffer,
    DccOfferResolved,
    DirectoryComplete,
    DirectoryFailed,
    DirectoryProgress,
    InviteAck,
    IsupportChanged,
    Joined,
    JoinFailed,
    Kicked,
    LinksBundle,
    LusersBundle,
    MembersSeeded,
    MentionsBundle,
    Message,
    NamesReply,
    NetworkAttached,
    NetworkDetached,
    NotifyList,
    OwnNickChanged,
    PeerAway,
    PresenceChanged,
    PresenceError,
    PresenceSnapshot,
    QueryWindowsList,
    QuitPartReasonChanged,
    ReadCursorSet,
    RecoverProgress,
    RecoverResult,
    ServerReply,
    ServerSettingsChanged,
    SessionIdentityChanged,
    SupportedUmodesChanged,
    TopicChanged,
    UmodeChanged,
    WebSessionSevered,
    WhoReply,
    WhoisAvatarReady,
    WhoisBundle,
    WhowasBundle,
    WindowCounts,
    WindowInviteDeclined,
    WindowInvited,
    WindowPending,
}

impl ClientEventKind {
    /// Parses only the discriminator. Consumers remain responsible for
    /// narrowing the fields they use, with absent/null kept distinct where the
    /// wire contract assigns meaning to both.
    pub fn from_payload(payload: &Value) -> Option<Self> {
        Self::from_wire_name(payload.get("kind")?.as_str()?)
    }

    pub fn from_wire_name(name: &str) -> Option<Self> {
        Some(match name {
            "archive_changed" => Self::ArchiveChanged,
            "archive_purged" => Self::ArchivePurged,
            "auto_away_debounce_changed" => Self::AutoAwayDebounceChanged,
            "auto_away_reason_changed" => Self::AutoAwayReasonChanged,
            "away_confirmed" => Self::AwayConfirmed,
            "banlist_bundle" => Self::BanlistBundle,
            "bundle_hash" => Self::BundleHash,
            "channel_created" => Self::ChannelCreated,
            "channel_modes_changed" => Self::ChannelModesChanged,
            "channels_changed" => Self::ChannelsChanged,
            "connection_progress" => Self::ConnectionProgress,
            "connection_state_changed" => Self::ConnectionStateChanged,
            "dcc_offer" => Self::DccOffer,
            "dcc_offer_resolved" => Self::DccOfferResolved,
            "directory_complete" => Self::DirectoryComplete,
            "directory_failed" => Self::DirectoryFailed,
            "directory_progress" => Self::DirectoryProgress,
            "invite_ack" => Self::InviteAck,
            "isupport_changed" => Self::IsupportChanged,
            "joined" => Self::Joined,
            "join_failed" => Self::JoinFailed,
            "kicked" => Self::Kicked,
            "links_bundle" => Self::LinksBundle,
            "lusers_bundle" => Self::LusersBundle,
            "members_seeded" => Self::MembersSeeded,
            "mentions_bundle" => Self::MentionsBundle,
            "message" => Self::Message,
            "names_reply" => Self::NamesReply,
            "network_attached" => Self::NetworkAttached,
            "network_detached" => Self::NetworkDetached,
            "notify_list" => Self::NotifyList,
            "own_nick_changed" => Self::OwnNickChanged,
            "peer_away" => Self::PeerAway,
            "presence_changed" => Self::PresenceChanged,
            "presence_error" => Self::PresenceError,
            "presence_snapshot" => Self::PresenceSnapshot,
            "query_windows_list" => Self::QueryWindowsList,
            "quit_part_reason_changed" => Self::QuitPartReasonChanged,
            "read_cursor_set" => Self::ReadCursorSet,
            "recover_progress" => Self::RecoverProgress,
            "recover_result" => Self::RecoverResult,
            "server_reply" => Self::ServerReply,
            "server_settings_changed" => Self::ServerSettingsChanged,
            "session_identity_changed" => Self::SessionIdentityChanged,
            "supported_umodes_changed" => Self::SupportedUmodesChanged,
            "topic_changed" => Self::TopicChanged,
            "umode_changed" => Self::UmodeChanged,
            "web_session_severed" => Self::WebSessionSevered,
            "who_reply" => Self::WhoReply,
            "whois_avatar_ready" => Self::WhoisAvatarReady,
            "whois_bundle" => Self::WhoisBundle,
            "whowas_bundle" => Self::WhowasBundle,
            "window_counts" => Self::WindowCounts,
            "window_invite_declined" => Self::WindowInviteDeclined,
            "window_invited" => Self::WindowInvited,
            "window_pending" => Self::WindowPending,
            _ => return None,
        })
    }

    pub const fn as_wire_name(self) -> &'static str {
        match self {
            Self::ArchiveChanged => "archive_changed",
            Self::ArchivePurged => "archive_purged",
            Self::AutoAwayDebounceChanged => "auto_away_debounce_changed",
            Self::AutoAwayReasonChanged => "auto_away_reason_changed",
            Self::AwayConfirmed => "away_confirmed",
            Self::BanlistBundle => "banlist_bundle",
            Self::BundleHash => "bundle_hash",
            Self::ChannelCreated => "channel_created",
            Self::ChannelModesChanged => "channel_modes_changed",
            Self::ChannelsChanged => "channels_changed",
            Self::ConnectionProgress => "connection_progress",
            Self::ConnectionStateChanged => "connection_state_changed",
            Self::DccOffer => "dcc_offer",
            Self::DccOfferResolved => "dcc_offer_resolved",
            Self::DirectoryComplete => "directory_complete",
            Self::DirectoryFailed => "directory_failed",
            Self::DirectoryProgress => "directory_progress",
            Self::InviteAck => "invite_ack",
            Self::IsupportChanged => "isupport_changed",
            Self::Joined => "joined",
            Self::JoinFailed => "join_failed",
            Self::Kicked => "kicked",
            Self::LinksBundle => "links_bundle",
            Self::LusersBundle => "lusers_bundle",
            Self::MembersSeeded => "members_seeded",
            Self::MentionsBundle => "mentions_bundle",
            Self::Message => "message",
            Self::NamesReply => "names_reply",
            Self::NetworkAttached => "network_attached",
            Self::NetworkDetached => "network_detached",
            Self::NotifyList => "notify_list",
            Self::OwnNickChanged => "own_nick_changed",
            Self::PeerAway => "peer_away",
            Self::PresenceChanged => "presence_changed",
            Self::PresenceError => "presence_error",
            Self::PresenceSnapshot => "presence_snapshot",
            Self::QueryWindowsList => "query_windows_list",
            Self::QuitPartReasonChanged => "quit_part_reason_changed",
            Self::ReadCursorSet => "read_cursor_set",
            Self::RecoverProgress => "recover_progress",
            Self::RecoverResult => "recover_result",
            Self::ServerReply => "server_reply",
            Self::ServerSettingsChanged => "server_settings_changed",
            Self::SessionIdentityChanged => "session_identity_changed",
            Self::SupportedUmodesChanged => "supported_umodes_changed",
            Self::TopicChanged => "topic_changed",
            Self::UmodeChanged => "umode_changed",
            Self::WebSessionSevered => "web_session_severed",
            Self::WhoReply => "who_reply",
            Self::WhoisAvatarReady => "whois_avatar_ready",
            Self::WhoisBundle => "whois_bundle",
            Self::WhowasBundle => "whowas_bundle",
            Self::WindowCounts => "window_counts",
            Self::WindowInviteDeclined => "window_invite_declined",
            Self::WindowInvited => "window_invited",
            Self::WindowPending => "window_pending",
        }
    }

    pub const fn carrier(self) -> EventCarrier {
        match self {
            Self::BanlistBundle
            | Self::LinksBundle
            | Self::NamesReply
            | Self::ServerReply
            | Self::WhoReply
            | Self::WhoisBundle
            | Self::WhowasBundle => EventCarrier::Requester,
            Self::ChannelCreated
            | Self::ChannelModesChanged
            | Self::MembersSeeded
            | Self::Message
            | Self::ReadCursorSet
            | Self::TopicChanged
            | Self::WindowCounts => EventCarrier::Channel,
            _ => EventCarrier::User,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every kind, to check the wire-name table end to end.
    const ALL_CLIENT_EVENT_KINDS: [ClientEventKind; 56] = [
        ClientEventKind::ArchiveChanged,
        ClientEventKind::ArchivePurged,
        ClientEventKind::AutoAwayDebounceChanged,
        ClientEventKind::AutoAwayReasonChanged,
        ClientEventKind::AwayConfirmed,
        ClientEventKind::BanlistBundle,
        ClientEventKind::BundleHash,
        ClientEventKind::ChannelCreated,
        ClientEventKind::ChannelModesChanged,
        ClientEventKind::ChannelsChanged,
        ClientEventKind::ConnectionProgress,
        ClientEventKind::ConnectionStateChanged,
        ClientEventKind::DccOffer,
        ClientEventKind::DccOfferResolved,
        ClientEventKind::DirectoryComplete,
        ClientEventKind::DirectoryFailed,
        ClientEventKind::DirectoryProgress,
        ClientEventKind::InviteAck,
        ClientEventKind::IsupportChanged,
        ClientEventKind::Joined,
        ClientEventKind::JoinFailed,
        ClientEventKind::Kicked,
        ClientEventKind::LinksBundle,
        ClientEventKind::LusersBundle,
        ClientEventKind::MembersSeeded,
        ClientEventKind::MentionsBundle,
        ClientEventKind::Message,
        ClientEventKind::NamesReply,
        ClientEventKind::NetworkAttached,
        ClientEventKind::NetworkDetached,
        ClientEventKind::NotifyList,
        ClientEventKind::OwnNickChanged,
        ClientEventKind::PeerAway,
        ClientEventKind::PresenceChanged,
        ClientEventKind::PresenceError,
        ClientEventKind::PresenceSnapshot,
        ClientEventKind::QueryWindowsList,
        ClientEventKind::QuitPartReasonChanged,
        ClientEventKind::ReadCursorSet,
        ClientEventKind::RecoverProgress,
        ClientEventKind::RecoverResult,
        ClientEventKind::ServerReply,
        ClientEventKind::ServerSettingsChanged,
        ClientEventKind::SessionIdentityChanged,
        ClientEventKind::SupportedUmodesChanged,
        ClientEventKind::TopicChanged,
        ClientEventKind::UmodeChanged,
        ClientEventKind::WebSessionSevered,
        ClientEventKind::WhoReply,
        ClientEventKind::WhoisAvatarReady,
        ClientEventKind::WhoisBundle,
        ClientEventKind::WhowasBundle,
        ClientEventKind::WindowCounts,
        ClientEventKind::WindowInviteDeclined,
        ClientEventKind::WindowInvited,
        ClientEventKind::WindowPending,
    ];

    #[test]
    fn inventory_has_56_unique_wire_names_and_round_trips() {
        let names: HashSet<_> = ALL_CLIENT_EVENT_KINDS
            .iter()
            .map(|kind| kind.as_wire_name())
            .collect();
        assert_eq!(ALL_CLIENT_EVENT_KINDS.len(), 56);
        assert_eq!(names.len(), 56);
        for kind in ALL_CLIENT_EVENT_KINDS {
            assert_eq!(
                ClientEventKind::from_wire_name(kind.as_wire_name()),
                Some(kind)
            );
        }
    }

    #[test]
    fn unknown_and_malformed_discriminators_are_ignored() {
        assert_eq!(ClientEventKind::from_wire_name("future_kind"), None);
        assert_eq!(
            ClientEventKind::from_payload(&serde_json::json!({"kind": "future_kind"})),
            None
        );
        assert_eq!(ClientEventKind::from_payload(&serde_json::json!({})), None);
        assert_eq!(
            ClientEventKind::from_payload(&serde_json::json!({"kind": 17})),
            None
        );
    }

    #[test]
    fn requester_replies_are_not_misclassified_as_broadcasts() {
        for kind in [
            ClientEventKind::BanlistBundle,
            ClientEventKind::LinksBundle,
            ClientEventKind::NamesReply,
            ClientEventKind::ServerReply,
            ClientEventKind::WhoReply,
            ClientEventKind::WhoisBundle,
            ClientEventKind::WhowasBundle,
        ] {
            assert_eq!(kind.carrier(), EventCarrier::Requester);
        }
    }
}
