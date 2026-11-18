//! Notification sounds on this computer.
//!
//! A live mention or direct message in a window that the user does not look
//! at plays one of five bundled sounds. The choices and the volume live in
//! `settings.json` (never on Grappa) and the default is silence. A pure gate
//! decides when a sound plays; one thread owns the output stream.

use std::sync::{mpsc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Instant;

/// Least time between two sounds: a burst of events plays one sound.
pub const MIN_GAP_MS: u64 = 2_000;

/// The bundled sounds. All five are public-domain files; the provenance of
/// each one is in `assets/sounds/PROVENANCE.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoundId {
    Kalimba,
    Bell,
    Alert,
    Dum,
    Deep,
}

impl SoundId {
    /// The sounds in the order of the choice lists (after "none").
    pub const ALL: [SoundId; 5] = [
        SoundId::Kalimba,
        SoundId::Bell,
        SoundId::Alert,
        SoundId::Dum,
        SoundId::Deep,
    ];

    /// The value stored in `settings.json`.
    pub fn key(self) -> &'static str {
        match self {
            SoundId::Kalimba => "kalimba",
            SoundId::Bell => "bell",
            SoundId::Alert => "alert",
            SoundId::Dum => "dum",
            SoundId::Deep => "deep",
        }
    }

    pub fn from_key(key: &str) -> Option<SoundId> {
        SoundId::ALL.into_iter().find(|sound| sound.key() == key)
    }

    fn bytes(self) -> &'static [u8] {
        match self {
            SoundId::Kalimba => include_bytes!("../assets/sounds/kalimba.wav"),
            SoundId::Bell => include_bytes!("../assets/sounds/bell.ogg"),
            SoundId::Alert => include_bytes!("../assets/sounds/alert.ogg"),
            SoundId::Dum => include_bytes!("../assets/sounds/dum.ogg"),
            SoundId::Deep => include_bytes!("../assets/sounds/deep.ogg"),
        }
    }

    fn extension(self) -> &'static str {
        match self {
            SoundId::Kalimba => "wav",
            _ => "ogg",
        }
    }

    /// The fixed gain of the file, never above 1.0. It brings the mean
    /// level of every file down to the level of the quietest one
    /// (measured with the mean volume of the decoded file).
    pub fn gain(self) -> f32 {
        match self {
            SoundId::Kalimba => 0.27,
            SoundId::Bell => 0.87,
            SoundId::Alert => 0.74,
            SoundId::Dum => 1.0,
            SoundId::Deep => 0.52,
        }
    }
}

/// The sound a stored value names. `"none"` and any value that this version
/// does not know give `None`: silence.
pub fn choice_from_setting(value: &str) -> Option<SoundId> {
    SoundId::from_key(value)
}

/// The entry of a choice list (0 is "none") for a stored value.
pub fn choice_index(value: &str) -> i32 {
    SoundId::ALL
        .iter()
        .position(|sound| Some(*sound) == choice_from_setting(value))
        .map_or(0, |position| position as i32 + 1)
}

/// The stored value for an entry of a choice list; an index that is not in
/// the list gives `"none"`.
pub fn choice_key(index: i32) -> &'static str {
    usize::try_from(index)
        .ok()
        .and_then(|index| index.checked_sub(1))
        .and_then(|index| SoundId::ALL.get(index))
        .map_or("none", |sound| sound.key())
}

/// The two events that have a sound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Mention,
    DirectMessage,
}

/// What the gate needs to know about one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateInput {
    /// The event came from the live stream, not from a history page, a
    /// catch-up or the first load of a window.
    pub live: bool,
    /// The window of the event is the selected window.
    pub window_selected: bool,
    /// The Cordiale window has the focus and is not minimized.
    pub app_focused: bool,
    /// The user wrote the message.
    pub own: bool,
    pub muted: bool,
    pub ignored: bool,
    /// The sound that the user chose for the kind of the event (a mention
    /// or a direct message): `None` for "none".
    pub chosen: Option<SoundId>,
    /// Milliseconds since the last sound played, `None` for no sound yet.
    pub since_last_ms: Option<u64>,
}

/// Whether a sound plays for the event. Rules, as in Cicchetto: a sound is
/// chosen, the event is live, the window is out of view (not selected, or
/// the application has no focus), the message is not the user's own and not
/// from an ignored sender, the conversation is not muted, and the last sound
/// is at least `MIN_GAP_MS` old.
pub fn should_play(input: &GateInput) -> bool {
    input.chosen.is_some()
        && input.live
        && !(input.window_selected && input.app_focused)
        && !input.own
        && !input.ignored
        && !input.muted
        && input.since_last_ms.is_none_or(|gap| gap >= MIN_GAP_MS)
}

/// The settings that the player reads. Set at start-up and when the user
/// changes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SoundPrefs {
    direct: Option<SoundId>,
    mention: Option<SoundId>,
    volume: u8,
}

static PREFS: RwLock<SoundPrefs> = RwLock::new(SoundPrefs {
    direct: None,
    mention: None,
    volume: 60,
});

/// Stores the settings values; an unknown value means silence.
pub fn configure(direct: &str, mention: &str, volume: u8) {
    if let Ok(mut prefs) = PREFS.write() {
        *prefs = SoundPrefs {
            direct: choice_from_setting(direct),
            mention: choice_from_setting(mention),
            volume: volume.min(100),
        };
    }
}

/// Whether the user chose a sound for any event. With the default settings
/// it is `false` and the live paths do no work for a sound.
pub fn any_chosen() -> bool {
    PREFS
        .read()
        .is_ok_and(|prefs| prefs.direct.is_some() || prefs.mention.is_some())
}

fn chosen_for(kind: EventKind) -> (Option<SoundId>, u8) {
    let prefs = PREFS.read().map(|prefs| *prefs).ok();
    match (kind, prefs) {
        (_, None) => (None, 0),
        (EventKind::Mention, Some(prefs)) => (prefs.mention, prefs.volume),
        (EventKind::DirectMessage, Some(prefs)) => (prefs.direct, prefs.volume),
    }
}

static LAST_PLAYED: Mutex<Option<Instant>> = Mutex::new(None);

/// One live event that may need a sound. The caller names the facts about
/// the window; the gate does the rest.
pub struct LiveEvent {
    pub kind: EventKind,
    pub window_selected: bool,
    pub app_focused: bool,
    pub own: bool,
    pub muted: bool,
    pub ignored: bool,
}

/// Plays the sound for a live event when the gate lets it through.
pub fn on_live_event(event: &LiveEvent) {
    let (chosen, volume) = chosen_for(event.kind);
    if chosen.is_none() {
        return;
    }
    let now = Instant::now();
    let Ok(mut last) = LAST_PLAYED.lock() else {
        return;
    };
    let since_last_ms = last.map(|at| now.saturating_duration_since(at).as_millis() as u64);
    let input = GateInput {
        live: true,
        window_selected: event.window_selected,
        app_focused: event.app_focused,
        own: event.own,
        muted: event.muted,
        ignored: event.ignored,
        chosen,
        since_last_ms,
    };
    if should_play(&input) {
        *last = Some(now);
        if let Some(sound) = chosen {
            play(sound, volume);
        }
    }
}

/// Plays the sound that the user chose for `kind`, for the preview button.
/// No gate applies; "none" plays nothing.
pub fn preview(kind: EventKind) {
    let (chosen, volume) = chosen_for(kind);
    if let Some(sound) = chosen {
        play(sound, volume);
    }
}

enum Command {
    Play {
        sound: SoundId,
        volume: u8,
    },
    /// The selected output changed: open it again at the next sound.
    Reopen,
}

fn play(sound: SoundId, volume: u8) {
    let _ = player().send(Command::Play { sound, volume });
}

/// Tells the player that the selected output changed.
pub fn reopen_output() {
    if let Some(commands) = PLAYER.get() {
        let _ = commands.send(Command::Reopen);
    }
}

static PLAYER: OnceLock<mpsc::Sender<Command>> = OnceLock::new();

/// The thread that owns the output stream; it starts at the first sound.
fn player() -> &'static mpsc::Sender<Command> {
    PLAYER.get_or_init(|| {
        let (commands, rx) = mpsc::channel();
        thread::spawn(move || audio_thread(rx));
        commands
    })
}

fn audio_thread(commands: mpsc::Receiver<Command>) {
    let mut device: Option<rodio::MixerDeviceSink> = None;
    let mut current: Option<rodio::Player> = None;
    for command in commands {
        match command {
            Command::Reopen => {
                current = None;
                device = None;
            }
            Command::Play { sound, volume } => {
                if device.is_none() {
                    match crate::audio_output::open_selected_sink() {
                        Ok(sink) => {
                            crate::audio_output::log_opened(&sink);
                            device = Some(sink);
                        }
                        Err(err) => {
                            // The unread badge still shows the event.
                            cordiale_core::persistence::log_line(&format!(
                                "notification sound: no audio output: {err}"
                            ));
                            continue;
                        }
                    }
                }
                let Some(sink) = device.as_ref() else {
                    continue;
                };
                let source =
                    match crate::media_player::clip_source(sound.bytes(), sound.extension()) {
                        Ok(source) => source,
                        Err(err) => {
                            cordiale_core::persistence::log_line(&format!(
                                "notification sound: cannot decode a bundled sound: {err}"
                            ));
                            continue;
                        }
                    };
                let player = rodio::Player::connect_new(sink.mixer());
                player.set_volume(f32::from(volume.min(100)) / 100.0 * sound.gain());
                player.append(source);
                current = Some(player);
            }
        }
    }
    drop(current);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rodio::Sample;

    fn live_event() -> GateInput {
        GateInput {
            live: true,
            window_selected: false,
            app_focused: true,
            own: false,
            muted: false,
            ignored: false,
            chosen: Some(SoundId::Bell),
            since_last_ms: None,
        }
    }

    #[test]
    fn a_live_event_out_of_view_plays() {
        assert!(should_play(&live_event()));
    }

    #[test]
    fn the_default_choice_is_silence() {
        assert!(!should_play(&GateInput {
            chosen: None,
            ..live_event()
        }));
        let prefs = SoundPrefs {
            direct: choice_from_setting("none"),
            mention: choice_from_setting("none"),
            volume: 60,
        };
        assert_eq!((prefs.direct, prefs.mention), (None, None));
    }

    #[test]
    fn history_catch_up_and_first_load_never_play() {
        assert!(!should_play(&GateInput {
            live: false,
            ..live_event()
        }));
    }

    #[test]
    fn the_selected_window_plays_only_without_focus() {
        let selected = GateInput {
            window_selected: true,
            ..live_event()
        };
        assert!(!should_play(&selected));
        assert!(should_play(&GateInput {
            app_focused: false,
            ..selected
        }));
    }

    #[test]
    fn own_ignored_and_muted_messages_stay_silent() {
        for input in [
            GateInput {
                own: true,
                ..live_event()
            },
            GateInput {
                ignored: true,
                ..live_event()
            },
            GateInput {
                muted: true,
                ..live_event()
            },
        ] {
            assert!(!should_play(&input));
        }
    }

    #[test]
    fn a_burst_plays_one_sound() {
        let at = |gap| GateInput {
            since_last_ms: Some(gap),
            ..live_event()
        };
        assert!(!should_play(&at(0)));
        assert!(!should_play(&at(MIN_GAP_MS - 1)));
        assert!(should_play(&at(MIN_GAP_MS)));
    }

    #[test]
    fn an_unknown_stored_value_falls_back_to_none() {
        assert_eq!(choice_from_setting("kalimba"), Some(SoundId::Kalimba));
        assert_eq!(choice_from_setting("none"), None);
        assert_eq!(choice_from_setting("glass"), None);
        assert_eq!(choice_from_setting(""), None);
        assert_eq!(choice_from_setting("KALIMBA"), None);
        assert_eq!(choice_index("glass"), 0);
    }

    #[test]
    fn a_choice_list_entry_maps_to_its_stored_value() {
        assert_eq!(choice_key(0), "none");
        assert_eq!(choice_key(-1), "none");
        assert_eq!(choice_key(6), "none");
        for (position, sound) in SoundId::ALL.iter().enumerate() {
            let index = position as i32 + 1;
            assert_eq!(choice_key(index), sound.key());
            assert_eq!(choice_index(sound.key()), index);
            assert_eq!(SoundId::from_key(sound.key()), Some(*sound));
        }
    }

    #[test]
    fn a_setting_maps_to_its_own_file() {
        let formats: Vec<(&str, &str)> = SoundId::ALL
            .iter()
            .map(|sound| (sound.key(), sound.extension()))
            .collect();
        assert_eq!(
            formats,
            [
                ("kalimba", "wav"),
                ("bell", "ogg"),
                ("alert", "ogg"),
                ("dum", "ogg"),
                ("deep", "ogg"),
            ]
        );
        let mut files: Vec<&[u8]> = SoundId::ALL.iter().map(|sound| sound.bytes()).collect();
        files.sort_unstable();
        files.dedup();
        assert_eq!(files.len(), 5);
    }

    #[test]
    fn the_bundled_files_stay_small() {
        let total: usize = SoundId::ALL.iter().map(|sound| sound.bytes().len()).sum();
        assert!(total < 250_000, "the sounds take {total} bytes");
    }

    #[test]
    fn no_gain_is_above_one() {
        for sound in SoundId::ALL {
            assert!(sound.gain() > 0.0 && sound.gain() <= 1.0);
        }
    }

    #[test]
    fn every_bundled_file_decodes_to_audible_samples() {
        for sound in SoundId::ALL {
            let samples: Vec<Sample> =
                crate::media_player::clip_source(sound.bytes(), sound.extension())
                    .unwrap_or_else(|err| panic!("{} does not decode: {err}", sound.key()))
                    .collect();
            assert!(!samples.is_empty(), "{} has no samples", sound.key());
            let peak = samples.iter().fold(0.0_f32, |peak, s| peak.max(s.abs()));
            assert!(peak > 0.05, "{} is too quiet: peak {peak}", sound.key());
            assert!(
                peak * sound.gain() <= 1.0,
                "{} clips: peak {peak}",
                sound.key()
            );
        }
    }
}
