//! The audio output device that radio, audio files and video sound share.
//!
//! The choice is kept on this device only (`Settings.audio_output`): the id
//! of a device, or nothing for the host default. Both players open their
//! sink through [`open_selected_sink`], so they always use the same device.
//! The device list comes from a [`DeviceProvider`], so tests need no audio
//! hardware.

use std::sync::Mutex;

use rodio::cpal::traits::HostTrait;
use rodio::DeviceTrait;

/// An output device that the host reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputDevice {
    /// Stable id of the device, kept in the settings.
    pub id: String,
    /// Name to show to the user. Two devices can have the same name.
    pub name: String,
}

/// Where the list of output devices comes from.
pub trait DeviceProvider {
    /// The output devices only, never the inputs.
    fn outputs(&self) -> Result<Vec<OutputDevice>, String>;
    /// The id of the host default output, when there is one.
    fn default_id(&self) -> Option<String>;
}

/// The output devices of the audio backend of this host.
pub struct HostDevices;

impl DeviceProvider for HostDevices {
    fn outputs(&self) -> Result<Vec<OutputDevice>, String> {
        let host = rodio::cpal::default_host();
        let devices = host.output_devices().map_err(|err| err.to_string())?;
        Ok(devices
            .filter_map(|device| {
                let id = device.id().ok()?.to_string();
                let name = device
                    .description()
                    .map(|description| description.name().to_string())
                    .unwrap_or_else(|_| id.clone());
                Some(OutputDevice { id, name })
            })
            .collect())
    }

    fn default_id(&self) -> Option<String> {
        let device = rodio::cpal::default_host().default_output_device()?;
        Some(device.id().ok()?.to_string())
    }
}

/// What the settings screen tells about the saved choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStatus {
    /// Nothing to tell.
    Ok,
    /// The saved device is not there: the host default is in use.
    Missing,
    /// The device list can't be read: the host default is in use.
    ListFailed,
}

impl OutputStatus {
    /// The key that the settings screen turns into a text.
    pub fn key(self) -> &'static str {
        match self {
            OutputStatus::Ok => "",
            OutputStatus::Missing => "missing",
            OutputStatus::ListFailed => "list-failed",
        }
    }
}

/// Status key of the settings screen: the new output opened for nothing, so
/// the active sound stays on the old output.
pub const NOT_MOVED_KEY: &str = "not-moved";

/// The saved choice checked against the devices of the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The device to use: `None` is the host default.
    pub target: Option<String>,
    pub status: OutputStatus,
}

/// Checks a saved choice. A device that is gone, or a list that can't be
/// read, gives the host default and a status, never another device.
pub fn resolve(saved: Option<&str>, provider: &dyn DeviceProvider) -> Resolved {
    let Some(saved) = saved else {
        return Resolved {
            target: None,
            status: OutputStatus::Ok,
        };
    };
    match provider.outputs() {
        Ok(devices) if devices.iter().any(|device| device.id == saved) => Resolved {
            target: Some(saved.to_string()),
            status: OutputStatus::Ok,
        },
        Ok(_) => Resolved {
            target: None,
            status: OutputStatus::Missing,
        },
        Err(_) => Resolved {
            target: None,
            status: OutputStatus::ListFailed,
        },
    }
}

/// The entries of the drop-down list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choices {
    /// The device of each entry: entry 0 is the host default (`None`).
    pub ids: Vec<Option<String>>,
    /// The text of each entry.
    pub names: Vec<String>,
    /// The entry that shows the saved choice.
    pub selected: usize,
    pub status: OutputStatus,
}

/// Builds the drop-down list. `default_label` names the host default entry.
pub fn choices(saved: Option<&str>, default_label: &str, provider: &dyn DeviceProvider) -> Choices {
    let resolved = resolve(saved, provider);
    let devices = provider.outputs().unwrap_or_default();
    let default_name = provider.default_id().and_then(|id| {
        devices
            .iter()
            .find(|device| device.id == id)
            .map(|device| device.name.clone())
    });
    let mut ids = vec![None];
    let mut names = vec![match default_name {
        Some(name) => format!("{default_label} ({name})"),
        None => default_label.to_string(),
    }];
    for (index, device) in devices.iter().enumerate() {
        let same = devices[..index]
            .iter()
            .filter(|other| other.name == device.name)
            .count();
        names.push(if same == 0 {
            device.name.clone()
        } else {
            format!("{} #{}", device.name, same + 1)
        });
        ids.push(Some(device.id.clone()));
    }
    let selected = ids
        .iter()
        .position(|id| *id == resolved.target)
        .unwrap_or(0);
    Choices {
        ids,
        names,
        selected,
        status: resolved.status,
    }
}

/// The device that both players use now.
pub struct OutputSelection(Mutex<Option<String>>);

impl OutputSelection {
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// The device in use: `None` is the host default.
    pub fn get(&self) -> Option<String> {
        self.0.lock().map(|id| id.clone()).unwrap_or(None)
    }

    pub fn set(&self, id: Option<String>) {
        if let Ok(mut current) = self.0.lock() {
            *current = id;
        }
    }
}

static SELECTION: OutputSelection = OutputSelection::new();

/// The selection that radio and media share.
pub fn shared() -> &'static OutputSelection {
    &SELECTION
}

/// Which stream errors reach the log. A dead stream can report the same
/// error many times: a new message is written at once, and a repeat only
/// when its count is a power of two.
pub struct ErrorThrottle {
    last: Option<String>,
    count: u64,
}

impl ErrorThrottle {
    pub const fn new() -> Self {
        Self {
            last: None,
            count: 0,
        }
    }

    /// The log line for one more error with this `message`, if it is due.
    pub fn line(&mut self, message: &str) -> Option<String> {
        if self.last.as_deref() == Some(message) {
            self.count += 1;
            return self
                .count
                .is_power_of_two()
                .then(|| format!("audio stream error: {message} (x{})", self.count));
        }
        self.last = Some(message.to_string());
        self.count = 1;
        Some(format!("audio stream error: {message}"))
    }
}

impl Default for ErrorThrottle {
    fn default() -> Self {
        Self::new()
    }
}

static STREAM_ERRORS: Mutex<ErrorThrottle> = Mutex::new(ErrorThrottle::new());

/// The error callback of the streams: rodio prints to stderr by default,
/// which the Windows build does not have, so the errors go to the log.
fn stream_error_callback() -> impl FnMut(rodio::CpalError) + Send + 'static {
    |err: rodio::CpalError| {
        let line = STREAM_ERRORS
            .lock()
            .ok()
            .and_then(|mut throttle| throttle.line(&err.to_string()));
        if let Some(line) = line {
            cordiale_core::persistence::log_line(&line);
        }
    }
}

/// The part of the log line that describes the open stream.
pub fn format_stream_config(
    channels: u16,
    rate: u32,
    format: &str,
    buffer_frames: Option<u32>,
) -> String {
    let buffer = match buffer_frames {
        Some(frames) => frames.to_string(),
        None => "default".to_string(),
    };
    format!("stream: {channels} ch, {rate} Hz, {format}, buffer {buffer}")
}

/// The log line for an output that a player opened.
pub fn opened_line(device: Option<&str>, stream: &str) -> String {
    format!(
        "audio output opened: {}; {stream}",
        device.unwrap_or("default device (name not available)")
    )
}

/// Writes the log line for an output that a player opened. The name is the
/// default device of the host: rodio does not tell which device it opened.
pub fn log_opened(sink: &rodio::MixerDeviceSink) {
    let config = sink.config();
    let buffer = match config.buffer_size() {
        rodio::cpal::BufferSize::Fixed(frames) => Some(*frames),
        rodio::cpal::BufferSize::Default => None,
    };
    let stream = format_stream_config(
        config.channel_count().get(),
        config.sample_rate().get(),
        &config.sample_format().to_string(),
        buffer,
    );
    cordiale_core::persistence::log_line(&opened_line(
        crate::debug_info::default_audio_output().as_deref(),
        &stream,
    ));
}

/// Opens the host default output. When it fails, rodio tries the other
/// outputs without a word: the log says so.
fn open_default_sink() -> Result<rodio::MixerDeviceSink, rodio::DeviceSinkError> {
    let first = rodio::DeviceSinkBuilder::from_default_device().and_then(|builder| {
        builder
            .with_error_callback(stream_error_callback())
            .open_stream()
    });
    match first {
        Ok(sink) => Ok(sink),
        Err(err) => {
            cordiale_core::persistence::log_line(&format!(
                "default audio output failed: {err}; trying the other outputs"
            ));
            let sink = rodio::DeviceSinkBuilder::open_default_sink()?;
            cordiale_core::persistence::log_line(
                "audio output: the default device failed, another device is open",
            );
            Ok(sink)
        }
    }
}

/// Opens the selected output for a player. A saved device that is gone
/// falls back to the host default; a device that fails to open is an error.
pub fn open_selected_sink() -> Result<rodio::MixerDeviceSink, String> {
    let device = shared().get().and_then(|id| {
        let parsed = id.parse::<rodio::cpal::DeviceId>().ok()?;
        let found = rodio::cpal::default_host().device_by_id(&parsed);
        if found.is_none() {
            cordiale_core::persistence::log_line(
                "the saved audio output is not available: using the default",
            );
        }
        found
    });
    let opened = match device {
        Some(device) => rodio::DeviceSinkBuilder::from_device(device).and_then(|builder| {
            builder
                .with_error_callback(stream_error_callback())
                .open_stream()
        }),
        None => open_default_sink(),
    };
    opened
        .map(|mut sink| {
            sink.log_on_drop(false);
            sink
        })
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        outputs: Result<Vec<OutputDevice>, String>,
        default: Option<String>,
    }

    impl DeviceProvider for Fake {
        fn outputs(&self) -> Result<Vec<OutputDevice>, String> {
            self.outputs.clone()
        }
        fn default_id(&self) -> Option<String> {
            self.default.clone()
        }
    }

    fn device(id: &str, name: &str) -> OutputDevice {
        OutputDevice {
            id: id.to_string(),
            name: name.to_string(),
        }
    }

    fn two_devices() -> Fake {
        Fake {
            outputs: Ok(vec![device("a:1", "Speakers"), device("a:2", "Headphones")]),
            default: Some("a:1".to_string()),
        }
    }

    #[test]
    fn no_saved_choice_selects_the_host_default() {
        let list = choices(None, "Host default", &two_devices());
        assert_eq!(list.selected, 0);
        assert_eq!(list.names[0], "Host default (Speakers)");
        assert_eq!(list.ids[0], None);
        assert_eq!(list.status, OutputStatus::Ok);
        assert_eq!(resolve(None, &two_devices()).target, None);
    }

    #[test]
    fn a_saved_device_is_selected() {
        let list = choices(Some("a:2"), "Host default", &two_devices());
        assert_eq!(list.selected, 2);
        assert_eq!(list.ids[2].as_deref(), Some("a:2"));
        assert_eq!(list.status, OutputStatus::Ok);
        let resolved = resolve(Some("a:2"), &two_devices());
        assert_eq!(resolved.target.as_deref(), Some("a:2"));
    }

    #[test]
    fn a_missing_saved_device_falls_back_to_the_default() {
        let resolved = resolve(Some("a:9"), &two_devices());
        assert_eq!(resolved.target, None);
        assert_eq!(resolved.status, OutputStatus::Missing);
        let list = choices(Some("a:9"), "Host default", &two_devices());
        assert_eq!(list.selected, 0);
        assert_eq!(list.status, OutputStatus::Missing);
    }

    #[test]
    fn a_list_error_keeps_the_host_default() {
        let fake = Fake {
            outputs: Err("no host".to_string()),
            default: None,
        };
        let resolved = resolve(Some("a:1"), &fake);
        assert_eq!(resolved.target, None);
        assert_eq!(resolved.status, OutputStatus::ListFailed);
        let list = choices(Some("a:1"), "Host default", &fake);
        assert_eq!(list.names, vec!["Host default".to_string()]);
        assert_eq!(list.selected, 0);
        assert_eq!(list.status, OutputStatus::ListFailed);
    }

    #[test]
    fn devices_with_the_same_name_stay_distinct() {
        let fake = Fake {
            outputs: Ok(vec![device("a:1", "Monitor"), device("a:2", "Monitor")]),
            default: None,
        };
        let list = choices(Some("a:2"), "Host default", &fake);
        assert_eq!(list.names[1], "Monitor");
        assert_eq!(list.names[2], "Monitor #2");
        assert_eq!(list.selected, 2);
    }

    #[test]
    fn the_status_keys_are_distinct() {
        let keys = [
            OutputStatus::Ok.key(),
            OutputStatus::Missing.key(),
            OutputStatus::ListFailed.key(),
            NOT_MOVED_KEY,
            "applied",
        ];
        for (index, key) in keys.iter().enumerate() {
            assert!(!keys[..index].contains(key), "duplicate key {key}");
        }
    }

    #[test]
    fn the_stream_line_names_every_setting() {
        assert_eq!(
            format_stream_config(2, 48_000, "f32", Some(2_048)),
            "stream: 2 ch, 48000 Hz, f32, buffer 2048"
        );
        assert_eq!(
            format_stream_config(6, 44_100, "i16", None),
            "stream: 6 ch, 44100 Hz, i16, buffer default"
        );
    }

    #[test]
    fn the_output_line_names_the_device_and_the_stream() {
        assert_eq!(
            opened_line(Some("Speakers (host: WASAPI)"), "stream: 2 ch, 48000 Hz, f32, buffer 2048"),
            "audio output opened: Speakers (host: WASAPI); stream: 2 ch, 48000 Hz, f32, buffer 2048"
        );
        assert!(opened_line(None, "stream: x").contains("name not available"));
    }

    #[test]
    fn a_repeated_stream_error_is_written_a_few_times() {
        let mut throttle = ErrorThrottle::new();
        let lines: Vec<Option<String>> = (0..9).map(|_| throttle.line("device lost")).collect();
        let written: Vec<&String> = lines.iter().flatten().collect();
        assert_eq!(written.len(), 4, "{written:?}");
        assert_eq!(lines[0].as_deref(), Some("audio stream error: device lost"));
        assert_eq!(
            lines[1].as_deref(),
            Some("audio stream error: device lost (x2)")
        );
        assert_eq!(lines[2], None);
        assert_eq!(
            lines[3].as_deref(),
            Some("audio stream error: device lost (x4)")
        );
        assert_eq!(
            lines[7].as_deref(),
            Some("audio stream error: device lost (x8)")
        );
    }

    #[test]
    fn a_new_stream_error_is_written_at_once() {
        let mut throttle = ErrorThrottle::new();
        assert!(throttle.line("first").is_some());
        assert!(throttle.line("first").is_some());
        assert_eq!(
            throttle.line("second").as_deref(),
            Some("audio stream error: second")
        );
        // The count starts again with the new message.
        assert_eq!(
            throttle.line("second").as_deref(),
            Some("audio stream error: second (x2)")
        );
        assert_eq!(
            throttle.line("first").as_deref(),
            Some("audio stream error: first")
        );
    }

    #[test]
    fn radio_and_media_read_the_same_selection() {
        let selection = OutputSelection::new();
        assert_eq!(selection.get(), None);
        selection.set(Some("a:2".to_string()));
        assert_eq!(selection.get().as_deref(), Some("a:2"));
        // Both players call `shared()`, which is one value.
        assert!(std::ptr::eq(shared(), shared()));
    }
}
