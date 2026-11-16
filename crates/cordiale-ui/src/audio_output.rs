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
        Some(device) => {
            rodio::DeviceSinkBuilder::from_device(device).and_then(|builder| builder.open_stream())
        }
        None => rodio::DeviceSinkBuilder::open_default_sink(),
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
    fn radio_and_media_read_the_same_selection() {
        let selection = OutputSelection::new();
        assert_eq!(selection.get(), None);
        selection.set(Some("a:2".to_string()));
        assert_eq!(selection.get().as_deref(), Some("a:2"));
        // Both players call `shared()`, which is one value.
        assert!(std::ptr::eq(shared(), shared()));
    }
}
