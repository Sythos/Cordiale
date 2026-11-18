//! Why the sound of an audio or video file could not be opened.
//!
//! The error says where the open stopped and what the track holds, so the
//! log can tell the causes apart and the window can name a reason.

/// The name of the AAC codec, as the error gives it.
pub const CODEC_AAC: &str = "AAC";

/// Where the open of an audio track stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenStage {
    /// The container could not be read.
    Probe,
    /// The container has no audio track that the player knows.
    NoTrack,
    /// No decoder could be made for the track.
    Decoder,
    /// The first packet of the track did not decode.
    FirstPacket,
}

/// What is known about an audio track.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrackInfo {
    pub codec: Option<String>,
    pub channels: Option<u16>,
    pub sample_rate: Option<u32>,
    /// For AAC, the profile in the audio specific configuration.
    pub profile: Option<String>,
}

impl TrackInfo {
    /// `config` is the codec set-up data of the track: for AAC, its audio
    /// specific configuration.
    pub fn new(
        codec: String,
        channels: Option<u16>,
        sample_rate: Option<u32>,
        config: Option<&[u8]>,
    ) -> Self {
        let profile = if codec == CODEC_AAC {
            config.and_then(aac_profile)
        } else {
            None
        };
        Self {
            codec: Some(codec),
            channels,
            sample_rate,
            profile,
        }
    }
}

/// The key of the note that says that no audio output is open.
pub const NOTE_NO_OUTPUT: &str = "no_output";

/// What the viewer says about a sound that cannot play. `key` names the
/// translated sentence; `detail` fills it: a codec, a profile or a channel
/// count. It never holds a file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioNote {
    pub key: &'static str,
    pub detail: String,
}

impl AudioNote {
    /// The file has a sound, but no audio output is open.
    pub fn no_output() -> Self {
        Self {
            key: NOTE_NO_OUTPUT,
            detail: String::new(),
        }
    }
}

/// An audio track that could not be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioOpenError {
    pub stage: OpenStage,
    pub track: TrackInfo,
    /// The library said that it does not support the codec or the profile.
    pub unsupported: bool,
    /// The message of the library.
    pub message: String,
    /// Why the second decoder failed as well, if it was tried.
    pub fallback: Option<String>,
}

impl AudioOpenError {
    pub fn probe(message: String) -> Self {
        Self {
            stage: OpenStage::Probe,
            track: TrackInfo::default(),
            unsupported: false,
            message,
            fallback: None,
        }
    }

    pub fn no_track() -> Self {
        Self {
            stage: OpenStage::NoTrack,
            track: TrackInfo::default(),
            unsupported: false,
            message: String::new(),
            fallback: None,
        }
    }

    /// No decoder could be made for `track`.
    pub fn decoder(track: TrackInfo, unsupported: bool, message: String) -> Self {
        Self {
            stage: OpenStage::Decoder,
            track,
            unsupported,
            message,
            fallback: None,
        }
    }

    pub fn first_packet(track: TrackInfo) -> Self {
        Self {
            stage: OpenStage::FirstPacket,
            track,
            unsupported: false,
            message: "no packet could be decoded".to_string(),
            fallback: None,
        }
    }

    /// What the viewer says about this error. A file without a sound track
    /// is normal: it gets no note.
    pub fn note(&self) -> Option<AudioNote> {
        let key = self.reason_key();
        let detail = match key {
            "no_track" => return None,
            "unsupported_codec" => self.track.codec.clone().unwrap_or_default(),
            "too_many_channels" => self
                .track
                .channels
                .map(|channels| channels.to_string())
                .unwrap_or_default(),
            "unsupported_profile" => self
                .track
                .profile
                .clone()
                .or_else(|| self.track.codec.clone())
                .unwrap_or_default(),
            _ => String::new(),
        };
        Some(AudioNote { key, detail })
    }

    /// Adds the reason why the second decoder failed too.
    pub fn with_fallback(mut self, other: &AudioOpenError) -> Self {
        self.fallback = Some(other.detail());
        self
    }

    fn detail(&self) -> String {
        match self.stage {
            OpenStage::NoTrack => "no audio track".to_string(),
            OpenStage::Probe => format!("the file could not be read: {}", self.message),
            OpenStage::Decoder => format!("no decoder: {}", self.message),
            OpenStage::FirstPacket => format!("the first packet failed: {}", self.message),
        }
    }

    /// A short sentence for the log.
    pub fn describe(&self) -> String {
        if self.stage == OpenStage::NoTrack {
            return self.detail();
        }
        let mut track = Vec::new();
        if let Some(codec) = &self.track.codec {
            track.push(codec.clone());
        }
        if let Some(profile) = &self.track.profile {
            track.push(profile.clone());
        }
        if let Some(channels) = self.track.channels {
            track.push(format!("{channels} channels"));
        }
        if let Some(rate) = self.track.sample_rate {
            track.push(format!("{rate} Hz"));
        }
        let track = if track.is_empty() {
            "unknown track".to_string()
        } else {
            track.join(", ")
        };
        let mut text = format!(
            "unsupported audio [{}]: {track}; {}",
            self.reason_key(),
            self.detail()
        );
        if let Some(fallback) = &self.fallback {
            text.push_str("; fallback: ");
            text.push_str(fallback);
        }
        text
    }

    /// A stable name of the cause, for the message in the window.
    pub fn reason_key(&self) -> &'static str {
        match self.stage {
            OpenStage::NoTrack => "no_track",
            OpenStage::Probe => "probe_failed",
            OpenStage::FirstPacket => "decode_failed",
            OpenStage::Decoder if !self.unsupported => "decode_failed",
            OpenStage::Decoder if self.track.codec.as_deref() != Some(CODEC_AAC) => {
                "unsupported_codec"
            }
            OpenStage::Decoder if self.track.channels.is_some_and(|count| count > 2) => {
                "too_many_channels"
            }
            OpenStage::Decoder => "unsupported_profile",
        }
    }
}

/// The AAC profile named in an audio specific configuration, for the log.
/// An HE-AAC stream that does not say so in the configuration shows as its
/// core profile.
pub fn aac_profile(config: &[u8]) -> Option<String> {
    let mut at = 0;
    let mut object = read_bits(config, &mut at, 5)?;
    if object == 31 {
        object = 32 + read_bits(config, &mut at, 6)?;
    }
    let name = match object {
        1 => "AAC Main".to_string(),
        2 => "AAC-LC".to_string(),
        3 => "AAC-SSR".to_string(),
        4 => "AAC-LTP".to_string(),
        5 => "HE-AAC (SBR)".to_string(),
        23 => "AAC-LD".to_string(),
        29 => "HE-AAC v2 (PS)".to_string(),
        39 => "AAC-ELD".to_string(),
        42 => "xHE-AAC".to_string(),
        other => format!("AAC object type {other}"),
    };
    Some(name)
}

/// Reads `count` bits, most significant first, from `at` on.
fn read_bits(data: &[u8], at: &mut usize, count: usize) -> Option<u32> {
    let mut value = 0u32;
    for _ in 0..count {
        let byte = *data.get(*at / 8)?;
        let bit = (byte >> (7 - *at % 8)) & 1;
        value = (value << 1) | u32::from(bit);
        *at += 1;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aac(channels: u16) -> TrackInfo {
        TrackInfo::new(CODEC_AAC.to_string(), Some(channels), Some(44_100), None)
    }

    #[test]
    fn the_error_stays_small_enough_for_a_result() {
        // Clippy warns about an error of 128 bytes or more in a `Result`.
        assert!(std::mem::size_of::<AudioOpenError>() < 128);
    }

    #[test]
    fn a_missing_track_and_a_bad_container_have_their_own_keys() {
        assert_eq!(AudioOpenError::no_track().reason_key(), "no_track");
        assert_eq!(AudioOpenError::no_track().describe(), "no audio track");
        let probe = AudioOpenError::probe("bad box".to_string());
        assert_eq!(probe.reason_key(), "probe_failed");
        assert!(probe.describe().contains("bad box"));
    }

    #[test]
    fn an_aac_track_with_too_many_channels_has_its_own_key() {
        let error = AudioOpenError::decoder(aac(6), true, "aac too complex".to_string());
        assert_eq!(error.reason_key(), "too_many_channels");
        let text = error.describe();
        assert!(text.contains("AAC"), "{text}");
        assert!(text.contains("6 channels"), "{text}");
        assert!(text.contains("44100 Hz"), "{text}");
    }

    #[test]
    fn an_aac_profile_that_the_decoder_refuses_has_its_own_key() {
        let error = AudioOpenError::decoder(aac(2), true, "aac too complex".to_string());
        assert_eq!(error.reason_key(), "unsupported_profile");
    }

    #[test]
    fn a_codec_without_a_decoder_has_its_own_key() {
        let track = TrackInfo::new("AC-3".to_string(), Some(2), Some(48_000), None);
        let error = AudioOpenError::decoder(track, true, "unsupported audio codec".to_string());
        assert_eq!(error.reason_key(), "unsupported_codec");
        assert!(error.describe().contains("AC-3"));
    }

    #[test]
    fn a_decoder_that_fails_without_saying_unsupported_is_a_decode_failure() {
        let error = AudioOpenError::decoder(aac(2), false, "malformed stream".to_string());
        assert_eq!(error.reason_key(), "decode_failed");
        assert_eq!(
            AudioOpenError::first_packet(aac(2)).reason_key(),
            "decode_failed"
        );
    }

    #[test]
    fn the_reason_of_the_second_decoder_goes_into_the_log_text() {
        let primary = AudioOpenError::decoder(aac(2), true, "aac too complex".to_string());
        let second = AudioOpenError::probe("no suitable format".to_string());
        let error = primary.with_fallback(&second);
        assert_eq!(error.reason_key(), "unsupported_profile");
        assert!(error.describe().contains("fallback"));
        assert!(error.describe().contains("no suitable format"));
    }

    fn note_of(error: &AudioOpenError) -> (&'static str, String) {
        let note = error.note().expect("a note");
        (note.key, note.detail)
    }

    #[test]
    fn a_codec_without_a_decoder_names_the_codec_in_its_note() {
        let track = TrackInfo::new("AC-3".to_string(), Some(2), Some(48_000), None);
        let error = AudioOpenError::decoder(track, true, "unsupported".to_string());
        assert_eq!(note_of(&error), ("unsupported_codec", "AC-3".to_string()));
    }

    #[test]
    fn too_many_channels_name_the_count_in_their_note() {
        let error = AudioOpenError::decoder(aac(6), true, "too complex".to_string());
        assert_eq!(note_of(&error), ("too_many_channels", "6".to_string()));
    }

    #[test]
    fn an_aac_profile_names_itself_in_its_note() {
        let track = TrackInfo::new(
            CODEC_AAC.to_string(),
            Some(2),
            Some(24_000),
            Some(&[0x2B, 0x11, 0x88, 0x00]),
        );
        let error = AudioOpenError::decoder(track, true, "too complex".to_string());
        assert_eq!(
            note_of(&error),
            ("unsupported_profile", "HE-AAC (SBR)".to_string())
        );
        // Without a profile the codec name stands in.
        let error = AudioOpenError::decoder(aac(2), true, "too complex".to_string());
        assert_eq!(note_of(&error), ("unsupported_profile", "AAC".to_string()));
    }

    #[test]
    fn a_file_that_cannot_be_read_or_decoded_has_a_note_without_detail() {
        let probe = AudioOpenError::probe("bad file".to_string());
        assert_eq!(note_of(&probe), ("probe_failed", String::new()));
        let first = AudioOpenError::first_packet(aac(2));
        assert_eq!(note_of(&first), ("decode_failed", String::new()));
    }

    #[test]
    fn a_file_without_a_sound_track_has_no_note() {
        assert_eq!(AudioOpenError::no_track().note(), None);
    }

    #[test]
    fn the_note_for_a_missing_output_has_its_own_key() {
        let note = AudioNote::no_output();
        assert_eq!(note.key, "no_output");
        assert!(note.detail.is_empty());
    }

    #[test]
    fn the_note_never_holds_a_message_of_the_library() {
        let error = AudioOpenError::probe("/some/path/file.mp4: bad".to_string());
        let note = error.note().expect("a note");
        assert!(!note.detail.contains("file"));
    }

    #[test]
    fn the_profile_comes_from_the_audio_specific_configuration() {
        assert_eq!(aac_profile(&[0x12, 0x10]).as_deref(), Some("AAC-LC"));
        assert_eq!(
            aac_profile(&[0x2B, 0x11, 0x88, 0x00]).as_deref(),
            Some("HE-AAC (SBR)")
        );
        assert_eq!(aac_profile(&[]), None);
        let track = TrackInfo::new(
            CODEC_AAC.to_string(),
            Some(2),
            Some(24_000),
            Some(&[0x2B, 0x11, 0x88, 0x00]),
        );
        assert_eq!(track.profile.as_deref(), Some("HE-AAC (SBR)"));
    }
}
