//! The in-app player for audio and video files held in memory.
//!
//! Everything is decoded in Rust, so the formats do not depend on the codecs
//! of the platform: symphonia reads the containers and decodes MP3, Vorbis,
//! FLAC, WAV and AAC; `opus-decoder` decodes Opus (also the Ogg/Opus files
//! of older iOS devices); `rusty_h264-decoder` decodes H.264 and `rusty_h265`
//! decodes HEVC/H.265 in MP4, MOV and M4V; `vp8-decoder`, `rusty_vp9` and
//! `rusty_av1d` decode VP8, VP9 and AV1 in WebM. Vorbis in WebM goes through
//! symphonia.
//!
//! One controller thread owns the output device and the open file. Audio
//! plays through rodio and is the clock of the video. A file with no audio
//! uses the wall clock. The controller sends its news to the window with the
//! callback given to [`MediaPlayer::spawn`].

use std::collections::VecDeque;
use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use opus_decoder::OpusDecoder;
use rodio::{ChannelCount, Sample, SampleRate, Source};
use symphonia::core::codecs::audio::well_known::{self, CODEC_ID_OPUS, CODEC_ID_VORBIS};
use symphonia::core::codecs::audio::{
    AudioCodecId, AudioCodecParameters, AudioDecoder as SymphoniaDecoder, AudioDecoderOptions,
    CODEC_ID_NULL_AUDIO,
};
use symphonia::core::codecs::CodecParameters;
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::probe::Hint;
use symphonia::core::formats::{FormatOptions, FormatReader, SeekMode, SeekTo};
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::packet::PacketRef;
use symphonia::core::units::{Duration as MediaDuration, Time, Timestamp};

use crate::media_audio_error::{AudioNote, AudioOpenError, OpenStage, TrackInfo, CODEC_AAC};
use crate::media_audio_v05::{self, Decoder05, Packets05};
use crate::media_demux::{self, Sample as VideoSample, VideoCodec, VideoTrack};
use crate::media_hw::{self, HardwareDecode};
use crate::AppWindow;

/// Largest picture the player decodes, in pixels (4K).
const MAX_PIXELS: usize = 3840 * 2160;
/// Fewest decoded pictures kept ahead of the clock, whatever their size.
const QUEUE_MIN_FRAMES: usize = 4;
/// Most decoded pictures kept ahead of the clock, for small pictures.
const QUEUE_MAX_FRAMES: usize = 12;
/// Memory that the queue of decoded pictures may hold, in bytes.
const QUEUE_BYTES: usize = 96 * 1024 * 1024;
/// Time that one pass of the controller loop gives to video decoding. A pass
/// always decodes one sample, so a slow picture cannot stop the video.
const DECODE_SLICE: Duration = Duration::from_millis(8);
/// Most samples handed to the video decoder in one pass of the controller loop.
const DECODE_MAX_SAMPLES: usize = 8;
/// The longest sleep of the controller loop.
const POLL_MAX: Duration = Duration::from_millis(15);
/// The shortest sleep of the controller loop.
const POLL_MIN: Duration = Duration::from_millis(1);
/// Opus decodes at this rate.
const OPUS_RATE: u32 = 48_000;

/// What the player reports; `generation` names the file it belongs to.
#[derive(Debug, Clone, PartialEq)]
pub enum MediaEvent {
    /// The file is open. A duration of 0 means that it is not known.
    Ready { duration: f64, has_video: bool },
    /// The play position, in seconds.
    Position(f64),
    /// A picture to show: straight RGBA, `width * height * 4` bytes.
    Frame {
        width: u32,
        height: u32,
        rgba: Vec<u8>,
    },
    /// Play reached the end of the file.
    Ended,
    /// The file can't be opened, decoded or played.
    Failed(String),
    /// The new output did not open: the sound goes on the old output.
    OutputNotMoved(String),
    /// The sound of the file cannot play: the viewer tells the user why.
    AudioNote(AudioNote),
}

enum Command {
    Open {
        bytes: Arc<[u8]>,
        extension: String,
        generation: u64,
    },
    Play,
    Pause,
    Seek(f64),
    Volume(f32),
    /// The selected output changed: open it and move the sound there.
    Reopen,
    Close,
}

/// Handle to the controller thread.
#[derive(Clone)]
pub struct MediaPlayer {
    commands: mpsc::Sender<Command>,
}

type EventSink = Arc<dyn Fn(u64, MediaEvent) + Send + Sync>;

impl MediaPlayer {
    /// Starts the controller thread; `on_event` runs on that thread.
    pub fn spawn(on_event: impl Fn(u64, MediaEvent) + Send + Sync + 'static) -> Self {
        let (commands, rx) = mpsc::channel();
        let on_event: EventSink = Arc::new(on_event);
        thread::spawn(move || controller(rx, on_event));
        Self { commands }
    }

    /// Opens a file; it starts to play at once. `extension` is the file type
    /// without the dot.
    pub fn open(&self, bytes: Arc<[u8]>, extension: &str, generation: u64) {
        let _ = self.commands.send(Command::Open {
            bytes,
            extension: extension.to_ascii_lowercase(),
            generation,
        });
    }

    pub fn play(&self) {
        let _ = self.commands.send(Command::Play);
    }

    pub fn pause(&self) {
        let _ = self.commands.send(Command::Pause);
    }

    /// Moves to `seconds` from the start.
    pub fn seek(&self, seconds: f64) {
        let _ = self.commands.send(Command::Seek(seconds));
    }

    /// `volume` from 0.0 (silent) to 1.0.
    pub fn set_volume(&self, volume: f32) {
        let _ = self.commands.send(Command::Volume(volume.clamp(0.0, 1.0)));
    }

    /// Moves the sound to the selected output (see `audio_output`). The
    /// position, the play or pause state and the volume stay.
    pub fn reopen_output(&self) {
        let _ = self.commands.send(Command::Reopen);
    }

    /// Stops the file and frees it.
    pub fn close(&self) {
        let _ = self.commands.send(Command::Close);
    }
}

fn controller(commands: Receiver<Command>, on_event: EventSink) {
    let mut device: Option<rodio::MixerDeviceSink> = None;
    let mut volume = 1.0f32;
    let mut session: Option<Session> = None;
    loop {
        let wait = session
            .as_ref()
            .map_or(Duration::from_secs(3600), Session::poll_interval);
        match commands.recv_timeout(wait) {
            Ok(Command::Open {
                bytes,
                extension,
                generation,
            }) => {
                session = None;
                // The sink follows the device that was the default when it
                // opened. Open it again for each file, so a new default
                // device (a headset, a monitor) gets the sound.
                device = None;
                ensure_device(&mut device);
                match Session::open_noted(bytes, &extension, generation, volume, device.as_ref()) {
                    Ok(opened) => {
                        on_event(
                            generation,
                            MediaEvent::Ready {
                                duration: opened.duration,
                                has_video: opened.video.is_some(),
                            },
                        );
                        if let Some(note) = opened.audio_note.clone() {
                            on_event(generation, MediaEvent::AudioNote(note));
                        }
                        session = Some(opened);
                    }
                    Err(OpenError::Audio(err)) => {
                        if audio_error_is_loggable(&err) {
                            cordiale_core::persistence::log_line(&format!(
                                "audio file could not be opened: {}",
                                err.describe()
                            ));
                        }
                        if let Some(note) = err.note() {
                            on_event(generation, MediaEvent::AudioNote(note));
                        }
                        on_event(generation, MediaEvent::Failed(err.describe()));
                    }
                    Err(OpenError::Text(reason)) => {
                        on_event(generation, MediaEvent::Failed(reason))
                    }
                }
            }
            Ok(Command::Play) => {
                if let Some(open) = session.as_mut() {
                    if open.ended {
                        match open.restart(volume, device.as_ref()) {
                            Ok(()) => {}
                            Err(reason) => on_event(open.generation, MediaEvent::Failed(reason)),
                        }
                    }
                    open.set_paused(false);
                }
            }
            Ok(Command::Pause) => {
                if let Some(open) = session.as_mut() {
                    open.set_paused(true);
                }
            }
            Ok(Command::Seek(seconds)) => {
                if let Some(open) = session.as_mut() {
                    if open.audio_exhausted() {
                        let paused = open.paused;
                        match open.restart(volume, device.as_ref()) {
                            Ok(()) => open.set_paused(paused),
                            Err(reason) => on_event(open.generation, MediaEvent::Failed(reason)),
                        }
                    }
                    open.seek(seconds);
                }
            }
            Ok(Command::Volume(value)) => {
                volume = value;
                if let Some(audio) = session.as_ref().and_then(|open| open.audio.as_ref()) {
                    audio.set_volume(volume);
                }
            }
            Ok(Command::Reopen) => {
                let moving = session
                    .as_ref()
                    .is_some_and(|open| !open.ended && open.audio.is_some());
                let mut next = None;
                ensure_device(&mut next);
                if next.is_none() && moving {
                    // The old output keeps the sound; the next file opens
                    // the selected output again.
                    if let Some(open) = session.as_ref() {
                        on_event(
                            open.generation,
                            MediaEvent::OutputNotMoved("no audio output".to_string()),
                        );
                    }
                } else {
                    device = next;
                    if let Some(open) = session.as_mut().filter(|open| !open.ended) {
                        if let Err(reason) = open.move_output(volume, device.as_ref()) {
                            on_event(open.generation, MediaEvent::OutputNotMoved(reason.clone()));
                            on_event(open.generation, MediaEvent::Failed(reason));
                        }
                    }
                }
            }
            Ok(Command::Close) => session = None,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if let Some(open) = session.as_mut() {
            open.tick(&on_event);
        }
    }
}

/// Opens the selected output when none is open. A video can play without a
/// sound device, so an error only goes to the log.
fn ensure_device(device: &mut Option<rodio::MixerDeviceSink>) {
    if device.is_some() {
        return;
    }
    match crate::audio_output::open_selected_sink() {
        Ok(sink) => {
            crate::audio_output::log_opened(&sink);
            *device = Some(sink);
        }
        Err(err) => cordiale_core::persistence::log_line(&format!("no audio output: {err}")),
    }
}

/// A play position that runs on the wall clock, for a file with no audio.
struct WallClock {
    base: f64,
    started: Option<Instant>,
}

impl WallClock {
    fn position(&self) -> f64 {
        self.base + self.started.map_or(0.0, |at| at.elapsed().as_secs_f64())
    }

    fn pause(&mut self) {
        self.base = self.position();
        self.started = None;
    }

    fn play(&mut self) {
        if self.started.is_none() {
            self.started = Some(Instant::now());
        }
    }

    fn seek(&mut self, seconds: f64) {
        let running = self.started.is_some();
        self.base = seconds;
        self.started = running.then(Instant::now);
    }
}

/// Moves the wall clock to the last position of a sound that has ended. The
/// clock already runs or stops with the sound, so only its time changes.
fn hand_over(clock: &mut WallClock, audio_at: f64) {
    clock.seek(audio_at);
}

/// The open file.
struct Session {
    generation: u64,
    bytes: Arc<[u8]>,
    extension: String,
    audio: Option<rodio::Player>,
    /// Under-runs of the audio output, shared with the sound source.
    audio_stats: Option<Arc<AudioStats>>,
    /// What the sound did at the start: one of the `AUDIO_*` words.
    audio_state: &'static str,
    /// What the viewer says about a sound that cannot play.
    audio_note: Option<AudioNote>,
    /// The sound still plays and is the clock. When it ends before the
    /// video, the wall clock goes on from `audio_at`.
    audio_live: bool,
    /// The last play position of the sound, in seconds.
    audio_at: f64,
    video: Option<VideoPlayer>,
    clock: WallClock,
    paused: bool,
    ended: bool,
    duration: f64,
    last_report: Instant,
}

/// Why a file did not open.
enum OpenError {
    /// The sound of an audio file could not be opened.
    Audio(Box<AudioOpenError>),
    Text(String),
}

impl From<String> for OpenError {
    fn from(reason: String) -> Self {
        Self::Text(reason)
    }
}

impl OpenError {
    fn into_text(self) -> String {
        match self {
            Self::Audio(err) => err.describe(),
            Self::Text(reason) => reason,
        }
    }
}

impl Session {
    fn open(
        bytes: Arc<[u8]>,
        extension: &str,
        generation: u64,
        volume: f32,
        device: Option<&rodio::MixerDeviceSink>,
    ) -> Result<Self, String> {
        Self::open_noted(bytes, extension, generation, volume, device).map_err(OpenError::into_text)
    }

    /// Like [`Session::open`], but an audio file that fails gives its typed
    /// error, so the viewer can say why.
    fn open_noted(
        bytes: Arc<[u8]>,
        extension: &str,
        generation: u64,
        volume: f32,
        device: Option<&rodio::MixerDeviceSink>,
    ) -> Result<Self, OpenError> {
        let (audio_source, video, audio_error) =
            if matches!(extension, "mp4" | "mov" | "m4v" | "webm") {
                let (video, audio_source, audio_error) = open_video(&bytes, extension)?;
                (audio_source, Some(video), audio_error)
            } else {
                match audio_source(&bytes, extension) {
                    Ok(source) => (Some(source), None, None),
                    Err(err) => return Err(OpenError::Audio(Box::new(err))),
                }
            };
        let mut duration = audio_source
            .as_ref()
            .and_then(|source| source.total_duration())
            .map_or(0.0, |total| total.as_secs_f64());
        if let Some(video) = &video {
            duration = duration.max(video.duration);
        }
        let mut audio_stats = None;
        let audio_state = match (audio_source.is_some(), device.is_some()) {
            (true, true) => AUDIO_PLAYING,
            (true, false) => AUDIO_NO_OUTPUT,
            (false, _) => AUDIO_NO_TRACK,
        };
        let audio = match (audio_source, device) {
            (Some(source), Some(sink)) => {
                let player = rodio::Player::connect_new(sink.mixer());
                player.set_volume(volume);
                let buffered = BufferedAudio::new(source);
                audio_stats = Some(buffered.stats());
                player.append(buffered);
                Some(player)
            }
            (None, _) if video.is_none() => return Err("no audio track".to_string().into()),
            (Some(_), None) if video.is_none() => return Err("no audio output".to_string().into()),
            (Some(_), None) => {
                cordiale_core::persistence::log_line(
                    "video has a sound, but no audio output is open: it plays without sound",
                );
                None
            }
            _ => None,
        };
        let audio_note = if video.is_some() && audio_state == AUDIO_NO_OUTPUT {
            Some(AudioNote::no_output())
        } else {
            audio_error.as_ref().and_then(AudioOpenError::note)
        };
        let mut clock = WallClock {
            base: 0.0,
            started: None,
        };
        clock.play();
        Ok(Self {
            generation,
            bytes,
            extension: extension.to_string(),
            audio_live: audio.is_some(),
            audio_at: 0.0,
            audio,
            audio_stats,
            audio_state,
            audio_note,
            video,
            clock,
            paused: false,
            ended: false,
            duration,
            last_report: Instant::now(),
        })
    }

    /// How long the controller may sleep before the next pass: until the next
    /// picture is due, and not at all while the video queue still has room.
    fn poll_interval(&self) -> Duration {
        if self.ended {
            return POLL_MAX;
        }
        self.video.as_ref().map_or(POLL_MAX, |video| {
            video.next_wait(self.position(), self.paused)
        })
    }

    /// Opens the file again from the start, after it played to the end.
    fn restart(
        &mut self,
        volume: f32,
        device: Option<&rodio::MixerDeviceSink>,
    ) -> Result<(), String> {
        let again = Session::open(
            Arc::clone(&self.bytes),
            &self.extension,
            self.generation,
            volume,
            device,
        )?;
        *self = again;
        Ok(())
    }

    /// Plays the file on another output from the same position, with the
    /// same play or pause state. A file with no sound has nothing to move.
    fn move_output(
        &mut self,
        volume: f32,
        device: Option<&rodio::MixerDeviceSink>,
    ) -> Result<(), String> {
        if self.audio.is_none() {
            return Ok(());
        }
        let position = self.position();
        let paused = self.paused;
        self.restart(volume, device)?;
        self.seek(position);
        self.set_paused(paused);
        Ok(())
    }

    /// The sound has played to its end, so its source cannot play again
    /// without opening the file again.
    fn audio_exhausted(&self) -> bool {
        self.audio
            .as_ref()
            .is_some_and(|audio| !self.audio_live || audio.empty())
    }

    fn position(&self) -> f64 {
        match &self.audio {
            Some(audio) if self.audio_live => audio.get_pos().as_secs_f64(),
            _ => self.clock.position(),
        }
    }

    /// Keeps the last position of the sound. When the sound has ended, the
    /// wall clock takes over from that position, so the rest of the video
    /// still plays.
    fn follow_audio(&mut self) {
        let Some(audio) = self.audio.as_ref().filter(|_| self.audio_live) else {
            return;
        };
        if audio.empty() {
            hand_over(&mut self.clock, self.audio_at);
            self.audio_live = false;
        } else {
            self.audio_at = audio.get_pos().as_secs_f64();
        }
    }

    fn set_paused(&mut self, paused: bool) {
        if self.ended && paused {
            return;
        }
        self.paused = paused;
        if paused {
            self.clock.pause();
            if let Some(audio) = &self.audio {
                audio.pause();
            }
        } else {
            self.clock.play();
            if let Some(audio) = &self.audio {
                audio.play();
            }
        }
    }

    fn seek(&mut self, seconds: f64) {
        let mut target = seconds.max(0.0);
        if self.duration > 0.0 {
            target = target.min(self.duration);
        }
        if let Some(audio) = &self.audio {
            let _ = audio.try_seek(Duration::from_secs_f64(target));
        }
        self.clock.seek(target);
        self.audio_at = target;
        if let Some(video) = self.video.as_mut() {
            video.seek(target);
        }
        self.ended = false;
    }

    fn tick(&mut self, on_event: &EventSink) {
        if self.ended {
            return;
        }
        self.follow_audio();
        let position = self.position();
        if let Some(video) = self.video.as_mut() {
            video.fill();
            if let Some(frame) = video.due(position) {
                on_event(self.generation, frame);
            }
            video.check_starved(self.paused);
        }
        if self.last_report.elapsed() >= Duration::from_millis(250) {
            self.last_report = Instant::now();
            on_event(self.generation, MediaEvent::Position(position));
        }
        let audio_done = self.audio.as_ref().is_none_or(|audio| audio.empty());
        let video_done = self.video.as_ref().is_none_or(VideoPlayer::finished);
        let clock_done = self.audio_live || self.duration <= 0.0 || position >= self.duration;
        if !self.paused && audio_done && video_done && clock_done {
            self.ended = true;
            self.paused = true;
            self.clock.pause();
            on_event(self.generation, MediaEvent::Position(self.duration));
            on_event(self.generation, MediaEvent::Ended);
        }
    }
}

// ----- measurements -----

/// What the video of one file did while it played. The player writes one
/// line with these numbers to the log when the file closes, so slow
/// systems can be told apart from slow decoders.
#[derive(Debug, Default, Clone, PartialEq)]
struct VideoStats {
    /// The decoder in use: `software`, or the name of the hardware path.
    decoder: &'static str,
    /// The hardware decoder failed and the software decoder took over.
    fell_back: bool,
    /// Pictures sent to the window.
    shown: u64,
    /// Pictures shown more than one frame time after their time.
    late: u64,
    /// Pictures that were due and skipped, because a newer one was due too.
    dropped: u64,
    /// Times when the queue ran empty during play.
    starved: u64,
    /// Samples decoded, and the time that their decoding took.
    decoded: u64,
    decode_total: Duration,
    decode_max: Duration,
    /// The longest colour conversion of a picture.
    convert_max: Duration,
}

impl VideoStats {
    fn record_decode(&mut self, took: Duration) {
        self.decoded += 1;
        self.decode_total += took;
        self.decode_max = self.decode_max.max(took);
    }
}

/// Counters of the audio output. The output thread, the decode worker and
/// the controller share them.
#[derive(Default)]
struct AudioStats {
    /// Times when the output found the decoded queue empty and had to wait.
    underruns: AtomicU64,
    /// The reader that decodes the sound: `main` or `fallback`.
    path: &'static str,
    /// The number of the audio track in the file, counted from 1; 0 when
    /// it is not known.
    track: u8,
    /// The largest absolute sample that the decoder made, before the gain,
    /// as the bits of an `f32`.
    peak: AtomicU32,
    /// How many samples the decoder made.
    samples: AtomicU64,
    /// Why the sound ended before the end of the stream, if it did.
    end: Mutex<Option<String>>,
}

impl AudioStats {
    fn with_path(path: &'static str) -> Self {
        Self {
            path,
            ..Self::default()
        }
    }

    fn with_track(mut self, track: u8) -> Self {
        self.track = track;
        self
    }

    /// Counts the samples of one decoded chunk and keeps the largest one.
    fn record_samples(&self, samples: &[Sample]) {
        let peak = samples
            .iter()
            .fold(0.0, |peak: f32, sample| peak.max(sample.abs()));
        self.samples
            .fetch_add(samples.len() as u64, Ordering::Relaxed);
        // A compare-and-swap loop: the largest value wins. `fetch_update` is
        // deprecated in the newest standard library and renamed there.
        let mut current = self.peak.load(Ordering::Relaxed);
        while peak > f32::from_bits(current) {
            match self.peak.compare_exchange_weak(
                current,
                peak.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    fn peak(&self) -> f32 {
        f32::from_bits(self.peak.load(Ordering::Relaxed))
    }

    /// Notes that the sound ended on an error. Only the first one counts,
    /// and only that one goes to the log.
    fn record_end(&self, reason: &str) {
        let Ok(mut end) = self.end.lock() else {
            return;
        };
        if end.is_none() {
            cordiale_core::persistence::log_line(&format!("audio ended early: {reason}"));
            *end = Some(reason.to_string());
        }
    }

    fn end_reason(&self) -> Option<String> {
        self.end.lock().ok().and_then(|end| end.clone())
    }
}

/// The file has a sound and it plays on the open output.
const AUDIO_PLAYING: &str = "playing";
/// The file has a sound, but no output is open: it plays without sound.
const AUDIO_NO_OUTPUT: &str = "no_output";
/// The file has no sound, or its audio track could not be opened.
const AUDIO_NO_TRACK: &str = "no_track";

/// The line for the log.
fn playback_summary(
    video: Option<&VideoStats>,
    audio: Option<&AudioStats>,
    audio_state: &str,
) -> String {
    let mut line = format!("media playback: audio={audio_state}");
    if let Some(video) = video {
        let average = video
            .decode_total
            .checked_div(u32::try_from(video.decoded).unwrap_or(u32::MAX).max(1))
            .unwrap_or_default();
        line.push_str(&format!(
            " decoder={}{} shown={} late={} dropped={} starved={} decode_avg={:.1}ms decode_max={:.1}ms convert_max={:.1}ms",
            video.decoder,
            if video.fell_back { " (fallback)" } else { "" },
            video.shown,
            video.late,
            video.dropped,
            video.starved,
            average.as_secs_f64() * 1000.0,
            video.decode_max.as_secs_f64() * 1000.0,
            video.convert_max.as_secs_f64() * 1000.0,
        ));
    }
    if let Some(audio) = audio {
        line.push_str(&format!(
            " audio_underruns={} audio_path={}",
            audio.underruns.load(Ordering::Relaxed),
            audio.path,
        ));
        // Only a later track is named: the first track is the usual case.
        if audio.track > 1 {
            line.push_str(&format!(" audio_track={}", audio.track));
        }
        line.push_str(&format!(
            " audio_peak={:.3} audio_samples={}",
            audio.peak(),
            audio.samples.load(Ordering::Relaxed),
        ));
        if let Some(reason) = audio.end_reason() {
            line.push_str(&format!(" audio_end={reason}"));
        }
    }
    line
}

impl Drop for Session {
    fn drop(&mut self) {
        let audio = self.audio_stats.as_deref();
        let video = self.video.as_ref().map(|video| &video.stats);
        if video.is_some() || audio.is_some() {
            cordiale_core::persistence::log_line(&playback_summary(video, audio, self.audio_state));
        }
    }
}

// ----- the viewer ----

static PLAYER: OnceLock<MediaPlayer> = OnceLock::new();
static CURRENT: AtomicU64 = AtomicU64::new(0);

/// Tickets for chat links that are classified before the viewer opens. A
/// ticket is taken before the network probe starts; a newer link, a close of
/// the viewer or a logout makes every older ticket stale.
pub struct LinkTickets(AtomicU64);

impl LinkTickets {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// A new ticket; every older ticket is stale from now on.
    pub fn take(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Makes every ticket taken so far stale.
    pub fn invalidate(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    /// True when `ticket` is the newest one and the screen is signed in.
    pub fn allows(&self, ticket: u64, screen: &str) -> bool {
        !matches!(screen, "connect" | "splash") && self.0.load(Ordering::SeqCst) == ticket
    }
}

static LINK_TICKETS: LinkTickets = LinkTickets::new();

/// Takes a ticket for a link, before its probe starts.
pub fn link_ticket() -> u64 {
    LINK_TICKETS.take()
}

/// Makes every pending link stale: a logout or a close of the viewer.
pub fn invalidate_links() {
    LINK_TICKETS.invalidate();
}

/// True when the link of `ticket` may still change the viewer or the browser.
pub fn link_allowed(ticket: u64, screen: &str) -> bool {
    LINK_TICKETS.allows(ticket, screen)
}

/// The player of the viewer; the first call starts it.
pub fn shared(ui: &slint::Weak<AppWindow>) -> &'static MediaPlayer {
    PLAYER.get_or_init(|| {
        let ui = Mutex::new(ui.clone());
        MediaPlayer::spawn(move |generation, event| {
            if generation != CURRENT.load(Ordering::Relaxed) {
                return;
            }
            let Ok(ui) = ui.lock() else {
                return;
            };
            let _ = ui.upgrade_in_event_loop(move |ui| apply(&ui, generation, event));
        })
    })
}

/// The player, when the viewer has started it.
pub fn existing() -> Option<&'static MediaPlayer> {
    PLAYER.get()
}

/// Starts the count for a new file in the viewer; the news of an earlier
/// file is dropped from now on.
pub fn begin() -> u64 {
    CURRENT.fetch_add(1, Ordering::Relaxed) + 1
}

/// The count of the file in the viewer now. [`end`] changes it, so a task
/// that keeps the count can see that the viewer has moved on.
pub fn current() -> u64 {
    CURRENT.load(Ordering::Relaxed)
}

/// The viewer shows another file or is closed: stops the sound, the video
/// and the animation.
pub fn end() {
    CURRENT.fetch_add(1, Ordering::Relaxed);
    if let Some(player) = PLAYER.get() {
        player.close();
    }
    crate::raster_image::stop();
}

/// Puts the news of the player into the viewer.
fn apply(ui: &AppWindow, generation: u64, event: MediaEvent) {
    if generation != CURRENT.load(Ordering::Relaxed) {
        return;
    }
    match event {
        MediaEvent::Ready {
            duration,
            has_video,
        } => {
            ui.set_media_duration(duration as f32);
            ui.set_media_position(0.0);
            ui.set_media_time(clock_label(0.0, duration).into());
            ui.set_media_playing(true);
            ui.set_media_kind(if has_video { "video" } else { "audio" }.into());
            // An earlier file's note must not stay; a note for this file
            // comes in its own event.
            ui.set_media_audio_note("".into());
            ui.set_media_audio_note_detail("".into());
        }
        MediaEvent::AudioNote(note) => {
            ui.set_media_audio_note(note.key.into());
            ui.set_media_audio_note_detail(note.detail.into());
        }
        MediaEvent::Position(seconds) => {
            ui.set_media_position(seconds as f32);
            let duration = f64::from(ui.get_media_duration());
            ui.set_media_time(clock_label(seconds, duration).into());
        }
        MediaEvent::Frame {
            width,
            height,
            rgba,
        } => {
            let buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                &rgba, width, height,
            );
            ui.set_media_image(slint::Image::from_rgba8(buffer));
        }
        MediaEvent::Ended => ui.set_media_playing(false),
        MediaEvent::OutputNotMoved(_) => {
            ui.set_audio_output_status(crate::audio_output::NOT_MOVED_KEY.into());
        }
        MediaEvent::Failed(reason) => {
            ui.set_media_error(reason.into());
            ui.set_media_kind("failed".into());
            // The file is still in memory, so Download works.
            ui.set_media_saveable(true);
        }
    }
}

/// One time as `m:ss`, or `h:mm:ss` from one hour on.
fn clock_text(seconds: f64) -> String {
    let total = if seconds.is_finite() && seconds > 0.0 {
        seconds as u64
    } else {
        0
    };
    let (hours, minutes, secs) = (total / 3600, total / 60 % 60, total % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{secs:02}")
    } else {
        format!("{minutes}:{secs:02}")
    }
}

/// The time label of the controls: the position and, if known, the length.
fn clock_label(position: f64, duration: f64) -> String {
    if duration > 0.0 {
        format!("{} / {}", clock_text(position), clock_text(duration))
    } else {
        clock_text(position)
    }
}

// ----- audio -----

/// How the packets of an audio track are read.
enum Packets {
    Format {
        reader: Box<dyn FormatReader>,
        track_id: u32,
    },
    /// The packets of a WebM track: position in the file and time.
    List {
        bytes: Arc<[u8]>,
        list: Vec<(usize, usize, i64)>,
        next: usize,
    },
    /// The packets of an MP4 track, read by the fallback reader.
    V05(Packets05),
}

struct Pcm {
    data: Vec<u8>,
    ts: Timestamp,
    dur: MediaDuration,
    trim_start: MediaDuration,
    trim_end: MediaDuration,
}

impl Packets {
    /// The next packet; `Ok(None)` at the end of the stream, and the message
    /// of the reader when it fails.
    fn next(&mut self) -> Result<Option<Pcm>, String> {
        match self {
            Packets::Format { reader, track_id } => loop {
                let packet = match reader.next_packet() {
                    Ok(Some(packet)) => packet,
                    Ok(None) => return Ok(None),
                    Err(err) => return Err(err.to_string()),
                };
                if packet.track_id == *track_id {
                    return Ok(Some(Pcm {
                        data: packet.data.into_vec(),
                        ts: packet.pts,
                        dur: packet.dur,
                        trim_start: packet.trim_start,
                        trim_end: packet.trim_end,
                    }));
                }
            },
            Packets::List { bytes, list, next } => {
                let Some(&(offset, size, us)) = list.get(*next) else {
                    return Ok(None);
                };
                *next += 1;
                let Some(data) = offset
                    .checked_add(size)
                    .and_then(|end| bytes.get(offset..end))
                else {
                    return Ok(None);
                };
                Ok(Some(Pcm {
                    data: data.to_vec(),
                    ts: Timestamp::new(us.max(0)),
                    dur: MediaDuration::ZERO,
                    trim_start: MediaDuration::ZERO,
                    trim_end: MediaDuration::ZERO,
                }))
            }
            Packets::V05(packets) => Ok(packets.next_data()?.map(|data| Pcm {
                data,
                // The fallback decoder reads the data of a packet, not its times.
                ts: Timestamp::new(0),
                dur: MediaDuration::ZERO,
                trim_start: MediaDuration::ZERO,
                trim_end: MediaDuration::ZERO,
            })),
        }
    }

    /// Moves to `seconds`. Returns how many seconds before that time the
    /// next packet starts: the decoded sound of that gap is to be dropped.
    fn seek(&mut self, seconds: f64) -> f64 {
        match self {
            Packets::Format { reader, track_id } => {
                let Some(time) = Time::try_from_secs_f64(seconds) else {
                    return 0.0;
                };
                let Ok(seeked) = reader.seek(
                    SeekMode::Coarse,
                    SeekTo::Time {
                        time,
                        track_id: Some(*track_id),
                    },
                ) else {
                    return 0.0;
                };
                let time_base = reader
                    .tracks()
                    .iter()
                    .find(|track| track.id == seeked.track_id)
                    .and_then(|track| track.time_base);
                let gap = seeked.required_ts.duration_from(seeked.actual_ts);
                gap.zip(time_base)
                    .and_then(|(gap, base)| base.calc_duration(gap))
                    .map_or(0.0, |gap| gap.as_secs_f64().clamp(0.0, seconds))
            }
            Packets::List { list, next, .. } => {
                let target = (seconds * 1_000_000.0) as i64;
                *next = list.partition_point(|packet| packet.2 < target);
                0.0
            }
            Packets::V05(packets) => packets.seek(seconds),
        }
    }
}

enum Decode {
    Symphonia(Box<dyn SymphoniaDecoder>),
    Opus {
        decoder: Box<OpusDecoder>,
        scratch: Vec<f32>,
    },
    /// The fallback decoder of MP4 sound.
    V05(Decoder05),
}

/// A decoded audio file as a rodio source.
struct AudioSource {
    packets: Packets,
    track_id: u32,
    /// The number of the audio track in the file, counted from 1.
    audio_track: u8,
    decode: Decode,
    channels: u16,
    rate: u32,
    pending: Vec<Sample>,
    at: usize,
    /// Interleaved samples still to drop at the start (Opus pre-skip).
    skip: usize,
    total: Option<Duration>,
    /// Why the last `refill` ended the sound, when it was an error.
    failure: Option<String>,
}

fn count(channels: u16) -> ChannelCount {
    ChannelCount::new(channels.max(1))
        .or_else(|| ChannelCount::new(2))
        .expect("a channel count")
}

fn rate(hz: u32) -> SampleRate {
    SampleRate::new(hz.max(1))
        .or_else(|| SampleRate::new(44_100))
        .expect("a sample rate")
}

impl AudioSource {
    /// The reader that decodes the sound, for the log.
    fn path(&self) -> &'static str {
        match self.decode {
            Decode::V05(_) => "fallback",
            _ => "main",
        }
    }

    /// Decodes the next packet into `pending`; `false` at the end.
    fn refill(&mut self) -> bool {
        loop {
            let packet = match self.packets.next() {
                Ok(Some(packet)) => packet,
                Ok(None) => return false,
                Err(err) => {
                    self.failure = Some(format!("read error: {err}"));
                    return false;
                }
            };
            self.pending.clear();
            self.at = 0;
            match &mut self.decode {
                Decode::Opus { decoder, scratch } => {
                    let channels = usize::from(self.channels);
                    match decoder.decode_float(&packet.data, scratch, false) {
                        Ok(frames) => {
                            let end = (frames * channels).min(scratch.len());
                            self.pending.extend_from_slice(&scratch[..end]);
                        }
                        Err(_) => continue,
                    }
                }
                Decode::Symphonia(decoder) => {
                    let mut coded =
                        PacketRef::new(self.track_id, packet.ts, packet.dur, &packet.data);
                    coded.trim_start = packet.trim_start;
                    coded.trim_end = packet.trim_end;
                    match decoder.decode_ref(&coded) {
                        Ok(decoded) => {
                            let spec = decoded.spec();
                            self.channels = spec.channels().count() as u16;
                            self.rate = spec.rate();
                            decoded.copy_to_vec_interleaved::<f32>(&mut self.pending);
                        }
                        Err(SymphoniaError::DecodeError(_)) => continue,
                        Err(err) => {
                            self.failure = Some(format!("decode error: {err}"));
                            return false;
                        }
                    }
                }
                Decode::V05(decoder) => match decoder.decode(&packet.data, &mut self.pending) {
                    media_audio_v05::Decoded::Samples { channels, rate } => {
                        self.channels = channels;
                        self.rate = rate;
                    }
                    media_audio_v05::Decoded::Skip => continue,
                    media_audio_v05::Decoded::Stop(err) => {
                        self.failure = Some(format!("decode error: {err}"));
                        return false;
                    }
                },
            }
            if self.skip > 0 {
                let dropped = self.skip.min(self.pending.len());
                self.pending.drain(..dropped);
                self.skip -= dropped;
            }
            if !self.pending.is_empty() {
                return true;
            }
        }
    }
}

impl Iterator for AudioSource {
    type Item = Sample;

    fn next(&mut self) -> Option<Sample> {
        if self.at >= self.pending.len() && !self.refill() {
            return None;
        }
        let sample = self.pending[self.at];
        self.at += 1;
        Some(sample)
    }
}

impl Source for AudioSource {
    fn current_span_len(&self) -> Option<usize> {
        None
    }

    fn channels(&self) -> ChannelCount {
        count(self.channels)
    }

    fn sample_rate(&self) -> SampleRate {
        rate(self.rate)
    }

    fn total_duration(&self) -> Option<Duration> {
        self.total
    }

    fn try_seek(&mut self, pos: Duration) -> Result<(), rodio::source::SeekError> {
        let gap = self.packets.seek(pos.as_secs_f64());
        self.skip = 0;
        match &mut self.decode {
            Decode::Symphonia(decoder) => {
                decoder.reset();
                // The reader may stop before the time: drop the early frames.
                let frames = (gap * f64::from(self.rate)).round() as usize;
                self.skip = frames * usize::from(self.channels);
            }
            Decode::Opus { decoder, .. } => decoder.reset(),
            Decode::V05(decoder) => {
                decoder.reset();
                let frames = (gap * f64::from(self.rate)).round() as usize;
                self.skip = frames * usize::from(self.channels);
            }
        }
        self.pending.clear();
        self.at = 0;
        Ok(())
    }
}

/// Decoded chunks that wait between the decode worker and the audio output.
/// Each chunk is one packet, so the queue holds a fixed, small amount of sound.
const AUDIO_QUEUE_CHUNKS: usize = 32;

/// How long the worker sleeps when the queue is full.
const AUDIO_WORKER_IDLE: Duration = Duration::from_millis(5);

enum AudioMessage {
    Chunk {
        epoch: u64,
        channels: u16,
        rate: u32,
        samples: Vec<Sample>,
    },
    End {
        epoch: u64,
    },
}

struct AudioSeek {
    epoch: u64,
    pos: Duration,
}

/// Runs an [`AudioSource`] on a worker thread, so that packet reads and decoding
/// never delay the audio output. The output only takes decoded samples from a
/// bounded queue.
struct BufferedAudio {
    messages: Receiver<AudioMessage>,
    seeks: mpsc::Sender<AudioSeek>,
    epoch: u64,
    current: Vec<Sample>,
    at: usize,
    ended: bool,
    /// No chunk of the current position has come yet (at the start, and
    /// after a seek): waiting for it is not an under-run.
    fresh: bool,
    channels: u16,
    rate: u32,
    total: Option<Duration>,
    stats: Arc<AudioStats>,
}

impl BufferedAudio {
    fn stats(&self) -> Arc<AudioStats> {
        Arc::clone(&self.stats)
    }

    /// The next message of the worker. When the queue is empty the output
    /// has to wait for the decoder: that is an under-run, a gap in the sound.
    fn next_message(&self) -> Option<AudioMessage> {
        match self.messages.try_recv() {
            Ok(message) => Some(message),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.worker_lost();
                None
            }
            Err(mpsc::TryRecvError::Empty) => {
                if !self.fresh {
                    self.stats.underruns.fetch_add(1, Ordering::Relaxed);
                }
                let message = self.messages.recv().ok();
                if message.is_none() {
                    self.worker_lost();
                }
                message
            }
        }
    }

    /// The worker only stops when this source is dropped, so a closed queue
    /// here means that the worker panicked.
    fn worker_lost(&self) {
        self.stats.record_end("the decode worker stopped");
    }

    fn new(source: AudioSource) -> Self {
        let channels = source.channels;
        let rate = source.rate;
        let total = source.total;
        let stats = Arc::new(AudioStats::with_path(source.path()).with_track(source.audio_track));
        let (tx, messages) = mpsc::sync_channel(AUDIO_QUEUE_CHUNKS);
        let (seeks, seek_rx) = mpsc::channel();
        let worker_stats = Arc::clone(&stats);
        thread::spawn(move || audio_worker(source, tx, seek_rx, worker_stats));
        Self {
            messages,
            seeks,
            epoch: 0,
            current: Vec::new(),
            at: 0,
            ended: false,
            fresh: true,
            channels,
            rate,
            total,
            stats,
        }
    }
}

/// Decodes ahead of the audio output until the queue is full.
fn audio_worker(
    mut source: AudioSource,
    out: mpsc::SyncSender<AudioMessage>,
    seeks: Receiver<AudioSeek>,
    stats: Arc<AudioStats>,
) {
    let mut epoch = 0;
    let mut waiting: Option<AudioMessage> = None;
    let mut finished = false;
    loop {
        // Only the last seek counts.
        let mut seek = None;
        loop {
            match seeks.try_recv() {
                Ok(next) => seek = Some(next),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
        if let Some(seek) = seek {
            let _ = source.try_seek(seek.pos);
            epoch = seek.epoch;
            waiting = None;
            finished = false;
        }
        if waiting.is_none() {
            if finished {
                match seeks.recv() {
                    Ok(next) => {
                        let _ = source.try_seek(next.pos);
                        epoch = next.epoch;
                        finished = false;
                    }
                    Err(_) => return,
                }
                continue;
            }
            // The constructors decode the first packet ahead: send what is
            // still unread before the next packet.
            waiting = Some(if source.at < source.pending.len() {
                let mut samples = std::mem::take(&mut source.pending);
                samples.drain(..source.at);
                AudioMessage::Chunk {
                    epoch,
                    channels: source.channels,
                    rate: source.rate,
                    samples,
                }
            } else if source.refill() {
                AudioMessage::Chunk {
                    epoch,
                    channels: source.channels,
                    rate: source.rate,
                    samples: std::mem::take(&mut source.pending),
                }
            } else {
                finished = true;
                if let Some(reason) = source.failure.take() {
                    stats.record_end(&reason);
                }
                AudioMessage::End { epoch }
            });
            if let Some(AudioMessage::Chunk { samples, .. }) = &waiting {
                stats.record_samples(samples);
            }
            source.at = 0;
        }
        if let Some(message) = waiting.take() {
            match out.try_send(message) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(message)) => {
                    waiting = Some(message);
                    thread::sleep(AUDIO_WORKER_IDLE);
                }
                Err(mpsc::TrySendError::Disconnected(_)) => return,
            }
        }
    }
}

impl Iterator for BufferedAudio {
    type Item = Sample;

    fn next(&mut self) -> Option<Sample> {
        loop {
            if self.at < self.current.len() {
                let sample = self.current[self.at];
                self.at += 1;
                return Some(sample);
            }
            if self.ended {
                return None;
            }
            match self.next_message() {
                Some(AudioMessage::Chunk {
                    epoch,
                    channels,
                    rate,
                    samples,
                }) if epoch == self.epoch => {
                    self.channels = channels;
                    self.rate = rate;
                    self.current = samples;
                    self.at = 0;
                    self.fresh = false;
                }
                Some(AudioMessage::End { epoch }) if epoch == self.epoch => self.ended = true,
                // A chunk from before a seek.
                Some(_) => {}
                None => return None,
            }
        }
    }
}

impl Source for BufferedAudio {
    fn current_span_len(&self) -> Option<usize> {
        None
    }

    fn channels(&self) -> ChannelCount {
        count(self.channels)
    }

    fn sample_rate(&self) -> SampleRate {
        rate(self.rate)
    }

    fn total_duration(&self) -> Option<Duration> {
        self.total
    }

    fn try_seek(&mut self, pos: Duration) -> Result<(), rodio::source::SeekError> {
        self.epoch += 1;
        self.current.clear();
        self.at = 0;
        self.ended = false;
        self.fresh = true;
        // The worker stops when it is gone: the sound then ends.
        let _ = self.seeks.send(AudioSeek {
            epoch: self.epoch,
            pos,
        });
        Ok(())
    }
}

fn opus_decoder(channels: usize) -> Result<Decode, String> {
    let channels = channels.clamp(1, 2);
    let decoder = OpusDecoder::new(OPUS_RATE, channels).map_err(|err| format!("{err:?}"))?;
    Ok(Decode::Opus {
        decoder: Box::new(decoder),
        scratch: vec![0.0; OpusDecoder::MAX_FRAME_SIZE_48K * channels],
    })
}

/// The readable name of a codec of symphonia 0.6.
fn codec_name(codec: AudioCodecId) -> String {
    let name = match codec {
        well_known::CODEC_ID_AAC => CODEC_AAC,
        well_known::CODEC_ID_AC3 => "AC-3",
        well_known::CODEC_ID_ALAC => "ALAC",
        well_known::CODEC_ID_DCA => "DTS",
        well_known::CODEC_ID_EAC3 => "E-AC-3",
        well_known::CODEC_ID_FLAC => "FLAC",
        well_known::CODEC_ID_MP1 => "MP1",
        well_known::CODEC_ID_MP2 => "MP2",
        well_known::CODEC_ID_MP3 => "MP3",
        well_known::CODEC_ID_OPUS => "Opus",
        well_known::CODEC_ID_VORBIS => "Vorbis",
        other => return format!("codec {other}"),
    };
    name.to_string()
}

fn track_info(params: &AudioCodecParameters) -> TrackInfo {
    TrackInfo::new(
        codec_name(params.codec),
        params
            .channels
            .as_ref()
            .map(|channels| channels.count() as u16),
        params.sample_rate,
        params.extra_data.as_deref(),
    )
}

/// How many audio tracks of one file the player tries, at most.
const MAX_AUDIO_TRACKS: u8 = 8;

/// Opens the first audio track that plays. `open(n)` opens the audio track
/// `n` of the file, counted from 0, and its error says how many audio tracks
/// the file has. A track that fails does not end the search: the next one is
/// tried, up to [`MAX_AUDIO_TRACKS`]. When none plays, the error of the first
/// track comes back, with the count of the tracks that were tried. A file
/// with one audio track gives the result of that track, unchanged.
fn first_playable_track(
    open: impl Fn(u8) -> Result<AudioSource, AudioOpenError>,
) -> Result<AudioSource, AudioOpenError> {
    let first = match open(0) {
        Ok(source) => return Ok(source),
        Err(err) => err,
    };
    let tracks = first.tracks;
    let tried = tracks.min(MAX_AUDIO_TRACKS);
    for nth in 1..tried {
        if let Ok(mut source) = open(nth) {
            source.audio_track = nth + 1;
            cordiale_core::persistence::log_line(&format!(
                "audio track {} of {tracks} opened: the first audio track could not be opened ({})",
                nth + 1,
                first.reason_key()
            ));
            return Ok(source);
        }
    }
    Err(first.with_tracks(usize::from(tried)))
}

/// Reads an audio file, or the sound of an MP4, MOV or M4V file. An MP4 with
/// several audio tracks gives the first track that plays.
fn symphonia_source(bytes: &Arc<[u8]>, extension: &str) -> Result<AudioSource, AudioOpenError> {
    first_playable_track(|nth| symphonia_track(bytes, extension, nth))
}

/// Reads the audio track number `nth` of a file, counted from 0 among the
/// tracks that have an audio codec.
fn symphonia_track(
    bytes: &Arc<[u8]>,
    extension: &str,
    nth: u8,
) -> Result<AudioSource, AudioOpenError> {
    let stream =
        MediaSourceStream::new(Box::new(Cursor::new(Arc::clone(bytes))), Default::default());
    let mut hint = Hint::new();
    if !extension.is_empty() {
        hint.with_extension(extension);
    }
    let reader = symphonia::default::get_probe()
        .probe(
            &hint,
            stream,
            FormatOptions::default(),
            MetadataOptions::default(),
        )
        .map_err(|err| AudioOpenError::probe(err.to_string()))?;
    let candidates: Vec<_> = reader
        .tracks()
        .iter()
        .filter_map(|track| match &track.codec_params {
            Some(CodecParameters::Audio(params)) if params.codec != CODEC_ID_NULL_AUDIO => {
                Some((track.id, params.clone(), track.delay, track.num_frames))
            }
            _ => None,
        })
        .collect();
    let tracks = candidates.len();
    let (track_id, params, delay, num_frames) = candidates
        .into_iter()
        .nth(usize::from(nth))
        .ok_or_else(AudioOpenError::no_track)?;
    let track = track_info(&params);
    let mut source = if params.codec == CODEC_ID_OPUS {
        let channels = params
            .channels
            .as_ref()
            .map_or(2, |channels| channels.count());
        let mut source = AudioSource {
            packets: Packets::Format { reader, track_id },
            track_id,
            audio_track: 1,
            decode: opus_decoder(channels).map_err(|err| {
                AudioOpenError::decoder(track.clone(), false, err).with_tracks(tracks)
            })?,
            channels: channels.clamp(1, 2) as u16,
            rate: OPUS_RATE,
            pending: Vec::new(),
            at: 0,
            skip: delay.unwrap_or(0) as usize * channels.clamp(1, 2),
            total: None,
            failure: None,
        };
        source.total = ogg_opus_duration(bytes, delay.unwrap_or(0));
        source
    } else {
        let decoder = symphonia::default::get_codecs()
            .make_audio_decoder(&params, &AudioDecoderOptions::default())
            .map_err(|err| {
                AudioOpenError::decoder(
                    track.clone(),
                    matches!(err, SymphoniaError::Unsupported(_)),
                    err.to_string(),
                )
                .with_tracks(tracks)
            })?;
        let total = match (num_frames, params.sample_rate) {
            (Some(frames), Some(hz)) if hz > 0 => {
                Some(Duration::from_secs_f64(frames as f64 / f64::from(hz)))
            }
            _ => None,
        };
        AudioSource {
            packets: Packets::Format { reader, track_id },
            track_id,
            audio_track: 1,
            decode: Decode::Symphonia(decoder),
            channels: params
                .channels
                .as_ref()
                .map_or(2, |channels| channels.count() as u16),
            rate: params.sample_rate.unwrap_or(44_100),
            pending: Vec::new(),
            at: 0,
            skip: 0,
            total,
            failure: None,
        }
    };
    // Decode the first packet: the real channel count and rate come with it.
    if !source.refill() {
        return Err(AudioOpenError::first_packet(track).with_tracks(tracks));
    }
    Ok(source)
}

/// Decodes a short clip that the program carries, for the notification
/// sounds. The error text is for the log: it holds no user data.
pub(crate) fn clip_source(
    bytes: &'static [u8],
    extension: &str,
) -> Result<impl Source<Item = Sample>, String> {
    let bytes: Arc<[u8]> = Arc::from(bytes);
    symphonia_source(&bytes, extension).map_err(|err| err.describe())
}

/// The sound of an MP4 file, read by symphonia 0.5: the AAC-LC layer of an
/// HE-AAC track plays here, where 0.6 refuses the track. It gives the first
/// audio track that plays, like [`symphonia_source`].
fn symphonia05_source(bytes: &Arc<[u8]>) -> Result<AudioSource, AudioOpenError> {
    first_playable_track(|nth| symphonia05_track(bytes, nth))
}

/// Reads the audio track number `nth` of an MP4 file with symphonia 0.5.
fn symphonia05_track(bytes: &Arc<[u8]>, nth: u8) -> Result<AudioSource, AudioOpenError> {
    let opened = media_audio_v05::open(bytes, nth)?;
    let mut source = AudioSource {
        packets: Packets::V05(opened.packets),
        track_id: opened.track_id,
        audio_track: 1,
        decode: Decode::V05(opened.decoder),
        channels: opened.channels,
        rate: opened.rate,
        pending: Vec::new(),
        at: 0,
        skip: 0,
        total: opened.total,
        failure: None,
    };
    // Decode the first packet: the real channel count and rate come with it.
    if !source.refill() {
        return Err(AudioOpenError::first_packet(opened.track).with_tracks(opened.tracks));
    }
    Ok(source)
}

/// Whether the container of `extension` is MP4.
fn is_mp4(extension: &str) -> bool {
    matches!(extension, "mp4" | "m4a" | "mov" | "m4v")
}

/// The sound of an audio file or of an MP4, MOV or M4V file. An MP4 that
/// the main reader refuses goes to the fallback reader; if that fails as
/// well, the error of the main reader comes back, with the other reason.
fn audio_source(bytes: &Arc<[u8]>, extension: &str) -> Result<AudioSource, AudioOpenError> {
    let primary = match symphonia_source(bytes, extension) {
        Ok(source) => return Ok(source),
        Err(err) => err,
    };
    if !is_mp4(extension) {
        return Err(primary);
    }
    // A damaged file can make the 0.5 crates panic: that must not stop the
    // controller thread.
    let second =
        catch_unwind(AssertUnwindSafe(|| symphonia05_source(bytes))).unwrap_or_else(|_| {
            Err(AudioOpenError::probe(
                "the fallback reader stopped on the file".to_string(),
            ))
        });
    match second {
        Ok(source) => {
            cordiale_core::persistence::log_line(&format!(
                "audio opened by the fallback reader: {}",
                primary.describe()
            ));
            Ok(source)
        }
        Err(err) => Err(primary.with_fallback(&err)),
    }
}

/// The Vorbis sound of a WebM file. symphonia decodes the packets; the
/// headers of the track are its set-up data.
fn vorbis_source(
    bytes: &Arc<[u8]>,
    track: media_demux::VorbisTrack,
    total: Option<Duration>,
) -> Option<AudioSource> {
    if track.packets.is_empty() {
        return None;
    }
    let mut params = AudioCodecParameters::new();
    params
        .for_codec(CODEC_ID_VORBIS)
        .with_sample_rate(track.sample_rate)
        .with_extra_data(track.headers.into_boxed_slice());
    let decoder = symphonia::default::get_codecs()
        .make_audio_decoder(&params, &AudioDecoderOptions::default())
        .ok()?;
    let mut source = AudioSource {
        packets: Packets::List {
            bytes: Arc::clone(bytes),
            list: track.packets,
            next: 0,
        },
        track_id: 0,
        audio_track: 1,
        decode: Decode::Symphonia(decoder),
        channels: track.channels.min(usize::from(u16::MAX)) as u16,
        rate: track.sample_rate,
        pending: Vec::new(),
        at: 0,
        skip: 0,
        total,
        failure: None,
    };
    source.refill().then_some(source)
}

/// The length of an Ogg/Opus file, from the position of its last page.
fn ogg_opus_duration(bytes: &[u8], pre_skip: u32) -> Option<Duration> {
    let last = bytes.windows(4).rposition(|window| window == b"OggS")?;
    let raw = bytes.get(last + 6..last + 14)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(raw);
    let granule = u64::from_le_bytes(array);
    if granule == u64::MAX {
        return None;
    }
    let samples = granule.saturating_sub(u64::from(pre_skip));
    Some(Duration::from_secs_f64(
        samples as f64 / f64::from(OPUS_RATE),
    ))
}

// ----- video -----

/// A picture with 8 bits per sample and tight rows.
pub struct Planar {
    pub width: usize,
    pub height: usize,
    pub planes: [Vec<u8>; 3],
    /// Samples per row of each plane.
    pub strides: [usize; 3],
    /// How many luma samples share one chroma sample, across and down.
    pub shift_x: usize,
    pub shift_y: usize,
    pub mono: bool,
    /// The samples use the full range 0 to 255, not the limited range 16 to
    /// 235 (luma) and 16 to 240 (chroma).
    pub full_range: bool,
    /// The planes hold green, blue and red (identity matrix), not YUV.
    pub identity: bool,
}

fn clamp_u8(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}

/// Converts a picture to straight RGBA, with the BT.709 matrix. The range is
/// limited unless the picture says that it is full. A picture with the
/// identity matrix has its planes copied as green, blue and red.
pub fn to_rgba(picture: &Planar) -> Option<Vec<u8>> {
    let (width, height) = (picture.width, picture.height);
    if width == 0 || height == 0 || width.checked_mul(height)? > MAX_PIXELS {
        return None;
    }
    let chroma_width = width.div_ceil(picture.shift_x);
    let chroma_height = height.div_ceil(picture.shift_y);
    let luma_ok = picture.planes[0].len() >= width * height && picture.strides[0] == width;
    let chroma_ok = picture.mono
        || (picture.strides[1] == chroma_width
            && picture.strides[2] == chroma_width
            && picture.planes[1].len() >= chroma_width * chroma_height
            && picture.planes[2].len() >= chroma_width * chroma_height);
    if !luma_ok || !chroma_ok {
        return None;
    }
    let mut out = vec![255u8; width * height * 4];
    for row in 0..height {
        let luma = &picture.planes[0][row * width..(row + 1) * width];
        let chroma_row = (row / picture.shift_y) * chroma_width;
        let pixels = &mut out[row * width * 4..(row + 1) * width * 4];
        for (column, pixel) in pixels.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let (u, v) = if picture.mono {
                (128, 128)
            } else {
                let at = chroma_row + column / picture.shift_x;
                (
                    i32::from(picture.planes[1][at]),
                    i32::from(picture.planes[2][at]),
                )
            };
            if picture.identity {
                // Planes in order: green, blue, red.
                pixel[0] = v as u8;
                pixel[1] = luma[column];
                pixel[2] = u as u8;
                continue;
            }
            let d = u - 128;
            let e = v - 128;
            if picture.full_range {
                let c = 256 * i32::from(luma[column]);
                pixel[0] = clamp_u8((c + 403 * e + 128) >> 8);
                pixel[1] = clamp_u8((c - 48 * d - 120 * e + 128) >> 8);
                pixel[2] = clamp_u8((c + 475 * d + 128) >> 8);
            } else {
                let c = 298 * (i32::from(luma[column]) - 16);
                pixel[0] = clamp_u8((c + 459 * e + 128) >> 8);
                pixel[1] = clamp_u8((c - 55 * d - 136 * e + 128) >> 8);
                pixel[2] = clamp_u8((c + 541 * d + 128) >> 8);
            }
        }
    }
    Some(out)
}

/// A picture of an HEVC decoder as 8-bit planes.
fn hevc_planar(frame: &rusty_h265::frame::Frame) -> Option<Planar> {
    let picture = &frame.picture;
    let (left, top, width, height) = picture.crop;
    if width == 0 || height == 0 || width.checked_mul(height)? > MAX_PIXELS {
        return None;
    }
    let mono = picture.chroma_format_idc == 0;
    let (shift_x, shift_y) = match picture.chroma_format_idc {
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1),
    };
    let narrow = |plane: &rusty_h265::frame::Plane,
                  x: usize,
                  y: usize,
                  w: usize,
                  h: usize,
                  depth: u8|
     -> Option<Vec<u8>> {
        let shift = u32::from(depth.saturating_sub(8));
        let mut out = Vec::with_capacity(w * h);
        for row in y..y + h {
            let start = row.checked_mul(plane.stride)?.checked_add(x)?;
            let source = plane.data.get(start..start.checked_add(w)?)?;
            out.extend(source.iter().map(|value| (*value >> shift) as u8));
        }
        Some(out)
    };
    let luma = narrow(
        &picture.planes[0],
        left,
        top,
        width,
        height,
        picture.bit_depth_luma,
    )?;
    let (chroma_width, chroma_height) = (width.div_ceil(shift_x), height.div_ceil(shift_y));
    let (u, v) = if mono {
        (Vec::new(), Vec::new())
    } else {
        let args = (left / shift_x, top / shift_y, chroma_width, chroma_height);
        (
            narrow(
                &picture.planes[1],
                args.0,
                args.1,
                args.2,
                args.3,
                picture.bit_depth_chroma,
            )?,
            narrow(
                &picture.planes[2],
                args.0,
                args.1,
                args.2,
                args.3,
                picture.bit_depth_chroma,
            )?,
        )
    };
    Some(Planar {
        width,
        height,
        planes: [luma, u, v],
        strides: [width, chroma_width, chroma_width],
        shift_x,
        shift_y,
        mono,
        full_range: false,
        identity: false,
    })
}

/// A picture of the VP9 decoder as 8-bit planes.
fn vp9_planar(frame: &rusty_vp9::DecodedFrame) -> Option<Planar> {
    let (width, height) = (frame.width as usize, frame.height as usize);
    if width == 0 || height == 0 || width.checked_mul(height)? > MAX_PIXELS {
        return None;
    }
    let (shift_x, shift_y) = (1usize << frame.subsampling_x, 1usize << frame.subsampling_y);
    let bytes_per_sample = if frame.bit_depth > 8 { 2 } else { 1 };
    let shift = frame.bit_depth.saturating_sub(8);
    let mut planes: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut strides = [0usize; 3];
    for index in 0..3 {
        let (plane_width, plane_height) = if index == 0 {
            (width, height)
        } else {
            (width.div_ceil(shift_x), height.div_ceil(shift_y))
        };
        let stride_bytes = *frame.strides.get(index)?;
        let plane = frame.planes.get(index)?;
        let mut out = Vec::with_capacity(plane_width * plane_height);
        for row in 0..plane_height {
            let start = row.checked_mul(stride_bytes)?;
            let source = plane.get(start..start.checked_add(plane_width * bytes_per_sample)?)?;
            if bytes_per_sample == 1 {
                out.extend_from_slice(source);
            } else {
                out.extend(
                    source
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| (u16::from_le_bytes(*pair) >> shift) as u8),
                );
            }
        }
        planes[index] = out;
        strides[index] = plane_width;
    }
    Some(Planar {
        width,
        height,
        planes,
        strides,
        shift_x,
        shift_y,
        mono: false,
        full_range: false,
        identity: false,
    })
}

/// A picture with 8-bit 4:2:0 planes and tight rows (H.264 and VP8 give
/// this). `None` when a plane is shorter than the size needs.
pub(crate) fn yuv420_planar(
    width: usize,
    height: usize,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
) -> Option<Planar> {
    if width == 0 || height == 0 || width.checked_mul(height)? > MAX_PIXELS {
        return None;
    }
    let chroma_width = width.div_ceil(2);
    let chroma_size = chroma_width * height.div_ceil(2);
    if y.len() < width * height || u.len() < chroma_size || v.len() < chroma_size {
        return None;
    }
    Some(Planar {
        width,
        height,
        planes: [y, u, v],
        strides: [width, chroma_width, chroma_width],
        shift_x: 2,
        shift_y: 2,
        mono: false,
        full_range: false,
        identity: false,
    })
}

/// Puts a picture in the queue at the place of its time. Decoders that do
/// not reorder give the pictures in decode order, and a B picture has an
/// earlier time than the picture before it.
fn queue_sorted(queue: &mut VecDeque<(i64, Planar)>, pts: i64, picture: Planar) {
    let at = queue.partition_point(|(time, _)| *time <= pts);
    queue.insert(at, (pts, picture));
}

/// Sends one AV1 temporal unit to the decoder and queues the pictures that
/// come out.
fn av1_decode(
    decoder: &mut rusty_av1d::Decoder,
    data: &[u8],
    pts: i64,
    queue: &mut VecDeque<(i64, Planar)>,
) {
    use rusty_av1d::Rav1dError;
    let mut sent = decoder.send_data(Box::from(data), None, Some(pts), None);
    // Every round drains the pictures, so the data that waited goes in at
    // the next round. The count only stops a decoder that does not advance.
    for _ in 0..64 {
        while let Ok(picture) = decoder.get_picture() {
            if let Some(planar) = av1_planar(&picture) {
                queue_sorted(queue, picture.timestamp().unwrap_or(pts), planar);
            }
        }
        match sent {
            Err(Rav1dError::TryAgain) => sent = decoder.send_pending_data(),
            _ => break,
        }
    }
}

/// A picture of the AV1 decoder as 8-bit planes. A picture with more than 8
/// bits per sample is narrowed.
fn av1_planar(picture: &rusty_av1d::Picture) -> Option<Planar> {
    use rusty_av1d::{PixelLayout, PlanarImageComponent};
    let (width, height) = (picture.width() as usize, picture.height() as usize);
    if width == 0 || height == 0 || width.checked_mul(height)? > MAX_PIXELS {
        return None;
    }
    let (shift_x, shift_y, mono) = match picture.pixel_layout() {
        PixelLayout::I400 => (1usize, 1usize, true),
        PixelLayout::I420 => (2, 2, false),
        PixelLayout::I422 => (2, 1, false),
        PixelLayout::I444 => (1, 1, false),
    };
    let wide = picture.bit_depth() > 8;
    let shift = picture
        .bits_per_component()
        .map_or(0, |bits| u32::from(bits.0.saturating_sub(8)));
    let mut planes: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut strides = [0usize; 3];
    for (index, component) in [
        PlanarImageComponent::Y,
        PlanarImageComponent::U,
        PlanarImageComponent::V,
    ]
    .into_iter()
    .enumerate()
    {
        if mono && index > 0 {
            break;
        }
        let (plane_width, plane_height) = if index == 0 {
            (width, height)
        } else {
            (width.div_ceil(shift_x), height.div_ceil(shift_y))
        };
        let bytes_per_sample = if wide { 2 } else { 1 };
        let stride = picture.stride(component) as usize;
        let data = picture.plane(component);
        let mut out = Vec::with_capacity(plane_width * plane_height);
        for row in 0..plane_height {
            let start = row.checked_mul(stride)?;
            let source = data.get(start..start.checked_add(plane_width * bytes_per_sample)?)?;
            if wide {
                out.extend(
                    source
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| (u16::from_le_bytes(*pair) >> shift) as u8),
                );
            } else {
                out.extend_from_slice(source);
            }
        }
        planes[index] = out;
        strides[index] = plane_width;
    }
    Some(Planar {
        width,
        height,
        planes,
        strides,
        shift_x,
        shift_y,
        mono,
        full_range: matches!(picture.color_range(), rusty_av1d::pixel::YUVRange::Full),
        // A gray picture has no color planes to be identity.
        identity: !mono
            && matches!(
                picture.matrix_coefficients(),
                rusty_av1d::pixel::MatrixCoefficients::Identity
            ),
    })
}

enum Decoder {
    H264(Box<rusty_h264_decoder::Decoder>),
    Hevc(Box<rusty_h265::decoder::Decoder>),
    Vp8(Box<vp8_decoder::Decoder>),
    Vp9(Box<rusty_vp9::Vp9Decoder>),
    Av1(Box<rusty_av1d::Decoder>),
    /// The decoder of the host hardware; any failure goes to software.
    Hardware(Box<dyn HardwareDecode>),
}

/// The decoded pictures of one file, and the position in its sample list.
struct VideoPlayer {
    bytes: Arc<[u8]>,
    track: VideoTrack,
    decoder: Decoder,
    next_sample: usize,
    drained: bool,
    decoded: VecDeque<(i64, Planar)>,
    /// Most pictures that wait in `decoded`; set by the size of the picture.
    queue_limit: usize,
    shown: Option<i64>,
    /// After a fall-back to software, the pictures at or before this time
    /// were shown already: the queue skips them.
    resume_after: Option<i64>,
    duration: f64,
    /// The average time between two pictures, in microseconds.
    frame_interval_us: i64,
    /// The queue ran empty and has not filled since.
    starving: bool,
    stats: VideoStats,
}

/// How many decoded pictures of this size wait ahead of the clock. Small
/// pictures get a longer queue, so a slow pass does not show. A large picture
/// gets a shorter one, so the memory stays within [`QUEUE_BYTES`].
fn queue_frames(width: u32, height: u32) -> usize {
    let bytes = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(3)
        / 2;
    (QUEUE_BYTES / bytes.max(1)).clamp(QUEUE_MIN_FRAMES, QUEUE_MAX_FRAMES)
}

/// A track with its decoder set up, or the reason the file can't play.
fn new_decoder(track: &VideoTrack) -> Result<Decoder, String> {
    match track.codec {
        VideoCodec::H264 => {
            let mut decoder = rusty_h264_decoder::Decoder::new();
            // The sequence and picture parameter sets come first.
            let mut sets = Vec::new();
            for set in &track.parameter_sets {
                sets.extend_from_slice(&ANNEX_B_START);
                sets.extend_from_slice(set);
            }
            let _ = decoder.decode(&sets);
            Ok(Decoder::H264(Box::new(decoder)))
        }
        VideoCodec::Hevc => {
            let mut decoder = rusty_h265::decoder::Decoder::new();
            for set in &track.parameter_sets {
                let _ = decoder.push_nal(set, None);
            }
            Ok(Decoder::Hevc(Box::new(decoder)))
        }
        VideoCodec::Vp8 => {
            let mut decoder = vp8_decoder::Decoder::new();
            decoder.set_max_pixels(MAX_PIXELS as u64);
            Ok(Decoder::Vp8(Box::new(decoder)))
        }
        VideoCodec::Vp9 => Ok(Decoder::Vp9(Box::new(rusty_vp9::Vp9Decoder::new()))),
        VideoCodec::Av1 => {
            let mut settings = rusty_av1d::Settings::new();
            // One thread and no frame delay: a picture comes out of the
            // decoder right after the data that holds it.
            settings.set_n_threads(1);
            settings.set_max_frame_delay(1);
            settings.set_frame_size_limit(MAX_PIXELS as u32);
            let mut decoder = rusty_av1d::Decoder::with_settings(&settings)
                .map_err(|_| "unsupported video codec".to_string())?;
            // The sequence header from the file header, before any frame.
            for set in &track.parameter_sets {
                if !set.is_empty() {
                    let _ = decoder.send_data(set.clone().into_boxed_slice(), None, None, None);
                    while decoder.send_pending_data().is_err() {
                        if decoder.get_picture().is_err() {
                            break;
                        }
                    }
                }
            }
            Ok(Decoder::Av1(Box::new(decoder)))
        }
        VideoCodec::Other => Err("unsupported video codec".to_string()),
    }
}

/// The start code in front of a NAL unit in an Annex B stream.
const ANNEX_B_START: [u8; 4] = [0, 0, 0, 1];

/// A sample with a length in front of each NAL unit (MP4, Matroska) as an
/// Annex B access unit. The data stops at a length that does not fit.
pub(crate) fn length_prefixed_to_annex_b(data: &[u8], length_size: usize) -> Vec<u8> {
    let length_size = length_size.clamp(1, 4);
    let mut out = Vec::with_capacity(data.len() + 16);
    let mut at = 0usize;
    while at + length_size <= data.len() {
        let size = data[at..at + length_size]
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        at += length_size;
        let Some(nal) = at.checked_add(size).and_then(|end| data.get(at..end)) else {
            break;
        };
        out.extend_from_slice(&ANNEX_B_START);
        out.extend_from_slice(nal);
        at += size;
    }
    out
}

impl VideoPlayer {
    fn new(bytes: Arc<[u8]>, track: VideoTrack) -> Result<Self, String> {
        Self::with_preference(bytes, track, media_hw::Preference::from_env())
    }

    /// The hardware decoder is tried first, unless `preference` is software.
    /// A host with no hardware decoder for the track uses the software one.
    fn with_preference(
        bytes: Arc<[u8]>,
        track: VideoTrack,
        preference: media_hw::Preference,
    ) -> Result<Self, String> {
        if track.samples.is_empty() {
            return Err("no video frames".to_string());
        }
        if (track.width as usize).saturating_mul(track.height as usize) > MAX_PIXELS {
            return Err("video too large".to_string());
        }
        let decoder = match media_hw::open(&track, preference) {
            Some(hardware) => Decoder::Hardware(hardware),
            None => new_decoder(&track)?,
        };
        Ok(Self::from_decoder(bytes, track, decoder))
    }

    fn from_decoder(bytes: Arc<[u8]>, track: VideoTrack, decoder: Decoder) -> Self {
        let last = track.samples.iter().map(|s| s.pts_us).max().unwrap_or(0);
        let step = last / i64::try_from(track.samples.len()).unwrap_or(1).max(1);
        let stats = VideoStats {
            decoder: match &decoder {
                Decoder::Hardware(hardware) => hardware.name(),
                _ => "software",
            },
            ..VideoStats::default()
        };
        if let Decoder::Hardware(hardware) = &decoder {
            cordiale_core::persistence::log_line(&format!(
                "video decode: {} hardware decoder",
                hardware.name()
            ));
        }
        Self {
            duration: (last + step) as f64 / 1_000_000.0,
            queue_limit: queue_frames(track.width, track.height),
            frame_interval_us: step.max(1),
            bytes,
            track,
            decoder,
            next_sample: 0,
            drained: false,
            decoded: VecDeque::new(),
            shown: None,
            resume_after: None,
            starving: false,
            stats,
        }
    }

    fn finished(&self) -> bool {
        self.drained && self.decoded.is_empty()
    }

    /// Decodes samples until the queue is full, or until the time slice of
    /// this pass is spent. It always decodes one, so the video goes on even
    /// when one picture takes longer than the slice.
    fn fill(&mut self) {
        let started = Instant::now();
        let mut samples = 0;
        while self.decoded.len() < self.queue_limit && samples < DECODE_MAX_SAMPLES && !self.drained
        {
            if samples > 0 && started.elapsed() >= DECODE_SLICE {
                break;
            }
            samples += 1;
            let before = Instant::now();
            self.decode_next();
            self.stats.record_decode(before.elapsed());
        }
    }

    /// How long the controller may sleep. The queue is not full: decode
    /// again at once. It is full: wait for the next picture to be due.
    fn next_wait(&self, position: f64, paused: bool) -> Duration {
        if !self.drained && self.decoded.len() < self.queue_limit {
            return POLL_MIN;
        }
        let Some((pts, _)) = self.decoded.front().filter(|_| !paused) else {
            return POLL_MAX;
        };
        let due_in = (pts - (position * 1_000_000.0) as i64).max(0) as u64;
        Duration::from_micros(due_in).clamp(POLL_MIN, POLL_MAX)
    }

    /// Counts a time when the picture queue ran empty during play, once for
    /// each time. The decoder is then slower than the video.
    fn check_starved(&mut self, paused: bool) {
        let empty = !paused && !self.drained && self.shown.is_some() && self.decoded.is_empty();
        if empty && !self.starving {
            self.stats.starved += 1;
        }
        self.starving = empty;
    }

    /// The index of the last key sample at or before `index`.
    fn key_at_or_before(&self, index: usize) -> usize {
        let end = (index + 1).min(self.track.samples.len());
        self.track.samples[..end]
            .iter()
            .rposition(|sample| sample.key)
            .unwrap_or(0)
    }

    /// The hardware decoder failed. The software decoder starts again from
    /// the key sample of the earliest picture that is not shown yet, so the
    /// queued pictures come back and the video goes on.
    fn fall_back(&mut self, reason: &str) {
        cordiale_core::persistence::log_line(&format!(
            "video decode: hardware decoder stopped, using software: {reason}"
        ));
        let Ok(decoder) = new_decoder(&self.track) else {
            self.drained = true;
            return;
        };
        self.decoder = decoder;
        let mut restart = self.next_sample.saturating_sub(1);
        if let Some((pts, _)) = self.decoded.front() {
            if let Some(index) = self.track.samples.iter().position(|s| s.pts_us == *pts) {
                restart = restart.min(index);
            }
        }
        self.next_sample = self.key_at_or_before(restart);
        self.drained = false;
        self.decoded.clear();
        self.resume_after = self.shown;
        self.stats.decoder = "software";
        self.stats.fell_back = true;
    }

    fn decode_next(&mut self) {
        let Some(sample) = self.track.samples.get(self.next_sample).cloned() else {
            self.drained = true;
            match &mut self.decoder {
                Decoder::Hevc(decoder) => decoder.flush(),
                Decoder::Vp9(decoder) => decoder.flush(),
                // The pictures that are left are not worth a failure.
                Decoder::Hardware(decoder) => {
                    for (pts, picture) in decoder.flush().unwrap_or_default() {
                        queue_sorted(&mut self.decoded, pts, picture);
                    }
                }
                // These give each picture with the sample that holds it.
                Decoder::H264(_) | Decoder::Vp8(_) | Decoder::Av1(_) => {}
            }
            self.collect();
            return;
        };
        self.next_sample += 1;
        let Some(data) = sample
            .offset
            .checked_add(sample.size)
            .and_then(|end| self.bytes.get(sample.offset..end))
        else {
            return;
        };
        if let Decoder::Hardware(decoder) = &mut self.decoder {
            let unit = media_hw::access_unit(&self.track, data, sample.key);
            match decoder.decode(&unit, sample.pts_us) {
                Ok(pictures) => {
                    for (pts, picture) in pictures {
                        queue_sorted(&mut self.decoded, pts, picture);
                    }
                }
                Err(reason) => self.fall_back(&reason),
            }
            return;
        }
        match &mut self.decoder {
            Decoder::H264(decoder) => {
                let access_unit = length_prefixed_to_annex_b(data, self.track.nal_length_size);
                if let Ok(Some(frame)) = decoder.decode(&access_unit) {
                    if let Some(picture) =
                        yuv420_planar(frame.width, frame.height, frame.y, frame.u, frame.v)
                    {
                        queue_sorted(&mut self.decoded, sample.pts_us, picture);
                    }
                }
            }
            Decoder::Vp8(decoder) => {
                if let Ok(Some(picture)) = decoder.decode(data) {
                    let (width, height) = (picture.width as usize, picture.height as usize);
                    let luma = width * height;
                    let chroma = picture.chroma_width() as usize * picture.chroma_height() as usize;
                    // Tight planes: Y, then U, then V, without padding.
                    let mut planes = picture.to_i420();
                    if planes.len() >= luma + 2 * chroma {
                        let v = planes.split_off(luma + chroma);
                        let u = planes.split_off(luma);
                        if let Some(picture) = yuv420_planar(width, height, planes, u, v) {
                            queue_sorted(&mut self.decoded, sample.pts_us, picture);
                        }
                    }
                }
            }
            Decoder::Av1(decoder) => av1_decode(decoder, data, sample.pts_us, &mut self.decoded),
            Decoder::Hevc(decoder) => {
                let length_size = self.track.nal_length_size.clamp(1, 4);
                let mut at = 0usize;
                while at + length_size <= data.len() {
                    let size = data[at..at + length_size]
                        .iter()
                        .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
                    at += length_size;
                    let Some(nal) = at.checked_add(size).and_then(|end| data.get(at..end)) else {
                        break;
                    };
                    let _ = decoder.push_nal(nal, Some(sample.pts_us));
                    at += size;
                }
            }
            Decoder::Vp9(decoder) => {
                let _ = decoder.push(data, Some(sample.pts_us));
            }
            // Handled above.
            Decoder::Hardware(_) => {}
        }
        self.collect();
    }

    /// Moves the pictures that the decoder has ready into the queue.
    fn collect(&mut self) {
        let mut last = self.decoded.back().map_or(0, |(pts, _)| *pts);
        match &mut self.decoder {
            Decoder::Hevc(decoder) => {
                while let Ok(frame) = decoder.next_frame() {
                    last = frame.pts.unwrap_or(last);
                    if let Some(picture) = hevc_planar(&frame) {
                        self.decoded.push_back((last, picture));
                    }
                }
            }
            Decoder::Vp9(decoder) => {
                while let Ok(frame) = decoder.next_frame() {
                    last = frame.pts.unwrap_or(last);
                    if let Some(picture) = vp9_planar(&frame) {
                        self.decoded.push_back((last, picture));
                    }
                }
            }
            // Queued by `decode_next`, with the time of their sample.
            Decoder::H264(_) | Decoder::Vp8(_) | Decoder::Av1(_) | Decoder::Hardware(_) => {}
        }
    }

    /// The newest picture that is due at `position`, as an event.
    fn due(&mut self, position: f64) -> Option<MediaEvent> {
        let now = (position * 1_000_000.0) as i64;
        let mut newest = None;
        let mut due = 0u64;
        if let Some(limit) = self.resume_after {
            while self.decoded.front().is_some_and(|(pts, _)| *pts <= limit) {
                self.decoded.pop_front();
            }
            if !self.decoded.is_empty() {
                self.resume_after = None;
            }
        }
        while self.decoded.front().is_some_and(|(pts, _)| *pts <= now) {
            newest = self.decoded.pop_front();
            due += 1;
        }
        let (pts, picture) = newest?;
        if self.shown == Some(pts) {
            return None;
        }
        // After a seek, the pictures before the target are skipped on
        // purpose: they are not counted.
        if self.shown.is_some() {
            self.stats.dropped += due - 1;
            if now - pts > self.frame_interval_us {
                self.stats.late += 1;
            }
        }
        self.shown = Some(pts);
        let started = Instant::now();
        let rgba = to_rgba(&picture)?;
        self.stats.convert_max = self.stats.convert_max.max(started.elapsed());
        self.stats.shown += 1;
        Some(MediaEvent::Frame {
            width: picture.width as u32,
            height: picture.height as u32,
            rgba,
        })
    }

    /// Goes to the last key frame at or before `seconds`; the pictures up to
    /// `seconds` are decoded and dropped by the normal loop.
    fn seek(&mut self, seconds: f64) {
        let target = (seconds * 1_000_000.0) as i64;
        let key = self
            .track
            .samples
            .iter()
            .rposition(|sample: &VideoSample| sample.key && sample.pts_us <= target)
            .unwrap_or(0);
        // A hardware decoder is reset and kept. When it cannot reset, or the
        // decoder is software, a new software decoder starts.
        let reset = match &mut self.decoder {
            Decoder::Hardware(decoder) => decoder.reset().is_ok(),
            _ => false,
        };
        if !reset {
            if let Ok(decoder) = new_decoder(&self.track) {
                self.decoder = decoder;
                if self.stats.decoder != "software" {
                    self.stats.decoder = "software";
                    self.stats.fell_back = true;
                }
            }
        }
        self.next_sample = key;
        self.drained = false;
        self.decoded.clear();
        self.shown = None;
        self.resume_after = None;
    }
}

/// A video, its sound if the player decodes it, and why the sound did not
/// open when the file has a track that the player cannot play.
type VideoOpened = (VideoPlayer, Option<AudioSource>, Option<AudioOpenError>);

/// Opens the video of an MP4, MOV, M4V or WebM file, and its sound if the
/// file has a sound that the player decodes.
fn open_video(bytes: &Arc<[u8]>, extension: &str) -> Result<VideoOpened, String> {
    if extension == "webm" {
        let media = media_demux::webm(bytes)?;
        let track = media.video.ok_or("no video track")?;
        let total = media
            .duration_us
            .map(|us| Duration::from_micros(us.max(0) as u64));
        let has_vorbis = media.vorbis.is_some();
        let has_opus = media.audio.is_some();
        let vorbis = media
            .vorbis
            .and_then(|track| vorbis_source(bytes, track, total));
        let audio = media.audio.and_then(|opus| {
            let first = !opus.packets.is_empty();
            let channels = opus.channels;
            let mut source = AudioSource {
                packets: Packets::List {
                    bytes: Arc::clone(bytes),
                    list: opus.packets,
                    next: 0,
                },
                track_id: 0,
                audio_track: 1,
                decode: opus_decoder(channels).ok()?,
                channels: channels as u16,
                rate: OPUS_RATE,
                pending: Vec::new(),
                at: 0,
                skip: opus.pre_skip * channels,
                total,
                failure: None,
            };
            (first && source.refill()).then_some(source)
        });
        let audio = audio.or(vorbis);
        let mut audio_error = None;
        if audio.is_none() && (has_opus || has_vorbis) {
            cordiale_core::persistence::log_line("webm audio track could not be opened");
            audio_error = Some(AudioOpenError::probe(
                "webm audio track could not be opened".to_string(),
            ));
        }
        return Ok((
            VideoPlayer::new(Arc::clone(bytes), track)?,
            audio,
            audio_error,
        ));
    }
    let track = media_demux::mp4_video(bytes)?;
    let player = VideoPlayer::new(Arc::clone(bytes), track)?;
    // A file without a sound that the player decodes plays without sound.
    let (audio, audio_error) = audio_or_log(audio_source(bytes, "mp4"));
    Ok((player, audio, audio_error))
}

/// How many samples the poster frame may decode before it gives up.
const POSTER_MAX_SAMPLES: usize = 240;

/// One still picture of a video, as straight RGBA.
pub struct Poster {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// The first picture that `player` decodes. It never starts the sound or the
/// clock, and it decodes at most [`POSTER_MAX_SAMPLES`] samples.
fn first_picture(mut player: VideoPlayer) -> Result<Poster, String> {
    for _ in 0..POSTER_MAX_SAMPLES {
        if !player.decoded.is_empty() || player.drained {
            break;
        }
        player.decode_next();
    }
    let (_, picture) = player.decoded.pop_front().ok_or("no decodable frame")?;
    let rgba = to_rgba(&picture).ok_or("frame can't be converted")?;
    Ok(Poster {
        width: u32::try_from(picture.width).map_err(|_| "frame too large")?,
        height: u32::try_from(picture.height).map_err(|_| "frame too large")?,
        rgba,
    })
}

/// The first decodable picture of an MP4, MOV, M4V or WebM file, for the
/// upload confirmation. Software decoding only; no sound is opened.
pub fn poster_frame(bytes: &Arc<[u8]>, extension: &str) -> Result<Poster, String> {
    let track = if extension.eq_ignore_ascii_case("webm") {
        media_demux::webm(bytes)?.video.ok_or("no video track")?
    } else {
        media_demux::mp4_video(bytes)?
    };
    let player =
        VideoPlayer::with_preference(Arc::clone(bytes), track, media_hw::Preference::Software)?;
    first_picture(player)
}

/// Whether an audio error is worth a log line: a file without an audio
/// track is normal, any other error means a present track failed.
fn audio_error_is_loggable(err: &AudioOpenError) -> bool {
    err.stage != OpenStage::NoTrack
}

/// The sound of a video, or `None`, and the error of a track that failed to
/// open. A missing audio track stays silent in the log and gives no error; a
/// track that fails to open is logged.
fn audio_or_log(
    result: Result<AudioSource, AudioOpenError>,
) -> (Option<AudioSource>, Option<AudioOpenError>) {
    match result {
        Ok(source) => (Some(source), None),
        Err(err) => {
            if !audio_error_is_loggable(&err) {
                return (None, None);
            }
            cordiale_core::persistence::log_line(&format!(
                "video audio track could not be opened: {}",
                err.describe()
            ));
            (None, Some(err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_current_link_ticket_is_allowed() {
        let tickets = LinkTickets::new();
        let ticket = tickets.take();
        assert!(tickets.allows(ticket, "chat"));
    }

    #[test]
    fn a_link_ticket_is_stale_after_logout_or_close() {
        let tickets = LinkTickets::new();
        let ticket = tickets.take();
        tickets.invalidate();
        assert!(!tickets.allows(ticket, "chat"));
    }

    #[test]
    fn a_newer_link_makes_the_older_ticket_stale() {
        let tickets = LinkTickets::new();
        let first = tickets.take();
        let second = tickets.take();
        assert!(!tickets.allows(first, "chat"));
        assert!(tickets.allows(second, "chat"));
    }

    #[test]
    fn a_link_ticket_is_stale_on_the_sign_in_screen() {
        let tickets = LinkTickets::new();
        let ticket = tickets.take();
        assert!(!tickets.allows(ticket, "connect"));
    }

    #[test]
    fn a_delayed_probe_is_dropped_after_a_newer_open() {
        let tickets = LinkTickets::new();
        // Probe A starts and is still pending when link B opens.
        let a = tickets.take();
        let b = tickets.take();
        // B answers first, then A answers late.
        assert!(tickets.allows(b, "chat"));
        assert!(!tickets.allows(a, "chat"));
    }

    #[test]
    fn the_poster_is_the_first_picture_and_stops_early() {
        let (bytes, track) = long_track(100);
        let player = VideoPlayer::from_decoder(
            bytes,
            track,
            Decoder::Hardware(Box::new(FakeHardware::new(None))),
        );
        let poster = first_picture(player).expect("poster");
        assert_eq!((poster.width, poster.height), (2, 2));
        assert_eq!(poster.rgba.len(), 2 * 2 * 4);
    }

    #[test]
    fn a_poster_decode_is_bounded_when_no_picture_comes() {
        let (bytes, track) = long_track(POSTER_MAX_SAMPLES * 3);
        let player = VideoPlayer::from_decoder(
            bytes,
            track,
            Decoder::Hardware(Box::new(FakeHardware::new(Some(0)))),
        );
        assert!(first_picture(player).is_err());
    }

    #[test]
    fn a_video_without_pictures_has_no_poster() {
        let (bytes, track) = garbage_track(VideoCodec::H264);
        let player = VideoPlayer::new(bytes, track).expect("player");
        assert!(first_picture(player).is_err());
    }

    #[test]
    fn files_that_are_not_video_have_no_poster() {
        let bytes: Arc<[u8]> = Arc::from(vec![0u8; 64]);
        assert!(poster_frame(&bytes, "mp4").is_err());
        assert!(poster_frame(&bytes, "webm").is_err());
    }

    #[test]
    fn a_real_mp4_file_gives_its_h264_picture() {
        let bytes: Arc<[u8]> = Arc::from(crate::media_fixtures::mp4_h264());
        for extension in ["mp4", "MOV", "m4v"] {
            let poster = poster_frame(&bytes, extension).expect("poster");
            assert_eq!(
                (poster.width, poster.height),
                crate::media_fixtures::PICTURE_SIZE
            );
            let row = poster.width as usize * 4;
            assert_eq!(poster.rgba.len(), row * poster.height as usize);
            // The left block is dark and the right block is bright.
            assert!(poster.rgba[0] < 80, "left red {}", poster.rgba[0]);
            assert!(
                poster.rgba[row - 4] > 180,
                "right red {}",
                poster.rgba[row - 4]
            );
            assert!(poster.rgba.chunks(4).all(|pixel| pixel[3] == 255));
        }
    }

    #[test]
    fn a_real_webm_file_gives_its_vp8_picture() {
        let bytes: Arc<[u8]> = Arc::from(crate::media_fixtures::webm_vp8());
        let poster = poster_frame(&bytes, "webm").expect("poster");
        assert_eq!(
            (poster.width, poster.height),
            crate::media_fixtures::PICTURE_SIZE
        );
        assert_eq!(
            poster.rgba.len(),
            (poster.width * poster.height * 4) as usize
        );
        assert!(poster.rgba.chunks(4).all(|pixel| pixel[3] == 255));
    }

    #[test]
    fn a_video_cut_short_has_no_poster() {
        let mp4 = crate::media_fixtures::mp4_h264();
        let webm = crate::media_fixtures::webm_vp8();
        // The mp4 loses its picture data; the webm loses its header tail.
        let cut: Arc<[u8]> = Arc::from(&mp4[..mp4.len() - 200]);
        assert!(poster_frame(&cut, "mp4").is_err());
        let cut: Arc<[u8]> = Arc::from(&webm[..40]);
        assert!(poster_frame(&cut, "webm").is_err());
    }

    #[test]
    fn a_missing_audio_track_is_not_logged() {
        assert!(!audio_error_is_loggable(&AudioOpenError::no_track()));
        assert!(audio_error_is_loggable(&AudioOpenError::probe(
            "bad file".to_string()
        )));
    }

    #[test]
    fn a_failed_audio_track_gives_no_source() {
        let (source, error) = audio_or_log(Err(AudioOpenError::no_track()));
        assert!(source.is_none() && error.is_none());
        let failed = AudioOpenError::first_packet(TrackInfo::default());
        let (source, error) = audio_or_log(Err(failed));
        assert!(source.is_none());
        assert_eq!(error.map(|err| err.reason_key()), Some("decode_failed"));
    }

    fn gray(width: usize, height: usize, luma: u8) -> Planar {
        Planar {
            width,
            height,
            planes: [
                vec![luma; width * height],
                vec![128; width.div_ceil(2) * height.div_ceil(2)],
                vec![128; width.div_ceil(2) * height.div_ceil(2)],
            ],
            strides: [width, width.div_ceil(2), width.div_ceil(2)],
            shift_x: 2,
            shift_y: 2,
            mono: false,
            full_range: false,
            identity: false,
        }
    }

    #[test]
    fn full_range_black_and_white_convert() {
        let mut black = gray(3, 3, 0);
        black.full_range = true;
        assert_eq!(&to_rgba(&black).expect("picture")[..4], &[0, 0, 0, 255]);
        let mut white = gray(3, 3, 255);
        white.full_range = true;
        assert_eq!(
            &to_rgba(&white).expect("picture")[..4],
            &[255, 255, 255, 255]
        );
    }

    #[test]
    fn identity_planes_are_green_blue_and_red() {
        let mut picture = gray(2, 2, 10);
        picture.identity = true;
        picture.planes[1] = vec![20; 1];
        picture.planes[2] = vec![30; 1];
        let rgba = to_rgba(&picture).expect("picture");
        assert_eq!(&rgba[..4], &[30, 10, 20, 255]);
    }

    #[test]
    fn limited_range_black_and_white_convert() {
        let black = to_rgba(&gray(3, 3, 16)).expect("picture");
        assert_eq!(&black[..4], &[0, 0, 0, 255]);
        let white = to_rgba(&gray(3, 3, 235)).expect("picture");
        assert_eq!(&white[..4], &[255, 255, 255, 255]);
        assert_eq!(black.len(), 3 * 3 * 4);
    }

    #[test]
    fn a_short_plane_or_a_huge_picture_is_refused() {
        let mut short = gray(4, 4, 16);
        short.planes[0].truncate(3);
        assert!(to_rgba(&short).is_none());
        assert!(to_rgba(&gray(1, 1, 16)).is_some());
        let huge = Planar {
            width: 5000,
            height: 5000,
            planes: [Vec::new(), Vec::new(), Vec::new()],
            strides: [5000, 2500, 2500],
            shift_x: 2,
            shift_y: 2,
            mono: false,
            full_range: false,
            identity: false,
        };
        assert!(to_rgba(&huge).is_none());
    }

    #[test]
    fn a_single_channel_picture_is_gray() {
        let mut picture = gray(2, 2, 126);
        picture.mono = true;
        picture.planes[1].clear();
        picture.planes[2].clear();
        let rgba = to_rgba(&picture).expect("picture");
        assert_eq!(rgba[0], rgba[1]);
        assert_eq!(rgba[1], rgba[2]);
    }

    #[test]
    fn the_wall_clock_goes_on_from_the_end_of_the_sound() {
        // A running clock continues from the last sound position.
        let mut running = WallClock {
            base: 0.0,
            started: None,
        };
        running.play();
        hand_over(&mut running, 12.5);
        assert!(running.position() >= 12.5);
        assert!(running.started.is_some());
        // A stopped clock stays stopped at that position.
        let mut stopped = WallClock {
            base: 3.0,
            started: None,
        };
        hand_over(&mut stopped, 12.5);
        assert_eq!(stopped.position(), 12.5);
        assert!(stopped.started.is_none());
    }

    #[test]
    fn the_wall_clock_runs_pauses_and_seeks() {
        let mut clock = WallClock {
            base: 0.0,
            started: None,
        };
        assert_eq!(clock.position(), 0.0);
        clock.seek(5.0);
        assert_eq!(clock.position(), 5.0);
        clock.play();
        clock.pause();
        let frozen = clock.position();
        assert!(frozen >= 5.0);
        assert_eq!(clock.position(), frozen);
    }

    #[test]
    fn the_length_of_an_ogg_opus_file_comes_from_its_last_page() {
        let mut page = b"OggS\0\0".to_vec();
        page.extend_from_slice(&96_000u64.to_le_bytes());
        let total = ogg_opus_duration(&page, 0).expect("duration");
        assert_eq!(total, Duration::from_secs(2));
        let mut open_ended = b"OggS\0\0".to_vec();
        open_ended.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(ogg_opus_duration(&open_ended, 0).is_none());
        assert!(ogg_opus_duration(b"nothing", 0).is_none());
    }

    #[test]
    fn files_that_are_not_media_are_refused() {
        let bytes: Arc<[u8]> = Arc::from(b"not media".to_vec());
        assert!(symphonia_source(&bytes, "mp3").is_err());
        assert!(symphonia_source(&bytes, "opus").is_err());
        assert!(open_video(&bytes, "mp4").is_err());
        assert!(open_video(&bytes, "webm").is_err());
    }

    #[test]
    fn a_file_that_cannot_be_read_gives_a_probe_error() {
        let bytes: Arc<[u8]> = Arc::from(b"not media".to_vec());
        let error = symphonia_source(&bytes, "wav").err().expect("an error");
        assert_eq!(error.stage, OpenStage::Probe);
        assert_eq!(error.reason_key(), "probe_failed");
    }

    /// One second of a ramp: 16-bit mono PCM in a WAV container.
    fn wav_second(rate: u32) -> Arc<[u8]> {
        let samples: Vec<i16> = (0..rate).map(|n| ((n % 200) as i16 - 100) * 100).collect();
        let data_len = (samples.len() * 2) as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(36 + data_len).to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&rate.to_le_bytes());
        bytes.extend_from_slice(&(rate * 2).to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&data_len.to_le_bytes());
        for sample in samples {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        Arc::from(bytes)
    }

    #[test]
    fn a_wav_file_is_read_and_decoded() {
        let bytes = wav_second(8_000);
        let source = symphonia_source(&bytes, "wav").expect("a WAV source");
        assert_eq!(source.channels, 1);
        assert_eq!(source.rate, 8_000);
        let total = source.total.expect("a length");
        assert!((total.as_secs_f64() - 1.0).abs() < 0.01);
        let samples: Vec<Sample> = source.collect();
        assert_eq!(samples.len(), 8_000);
        assert!(samples.iter().any(|sample| sample.abs() > 0.1));
    }

    #[test]
    fn an_audio_file_without_an_output_device_fails_with_a_reason() {
        let bytes = wav_second(8_000);
        let result = Session::open(bytes, "wav", 1, 1.0, None);
        assert_eq!(result.err().as_deref(), Some("no audio output"));
    }

    #[test]
    fn buffered_audio_gives_the_same_samples_as_direct_decoding() {
        let bytes = wav_second(8_000);
        let direct: Vec<Sample> = symphonia_source(&bytes, "wav").expect("a source").collect();
        let source = symphonia_source(&bytes, "wav").expect("a source");
        let buffered = BufferedAudio::new(source);
        assert!(buffered.total_duration().is_some());
        let samples: Vec<Sample> = buffered.collect();
        assert_eq!(samples, direct);
    }

    #[test]
    fn buffered_audio_keeps_a_clip_of_one_packet() {
        let bytes = wav_second(200);
        let direct: Vec<Sample> = symphonia_source(&bytes, "wav").expect("a source").collect();
        assert_eq!(direct.len(), 200);
        let source = symphonia_source(&bytes, "wav").expect("a source");
        let samples: Vec<Sample> = BufferedAudio::new(source).collect();
        assert_eq!(samples, direct);
    }

    #[test]
    fn buffered_audio_seeks_and_restarts_after_the_end() {
        let bytes = wav_second(8_000);
        let source = symphonia_source(&bytes, "wav").expect("a source");
        let mut buffered = BufferedAudio::new(source);
        while buffered.next().is_some() {}
        buffered.try_seek(Duration::ZERO).expect("a seek");
        assert_eq!(buffered.by_ref().count(), 8_000);
        buffered
            .try_seek(Duration::from_millis(500))
            .expect("a seek");
        let left = buffered.count();
        assert!(left > 0 && left <= 4_100, "{left} samples left");
    }

    #[test]
    fn seeking_a_wav_file_skips_the_start() {
        let bytes = wav_second(8_000);
        let mut source = symphonia_source(&bytes, "wav").expect("a WAV source");
        source.try_seek(Duration::from_millis(500)).expect("a seek");
        let left = source.count();
        assert!(left > 0 && left <= 4_100, "{left} samples left");
    }

    #[test]
    fn seeking_a_wav_file_to_the_start_keeps_every_sample() {
        let bytes = wav_second(8_000);
        let mut source = symphonia_source(&bytes, "wav").expect("a WAV source");
        for _ in 0..3_000 {
            source.next();
        }
        source.try_seek(Duration::ZERO).expect("a seek");
        assert_eq!(source.count(), 8_000);
    }

    const AAC_STEREO: &[u8] = include_bytes!("../test-data/tone_aac_lc_stereo.m4a");
    const AAC_MONO_8K: &[u8] = include_bytes!("../test-data/tone_aac_lc_mono_8k.m4a");
    const AAC_51: &[u8] = include_bytes!("../test-data/tone_aac_51.m4a");
    const AC3: &[u8] = include_bytes!("../test-data/tone_ac3.mp4");
    /// The stereo file, with an audio specific configuration of explicit SBR.
    const AAC_EXPLICIT_SBR: &[u8] = include_bytes!("../test-data/tone_he_aac_explicit_sbr.m4a");
    /// Object type 5 (SBR), 24000 Hz, 2 channels, extension rate 48000 Hz,
    /// underlying type 2 (AAC-LC), three zero flags, padded to 5 bytes.
    const EXPLICIT_SBR_CONFIG: [u8; 5] = [0x2B, 0x11, 0x88, 0x00, 0x00];
    /// Track 1 is AC-3 (no decoder), track 2 is AAC-LC stereo.
    const TWO_AC3_THEN_AAC: &[u8] = include_bytes!("../test-data/two_audio_ac3_then_aac.mp4");
    /// Track 1 is AAC-LC 5.1 (no decoder), track 2 is AAC-LC stereo.
    const TWO_51_THEN_STEREO: &[u8] = include_bytes!("../test-data/two_audio_51_then_stereo.m4a");
    /// Track 1 is AC-3 and track 2 is AAC-LC 5.1: no decoder plays either.
    const TWO_UNPLAYABLE: &[u8] = include_bytes!("../test-data/two_audio_unplayable.mp4");

    fn bytes_of(data: &'static [u8]) -> Arc<[u8]> {
        Arc::from(data)
    }

    fn peak(samples: &[Sample]) -> f32 {
        samples
            .iter()
            .fold(0.0, |peak: f32, sample| peak.max(sample.abs()))
    }

    /// The error of a file that must not open.
    fn open_error(bytes: &Arc<[u8]>, extension: &str) -> AudioOpenError {
        match audio_source(bytes, extension) {
            Ok(_) => panic!("the file opened"),
            Err(err) => err,
        }
    }

    #[test]
    fn the_main_reader_decodes_an_aac_lc_file() {
        let source = symphonia_source(&bytes_of(AAC_STEREO), "m4a").expect("an AAC source");
        assert_eq!(source.channels, 2);
        assert_eq!(source.rate, 44_100);
        let samples: Vec<Sample> = source.collect();
        assert!(samples.len() >= 80_000, "{} samples", samples.len());
        assert!(peak(&samples) > 0.05, "peak {}", peak(&samples));
    }

    #[test]
    fn the_fallback_reader_decodes_an_aac_lc_file() {
        let bytes = bytes_of(AAC_STEREO);
        let source = symphonia05_source(&bytes).expect("an AAC source");
        assert_eq!(source.channels, 2);
        assert_eq!(source.rate, 44_100);
        let samples: Vec<Sample> = source.collect();
        assert!(peak(&samples) > 0.05, "peak {}", peak(&samples));
        let main: Vec<Sample> = symphonia_source(&bytes, "m4a").expect("a source").collect();
        assert!(samples.len().abs_diff(main.len()) <= 2_048);
    }

    #[test]
    fn both_readers_decode_a_mono_file_of_8_khz() {
        let bytes = bytes_of(AAC_MONO_8K);
        let main = symphonia_source(&bytes, "m4a").expect("an AAC source");
        let fallback = symphonia05_source(&bytes).expect("an AAC source");
        for source in [main, fallback] {
            assert_eq!(source.channels, 1);
            assert_eq!(source.rate, 8_000);
            let samples: Vec<Sample> = source.collect();
            assert!(samples.len() >= 3_000, "{} samples", samples.len());
            assert!(peak(&samples) > 0.05, "peak {}", peak(&samples));
        }
    }

    #[test]
    fn both_readers_seek_in_an_aac_file() {
        let bytes = bytes_of(AAC_STEREO);
        let main = symphonia_source(&bytes, "m4a").expect("an AAC source");
        let fallback = symphonia05_source(&bytes).expect("an AAC source");
        for mut source in [main, fallback] {
            source.try_seek(Duration::from_millis(500)).expect("a seek");
            let samples: Vec<Sample> = source.collect();
            // The file holds a second: about half of its samples are left.
            assert!(
                samples.len() > 36_000 && samples.len() < 56_000,
                "{} samples",
                samples.len()
            );
            assert!(peak(&samples) > 0.05);
        }
    }

    #[test]
    fn a_file_with_six_channels_gives_a_typed_error() {
        let error = open_error(&bytes_of(AAC_51), "m4a");
        assert_eq!(error.reason_key(), "too_many_channels");
        assert_eq!(error.stage, OpenStage::Decoder);
        assert_eq!(error.track.codec.as_deref(), Some("AAC"));
        assert_eq!(error.track.channels, Some(6));
        assert_eq!(error.track.sample_rate, Some(44_100));
        assert_eq!(error.track.profile.as_deref(), Some("AAC-LC"));
        // The fallback reader tried the file and failed too.
        assert!(error.fallback.is_some());
        assert!(error.describe().contains("6 channels"));
    }

    #[test]
    fn a_file_with_ac3_sound_gives_a_typed_error() {
        let error = open_error(&bytes_of(AC3), "mp4");
        assert_eq!(error.reason_key(), "unsupported_codec");
        assert_eq!(error.track.codec.as_deref(), Some("AC-3"));
        assert!(error.describe().contains("AC-3"));
    }

    #[test]
    fn a_file_that_is_not_mp4_gets_no_second_try() {
        let bytes: Arc<[u8]> = Arc::from(b"not media".to_vec());
        let error = open_error(&bytes, "wav");
        assert_eq!(error.reason_key(), "probe_failed");
        assert!(error.fallback.is_none());
    }

    #[test]
    fn only_the_fallback_decoder_takes_explicit_sbr_signalling() {
        // The 0.6 decoder refuses the stream.
        let mut params = AudioCodecParameters::new();
        params
            .for_codec(well_known::CODEC_ID_AAC)
            .with_sample_rate(24_000)
            .with_extra_data(Box::from(EXPLICIT_SBR_CONFIG));
        let refused = symphonia::default::get_codecs()
            .make_audio_decoder(&params, &AudioDecoderOptions::default());
        let Err(err) = refused else {
            panic!("the 0.6 decoder took the stream");
        };
        assert!(err.to_string().contains("too complex"), "{err}");
        // The 0.5 decoder reads past the flag and makes a decoder.
        let mut params = symphonia05::core::codecs::CodecParameters::new();
        params
            .for_codec(symphonia05::core::codecs::CODEC_TYPE_AAC)
            .with_sample_rate(24_000)
            .with_extra_data(Box::from(EXPLICIT_SBR_CONFIG));
        let made = symphonia05::default::get_codecs().make(
            &params,
            &symphonia05::core::codecs::DecoderOptions::default(),
        );
        if let Err(err) = made {
            panic!("the 0.5 decoder refused the stream: {err}");
        }
    }

    #[test]
    fn an_mp4_with_explicit_sbr_signalling_plays_through_the_fallback() {
        let bytes = bytes_of(AAC_EXPLICIT_SBR);
        let error = symphonia_source(&bytes, "m4a")
            .err()
            .expect("the main reader refuses the file");
        assert_eq!(error.reason_key(), "unsupported_profile");
        assert_eq!(error.track.profile.as_deref(), Some("HE-AAC (SBR)"));
        let source = audio_source(&bytes, "m4a").expect("the fallback reader plays the file");
        assert_eq!(source.channels, 2);
        let samples: Vec<Sample> = source.collect();
        assert!(samples.len() >= 80_000, "{} samples", samples.len());
        assert!(peak(&samples) > 0.05, "peak {}", peak(&samples));
    }

    /// Checks a source that plays the stereo tone of the second audio track
    /// of one of the two-track files; `track` is the number it must report.
    fn assert_stereo_tone(source: AudioSource, track: u8) {
        assert_eq!(source.audio_track, track);
        assert_eq!(source.channels, 2);
        assert_eq!(source.rate, 44_100);
        let samples: Vec<Sample> = source.collect();
        assert!(samples.len() >= 10_000, "{} samples", samples.len());
        assert!(peak(&samples) > 0.05, "peak {}", peak(&samples));
    }

    #[test]
    fn the_main_reader_goes_on_to_the_next_audio_track() {
        let ac3 = symphonia_source(&bytes_of(TWO_AC3_THEN_AAC), "mp4").expect("track 2 plays");
        assert_stereo_tone(ac3, 2);
        let six = symphonia_source(&bytes_of(TWO_51_THEN_STEREO), "m4a").expect("track 2 plays");
        assert_stereo_tone(six, 2);
    }

    #[test]
    fn the_combined_reader_goes_on_to_the_next_audio_track() {
        let ac3 = audio_source(&bytes_of(TWO_AC3_THEN_AAC), "mp4").expect("track 2 plays");
        assert_stereo_tone(ac3, 2);
        let six = audio_source(&bytes_of(TWO_51_THEN_STEREO), "m4a").expect("track 2 plays");
        assert_stereo_tone(six, 2);
    }

    #[test]
    fn the_fallback_reader_goes_on_to_the_next_audio_track() {
        for data in [TWO_AC3_THEN_AAC, TWO_51_THEN_STEREO] {
            let source = symphonia05_source(&bytes_of(data)).expect("a track plays");
            // The number depends on the tracks that the 0.5 reader lists.
            assert_eq!(source.channels, 2);
            assert_eq!(source.rate, 44_100);
            let samples: Vec<Sample> = source.collect();
            assert!(peak(&samples) > 0.05, "peak {}", peak(&samples));
        }
    }

    #[test]
    fn a_file_where_no_audio_track_plays_gives_the_error_of_the_first_track() {
        let bytes = bytes_of(TWO_UNPLAYABLE);
        assert!(symphonia05_source(&bytes).is_err());
        let main = symphonia_source(&bytes, "mp4").err().expect("an error");
        assert_eq!(main.tracks, 2);
        let error = open_error(&bytes, "mp4");
        assert_eq!(error.stage, OpenStage::Decoder);
        assert_eq!(error.reason_key(), "unsupported_codec");
        assert_eq!(error.track.codec.as_deref(), Some("AC-3"));
        assert_eq!(error.tracks, 2);
        assert!(error.fallback.is_some());
        let text = error.describe();
        assert!(text.contains("AC-3"), "{text}");
        assert!(text.contains("2 audio tracks tried"), "{text}");
    }

    #[test]
    fn a_file_with_one_audio_track_is_read_as_before() {
        let bytes = bytes_of(AAC_STEREO);
        let source = symphonia_source(&bytes, "m4a").expect("an AAC source");
        assert_eq!(source.audio_track, 1);
        let fallback = symphonia05_source(&bytes).expect("an AAC source");
        assert_eq!(fallback.audio_track, 1);
        let error = open_error(&bytes_of(AAC_51), "m4a");
        assert_eq!(error.tracks, 1);
        assert!(!error.describe().contains("tried"));
        let error = open_error(&bytes_of(AC3), "mp4");
        assert_eq!(error.tracks, 1);
        assert!(!error.describe().contains("tried"));
    }

    #[test]
    fn at_most_eight_audio_tracks_are_tried() {
        let calls = std::cell::Cell::new(0u8);
        let result = first_playable_track(|_| {
            calls.set(calls.get() + 1);
            Err(AudioOpenError::first_packet(TrackInfo::default()).with_tracks(20))
        });
        let error = result.err().expect("an error");
        assert_eq!(calls.get(), 8);
        assert_eq!(error.tracks, 8);
        // A file with one audio track is tried once.
        calls.set(0);
        let result = first_playable_track(|_| {
            calls.set(calls.get() + 1);
            Err(AudioOpenError::first_packet(TrackInfo::default()).with_tracks(1))
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn the_stats_name_the_track_only_after_the_first() {
        let first = symphonia_source(&bytes_of(AAC_STEREO), "m4a").expect("a source");
        assert_eq!(BufferedAudio::new(first).stats().track, 1);
        let second = symphonia_source(&bytes_of(TWO_AC3_THEN_AAC), "mp4").expect("a source");
        let stats = BufferedAudio::new(second).stats();
        assert_eq!(stats.track, 2);
        let line = playback_summary(None, Some(&stats), AUDIO_PLAYING);
        assert!(
            line.contains(" audio_path=main audio_track=2 audio_peak="),
            "{line}"
        );
    }

    fn crc8(data: &[u8]) -> u8 {
        data.iter().fold(0u8, |mut crc, byte| {
            crc ^= byte;
            for _ in 0..8 {
                crc = if crc & 0x80 != 0 {
                    (crc << 1) ^ 0x07
                } else {
                    crc << 1
                };
            }
            crc
        })
    }

    fn crc16(data: &[u8]) -> u16 {
        data.iter().fold(0u16, |mut crc, byte| {
            crc ^= u16::from(*byte) << 8;
            for _ in 0..8 {
                crc = if crc & 0x8000 != 0 {
                    (crc << 1) ^ 0x8005
                } else {
                    crc << 1
                };
            }
            crc
        })
    }

    /// Two frames of 4096 samples: 16-bit mono FLAC at 8 kHz, stored as is.
    fn flac_two_frames() -> Arc<[u8]> {
        let block = 4096u16;
        let frames = 2u64;
        let mut bytes = b"fLaC".to_vec();
        bytes.extend_from_slice(&[0x80, 0, 0, 34]);
        bytes.extend_from_slice(&block.to_be_bytes());
        bytes.extend_from_slice(&block.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        // 20 bits of rate, 3 of channels less 1, 5 of bits less 1, 36 of samples.
        let packed = (8_000u64 << 44) | (15u64 << 36) | (frames * u64::from(block));
        bytes.extend_from_slice(&packed.to_be_bytes());
        bytes.extend_from_slice(&[0; 16]);
        for number in 0..frames {
            let mut frame = vec![0xFF, 0xF8, 0xC0, 0x08, number as u8];
            frame.push(crc8(&frame));
            frame.push(0x02);
            for n in 0..block {
                let sample = ((n % 200) as i16 - 100) * 100;
                frame.extend_from_slice(&sample.to_be_bytes());
            }
            let crc = crc16(&frame);
            frame.extend_from_slice(&crc.to_be_bytes());
            bytes.extend_from_slice(&frame);
        }
        Arc::from(bytes)
    }

    /// Silent MPEG-1 Layer III frames: 44.1 kHz, 128 kbit/s, mono.
    fn mp3_silence(frames: usize) -> Arc<[u8]> {
        let mut bytes = Vec::new();
        for _ in 0..frames {
            let mut frame = vec![0u8; 417];
            frame[..4].copy_from_slice(&[0xFF, 0xFB, 0x90, 0xC0]);
            bytes.extend_from_slice(&frame);
        }
        Arc::from(bytes)
    }

    #[test]
    fn a_flac_file_is_read_and_decoded() {
        let bytes = flac_two_frames();
        let source = symphonia_source(&bytes, "flac").expect("a FLAC source");
        assert_eq!(source.channels, 1);
        assert_eq!(source.rate, 8_000);
        let total = source.total.expect("a length");
        assert!((total.as_secs_f64() - 1.024).abs() < 0.01);
        let samples: Vec<Sample> = source.collect();
        assert_eq!(samples.len(), 8_192);
        assert!(samples.iter().any(|sample| sample.abs() > 0.1));
    }

    #[test]
    fn seeking_a_flac_file_skips_the_start() {
        let bytes = flac_two_frames();
        let mut source = symphonia_source(&bytes, "flac").expect("a FLAC source");
        source.try_seek(Duration::from_millis(700)).expect("a seek");
        let left = source.count();
        assert!(left > 0 && left < 8_192, "{left} samples left");
    }

    #[test]
    fn an_mp3_file_is_read_and_decoded() {
        let bytes = mp3_silence(20);
        let source = symphonia_source(&bytes, "mp3").expect("an MP3 source");
        assert_eq!(source.channels, 1);
        assert_eq!(source.rate, 44_100);
        assert!(source.count() >= 1_152);
    }

    #[test]
    fn times_read_as_minutes_and_hours() {
        assert_eq!(clock_text(0.0), "0:00");
        assert_eq!(clock_text(75.9), "1:15");
        assert_eq!(clock_text(3725.0), "1:02:05");
        assert_eq!(clock_text(-4.0), "0:00");
        assert_eq!(clock_text(f64::NAN), "0:00");
        assert_eq!(clock_label(5.0, 61.0), "0:05 / 1:01");
        assert_eq!(clock_label(5.0, 0.0), "0:05");
    }

    #[test]
    fn length_prefixed_samples_become_annex_b() {
        let sample = [0, 0, 0, 2, 0xAA, 0xBB, 0, 0, 0, 1, 0xCC];
        assert_eq!(
            length_prefixed_to_annex_b(&sample, 4),
            vec![0, 0, 0, 1, 0xAA, 0xBB, 0, 0, 0, 1, 0xCC]
        );
        // Two bytes of length.
        assert_eq!(
            length_prefixed_to_annex_b(&[0, 1, 0xDD, 0, 2, 1, 2], 2),
            vec![0, 0, 0, 1, 0xDD, 0, 0, 0, 1, 1, 2]
        );
        // A length that runs past the data ends the conversion.
        assert_eq!(
            length_prefixed_to_annex_b(&[0, 0, 0, 1, 0xEE, 0, 0, 0, 9, 1], 4),
            vec![0, 0, 0, 1, 0xEE]
        );
        assert!(length_prefixed_to_annex_b(&[], 4).is_empty());
        assert!(length_prefixed_to_annex_b(&[0, 0], 4).is_empty());
    }

    #[test]
    fn pictures_in_decode_order_are_queued_in_time_order() {
        let mut queue = VecDeque::new();
        // An I picture, a P picture, then the B pictures between them.
        for pts in [0, 120_000, 40_000, 80_000, 160_000] {
            queue_sorted(&mut queue, pts, gray(2, 2, 16));
        }
        let times: Vec<i64> = queue.iter().map(|(pts, _)| *pts).collect();
        assert_eq!(times, vec![0, 40_000, 80_000, 120_000, 160_000]);
        // A picture with a time that is already queued goes after it.
        queue_sorted(&mut queue, 40_000, gray(2, 2, 235));
        assert_eq!(queue[1].1.planes[0][0], 16);
        assert_eq!(queue[2].1.planes[0][0], 235);
    }

    #[test]
    fn tight_420_planes_make_a_picture() {
        let picture =
            yuv420_planar(3, 3, vec![16; 9], vec![128; 4], vec![128; 4]).expect("picture");
        assert_eq!(picture.strides, [3, 2, 2]);
        assert!(to_rgba(&picture).is_some());
        // A chroma plane that is too short, and a picture of no size.
        assert!(yuv420_planar(3, 3, vec![16; 9], vec![128; 3], vec![128; 4]).is_none());
        assert!(yuv420_planar(0, 3, Vec::new(), Vec::new(), Vec::new()).is_none());
    }

    #[test]
    fn every_built_in_video_codec_has_a_decoder() {
        for codec in [
            VideoCodec::H264,
            VideoCodec::Hevc,
            VideoCodec::Vp8,
            VideoCodec::Vp9,
            VideoCodec::Av1,
        ] {
            let (_, track) = garbage_track(codec);
            assert!(new_decoder(&track).is_ok(), "{codec:?}");
        }
        let (_, track) = garbage_track(VideoCodec::Other);
        assert!(new_decoder(&track).is_err());
    }

    /// A file of three samples that are not video, and a track that names
    /// `codec` for them.
    fn garbage_track(codec: VideoCodec) -> (Arc<[u8]>, VideoTrack) {
        let mut sample = vec![0, 0, 0, 12, 0x65];
        sample.extend_from_slice(&[0xFF; 11]);
        let bytes: Arc<[u8]> = Arc::from(sample.repeat(3));
        let samples = (0..3)
            .map(|index| VideoSample {
                offset: index * 16,
                size: 16,
                pts_us: index as i64 * 40_000,
                key: index == 0,
            })
            .collect();
        let track = VideoTrack {
            codec,
            width: 16,
            height: 16,
            parameter_sets: Vec::new(),
            nal_length_size: 4,
            samples,
        };
        (bytes, track)
    }

    #[test]
    fn samples_that_are_not_video_give_no_picture_and_no_panic() {
        for codec in [VideoCodec::H264, VideoCodec::Vp8, VideoCodec::Av1] {
            let (bytes, track) = garbage_track(codec);
            let mut player = VideoPlayer::new(bytes, track).expect("player");
            for _ in 0..5 {
                player.decode_next();
            }
            assert!(player.decoded.is_empty(), "{codec:?}");
            assert!(player.finished(), "{codec:?}");
            // A seek starts over with a new decoder.
            player.seek(0.0);
            assert!(!player.finished());
        }
    }

    /// A hardware decoder that gives one gray picture for each sample, and
    /// fails from the sample number `fail_at` (counted from 0).
    struct FakeHardware {
        calls: usize,
        fail_at: Option<usize>,
        resets: Arc<std::sync::atomic::AtomicUsize>,
        reset_fails: bool,
    }

    impl FakeHardware {
        fn new(fail_at: Option<usize>) -> Self {
            Self {
                calls: 0,
                fail_at,
                resets: Arc::default(),
                reset_fails: false,
            }
        }
    }

    impl HardwareDecode for FakeHardware {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn decode(&mut self, _data: &[u8], pts_us: i64) -> Result<Vec<(i64, Planar)>, String> {
            let call = self.calls;
            self.calls += 1;
            if self.fail_at.is_some_and(|at| call >= at) {
                return Err("no hardware".to_string());
            }
            Ok(vec![(pts_us, gray(2, 2, 16))])
        }

        fn flush(&mut self) -> Result<Vec<(i64, Planar)>, String> {
            Ok(Vec::new())
        }

        fn reset(&mut self) -> Result<(), String> {
            self.resets.fetch_add(1, Ordering::Relaxed);
            if self.reset_fails {
                Err("no reset".to_string())
            } else {
                Ok(())
            }
        }
    }

    /// A track of `count` samples, 40 ms apart, with a key sample every five.
    fn long_track(count: usize) -> (Arc<[u8]>, VideoTrack) {
        let (_, mut track) = garbage_track(VideoCodec::H264);
        let mut sample = vec![0, 0, 0, 12, 0x65];
        sample.extend_from_slice(&[0xFF; 11]);
        let bytes: Arc<[u8]> = Arc::from(sample.repeat(count));
        track.samples = (0..count)
            .map(|index| VideoSample {
                offset: index * 16,
                size: 16,
                pts_us: index as i64 * 40_000,
                key: index % 5 == 0,
            })
            .collect();
        (bytes, track)
    }

    fn hardware_player(count: usize, hardware: FakeHardware) -> VideoPlayer {
        let (bytes, track) = long_track(count);
        VideoPlayer::from_decoder(bytes, track, Decoder::Hardware(Box::new(hardware)))
    }

    #[test]
    fn the_picture_queue_stays_within_its_memory_limit() {
        for (width, height) in [(16, 16), (640, 360), (1920, 1080), (3840, 2160)] {
            let frames = queue_frames(width, height);
            assert!((QUEUE_MIN_FRAMES..=QUEUE_MAX_FRAMES).contains(&frames));
            let bytes = width as usize * height as usize * 3 / 2;
            if frames > QUEUE_MIN_FRAMES {
                assert!(frames * bytes <= QUEUE_BYTES, "{width}x{height}");
            }
        }
        // The largest picture that the player decodes still fits, at the
        // least length of the queue.
        const { assert!(QUEUE_MIN_FRAMES * MAX_PIXELS * 3 / 2 <= QUEUE_BYTES) };
        assert_eq!(queue_frames(16, 16), QUEUE_MAX_FRAMES);
        assert_eq!(queue_frames(3840, 2160), 8);
    }

    #[test]
    fn decoding_stops_when_the_queue_is_full() {
        let mut player = hardware_player(100, FakeHardware::new(None));
        for _ in 0..100 {
            player.fill();
        }
        assert_eq!(player.decoded.len(), player.queue_limit);
        assert_eq!(player.next_sample, player.queue_limit);
        assert!(!player.drained);
        // A picture that is shown makes room for exactly one more.
        assert!(player.due(0.0).is_some());
        player.fill();
        assert_eq!(player.decoded.len(), player.queue_limit);
    }

    #[test]
    fn a_pass_decodes_at_least_one_sample_and_a_bounded_number() {
        let mut player = hardware_player(100, FakeHardware::new(None));
        player.fill();
        assert!(player.next_sample >= 1);
        assert!(player.next_sample <= DECODE_MAX_SAMPLES);
        assert_eq!(player.stats.decoded as usize, player.next_sample);
    }

    #[test]
    fn the_end_of_the_file_drains_the_queue() {
        let mut player = hardware_player(3, FakeHardware::new(None));
        for _ in 0..5 {
            player.fill();
        }
        assert!(player.drained);
        assert_eq!(player.decoded.len(), 3);
        assert!(!player.finished());
        player.due(1.0);
        assert!(player.finished());
    }

    #[test]
    fn late_and_dropped_pictures_are_counted() {
        let mut player = hardware_player(10, FakeHardware::new(None));
        // Three pictures are ready, at 0, 40 and 80 ms.
        for _ in 0..3 {
            player.decode_next();
        }
        // The first picture is on time.
        assert!(player.due(0.0).is_some());
        assert_eq!((player.stats.late, player.stats.dropped), (0, 0));
        // The clock is at 0.2 s: the pictures at 40 and 80 ms were both due,
        // and the newest of them is more than one frame time late.
        assert!(player.due(0.2).is_some());
        assert_eq!(player.stats.dropped, 1);
        assert_eq!(player.stats.late, 1);
        assert_eq!(player.stats.shown, 2);
    }

    #[test]
    fn a_picture_on_time_is_not_late() {
        let mut player = hardware_player(10, FakeHardware::new(None));
        player.fill();
        assert!(player.due(0.0).is_some());
        assert!(player.due(0.041).is_some());
        assert_eq!((player.stats.late, player.stats.dropped), (0, 0));
    }

    #[test]
    fn an_empty_queue_during_play_counts_once_for_each_time() {
        let mut player = hardware_player(100, FakeHardware::new(None));
        player.check_starved(false);
        assert_eq!(player.stats.starved, 0);
        player.fill();
        assert!(player.due(0.0).is_some());
        player.decoded.clear();
        player.check_starved(false);
        player.check_starved(false);
        assert_eq!(player.stats.starved, 1);
        // Paused is not starved.
        player.check_starved(true);
        player.check_starved(false);
        assert_eq!(player.stats.starved, 2);
        player.fill();
        player.check_starved(false);
        player.decoded.clear();
        player.check_starved(false);
        assert_eq!(player.stats.starved, 3);
    }

    #[test]
    fn the_controller_sleeps_until_the_next_picture() {
        let mut player = hardware_player(100, FakeHardware::new(None));
        // The queue has room: decode again at once.
        assert_eq!(player.next_wait(0.0, false), POLL_MIN);
        for _ in 0..100 {
            player.fill();
        }
        // Full: the next picture, at 0 s, is due now.
        assert_eq!(player.next_wait(0.0, false), POLL_MIN);
        player.decoded.pop_front();
        player.decoded.push_back((10_000_000, gray(2, 2, 16)));
        // The first picture is at 40 ms and the clock is at 30 ms.
        let wait = player.next_wait(0.03, false);
        assert!(
            (POLL_MIN..=Duration::from_millis(10)).contains(&wait),
            "{wait:?}"
        );
        // A far picture and a paused player wait the longest time.
        assert_eq!(player.next_wait(-1.0, false), POLL_MAX);
        assert_eq!(player.next_wait(0.0, true), POLL_MAX);
    }

    #[test]
    fn a_failing_hardware_decoder_gives_way_to_software() {
        let mut player = hardware_player(30, FakeHardware::new(Some(7)));
        for _ in 0..7 {
            player.decode_next();
        }
        assert!(matches!(player.decoder, Decoder::Hardware(_)));
        assert_eq!(player.decoded.len(), 7);
        // The eighth sample fails: software starts at the key sample (0) of the
        // earliest queued picture, so no queued picture is lost.
        player.decode_next();
        assert!(matches!(player.decoder, Decoder::H264(_)));
        assert!(player.stats.fell_back);
        assert_eq!(player.stats.decoder, "software");
        assert_eq!(player.next_sample, 0);
        assert!(player.decoded.is_empty());
        // The player goes on with the file.
        for _ in 0..40 {
            player.fill();
        }
        assert!(player.drained);
    }

    #[test]
    fn a_hardware_decoder_that_fails_at_once_gives_way_to_software() {
        let mut player = hardware_player(10, FakeHardware::new(Some(0)));
        player.decode_next();
        assert!(matches!(player.decoder, Decoder::H264(_)));
        assert_eq!(player.next_sample, 0);
        assert!(!player.drained);
    }

    #[test]
    fn a_track_with_no_decoder_at_all_ends_instead_of_stopping() {
        let mut player = hardware_player(10, FakeHardware::new(Some(0)));
        player.track.codec = VideoCodec::Other;
        player.decode_next();
        assert!(player.drained);
        assert!(player.finished());
    }

    #[test]
    fn a_seek_resets_the_hardware_decoder_and_starts_at_a_key_sample() {
        let hardware = FakeHardware::new(None);
        let resets = Arc::clone(&hardware.resets);
        let mut player = hardware_player(30, hardware);
        player.fill();
        assert!(player.due(0.0).is_some());
        player.seek(0.3);
        assert_eq!(resets.load(Ordering::Relaxed), 1);
        assert!(matches!(player.decoder, Decoder::Hardware(_)));
        assert!(player.decoded.is_empty());
        assert!(player.shown.is_none());
        // 0.3 s is sample 7; the key sample before it is 5.
        assert_eq!(player.next_sample, 5);
        assert!(!player.drained);
        // The pictures before the target are skipped without being counted.
        player.fill();
        let dropped = player.stats.dropped;
        assert!(player.due(0.3).is_some());
        assert_eq!(player.stats.dropped, dropped);
    }

    #[test]
    fn a_seek_goes_to_software_when_the_hardware_cannot_reset() {
        let mut hardware = FakeHardware::new(None);
        hardware.reset_fails = true;
        let mut player = hardware_player(30, hardware);
        player.seek(0.3);
        assert!(matches!(player.decoder, Decoder::H264(_)));
        assert!(player.stats.fell_back);
        assert_eq!(player.next_sample, 5);
    }

    #[test]
    fn the_software_preference_plays_without_hardware() {
        let (bytes, track) = garbage_track(VideoCodec::H264);
        let player = VideoPlayer::with_preference(bytes, track, media_hw::Preference::Software)
            .expect("player");
        assert!(matches!(player.decoder, Decoder::H264(_)));
        assert_eq!(player.stats.decoder, "software");
        assert!(!player.stats.fell_back);
    }

    #[test]
    fn a_host_with_no_hardware_decoder_plays_in_software() {
        // The test host may have a decoder or not; either way the file opens.
        let (bytes, track) = garbage_track(VideoCodec::H264);
        let player =
            VideoPlayer::with_preference(bytes, track, media_hw::Preference::Auto).expect("player");
        assert!(matches!(
            player.decoder,
            Decoder::H264(_) | Decoder::Hardware(_)
        ));
    }

    fn audio_with(queue: usize) -> (BufferedAudio, mpsc::SyncSender<AudioMessage>) {
        let (tx, messages) = mpsc::sync_channel(queue);
        let (seeks, _) = mpsc::channel();
        let audio = BufferedAudio {
            messages,
            seeks,
            epoch: 0,
            current: Vec::new(),
            at: 0,
            ended: false,
            fresh: false,
            channels: 1,
            rate: 8_000,
            total: None,
            stats: Arc::new(AudioStats::default()),
        };
        (audio, tx)
    }

    fn chunk(samples: Vec<Sample>) -> AudioMessage {
        AudioMessage::Chunk {
            epoch: 0,
            channels: 1,
            rate: 8_000,
            samples,
        }
    }

    #[test]
    fn a_full_queue_is_no_under_run() {
        let (mut audio, tx) = audio_with(4);
        tx.send(chunk(vec![0.5, 0.25])).expect("send");
        tx.send(chunk(vec![0.125])).expect("send");
        assert_eq!(audio.next(), Some(0.5));
        assert_eq!(audio.next(), Some(0.25));
        assert_eq!(audio.next(), Some(0.125));
        assert_eq!(audio.stats.underruns.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_empty_queue_is_an_under_run_and_the_output_waits_for_the_sound() {
        let (mut audio, tx) = audio_with(4);
        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            tx.send(chunk(vec![0.5])).expect("send");
        });
        // The output waits, and takes the sound when it comes.
        assert_eq!(audio.next(), Some(0.5));
        assert_eq!(audio.stats.underruns.load(Ordering::Relaxed), 1);
        sender.join().expect("sender");
    }

    #[test]
    fn waiting_at_the_start_or_after_a_seek_is_no_under_run() {
        let (mut audio, tx) = audio_with(4);
        audio.fresh = true;
        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            tx.send(chunk(vec![0.5])).expect("send");
        });
        assert_eq!(audio.next(), Some(0.5));
        sender.join().expect("sender");
        assert!(!audio.fresh);
        assert_eq!(audio.stats.underruns.load(Ordering::Relaxed), 0);
        audio.try_seek(Duration::ZERO).expect("a seek");
        assert!(audio.fresh);
    }

    #[test]
    fn a_stopped_worker_ends_the_sound_without_an_under_run() {
        let (mut audio, tx) = audio_with(4);
        drop(tx);
        assert_eq!(audio.next(), None);
        assert_eq!(audio.stats.underruns.load(Ordering::Relaxed), 0);
        // The worker only stops with the source: this is an early end.
        assert_eq!(
            audio.stats.end_reason().as_deref(),
            Some("the decode worker stopped")
        );
    }

    #[test]
    fn the_stats_keep_the_peak_and_count_the_samples() {
        let stats = AudioStats::with_path("main");
        assert_eq!(stats.peak(), 0.0);
        stats.record_samples(&[0.25, -0.75, 0.5]);
        stats.record_samples(&[0.125]);
        stats.record_samples(&[]);
        assert_eq!(stats.peak(), 0.75);
        assert_eq!(stats.samples.load(Ordering::Relaxed), 4);
        stats.record_samples(&[-1.0]);
        assert_eq!(stats.peak(), 1.0);
    }

    #[test]
    fn only_the_first_early_end_is_kept() {
        let stats = AudioStats::default();
        assert_eq!(stats.end_reason(), None);
        stats.record_end("decode error: first");
        stats.record_end("read error: second");
        assert_eq!(stats.end_reason().as_deref(), Some("decode error: first"));
    }

    #[test]
    fn the_stats_name_the_reader_of_the_sound() {
        let bytes = bytes_of(AAC_STEREO);
        let main = symphonia_source(&bytes, "m4a").expect("an AAC source");
        assert_eq!(main.path(), "main");
        assert_eq!(BufferedAudio::new(main).stats().path, "main");
        let fallback = symphonia05_source(&bytes).expect("an AAC source");
        assert_eq!(fallback.path(), "fallback");
        assert_eq!(BufferedAudio::new(fallback).stats().path, "fallback");
    }

    #[test]
    fn the_worker_records_the_samples_that_it_decodes() {
        let source = symphonia_source(&wav_second(8_000), "wav").expect("a source");
        let buffered = BufferedAudio::new(source);
        let stats = buffered.stats();
        let samples = buffered.count();
        assert_eq!(samples, 8_000);
        assert_eq!(stats.samples.load(Ordering::Relaxed), 8_000);
        assert!(stats.peak() > 0.1);
        assert_eq!(stats.end_reason(), None);
    }

    #[test]
    fn the_summary_line_has_every_number() {
        let stats = VideoStats {
            decoder: "VA-API",
            fell_back: false,
            shown: 120,
            late: 3,
            dropped: 1,
            starved: 2,
            decoded: 4,
            decode_total: Duration::from_millis(8),
            decode_max: Duration::from_millis(5),
            convert_max: Duration::from_millis(7),
        };
        let audio = AudioStats::with_path("main");
        audio.underruns.store(6, Ordering::Relaxed);
        audio.record_samples(&[0.25, -0.5, 0.125]);
        let line = playback_summary(Some(&stats), Some(&audio), AUDIO_PLAYING);
        assert_eq!(
            line,
            "media playback: audio=playing decoder=VA-API shown=120 late=3 dropped=1 starved=2 \
             decode_avg=2.0ms decode_max=5.0ms convert_max=7.0ms audio_underruns=6 \
             audio_path=main audio_peak=0.500 audio_samples=3"
        );
        let fallback = VideoStats {
            decoder: "software",
            fell_back: true,
            ..VideoStats::default()
        };
        assert!(playback_summary(Some(&fallback), None, AUDIO_NO_OUTPUT)
            .contains("software (fallback)"));
        assert_eq!(
            playback_summary(
                None,
                Some(&AudioStats::with_path("fallback")),
                AUDIO_PLAYING
            ),
            "media playback: audio=playing audio_underruns=0 audio_path=fallback \
             audio_peak=0.000 audio_samples=0"
        );
        // The number of the audio track shows only after the first track.
        assert_eq!(
            playback_summary(
                None,
                Some(&AudioStats::with_path("main").with_track(1)),
                AUDIO_PLAYING
            ),
            "media playback: audio=playing audio_underruns=0 audio_path=main \
             audio_peak=0.000 audio_samples=0"
        );
        assert_eq!(
            playback_summary(
                None,
                Some(&AudioStats::with_path("fallback").with_track(2)),
                AUDIO_PLAYING
            ),
            "media playback: audio=playing audio_underruns=0 audio_path=fallback \
             audio_track=2 audio_peak=0.000 audio_samples=0"
        );
        // A sound that ended on an error says why, at the end of the line.
        let ended = AudioStats::with_path("main");
        ended.record_end("read error: broken");
        assert_eq!(
            playback_summary(None, Some(&ended), AUDIO_PLAYING),
            "media playback: audio=playing audio_underruns=0 audio_path=main \
             audio_peak=0.000 audio_samples=0 audio_end=read error: broken"
        );
        // A video with a sound and no output, and a video with no sound,
        // read differently in the log.
        assert!(playback_summary(Some(&fallback), None, AUDIO_NO_OUTPUT)
            .starts_with("media playback: audio=no_output decoder="));
        assert!(playback_summary(Some(&fallback), None, AUDIO_NO_TRACK)
            .starts_with("media playback: audio=no_track decoder="));
    }

    #[test]
    fn a_vorbis_track_with_bad_headers_is_not_played() {
        let bytes: Arc<[u8]> = Arc::from(vec![0u8; 8]);
        let track = media_demux::VorbisTrack {
            channels: 2,
            sample_rate: 44_100,
            headers: vec![1, 2, 3],
            packets: vec![(0, 4, 0)],
        };
        assert!(vorbis_source(&bytes, track, None).is_none());
        let empty = media_demux::VorbisTrack {
            channels: 2,
            sample_rate: 44_100,
            headers: Vec::new(),
            packets: Vec::new(),
        };
        assert!(vorbis_source(&bytes, empty, None).is_none());
    }

    #[test]
    fn the_opus_decoder_takes_one_or_two_channels() {
        assert!(opus_decoder(1).is_ok());
        assert!(opus_decoder(2).is_ok());
        assert!(opus_decoder(8).is_ok());
    }
}
