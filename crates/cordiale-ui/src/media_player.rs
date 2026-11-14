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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use opus_decoder::OpusDecoder;
use rodio::{ChannelCount, Sample, SampleRate, Source};
use symphonia::core::codecs::audio::well_known::{CODEC_ID_OPUS, CODEC_ID_VORBIS};
use symphonia::core::codecs::audio::{
    AudioCodecParameters, AudioDecoder as SymphoniaDecoder, AudioDecoderOptions,
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

use crate::media_demux::{self, Sample as VideoSample, VideoCodec, VideoTrack};
use crate::AppWindow;

/// Largest picture the player decodes, in pixels (4K).
const MAX_PIXELS: usize = 3840 * 2160;
/// Decoded pictures kept ahead of the clock.
const QUEUE_FRAMES: usize = 4;
/// Samples handed to the video decoder in one pass of the controller loop.
const DECODE_BUDGET: usize = 3;
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
        let wait = if session.is_some() {
            Duration::from_millis(15)
        } else {
            Duration::from_secs(3600)
        };
        match commands.recv_timeout(wait) {
            Ok(Command::Open {
                bytes,
                extension,
                generation,
            }) => {
                session = None;
                if device.is_none() {
                    match rodio::DeviceSinkBuilder::open_default_sink() {
                        Ok(mut sink) => {
                            sink.log_on_drop(false);
                            device = Some(sink);
                        }
                        Err(err) => {
                            // A video can play without a sound device.
                            cordiale_core::persistence::log_line(&format!(
                                "no audio output: {err}"
                            ));
                        }
                    }
                }
                match Session::open(bytes, &extension, generation, volume, device.as_ref()) {
                    Ok(opened) => {
                        on_event(
                            generation,
                            MediaEvent::Ready {
                                duration: opened.duration,
                                has_video: opened.video.is_some(),
                            },
                        );
                        session = Some(opened);
                    }
                    Err(reason) => on_event(generation, MediaEvent::Failed(reason)),
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
            Ok(Command::Close) => session = None,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if let Some(open) = session.as_mut() {
            open.tick(&on_event);
        }
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

impl Session {
    fn open(
        bytes: Arc<[u8]>,
        extension: &str,
        generation: u64,
        volume: f32,
        device: Option<&rodio::MixerDeviceSink>,
    ) -> Result<Self, String> {
        let (audio_source, video) = if matches!(extension, "mp4" | "mov" | "m4v" | "webm") {
            let (video, audio_source) = open_video(&bytes, extension)?;
            (audio_source, Some(video))
        } else {
            (Some(symphonia_source(&bytes, extension)?), None)
        };
        let mut duration = audio_source
            .as_ref()
            .and_then(|source| source.total_duration())
            .map_or(0.0, |total| total.as_secs_f64());
        if let Some(video) = &video {
            duration = duration.max(video.duration);
        }
        let audio = match (audio_source, device) {
            (Some(source), Some(sink)) => {
                let player = rodio::Player::connect_new(sink.mixer());
                player.set_volume(volume);
                player.append(source);
                Some(player)
            }
            (None, _) if video.is_none() => return Err("no audio track".to_string()),
            (Some(_), None) if video.is_none() => return Err("no audio output".to_string()),
            _ => None,
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
            video,
            clock,
            paused: false,
            ended: false,
            duration,
            last_report: Instant::now(),
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

// ----- the viewer ----

static PLAYER: OnceLock<MediaPlayer> = OnceLock::new();
static CURRENT: AtomicU64 = AtomicU64::new(0);

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
}

struct Pcm {
    data: Vec<u8>,
    ts: Timestamp,
    dur: MediaDuration,
    trim_start: MediaDuration,
    trim_end: MediaDuration,
}

impl Packets {
    fn next(&mut self) -> Option<Pcm> {
        match self {
            Packets::Format { reader, track_id } => loop {
                let packet = reader.next_packet().ok()??;
                if packet.track_id == *track_id {
                    return Some(Pcm {
                        data: packet.data.into_vec(),
                        ts: packet.pts,
                        dur: packet.dur,
                        trim_start: packet.trim_start,
                        trim_end: packet.trim_end,
                    });
                }
            },
            Packets::List { bytes, list, next } => {
                let (offset, size, us) = *list.get(*next)?;
                *next += 1;
                let data = bytes.get(offset..offset.checked_add(size)?)?.to_vec();
                Some(Pcm {
                    data,
                    ts: Timestamp::new(us.max(0)),
                    dur: MediaDuration::ZERO,
                    trim_start: MediaDuration::ZERO,
                    trim_end: MediaDuration::ZERO,
                })
            }
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
        }
    }
}

enum Decode {
    Symphonia(Box<dyn SymphoniaDecoder>),
    Opus {
        decoder: Box<OpusDecoder>,
        scratch: Vec<f32>,
    },
}

/// A decoded audio file as a rodio source.
struct AudioSource {
    packets: Packets,
    track_id: u32,
    decode: Decode,
    channels: u16,
    rate: u32,
    pending: Vec<Sample>,
    at: usize,
    /// Interleaved samples still to drop at the start (Opus pre-skip).
    skip: usize,
    total: Option<Duration>,
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
    /// Decodes the next packet into `pending`; `false` at the end.
    fn refill(&mut self) -> bool {
        loop {
            let Some(packet) = self.packets.next() else {
                return false;
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
                        Err(_) => return false,
                    }
                }
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
        }
        self.pending.clear();
        self.at = 0;
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

/// Reads an audio file, or the sound of an MP4, MOV or M4V file.
fn symphonia_source(bytes: &Arc<[u8]>, extension: &str) -> Result<AudioSource, String> {
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
        .map_err(|_| "unsupported audio".to_string())?;
    let (track_id, params, delay, num_frames) = reader
        .tracks()
        .iter()
        .find_map(|track| match &track.codec_params {
            Some(CodecParameters::Audio(params)) if params.codec != CODEC_ID_NULL_AUDIO => {
                Some((track.id, params.clone(), track.delay, track.num_frames))
            }
            _ => None,
        })
        .ok_or("no audio track")?;
    let mut source = if params.codec == CODEC_ID_OPUS {
        let channels = params
            .channels
            .as_ref()
            .map_or(2, |channels| channels.count());
        let mut source = AudioSource {
            packets: Packets::Format { reader, track_id },
            track_id,
            decode: opus_decoder(channels)?,
            channels: channels.clamp(1, 2) as u16,
            rate: OPUS_RATE,
            pending: Vec::new(),
            at: 0,
            skip: delay.unwrap_or(0) as usize * channels.clamp(1, 2),
            total: None,
        };
        source.total = ogg_opus_duration(bytes, delay.unwrap_or(0));
        source
    } else {
        let decoder = symphonia::default::get_codecs()
            .make_audio_decoder(&params, &AudioDecoderOptions::default())
            .map_err(|_| "unsupported audio".to_string())?;
        let total = match (num_frames, params.sample_rate) {
            (Some(frames), Some(hz)) if hz > 0 => {
                Some(Duration::from_secs_f64(frames as f64 / f64::from(hz)))
            }
            _ => None,
        };
        AudioSource {
            packets: Packets::Format { reader, track_id },
            track_id,
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
        }
    };
    // Decode the first packet: the real channel count and rate come with it.
    if !source.refill() {
        return Err("unsupported audio".to_string());
    }
    Ok(source)
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
        decode: Decode::Symphonia(decoder),
        channels: track.channels.min(usize::from(u16::MAX)) as u16,
        rate: track.sample_rate,
        pending: Vec::new(),
        at: 0,
        skip: 0,
        total,
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
fn yuv420_planar(
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
}

/// The decoded pictures of one file, and the position in its sample list.
struct VideoPlayer {
    bytes: Arc<[u8]>,
    track: VideoTrack,
    decoder: Decoder,
    next_sample: usize,
    drained: bool,
    decoded: VecDeque<(i64, Planar)>,
    shown: Option<i64>,
    duration: f64,
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
fn length_prefixed_to_annex_b(data: &[u8], length_size: usize) -> Vec<u8> {
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
        if track.samples.is_empty() {
            return Err("no video frames".to_string());
        }
        if (track.width as usize).saturating_mul(track.height as usize) > MAX_PIXELS {
            return Err("video too large".to_string());
        }
        let decoder = new_decoder(&track)?;
        let last = track.samples.iter().map(|s| s.pts_us).max().unwrap_or(0);
        let step = last / i64::try_from(track.samples.len()).unwrap_or(1).max(1);
        Ok(Self {
            duration: (last + step) as f64 / 1_000_000.0,
            bytes,
            track,
            decoder,
            next_sample: 0,
            drained: false,
            decoded: VecDeque::new(),
            shown: None,
        })
    }

    fn finished(&self) -> bool {
        self.drained && self.decoded.is_empty()
    }

    /// Decodes a few samples, up to the length of the queue.
    fn fill(&mut self) {
        let mut budget = DECODE_BUDGET;
        while self.decoded.len() < QUEUE_FRAMES && budget > 0 && !self.drained {
            budget -= 1;
            self.decode_next();
        }
    }

    fn decode_next(&mut self) {
        let Some(sample) = self.track.samples.get(self.next_sample).cloned() else {
            self.drained = true;
            match &mut self.decoder {
                Decoder::Hevc(decoder) => decoder.flush(),
                Decoder::Vp9(decoder) => decoder.flush(),
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
            Decoder::H264(_) | Decoder::Vp8(_) | Decoder::Av1(_) => {}
        }
    }

    /// The newest picture that is due at `position`, as an event.
    fn due(&mut self, position: f64) -> Option<MediaEvent> {
        let now = (position * 1_000_000.0) as i64;
        let mut newest = None;
        while self.decoded.front().is_some_and(|(pts, _)| *pts <= now) {
            newest = self.decoded.pop_front();
        }
        let (pts, picture) = newest?;
        if self.shown == Some(pts) {
            return None;
        }
        self.shown = Some(pts);
        let rgba = to_rgba(&picture)?;
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
        if let Ok(decoder) = new_decoder(&self.track) {
            self.decoder = decoder;
        }
        self.next_sample = key;
        self.drained = false;
        self.decoded.clear();
        self.shown = None;
    }
}

/// Opens the video of an MP4, MOV, M4V or WebM file, and its sound if the
/// file has a sound that the player decodes.
fn open_video(
    bytes: &Arc<[u8]>,
    extension: &str,
) -> Result<(VideoPlayer, Option<AudioSource>), String> {
    if extension == "webm" {
        let media = media_demux::webm(bytes)?;
        let track = media.video.ok_or("no video track")?;
        let total = media
            .duration_us
            .map(|us| Duration::from_micros(us.max(0) as u64));
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
                decode: opus_decoder(channels).ok()?,
                channels: channels as u16,
                rate: OPUS_RATE,
                pending: Vec::new(),
                at: 0,
                skip: opus.pre_skip * channels,
                total,
            };
            (first && source.refill()).then_some(source)
        });
        let audio = audio.or(vorbis);
        return Ok((VideoPlayer::new(Arc::clone(bytes), track)?, audio));
    }
    let track = media_demux::mp4_video(bytes)?;
    let player = VideoPlayer::new(Arc::clone(bytes), track)?;
    // A file without a sound that the player decodes plays without sound.
    let audio = symphonia_source(bytes, "mp4").ok();
    Ok((player, audio))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_file_that_cannot_be_opened_gives_the_same_error() {
        let bytes: Arc<[u8]> = Arc::from(b"not media".to_vec());
        let error = symphonia_source(&bytes, "wav").err();
        assert_eq!(error.as_deref(), Some("unsupported audio"));
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
