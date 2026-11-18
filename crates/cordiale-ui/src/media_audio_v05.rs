//! The second reader of MP4 sound: symphonia 0.5.
//!
//! The 0.6 AAC decoder refuses a stream whose configuration names SBR or PS
//! (HE-AAC). The 0.5 decoder reads past that flag and decodes the AAC-LC
//! layer of the stream: the sound has less bandwidth, but it plays. The
//! player tries this reader only after the 0.6 reader failed. Nothing of the
//! 0.5 crates leaves this module except the types defined here.

use std::io::{Cursor, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use symphonia05::core::audio::SampleBuffer;
use symphonia05::core::codecs::{
    CodecParameters, CodecType, Decoder, DecoderOptions, CODEC_TYPE_AAC, CODEC_TYPE_ALAC,
    CODEC_TYPE_DCA, CODEC_TYPE_EAC3, CODEC_TYPE_FLAC, CODEC_TYPE_MP1, CODEC_TYPE_MP2,
    CODEC_TYPE_MP3, CODEC_TYPE_NULL, CODEC_TYPE_OPUS, CODEC_TYPE_VORBIS,
};
use symphonia05::core::errors::Error;
use symphonia05::core::formats::{FormatOptions, FormatReader, Packet, SeekMode, SeekTo};
use symphonia05::core::io::MediaSourceStream;
use symphonia05::core::meta::MetadataOptions;
use symphonia05::core::probe::Hint;
use symphonia05::core::units::{Time, TimeBase};

use crate::media_audio_error::{AudioOpenError, TrackInfo, CODEC_AAC};

/// The packets of one audio track.
pub struct Packets05 {
    reader: Box<dyn FormatReader>,
    track_id: u32,
    time_base: Option<TimeBase>,
}

impl Packets05 {
    /// The data of the next packet of the track; `Ok(None)` at the end of
    /// the stream, and the message of the reader when it fails.
    pub fn next_data(&mut self) -> Result<Option<Vec<u8>>, String> {
        loop {
            let packet = match self.reader.next_packet() {
                Ok(packet) => packet,
                // This reader reports the end of the stream as an error.
                Err(Error::IoError(err)) if err.kind() == ErrorKind::UnexpectedEof => {
                    return Ok(None)
                }
                Err(err) => return Err(err.to_string()),
            };
            if packet.track_id() == self.track_id {
                return Ok(Some(packet.data.into_vec()));
            }
        }
    }

    /// Moves to `seconds`. Returns how many seconds before that time the
    /// next packet starts: the decoded sound of that gap is to be dropped.
    pub fn seek(&mut self, seconds: f64) -> f64 {
        let Ok(seeked) = self.reader.seek(
            SeekMode::Coarse,
            SeekTo::Time {
                time: Time::from(seconds),
                track_id: Some(self.track_id),
            },
        ) else {
            return 0.0;
        };
        let gap = seeked.required_ts.saturating_sub(seeked.actual_ts);
        self.time_base.map_or(0.0, |base| {
            let time = base.calc_time(gap);
            (time.seconds as f64 + time.frac).clamp(0.0, seconds)
        })
    }
}

/// What one call of [`Decoder05::decode`] gave.
pub enum Decoded {
    /// Samples were appended; this is their layout.
    Samples { channels: u16, rate: u32 },
    /// The packet is damaged: go on with the next one.
    Skip,
    /// The decoder cannot go on: the sound ends. The message says why.
    Stop(String),
}

/// The decoder of one audio track.
pub struct Decoder05 {
    decoder: Box<dyn Decoder>,
    track_id: u32,
}

impl Decoder05 {
    /// Decodes one packet and appends its samples, interleaved, to `out`.
    pub fn decode(&mut self, data: &[u8], out: &mut Vec<f32>) -> Decoded {
        // The AAC decoder reads only the data of the packet, not its times.
        let coded = Packet::new_from_slice(self.track_id, 0, 0, data);
        match self.decoder.decode(&coded) {
            Ok(decoded) => {
                let spec = *decoded.spec();
                let mut converted = SampleBuffer::<f32>::new(decoded.capacity() as u64, spec);
                converted.copy_interleaved_ref(decoded);
                out.extend_from_slice(converted.samples());
                Decoded::Samples {
                    channels: spec.channels.count() as u16,
                    rate: spec.rate,
                }
            }
            Err(Error::DecodeError(_)) => Decoded::Skip,
            Err(err) => Decoded::Stop(err.to_string()),
        }
    }

    /// Call after a seek.
    pub fn reset(&mut self) {
        self.decoder.reset();
    }
}

/// An audio track that is ready to give its first packet.
pub struct Opened {
    pub packets: Packets05,
    pub decoder: Decoder05,
    pub track_id: u32,
    /// The layout that the track declares; the first packet gives the real one.
    pub channels: u16,
    pub rate: u32,
    pub total: Option<Duration>,
    pub track: TrackInfo,
    /// How many audio tracks the file has that this reader knows.
    pub tracks: usize,
}

/// The readable name of a codec.
fn codec_name(codec: CodecType) -> String {
    let name = match codec {
        CODEC_TYPE_AAC => CODEC_AAC,
        CODEC_TYPE_ALAC => "ALAC",
        CODEC_TYPE_DCA => "DTS",
        CODEC_TYPE_EAC3 => "E-AC-3",
        CODEC_TYPE_FLAC => "FLAC",
        CODEC_TYPE_MP1 => "MP1",
        CODEC_TYPE_MP2 => "MP2",
        CODEC_TYPE_MP3 => "MP3",
        CODEC_TYPE_OPUS => "Opus",
        CODEC_TYPE_VORBIS => "Vorbis",
        other => return format!("codec {other:?}"),
    };
    name.to_string()
}

fn track_info(params: &CodecParameters) -> TrackInfo {
    TrackInfo::new(
        codec_name(params.codec),
        params.channels.map(|channels| channels.count() as u16),
        params.sample_rate,
        params.extra_data.as_deref(),
    )
}

/// Reads the MP4 file and makes the decoder of its audio track number `nth`,
/// counted from 0 among the tracks that have a codec.
pub fn open(bytes: &Arc<[u8]>, nth: u8) -> Result<Opened, AudioOpenError> {
    let stream =
        MediaSourceStream::new(Box::new(Cursor::new(Arc::clone(bytes))), Default::default());
    let mut hint = Hint::new();
    hint.with_extension("mp4");
    let probed = symphonia05::default::get_probe()
        .format(
            &hint,
            stream,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|err| AudioOpenError::probe(err.to_string()))?;
    let reader = probed.format;
    // A track without a codec is a video, subtitle or unknown track.
    let candidates: Vec<(u32, CodecParameters)> = reader
        .tracks()
        .iter()
        .filter(|track| track.codec_params.codec != CODEC_TYPE_NULL)
        .map(|track| (track.id, track.codec_params.clone()))
        .collect();
    let tracks = candidates.len();
    let (track_id, params) = candidates
        .into_iter()
        .nth(usize::from(nth))
        .ok_or_else(AudioOpenError::no_track)?;
    let track = track_info(&params);
    let decoder = symphonia05::default::get_codecs()
        .make(&params, &DecoderOptions::default())
        .map_err(|err| {
            AudioOpenError::decoder(
                track.clone(),
                matches!(err, Error::Unsupported(_)),
                err.to_string(),
            )
            .with_tracks(tracks)
        })?;
    let time_base = params
        .time_base
        .filter(|base| base.numer > 0 && base.denom > 0);
    let total = params
        .n_frames
        .zip(time_base)
        .map(|(frames, base)| base.calc_time(frames))
        .and_then(|time| Duration::try_from_secs_f64(time.seconds as f64 + time.frac).ok());
    Ok(Opened {
        packets: Packets05 {
            reader,
            track_id,
            time_base,
        },
        decoder: Decoder05 { decoder, track_id },
        track_id,
        channels: params
            .channels
            .map_or(2, |channels| channels.count() as u16),
        rate: params.sample_rate.unwrap_or(44_100),
        total,
        track,
        tracks,
    })
}
