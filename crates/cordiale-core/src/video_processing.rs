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

//! Shrinking a video before it is uploaded ("Shrink videos before sending").
//!
//! The original file is never touched: the video is re-encoded into a
//! temporary MP4 (VP9 video, the audio streams copied) that is deleted when
//! the [`ShrunkVideo`] is dropped. The encoder is FFmpeg, linked through the
//! `video-shrink` feature; without it [`is_available`] is false and
//! [`shrink`] says so instead of falling back to anything else.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

/// The MIME type of what [`shrink`] writes (an allowlisted Grappa type).
pub const SHRUNK_MIME: &str = "video/mp4";

/// Taller videos are scaled down to this height; smaller ones keep theirs.
const MAX_HEIGHT: u32 = 720;

/// Why a video was not shrunk. Nothing is uploaded after any of these: the
/// user asked for a smaller file, not for the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShrinkError {
    /// This build has no video encoder.
    Unavailable,
    /// The user (or a disconnect) stopped it.
    Cancelled,
    /// The encoder or the container refused this file.
    Failed(String),
    /// The result is not smaller than the original.
    NotSmaller,
    /// The result is still over the server's cap for videos.
    OverCap,
}

/// A shrunk video in a temporary folder, removed when this is dropped.
#[derive(Debug)]
pub struct ShrunkVideo {
    dir: PathBuf,
    /// The file to upload.
    pub path: PathBuf,
    /// Its name for the upload (the original's stem plus `-shrunk.mp4`).
    pub filename: String,
    /// Its MIME type, always [`SHRUNK_MIME`].
    pub mime: &'static str,
}

impl Drop for ShrunkVideo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Whether this build can shrink videos at all.
pub fn is_available() -> bool {
    cfg!(feature = "video-shrink")
}

/// The upload name of the shrunk copy of `original`: the stem, then
/// `-shrunk.mp4` (a file without an extension keeps its whole name).
pub fn shrunk_filename(original: &str) -> String {
    let stem = match original.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => original,
    };
    format!("{stem}-shrunk.mp4")
}

/// Whether a shrunk copy of `shrunk` bytes may replace an original of
/// `original` bytes, given the server's cap for videos (`None` when the
/// limits are unknown, which the server then enforces itself).
pub fn check_result(original: u64, shrunk: u64, cap: Option<u64>) -> Result<(), ShrinkError> {
    if shrunk >= original {
        return Err(ShrinkError::NotSmaller);
    }
    if cap.is_some_and(|cap| shrunk > cap) {
        return Err(ShrinkError::OverCap);
    }
    Ok(())
}

/// The size a `width` x `height` video is encoded at: at most
/// [`MAX_HEIGHT`] tall, the aspect ratio kept, both sides even (the
/// encoder's 4:2:0 chroma needs it).
pub fn target_size(width: u32, height: u32) -> (u32, u32) {
    let even = |value: u32| (value & !1).max(2);
    if height <= MAX_HEIGHT || width == 0 {
        return (even(width), even(height));
    }
    let scaled = u64::from(width) * u64::from(MAX_HEIGHT) / u64::from(height);
    (even(u32::try_from(scaled).unwrap_or(width)), MAX_HEIGHT)
}

/// A new, empty folder under the system temp folder.
fn fresh_output_dir() -> std::io::Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join("cordiale-shrink").join(format!(
        "{stamp}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Re-encodes `input` into a temporary MP4. `cancel` is checked between
/// packets; `progress` gets whole percents (0 to 99) as they change. Run it
/// on a blocking thread: it takes as long as the video does.
pub fn shrink(
    input: &Path,
    cancel: &AtomicBool,
    progress: &dyn Fn(u8),
) -> Result<ShrunkVideo, ShrinkError> {
    if !is_available() {
        return Err(ShrinkError::Unavailable);
    }
    let original = input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let filename = shrunk_filename(&original);
    let dir = fresh_output_dir().map_err(|err| ShrinkError::Failed(err.to_string()))?;
    let path = dir.join(&filename);
    // Dropping this on any early return removes the folder and what is in it.
    let video = ShrunkVideo {
        dir,
        path,
        filename,
        mime: SHRUNK_MIME,
    };
    transcode(input, &video.path, cancel, progress)?;
    Ok(video)
}

#[cfg(not(feature = "video-shrink"))]
fn transcode(
    _input: &Path,
    _output: &Path,
    _cancel: &AtomicBool,
    _progress: &dyn Fn(u8),
) -> Result<(), ShrinkError> {
    Err(ShrinkError::Unavailable)
}

#[cfg(feature = "video-shrink")]
fn transcode(
    input: &Path,
    output: &Path,
    cancel: &AtomicBool,
    progress: &dyn Fn(u8),
) -> Result<(), ShrinkError> {
    ffmpeg_backend::transcode(input, output, cancel, progress)
}

/// The FFmpeg side: demux, decode the best video stream, scale it to 4:2:0
/// at most [`MAX_HEIGHT`] tall, encode it with libvpx-vp9 and copy the audio
/// streams as they are.
#[cfg(feature = "video-shrink")]
mod ffmpeg_backend {
    use super::{target_size, ShrinkError};
    use ffmpeg_next::software::scaling;
    use ffmpeg_next::{
        codec, decoder, encoder, format, frame, media, Dictionary, Packet, Rational,
    };
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn fail(err: impl std::fmt::Display) -> ShrinkError {
        ShrinkError::Failed(err.to_string())
    }

    /// The decode, scale and encode chain of the video stream.
    struct VideoJob {
        out_index: usize,
        decoder: decoder::Video,
        scaler: scaling::Context,
        encoder: encoder::Video,
        in_time_base: Rational,
        width: u32,
        height: u32,
        last_pts: Option<i64>,
    }

    impl VideoJob {
        fn new(
            stream: &format::stream::Stream,
            octx: &mut format::context::Output,
            out_index: usize,
        ) -> Result<Self, ShrinkError> {
            let global_header = octx.format().flags().contains(format::Flags::GLOBAL_HEADER);
            let decoder = codec::context::Context::from_parameters(stream.parameters())
                .map_err(fail)?
                .decoder()
                .video()
                .map_err(fail)?;
            let (width, height) = target_size(decoder.width(), decoder.height());
            let scaler = scaling::Context::get(
                decoder.format(),
                decoder.width(),
                decoder.height(),
                format::Pixel::YUV420P,
                width,
                height,
                scaling::Flags::BILINEAR,
            )
            .map_err(fail)?;
            let vp9 = encoder::find_by_name("libvpx-vp9").ok_or(ShrinkError::Unavailable)?;
            let mut ost = octx.add_stream(vp9).map_err(fail)?;
            let mut enc = codec::context::Context::new_with_codec(vp9)
                .encoder()
                .video()
                .map_err(fail)?;
            enc.set_width(width);
            enc.set_height(height);
            enc.set_aspect_ratio(decoder.aspect_ratio());
            enc.set_format(format::Pixel::YUV420P);
            enc.set_frame_rate(decoder.frame_rate());
            enc.set_time_base(stream.time_base());
            if global_header {
                enc.set_flags(codec::Flags::GLOBAL_HEADER);
            }
            let mut options = Dictionary::new();
            // Constant quality with no bitrate target; "good" with a fast
            // cpu-used keeps a phone clip to a few minutes of encoding.
            options.set("crf", "34");
            options.set("b", "0");
            options.set("deadline", "good");
            options.set("cpu-used", "4");
            options.set("row-mt", "1");
            let opened = enc.open_with(options).map_err(fail)?;
            ost.set_parameters(&opened);
            Ok(Self {
                out_index,
                decoder,
                scaler,
                encoder: opened,
                in_time_base: stream.time_base(),
                width,
                height,
                last_pts: None,
            })
        }

        fn send_packet(
            &mut self,
            packet: &Packet,
            octx: &mut format::context::Output,
            out_time_base: Rational,
        ) -> Result<(), ShrinkError> {
            self.decoder.send_packet(packet).map_err(fail)?;
            self.encode_decoded(octx, out_time_base)
        }

        fn finish(
            &mut self,
            octx: &mut format::context::Output,
            out_time_base: Rational,
        ) -> Result<(), ShrinkError> {
            self.decoder.send_eof().map_err(fail)?;
            self.encode_decoded(octx, out_time_base)?;
            self.encoder.send_eof().map_err(fail)?;
            self.write_encoded(octx, out_time_base)
        }

        fn encode_decoded(
            &mut self,
            octx: &mut format::context::Output,
            out_time_base: Rational,
        ) -> Result<(), ShrinkError> {
            let mut decoded = frame::Video::empty();
            while self.decoder.receive_frame(&mut decoded).is_ok() {
                let pts = decoded.timestamp();
                self.last_pts = pts.or(self.last_pts);
                let mut scaled = frame::Video::new(format::Pixel::YUV420P, self.width, self.height);
                self.scaler.run(&decoded, &mut scaled).map_err(fail)?;
                scaled.set_pts(pts);
                self.encoder.send_frame(&scaled).map_err(fail)?;
                self.write_encoded(octx, out_time_base)?;
            }
            Ok(())
        }

        fn write_encoded(
            &mut self,
            octx: &mut format::context::Output,
            out_time_base: Rational,
        ) -> Result<(), ShrinkError> {
            let mut packet = Packet::empty();
            while self.encoder.receive_packet(&mut packet).is_ok() {
                packet.set_stream(self.out_index);
                packet.rescale_ts(self.in_time_base, out_time_base);
                packet.write_interleaved(octx).map_err(fail)?;
            }
            Ok(())
        }

        /// How far the decoded video is, in whole percents of `total`
        /// microseconds (the container's duration).
        fn percent(&self, total: i64) -> Option<u8> {
            if total <= 0 {
                return None;
            }
            let seconds = f64::from(self.in_time_base) * self.last_pts? as f64;
            let percent = (seconds * 1_000_000.0 * 100.0 / total as f64).clamp(0.0, 99.0);
            Some(percent as u8)
        }
    }

    pub(super) fn transcode(
        input: &Path,
        output: &Path,
        cancel: &AtomicBool,
        progress: &dyn Fn(u8),
    ) -> Result<(), ShrinkError> {
        ffmpeg_next::init().map_err(fail)?;
        let mut ictx = format::input(&input).map_err(fail)?;
        let mut octx = format::output_as(&output, "mp4").map_err(fail)?;
        let video_index = ictx
            .streams()
            .best(media::Type::Video)
            .map(|stream| stream.index())
            .ok_or_else(|| ShrinkError::Failed("no video stream".to_string()))?;
        let total = ictx.duration();

        // Input stream index -> output stream index. The video is encoded,
        // the audio is copied, anything else (subtitles, data) is dropped.
        let mut mapping: Vec<Option<usize>> = vec![None; ictx.nb_streams() as usize];
        let mut in_time_bases = vec![Rational(0, 1); ictx.nb_streams() as usize];
        let mut next_out = 0;
        let mut job = None;
        for stream in ictx.streams() {
            let index = stream.index();
            if index == video_index {
                job = Some(VideoJob::new(&stream, &mut octx, next_out)?);
            } else if stream.parameters().medium() == media::Type::Audio {
                let mut ost = octx
                    .add_stream(encoder::find(codec::Id::None))
                    .map_err(fail)?;
                ost.set_parameters(stream.parameters());
            } else {
                continue;
            }
            mapping[index] = Some(next_out);
            in_time_bases[index] = stream.time_base();
            next_out += 1;
        }
        let mut job = job.ok_or_else(|| ShrinkError::Failed("no video stream".to_string()))?;

        octx.write_header().map_err(fail)?;
        // The muxer may change the time bases when it writes the header.
        let out_time_bases: Vec<Rational> = (0..next_out)
            .map(|index| {
                octx.stream(index)
                    .map_or(Rational(1, 1000), |stream| stream.time_base())
            })
            .collect();

        let mut last_percent = None;
        for (stream, mut packet) in ictx.packets() {
            if cancel.load(Ordering::Relaxed) {
                return Err(ShrinkError::Cancelled);
            }
            let index = stream.index();
            let Some(out_index) = mapping[index] else {
                continue;
            };
            let out_time_base = out_time_bases[out_index];
            if index == video_index {
                job.send_packet(&packet, &mut octx, out_time_base)?;
                let percent = job.percent(total);
                if percent != last_percent {
                    last_percent = percent;
                    if let Some(percent) = percent {
                        progress(percent);
                    }
                }
            } else {
                packet.rescale_ts(in_time_bases[index], out_time_base);
                packet.set_position(-1);
                packet.set_stream(out_index);
                packet.write_interleaved(&mut octx).map_err(fail)?;
            }
        }
        if cancel.load(Ordering::Relaxed) {
            return Err(ShrinkError::Cancelled);
        }
        let video_out_time_base = out_time_bases[job.out_index];
        job.finish(&mut octx, video_out_time_base)?;
        octx.write_trailer().map_err(fail)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shrunk_copy_is_named_after_the_original_stem() {
        assert_eq!(shrunk_filename("holiday.MOV"), "holiday-shrunk.mp4");
        assert_eq!(shrunk_filename("a.b.webm"), "a.b-shrunk.mp4");
        assert_eq!(shrunk_filename("clip"), "clip-shrunk.mp4");
        assert_eq!(
            crate::upload::mime_for_filename(&shrunk_filename("x.mov")).map(|found| found.0),
            Some(SHRUNK_MIME)
        );
    }

    #[test]
    fn a_result_must_be_smaller_and_within_the_cap() {
        assert_eq!(check_result(100, 60, Some(80)), Ok(()));
        assert_eq!(check_result(100, 60, None), Ok(()));
        assert_eq!(check_result(100, 100, None), Err(ShrinkError::NotSmaller));
        assert_eq!(
            check_result(100, 150, Some(500)),
            Err(ShrinkError::NotSmaller)
        );
        assert_eq!(check_result(100, 90, Some(80)), Err(ShrinkError::OverCap));
        // An original over the cap can still be brought under it.
        assert_eq!(check_result(1000, 70, Some(80)), Ok(()));
    }

    #[test]
    fn target_size_caps_the_height_and_keeps_sides_even() {
        assert_eq!(target_size(1920, 1080), (1280, 720));
        assert_eq!(target_size(1280, 720), (1280, 720));
        assert_eq!(target_size(641, 481), (640, 480));
        assert_eq!(target_size(1080, 1920), (404, 720));
        assert_eq!(target_size(3840, 2160), (1280, 720));
    }

    #[cfg(not(feature = "video-shrink"))]
    #[test]
    fn without_the_encoder_shrinking_says_so() {
        assert!(!is_available());
        let cancel = AtomicBool::new(false);
        let result = shrink(Path::new("missing.mp4"), &cancel, &|_| {});
        assert_eq!(result.err(), Some(ShrinkError::Unavailable));
    }
}
