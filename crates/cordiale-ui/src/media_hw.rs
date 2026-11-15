//! Optional hardware video decoding for the in-app player.
//!
//! The player decodes in Rust by default. With the `hw-decode` feature, the
//! host decoder (VA-API or VDPAU on Linux, D3D11VA or DXVA2 on Windows,
//! VideoToolbox on macOS) is tried first through FFmpeg. Any failure sends
//! the player back to the software decoders: the file keeps playing, with no
//! error shown. A build without the feature has no hardware path at all.
//!
//! The environment variable `CORDIALE_VIDEO_DECODE=software` turns the
//! hardware path off at run time, to compare the two paths on one machine.

use crate::media_demux::{VideoCodec, VideoTrack};
use crate::media_player::{length_prefixed_to_annex_b, Planar};

/// A decoder that runs on the host hardware. It gives pictures with the time
/// of their sample, in the order that the hardware returns them.
pub trait HardwareDecode {
    /// A short name for the log.
    fn name(&self) -> &'static str;
    /// Sends one sample, in the form that [`access_unit`] gives.
    fn decode(&mut self, data: &[u8], pts_us: i64) -> Result<Vec<(i64, Planar)>, String>;
    /// Gives the pictures that the decoder still holds, at the end of the file.
    fn flush(&mut self) -> Result<Vec<(i64, Planar)>, String>;
    /// Drops what the decoder holds, before a seek.
    fn reset(&mut self) -> Result<(), String>;
}

/// Which decoders the player may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preference {
    /// Hardware first, software when the hardware cannot decode the file.
    Auto,
    /// Software only.
    Software,
}

impl Preference {
    /// Reads the value of `CORDIALE_VIDEO_DECODE`; anything unknown is `Auto`.
    pub fn parse(value: Option<&str>) -> Self {
        match value
            .map(|text| text.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("software" | "off" | "0" | "false" | "no") => Self::Software,
            _ => Self::Auto,
        }
    }

    pub fn from_env() -> Self {
        Self::parse(std::env::var("CORDIALE_VIDEO_DECODE").ok().as_deref())
    }
}

/// Codecs that a hardware path can decode. VP8 has no hardware decoder on
/// the supported systems.
pub fn supports(codec: VideoCodec) -> bool {
    matches!(
        codec,
        VideoCodec::H264 | VideoCodec::Hevc | VideoCodec::Vp9 | VideoCodec::Av1
    )
}

/// The bytes of one sample for the hardware decoder. H.264 and HEVC samples
/// become Annex B access units, with the parameter sets in front of each key
/// sample. VP9 and AV1 samples go as they are.
pub fn access_unit(track: &VideoTrack, data: &[u8], key: bool) -> Vec<u8> {
    match track.codec {
        VideoCodec::H264 | VideoCodec::Hevc => {
            let mut out = Vec::new();
            if key {
                for set in &track.parameter_sets {
                    out.extend_from_slice(&[0, 0, 0, 1]);
                    out.extend_from_slice(set);
                }
            }
            out.extend(length_prefixed_to_annex_b(data, track.nal_length_size));
            out
        }
        _ => data.to_vec(),
    }
}

/// The hardware decoder for a track, or `None` when the host has none for
/// it. `None` is not an error: the player uses the software decoder.
pub fn open(track: &VideoTrack, preference: Preference) -> Option<Box<dyn HardwareDecode>> {
    if preference == Preference::Software || !supports(track.codec) {
        return None;
    }
    backend_open(track)
}

#[cfg(not(feature = "hw-decode"))]
fn backend_open(_track: &VideoTrack) -> Option<Box<dyn HardwareDecode>> {
    None
}

#[cfg(feature = "hw-decode")]
fn backend_open(track: &VideoTrack) -> Option<Box<dyn HardwareDecode>> {
    ffmpeg_backend::open(track)
}

/// The FFmpeg side. It uses the C interface only: a device context for the
/// host hardware, a `get_format` callback that takes the hardware pixel
/// format, and a copy of each picture to a frame in main memory.
#[cfg(feature = "hw-decode")]
mod ffmpeg_backend {
    use super::HardwareDecode;
    use crate::media_demux::{VideoCodec, VideoTrack};
    use crate::media_player::{yuv420_planar, Planar};
    use ffmpeg_next::ffi;
    use ffmpeg_next::util::error::EAGAIN;
    use ffmpeg_next::Error as FfmpegError;
    use std::os::raw::{c_int, c_void};
    use std::ptr;

    /// `AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX`: the codec takes a device
    /// context that the caller creates.
    const METHOD_HW_DEVICE_CTX: c_int = 1;

    fn codec_id(codec: VideoCodec) -> Option<ffi::AVCodecID> {
        match codec {
            VideoCodec::H264 => Some(ffi::AVCodecID::AV_CODEC_ID_H264),
            VideoCodec::Hevc => Some(ffi::AVCodecID::AV_CODEC_ID_HEVC),
            VideoCodec::Vp9 => Some(ffi::AVCodecID::AV_CODEC_ID_VP9),
            VideoCodec::Av1 => Some(ffi::AVCodecID::AV_CODEC_ID_AV1),
            VideoCodec::Vp8 | VideoCodec::Other => None,
        }
    }

    /// The device types of this system, best first.
    fn device_kinds() -> &'static [ffi::AVHWDeviceType] {
        if cfg!(windows) {
            &[
                ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_D3D11VA,
                ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_DXVA2,
            ]
        } else if cfg!(target_os = "macos") {
            &[ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VIDEOTOOLBOX]
        } else {
            &[
                ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI,
                ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VDPAU,
            ]
        }
    }

    /// The pixel format that the codec uses with the device type `kind`, from
    /// the hardware configurations of the codec. `None` when the codec has no
    /// configuration for that device type.
    unsafe fn device_pixel_format(
        codec: *const ffi::AVCodec,
        kind: ffi::AVHWDeviceType,
    ) -> Option<ffi::AVPixelFormat> {
        let mut index = 0;
        loop {
            let config = ffi::avcodec_get_hw_config(codec, index);
            if config.is_null() {
                return None;
            }
            if (*config).methods & METHOD_HW_DEVICE_CTX != 0 && (*config).device_type == kind {
                return Some((*config).pix_fmt);
            }
            index += 1;
        }
    }

    /// Takes the pixel format of the open device, which `open_device` keeps
    /// in the `opaque` field of the context. When the decoder does not offer
    /// it, the decoder fails and the player uses the software path.
    unsafe extern "C" fn pick_hw_format(
        context: *mut ffi::AVCodecContext,
        formats: *const ffi::AVPixelFormat,
    ) -> ffi::AVPixelFormat {
        let wanted = (*context).opaque as isize as c_int;
        let mut at = formats;
        while *at != ffi::AVPixelFormat::AV_PIX_FMT_NONE {
            if *at as c_int == wanted {
                return *at;
            }
            at = at.add(1);
        }
        ffi::AVPixelFormat::AV_PIX_FMT_NONE
    }

    /// An open codec context, freed with its device reference.
    struct Context(*mut ffi::AVCodecContext);

    impl Drop for Context {
        fn drop(&mut self) {
            unsafe { ffi::avcodec_free_context(&mut self.0) };
        }
    }

    struct Decoder {
        context: Context,
        /// The frame that the decoder fills.
        frame: *mut ffi::AVFrame,
        /// The copy of a hardware frame in main memory.
        transfer: *mut ffi::AVFrame,
        last_pts: i64,
        name: &'static str,
    }

    impl Drop for Decoder {
        fn drop(&mut self) {
            unsafe {
                ffi::av_frame_free(&mut self.frame);
                ffi::av_frame_free(&mut self.transfer);
            }
        }
    }

    pub(super) fn open(track: &VideoTrack) -> Option<Box<dyn HardwareDecode>> {
        let id = codec_id(track.codec)?;
        unsafe {
            let codec = ffi::avcodec_find_decoder(id);
            if codec.is_null() {
                return None;
            }
            for kind in device_kinds() {
                if let Some(decoder) = open_device(codec, *kind, track) {
                    return Some(Box::new(decoder));
                }
            }
        }
        None
    }

    unsafe fn open_device(
        codec: *const ffi::AVCodec,
        kind: ffi::AVHWDeviceType,
        track: &VideoTrack,
    ) -> Option<Decoder> {
        let pix_fmt = device_pixel_format(codec, kind)?;
        let mut device = ptr::null_mut();
        if ffi::av_hwdevice_ctx_create(&mut device, kind, ptr::null(), ptr::null_mut(), 0) < 0 {
            return None;
        }
        let raw = ffi::avcodec_alloc_context3(codec);
        if raw.is_null() {
            ffi::av_buffer_unref(&mut device);
            return None;
        }
        // The context owns the device reference from here.
        let context = Context(raw);
        (*raw).hw_device_ctx = device;
        (*raw).opaque = pix_fmt as c_int as isize as *mut c_void;
        (*raw).get_format = Some(pick_hw_format);
        (*raw).width = c_int::try_from(track.width).ok()?;
        (*raw).height = c_int::try_from(track.height).ok()?;
        if ffi::avcodec_open2(raw, codec, ptr::null_mut()) < 0 {
            return None;
        }
        let frame = ffi::av_frame_alloc();
        let transfer = ffi::av_frame_alloc();
        let decoder = Decoder {
            context,
            frame,
            transfer,
            last_pts: 0,
            name: kind_name(kind),
        };
        // The drop of `decoder` frees a null frame without harm.
        (!frame.is_null() && !transfer.is_null()).then_some(decoder)
    }

    fn kind_name(kind: ffi::AVHWDeviceType) -> &'static str {
        match kind {
            ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_D3D11VA => "D3D11VA",
            ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_DXVA2 => "DXVA2",
            ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VIDEOTOOLBOX => "VideoToolbox",
            ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VAAPI => "VA-API",
            ffi::AVHWDeviceType::AV_HWDEVICE_TYPE_VDPAU => "VDPAU",
            _ => "hardware",
        }
    }

    /// Copies a picture in NV12 or planar 4:2:0 form, 8 bits, to tight planes.
    unsafe fn picture(frame: &ffi::AVFrame) -> Result<Planar, String> {
        let width = usize::try_from(frame.width).map_err(|_| "bad size")?;
        let height = usize::try_from(frame.height).map_err(|_| "bad size")?;
        let chroma_width = width.div_ceil(2);
        let chroma_height = height.div_ceil(2);
        let rows = |plane: usize, columns: usize, count: usize| -> Result<Vec<&[u8]>, String> {
            let stride = usize::try_from(frame.linesize[plane]).map_err(|_| "bad stride")?;
            let base = frame.data[plane];
            if base.is_null() || stride < columns {
                return Err("bad plane".to_string());
            }
            Ok((0..count)
                .map(|row| std::slice::from_raw_parts(base.add(row * stride), columns))
                .collect())
        };
        let y: Vec<u8> = rows(0, width, height)?.concat();
        let (u, v) = if frame.format == ffi::AVPixelFormat::AV_PIX_FMT_NV12 as c_int {
            let mut u = Vec::with_capacity(chroma_width * chroma_height);
            let mut v = Vec::with_capacity(chroma_width * chroma_height);
            for row in rows(1, chroma_width * 2, chroma_height)? {
                for pair in row.as_chunks::<2>().0 {
                    u.push(pair[0]);
                    v.push(pair[1]);
                }
            }
            (u, v)
        } else if frame.format == ffi::AVPixelFormat::AV_PIX_FMT_YUV420P as c_int {
            (
                rows(1, chroma_width, chroma_height)?.concat(),
                rows(2, chroma_width, chroma_height)?.concat(),
            )
        } else {
            return Err(format!("picture format {}", frame.format));
        };
        let mut picture = yuv420_planar(width, height, y, u, v).ok_or("bad picture")?;
        picture.full_range = frame.color_range == ffi::AVColorRange::AVCOL_RANGE_JPEG;
        Ok(picture)
    }

    impl Decoder {
        /// Takes every picture that the decoder has ready.
        fn receive(&mut self) -> Result<Vec<(i64, Planar)>, String> {
            let mut out = Vec::new();
            unsafe {
                loop {
                    let code = ffi::avcodec_receive_frame(self.context.0, self.frame);
                    if code < 0 {
                        // "Send more data" and "end of file" end the loop.
                        // Any other result is a failure of the decoder.
                        match FfmpegError::from(code) {
                            FfmpegError::Eof => break,
                            FfmpegError::Other { errno } if errno == EAGAIN => break,
                            _ => return Err(format!("hardware decoder failed ({code})")),
                        }
                    }
                    let mut source = self.frame;
                    if !(*self.frame).hw_frames_ctx.is_null() {
                        ffi::av_frame_unref(self.transfer);
                        // The copy has the pixels only: the properties, such
                        // as the colour range, come from the decoded frame.
                        if ffi::av_hwframe_transfer_data(self.transfer, self.frame, 0) < 0
                            || ffi::av_frame_copy_props(self.transfer, self.frame) < 0
                        {
                            ffi::av_frame_unref(self.frame);
                            return Err("hardware picture copy failed".to_string());
                        }
                        source = self.transfer;
                    }
                    let pts = (*self.frame).pts;
                    let pts = if pts == i64::MIN { self.last_pts } else { pts };
                    self.last_pts = pts;
                    let result = picture(&*source);
                    ffi::av_frame_unref(self.frame);
                    out.push((pts, result?));
                }
            }
            Ok(out)
        }
    }

    impl HardwareDecode for Decoder {
        fn name(&self) -> &'static str {
            self.name
        }

        fn decode(&mut self, data: &[u8], pts_us: i64) -> Result<Vec<(i64, Planar)>, String> {
            let size = c_int::try_from(data.len()).map_err(|_| "sample too large")?;
            unsafe {
                let mut packet = ffi::av_packet_alloc();
                if packet.is_null() {
                    return Err("no memory".to_string());
                }
                if ffi::av_new_packet(packet, size) < 0 {
                    ffi::av_packet_free(&mut packet);
                    return Err("no memory".to_string());
                }
                ptr::copy_nonoverlapping(data.as_ptr(), (*packet).data, data.len());
                (*packet).pts = pts_us;
                let sent = ffi::avcodec_send_packet(self.context.0, packet);
                ffi::av_packet_free(&mut packet);
                if sent < 0 {
                    return Err(format!("hardware decoder refused a sample ({sent})"));
                }
            }
            self.receive()
        }

        fn flush(&mut self) -> Result<Vec<(i64, Planar)>, String> {
            unsafe { ffi::avcodec_send_packet(self.context.0, ptr::null()) };
            self.receive()
        }

        fn reset(&mut self) -> Result<(), String> {
            unsafe { ffi::avcodec_flush_buffers(self.context.0) };
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media_demux::Sample;

    fn track(codec: VideoCodec) -> VideoTrack {
        VideoTrack {
            codec,
            width: 16,
            height: 16,
            parameter_sets: vec![vec![0x67, 1], vec![0x68, 2]],
            nal_length_size: 4,
            samples: vec![Sample {
                offset: 0,
                size: 0,
                pts_us: 0,
                key: true,
            }],
        }
    }

    #[test]
    fn the_preference_reads_the_environment_value() {
        assert_eq!(Preference::parse(None), Preference::Auto);
        assert_eq!(Preference::parse(Some("auto")), Preference::Auto);
        assert_eq!(Preference::parse(Some("whatever")), Preference::Auto);
        assert_eq!(Preference::parse(Some("software")), Preference::Software);
        assert_eq!(Preference::parse(Some(" Off ")), Preference::Software);
        assert_eq!(Preference::parse(Some("0")), Preference::Software);
    }

    #[test]
    fn only_codecs_with_a_hardware_path_are_tried() {
        for codec in [
            VideoCodec::H264,
            VideoCodec::Hevc,
            VideoCodec::Vp9,
            VideoCodec::Av1,
        ] {
            assert!(supports(codec), "{codec:?}");
        }
        assert!(!supports(VideoCodec::Vp8));
        assert!(!supports(VideoCodec::Other));
    }

    #[test]
    fn software_preference_never_opens_hardware() {
        assert!(open(&track(VideoCodec::H264), Preference::Software).is_none());
        assert!(open(&track(VideoCodec::Vp8), Preference::Auto).is_none());
    }

    #[cfg(not(feature = "hw-decode"))]
    #[test]
    fn a_build_without_the_feature_has_no_hardware_decoder() {
        assert!(open(&track(VideoCodec::H264), Preference::Auto).is_none());
    }

    #[test]
    fn a_key_sample_gets_its_parameter_sets_in_front() {
        let sample = [0, 0, 0, 2, 0x65, 9];
        let key = access_unit(&track(VideoCodec::H264), &sample, true);
        assert_eq!(
            key,
            vec![0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 2, 0, 0, 0, 1, 0x65, 9]
        );
        let plain = access_unit(&track(VideoCodec::H264), &sample, false);
        assert_eq!(plain, vec![0, 0, 0, 1, 0x65, 9]);
    }

    #[test]
    fn vp9_and_av1_samples_go_unchanged() {
        for codec in [VideoCodec::Vp9, VideoCodec::Av1] {
            assert_eq!(access_unit(&track(codec), &[1, 2, 3], true), vec![1, 2, 3]);
        }
    }
}
