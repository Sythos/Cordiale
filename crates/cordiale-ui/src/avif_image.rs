//! AVIF stills for the media viewer, decoded in Rust.
//!
//! `avif-parse` reads the container and gives the AV1 data of the picture
//! and of its alpha channel. `rusty_av1d` decodes the AV1 data. Nothing here
//! uses a codec of the platform or a C library. The file is never run: the
//! parser and the decoder only read it, and the size of the picture is
//! checked before any pixel buffer is made.

use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

use rusty_av1d::{Decoder, PixelLayout, Rav1dError, Settings};
use rusty_av1d::{Picture, PlanarImageComponent};

/// Most pixels that the viewer decodes in one picture.
const MAX_PIXELS: u64 = 50_000_000;
/// Rounds of the decoder loop; it only stops a decoder that does not advance.
const MAX_ROUNDS: usize = 64;

/// A decoded AVIF: straight RGBA pixels.
pub struct Decoded {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// One plane of a decoded picture: the samples as bytes, with the length of
/// a row in bytes. A sample takes two bytes when `wide` is set.
struct View<'a> {
    data: &'a [u8],
    stride: usize,
    wide: bool,
}

impl View<'_> {
    /// The samples of row `y`, `width` of them; `None` when the data is short.
    fn row(&self, y: usize, width: usize) -> Option<&[u8]> {
        let start = y.checked_mul(self.stride)?;
        let length = width.checked_mul(if self.wide { 2 } else { 1 })?;
        self.data.get(start..start.checked_add(length)?)
    }

    fn sample(row: &[u8], x: usize, wide: bool) -> u16 {
        if wide {
            u16::from_le_bytes([row[2 * x], row[2 * x + 1]])
        } else {
            u16::from(row[x])
        }
    }
}

/// How the samples map to colors.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Color {
    bits: u32,
    full_range: bool,
    /// The luma weights of red and blue; green is what is left of 1.
    kr: f32,
    kb: f32,
    /// The three planes already hold green, blue and red (identity matrix).
    identity: bool,
}

impl Color {
    fn new(bits: u32, full_range: bool, matrix: &rusty_av1d::pixel::MatrixCoefficients) -> Self {
        use rusty_av1d::pixel::MatrixCoefficients as Matrix;
        let (kr, kb) = match matrix {
            Matrix::BT470BG | Matrix::ST170M | Matrix::BT470M | Matrix::ST240M => (0.299, 0.114),
            Matrix::BT2020NonConstantLuminance | Matrix::BT2020ConstantLuminance => {
                (0.2627, 0.0593)
            }
            _ => (0.2126, 0.0722),
        };
        Self {
            bits: bits.clamp(8, 16),
            full_range,
            kr,
            kb,
            identity: matches!(matrix, Matrix::Identity),
        }
    }
}

fn to_byte(value: f32) -> u8 {
    (value * 255.0 + 0.5).clamp(0.0, 255.0) as u8
}

/// The luma and chroma of one sample as numbers: luma from 0 to 1, chroma
/// from -0.5 to 0.5.
fn normalize(color: &Color, luma: u16, cb: u16, cr: u16) -> (f32, f32, f32) {
    let shift = color.bits - 8;
    let max = ((1u32 << color.bits) - 1) as f32;
    let middle = (128u32 << shift) as f32;
    if color.full_range {
        (
            f32::from(luma) / max,
            (f32::from(cb) - middle) / max,
            (f32::from(cr) - middle) / max,
        )
    } else {
        let offset = (16u32 << shift) as f32;
        (
            (f32::from(luma) - offset) / (219u32 << shift) as f32,
            (f32::from(cb) - middle) / (224u32 << shift) as f32,
            (f32::from(cr) - middle) / (224u32 << shift) as f32,
        )
    }
}

/// One pixel as red, green and blue bytes.
fn pixel(color: &Color, luma: u16, cb: u16, cr: u16) -> [u8; 3] {
    if color.identity {
        // The planes hold green (first), blue and red, as full-range values.
        let max = ((1u32 << color.bits) - 1) as f32;
        return [
            to_byte(f32::from(cr) / max),
            to_byte(f32::from(luma) / max),
            to_byte(f32::from(cb) / max),
        ];
    }
    let (y, cb, cr) = normalize(color, luma, cb, cr);
    let red = y + 2.0 * (1.0 - color.kr) * cr;
    let blue = y + 2.0 * (1.0 - color.kb) * cb;
    let green = (y - color.kr * red - color.kb * blue) / (1.0 - color.kr - color.kb);
    [to_byte(red), to_byte(green), to_byte(blue)]
}

/// The planes of a picture as RGBA. `chroma` is empty for a gray picture;
/// `shift` is the chroma subsampling across and down.
fn to_rgba(
    color: &Color,
    width: usize,
    height: usize,
    luma: &View,
    chroma: Option<(&View, &View)>,
    shift: (usize, usize),
) -> Option<Vec<u8>> {
    let mut out = vec![255u8; width.checked_mul(height)?.checked_mul(4)?];
    let chroma_width = width.div_ceil(shift.0);
    let middle = 128u16 << (color.bits - 8);
    for y in 0..height {
        let luma_row = luma.row(y, width)?;
        let chroma_rows = match chroma {
            Some((cb, cr)) => Some((
                cb.row(y / shift.1, chroma_width)?,
                cr.row(y / shift.1, chroma_width)?,
                cb.wide,
            )),
            None => None,
        };
        let line = &mut out[y * width * 4..(y + 1) * width * 4];
        for (x, target) in line.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let l = View::sample(luma_row, x, luma.wide);
            let (cb, cr) = match chroma_rows {
                Some((cb_row, cr_row, wide)) => (
                    View::sample(cb_row, x / shift.0, wide),
                    View::sample(cr_row, x / shift.0, wide),
                ),
                None => (middle, middle),
            };
            let rgb = if chroma.is_none() && color.identity {
                // A gray picture has no color planes to be identity.
                pixel(
                    &Color {
                        identity: false,
                        ..*color
                    },
                    l,
                    cb,
                    cr,
                )
            } else {
                pixel(color, l, cb, cr)
            };
            target[..3].copy_from_slice(&rgb);
        }
    }
    Some(out)
}

/// Decodes one still AV1 picture.
fn decode_picture(obus: &[u8]) -> Option<Picture> {
    let mut settings = Settings::new();
    settings.set_n_threads(1);
    settings.set_max_frame_delay(1);
    settings.set_frame_size_limit(u32::try_from(MAX_PIXELS).ok()?);
    let mut decoder = Decoder::with_settings(&settings).ok()?;
    let mut sent = decoder.send_data(Box::from(obus), None, None, None);
    for _ in 0..MAX_ROUNDS {
        match decoder.get_picture() {
            Ok(picture) => return Some(picture),
            Err(Rav1dError::TryAgain) => match sent {
                Err(Rav1dError::TryAgain) => sent = decoder.send_pending_data(),
                Ok(()) => break,
                Err(_) => return None,
            },
            Err(_) => return None,
        }
    }
    None
}

/// Reads the planes of a picture as views, checked against its size.
struct Frame<'a> {
    width: usize,
    height: usize,
    color: Color,
    luma: View<'a>,
    chroma: Option<(View<'a>, View<'a>)>,
    shift: (usize, usize),
}

fn frame(picture: &Picture) -> Option<Frame<'_>> {
    let (width, height) = (picture.width() as usize, picture.height() as usize);
    if width == 0 || height == 0 || (width as u64) * (height as u64) > MAX_PIXELS {
        return None;
    }
    let (shift, mono) = match picture.pixel_layout() {
        PixelLayout::I400 => ((1, 1), true),
        PixelLayout::I420 => ((2, 2), false),
        PixelLayout::I422 => ((2, 1), false),
        PixelLayout::I444 => ((1, 1), false),
    };
    let wide = picture.bit_depth() > 8;
    let bits = picture
        .bits_per_component()
        .map_or(8, |bits| u32::from(bits.0));
    let view = |component| View {
        data: picture.plane(component),
        stride: picture.stride(component) as usize,
        wide,
    };
    let color = Color::new(
        bits,
        matches!(picture.color_range(), rusty_av1d::pixel::YUVRange::Full),
        &picture.matrix_coefficients(),
    );
    Some(Frame {
        width,
        height,
        color,
        luma: view(PlanarImageComponent::Y),
        chroma: (!mono).then(|| (view(PlanarImageComponent::U), view(PlanarImageComponent::V))),
        shift,
    })
}

/// The alpha channel: one byte for each pixel, from the luma plane of the
/// alpha picture, which must have the size of the color picture.
fn alpha_values(picture: &Picture, width: usize, height: usize) -> Option<Vec<u8>> {
    let alpha = frame(picture)?;
    if alpha.width != width || alpha.height != height {
        return None;
    }
    let max = ((1u32 << alpha.color.bits) - 1) as f32;
    let mut out = Vec::with_capacity(width * height);
    for y in 0..height {
        let row = alpha.luma.row(y, width)?;
        for x in 0..width {
            let value = f32::from(View::sample(row, x, alpha.luma.wide));
            let value = if alpha.color.full_range {
                value / max
            } else {
                let shift = alpha.color.bits - 8;
                (value - (16u32 << shift) as f32) / (219u32 << shift) as f32
            };
            out.push(to_byte(value));
        }
    }
    Some(out)
}

fn decode_inner(bytes: &[u8]) -> Option<Decoded> {
    let data = avif_parse::read_avif(&mut Cursor::new(bytes)).ok()?;
    let picture = decode_picture(&data.primary_item)?;
    let main = frame(&picture)?;
    let chroma = main.chroma.as_ref().map(|(cb, cr)| (cb, cr));
    let mut rgba = to_rgba(
        &main.color,
        main.width,
        main.height,
        &main.luma,
        chroma,
        main.shift,
    )?;
    if let Some(item) = &data.alpha_item {
        // A bad alpha channel leaves the picture opaque.
        let alpha_picture = decode_picture(item);
        if let Some(alpha) = alpha_picture
            .as_ref()
            .and_then(|alpha| alpha_values(alpha, main.width, main.height))
        {
            for (pixel, alpha) in rgba.as_chunks_mut::<4>().0.iter_mut().zip(alpha) {
                if data.premultiplied_alpha && alpha != 0 && alpha != 255 {
                    for channel in &mut pixel[..3] {
                        *channel = ((u16::from(*channel) * 255 + u16::from(alpha) / 2)
                            / u16::from(alpha))
                        .min(255) as u8;
                    }
                }
                pixel[3] = alpha;
            }
        }
    }
    Some(Decoded {
        width: u32::try_from(main.width).ok()?,
        height: u32::try_from(main.height).ok()?,
        rgba,
    })
}

/// Decodes an AVIF still, or `None` when the file is not a valid AVIF or the
/// picture is too large. A decoder that fails inside is caught: the viewer
/// then shows the same message as for any other bad image.
pub fn decode(bytes: &[u8]) -> Option<Decoded> {
    catch_unwind(AssertUnwindSafe(|| decode_inner(bytes))).ok()?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn color(full_range: bool) -> Color {
        Color::new(8, full_range, &rusty_av1d::pixel::MatrixCoefficients::BT709)
    }

    #[test]
    fn limited_range_black_and_white_convert() {
        assert_eq!(pixel(&color(false), 16, 128, 128), [0, 0, 0]);
        assert_eq!(pixel(&color(false), 235, 128, 128), [255, 255, 255]);
    }

    #[test]
    fn full_range_black_and_white_convert() {
        assert_eq!(pixel(&color(true), 0, 128, 128), [0, 0, 0]);
        assert_eq!(pixel(&color(true), 255, 128, 128), [255, 255, 255]);
    }

    #[test]
    fn red_chroma_gives_a_red_pixel() {
        let [red, green, blue] = pixel(&color(true), 76, 85, 255);
        assert!(red > 240 && green < 40 && blue < 20, "{red} {green} {blue}");
    }

    #[test]
    fn the_identity_matrix_keeps_the_planes_as_green_blue_red() {
        let identity = Color::new(8, true, &rusty_av1d::pixel::MatrixCoefficients::Identity);
        // Plane order is green, blue, red.
        assert_eq!(pixel(&identity, 10, 20, 30), [30, 10, 20]);
    }

    #[test]
    fn ten_bit_samples_scale_to_the_same_bytes() {
        let ten = Color::new(10, true, &rusty_av1d::pixel::MatrixCoefficients::BT709);
        assert_eq!(pixel(&ten, 1023, 512, 512), [255, 255, 255]);
        assert_eq!(pixel(&ten, 0, 512, 512), [0, 0, 0]);
    }

    #[test]
    fn a_gray_picture_has_equal_channels() {
        let data = vec![0u8, 128, 255, 64];
        let luma = View {
            data: &data,
            stride: 2,
            wide: false,
        };
        let rgba = to_rgba(&color(true), 2, 2, &luma, None, (1, 1)).expect("pixels");
        assert_eq!(rgba.len(), 16);
        assert_eq!(&rgba[..4], &[0, 0, 0, 255]);
        assert_eq!(&rgba[4..8], &[128, 128, 128, 255]);
        assert_eq!(&rgba[8..12], &[255, 255, 255, 255]);
    }

    #[test]
    fn subsampled_chroma_is_shared_by_a_block() {
        let luma_data = vec![128u8; 4];
        let blue = vec![255u8];
        let red = vec![128u8];
        let luma = View {
            data: &luma_data,
            stride: 2,
            wide: false,
        };
        let cb = View {
            data: &blue,
            stride: 1,
            wide: false,
        };
        let cr = View {
            data: &red,
            stride: 1,
            wide: false,
        };
        let rgba = to_rgba(&color(true), 2, 2, &luma, Some((&cb, &cr)), (2, 2)).expect("pixels");
        // All four pixels use the same chroma sample.
        assert_eq!(&rgba[..4], &rgba[4..8]);
        assert_eq!(&rgba[..4], &rgba[12..16]);
        assert!(rgba[2] > rgba[0]);
    }

    #[test]
    fn a_short_plane_is_refused() {
        let data = vec![0u8; 3];
        let luma = View {
            data: &data,
            stride: 2,
            wide: false,
        };
        assert!(to_rgba(&color(true), 2, 2, &luma, None, (1, 1)).is_none());
    }

    #[test]
    fn two_byte_samples_are_read_little_endian() {
        let data = vec![0x00u8, 0x01, 0xFF, 0x03];
        let view = View {
            data: &data,
            stride: 4,
            wide: true,
        };
        let row = view.row(0, 2).expect("row");
        assert_eq!(View::sample(row, 0, true), 256);
        assert_eq!(View::sample(row, 1, true), 1023);
    }

    #[test]
    fn files_that_are_not_avif_are_refused() {
        assert!(decode(b"").is_none());
        assert!(decode(b"not an image").is_none());
        let mut fake = vec![0, 0, 0, 16];
        fake.extend_from_slice(b"ftypavif\0\0\0\0");
        assert!(decode(&fake).is_none());
    }
}
