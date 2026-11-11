//! Images that Slint can't load as they are: ICO files, and the frames of
//! animated GIF and APNG files, plus the timer that plays the frames.

use std::cell::RefCell;
use std::io::Cursor;
use std::time::Duration;

use image::{AnimationDecoder, ImageFormat};

use crate::AppWindow;

/// Most frames of an animation, and most bytes of all its frames. A longer
/// or larger animation shows its first frame only.
const MAX_FRAMES: usize = 400;
const MAX_FRAME_BYTES: usize = 256 * 1024 * 1024;
/// Browsers show a frame at least this long; a shorter delay is a mistake
/// in the file (GIF writers often store 0).
const MIN_DELAY: Duration = Duration::from_millis(20);
const DEFAULT_DELAY: Duration = Duration::from_millis(100);

/// One frame of an animation.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
    pub delay: Duration,
}

/// An ICO file as straight RGBA pixels: width, height and the bytes.
pub fn ico(bytes: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let decoded = image::load_from_memory_with_format(bytes, ImageFormat::Ico).ok()?;
    let rgba = decoded.to_rgba8();
    Some((rgba.width(), rgba.height(), rgba.into_raw()))
}

fn collect(frames: image::Frames<'_>) -> Option<Vec<Frame>> {
    let mut out = Vec::new();
    let mut total = 0usize;
    for frame in frames {
        let frame = frame.ok()?;
        let delay = Duration::from(frame.delay());
        let buffer = frame.into_buffer();
        let (width, height) = (buffer.width(), buffer.height());
        total = total.checked_add(buffer.as_raw().len())?;
        if out.len() >= MAX_FRAMES || total > MAX_FRAME_BYTES {
            return None;
        }
        out.push(Frame {
            width,
            height,
            rgba: buffer.into_raw(),
            delay: if delay < MIN_DELAY {
                DEFAULT_DELAY
            } else {
                delay
            },
        });
    }
    Some(out)
}

/// The frames of an animated GIF or APNG file; `None` for a still picture,
/// for another format, or for an animation that is too large.
pub fn animation(bytes: &[u8], extension: &str) -> Option<Vec<Frame>> {
    let frames = match extension {
        "gif" => {
            let decoder = image::codecs::gif::GifDecoder::new(Cursor::new(bytes)).ok()?;
            collect(decoder.into_frames())?
        }
        "png" | "apng" => {
            let decoder = image::codecs::png::PngDecoder::new(Cursor::new(bytes)).ok()?;
            if !decoder.is_apng().ok()? {
                return None;
            }
            collect(decoder.apng().ok()?.into_frames())?
        }
        _ => return None,
    };
    (frames.len() > 1).then_some(frames)
}

struct Running {
    timer: slint::Timer,
    images: Vec<(slint::Image, Duration)>,
    index: usize,
}

thread_local! {
    static RUNNING: RefCell<Option<Running>> = const { RefCell::new(None) };
}

/// Shows the frames in the viewer, one after the other, until [`stop`].
/// Call this on the window's thread.
pub fn start(ui: &slint::Weak<AppWindow>, frames: Vec<Frame>) {
    stop();
    let images: Vec<(slint::Image, Duration)> = frames
        .into_iter()
        .map(|frame| {
            let buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                &frame.rgba,
                frame.width,
                frame.height,
            );
            (slint::Image::from_rgba8(buffer), frame.delay)
        })
        .collect();
    let Some((first, delay)) = images.first().cloned() else {
        return;
    };
    if let Some(window) = ui.upgrade() {
        window.set_media_image(first);
    }
    let timer = slint::Timer::default();
    let weak = ui.clone();
    timer.start(slint::TimerMode::Repeated, delay, move || step(&weak));
    RUNNING.with(|slot| {
        *slot.borrow_mut() = Some(Running {
            timer,
            images,
            index: 0,
        });
    });
}

fn step(ui: &slint::Weak<AppWindow>) {
    RUNNING.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(running) = slot.as_mut() else {
            return;
        };
        running.index = (running.index + 1) % running.images.len();
        let (image, delay) = running.images[running.index].clone();
        if let Some(window) = ui.upgrade() {
            window.set_media_image(image);
        }
        running.timer.set_interval(delay);
    });
}

/// Stops the animation; the viewer keeps the last frame it showed.
pub fn stop() {
    RUNNING.with(|slot| {
        if let Some(running) = slot.borrow_mut().take() {
            running.timer.stop();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 1x1 ICO file with one 32-bit BMP entry.
    fn tiny_ico() -> Vec<u8> {
        let mut file = vec![0, 0, 1, 0, 1, 0];
        // Entry: 1x1, no palette, 1 plane, 32 bits, 48 bytes at offset 22.
        file.extend_from_slice(&[1, 1, 0, 0, 1, 0, 32, 0]);
        file.extend_from_slice(&48u32.to_le_bytes());
        file.extend_from_slice(&22u32.to_le_bytes());
        // BITMAPINFOHEADER: height counts the image and the mask.
        file.extend_from_slice(&40u32.to_le_bytes());
        file.extend_from_slice(&1i32.to_le_bytes());
        file.extend_from_slice(&2i32.to_le_bytes());
        file.extend_from_slice(&[1, 0, 32, 0]);
        file.extend_from_slice(&[0; 24]);
        // One BGRA pixel, then the 4-byte AND mask row.
        file.extend_from_slice(&[0, 0, 255, 255]);
        file.extend_from_slice(&[0; 4]);
        file
    }

    #[test]
    fn an_ico_file_gives_rgba_pixels() {
        let (width, height, rgba) = ico(&tiny_ico()).expect("valid ICO");
        assert_eq!((width, height), (1, 1));
        assert_eq!(rgba, vec![255, 0, 0, 255]);
    }

    #[test]
    fn garbage_is_not_an_icon_or_an_animation() {
        assert!(ico(b"not an icon").is_none());
        assert!(animation(b"not a picture", "gif").is_none());
        assert!(animation(b"not a picture", "png").is_none());
        assert!(animation(b"x", "jpg").is_none());
    }
}
