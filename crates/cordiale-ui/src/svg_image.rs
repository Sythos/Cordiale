//! Safe SVG rendering for the media viewer.
//!
//! The SVG is drawn to a bitmap with resvg. resvg runs no script. The
//! resolver below refuses every `<image>` that points outside the file, so a
//! file can neither read a local path nor load content from the network.
//! Only an image inside a data URL is kept.

use resvg::{tiny_skia, usvg};

/// Longest side of the bitmap, in pixels.
const MAX_SIDE: f32 = 2048.0;
/// A small drawing is enlarged to this side, so it is not blurry on screen.
const MIN_SIDE: f32 = 512.0;

/// A rendered SVG: straight RGBA pixels.
pub struct Rendered {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

fn options() -> usvg::Options<'static> {
    usvg::Options {
        resources_dir: None,
        image_href_resolver: usvg::ImageHrefResolver {
            resolve_data: usvg::ImageHrefResolver::default_data_resolver(),
            resolve_string: Box::new(|_, _| None),
        },
        ..usvg::Options::default()
    }
}

/// Renders `data` to a bitmap, or `None` when the file is not a valid SVG.
pub fn render(data: &[u8]) -> Option<Rendered> {
    let tree = usvg::Tree::from_data(data, &options()).ok()?;
    let size = tree.size();
    let (width, height) = (size.width(), size.height());
    if !(width > 0.0 && height > 0.0) {
        return None;
    }
    let longest = width.max(height);
    let scale = if longest < MIN_SIDE {
        MIN_SIDE / longest
    } else {
        (MAX_SIDE / longest).min(1.0)
    };
    let pixel_width = (width * scale).ceil().max(1.0) as u32;
    let pixel_height = (height * scale).ceil().max(1.0) as u32;
    let mut pixmap = tiny_skia::Pixmap::new(pixel_width, pixel_height)?;
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    let mut rgba = pixmap.take();
    // tiny-skia stores premultiplied alpha; the viewer image is straight.
    for pixel in rgba.as_chunks_mut::<4>().0 {
        let alpha = u16::from(pixel[3]);
        if alpha != 0 && alpha != 255 {
            for channel in &mut pixel[..3] {
                *channel = ((u16::from(*channel) * 255 + alpha / 2) / alpha).min(255) as u8;
            }
        }
    }
    Some(Rendered {
        width: pixel_width,
        height: pixel_height,
        rgba,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_simple_drawing_renders() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="red"/></svg>"#;
        let drawing = render(svg).expect("valid SVG");
        assert!(drawing.width >= 10 && drawing.height >= 10);
        assert_eq!(&drawing.rgba[..4], &[255, 0, 0, 255]);
    }

    #[test]
    fn an_external_image_is_not_loaded() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="10" height="10"><image xlink:href="/etc/hostname" width="10" height="10"/><script>alert(1)</script></svg>"#;
        let drawing = render(svg).expect("valid SVG");
        assert!(drawing
            .rgba
            .as_chunks::<4>()
            .0
            .iter()
            .all(|pixel| pixel[3] == 0));
    }

    #[test]
    fn invalid_data_is_refused() {
        assert!(render(b"not an svg").is_none());
        assert!(render(b"").is_none());
    }
}
