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

//! Image metadata removal before an end-to-end encrypted upload.
//!
//! The server cannot clean ciphertext, so the client cleans the image first.
//! The cleaner copies the pixel data without decoding it and keeps only the
//! chunks that a viewer needs to draw the image. Everything else is dropped:
//! EXIF, GPS, XMP, IPTC, comments, text chunks and unknown chunks.
//!
//! The only EXIF value that stays is the JPEG orientation, written in a new
//! minimal EXIF block. Without it a rotated photo would show on its side.
//!
//! Any file that the cleaner cannot read as the type it claims is refused:
//! the caller must not upload the original instead.

use std::fmt;

/// Why an image was not cleaned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripError {
    /// The cleaner has no rule for this MIME type.
    Unsupported,
    /// The bytes are not a well-formed image of the claimed type.
    Malformed,
}

impl fmt::Display for StripError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("no metadata rule for this image type"),
            Self::Malformed => f.write_str("the image is not well formed"),
        }
    }
}

impl std::error::Error for StripError {}

/// Returns a copy of `bytes` without metadata. `mime` is the type of the file.
pub fn strip_image_metadata(mime: &str, bytes: &[u8]) -> Result<Vec<u8>, StripError> {
    match mime {
        "image/jpeg" => strip_jpeg(bytes),
        "image/png" | "image/apng" => strip_png(bytes),
        "image/gif" => strip_gif(bytes),
        "image/webp" => strip_webp(bytes),
        _ => Err(StripError::Unsupported),
    }
}

// ---------------------------------------------------------------- JPEG

/// Orientation tag of the TIFF header inside an EXIF block.
const EXIF_ORIENTATION_TAG: u16 = 0x0112;

fn strip_jpeg(bytes: &[u8]) -> Result<Vec<u8>, StripError> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return Err(StripError::Malformed);
    }
    let mut out = vec![0xFF, 0xD8];
    let mut orientation = None;
    let mut pos = 2;
    loop {
        // Fill bytes before a marker are allowed.
        while bytes.get(pos) == Some(&0xFF) && bytes.get(pos + 1) == Some(&0xFF) {
            pos += 1;
        }
        let (Some(&0xFF), Some(&marker)) = (bytes.get(pos), bytes.get(pos + 1)) else {
            return Err(StripError::Malformed);
        };
        match marker {
            // Start of scan: the entropy-coded data runs to the end of the
            // file and is copied as it is.
            0xDA => {
                insert_orientation(&mut out, orientation);
                out.extend_from_slice(&bytes[pos..]);
                return Ok(out);
            }
            // Markers without a length field.
            0x01 | 0xD0..=0xD7 => {
                out.extend_from_slice(&bytes[pos..pos + 2]);
                pos += 2;
            }
            // End of image before any scan: not a picture.
            0xD9 | 0xD8 => return Err(StripError::Malformed),
            _ => {
                let len = segment_length(bytes, pos + 2)?;
                let end = pos + 2 + len;
                let segment = &bytes[pos..end];
                let data = &segment[4..];
                match marker {
                    0xE1 => {
                        if let Some(value) = exif_orientation(data) {
                            orientation = Some(value);
                        }
                    }
                    // JFIF, the ICC colour profile and the Adobe colour
                    // transform change how the pixels are drawn.
                    0xE0 | 0xEE => out.extend_from_slice(segment),
                    0xE2 if data.starts_with(b"ICC_PROFILE\0") => out.extend_from_slice(segment),
                    // Any other application segment and every comment.
                    0xE2..=0xEF | 0xFE => {}
                    _ => out.extend_from_slice(segment),
                }
                pos = end;
            }
        }
    }
}

/// The length of the segment whose length field starts at `at`, with the
/// field itself. The segment must fit in `bytes` after the marker.
fn segment_length(bytes: &[u8], at: usize) -> Result<usize, StripError> {
    let field = bytes.get(at..at + 2).ok_or(StripError::Malformed)?;
    let len = usize::from(u16::from_be_bytes([field[0], field[1]]));
    if len < 2 || at + len > bytes.len() {
        return Err(StripError::Malformed);
    }
    Ok(len)
}

/// The orientation (1 to 8) in the data of an APP1 segment, if it has one.
fn exif_orientation(data: &[u8]) -> Option<u16> {
    let tiff = data.strip_prefix(b"Exif\0\0")?;
    let little = match tiff.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let read16 = |at: usize| -> Option<u16> {
        let raw: [u8; 2] = tiff.get(at..at + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    };
    let read32 = |at: usize| -> Option<u32> {
        let raw: [u8; 4] = tiff.get(at..at + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    };
    if read16(2)? != 42 {
        return None;
    }
    let ifd = usize::try_from(read32(4)?).ok()?;
    let count = usize::from(read16(ifd)?);
    for index in 0..count {
        let entry = ifd.checked_add(2)?.checked_add(index.checked_mul(12)?)?;
        if read16(entry)? == EXIF_ORIENTATION_TAG {
            let value = read16(entry + 8)?;
            return (2..=8).contains(&value).then_some(value);
        }
    }
    None
}

/// Writes a minimal big-endian EXIF block that holds only `orientation`. An
/// absent or default orientation writes nothing.
fn insert_orientation(out: &mut Vec<u8>, orientation: Option<u16>) {
    let Some(value) = orientation else {
        return;
    };
    let mut data = Vec::new();
    data.extend_from_slice(b"Exif\0\0MM\0\x2A\0\0\0\x08");
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&EXIF_ORIENTATION_TAG.to_be_bytes());
    data.extend_from_slice(&3u16.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&value.to_be_bytes());
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(&0u32.to_be_bytes());
    let len = u16::try_from(data.len() + 2).unwrap_or(u16::MAX);
    out.extend_from_slice(&[0xFF, 0xE1]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&data);
}

// ----------------------------------------------------------------- PNG

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// The chunks that a decoder needs to draw a still or animated image.
const PNG_KEPT: [&[u8; 4]; 13] = [
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT",
    b"acTL", b"fcTL", b"fdAT",
];

fn strip_png(bytes: &[u8]) -> Result<Vec<u8>, StripError> {
    if !bytes.starts_with(&PNG_SIGNATURE) {
        return Err(StripError::Malformed);
    }
    let mut out = PNG_SIGNATURE.to_vec();
    let mut pos = PNG_SIGNATURE.len();
    let mut first = true;
    loop {
        let header = bytes.get(pos..pos + 8).ok_or(StripError::Malformed)?;
        let len = usize::try_from(u32::from_be_bytes([
            header[0], header[1], header[2], header[3],
        ]))
        .map_err(|_| StripError::Malformed)?;
        let kind: [u8; 4] = [header[4], header[5], header[6], header[7]];
        let end = pos
            .checked_add(12)
            .and_then(|n| n.checked_add(len))
            .filter(|end| *end <= bytes.len())
            .ok_or(StripError::Malformed)?;
        if first && &kind != b"IHDR" {
            return Err(StripError::Malformed);
        }
        first = false;
        if PNG_KEPT.iter().any(|kept| **kept == kind) {
            out.extend_from_slice(&bytes[pos..end]);
        }
        pos = end;
        if &kind == b"IEND" {
            // Anything after the end chunk is dropped.
            return Ok(out);
        }
    }
}

// ----------------------------------------------------------------- GIF

fn strip_gif(bytes: &[u8]) -> Result<Vec<u8>, StripError> {
    if bytes.len() < 13 || !(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return Err(StripError::Malformed);
    }
    let mut pos = 13 + color_table_len(bytes[10]);
    if pos > bytes.len() {
        return Err(StripError::Malformed);
    }
    let mut out = bytes[..pos].to_vec();
    loop {
        match *bytes.get(pos).ok_or(StripError::Malformed)? {
            0x3B => {
                out.push(0x3B);
                return Ok(out);
            }
            0x2C => {
                let descriptor = bytes.get(pos..pos + 10).ok_or(StripError::Malformed)?;
                let table = color_table_len(descriptor[9]);
                // The descriptor, the local table and the minimum code size.
                let data_start = pos + 10 + table + 1;
                let end = skip_sub_blocks(bytes, data_start)?;
                out.extend_from_slice(&bytes[pos..end]);
                pos = end;
            }
            0x21 => {
                let label = *bytes.get(pos + 1).ok_or(StripError::Malformed)?;
                let end = skip_sub_blocks(bytes, pos + 2)?;
                let keep = match label {
                    // Graphic control: delay and transparency.
                    0xF9 => true,
                    // Application block: only the loop count of an animation.
                    0xFF => {
                        let block = &bytes[pos + 2..end];
                        block.len() > 12
                            && block[0] == 11
                            && (&block[1..12] == b"NETSCAPE2.0" || &block[1..12] == b"ANIMEXTS1.0")
                    }
                    // Comment, plain text and any unknown extension.
                    _ => false,
                };
                if keep {
                    out.extend_from_slice(&bytes[pos..end]);
                }
                pos = end;
            }
            _ => return Err(StripError::Malformed),
        }
    }
}

/// The byte length of a colour table from the packed field.
fn color_table_len(packed: u8) -> usize {
    if packed & 0x80 == 0 {
        0
    } else {
        3 * (1usize << (usize::from(packed & 0x07) + 1))
    }
}

/// The index after the sub-blocks that start at `pos`, terminator included.
fn skip_sub_blocks(bytes: &[u8], mut pos: usize) -> Result<usize, StripError> {
    loop {
        let size = usize::from(*bytes.get(pos).ok_or(StripError::Malformed)?);
        pos += 1;
        if size == 0 {
            return Ok(pos);
        }
        pos = pos
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or(StripError::Malformed)?;
    }
}

// ---------------------------------------------------------------- WebP

/// The EXIF and XMP flags of the `VP8X` header.
const WEBP_METADATA_FLAGS: u8 = 0b0000_1100;

fn strip_webp(bytes: &[u8]) -> Result<Vec<u8>, StripError> {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return Err(StripError::Malformed);
    }
    let declared = usize::try_from(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
        .map_err(|_| StripError::Malformed)?;
    let total = declared.checked_add(8).ok_or(StripError::Malformed)?;
    if total > bytes.len() || total < 12 {
        return Err(StripError::Malformed);
    }
    let mut body = b"WEBP".to_vec();
    let mut pos = 12;
    while pos < total {
        let header = bytes.get(pos..pos + 8).ok_or(StripError::Malformed)?;
        let len = usize::try_from(u32::from_le_bytes([
            header[4], header[5], header[6], header[7],
        ]))
        .map_err(|_| StripError::Malformed)?;
        let padded = len + (len & 1);
        let end = pos
            .checked_add(8)
            .and_then(|n| n.checked_add(padded))
            .filter(|end| *end <= total)
            .ok_or(StripError::Malformed)?;
        match &header[..4] {
            b"EXIF" | b"XMP " => {}
            b"VP8X" => {
                if len < 10 {
                    return Err(StripError::Malformed);
                }
                let mut chunk = bytes[pos..end].to_vec();
                chunk[8] &= !WEBP_METADATA_FLAGS;
                body.extend_from_slice(&chunk);
            }
            _ => body.extend_from_slice(&bytes[pos..end]),
        }
        pos = end;
    }
    let size = u32::try_from(body.len()).map_err(|_| StripError::Malformed)?;
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg_segment(marker: u8, data: &[u8]) -> Vec<u8> {
        let mut segment = vec![0xFF, marker];
        segment.extend_from_slice(&u16::try_from(data.len() + 2).unwrap().to_be_bytes());
        segment.extend_from_slice(data);
        segment
    }

    /// A tiny JPEG: JFIF, an EXIF block with GPS text and orientation, a
    /// comment, an XMP block, then the scan.
    fn sample_jpeg(orientation: u16) -> Vec<u8> {
        let mut exif = b"Exif\0\0MM\0\x2A\0\0\0\x08".to_vec();
        exif.extend_from_slice(&1u16.to_be_bytes());
        exif.extend_from_slice(&EXIF_ORIENTATION_TAG.to_be_bytes());
        exif.extend_from_slice(&3u16.to_be_bytes());
        exif.extend_from_slice(&1u32.to_be_bytes());
        exif.extend_from_slice(&orientation.to_be_bytes());
        exif.extend_from_slice(&[0, 0]);
        exif.extend_from_slice(&0u32.to_be_bytes());
        exif.extend_from_slice(b"GPS-SECRET-PLACE");
        let mut file = vec![0xFF, 0xD8];
        file.extend(jpeg_segment(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"));
        file.extend(jpeg_segment(0xE1, &exif));
        file.extend(jpeg_segment(
            0xE1,
            b"http://ns.adobe.com/xap/1.0/\0owner-name",
        ));
        file.extend(jpeg_segment(0xFE, b"camera-serial-1234"));
        file.extend(jpeg_segment(0xDB, &[0; 65]));
        file.extend(jpeg_segment(0xDA, &[1, 1, 0, 0, 63, 0]));
        file.extend_from_slice(&[0x12, 0x34, 0xFF, 0xD9]);
        file
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn jpeg_loses_gps_comment_and_xmp() {
        let clean = strip_image_metadata("image/jpeg", &sample_jpeg(1)).expect("clean");
        for secret in [
            &b"GPS-SECRET-PLACE"[..],
            b"camera-serial-1234",
            b"owner-name",
        ] {
            assert!(!contains(&clean, secret));
        }
        assert!(contains(&clean, b"JFIF"));
        assert!(clean.ends_with(&[0x12, 0x34, 0xFF, 0xD9]));
        assert!(!contains(&clean, b"Exif"));
    }

    #[test]
    fn jpeg_keeps_a_non_default_orientation_only() {
        let clean = strip_image_metadata("image/jpeg", &sample_jpeg(6)).expect("clean");
        assert!(contains(&clean, b"Exif"));
        assert!(!contains(&clean, b"GPS-SECRET-PLACE"));
        let start = clean
            .windows(2)
            .position(|w| w == [0xFF, 0xE1])
            .expect("exif segment");
        let len = usize::from(u16::from_be_bytes([clean[start + 2], clean[start + 3]]));
        let data = &clean[start + 4..start + 2 + len];
        assert_eq!(exif_orientation(data), Some(6));
    }

    #[test]
    fn jpeg_that_is_cut_or_wrong_is_refused() {
        let full = sample_jpeg(1);
        assert_eq!(
            strip_image_metadata("image/jpeg", &full[..20]),
            Err(StripError::Malformed)
        );
        assert_eq!(
            strip_image_metadata("image/jpeg", b"not a picture"),
            Err(StripError::Malformed)
        );
        assert_eq!(
            strip_image_metadata("image/jpeg", &[]),
            Err(StripError::Malformed)
        );
    }

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = u32::try_from(data.len()).unwrap().to_be_bytes().to_vec();
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(data);
        chunk.extend_from_slice(&[0, 0, 0, 0]);
        chunk
    }

    fn sample_png() -> Vec<u8> {
        let mut file = PNG_SIGNATURE.to_vec();
        file.extend(png_chunk(b"IHDR", &[0; 13]));
        file.extend(png_chunk(b"tEXt", b"Author\0private-author"));
        file.extend(png_chunk(b"eXIf", b"GPS-SECRET-PLACE"));
        file.extend(png_chunk(b"tIME", &[7; 7]));
        file.extend(png_chunk(b"IDAT", &[9; 4]));
        file.extend(png_chunk(b"IEND", &[]));
        file.extend_from_slice(b"trailing-secret");
        file
    }

    #[test]
    fn png_keeps_only_drawing_chunks() {
        let clean = strip_image_metadata("image/png", &sample_png()).expect("clean");
        assert!(contains(&clean, b"IHDR") && contains(&clean, b"IDAT"));
        for secret in [
            &b"private-author"[..],
            b"GPS-SECRET-PLACE",
            b"tIME",
            b"trailing-secret",
        ] {
            assert!(!contains(&clean, secret));
        }
    }

    #[test]
    fn png_with_a_cut_chunk_is_refused() {
        let full = sample_png();
        assert_eq!(
            strip_image_metadata("image/png", &full[..30]),
            Err(StripError::Malformed)
        );
        assert_eq!(
            strip_image_metadata("image/png", &[1, 2, 3]),
            Err(StripError::Malformed)
        );
    }

    #[test]
    fn gif_loses_comment_and_keeps_the_loop() {
        let mut file = b"GIF89a".to_vec();
        file.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0]);
        file.extend_from_slice(&[0; 6]);
        let mut comment = vec![0x21, 0xFE, 6];
        comment.extend_from_slice(b"secret");
        comment.push(0);
        file.extend(comment);
        let mut netscape = vec![0x21, 0xFF, 11];
        netscape.extend_from_slice(b"NETSCAPE2.0");
        netscape.extend_from_slice(&[3, 1, 0, 0, 0]);
        file.extend(netscape);
        file.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 0x01, 0]);
        file.push(0x3B);
        let clean = strip_image_metadata("image/gif", &file).expect("clean");
        assert!(!contains(&clean, b"secret"));
        assert!(contains(&clean, b"NETSCAPE2.0"));
        assert!(clean.ends_with(&[0x3B]));
        let mut cut = file.clone();
        cut.truncate(cut.len() - 4);
        assert_eq!(
            strip_image_metadata("image/gif", &cut),
            Err(StripError::Malformed)
        );
    }

    fn webp_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = kind.to_vec();
        chunk.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        chunk.extend_from_slice(data);
        if data.len() % 2 == 1 {
            chunk.push(0);
        }
        chunk
    }

    #[test]
    fn webp_loses_exif_and_xmp_and_their_flags() {
        let mut body = b"WEBP".to_vec();
        let mut vp8x = vec![0b0000_1100, 0, 0, 0];
        vp8x.extend_from_slice(&[0; 6]);
        body.extend(webp_chunk(b"VP8X", &vp8x));
        body.extend(webp_chunk(b"VP8 ", &[5; 7]));
        body.extend(webp_chunk(b"EXIF", b"GPS-SECRET-PLACE"));
        body.extend(webp_chunk(b"XMP ", b"owner-name"));
        let mut file = b"RIFF".to_vec();
        file.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        file.extend(body);
        let clean = strip_image_metadata("image/webp", &file).expect("clean");
        assert!(!contains(&clean, b"GPS-SECRET-PLACE"));
        assert!(!contains(&clean, b"owner-name"));
        assert!(contains(&clean, b"VP8 "));
        let flags = clean[20];
        assert_eq!(flags & WEBP_METADATA_FLAGS, 0);
        let declared = u32::from_le_bytes([clean[4], clean[5], clean[6], clean[7]]);
        assert_eq!(usize::try_from(declared).unwrap() + 8, clean.len());
        assert_eq!(
            strip_image_metadata("image/webp", &file[..15]),
            Err(StripError::Malformed)
        );
    }

    #[test]
    fn other_types_have_no_rule() {
        assert_eq!(
            strip_image_metadata("image/svg+xml", b"<svg/>"),
            Err(StripError::Unsupported)
        );
        assert_eq!(
            strip_image_metadata("application/pdf", b"%PDF"),
            Err(StripError::Unsupported)
        );
    }
}
