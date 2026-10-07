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

//! File attachments for Grappa's `POST /api/uploads`: the closed set of file
//! types the server accepts, their cap category, and how the resulting link
//! is announced in chat.

/// The size-cap category Grappa assigns to an accepted file type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadCategory {
    Image,
    Video,
    Document,
    Audio,
}

impl UploadCategory {
    /// Prefix Cicchetto puts before an uploaded file's link in the message
    /// it posts; attachments stay ordinary text messages on IRC.
    pub fn emoji(self) -> &'static str {
        match self {
            Self::Image => "📸",
            Self::Video => "🎬",
            Self::Document => "📄",
            Self::Audio => "🎵",
        }
    }
}

/// The MIME type Grappa's allowlist expects for a file name, by extension,
/// with its cap category. `None` means the server would refuse the file
/// (415), so it is not sent.
pub fn mime_for_filename(filename: &str) -> Option<(&'static str, UploadCategory)> {
    let extension = filename.rsplit_once('.')?.1.to_ascii_lowercase();
    let found = match extension.as_str() {
        "png" => ("image/png", UploadCategory::Image),
        "jpg" | "jpeg" => ("image/jpeg", UploadCategory::Image),
        "gif" => ("image/gif", UploadCategory::Image),
        "webp" => ("image/webp", UploadCategory::Image),
        "apng" => ("image/apng", UploadCategory::Image),
        "mp4" => ("video/mp4", UploadCategory::Video),
        "mov" => ("video/quicktime", UploadCategory::Video),
        "webm" => ("video/webm", UploadCategory::Video),
        "pdf" => ("application/pdf", UploadCategory::Document),
        "txt" => ("text/plain", UploadCategory::Document),
        "md" | "markdown" => ("text/markdown", UploadCategory::Document),
        "odt" => (
            "application/vnd.oasis.opendocument.text",
            UploadCategory::Document,
        ),
        "ods" => (
            "application/vnd.oasis.opendocument.spreadsheet",
            UploadCategory::Document,
        ),
        "docx" => (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            UploadCategory::Document,
        ),
        "xlsx" => (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            UploadCategory::Document,
        ),
        "mp3" => ("audio/mpeg", UploadCategory::Audio),
        "m4a" | "m4r" => ("audio/mp4", UploadCategory::Audio),
        "aac" => ("audio/aac", UploadCategory::Audio),
        "wav" => ("audio/wav", UploadCategory::Audio),
        "flac" => ("audio/flac", UploadCategory::Audio),
        _ => return None,
    };
    Some(found)
}

/// Shortest remaining lifetime worth announcing, in seconds (0,01 h).
const MIN_ANNOUNCED_SECS: i64 = 36;

/// The remaining lifetime of an upload as hours with a decimal comma and no
/// trailing zeros (`24h`, `1,5h`). It is rounded down, to a tenth of an hour
/// (hundredths below that), so the text never promises more than the server
/// keeps. `None` when under 0,01 h is left or the time has passed: such an
/// upload isn't announced as live.
pub fn remaining_lifetime_label(remaining_secs: i64) -> Option<String> {
    if remaining_secs < MIN_ANNOUNCED_SECS {
        return None;
    }
    let tenths = remaining_secs / 360;
    if tenths == 0 {
        return Some(format!("0,{:02}h", remaining_secs / 36));
    }
    let (hours, tenth) = (tenths / 10, tenths % 10);
    Some(if tenth == 0 {
        format!("{hours}h")
    } else {
        format!("{hours},{tenth}h")
    })
}

/// The chat message announcing an uploaded file, as Cicchetto posts it, with
/// the remaining lifetime (see [`remaining_lifetime_label`]) after the link
/// when it is known.
pub fn attachment_message(category: UploadCategory, url: &str, remaining: Option<&str>) -> String {
    match remaining {
        Some(remaining) => format!("{} {url} ({remaining})", category.emoji()),
        None => format!("{} {url}", category.emoji()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_extensions_to_the_server_allowlist() {
        assert_eq!(
            mime_for_filename("Photo.JPG"),
            Some(("image/jpeg", UploadCategory::Image))
        );
        assert_eq!(
            mime_for_filename("clip.mov"),
            Some(("video/quicktime", UploadCategory::Video))
        );
        assert_eq!(
            mime_for_filename("notes.md"),
            Some(("text/markdown", UploadCategory::Document))
        );
        assert_eq!(
            mime_for_filename("song.m4a"),
            Some(("audio/mp4", UploadCategory::Audio))
        );
        assert_eq!(mime_for_filename("setup.exe"), None);
        assert_eq!(mime_for_filename("README"), None);
    }

    #[test]
    fn announces_uploads_with_the_category_emoji() {
        assert_eq!(
            attachment_message(UploadCategory::Image, "https://irc.example/uploads/abc.png", None),
            "📸 https://irc.example/uploads/abc.png"
        );
        assert_eq!(UploadCategory::Audio.emoji(), "🎵");
    }

    #[test]
    fn appends_the_remaining_lifetime_once() {
        assert_eq!(
            attachment_message(
                UploadCategory::Video,
                "https://irc.example/uploads/abc.mp4",
                Some("24h"),
            ),
            "🎬 https://irc.example/uploads/abc.mp4 (24h)"
        );
    }

    #[test]
    fn formats_whole_and_fractional_hours() {
        assert_eq!(remaining_lifetime_label(86_400).as_deref(), Some("24h"));
        assert_eq!(remaining_lifetime_label(5_400).as_deref(), Some("1,5h"));
        assert_eq!(remaining_lifetime_label(3_600).as_deref(), Some("1h"));
        assert_eq!(remaining_lifetime_label(259_200).as_deref(), Some("72h"));
        assert_eq!(remaining_lifetime_label(360).as_deref(), Some("0,1h"));
    }

    #[test]
    fn rounds_the_lifetime_down() {
        assert_eq!(remaining_lifetime_label(86_399).as_deref(), Some("23,9h"));
        assert_eq!(remaining_lifetime_label(5_759).as_deref(), Some("1,5h"));
        assert_eq!(remaining_lifetime_label(359).as_deref(), Some("0,09h"));
        assert_eq!(remaining_lifetime_label(36).as_deref(), Some("0,01h"));
    }

    #[test]
    fn expired_or_nearly_expired_uploads_have_no_label() {
        assert_eq!(remaining_lifetime_label(35), None);
        assert_eq!(remaining_lifetime_label(0), None);
        assert_eq!(remaining_lifetime_label(-3_600), None);
    }
}
