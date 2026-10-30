//! Saving the image shown in the media viewer, and sharing its link.
//!
//! The viewer keeps the bytes of the open image in memory, so Download needs
//! no second request. The bytes are never logged.

use std::path::Path;
use std::sync::Mutex;

/// The image that the viewer shows now.
struct OpenImage {
    extension: String,
    bytes: Vec<u8>,
}

static OPEN_IMAGE: Mutex<Option<OpenImage>> = Mutex::new(None);

/// How a Download or Share request ended; a cancel is not an error.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Cancelled,
    Failed,
}

/// Keeps the bytes of the image that the viewer shows.
pub fn remember(extension: &str, bytes: Vec<u8>) {
    let extension = safe_extension(extension);
    if let Ok(mut open) = OPEN_IMAGE.lock() {
        *open = Some(OpenImage { extension, bytes });
    }
}

/// The file type without any character that is not a letter or a digit.
fn safe_extension(extension: &str) -> String {
    let clean: String = extension
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    if clean.is_empty() {
        "png".to_string()
    } else {
        clean
    }
}

/// Drops the bytes of the open image.
pub fn forget() {
    if let Ok(mut open) = OPEN_IMAGE.lock() {
        *open = None;
    }
}

/// A file name for the saved image. The viewer title is the last part of the
/// link; it keeps its own file type when it has one of the known types.
pub fn file_name(title: &str, extension: &str) -> String {
    let clean: String = title
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
        .collect();
    let clean = clean.trim().trim_matches('.');
    let has_type = Path::new(clean)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension));
    match (clean.is_empty(), has_type) {
        (true, _) => format!("image.{extension}"),
        (false, true) => clean.to_string(),
        (false, false) => {
            let stem = Path::new(clean)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|stem| !stem.is_empty() && Path::new(clean).extension().is_some())
                .unwrap_or(clean);
            format!("{stem}.{extension}")
        }
    }
}

/// Writes the open image to `path`.
fn write_to(path: &Path) -> Outcome {
    let Ok(open) = OPEN_IMAGE.lock() else {
        return Outcome::Failed;
    };
    let Some(image) = open.as_ref() else {
        return Outcome::Failed;
    };
    match std::fs::write(path, &image.bytes) {
        Ok(()) => Outcome::Done,
        Err(err) => {
            cordiale_core::persistence::log_line(&format!("image not saved: {err}"));
            Outcome::Failed
        }
    }
}

/// Asks where to save the open image and saves it there.
pub fn download(title: &str) -> Outcome {
    let extension = match OPEN_IMAGE.lock() {
        Ok(open) => match open.as_ref() {
            Some(image) => image.extension.clone(),
            None => return Outcome::Failed,
        },
        Err(_) => return Outcome::Failed,
    };
    let Some(path) = rfd::FileDialog::new()
        .set_file_name(file_name(title, &extension))
        .add_filter("image", &[extension.as_str()])
        .save_file()
    else {
        return Outcome::Cancelled;
    };
    write_to(&path)
}

/// Shares the image link. Cordiale has no file share on any platform, so the
/// link goes to the clipboard.
pub fn share_link(url: &str) -> Outcome {
    if url.is_empty() {
        return Outcome::Failed;
    }
    match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(url.to_string())) {
        Ok(()) => Outcome::Done,
        Err(err) => {
            cordiale_core::persistence::log_line(&format!("image link not copied: {err}"));
            Outcome::Failed
        }
    }
}

/// The status key that reports an outcome, or `None` for a cancel.
pub fn status_key(outcome: &Outcome, saving: bool) -> Option<&'static str> {
    match (outcome, saving) {
        (Outcome::Cancelled, _) => None,
        (Outcome::Done, true) => Some("media-saved"),
        (Outcome::Failed, true) => Some("media-save-failed"),
        (Outcome::Done, false) => Some("media-link-copied"),
        (Outcome::Failed, false) => Some("media-link-failed"),
    }
}

/// Writes the open image to `path` without a dialog, for tests.
#[cfg(test)]
pub fn save_open_image_to(path: &Path) -> Outcome {
    write_to(path)
}
