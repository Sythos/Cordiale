//! Files of the locked query windows (Grappa protocol 58).
//!
//! A file picked in a locked window never goes through the plain upload. The
//! worker reads it, removes the metadata of images and videos, seals it with
//! AES-256-GCM under a new key and nonce, and uploads the ciphertext with
//! `POST /api/uploads/encrypted`. The descriptor (URL, key, nonce, hash, name,
//! type, size, category, expiry) then goes to the peer inside an Olm message,
//! and the other devices of the account get it through the copy path.
//!
//! Every failure ends in a status message and nothing else: the plain upload
//! is never a fallback, and the original file never leaves the device.
//!
//! A click on the link of a file row decrypts the file here. The descriptor
//! comes from the sealed history of a locked entry, and it is checked against
//! the configured server before the download starts.

use super::*;

use cordiale_core::e2e_file::{self, FileDescriptor};
use cordiale_core::metadata_strip::strip_image_metadata;

/// The first protocol version with `POST /api/uploads/encrypted`.
pub(crate) const ENCRYPTED_UPLOAD_PROTOCOL: u32 = 58;

/// True when the server of this session has the encrypted upload door. A
/// server whose version is not known does not count: the file stays here.
pub(crate) fn encrypted_upload_supported(protocol: Option<u32>) -> bool {
    protocol.is_some_and(|version| version >= ENCRYPTED_UPLOAD_PROTOCOL)
}

/// A file that is cleaned and sealed, ready for the upload.
pub(crate) struct Prepared {
    /// The name that goes in the descriptor, already cleaned.
    pub(crate) name: String,
    pub(crate) mime: &'static str,
    pub(crate) category: UploadCategory,
    pub(crate) sealed: e2e_file::Sealed,
}

/// Cleans and seals a file that is read whole. The server cap by category
/// applies to the plain file. Images lose their metadata first: an image
/// that cannot be cleaned is refused, never sent as it is. The error is the
/// status key to show.
pub(crate) fn clean_and_seal(
    name: &str,
    mime: &'static str,
    category: UploadCategory,
    bytes: Vec<u8>,
    cap: Option<u64>,
) -> Result<Prepared, &'static str> {
    if cap.is_some_and(|cap| bytes.len() as u64 > cap) {
        return Err("attach-too-large");
    }
    let bytes = if category == UploadCategory::Image {
        strip_image_metadata(mime, &bytes).map_err(|_| "e2e-file-strip-failed")?
    } else {
        bytes
    };
    let sealed = e2e_file::seal(&bytes).map_err(|_| "e2e-file-failed")?;
    Ok(Prepared {
        name: e2e_file::clean_name(name),
        mime,
        category,
        sealed,
    })
}

/// Reads, cleans and seals the file at `path`. A video is encoded again into
/// a new MP4 (no metadata is copied to it); a build without the video encoder
/// refuses the video. Run it on a blocking thread.
fn prepare(
    path: &std::path::Path,
    mime: &'static str,
    category: UploadCategory,
    cap: Option<u64>,
    cancel: &std::sync::atomic::AtomicBool,
    progress: &dyn Fn(u8),
) -> Result<Prepared, &'static str> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let read_failed = |err: std::io::Error| {
        persistence::log_line(&format!("encrypted attachment read failed: {err}"));
        "attach-read-failed"
    };
    if category == UploadCategory::Video {
        if !video_processing::is_available() {
            return Err("e2e-file-strip-unavailable");
        }
        let video = video_processing::shrink(path, cancel, progress).map_err(|error| {
            persistence::log_line(&format!("encrypted video processing stopped: {error:?}"));
            match error {
                ShrinkError::Unavailable => "e2e-file-strip-unavailable",
                ShrinkError::Cancelled => "attach-failed",
                _ => "e2e-file-strip-failed",
            }
        })?;
        let bytes = std::fs::read(&video.path).map_err(read_failed)?;
        return clean_and_seal(&video.filename, video.mime, category, bytes, cap);
    }
    let len = std::fs::metadata(path).map_err(read_failed)?.len();
    if cap.is_some_and(|cap| len > cap) {
        return Err("attach-too-large");
    }
    let bytes = std::fs::read(path).map_err(read_failed)?;
    clean_and_seal(&name, mime, category, bytes, cap)
}

/// Status key for an encrypted upload that the server did not take. A server
/// without the route (404, 405 or 501) is a server without the flow.
pub(crate) fn encrypted_upload_error_status(status: Option<u16>) -> &'static str {
    match status {
        Some(404 | 405 | 501) => "e2e-file-unsupported-server",
        Some(413) => "attach-rejected-size",
        Some(507) => "attach-no-space",
        _ => "e2e-file-failed",
    }
}

/// The expiry of an upload answer as the UTC text of a descriptor, or `None`
/// when the server gave no time that can be read.
pub(crate) fn descriptor_expiry(expires_at: &str) -> Option<String> {
    let time = chrono::DateTime::parse_from_rfc3339(expires_at).ok()?;
    Some(
        time.with_timezone(&chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
    )
}

/// Where a file goes and how: taken when the file is accepted, so that it
/// does not depend on the window that is open when the upload ends.
struct FileJob {
    client: GrappaClient,
    token: String,
    network: String,
    nick: String,
    ui: slint::Weak<AppWindow>,
    expire: Option<i64>,
    worker: mpsc::UnboundedSender<WorkerCommand>,
    shrink_notices: SharedShrinkNoticeTracker,
}

/// Starts the encrypted upload of a file picked in the locked window of
/// `nick`. The checks run here; the work runs in its own task.
pub(crate) fn handle_attach_locked(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    (network, nick): (String, String),
    path: std::path::PathBuf,
    options: UploadOptions,
    worker: &mpsc::UnboundedSender<WorkerCommand>,
    shrink_notices: Arc<Mutex<ShrinkNoticeTracker>>,
) {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let fail = |kind: &'static str| set_attach_status(ui, kind, filename.clone());
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        fail("e2e-not-ready");
        return;
    };
    if !state.e2e.can_use_engine(&network) {
        fail("e2e-not-ready");
        return;
    }
    // A server without the encrypted door never gets the file, and the plain
    // door is not tried.
    if !encrypted_upload_supported(state.conn.server_protocol_version) {
        fail("e2e-file-unsupported-server");
        return;
    }
    let Some((mime, category)) = mime_for_filename(&filename) else {
        fail("attach-unsupported-type");
        return;
    };
    let cap = state
        .prefs
        .upload_limits
        .as_ref()
        .map(|limits| upload_cap(limits, category));
    // Too many files already wait: the new one is refused, not queued.
    let Ok(queued) = UPLOAD_QUEUE.try_acquire() else {
        fail("attach-failed");
        return;
    };
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_status_kind("".into());
        ui.set_status_message("".into());
    });
    let job = FileJob {
        client,
        token,
        network,
        nick,
        ui: ui.clone(),
        expire: options.expire,
        worker: worker.clone(),
        shrink_notices,
    };
    tokio::spawn(prepare_and_upload(
        job,
        (path, filename),
        (mime, category, cap),
        state.conn.shrink_cancel.clone(),
        queued,
    ));
}

/// Waits for an upload slot, prepares the file, uploads the ciphertext and
/// hands the descriptor back to the worker, which sends it through the engine.
async fn prepare_and_upload(
    job: FileJob,
    (path, filename): (std::path::PathBuf, String),
    (mime, category, cap): (&'static str, UploadCategory, Option<u64>),
    cancel: Arc<CancelFlag>,
    _queued: tokio::sync::SemaphorePermit<'static>,
) {
    let work = async {
        let Ok(_slot) = UPLOAD_SLOTS.acquire().await else {
            return;
        };
        let notice = (category == UploadCategory::Video)
            .then(|| begin_shrink_notice(&job.ui, &job.shrink_notices, filename.clone()));
        let progress_ui = job.ui.clone();
        let progress_notice = notice.clone();
        let progress_name = filename.clone();
        let task_cancel = cancel.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            prepare(&path, mime, category, cap, &task_cancel.flag, &|percent| {
                if let Some(notice) = &progress_notice {
                    update_shrink_notice(
                        &progress_ui,
                        notice,
                        format!("{progress_name} ({percent}%)"),
                    );
                }
            })
        })
        .await;
        let prepared = match prepared {
            Ok(result) => result,
            Err(err) => {
                persistence::log_line(&format!("encrypted attachment task failed: {err}"));
                Err("e2e-file-failed")
            }
        };
        let status = |kind: &'static str| (kind, filename.clone());
        let mut prepared = match prepared {
            Ok(prepared) => {
                if let Some(notice) = &notice {
                    finish_shrink_notice(&job.ui, notice, None);
                }
                prepared
            }
            Err(kind) => {
                match &notice {
                    Some(notice) => finish_shrink_notice(&job.ui, notice, Some(status(kind))),
                    None => set_attach_status(&job.ui, kind, filename.clone()),
                }
                return;
            }
        };
        if cancel.is_cancelled() {
            return;
        }
        let ciphertext = std::mem::take(&mut prepared.sealed.ciphertext);
        let uploaded = match job
            .client
            .upload_encrypted_file(&job.token, ciphertext, job.expire)
            .await
        {
            Ok(uploaded) => uploaded,
            Err(err) => {
                // The log gets the kind of the failure: never a name or a key.
                persistence::log_line(&format!(
                    "encrypted attachment upload failed: status={:?}",
                    err.status()
                ));
                let kind =
                    encrypted_upload_error_status(err.status().map(|status| status.as_u16()));
                set_attach_status(&job.ui, kind, filename);
                return;
            }
        };
        let Some(expires_at) = descriptor_expiry(&uploaded.expires_at) else {
            set_attach_status(&job.ui, "e2e-file-failed", filename);
            return;
        };
        let descriptor = FileDescriptor::for_sealed(
            &prepared.sealed,
            &uploaded.url,
            &expires_at,
            (&prepared.name, prepared.mime, prepared.category),
        );
        // The peer accepts only an upload of this server: check what is about
        // to be sent with the same rules.
        if descriptor
            .validate(job.client.base_url(), chrono::Utc::now().timestamp())
            .is_err()
        {
            persistence::log_line("encrypted attachment answer was not an upload of this server");
            set_attach_status(&job.ui, "e2e-file-failed", filename);
            return;
        }
        persistence::log_line(&format!(
            "encrypted attachment uploaded: slug={}",
            uploaded.slug
        ));
        let _ = job.worker.send(WorkerCommand::E2eFileReady {
            network: job.network.clone(),
            nick: job.nick.clone(),
            descriptor: Box::new(descriptor),
        });
    };
    if run_unless_cancelled(&cancel, work).await.is_none() {
        persistence::log_line("encrypted attachment upload cancelled");
    }
}

/// Sends the descriptor of an uploaded file through the engine of the locked
/// window. A descriptor with bad fields is refused. The send is the same as
/// the one of a text: the other devices get a copy, and a peer without keys
/// gets the file when its keys come.
pub(crate) async fn send_prepared(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    nick: String,
    descriptor: FileDescriptor,
) {
    if descriptor.check_shape().is_err() {
        set_attach_status(ui, "e2e-file-failed", descriptor.name);
        return;
    }
    let stored = e2e_file::file_text(&descriptor);
    handle_send_locked(state, ui, network, nick, stored).await;
}

/// Where the decrypted file goes.
#[derive(Debug, PartialEq, Eq)]
enum OpenWith {
    /// The image viewer, with this file extension.
    Image(&'static str),
    /// The text viewer.
    Text,
    /// The save dialog: no preview.
    Save,
}

/// How a decrypted file is shown, by its MIME type. Only the types that the
/// viewer can draw safely are previewed; any other type is saved, never run.
fn open_with(mime: &str) -> OpenWith {
    match mime {
        "image/jpeg" => OpenWith::Image("jpg"),
        "image/png" | "image/apng" => OpenWith::Image("png"),
        "image/gif" => OpenWith::Image("gif"),
        "image/webp" => OpenWith::Image("webp"),
        "text/plain" | "text/markdown" => OpenWith::Text,
        _ => OpenWith::Save,
    }
}

/// Like [`open_with`], but a text over the size limit of the text viewer goes
/// to the save dialog: the viewer would show only a part of it.
fn open_for_size(mime: &str, len: usize) -> OpenWith {
    match open_with(mime) {
        OpenWith::Text if len > cordiale_core::media::MAX_TEXT_BYTES => OpenWith::Save,
        other => other,
    }
}

/// Status key for a descriptor or a download that was refused.
fn open_error_status(error: e2e_file::FileError) -> &'static str {
    match error {
        e2e_file::FileError::Expired => "e2e-file-expired",
        _ => "e2e-file-invalid",
    }
}

/// Checks the descriptor of a clicked file row, downloads the ciphertext,
/// checks its hash, decrypts it and shows the result. The checks come first:
/// nothing is fetched for a descriptor that fails them.
pub(crate) fn open_e2e_file(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    descriptor: FileDescriptor,
) {
    let Some(client) = state.conn.client.clone() else {
        set_attach_status(ui, "e2e-not-ready", descriptor.name);
        return;
    };
    let valid = match descriptor.validate(client.base_url(), chrono::Utc::now().timestamp()) {
        Ok(valid) => valid,
        Err(error) => {
            persistence::log_line(&format!("encrypted file refused: {error}"));
            set_attach_status(ui, open_error_status(error), descriptor.name);
            return;
        }
    };
    let ui = ui.clone();
    tokio::spawn(async move {
        let name = valid.name.clone();
        let ciphertext = match client.fetch_encrypted_file(&valid).await {
            Ok(bytes) => bytes,
            Err(err) => {
                persistence::log_line(&format!(
                    "encrypted file download failed: status={:?}",
                    err.status()
                ));
                let kind = match err.status().map(|status| status.as_u16()) {
                    Some(404 | 410) => "e2e-file-expired",
                    _ => "e2e-file-open-failed",
                };
                set_attach_status(&ui, kind, name);
                return;
            }
        };
        let plain = match valid.open(&ciphertext) {
            Ok(plain) => plain,
            Err(error) => {
                persistence::log_line(&format!("encrypted file refused: {error}"));
                set_attach_status(&ui, open_error_status(error), name);
                return;
            }
        };
        show_decrypted(&ui, &valid, plain);
    });
}

/// Shows a decrypted file by its type.
fn show_decrypted(ui: &slint::Weak<AppWindow>, file: &e2e_file::ValidFile, plain: Vec<u8>) {
    let (name, url) = (file.name.clone(), file.url.to_string());
    match open_for_size(&file.mime, plain.len()) {
        OpenWith::Image(extension) => {
            let written = temp_files::write_private("e2e-media", &format!(".{extension}"), &plain);
            let _ = ui.upgrade_in_event_loop(move |ui| {
                media_save::forget();
                ui.set_media_url(url.into());
                ui.set_media_title(name.into());
                ui.set_media_zoom(false);
                ui.set_media_open(true);
                let loaded = written
                    .as_ref()
                    .ok()
                    .and_then(|path| slint::Image::load_from_path(path).ok());
                if let Ok(path) = &written {
                    temp_files::discard(path);
                }
                match loaded {
                    Some(image) => {
                        media_save::remember(extension, plain);
                        ui.set_media_image(image);
                        ui.set_media_kind("image".into());
                    }
                    None => {
                        ui.set_media_error("unsupported image".into());
                        ui.set_media_kind("failed".into());
                    }
                }
            });
        }
        OpenWith::Text => {
            // Only a text that fits the viewer comes here: a larger one goes
            // to the save dialog, so the whole file stays reachable.
            let shown = String::from_utf8_lossy(&plain).into_owned();
            let _ = ui.upgrade_in_event_loop(move |ui| {
                media_save::forget();
                ui.set_media_url(url.into());
                ui.set_media_title(name.into());
                ui.set_media_zoom(false);
                ui.set_media_text(shown.into());
                ui.set_media_truncated(false);
                ui.set_media_kind("text".into());
                ui.set_media_open(true);
            });
        }
        OpenWith::Save => {
            // The dialog runs on the UI thread, as the Download button does.
            let _ = ui.upgrade_in_event_loop(move |ui| {
                let Some(path) = rfd::FileDialog::new().set_file_name(&name).save_file() else {
                    return;
                };
                if let Err(err) = std::fs::write(&path, &plain) {
                    persistence::log_line(&format!("encrypted file not saved: {err}"));
                    ui.set_status_attach_name(name.into());
                    ui.set_status_kind("e2e-file-open-failed".into());
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordiale_core::e2e_file::FileError;

    const SERVER: &str = "https://irc.example";

    #[test]
    fn only_a_server_with_protocol_58_takes_encrypted_files() {
        assert!(!encrypted_upload_supported(None));
        assert!(!encrypted_upload_supported(Some(0)));
        assert!(!encrypted_upload_supported(Some(57)));
        assert!(encrypted_upload_supported(Some(58)));
        assert!(encrypted_upload_supported(Some(59)));
    }

    /// A PNG with a text chunk that holds a private marker.
    fn png_with_marker(marker: &[u8]) -> Vec<u8> {
        fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
            let mut out = u32::try_from(data.len()).unwrap().to_be_bytes().to_vec();
            out.extend_from_slice(kind);
            out.extend_from_slice(data);
            out.extend_from_slice(&[0; 4]);
            out
        }
        let mut file = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        file.extend(chunk(b"IHDR", &[0; 13]));
        file.extend(chunk(b"tEXt", marker));
        file.extend(chunk(b"IDAT", &[1, 2, 3]));
        file.extend(chunk(b"IEND", &[]));
        file
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn an_image_is_cleaned_before_it_is_sealed() {
        let marker = b"Comment\0gps-52.5N-13.4E";
        let original = png_with_marker(marker);
        let prepared = clean_and_seal(
            "photo.png",
            "image/png",
            UploadCategory::Image,
            original.clone(),
            None,
        )
        .expect("prepared");
        assert!(!contains(&prepared.sealed.ciphertext, marker));
        // The receiver gets the cleaned image: the pixel data stay, the text
        // chunk is gone.
        let descriptor = FileDescriptor::for_sealed(
            &prepared.sealed,
            "https://irc.example/uploads/abc",
            "2099-01-01T00:00:00Z",
            (&prepared.name, prepared.mime, prepared.category),
        );
        let valid = descriptor.validate(SERVER, 1_000).expect("valid");
        let plain = valid.open(&prepared.sealed.ciphertext).expect("open");
        assert!(!contains(&plain, b"gps-52.5N-13.4E"));
        assert!(contains(&plain, b"IDAT"));
        assert!(plain.len() < original.len());
    }

    #[test]
    fn an_image_that_cannot_be_cleaned_is_not_sent() {
        for (mime, bytes) in [
            ("image/png", b"not a png at all".to_vec()),
            ("image/jpeg", vec![0xFF, 0xD8, 0xFF]),
            ("image/gif", b"GIF89a".to_vec()),
            ("image/webp", b"RIFF".to_vec()),
        ] {
            let result = clean_and_seal("x", mime, UploadCategory::Image, bytes, None);
            assert_eq!(result.err(), Some("e2e-file-strip-failed"), "{mime}");
        }
    }

    #[test]
    fn a_document_keeps_its_bytes_and_still_gets_a_new_key_each_time() {
        let bytes = b"%PDF-1.7 body".to_vec();
        let first = clean_and_seal(
            "a.pdf",
            "application/pdf",
            UploadCategory::Document,
            bytes.clone(),
            None,
        )
        .expect("first");
        let second = clean_and_seal(
            "a.pdf",
            "application/pdf",
            UploadCategory::Document,
            bytes.clone(),
            None,
        )
        .expect("second");
        assert_eq!(first.sealed.plain_len, bytes.len() as u64);
        assert_ne!(first.sealed.key.as_slice(), second.sealed.key.as_slice());
        assert_ne!(first.sealed.ciphertext, second.sealed.ciphertext);
        assert!(!contains(&first.sealed.ciphertext, b"%PDF"));
    }

    #[test]
    fn the_server_cap_applies_to_the_plain_file() {
        let result = clean_and_seal(
            "a.txt",
            "text/plain",
            UploadCategory::Document,
            vec![0; 11],
            Some(10),
        );
        assert_eq!(result.err(), Some("attach-too-large"));
        let ok = clean_and_seal(
            "a.txt",
            "text/plain",
            UploadCategory::Document,
            vec![0; 10],
            Some(10),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn the_name_in_the_descriptor_is_cleaned() {
        let prepared = clean_and_seal(
            "dir/evil\u{202E}gpj.exe",
            "text/plain",
            UploadCategory::Document,
            vec![1],
            None,
        )
        .expect("prepared");
        assert_eq!(prepared.name, "direvilgpj.exe");
    }

    #[test]
    fn a_missing_door_is_an_unsupported_server_and_other_errors_stay_errors() {
        for status in [404, 405, 501] {
            assert_eq!(
                encrypted_upload_error_status(Some(status)),
                "e2e-file-unsupported-server"
            );
        }
        assert_eq!(
            encrypted_upload_error_status(Some(413)),
            "attach-rejected-size"
        );
        assert_eq!(encrypted_upload_error_status(Some(507)), "attach-no-space");
        assert_eq!(encrypted_upload_error_status(Some(500)), "e2e-file-failed");
        assert_eq!(encrypted_upload_error_status(None), "e2e-file-failed");
    }

    #[test]
    fn the_upload_expiry_becomes_utc_text() {
        assert_eq!(
            descriptor_expiry("2026-11-10T12:00:00.123456+01:00").as_deref(),
            Some("2026-11-10T11:00:00Z")
        );
        assert_eq!(
            descriptor_expiry("2026-11-10T12:00:00Z").as_deref(),
            Some("2026-11-10T12:00:00Z")
        );
        assert_eq!(descriptor_expiry("soon"), None);
        assert_eq!(descriptor_expiry(""), None);
    }

    #[test]
    fn only_safe_types_get_a_preview() {
        assert_eq!(open_with("image/jpeg"), OpenWith::Image("jpg"));
        assert_eq!(open_with("image/png"), OpenWith::Image("png"));
        assert_eq!(open_with("text/plain"), OpenWith::Text);
        for mime in [
            "image/svg+xml",
            "text/html",
            "application/pdf",
            "application/x-msdownload",
            "video/mp4",
        ] {
            assert_eq!(open_with(mime), OpenWith::Save, "{mime}");
        }
    }

    #[test]
    fn a_text_over_the_viewer_limit_goes_to_the_save_dialog() {
        let limit = cordiale_core::media::MAX_TEXT_BYTES;
        assert_eq!(open_for_size("text/plain", limit), OpenWith::Text);
        assert_eq!(open_for_size("text/markdown", limit + 1), OpenWith::Save);
        assert_eq!(
            open_for_size("image/png", limit + 1),
            OpenWith::Image("png")
        );
    }

    #[test]
    fn an_expired_descriptor_gets_the_expired_text() {
        assert_eq!(open_error_status(FileError::Expired), "e2e-file-expired");
        for error in [
            FileError::BadUrl,
            FileError::BadKey,
            FileError::BadIv,
            FileError::BadHash,
            FileError::HashMismatch,
            FileError::DecryptFailed,
            FileError::Malformed,
        ] {
            assert_eq!(open_error_status(error), "e2e-file-invalid");
        }
    }

    #[test]
    fn a_locked_row_shows_a_file_as_a_link_and_never_as_raw_text() {
        use cordiale_core::e2e_store::E2eMessage;
        let prepared = clean_and_seal(
            "notes.txt",
            "text/plain",
            UploadCategory::Document,
            b"hello".to_vec(),
            None,
        )
        .expect("prepared");
        let descriptor = FileDescriptor::for_sealed(
            &prepared.sealed,
            "https://irc.example/uploads/abc",
            "2099-01-01T00:00:00Z",
            (&prepared.name, prepared.mime, prepared.category),
        );
        let message = |text: String| E2eMessage {
            id: "m".to_string(),
            conversation_id: "c".to_string(),
            sender_device: "dev".to_string(),
            sent_at: 1_000,
            text,
            encrypted: true,
            captures: Vec::new(),
        };
        let row = e2e_runtime::locked_row_with_drop(
            &message(e2e_file::file_text(&descriptor)),
            "me",
            "bob",
            None,
        );
        assert!(row
            .text
            .starts_with("📄 notes.txt (text/plain, 5 B) https://irc.example/"));
        assert!(!row.text.contains('\u{1}'));
        assert!(!row.text.contains(&descriptor.key));
        let links = cordiale_core::media::find_links(&row.text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].href, "https://irc.example/uploads/abc");
        let bad = e2e_runtime::locked_row_with_drop(
            &message(format!("{}{{}}\u{1}", e2e_file::FILE_OPEN)),
            "me",
            "bob",
            None,
        );
        assert_eq!(bad.text, e2e_runtime::INVALID_FILE_ROW_TEXT);
    }
}
