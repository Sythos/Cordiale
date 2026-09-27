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

//! The admin console's Uploads tab (Cicchetto's `AdminUploadsTab`): the
//! registry with soft-deleted rows kept as audit history, live usage
//! against the global budget, and an early delete for a live upload. It is
//! an operator surface only; there is no "delete my upload" for a regular
//! user, and the per-subject caps are never shown as a personal quota.

use cordiale_core::admin::{AdminUpload, AdminUploadsResponse};

/// One registry row, ready for the Slint model.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UploadRowView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) mime: String,
    pub(crate) size: String,
    pub(crate) subject: String,
    /// When the reaper sweeps it, "" for never.
    pub(crate) expires: String,
    /// When it was deleted, "" while live.
    pub(crate) deleted: String,
    /// Only a live row can be deleted; a deleted one stays as history.
    pub(crate) live: bool,
}

/// The rows, with sizes and instants rendered by the caller's formatters.
pub(crate) fn upload_rows(
    view: &AdminUploadsResponse,
    size: impl Fn(u64) -> String,
    instant: impl Fn(&str) -> String,
) -> Vec<UploadRowView> {
    view.uploads
        .iter()
        .map(|upload| UploadRowView {
            id: upload.id.clone(),
            name: upload.display_name().to_string(),
            slug: upload.slug.clone(),
            mime: upload.mime.clone(),
            size: size(upload.bytes),
            subject: format!("{} · {}", upload.subject_kind, upload.subject_id),
            expires: upload
                .expires_at
                .as_deref()
                .map(&instant)
                .unwrap_or_default(),
            deleted: upload
                .deleted_at
                .as_deref()
                .map(&instant)
                .unwrap_or_default(),
            live: upload.is_live(),
        })
        .collect()
}

/// The budget line's figures: used, cap, and the share of the cap when the
/// cap is a positive number (a share of zero would be no number at all).
pub(crate) fn budget(view: &AdminUploadsResponse) -> (u64, u64, Option<u64>) {
    let share = (view.global_cap_bytes > 0).then(|| {
        let percent = u128::from(view.live_bytes_sum) * 100 / u128::from(view.global_cap_bytes);
        u64::try_from(percent).unwrap_or(u64::MAX)
    });
    (view.live_bytes_sum, view.global_cap_bytes, share)
}

/// Whether `id` names a live row of the last list: a delete is never sent
/// for a row already soft-deleted, or one the list doesn't show.
pub(crate) fn can_delete(view: Option<&AdminUploadsResponse>, id: &str) -> bool {
    view.is_some_and(|view| {
        view.uploads
            .iter()
            .any(|upload: &AdminUpload| upload.id == id && upload.is_live())
    })
}

/// Status key for a failed list or delete: 403 is a session without the
/// admin console (not an admin, or a per-client token).
pub(crate) fn error_key(status: Option<u16>, fallback: &'static str) -> &'static str {
    if status == Some(403) {
        "forbidden"
    } else {
        fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload(id: &str, deleted_at: Option<&str>, name: Option<&str>) -> AdminUpload {
        AdminUpload {
            id: id.into(),
            slug: format!("slug{id}"),
            mime: "image/png".into(),
            bytes: 2048,
            original_filename: name.map(str::to_string),
            subject_kind: "user".into(),
            subject_id: "s1".into(),
            expires_at: None,
            deleted_at: deleted_at.map(str::to_string),
            inserted_at: None,
        }
    }

    fn view() -> AdminUploadsResponse {
        AdminUploadsResponse {
            uploads: vec![
                upload("u1", None, Some("cat.png")),
                upload("u2", Some("2026-09-27T10:00:00Z"), None),
            ],
            live_bytes_sum: 256,
            global_cap_bytes: 1024,
        }
    }

    #[test]
    fn deleted_rows_stay_listed_without_a_delete() {
        let rows = upload_rows(&view(), |bytes| format!("{bytes} B"), |at| at.to_string());
        assert_eq!(rows.len(), 2);
        assert!(rows[0].live);
        assert_eq!(rows[0].name, "cat.png");
        assert_eq!(rows[0].deleted, "");
        assert_eq!(rows[0].expires, "");
        assert!(!rows[1].live);
        assert_eq!(rows[1].name, "slugu2");
        assert_eq!(rows[1].deleted, "2026-09-27T10:00:00Z");
        assert_eq!(rows[1].subject, "user · s1");
    }

    #[test]
    fn a_soft_deleted_or_unknown_row_is_never_deleted_again() {
        let view = view();
        assert!(can_delete(Some(&view), "u1"));
        assert!(!can_delete(Some(&view), "u2"));
        assert!(!can_delete(Some(&view), "u3"));
        assert!(!can_delete(None, "u1"));
    }

    #[test]
    fn the_budget_share_needs_a_positive_cap() {
        assert_eq!(budget(&view()), (256, 1024, Some(25)));
        let uncapped = AdminUploadsResponse {
            global_cap_bytes: 0,
            ..view()
        };
        assert_eq!(budget(&uncapped), (256, 0, None));
    }

    #[test]
    fn a_session_without_the_console_is_told_so() {
        assert_eq!(error_key(Some(403), "failed"), "forbidden");
        assert_eq!(error_key(Some(500), "delete-failed"), "delete-failed");
        assert_eq!(error_key(None, "failed"), "failed");
    }
}
