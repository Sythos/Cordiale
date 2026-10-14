//! Private temporary files for media, avatars, wallpapers and pasted uploads.
//!
//! The shared OS temporary folder is not safe for predictable names: another
//! local process can plant a symbolic link there. Every file goes into one
//! folder that this process creates itself, with access limited to the
//! current user on Unix, and gets a unique name that is created exclusively.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);
static PRIVATE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

/// A name part that differs between calls and between processes.
fn unique_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{nanos:x}-{count:x}", std::process::id())
}

/// A folder builder with access limited to the current user on Unix.
fn private_dir_builder() -> std::fs::DirBuilder {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
}

/// Creates a new folder in `parent` that did not exist before. The creation
/// fails when the name is taken, also when it is a symbolic link, so the
/// caller owns the folder. Access is limited to the current user on Unix.
fn create_private_dir(parent: &Path) -> std::io::Result<PathBuf> {
    let mut last_error = None;
    for _ in 0..16 {
        let path = parent.join(format!("cordiale-{}", unique_token()));
        match private_dir_builder().create(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => last_error = Some(err),
            Err(err) => return Err(err),
        }
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::other("no free folder name")))
}

/// The private folder of this process, created on first use.
pub fn private_dir() -> Option<&'static Path> {
    PRIVATE_DIR
        .get_or_init(|| create_private_dir(&std::env::temp_dir()).ok())
        .as_deref()
}

/// Opens a new file in `dir` for writing. The name starts with `prefix` and
/// ends with `suffix`. The exclusive open fails if the path exists, also when
/// it is a symbolic link, so it never follows a link. A taken name gets a new try.
fn create_in(dir: &Path, prefix: &str, suffix: &str) -> std::io::Result<(std::fs::File, PathBuf)> {
    let mut last_error = None;
    for _ in 0..16 {
        let path = dir.join(format!("{prefix}-{}{suffix}", unique_token()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => last_error = Some(err),
            Err(err) => return Err(err),
        }
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::other("no free file name")))
}

/// Writes `bytes` to a new file with a unique name in `dir`.
fn write_in(dir: &Path, prefix: &str, suffix: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let (mut file, path) = create_in(dir, prefix, suffix)?;
    if let Err(err) = file.write_all(bytes) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(err);
    }
    Ok(path)
}

/// Writes `bytes` to a new private file named `<prefix>-<unique><suffix>`.
pub fn write_private(prefix: &str, suffix: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let dir = private_dir().ok_or_else(|| std::io::Error::other("no private temporary folder"))?;
    write_in(dir, prefix, suffix, bytes)
}

/// Returns a new empty private sub-folder, for a file that must keep its name.
pub fn private_subdir() -> std::io::Result<PathBuf> {
    let dir = private_dir().ok_or_else(|| std::io::Error::other("no private temporary folder"))?;
    create_private_dir(dir)
}

/// Removes a private file once its consumer has released it.
pub fn discard(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Removes the private folder and everything in it. Call it when the app quits.
pub fn cleanup_all() {
    if let Some(Some(dir)) = PRIVATE_DIR.get() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        create_private_dir(&std::env::temp_dir()).expect("scratch folder")
    }

    #[test]
    fn names_are_unique_and_files_are_written() {
        let dir = scratch();
        let first = write_in(&dir, "media", ".png", b"one").unwrap();
        let second = write_in(&dir, "media", ".png", b"two").unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read(&first).unwrap(), b"one");
        assert_eq!(std::fs::read(&second).unwrap(), b"two");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_path_is_never_reused() {
        let dir = scratch();
        let (file, path) = create_in(&dir, "media", ".png").unwrap();
        drop(file);
        std::fs::write(&path, b"keep").unwrap();
        // The exclusive open refuses a path that exists.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let err = options.open(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_is_not_followed() {
        let dir = scratch();
        let target = dir.join("victim");
        std::fs::write(&target, b"safe").unwrap();
        let link = dir.join("planted");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut options = std::fs::OpenOptions::new();
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.write(true).create_new(true).mode(0o600);
        }
        assert!(options.open(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"safe");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn folder_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        let path = write_in(&dir, "media", ".png", b"x").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discard_and_cleanup_remove_files() {
        let path = write_private("test", ".bin", b"data").unwrap();
        assert!(path.exists());
        discard(&path);
        assert!(!path.exists());
        let kept = write_private("test", ".bin", b"data").unwrap();
        cleanup_all();
        assert!(!kept.exists());
    }
}
