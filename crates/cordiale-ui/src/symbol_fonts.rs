//! Symbol fonts for chat text.
//!
//! A theme font (Consolas, Menlo, DejaVu Sans Mono, JetBrains Mono...) often
//! has no glyph for symbols such as crosses (U+2020, U+271D, U+2626...).
//! Slint draws a square box for such a character. The system fonts that do
//! have the glyphs are registered here, so the renderer can find them when
//! the theme font cannot draw a character. The chat text itself is never
//! changed.

use std::path::PathBuf;

/// System font files that hold symbol and dingbat glyphs, most useful first.
/// `windows_dir` is the Windows directory, when the platform has one.
fn symbol_font_candidates(windows_dir: Option<&str>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if cfg!(target_os = "windows") {
        if let Some(dir) = windows_dir.filter(|dir| !dir.is_empty()) {
            let fonts = PathBuf::from(dir).join("Fonts");
            paths.push(fonts.join("seguisym.ttf"));
            paths.push(fonts.join("segoeui.ttf"));
        }
    } else if cfg!(target_os = "macos") {
        paths.push(PathBuf::from("/System/Library/Fonts/Apple Symbols.ttf"));
        paths.push(PathBuf::from(
            "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        ));
    } else {
        for path in [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/noto/NotoSansSymbols2-Regular.ttf",
            "/usr/share/fonts/noto/NotoSansSymbols2-Regular.ttf",
        ] {
            paths.push(PathBuf::from(path));
        }
    }
    paths
}

/// Registers the symbol fonts that exist on this system. A missing or
/// unreadable file is skipped: the text is still shown with the theme font.
pub fn register_symbol_fonts() {
    let windows_dir = std::env::var("WINDIR").ok();
    for path in symbol_font_candidates(windows_dir.as_deref()) {
        if !path.is_file() {
            continue;
        }
        if let Err(err) = slint::register_font_from_path(&path) {
            crate::persistence::log_line(&format!("symbol font not registered: {err}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_are_absolute_font_files() {
        let windir = if cfg!(target_os = "windows") {
            Some("C:\\Windows")
        } else {
            None
        };
        let paths = symbol_font_candidates(windir);
        assert!(!paths.is_empty());
        for path in paths {
            assert!(path.is_absolute(), "{path:?}");
            assert!(path.extension().is_some(), "{path:?}");
        }
    }

    #[test]
    fn a_missing_windows_directory_gives_no_windows_candidate() {
        if cfg!(target_os = "windows") {
            assert!(symbol_font_candidates(None).is_empty());
            assert!(symbol_font_candidates(Some("")).is_empty());
        }
    }
}
