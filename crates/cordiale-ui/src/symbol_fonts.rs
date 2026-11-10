//! Symbol fonts for chat text.
//!
//! A theme font (Consolas, Menlo, DejaVu Sans Mono, JetBrains Mono...) often
//! has no glyph for symbols such as crosses (U+2020, U+271D, U+2626...), and
//! the fallback font of the system may not have it either. The renderer then
//! draws a square box. The system fonts that have the glyphs are added at the
//! end of the fallback list of each common script. The chat text is never
//! changed, and the font of the theme stays the first choice.

use std::path::PathBuf;

use slint::fontique_011::{fontique, shared_collection};

/// Scripts whose fallback list receives the symbol fonts. Symbols have the
/// Common script, so the renderer asks for the script of the text around them.
const FALLBACK_SCRIPTS: [[u8; 4]; 5] = [*b"Latn", *b"Cyrl", *b"Grek", *b"Zyyy", *b"Zinh"];

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

/// Registers the symbol fonts that exist on this system and adds them to the
/// end of the fallback lists. A missing or unreadable file is skipped: the
/// text is still shown with the theme font.
pub fn register_symbol_fonts() {
    let windows_dir = std::env::var("WINDIR").ok();
    let mut collection = shared_collection();
    let mut families = Vec::new();
    for path in symbol_font_candidates(windows_dir.as_deref()) {
        if !path.is_file() {
            continue;
        }
        match std::fs::read(&path) {
            Ok(data) => {
                let blob = fontique::Blob::new(std::sync::Arc::new(data));
                for (family, _) in collection.register_fonts(blob, None) {
                    if !families.contains(&family) {
                        families.push(family);
                    }
                }
            }
            Err(err) => {
                cordiale_core::persistence::log_line(&format!("symbol font not read: {err}"));
            }
        }
    }
    if families.is_empty() {
        return;
    }
    for script in FALLBACK_SCRIPTS {
        let key = fontique::FallbackKey::new(fontique::Script::from_bytes(script), None);
        // Reading the list first keeps the fallback font of the system: once a
        // list is set, the system is not asked for that script again.
        let current: Vec<_> = collection.fallback_families(key).collect();
        collection.append_fallbacks(
            key,
            families
                .iter()
                .copied()
                .filter(|family| !current.contains(family)),
        );
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

    /// True when the font file has a glyph for the character.
    fn font_has_glyph(data: &[u8], face_count: u32, ch: char) -> bool {
        (0..face_count.max(1)).any(|index| {
            ttf_parser::Face::parse(data, index)
                .map(|face| face.glyph_index(ch).is_some())
                .unwrap_or(false)
        })
    }

    #[test]
    fn the_system_symbol_fonts_draw_the_crosses() {
        let windir = std::env::var("WINDIR").ok();
        let fonts: Vec<Vec<u8>> = symbol_font_candidates(windir.as_deref())
            .into_iter()
            .filter_map(|path| std::fs::read(path).ok())
            .collect();
        if fonts.is_empty() {
            // No symbol font on this machine: nothing to check.
            return;
        }
        let crosses = [
            '\u{2020}', '\u{2021}', '\u{2626}', '\u{2628}', '\u{2629}', '\u{271d}', '\u{271e}',
            '\u{271f}', '\u{2720}',
        ];
        for ch in crosses {
            let drawn = fonts.iter().any(|data| {
                let count = ttf_parser::fonts_in_collection(data).unwrap_or(1);
                font_has_glyph(data, count, ch)
            });
            assert!(drawn, "no system symbol font draws U+{:04X}", ch as u32);
        }
    }

    #[test]
    fn the_fallback_scripts_are_valid_codes() {
        for script in FALLBACK_SCRIPTS {
            assert!(script.iter().all(u8::is_ascii_alphabetic), "{script:?}");
        }
    }
}
