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

/// Monochrome emoji font (OpenMoji Black, licence CC BY-SA 4.0). It covers the
/// emoji of Unicode 17 and 18 that old system emoji fonts do not have. The
/// licence and the source are in `assets/fonts`.
const EMOJI_FONT: &[u8] = include_bytes!("../assets/fonts/OpenMoji-black-glyf.ttf");

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
    install_fallback_fonts(
        &mut collection,
        &symbol_font_candidates(windows_dir.as_deref()),
    );
}

/// Registers the font files that exist and the bundled emoji font in the
/// collection. Then adds all of them to the end of the fallback lists.
fn install_fallback_fonts(collection: &mut fontique::Collection, system_fonts: &[PathBuf]) {
    let mut families = Vec::new();
    for path in system_fonts {
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
    // The bundled emoji font is the last fallback: it covers the systems that
    // have no emoji font, or an old one.
    let blob = fontique::Blob::new(std::sync::Arc::new(EMOJI_FONT));
    for (family, _) in collection.register_fonts(blob, None) {
        if !families.contains(&family) {
            families.push(family);
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
    fn the_bundled_emoji_font_draws_the_new_emoji() {
        let face = ttf_parser::Face::parse(EMOJI_FONT, 0).expect("bundled font parses");
        for ch in ['\u{1FAEB}', '\u{1FADD}', '\u{1F600}'] {
            assert!(face.glyph_index(ch).is_some(), "U+{:04X}", ch as u32);
        }
    }

    #[test]
    fn the_emoji_font_is_in_every_fallback_list_without_system_fonts() {
        // A clean collection has no system font: this is the worst case, and
        // it is the same on Windows, macOS and Linux.
        let mut collection = fontique::Collection::new(fontique::CollectionOptions {
            shared: false,
            system_fonts: false,
        });
        install_fallback_fonts(&mut collection, &[]);
        for script in FALLBACK_SCRIPTS {
            let key = fontique::FallbackKey::new(fontique::Script::from_bytes(script), None);
            let ids: Vec<_> = collection.fallback_families(key).collect();
            let names: Vec<String> = ids
                .into_iter()
                .filter_map(|id| collection.family_name(id).map(str::to_owned))
                .collect();
            assert!(
                names.iter().any(|name| name.contains("OpenMoji")),
                "{script:?}: {names:?}"
            );
        }
    }

    #[test]
    fn installing_the_fonts_twice_does_not_repeat_a_family() {
        let mut collection = fontique::Collection::new(fontique::CollectionOptions {
            shared: false,
            system_fonts: false,
        });
        install_fallback_fonts(&mut collection, &[]);
        install_fallback_fonts(&mut collection, &[]);
        let key = fontique::FallbackKey::new(fontique::Script::from_bytes(*b"Zyyy"), None);
        let ids: Vec<_> = collection.fallback_families(key).collect();
        let mut unique = ids.clone();
        unique.dedup();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn the_picker_data_keeps_the_new_emoji_unchanged() {
        for (ch, name) in [('\u{1FAEB}', "cracking face"), ('\u{1FADD}', "pickle")] {
            let text = ch.to_string();
            let emoji = emojis::get(&text).unwrap_or_else(|| panic!("{name} is in the data"));
            assert_eq!(emoji.as_str(), text, "{name}");
        }
    }

    #[test]
    fn the_fallback_scripts_are_valid_codes() {
        for script in FALLBACK_SCRIPTS {
            assert!(script.iter().all(u8::is_ascii_alphabetic), "{script:?}");
        }
    }
}
