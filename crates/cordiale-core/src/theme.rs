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

//! Color themes: Grappa's closed 27-color theme palette and built-in
//! copies of its irssi-derived gallery, used when the server offers none.

use std::collections::HashMap;

/// An sRGB color.
pub type Rgb = (u8, u8, u8);

/// The base color keys of a Grappa theme, in wire order.
pub const BASE_COLOR_KEYS: [&str; 11] = [
    "bg",
    "bg_alt",
    "fg",
    "accent",
    "muted",
    "border",
    "mention",
    "mode_op",
    "mode_halfop",
    "mode_voiced",
    "mode_plain",
];

/// A theme's full palette: the eleven base colors plus sixteen nick colors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThemePalette {
    pub bg: Rgb,
    pub bg_alt: Rgb,
    pub fg: Rgb,
    pub accent: Rgb,
    pub muted: Rgb,
    pub border: Rgb,
    pub mention: Rgb,
    pub mode_op: Rgb,
    pub mode_halfop: Rgb,
    pub mode_voiced: Rgb,
    pub mode_plain: Rgb,
    pub nicks: [Rgb; 16],
}

impl ThemePalette {
    /// Reads a Grappa theme's `colors` map. Every one of the 27 keys must
    /// be present and a valid `#rgb`/`#rrggbb` color, as the server's own
    /// sanitizer guarantees; otherwise the theme is not usable.
    pub fn from_colors(colors: &HashMap<String, String>) -> Option<Self> {
        let color = |key: &str| parse_hex(colors.get(key)?);
        let mut nicks = [(0, 0, 0); 16];
        for (index, slot) in nicks.iter_mut().enumerate() {
            *slot = color(&format!("nick_{index}"))?;
        }
        Some(ThemePalette {
            bg: color("bg")?,
            bg_alt: color("bg_alt")?,
            fg: color("fg")?,
            accent: color("accent")?,
            muted: color("muted")?,
            border: color("border")?,
            mention: color("mention")?,
            mode_op: color("mode_op")?,
            mode_halfop: color("mode_halfop")?,
            mode_voiced: color("mode_voiced")?,
            mode_plain: color("mode_plain")?,
            nicks,
        })
    }

    /// Whether the background is dark (perceived luminance below half).
    pub fn is_dark(&self) -> bool {
        let (r, g, b) = self.bg;
        0.299 * f32::from(r) + 0.587 * f32::from(g) + 0.114 * f32::from(b) < 128.0
    }

    /// The nick color for a stable hash of the nick.
    pub fn nick_color(&self, hash: u32) -> Rgb {
        self.nicks[(hash % 16) as usize]
    }
}

/// Parses `#rgb` or `#rrggbb` (case-insensitive).
pub fn parse_hex(value: &str) -> Option<Rgb> {
    let digits = value.strip_prefix('#')?;
    let channel = |text: &str| u8::from_str_radix(text, 16).ok();
    match digits.len() {
        3 => {
            let mut chars = digits.chars().map(|c| c.to_string().repeat(2));
            Some((
                channel(&chars.next()?)?,
                channel(&chars.next()?)?,
                channel(&chars.next()?)?,
            ))
        }
        6 if digits.is_ascii() => Some((
            channel(&digits[0..2])?,
            channel(&digits[2..4])?,
            channel(&digits[4..6])?,
        )),
        _ => None,
    }
}

/// A built-in theme: copies of Grappa's own gallery entries, so the same
/// irssi-style color sets exist when the server has no theme endpoints.
pub struct BuiltinTheme {
    pub name: &'static str,
    base: [&'static str; 11],
    nicks: [&'static str; 16],
}

impl BuiltinTheme {
    pub fn palette(&self) -> ThemePalette {
        let mut colors: HashMap<String, String> = BASE_COLOR_KEYS
            .iter()
            .zip(self.base)
            .map(|(key, hex)| (key.to_string(), hex.to_string()))
            .collect();
        for (index, hex) in self.nicks.iter().enumerate() {
            colors.insert(format!("nick_{index}"), hex.to_string());
        }
        ThemePalette::from_colors(&colors).expect("built-in theme colors are valid")
    }
}

const WARM_NICKS: [&str; 16] = [
    "#ff8c8c", "#ffb060", "#ffd060", "#d8e060", "#90d870", "#60d8a8", "#60d8d8", "#60b8e8",
    "#88a8ff", "#b890ff", "#e088e0", "#ff90c0", "#e0a888", "#c0c0c0", "#a0e8b8", "#f0d090",
];

/// Grappa's built-in gallery subset kept locally, irssi first.
pub static BUILTIN_THEMES: [BuiltinTheme; 5] = [
    BuiltinTheme {
        name: "irssi-dark",
        base: [
            "#0a0a0a", "#111111", "#e0e0e0", "#5fafd7", "#707070", "#1f1f1f", "#2a1f00", "#d77070",
            "#d7af5f", "#70d770", "#e0e0e0",
        ],
        nicks: WARM_NICKS,
    },
    BuiltinTheme {
        name: "sux",
        base: [
            "#000000", "#0e0e0e", "#e5e5e5", "#00d75f", "#767676", "#1c1c1c", "#2b2b00", "#ff5f5f",
            "#d7af5f", "#5fd75f", "#e5e5e5",
        ],
        nicks: WARM_NICKS,
    },
    BuiltinTheme {
        name: "mirc-light",
        base: [
            "#ffffff", "#f5f5f5", "#000000", "#00007f", "#7f7f7f", "#c0c0c0", "#fff8c0", "#7f0000",
            "#7f5f00", "#007f00", "#000000",
        ],
        nicks: [
            "#c03030", "#c06020", "#a07000", "#607000", "#207020", "#008060", "#007080", "#005090",
            "#2030a0", "#5020a0", "#800070", "#a02060", "#804020", "#404040", "#206040", "#806020",
        ],
    },
    BuiltinTheme {
        name: "solarized-dark",
        base: [
            "#002b36", "#073642", "#839496", "#268bd2", "#586e75", "#094f5c", "#164450", "#dc322f",
            "#b58900", "#859900", "#839496",
        ],
        nicks: [
            "#dc322f", "#cb4b16", "#b58900", "#859900", "#2aa198", "#268bd2", "#6c71c4", "#d33682",
            "#e07a70", "#d79a4b", "#b0c060", "#6fc0a8", "#74b0e0", "#9a8fd0", "#d777b0", "#93a1a1",
        ],
    },
    BuiltinTheme {
        name: "solarized-light",
        base: [
            "#fdf6e3", "#eee8d5", "#657b83", "#268bd2", "#93a1a1", "#ddd6c1", "#fbefc8", "#dc322f",
            "#b58900", "#859900", "#657b83",
        ],
        nicks: [
            "#dc322f", "#cb4b16", "#b58900", "#859900", "#2aa198", "#268bd2", "#6c71c4", "#d33682",
            "#a03030", "#a0601a", "#7a8500", "#1a8a80", "#1a7ac0", "#5a50b0", "#b02a70", "#586e75",
        ],
    },
];

/// The built-in theme called `name`, if any.
pub fn builtin_theme(name: &str) -> Option<&'static BuiltinTheme> {
    BUILTIN_THEMES.iter().find(|theme| theme.name == name)
}

/// The installed font family to try for a Grappa `font_family` token, per
/// platform for the default monospace; unknown tokens fall back to it too.
pub fn font_family_for(token: &str) -> &'static str {
    match token {
        "jetbrains-mono" => "JetBrains Mono",
        "fira-code" => "Fira Code",
        "iosevka" => "Iosevka",
        "hack" => "Hack",
        "cascadia-code" => "Cascadia Code",
        "source-code-pro" => "Source Code Pro",
        "ibm-plex-mono" => "IBM Plex Mono",
        _ => default_monospace_family(),
    }
}

/// A monospace family present by default on each platform.
pub fn default_monospace_family() -> &'static str {
    if cfg!(target_os = "windows") {
        "Consolas"
    } else if cfg!(target_os = "macos") {
        "Menlo"
    } else {
        "DejaVu Sans Mono"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_and_long_hex() {
        assert_eq!(parse_hex("#0a0a0a"), Some((10, 10, 10)));
        assert_eq!(parse_hex("#FFF"), Some((255, 255, 255)));
        assert_eq!(parse_hex("#abc"), Some((0xaa, 0xbb, 0xcc)));
        assert_eq!(parse_hex("0a0a0a"), None);
        assert_eq!(parse_hex("#12345"), None);
        assert_eq!(parse_hex("#gggggg"), None);
    }

    #[test]
    fn every_builtin_theme_has_a_valid_palette() {
        for theme in &BUILTIN_THEMES {
            let palette = theme.palette();
            assert_eq!(palette.nicks.len(), 16, "{}", theme.name);
        }
        assert!(builtin_theme("irssi-dark")
            .expect("irssi")
            .palette()
            .is_dark());
        assert!(builtin_theme("sux").expect("sux").palette().is_dark());
        assert!(!builtin_theme("mirc-light")
            .expect("mirc")
            .palette()
            .is_dark());
        assert!(builtin_theme("nope").is_none());
    }

    #[test]
    fn from_colors_needs_all_twenty_seven_keys() {
        let theme = builtin_theme("sux").expect("sux");
        let mut colors: HashMap<String, String> = BASE_COLOR_KEYS
            .iter()
            .zip(theme.base)
            .map(|(key, hex)| (key.to_string(), hex.to_string()))
            .collect();
        for (index, hex) in theme.nicks.iter().enumerate() {
            colors.insert(format!("nick_{index}"), hex.to_string());
        }
        let palette = ThemePalette::from_colors(&colors).expect("complete");
        assert_eq!(palette.accent, (0x00, 0xd7, 0x5f));
        assert_eq!(palette.nick_color(17), palette.nicks[1]);

        colors.remove("nick_15");
        assert_eq!(ThemePalette::from_colors(&colors), None);
    }
}
