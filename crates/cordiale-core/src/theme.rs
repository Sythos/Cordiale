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

/// The font tokens a theme may name, in the editor's menu order.
pub const FONT_FAMILIES: [&str; 8] = [
    "mono-default",
    "jetbrains-mono",
    "fira-code",
    "iosevka",
    "hack",
    "cascadia-code",
    "source-code-pro",
    "ibm-plex-mono",
];

/// `#rrggbb`, the form Grappa stores.
pub fn to_hex((r, g, b): Rgb) -> String {
    format!("#{r:02x}{g:02x}{b:02x}")
}

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

    /// The 27 colors in wire order: the base keys, then `nick_0`..`nick_15`.
    pub fn color_entries(&self) -> Vec<(String, Rgb)> {
        let base = [
            self.bg,
            self.bg_alt,
            self.fg,
            self.accent,
            self.muted,
            self.border,
            self.mention,
            self.mode_op,
            self.mode_halfop,
            self.mode_voiced,
            self.mode_plain,
        ];
        BASE_COLOR_KEYS
            .iter()
            .map(|key| key.to_string())
            .zip(base)
            .chain(
                self.nicks
                    .iter()
                    .enumerate()
                    .map(|(index, rgb)| (format!("nick_{index}"), *rgb)),
            )
            .collect()
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

    /// The theme's `muted` color as secondary text: nudged toward the
    /// foreground until it reads at 4.5:1 on the background, and left
    /// alone when it already does. A foreground that cannot reach 4.5:1
    /// itself is replaced as the target by white or black, so the muted
    /// text is still legible (if no longer dimmer than the body text).
    pub fn muted_text(&self) -> Rgb {
        let target = if contrast_ratio(self.fg, self.bg) >= MIN_TEXT_CONTRAST {
            self.fg
        } else if self.is_dark() {
            (255, 255, 255)
        } else {
            (0, 0, 0)
        };
        nudge_for_contrast(self.muted, target, self.bg, MIN_TEXT_CONTRAST)
    }
}

/// The WCAG AA contrast floor for normal-size text.
pub const MIN_TEXT_CONTRAST: f64 = 4.5;

/// WCAG 2.1 relative luminance of an sRGB color, `0.0` (black) to `1.0`.
fn relative_luminance((r, g, b): Rgb) -> f64 {
    let linear = |channel: u8| {
        let value = f64::from(channel) / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
}

/// WCAG 2.1 contrast ratio of two colors, `1.0` (identical) to `21.0`
/// (black on white), whichever one is lighter.
pub fn contrast_ratio(a: Rgb, b: Rgb) -> f64 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    let (lighter, darker) = if la >= lb { (la, lb) } else { (lb, la) };
    (lighter + 0.05) / (darker + 0.05)
}

/// `color` itself when it already reaches `min_ratio` on `background`;
/// otherwise the nearest color on the way to `toward` that does, or
/// `toward` when even that falls short. Never moves away from `toward`.
pub fn nudge_for_contrast(color: Rgb, toward: Rgb, background: Rgb, min_ratio: f64) -> Rgb {
    if contrast_ratio(color, background) >= min_ratio {
        return color;
    }
    const STEPS: u32 = 100;
    let blend = |from: u8, to: u8, amount: f64| {
        (f64::from(from) + (f64::from(to) - f64::from(from)) * amount).round() as u8
    };
    for step in 1..=STEPS {
        let amount = f64::from(step) / f64::from(STEPS);
        let candidate = (
            blend(color.0, toward.0, amount),
            blend(color.1, toward.1, amount),
            blend(color.2, toward.2, amount),
        );
        if contrast_ratio(candidate, background) >= min_ratio {
            return candidate;
        }
    }
    toward
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
    fn palette_round_trips_through_its_color_entries() {
        let palette = builtin_theme("sux").expect("sux").palette();
        let entries = palette.color_entries();
        assert_eq!(entries.len(), 27);
        assert_eq!(entries[0].0, "bg");
        assert_eq!(entries[11].0, "nick_0");
        let colors: HashMap<String, String> = entries
            .iter()
            .map(|(key, rgb)| (key.clone(), to_hex(*rgb)))
            .collect();
        assert_eq!(ThemePalette::from_colors(&colors), Some(palette));
        assert_eq!(to_hex((255, 0, 10)), "#ff000a");
        assert_eq!(FONT_FAMILIES[0], "mono-default");
    }

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

    fn assert_ratio(a: Rgb, b: Rgb, expected: f64) {
        let ratio = contrast_ratio(a, b);
        assert!(
            (ratio - expected).abs() < 0.01,
            "{a:?} on {b:?}: {ratio} != {expected}"
        );
    }

    #[test]
    fn contrast_ratio_matches_known_values() {
        assert_ratio((0, 0, 0), (255, 255, 255), 21.0);
        assert_ratio((255, 255, 255), (0, 0, 0), 21.0);
        assert_ratio((0x80, 0x80, 0x80), (0x1c, 0x1c, 0x1c), 4.32);
        assert_ratio((0x80, 0x80, 0x80), (0xfa, 0xfa, 0xfa), 3.78);
        assert_ratio((0x78, 0x78, 0x78), (0x0a, 0x0a, 0x0a), 4.48);
        assert_ratio((0x70, 0x70, 0x70), (0x0a, 0x0a, 0x0a), 4.00);
        assert_ratio((0x7f, 0x7f, 0x7f), (0xff, 0xff, 0xff), 4.00);
        assert_ratio((0x33, 0x33, 0x33), (0x33, 0x33, 0x33), 1.0);
    }

    #[test]
    fn nudge_leaves_a_passing_color_alone() {
        let color = (0x96, 0x96, 0x96);
        let background = (0x1c, 0x1c, 0x1c);
        assert_eq!(
            nudge_for_contrast(color, (255, 255, 255), background, MIN_TEXT_CONTRAST),
            color
        );
    }

    #[test]
    fn nudge_reaches_the_floor_without_overshooting() {
        let background = (0x0a, 0x0a, 0x0a);
        let nudged = nudge_for_contrast(
            (0x78, 0x78, 0x78),
            (0xe0, 0xe0, 0xe0),
            background,
            MIN_TEXT_CONTRAST,
        );
        assert!(contrast_ratio(nudged, background) >= MIN_TEXT_CONTRAST);
        assert!(nudged.0 > 0x78 && nudged.0 < 0xe0);
        assert!(nudged.0 < 0x90, "moved further than needed: {nudged:?}");

        let background = (0xff, 0xff, 0xff);
        let nudged =
            nudge_for_contrast((0x7f, 0x7f, 0x7f), (0, 0, 0), background, MIN_TEXT_CONTRAST);
        assert!(contrast_ratio(nudged, background) >= MIN_TEXT_CONTRAST);
        assert!(nudged.0 < 0x7f);
    }

    #[test]
    fn nudge_never_moves_away_from_its_target() {
        let cases = [
            ((0x40, 0x90, 0x50), (0xd0, 0x30, 0xe0), (0x10, 0x20, 0x30)),
            ((0x70, 0x70, 0x70), (0xe0, 0xe0, 0xe0), (0x0a, 0x0a, 0x0a)),
            ((0x93, 0xa1, 0xa1), (0x00, 0x00, 0x00), (0xfd, 0xf6, 0xe3)),
            ((0x20, 0x20, 0x20), (0xff, 0xff, 0xff), (0x00, 0x00, 0x00)),
        ];
        for (color, toward, background) in cases {
            let nudged = nudge_for_contrast(color, toward, background, MIN_TEXT_CONTRAST);
            assert!(nudged.0.abs_diff(toward.0) <= color.0.abs_diff(toward.0));
            assert!(nudged.1.abs_diff(toward.1) <= color.1.abs_diff(toward.1));
            assert!(nudged.2.abs_diff(toward.2) <= color.2.abs_diff(toward.2));
        }
    }

    #[test]
    fn nudge_stops_at_the_target_when_the_floor_is_out_of_reach() {
        let background = (0x80, 0x80, 0x80);
        let toward = (0x90, 0x90, 0x90);
        assert_eq!(
            nudge_for_contrast((0x84, 0x84, 0x84), toward, background, MIN_TEXT_CONTRAST),
            toward
        );
    }

    #[test]
    fn muted_text_is_legible_on_every_builtin_theme() {
        for theme in &BUILTIN_THEMES {
            let palette = theme.palette();
            let muted = palette.muted_text();
            assert!(
                contrast_ratio(muted, palette.bg) >= MIN_TEXT_CONTRAST,
                "{}: {muted:?}",
                theme.name
            );
        }
    }

    #[test]
    fn muted_text_keeps_a_legible_color_and_stays_dimmer_than_the_body() {
        let sux = builtin_theme("sux").expect("sux").palette();
        assert_eq!(sux.muted_text(), sux.muted);

        for name in ["irssi-dark", "mirc-light"] {
            let palette = builtin_theme(name).expect(name).palette();
            let muted = palette.muted_text();
            assert_ne!(muted, palette.muted, "{name}");
            assert!(
                contrast_ratio(muted, palette.bg) < contrast_ratio(palette.fg, palette.bg),
                "{name}"
            );
        }
    }
}
