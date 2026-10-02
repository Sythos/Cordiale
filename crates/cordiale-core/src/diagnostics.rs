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

//! The text of the Debug page: what a user can paste into a bug report.
//!
//! Gathering the values is the GUI's job (they come from the operating
//! system and the window); this module only lays them out. A value that
//! couldn't be determined is `None` and prints as "Not available": it is
//! never guessed. The text never carries secrets, account names, hostnames,
//! addresses or full personal paths.

use std::fmt::Write;

/// What the page prints for a value the platform can't provide.
pub const NOT_AVAILABLE: &str = "Not available";

/// Everything the report lists, as the platform reported it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Diagnostics {
    pub version: String,
    pub build: String,
    /// The operating system and CPU architecture Cordiale was built for.
    pub executable: String,
    pub graphics: Option<String>,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub cpu_arch: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<usize>,
    pub memory_total: Option<u64>,
    pub memory_available: Option<u64>,
    /// Chat rows Cordiale holds in memory, over all windows.
    pub chat_rows_total: Option<usize>,
    /// Chat rows in the window that holds the most.
    pub chat_rows_largest: Option<usize>,
    /// Width and height of the display, in physical pixels.
    pub display_size: Option<(u32, u32)>,
    pub scale_factor: Option<f32>,
    pub windowing_system: Option<String>,
    pub system_locale: Option<String>,
    pub app_language: Option<String>,
    pub keyboard_layout: Option<String>,
    pub input_method: Option<String>,
    pub local_time: Option<String>,
    pub time_zone: Option<String>,
    /// Where Cordiale keeps its settings: the home folder is written `~`
    /// (`%APPDATA%` on Windows).
    pub data_dir: String,
    pub log_file: String,
    /// The log as it was before the last rotation.
    pub previous_log_file: String,
    /// A problem with where the files are kept, when there is one.
    pub storage_note: Option<String>,
}

impl Diagnostics {
    /// The report, one `Label: value` line per entry, related entries
    /// grouped by blank lines.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "Cordiale {} (build {})", self.version, self.build);
        line(&mut out, "Executable", Some(&self.executable));
        line(&mut out, "Graphics", self.graphics.as_deref());

        out.push('\n');
        line(&mut out, "Operating system", self.os.as_deref());
        line(&mut out, "Kernel or build", self.kernel.as_deref());
        line(&mut out, "CPU architecture", self.cpu_arch.as_deref());
        line(&mut out, "CPU model", self.cpu_model.as_deref());
        line(
            &mut out,
            "CPU logical cores",
            self.cpu_cores.map(|cores| cores.to_string()).as_deref(),
        );
        line(
            &mut out,
            "Memory total",
            self.memory_total.map(format_memory).as_deref(),
        );
        line(
            &mut out,
            "Memory available",
            self.memory_available.map(format_memory).as_deref(),
        );
        line(
            &mut out,
            "Chat rows held (all windows)",
            self.chat_rows_total.map(|rows| rows.to_string()).as_deref(),
        );
        line(
            &mut out,
            "Chat rows held (largest window)",
            self.chat_rows_largest
                .map(|rows| rows.to_string())
                .as_deref(),
        );

        out.push('\n');
        line(
            &mut out,
            "Display resolution",
            self.display_size
                .map(|(width, height)| format!("{width}x{height} px"))
                .as_deref(),
        );
        line(
            &mut out,
            "Display scale factor",
            self.scale_factor.map(format_scale).as_deref(),
        );
        line(
            &mut out,
            "Windowing system",
            self.windowing_system.as_deref(),
        );

        out.push('\n');
        line(&mut out, "System locale", self.system_locale.as_deref());
        line(
            &mut out,
            "System language",
            self.system_locale
                .as_deref()
                .and_then(language_of_locale)
                .as_deref(),
        );
        line(&mut out, "Cordiale language", self.app_language.as_deref());
        // What Cordiale itself reads, writes and draws; deliberately apart
        // from the locale and from the keyboard lines below.
        line(&mut out, "Text encoding (Cordiale)", Some("UTF-8"));
        line(&mut out, "Keyboard layout", self.keyboard_layout.as_deref());
        line(&mut out, "Input method", self.input_method.as_deref());

        out.push('\n');
        line(&mut out, "Local time", self.local_time.as_deref());
        line(&mut out, "Time zone", self.time_zone.as_deref());

        out.push('\n');
        line(&mut out, "Data folder", Some(&self.data_dir));
        line(&mut out, "Log file", Some(&self.log_file));
        line(&mut out, "Previous log file", Some(&self.previous_log_file));
        if let Some(note) = &self.storage_note {
            line(&mut out, "Storage note", Some(note));
        }

        // No trailing newline: what gets copied is exactly the lines.
        out.truncate(out.trim_end().len());
        out
    }
}

/// One `label: value` line; an absent or blank value is "Not available".
fn line(out: &mut String, label: &str, value: Option<&str>) {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(NOT_AVAILABLE);
    let _ = writeln!(out, "{label}: {value}");
}

/// Bytes as GiB with one decimal, the way RAM is usually quoted.
pub fn format_memory(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / (1u64 << 30) as f64)
}

/// A display scale factor with at least one decimal: `1.0`, `1.5`, `1.25`.
pub fn format_scale(scale: f32) -> String {
    let mut text = format!("{scale:.2}");
    if text.ends_with('0') {
        text.pop();
    }
    text
}

/// The language part of a system locale (`it_IT.UTF-8` or `it-IT` give
/// `it`), `None` for `C`, `POSIX` or anything that isn't a language code.
pub fn language_of_locale(locale: &str) -> Option<String> {
    let tag = locale.split(['.', '@']).next()?;
    let language = tag.split(['_', '-']).next()?;
    let valid =
        (2..=3).contains(&language.len()) && language.chars().all(|c| c.is_ascii_alphabetic());
    valid.then(|| language.to_ascii_lowercase())
}

/// The graphics line from what Slint exposes: the window backend and the
/// renderer, whichever are known.
pub fn describe_graphics(backend: Option<&str>, renderer: Option<&str>) -> Option<String> {
    match (backend, renderer) {
        (Some(backend), Some(renderer)) => Some(format!("{backend} backend, {renderer} renderer")),
        (Some(backend), None) => Some(format!("{backend} backend")),
        (None, Some(renderer)) => Some(format!("{renderer} renderer")),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> Diagnostics {
        Diagnostics {
            version: "0.1.13".into(),
            build: "42".into(),
            executable: "linux x86_64".into(),
            graphics: Some("winit backend, femtovg (OpenGL) renderer".into()),
            os: Some("Linux (Ubuntu 24.04)".into()),
            kernel: Some("6.8.0-48-generic".into()),
            cpu_arch: Some("x86_64".into()),
            cpu_model: Some("Example CPU @ 3.00GHz".into()),
            cpu_cores: Some(8),
            memory_total: Some(16 << 30),
            memory_available: Some(10 << 30),
            chat_rows_total: Some(12_345),
            chat_rows_largest: Some(5_000),
            display_size: Some((2560, 1440)),
            scale_factor: Some(1.5),
            windowing_system: Some("Wayland".into()),
            system_locale: Some("it_IT.UTF-8".into()),
            app_language: Some("it".into()),
            keyboard_layout: Some("it".into()),
            input_method: Some("ibus".into()),
            local_time: Some("2026-09-30 14:03:05 +02:00".into()),
            time_zone: Some("Europe/Rome".into()),
            data_dir: "~/.config/cordiale".into(),
            log_file: "~/.local/state/cordiale/cordiale.log".into(),
            previous_log_file: "~/.local/state/cordiale/cordiale.log.1".into(),
            storage_note: None,
        }
    }

    #[test]
    fn a_complete_report_lists_every_field() {
        let expected = "\
Cordiale 0.1.13 (build 42)
Executable: linux x86_64
Graphics: winit backend, femtovg (OpenGL) renderer

Operating system: Linux (Ubuntu 24.04)
Kernel or build: 6.8.0-48-generic
CPU architecture: x86_64
CPU model: Example CPU @ 3.00GHz
CPU logical cores: 8
Memory total: 16.0 GiB
Memory available: 10.0 GiB
Chat rows held (all windows): 12345
Chat rows held (largest window): 5000

Display resolution: 2560x1440 px
Display scale factor: 1.5
Windowing system: Wayland

System locale: it_IT.UTF-8
System language: it
Cordiale language: it
Text encoding (Cordiale): UTF-8
Keyboard layout: it
Input method: ibus

Local time: 2026-09-30 14:03:05 +02:00
Time zone: Europe/Rome

Data folder: ~/.config/cordiale
Log file: ~/.local/state/cordiale/cordiale.log
Previous log file: ~/.local/state/cordiale/cordiale.log.1";
        assert_eq!(full().render(), expected);
    }

    #[test]
    fn a_storage_problem_is_listed_after_the_log_files() {
        let report = Diagnostics {
            storage_note: Some("Could not move ~/.cordiale (disk full).".into()),
            ..full()
        }
        .render();
        assert!(
            report.ends_with(
                "Previous log file: ~/.local/state/cordiale/cordiale.log.1\n\
Storage note: Could not move ~/.cordiale (disk full)."
            ),
            "{report}"
        );
    }

    #[test]
    fn unknown_values_say_not_available() {
        let report = Diagnostics {
            version: "0.1.13".into(),
            build: "0".into(),
            executable: "windows x86_64".into(),
            data_dir: "%APPDATA%\\Cordiale".into(),
            log_file: "%LOCALAPPDATA%\\Cordiale\\cordiale.log".into(),
            previous_log_file: "%LOCALAPPDATA%\\Cordiale\\cordiale.log.1".into(),
            ..Diagnostics::default()
        }
        .render();
        let expected = "\
Cordiale 0.1.13 (build 0)
Executable: windows x86_64
Graphics: Not available

Operating system: Not available
Kernel or build: Not available
CPU architecture: Not available
CPU model: Not available
CPU logical cores: Not available
Memory total: Not available
Memory available: Not available
Chat rows held (all windows): Not available
Chat rows held (largest window): Not available

Display resolution: Not available
Display scale factor: Not available
Windowing system: Not available

System locale: Not available
System language: Not available
Cordiale language: Not available
Text encoding (Cordiale): UTF-8
Keyboard layout: Not available
Input method: Not available

Local time: Not available
Time zone: Not available

Data folder: %APPDATA%\\Cordiale
Log file: %LOCALAPPDATA%\\Cordiale\\cordiale.log
Previous log file: %LOCALAPPDATA%\\Cordiale\\cordiale.log.1";
        assert_eq!(report, expected);
    }

    #[test]
    fn blank_values_count_as_unknown() {
        let report = Diagnostics {
            cpu_model: Some("  ".into()),
            os: Some(String::new()),
            ..Diagnostics::default()
        }
        .render();
        assert!(report.contains("CPU model: Not available\n"));
        assert!(report.contains("Operating system: Not available\n"));
    }

    #[test]
    fn memory_is_shown_in_gib_with_one_decimal() {
        assert_eq!(format_memory(16 << 30), "16.0 GiB");
        assert_eq!(format_memory(8_589_934_592 + 536_870_912), "8.5 GiB");
        assert_eq!(format_memory(0), "0.0 GiB");
    }

    #[test]
    fn scale_factor_keeps_one_or_two_decimals() {
        assert_eq!(format_scale(1.0), "1.0");
        assert_eq!(format_scale(1.5), "1.5");
        assert_eq!(format_scale(1.25), "1.25");
        assert_eq!(format_scale(2.0), "2.0");
    }

    #[test]
    fn language_comes_from_the_first_part_of_the_locale() {
        assert_eq!(language_of_locale("it_IT.UTF-8").as_deref(), Some("it"));
        assert_eq!(language_of_locale("en-US").as_deref(), Some("en"));
        assert_eq!(language_of_locale("DE_de@euro").as_deref(), Some("de"));
        assert_eq!(language_of_locale("zh-Hans-CN").as_deref(), Some("zh"));
        assert_eq!(language_of_locale("fil").as_deref(), Some("fil"));
    }

    #[test]
    fn locales_without_a_language_are_unknown() {
        for locale in ["", "C", "POSIX", "C.UTF-8", "_IT", "1234"] {
            assert_eq!(language_of_locale(locale), None, "{locale:?}");
        }
    }

    #[test]
    fn graphics_line_uses_what_is_known() {
        assert_eq!(
            describe_graphics(Some("winit"), Some("software")).as_deref(),
            Some("winit backend, software renderer")
        );
        assert_eq!(
            describe_graphics(Some("winit"), None).as_deref(),
            Some("winit backend")
        );
        assert_eq!(
            describe_graphics(None, Some("software")).as_deref(),
            Some("software renderer")
        );
        assert_eq!(describe_graphics(None, None), None);
    }
}
