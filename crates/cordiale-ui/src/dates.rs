// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)
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

//! The one place Cordiale renders a date, per Grappa's
//! `display_prefs.date_format` (protocol v29) — Cicchetto's `dateFormat.ts`.
//!
//! The preference governs field ORDER only, never language. The three
//! explicit keys are built from the date's own fields, so they come out the
//! same whatever the interface language. `auto` follows the viewer's
//! locale: Cordiale's interface language, and for English the region of
//! `LC_ALL`/`LC_TIME`/`LANG` when the system sets one. Without a region the
//! floor is day-first (`en-GB`), as in Cicchetto, never month-first.

use std::sync::atomic::{AtomicU8, Ordering};

use chrono::{DateTime, Datelike, Local, NaiveDate, Weekday};
use cordiale_core::persistence::Language;
use cordiale_core::rest::DateFormat;

/// How `auto` lays a date out for the current locale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AutoStyle {
    /// `20/09/2026` (en-GB, it, fr, es).
    DaySlash,
    /// `20.09.2026` (de).
    DayDot,
    /// `09/20/2026` (en-US).
    MonthSlash,
}

static FORMAT: AtomicU8 = AtomicU8::new(0);
static AUTO_STYLE: AtomicU8 = AtomicU8::new(0);
static LANGUAGE: AtomicU8 = AtomicU8::new(0);

fn format_index(format: DateFormat) -> u8 {
    match format {
        DateFormat::Auto => 0,
        DateFormat::Dmy => 1,
        DateFormat::Mdy => 2,
        DateFormat::Ymd => 3,
    }
}

fn style_index(style: AutoStyle) -> u8 {
    match style {
        AutoStyle::DaySlash => 0,
        AutoStyle::DayDot => 1,
        AutoStyle::MonthSlash => 2,
    }
}

/// The preference in force; `None` (absent from the server) is `auto`.
pub(crate) fn set_format(format: Option<DateFormat>) {
    FORMAT.store(format_index(format.unwrap_or_default()), Ordering::Relaxed);
}

pub(crate) fn current_format() -> DateFormat {
    DateFormat::ALL[usize::from(FORMAT.load(Ordering::Relaxed)).min(3)]
}

/// Re-resolves `auto` after the interface language changes.
pub(crate) fn set_language(language: Option<Language>) {
    LANGUAGE.store(language_index(language), Ordering::Relaxed);
    let style = auto_style(language, &system_locale());
    AUTO_STYLE.store(style_index(style), Ordering::Relaxed);
}

fn language_index(language: Option<Language>) -> u8 {
    match language {
        None | Some(Language::En) => 0,
        Some(Language::It) => 1,
        Some(Language::Fr) => 2,
        Some(Language::De) => 3,
        Some(Language::Es) => 4,
    }
}

fn current_language() -> Option<Language> {
    match LANGUAGE.load(Ordering::Relaxed) {
        1 => Some(Language::It),
        2 => Some(Language::Fr),
        3 => Some(Language::De),
        4 => Some(Language::Es),
        _ => None,
    }
}

fn current_auto_style() -> AutoStyle {
    match AUTO_STYLE.load(Ordering::Relaxed) {
        1 => AutoStyle::DayDot,
        2 => AutoStyle::MonthSlash,
        _ => AutoStyle::DaySlash,
    }
}

/// `LC_ALL`, then `LC_TIME`, then `LANG`, like the C library; "" when none
/// is set (as on Windows).
fn system_locale() -> String {
    ["LC_ALL", "LC_TIME", "LANG"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

/// `auto`'s layout for an interface language. English defers to the
/// system region: month-first only where that region writes it so.
pub(crate) fn auto_style(language: Option<Language>, system_locale: &str) -> AutoStyle {
    match language {
        Some(Language::De) => AutoStyle::DayDot,
        Some(Language::It | Language::Fr | Language::Es) => AutoStyle::DaySlash,
        Some(Language::En) | None => {
            let region = system_locale
                .split(['.', '@'])
                .next()
                .and_then(|tag| tag.split(['_', '-']).nth(1))
                .unwrap_or("");
            if matches!(
                region,
                "US" | "PH" | "FM" | "MH" | "PW" | "AS" | "GU" | "MP" | "PR" | "UM" | "VI"
            ) {
                AutoStyle::MonthSlash
            } else {
                AutoStyle::DaySlash
            }
        }
    }
}

/// The date half, per `format` (and `style` for `auto`).
pub(crate) fn render_date_with<D: Datelike>(
    date: &D,
    format: DateFormat,
    style: AutoStyle,
) -> String {
    let (day, month, year) = (date.day(), date.month(), date.year());
    match format {
        DateFormat::Dmy => format!("{day:02}/{month:02}/{year:04}"),
        DateFormat::Mdy => format!("{month:02}/{day:02}/{year:04}"),
        DateFormat::Ymd => format!("{year:04}-{month:02}-{day:02}"),
        DateFormat::Auto => match style {
            AutoStyle::DaySlash => format!("{day:02}/{month:02}/{year:04}"),
            AutoStyle::DayDot => format!("{day:02}.{month:02}.{year:04}"),
            AutoStyle::MonthSlash => format!("{month:02}/{day:02}/{year:04}"),
        },
    }
}

/// A local date and time per the current preference; the time stays 24h,
/// with or without seconds.
pub(crate) fn render_date_time(moment: &DateTime<Local>, seconds: bool) -> String {
    let date = render_date_with(moment, current_format(), current_auto_style());
    let time = if seconds {
        moment.format("%H:%M:%S")
    } else {
        moment.format("%H:%M")
    };
    format!("{date} {time}")
}

/// The local calendar date of an epoch-milliseconds timestamp, in the time
/// zone that the message times use. `None` for a value out of range.
pub(crate) fn local_date_of_millis(millis: i64) -> Option<NaiveDate> {
    DateTime::from_timestamp_millis(millis).map(|moment| moment.with_timezone(&Local).date_naive())
}

/// The weekday name in an interface language (`None` is English).
pub(crate) fn weekday_name(weekday: Weekday, language: Option<Language>) -> &'static str {
    const EN: [&str; 7] = [
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ];
    const IT: [&str; 7] = [
        "Lunedì",
        "Martedì",
        "Mercoledì",
        "Giovedì",
        "Venerdì",
        "Sabato",
        "Domenica",
    ];
    const FR: [&str; 7] = [
        "Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche",
    ];
    const DE: [&str; 7] = [
        "Montag",
        "Dienstag",
        "Mittwoch",
        "Donnerstag",
        "Freitag",
        "Samstag",
        "Sonntag",
    ];
    const ES: [&str; 7] = [
        "Lunes",
        "Martes",
        "Miércoles",
        "Jueves",
        "Viernes",
        "Sábado",
        "Domingo",
    ];
    let names = match language {
        Some(Language::It) => &IT,
        Some(Language::Fr) => &FR,
        Some(Language::De) => &DE,
        Some(Language::Es) => &ES,
        Some(Language::En) | None => &EN,
    };
    names[weekday.num_days_from_monday() as usize]
}

/// The label of a date separator: the weekday of the day that starts and
/// its date, per `format`, `style` and `language`.
pub(crate) fn separator_label_with(
    date: &NaiveDate,
    format: DateFormat,
    style: AutoStyle,
    language: Option<Language>,
) -> String {
    format!(
        "{}, {}",
        weekday_name(date.weekday(), language),
        render_date_with(date, format, style)
    )
}

/// The label of a date separator per the current preferences.
pub(crate) fn separator_label(date: &NaiveDate) -> String {
    separator_label_with(
        date,
        current_format(),
        current_auto_style(),
        current_language(),
    )
}

/// The Settings selector's live examples, one per `DateFormat::ALL` entry,
/// on today's date.
pub(crate) fn examples() -> Vec<String> {
    let today = Local::now();
    DateFormat::ALL
        .iter()
        .map(|format| render_date_with(&today, *format, current_auto_style()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 9, 7).expect("date")
    }

    #[test]
    fn explicit_formats_ignore_the_locale() {
        for style in [
            AutoStyle::DaySlash,
            AutoStyle::DayDot,
            AutoStyle::MonthSlash,
        ] {
            assert_eq!(
                render_date_with(&day(), DateFormat::Dmy, style),
                "07/09/2026"
            );
            assert_eq!(
                render_date_with(&day(), DateFormat::Mdy, style),
                "09/07/2026"
            );
            assert_eq!(
                render_date_with(&day(), DateFormat::Ymd, style),
                "2026-09-07"
            );
        }
    }

    #[test]
    fn auto_follows_the_resolved_locale() {
        assert_eq!(
            render_date_with(&day(), DateFormat::Auto, AutoStyle::DaySlash),
            "07/09/2026"
        );
        assert_eq!(
            render_date_with(&day(), DateFormat::Auto, AutoStyle::DayDot),
            "07.09.2026"
        );
        assert_eq!(
            render_date_with(&day(), DateFormat::Auto, AutoStyle::MonthSlash),
            "09/07/2026"
        );
    }

    #[test]
    fn auto_style_by_language_and_region() {
        assert_eq!(
            auto_style(Some(Language::It), "en_US.UTF-8"),
            AutoStyle::DaySlash
        );
        assert_eq!(auto_style(Some(Language::De), ""), AutoStyle::DayDot);
        assert_eq!(
            auto_style(Some(Language::En), "en_US.UTF-8"),
            AutoStyle::MonthSlash
        );
        assert_eq!(
            auto_style(Some(Language::En), "en_GB.UTF-8"),
            AutoStyle::DaySlash
        );
        assert_eq!(
            auto_style(Some(Language::En), "it_IT@euro"),
            AutoStyle::DaySlash
        );
        // No region at all: the day-first floor, never month-first.
        assert_eq!(auto_style(Some(Language::En), ""), AutoStyle::DaySlash);
        assert_eq!(auto_style(None, "C"), AutoStyle::DaySlash);
    }

    #[test]
    fn an_absent_preference_is_auto() {
        set_format(None);
        assert_eq!(current_format(), DateFormat::Auto);
        set_format(Some(DateFormat::Ymd));
        assert_eq!(current_format(), DateFormat::Ymd);
        set_format(None);
    }

    #[test]
    fn separator_label_has_a_localized_weekday_and_the_configured_date() {
        let friday = NaiveDate::from_ymd_opt(2026, 11, 13).expect("date");
        let label =
            |format, language| separator_label_with(&friday, format, AutoStyle::DaySlash, language);
        assert_eq!(
            label(DateFormat::Ymd, Some(Language::En)),
            "Friday, 2026-11-13"
        );
        assert_eq!(label(DateFormat::Ymd, None), "Friday, 2026-11-13");
        assert_eq!(
            label(DateFormat::Dmy, Some(Language::It)),
            "Venerdì, 13/11/2026"
        );
        assert_eq!(
            label(DateFormat::Mdy, Some(Language::Fr)),
            "Vendredi, 11/13/2026"
        );
        assert_eq!(
            label(DateFormat::Ymd, Some(Language::De)),
            "Freitag, 2026-11-13"
        );
        assert_eq!(
            label(DateFormat::Dmy, Some(Language::Es)),
            "Viernes, 13/11/2026"
        );
        assert_eq!(
            separator_label_with(
                &friday,
                DateFormat::Auto,
                AutoStyle::DayDot,
                Some(Language::De)
            ),
            "Freitag, 13.11.2026"
        );
    }

    #[test]
    fn every_weekday_has_a_name_in_every_language() {
        for language in [
            None,
            Some(Language::En),
            Some(Language::It),
            Some(Language::Fr),
            Some(Language::De),
            Some(Language::Es),
        ] {
            let names: std::collections::HashSet<_> = (0..7)
                .map(|offset| {
                    let date = NaiveDate::from_ymd_opt(2026, 11, 9 + offset).expect("date");
                    weekday_name(date.weekday(), language)
                })
                .collect();
            assert_eq!(names.len(), 7);
        }
    }

    #[test]
    fn local_date_follows_the_local_time_zone_near_midnight() {
        use chrono::TimeZone as _;
        let late = Local
            .with_ymd_and_hms(2026, 11, 13, 23, 59, 59)
            .single()
            .expect("time");
        let early = Local
            .with_ymd_and_hms(2026, 11, 14, 0, 0, 1)
            .single()
            .expect("time");
        assert_eq!(
            local_date_of_millis(late.timestamp_millis()),
            NaiveDate::from_ymd_opt(2026, 11, 13)
        );
        assert_eq!(
            local_date_of_millis(early.timestamp_millis()),
            NaiveDate::from_ymd_opt(2026, 11, 14)
        );
    }
}
