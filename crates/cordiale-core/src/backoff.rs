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

//! Pacing of WebSocket reconnect attempts, and the server's own "wait this
//! long" hints (`Retry-After`, `retry_after_ms`).
//!
//! Everything here is a pure function of its inputs: the random source and
//! the clock are passed in, so the tests don't sleep and don't depend on
//! luck. `session.rs` supplies the real ones.
//!
//! The numbers are Cordiale's own choice, not the server's (the contract
//! fixes no reconnect timing): 1 s, 2 s, 4 s ... up to 60 s, each spread by
//! plus or minus 25 % so that clients dropped by the same outage don't all
//! come back on the same beat.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

/// The wait before the first retry; every further failure doubles it.
pub const BASE_DELAY: Duration = Duration::from_secs(1);
/// The nominal wait stops growing here (the jitter can still add a quarter).
pub const MAX_DELAY: Duration = Duration::from_secs(60);
/// A connection has to stay up this long before the next drop is treated as
/// a fresh outage: a join that is accepted and then closed right away must
/// not reset the growth.
pub const STABLE_AFTER: Duration = Duration::from_secs(30);
/// The longest `Retry-After` honoured. A proxy asking for more is asking for
/// something a desktop client shouldn't sit through unannounced.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);
/// Fraction of the nominal delay the jitter spreads over, either side.
const JITTER: f64 = 0.25;
/// `BASE_DELAY << MAX_DOUBLINGS` is past `MAX_DELAY`, so more doublings only
/// risk an overflow.
const MAX_DOUBLINGS: u32 = 6;

/// How many times in a row a connection attempt has failed, and so how long
/// the next wait is.
#[derive(Debug, Default)]
pub struct Backoff {
    failures: u32,
}

impl Backoff {
    /// The wait before the next attempt, after a connection (or an attempt
    /// at one) ended. `up_for` is how long the last connection stayed
    /// established, `Duration::ZERO` when it never got that far. `unit` is a
    /// random number in `[0, 1)`. A server hint (`retry_after`) is a floor:
    /// the wait is never shorter than the hint (nor longer than
    /// `MAX_RETRY_AFTER` because of it), and the hint gets up to a quarter
    /// more on top, so a crowd told "wait 30 s" doesn't return in the same
    /// second.
    pub fn next_delay(
        &mut self,
        up_for: Duration,
        retry_after: Option<Duration>,
        unit: f64,
    ) -> Duration {
        if up_for >= STABLE_AFTER {
            self.failures = 0;
        }
        let backoff = jittered(nominal_delay(self.failures), unit);
        self.failures = self.failures.saturating_add(1);
        match retry_after {
            Some(hint) => {
                let hint = spread_upwards(hint.min(MAX_RETRY_AFTER), unit);
                backoff.max(hint.min(MAX_RETRY_AFTER))
            }
            None => backoff,
        }
    }
}

/// The delay before jitter after `failures` failed attempts in a row: 1 s,
/// 2 s, 4 s ... capped at `MAX_DELAY`.
pub fn nominal_delay(failures: u32) -> Duration {
    BASE_DELAY
        .saturating_mul(1 << failures.min(MAX_DOUBLINGS))
        .min(MAX_DELAY)
}

/// `nominal` scaled by a factor between 0.75 and 1.25, picked by `unit`
/// (`0.0` is the shortest, `1.0` the longest). Anything that isn't a number
/// in `[0, 1]` is clamped, or taken as the middle.
pub fn jittered(nominal: Duration, unit: f64) -> Duration {
    nominal.mul_f64(1.0 - JITTER + 2.0 * JITTER * sane_unit(unit))
}

fn spread_upwards(wait: Duration, unit: f64) -> Duration {
    wait.mul_f64(1.0 + JITTER * sane_unit(unit))
}

fn sane_unit(unit: f64) -> f64 {
    if unit.is_finite() {
        unit.clamp(0.0, 1.0)
    } else {
        0.5
    }
}

/// A random number in `[0, 1)` from the standard library's per-process
/// random hasher keys: no need for a dependency just to spread out retries.
pub fn random_unit() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    let bits = RandomState::new().hash_one(nanos);
    // The top 53 bits fill an f64 mantissa exactly.
    (bits >> 11) as f64 / (1u64 << 53) as f64
}

/// Reads a `Retry-After` header value: a whole number of seconds, or an HTTP
/// date (`Sun, 06 Nov 1994 08:49:37 GMT`, the form servers are required to
/// send) counted from `now`. A date already past means "now"; anything else
/// that doesn't parse is `None`.
pub fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.parse().ok().map(Duration::from_secs);
    }
    let when = parse_http_date(value)?;
    Some(when.duration_since(now).unwrap_or(Duration::ZERO))
}

/// The wait a rate-limited answer asks for: the `Retry-After` header when
/// there is one, else the body's `retry_after_ms` (Grappa's `429
/// rate_limited`, and the error reply to a WS verb). `body` is the JSON
/// object that holds `retry_after_ms`.
pub fn rate_limit_wait(
    header: Option<&str>,
    body: Option<&Value>,
    now: SystemTime,
) -> Option<Duration> {
    header
        .and_then(|value| parse_retry_after(value, now))
        .or_else(|| {
            body?
                .get("retry_after_ms")?
                .as_u64()
                .map(Duration::from_millis)
        })
}

/// How long to tell the user to wait: whole seconds, rounded up, at least 1.
pub fn display_seconds(wait: Duration) -> u64 {
    (wait.as_millis().div_ceil(1000) as u64).max(1)
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Parses the preferred HTTP date form (IMF-fixdate). The obsolete RFC 850
/// and `asctime` forms are not accepted.
fn parse_http_date(value: &str) -> Option<SystemTime> {
    let mut parts = value.split_whitespace();
    let _weekday = parts.next()?;
    let day: u32 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let month = MONTHS.iter().position(|name| *name == month_name)? as u32 + 1;
    let year: i64 = parts.next()?.parse().ok()?;
    let clock = parts.next()?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    let mut fields = clock.split(':');
    let hour: i64 = fields.next()?.parse().ok()?;
    let minute: i64 = fields.next()?.parse().ok()?;
    let second: i64 = fields.next()?.parse().ok()?;
    if fields.next().is_some()
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds)
        .ok()
        .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))
}

/// Days from 1970-01-01 to the given proleptic Gregorian date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = (i64::from(month) + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    #[test]
    fn nominal_delay_doubles_up_to_the_cap() {
        let delays: Vec<u64> = (0..9).map(|n| nominal_delay(n).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(nominal_delay(u32::MAX), MAX_DELAY);
    }

    #[test]
    fn jitter_spreads_a_quarter_either_way() {
        let nominal = secs(8);
        assert_eq!(jittered(nominal, 0.0), secs(6));
        assert_eq!(jittered(nominal, 0.5), secs(8));
        assert_eq!(jittered(nominal, 1.0), secs(10));
        assert!(jittered(nominal, 0.25) < jittered(nominal, 0.75));
    }

    #[test]
    fn jitter_survives_an_unusable_random_number() {
        assert_eq!(jittered(secs(8), -3.0), secs(6));
        assert_eq!(jittered(secs(8), 7.0), secs(10));
        assert_eq!(jittered(secs(8), f64::NAN), secs(8));
        assert_eq!(jittered(secs(8), f64::INFINITY), secs(8));
    }

    #[test]
    fn the_real_random_source_stays_in_range() {
        for _ in 0..100 {
            let unit = random_unit();
            assert!((0.0..1.0).contains(&unit), "{unit}");
        }
    }

    #[test]
    fn failures_in_a_row_grow_the_delay() {
        let mut backoff = Backoff::default();
        let waits: Vec<u64> = (0..8)
            .map(|_| backoff.next_delay(Duration::ZERO, None, 0.5).as_secs())
            .collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 32, 60, 60]);
    }

    #[test]
    fn a_connection_that_stayed_up_resets_the_growth() {
        let mut backoff = Backoff::default();
        for _ in 0..4 {
            backoff.next_delay(Duration::ZERO, None, 0.5);
        }
        assert_eq!(backoff.next_delay(STABLE_AFTER, None, 0.5), SECOND);
        assert_eq!(backoff.next_delay(Duration::ZERO, None, 0.5), secs(2));
    }

    #[test]
    fn a_short_lived_connection_does_not_reset_the_growth() {
        let mut backoff = Backoff::default();
        for _ in 0..3 {
            backoff.next_delay(Duration::ZERO, None, 0.5);
        }
        let just_short = STABLE_AFTER - Duration::from_millis(1);
        assert_eq!(backoff.next_delay(just_short, None, 0.5), secs(8));
    }

    #[test]
    fn a_server_hint_is_a_floor() {
        let mut backoff = Backoff::default();
        // The hint is longer than the backoff: it wins, spread upwards only.
        let wait = backoff.next_delay(Duration::ZERO, Some(secs(30)), 0.0);
        assert_eq!(wait, secs(30));
        let wait = backoff.next_delay(Duration::ZERO, Some(secs(30)), 1.0);
        assert_eq!(wait, Duration::from_millis(37_500));
        // The hint is shorter than the backoff: the backoff wins.
        let mut backoff = Backoff::default();
        for _ in 0..5 {
            backoff.next_delay(Duration::ZERO, None, 0.5);
        }
        assert_eq!(
            backoff.next_delay(Duration::ZERO, Some(secs(2)), 0.5),
            secs(32)
        );
    }

    #[test]
    fn a_huge_server_hint_is_capped() {
        let mut backoff = Backoff::default();
        let wait = backoff.next_delay(Duration::ZERO, Some(secs(86_400)), 0.0);
        assert_eq!(wait, MAX_RETRY_AFTER);
        let wait = backoff.next_delay(Duration::ZERO, Some(Duration::MAX), 0.0);
        assert_eq!(wait, MAX_RETRY_AFTER);
    }

    #[test]
    fn retry_after_reads_delta_seconds() {
        let now = UNIX_EPOCH;
        assert_eq!(parse_retry_after("42", now), Some(secs(42)));
        assert_eq!(parse_retry_after(" 0 ", now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("-1", now), None);
        assert_eq!(parse_retry_after("1.5", now), None);
        assert_eq!(parse_retry_after("", now), None);
        assert_eq!(parse_retry_after("soon", now), None);
        // Too large for a u64 is not a number we can use.
        assert_eq!(parse_retry_after("99999999999999999999999", now), None);
    }

    #[test]
    fn retry_after_reads_an_http_date_against_the_given_clock() {
        // 784111777 s after the epoch is the RFC 9110 example date.
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        let now = UNIX_EPOCH + secs(784_111_777 - 90);
        assert_eq!(parse_retry_after(date, now), Some(secs(90)));
        // A date that has passed means retry now.
        let later = UNIX_EPOCH + secs(784_111_777 + 5);
        assert_eq!(parse_retry_after(date, later), Some(Duration::ZERO));
    }

    #[test]
    fn http_dates_cover_leap_years_and_the_epoch() {
        let at = |value: &str| {
            parse_http_date(value)
                .expect("date")
                .duration_since(UNIX_EPOCH)
                .expect("after the epoch")
                .as_secs()
        };
        assert_eq!(at("Thu, 01 Jan 1970 00:00:00 GMT"), 0);
        assert_eq!(at("Thu, 01 Mar 2001 00:00:00 GMT"), 983_404_800);
        assert_eq!(at("Tue, 29 Feb 2000 12:00:00 GMT"), 951_825_600);
        assert_eq!(at("Mon, 31 Dec 2029 23:59:59 GMT"), 1_893_455_999);
    }

    #[test]
    fn malformed_http_dates_are_refused() {
        let now = UNIX_EPOCH;
        for value in [
            "Sun, 06 Nov 1994 08:49:37",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Nov 1994 08:49:37 GMT extra",
            "Sun, 06 Nov 1994 25:49:37 GMT",
            "Sun, 06 Nov 1994 08:61:37 GMT",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sun, 00 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nuv 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Mon, 01 Jan 1900 00:00:00 GMT",
        ] {
            assert_eq!(parse_retry_after(value, now), None, "{value}");
        }
    }

    #[test]
    fn rate_limit_wait_prefers_the_header_over_the_body() {
        let now = UNIX_EPOCH;
        let body = serde_json::json!({"error": "rate_limited", "retry_after_ms": 1500});
        assert_eq!(rate_limit_wait(Some("7"), Some(&body), now), Some(secs(7)));
        assert_eq!(
            rate_limit_wait(None, Some(&body), now),
            Some(Duration::from_millis(1500))
        );
        // A header that doesn't parse falls back to the body.
        assert_eq!(
            rate_limit_wait(Some("later"), Some(&body), now),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(rate_limit_wait(None, None, now), None);
        let bare = serde_json::json!({"error": "rate_limited"});
        assert_eq!(rate_limit_wait(None, Some(&bare), now), None);
        let odd = serde_json::json!({"retry_after_ms": "soon"});
        assert_eq!(rate_limit_wait(None, Some(&odd), now), None);
    }

    #[test]
    fn display_seconds_rounds_up_and_never_shows_zero() {
        assert_eq!(display_seconds(Duration::ZERO), 1);
        assert_eq!(display_seconds(Duration::from_millis(1)), 1);
        assert_eq!(display_seconds(Duration::from_millis(1000)), 1);
        assert_eq!(display_seconds(Duration::from_millis(1001)), 2);
        assert_eq!(display_seconds(secs(45)), 45);
    }
}
