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

//! Remembers the window geometry and the two column widths between runs.
//!
//! The data lives in the local `settings.json` (`Settings::window`) and
//! never leaves the device. The arithmetic is in plain functions, so the
//! tests need no window: what a host cannot read or set (the position on
//! Wayland, for example) is a missing value that is skipped silently.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use cordiale_core::persistence::{self, WindowState};
use slint::winit_030::WinitWindowAccessor;
use slint::ComponentHandle;

use crate::AppWindow;

/// How often the window is sampled. A change is saved once two samples in a
/// row agree, so a drag or a resize writes the file once, after it stops.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(750);

/// The window never restores smaller than this (logical pixels).
const MIN_WINDOW_WIDTH: u32 = 480;
const MIN_WINDOW_HEIGHT: u32 = 320;
/// Size assumed for the visibility check when no size was saved.
const DEFAULT_WINDOW_WIDTH: u32 = 900;
const DEFAULT_WINDOW_HEIGHT: u32 = 600;
/// Part of the window (physical pixels) that must lie on a monitor for the
/// saved position to count as visible.
const MIN_VISIBLE_WIDTH: i32 = 120;
const MIN_VISIBLE_HEIGHT: i32 = 60;

/// Limits of the two columns: the same as the drag limits in the layout
/// (`sidebar-hard-max-width`, the member column's 320px drag ceiling).
const COLUMN_MIN_WIDTH: u32 = 100;
const SIDEBAR_MAX_WIDTH: u32 = 720;
const MEMBERS_MAX_WIDTH: u32 = 320;
/// Window width taken by the chat column and the layout padding, gaps and
/// handles (`chat-min-width` + `layout-fixed-width` in the layout).
const CHAT_AND_LAYOUT_WIDTH: u32 = 240 + 92;

/// A monitor's area in physical desktop pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Area {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// What the window reports right now.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// Current size, logical pixels.
    pub size: (u32, u32),
    /// Position, physical pixels; `None` where the host cannot report it.
    pub position: Option<(i32, i32)>,
    pub maximized: bool,
    pub fullscreen: bool,
    pub sidebar_width: u32,
    pub members_width: u32,
}

/// What to apply at launch. A `None` leaves the default in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RestorePlan {
    pub size: Option<(u32, u32)>,
    pub position: Option<(i32, i32)>,
    pub maximized: bool,
    pub fullscreen: bool,
    pub sidebar_width: Option<u32>,
    pub members_width: Option<u32>,
}

/// Merges a sample into the saved state. The normal size and position change
/// only while the window is neither maximized nor full-screen: they keep the
/// bounds to go back to.
pub fn record(previous: Option<WindowState>, sample: &Sample) -> WindowState {
    let mut state = previous.unwrap_or_default();
    if !sample.maximized
        && !sample.fullscreen
        && sample.size.0 >= MIN_WINDOW_WIDTH
        && sample.size.1 >= MIN_WINDOW_HEIGHT
    {
        state.width = Some(sample.size.0);
        state.height = Some(sample.size.1);
        if let Some((x, y)) = sample.position {
            state.x = Some(x);
            state.y = Some(y);
        }
    }
    state.maximized = sample.maximized;
    state.fullscreen = sample.fullscreen;
    state.sidebar_width = Some(sample.sidebar_width);
    state.members_width = Some(sample.members_width);
    state
}

/// Whether the rectangle lies on a monitor enough for the user to grab it.
fn is_visible(x: i32, y: i32, width: i32, height: i32, monitors: &[Area]) -> bool {
    monitors.iter().any(|monitor| {
        let overlap_width = (x + width).min(monitor.x + monitor.width) - x.max(monitor.x);
        let overlap_height = (y + height).min(monitor.y + monitor.height) - y.max(monitor.y);
        overlap_width >= MIN_VISIBLE_WIDTH.min(width)
            && overlap_height >= MIN_VISIBLE_HEIGHT.min(height)
    })
}

/// Brings both column widths into their limits and, when the window width
/// is known, into the room that the chat column leaves. The member column
/// gives way first, as in the layout.
pub fn clamp_columns(
    sidebar: Option<u32>,
    members: Option<u32>,
    window_width: Option<u32>,
) -> (Option<u32>, Option<u32>) {
    let mut sidebar = sidebar.map(|w| w.clamp(COLUMN_MIN_WIDTH, SIDEBAR_MAX_WIDTH));
    let mut members = members.map(|w| w.clamp(COLUMN_MIN_WIDTH, MEMBERS_MAX_WIDTH));
    if let Some(width) = window_width {
        let room = width.saturating_sub(CHAT_AND_LAYOUT_WIDTH);
        if let (Some(sidebar_value), Some(members_value)) = (sidebar, members) {
            if sidebar_value + members_value > room {
                members = Some(room.saturating_sub(sidebar_value).max(COLUMN_MIN_WIDTH));
            }
        }
        if let (Some(sidebar_value), Some(members_value)) = (sidebar, members) {
            if sidebar_value + members_value > room {
                sidebar = Some(room.saturating_sub(members_value).max(COLUMN_MIN_WIDTH));
            }
        }
    }
    (sidebar, members)
}

/// Decides what to restore. `monitors` and `scale` describe the current
/// desktop; `position_supported` is false where the host cannot place a
/// window (the position is then skipped, the rest still applies).
pub fn plan(
    state: &WindowState,
    monitors: &[Area],
    scale: f32,
    position_supported: bool,
) -> RestorePlan {
    let scale = if scale.is_finite() && scale > 0.0 {
        scale
    } else {
        1.0
    };
    let largest = monitors
        .iter()
        .map(|m| {
            (
                (m.width as f32 / scale) as u32,
                (m.height as f32 / scale) as u32,
            )
        })
        .max_by_key(|(w, h)| u64::from(*w) * u64::from(*h));
    let (max_width, max_height) = largest.unwrap_or((u32::MAX, u32::MAX));
    let fit = |width: u32, height: u32| {
        (
            width.clamp(MIN_WINDOW_WIDTH, max_width.max(MIN_WINDOW_WIDTH)),
            height.clamp(MIN_WINDOW_HEIGHT, max_height.max(MIN_WINDOW_HEIGHT)),
        )
    };
    // A maximized or full-screen window always gets valid normal bounds, so
    // leaving that state never falls back to a host default.
    let special = state.maximized || state.fullscreen;
    let size = match (state.width, state.height) {
        (Some(width), Some(height)) => Some(fit(width, height)),
        _ if special => Some(fit(DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)),
        _ => None,
    };
    let (shown_width, shown_height) = size.unwrap_or((DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT));
    let position = match (state.x, state.y) {
        (Some(x), Some(y))
            if position_supported
                && is_visible(
                    x,
                    y,
                    (shown_width as f32 * scale) as i32,
                    (shown_height as f32 * scale) as i32,
                    monitors,
                ) =>
        {
            Some((x, y))
        }
        _ => None,
    };
    // The saved column widths of a maximized or full-screen window fit the
    // larger window, not the normal width: the layout clamps them later.
    let layout_width = if state.maximized || state.fullscreen {
        None
    } else {
        size.map(|(w, _)| w)
    };
    let (sidebar_width, members_width) =
        clamp_columns(state.sidebar_width, state.members_width, layout_width);
    RestorePlan {
        size,
        position,
        // The two states stay distinct: full-screen wins over maximized.
        maximized: state.maximized && !state.fullscreen,
        fullscreen: state.fullscreen,
        sidebar_width,
        members_width,
    }
}

/// Size to apply when a window that is neither maximized nor full-screen is
/// smaller than the minimum (for example a title-bar-only strip after leaving
/// full-screen on Windows). It is the last valid normal size or the default.
pub fn repair_size(sample: &Sample, saved: Option<WindowState>) -> Option<(u32, u32)> {
    if sample.maximized || sample.fullscreen {
        return None;
    }
    if sample.size.0 >= MIN_WINDOW_WIDTH && sample.size.1 >= MIN_WINDOW_HEIGHT {
        return None;
    }
    let size = saved
        .and_then(|state| state.width.zip(state.height))
        .filter(|(w, h)| *w >= MIN_WINDOW_WIDTH && *h >= MIN_WINDOW_HEIGHT);
    Some(size.unwrap_or((DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)))
}

/// Decides when a sampled state is written: once it is stable (equal to the
/// previous sample) and differs from what the file holds.
pub struct SaveGate {
    last_seen: Option<WindowState>,
    saved: Option<WindowState>,
}

impl SaveGate {
    pub fn new(saved: Option<WindowState>) -> Self {
        SaveGate {
            last_seen: None,
            saved,
        }
    }

    /// What the file holds, as far as this gate knows.
    #[cfg(test)]
    pub fn saved(&self) -> Option<WindowState> {
        self.saved
    }

    /// The last state seen by `observe`, stable or not.
    pub fn last_seen(&self) -> Option<WindowState> {
        self.last_seen
    }

    /// The newest known state: the last one seen, else the saved one. New
    /// samples merge into it, so the debounce keeps no observed bounds out.
    pub fn latest(&self) -> Option<WindowState> {
        self.last_seen.or(self.saved)
    }

    /// Returns true when `state` differs from the saved one, without the
    /// stability check. Used when the window closes.
    pub fn flush(&mut self, state: WindowState) -> bool {
        if self.saved == Some(state) {
            return false;
        }
        self.saved = Some(state);
        true
    }

    /// Returns true when `state` must be written now.
    pub fn observe(&mut self, state: WindowState) -> bool {
        let stable = self.last_seen == Some(state);
        self.last_seen = Some(state);
        if stable && self.saved != Some(state) {
            self.saved = Some(state);
            return true;
        }
        false
    }
}

/// Reads the window. `None` while the window is minimized or not backed by
/// winit yet: nothing is sampled then.
fn sample(ui: &AppWindow) -> Option<Sample> {
    let window = ui.window();
    let (minimized, position) = window.with_winit_window(|winit| {
        (
            winit.is_minimized().unwrap_or(false),
            winit.outer_position().ok().map(|p| (p.x, p.y)),
        )
    })?;
    let size = window.size();
    if minimized || size.width == 0 || size.height == 0 {
        return None;
    }
    let scale = window.scale_factor().max(f32::EPSILON);
    Some(Sample {
        size: (
            (size.width as f32 / scale).round() as u32,
            (size.height as f32 / scale).round() as u32,
        ),
        position,
        maximized: window.is_maximized(),
        fullscreen: window.is_fullscreen(),
        sidebar_width: ui.get_sidebar_width().max(0.0).round() as u32,
        members_width: ui.get_members_width().max(0.0).round() as u32,
    })
}

/// Applies the saved state to the window. It needs the event loop, so it
/// runs from a timer. Values the host cannot honour are skipped silently.
fn restore(ui: &AppWindow, state: &WindowState) {
    let window = ui.window();
    let (monitors, position_supported) = window
        .with_winit_window(|winit| {
            let monitors: Vec<Area> = winit
                .available_monitors()
                .map(|monitor| {
                    let position = monitor.position();
                    let size = monitor.size();
                    Area {
                        x: position.x,
                        y: position.y,
                        width: i32::try_from(size.width).unwrap_or(i32::MAX),
                        height: i32::try_from(size.height).unwrap_or(i32::MAX),
                    }
                })
                .collect();
            (monitors, winit.outer_position().is_ok())
        })
        .unwrap_or((Vec::new(), false));
    let plan = plan(state, &monitors, window.scale_factor(), position_supported);
    if let Some((width, height)) = plan.size {
        window.set_size(slint::LogicalSize::new(width as f32, height as f32));
    }
    if let Some((x, y)) = plan.position {
        window.set_position(slint::PhysicalPosition::new(x, y));
    }
    // Normal bounds are set above; now enter exactly one special state.
    if plan.fullscreen {
        window.set_fullscreen(true);
    } else if plan.maximized {
        window.set_maximized(true);
    }
    if let Some(width) = plan.sidebar_width {
        ui.set_sidebar_width(width as f32);
    }
    if let Some(width) = plan.members_width {
        ui.set_members_width(width as f32);
    }
}

/// Restores the saved window state once the event loop runs, then saves
/// changes. Keep the returned timer alive until the window closes.
pub fn install(ui: &AppWindow, saved: Option<WindowState>) -> WindowStateSaver {
    if let Some(state) = saved {
        let weak = ui.as_weak();
        slint::Timer::single_shot(Duration::ZERO, move || {
            if let Some(ui) = weak.upgrade() {
                restore(&ui, &state);
            }
        });
    }
    let timer = slint::Timer::default();
    let gate = Rc::new(RefCell::new(SaveGate::new(saved)));
    let weak = ui.as_weak();
    let timer_gate = Rc::clone(&gate);
    timer.start(slint::TimerMode::Repeated, SAMPLE_INTERVAL, move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let Some(sample) = sample(&ui) else {
            return;
        };
        let mut gate = timer_gate.borrow_mut();
        if let Some((width, height)) = repair_size(&sample, gate.latest()) {
            ui.window()
                .set_size(slint::LogicalSize::new(width as f32, height as f32));
        }
        let state = record(gate.latest(), &sample);
        if gate.observe(state) {
            write(state);
        }
    });
    // Closing the window right after a change must not lose it: write the
    // final state without waiting for the debounce.
    let weak = ui.as_weak();
    let close_gate = Rc::clone(&gate);
    ui.window().on_close_requested(move || {
        if let Some(ui) = weak.upgrade() {
            let mut gate = close_gate.borrow_mut();
            let state = sample(&ui)
                .map(|sample| record(gate.latest(), &sample))
                .or(gate.last_seen());
            if let Some(state) = state {
                if gate.flush(state) {
                    write(state);
                }
            }
        }
        slint::CloseRequestResponse::HideWindow
    });
    WindowStateSaver {
        _timer: timer,
        gate,
    }
}

/// Keeps the saving timer alive. Drop it after the window closes.
pub struct WindowStateSaver {
    _timer: slint::Timer,
    gate: Rc<RefCell<SaveGate>>,
}

impl WindowStateSaver {
    /// Writes the last sampled state if the file does not hold it yet. It
    /// covers exits that send no close request (for example Cmd+Q on macOS).
    /// The window can be gone by now, so it does not sample.
    pub fn flush(&self) {
        let mut gate = self.gate.borrow_mut();
        if let Some(state) = gate.last_seen() {
            if gate.flush(state) {
                write(state);
            }
        }
    }
}

/// Stores the state next to every other setting, which stay as they are.
fn write(state: WindowState) {
    let _ = persistence::update_settings(|settings| settings.window = Some(state));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor(x: i32, y: i32, width: i32, height: i32) -> Area {
        Area {
            x,
            y,
            width,
            height,
        }
    }

    fn sample(maximized: bool, fullscreen: bool) -> Sample {
        Sample {
            size: (1000, 700),
            position: Some((50, 60)),
            maximized,
            fullscreen,
            sidebar_width: 220,
            members_width: 180,
        }
    }

    #[test]
    fn latest_keeps_bounds_seen_once_before_maximizing() {
        let old = record(None, &sample(false, false));
        let mut gate = SaveGate::new(Some(old));
        let mut resized = sample(false, false);
        resized.size = (1200, 800);
        assert!(!gate.observe(record(gate.latest(), &resized)));
        let mut maximized = sample(true, false);
        maximized.size = (1920, 1080);
        let state = record(gate.latest(), &maximized);
        assert_eq!(state.width, Some(1200));
        assert_eq!(state.height, Some(800));
        assert!(state.maximized);
    }

    #[test]
    fn record_keeps_normal_bounds_while_maximized() {
        let normal = record(None, &sample(false, false));
        assert_eq!(normal.width, Some(1000));
        assert_eq!((normal.x, normal.y), (Some(50), Some(60)));
        let mut maximized = sample(true, false);
        maximized.size = (1920, 1080);
        maximized.position = Some((0, 0));
        let state = record(Some(normal), &maximized);
        assert!(state.maximized);
        assert_eq!(state.width, Some(1000));
        assert_eq!(state.height, Some(700));
        assert_eq!((state.x, state.y), (Some(50), Some(60)));
        let full = record(Some(normal), &sample(false, true));
        assert!(full.fullscreen);
        assert_eq!(full.width, Some(1000));
    }

    #[test]
    fn record_without_position_support_keeps_the_rest() {
        let mut unsupported = sample(false, false);
        unsupported.position = None;
        let state = record(None, &unsupported);
        assert_eq!((state.x, state.y), (None, None));
        assert_eq!(state.width, Some(1000));
        assert_eq!(state.sidebar_width, Some(220));
        assert_eq!(state.members_width, Some(180));
    }

    #[test]
    fn record_ignores_a_tiny_size() {
        let mut tiny = sample(false, false);
        tiny.size = (10, 10);
        let state = record(None, &tiny);
        assert_eq!(state.width, None);
        assert_eq!(state.height, None);
    }

    #[test]
    fn plan_restores_a_visible_window() {
        let state = record(None, &sample(false, false));
        let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, true);
        assert_eq!(plan.size, Some((1000, 700)));
        assert_eq!(plan.position, Some((50, 60)));
        assert_eq!(plan.sidebar_width, Some(220));
        assert_eq!(plan.members_width, Some(180));
        assert!(!plan.maximized && !plan.fullscreen);
    }

    #[test]
    fn plan_restores_maximized_and_fullscreen_flags() {
        let state = WindowState {
            maximized: true,
            fullscreen: true,
            ..WindowState::default()
        };
        let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, true);
        // Full-screen wins; the normal size is the safe default.
        assert!(!plan.maximized && plan.fullscreen);
        assert_eq!(plan.size, Some((900, 600)));
        assert_eq!(plan.position, None);
        let maximized = WindowState {
            maximized: true,
            ..WindowState::default()
        };
        let plan = super::plan(&maximized, &[monitor(0, 0, 1920, 1080)], 1.0, true);
        assert!(plan.maximized && !plan.fullscreen);
    }

    #[test]
    fn plan_default_size_fits_a_small_monitor() {
        let state = WindowState {
            fullscreen: true,
            ..WindowState::default()
        };
        let plan = plan(&state, &[monitor(0, 0, 800, 500)], 1.0, true);
        assert_eq!(plan.size, Some((800, 500)));
    }

    #[test]
    fn repair_size_fixes_a_collapsed_normal_window() {
        let saved = record(None, &sample(false, false));
        let mut strip = sample(false, false);
        strip.size = (1000, 39);
        assert_eq!(repair_size(&strip, Some(saved)), Some((1000, 700)));
        assert_eq!(repair_size(&strip, None), Some((900, 600)));
        assert_eq!(repair_size(&sample(false, false), Some(saved)), None);
        strip.fullscreen = true;
        assert_eq!(repair_size(&strip, Some(saved)), None);
        strip.fullscreen = false;
        strip.maximized = true;
        assert_eq!(repair_size(&strip, Some(saved)), None);
    }

    #[test]
    fn plan_without_saved_state_changes_nothing() {
        let plan = plan(
            &WindowState::default(),
            &[monitor(0, 0, 1920, 1080)],
            1.0,
            true,
        );
        assert_eq!(plan, RestorePlan::default());
    }

    #[test]
    fn plan_skips_the_position_where_the_host_cannot_place_windows() {
        let state = record(None, &sample(false, false));
        let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, false);
        assert_eq!(plan.position, None);
        assert_eq!(plan.size, Some((1000, 700)));
        assert_eq!(plan.sidebar_width, Some(220));
    }

    #[test]
    fn plan_skips_the_position_without_known_monitors() {
        let state = record(None, &sample(false, false));
        let plan = plan(&state, &[], 1.0, true);
        assert_eq!(plan.position, None);
        assert_eq!(plan.size, Some((1000, 700)));
    }

    #[test]
    fn plan_drops_a_position_on_a_removed_monitor() {
        let mut state = record(None, &sample(false, false));
        state.x = Some(2500);
        state.y = Some(100);
        let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, true);
        assert_eq!(plan.position, None);
        state.x = Some(-32000);
        state.y = Some(-32000);
        let plan = super::plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, true);
        assert_eq!(plan.position, None);
    }

    #[test]
    fn plan_accepts_a_position_on_a_second_monitor() {
        let mut state = record(None, &sample(false, false));
        state.x = Some(2000);
        state.y = Some(100);
        let monitors = [monitor(0, 0, 1920, 1080), monitor(1920, 0, 1920, 1080)];
        let plan = plan(&state, &monitors, 1.0, true);
        assert_eq!(plan.position, Some((2000, 100)));
    }

    #[test]
    fn plan_rejects_a_window_mostly_off_screen() {
        let mut state = record(None, &sample(false, false));
        state.x = Some(1900);
        state.y = Some(100);
        let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, true);
        assert_eq!(plan.position, None);
    }

    #[test]
    fn plan_clamps_the_size_to_the_monitor_and_the_minimum() {
        let state = WindowState {
            width: Some(9000),
            height: Some(10),
            ..WindowState::default()
        };
        let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, true);
        assert_eq!(plan.size, Some((1920, MIN_WINDOW_HEIGHT)));
        let scaled = super::plan(&state, &[monitor(0, 0, 3840, 2160)], 2.0, true);
        assert_eq!(scaled.size, Some((1920, MIN_WINDOW_HEIGHT)));
    }

    #[test]
    fn plan_ignores_a_size_with_one_value_missing() {
        let state = WindowState {
            width: Some(800),
            ..WindowState::default()
        };
        let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, true);
        assert_eq!(plan.size, None);
    }

    #[test]
    fn plan_survives_an_invalid_scale() {
        let state = record(None, &sample(false, false));
        let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 0.0, true);
        assert_eq!(plan.size, Some((1000, 700)));
        let plan = super::plan(&state, &[monitor(0, 0, 1920, 1080)], f32::NAN, true);
        assert_eq!(plan.size, Some((1000, 700)));
    }

    #[test]
    fn columns_are_clamped_to_their_limits() {
        assert_eq!(
            clamp_columns(Some(5), Some(5000), None),
            (Some(COLUMN_MIN_WIDTH), Some(MEMBERS_MAX_WIDTH))
        );
        assert_eq!(
            clamp_columns(Some(5000), Some(200), None),
            (Some(SIDEBAR_MAX_WIDTH), Some(200))
        );
        assert_eq!(clamp_columns(None, None, Some(900)), (None, None));
        assert_eq!(clamp_columns(Some(200), None, None), (Some(200), None));
    }

    #[test]
    fn columns_leave_room_for_the_chat() {
        // 900 - 332 = 568 pixels for both columns.
        assert_eq!(
            clamp_columns(Some(400), Some(300), Some(900)),
            (Some(400), Some(168))
        );
        // Members hit their minimum first, then the sidebar gives way.
        let (sidebar, members) = clamp_columns(Some(600), Some(300), Some(500));
        assert_eq!(members, Some(COLUMN_MIN_WIDTH));
        assert_eq!(sidebar, Some(COLUMN_MIN_WIDTH));
    }

    #[test]
    fn plan_keeps_columns_saved_in_a_maximized_or_fullscreen_window() {
        for (maximized, fullscreen) in [(true, false), (false, true)] {
            let state = WindowState {
                width: Some(900),
                height: Some(600),
                maximized,
                fullscreen,
                sidebar_width: Some(600),
                members_width: Some(300),
                ..WindowState::default()
            };
            let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, true);
            assert_eq!(plan.sidebar_width, Some(600));
            assert_eq!(plan.members_width, Some(300));
        }
    }

    #[test]
    fn plan_clamps_columns_against_the_normal_width() {
        let state = WindowState {
            width: Some(900),
            height: Some(600),
            sidebar_width: Some(400),
            members_width: Some(300),
            ..WindowState::default()
        };
        let plan = plan(&state, &[monitor(0, 0, 1920, 1080)], 1.0, true);
        assert_eq!(plan.sidebar_width, Some(400));
        assert_eq!(plan.members_width, Some(168));
    }

    #[test]
    fn gate_flush_saves_a_value_seen_once() {
        let first = record(None, &sample(false, false));
        let mut gate = SaveGate::new(Some(first));
        let mut moved = sample(false, false);
        moved.position = Some((90, 90));
        let changed = record(Some(first), &moved);
        assert!(gate.flush(changed));
        assert!(!gate.flush(changed), "a saved value is not written again");
        assert_eq!(gate.saved(), Some(changed));
        assert_eq!(gate.last_seen(), None);
    }

    #[test]
    fn gate_saves_only_a_stable_change() {
        let first = record(None, &sample(false, false));
        let mut gate = SaveGate::new(Some(first));
        assert!(!gate.observe(first));
        let mut moved = sample(false, false);
        moved.position = Some((90, 90));
        let changed = record(Some(first), &moved);
        assert!(
            !gate.observe(changed),
            "first sight of a change is not saved"
        );
        assert!(gate.observe(changed), "the same value twice is stable");
        assert!(
            !gate.observe(changed),
            "an unchanged value is not saved again"
        );
        assert_eq!(gate.saved(), Some(changed));
    }

    #[test]
    fn gate_ignores_a_value_that_keeps_changing() {
        let mut gate = SaveGate::new(None);
        for width in 400..420 {
            let mut resizing = sample(false, false);
            resizing.size = (width, 700);
            assert!(!gate.observe(record(None, &resizing)));
        }
    }
}
