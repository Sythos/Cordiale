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

//! The startup stages and the handoff from the splash window to the main
//! window.
//!
//! The splash is a small window of its own. The main window stays hidden
//! until the automatic sign-in and the account load end. The progress comes
//! from work that is done: a stage starts when its work starts, and the bar
//! is full only after the account is ready. All the functions run on the
//! UI thread; the worker reaches them through `upgrade_in_event_loop`.

use std::cell::RefCell;

use cordiale_core::bootstrap::BootstrapStage;
use cordiale_core::persistence::{self, WindowState};
use slint::ComponentHandle;

use crate::window_state::{self, WindowStateSaver};
use crate::{AppWindow, SplashWindow};

/// The stages of the startup, in the order they start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StartupStage {
    LoadingSettings,
    StartingServices,
    SigningIn,
    LoadingAccount,
    OpeningMainWindow,
}

impl StartupStage {
    /// How many stages the startup has.
    const COUNT: usize = 5;

    /// The number the layout uses to pick the status text.
    pub fn index(self) -> i32 {
        self as i32
    }

    /// The share of the work that is done when this stage starts. It is
    /// always below 1: only the end of the handoff fills the bar.
    pub fn progress(self) -> f32 {
        self.index() as f32 / Self::COUNT as f32
    }

    /// The startup stage that matches a stage of the sign-in.
    pub fn from_bootstrap(stage: BootstrapStage) -> Self {
        match stage {
            BootstrapStage::SigningIn => Self::SigningIn,
            BootstrapStage::LoadingAccount => Self::LoadingAccount,
        }
    }
}

/// The screen the main window opens on. The window starts on the
/// `splash` screen, which is only a name for "not ready"; any other screen
/// was chosen by the sign-in and stays.
pub fn screen_after_startup<'a>(current: &'a str, next: &'a str) -> &'a str {
    if current == "splash" {
        next
    } else {
        current
    }
}

/// Whether the startup ended with an account that is ready.
pub fn startup_completed(screen: &str) -> bool {
    screen == "connected"
}

struct Startup {
    splash: SplashWindow,
    saved_window: Option<WindowState>,
}

thread_local! {
    static STARTUP: RefCell<Option<Startup>> = const { RefCell::new(None) };
    static SAVER: RefCell<Option<WindowStateSaver>> = const { RefCell::new(None) };
}

/// Keeps the splash window until the handoff.
pub fn begin(splash: SplashWindow, saved_window: Option<WindowState>) {
    STARTUP.with(|startup| {
        *startup.borrow_mut() = Some(Startup {
            splash,
            saved_window,
        });
    });
}

/// Shows `stage` on the splash (while it is open) and on the connect screen.
pub fn advance(ui: &AppWindow, stage: StartupStage) {
    ui.set_startup_stage(stage.index());
    ui.set_startup_progress(stage.progress());
    set_splash_stage(stage, stage.progress());
}

fn set_splash_stage(stage: StartupStage, progress: f32) {
    STARTUP.with(|startup| {
        if let Some(startup) = startup.borrow().as_ref() {
            startup.splash.set_stage(stage.index());
            startup.splash.set_progress(progress);
        }
    });
}

/// Ends the splash and opens the main window. `completed` is true only when
/// the account is ready: a failed startup closes the splash with a bar that
/// is not full. The call does nothing after the first time.
pub fn finish(ui: &AppWindow, completed: bool) {
    let Some(startup) = STARTUP.with(|startup| startup.borrow_mut().take()) else {
        return;
    };
    let screen = ui.get_screen();
    let next = ui.get_next_screen();
    ui.set_screen(screen_after_startup(&screen, &next).into());
    if completed {
        startup
            .splash
            .set_stage(StartupStage::OpeningMainWindow.index());
        startup.splash.set_progress(1.0);
    }
    // The saved size, position and state apply only now: the splash never
    // takes them. A host that cannot place a window keeps its own placement.
    let saver = window_state::install(ui, startup.saved_window);
    SAVER.with(|slot| *slot.borrow_mut() = Some(saver));
    if let Err(error) = ui.show() {
        persistence::log_line(&format!("main window failed to open: {error}"));
        let _ = slint::quit_event_loop();
        return;
    }
    crate::center_window_on_monitor(ui.window());
    let _ = startup.splash.hide();
}

/// How often the startup looks for the end of the sign-in. The check reads
/// a flag; the bar does not move with it.
const SIGN_IN_POLL: std::time::Duration = std::time::Duration::from_millis(100);

thread_local! {
    static WATCH: RefCell<Option<slint::Timer>> = const { RefCell::new(None) };
}

/// Opens the main window when the sign-in at launch ends, with success or
/// not. Where no sign-in runs, the window opens at the first check. Call it
/// after the sign-in command is sent, with `connecting` already set.
pub fn watch_sign_in(ui: &AppWindow) {
    let timer = slint::Timer::default();
    let weak = ui.as_weak();
    timer.start(slint::TimerMode::Repeated, SIGN_IN_POLL, move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        if ui.get_connecting() {
            return;
        }
        finish(&ui, startup_completed(&ui.get_screen()));
        WATCH.with(|watch| {
            if let Some(timer) = watch.borrow().as_ref() {
                timer.stop();
            }
        });
    });
    WATCH.with(|watch| *watch.borrow_mut() = Some(timer));
}

/// The saver of the window state, once the main window has opened.
pub fn take_window_saver() -> Option<WindowStateSaver> {
    SAVER.with(|slot| slot.borrow_mut().take())
}
