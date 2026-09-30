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

//! Gathers the host details for the Debug page. Everything is read locally
//! and only shown on screen; `cordiale_core::diagnostics` lays the text out.
//! Whatever the platform can't tell reliably stays `None` ("Not available").

use std::sync::OnceLock;

use chrono::Local;
use cordiale_core::diagnostics::{describe_graphics, Diagnostics};
use cordiale_core::persistence;
use slint::winit_030::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
use slint::winit_030::WinitWindowAccessor;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, System};

/// The renderer Slint ended up with, known once the first frame is set up.
static RENDERER: OnceLock<&'static str> = OnceLock::new();

/// Starts noting which renderer draws the window. Call before the window is
/// shown: the OpenGL renderer reports when its context is ready, the
/// software one doesn't support notifiers at all.
pub(crate) fn watch_renderer(window: &slint::Window) {
    let registered = window.set_rendering_notifier(|state, api| {
        if matches!(state, slint::RenderingState::RenderingSetup)
            && matches!(api, slint::GraphicsAPI::NativeOpenGL { .. })
        {
            let _ = RENDERER.set("femtovg (OpenGL)");
        }
    });
    if matches!(
        registered,
        Err(slint::SetRenderingNotifierError::Unsupported)
    ) {
        let _ = RENDERER.set("software");
    }
}

/// The report text for the Debug page. `app_language` is the code of the
/// language picked in Cordiale, if any.
pub(crate) fn report(window: &slint::Window, app_language: Option<&str>) -> String {
    let mut system = System::new();
    system.refresh_cpu_list(CpuRefreshKind::nothing());
    system.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
    let cpu_model = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_string());
    let cpu_cores = Some(system.cpus().len()).filter(|cores| *cores > 0);

    let (display_size, windowing_system) = window
        .with_winit_window(|winit| (monitor_size(winit), windowing_system_of(winit)))
        .unwrap_or((None, None));
    let backend = window.has_winit_window().then_some("winit");

    Diagnostics {
        version: cordiale_core::APP_VERSION.to_string(),
        build: cordiale_core::BUILD_ID.to_string(),
        executable: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        graphics: describe_graphics(backend, RENDERER.get().copied()),
        os: os_description(),
        kernel: System::kernel_version(),
        cpu_arch: Some(System::cpu_arch()),
        cpu_model,
        cpu_cores,
        memory_total: Some(system.total_memory()).filter(|bytes| *bytes > 0),
        memory_available: Some(system.available_memory()).filter(|bytes| *bytes > 0),
        display_size,
        scale_factor: Some(window.scale_factor()),
        windowing_system: windowing_system.map(str::to_string),
        system_locale: sys_locale::get_locale(),
        app_language: app_language.map(str::to_string),
        keyboard_layout: keyboard_layout(),
        // No platform API is queried for the input method yet.
        input_method: None,
        local_time: Some(Local::now().format("%Y-%m-%d %H:%M:%S %:z").to_string()),
        time_zone: iana_time_zone::get_timezone().ok(),
        data_dir: persistence::config_dir_display(),
        log_file: persistence::log_file_display(),
    }
    .render()
}

/// The OS as its own tools name it, e.g. "Windows 11 Pro" or
/// "Linux (Ubuntu 24.04)"; the plain name and version when there's no
/// long form.
fn os_description() -> Option<String> {
    System::long_os_version().or_else(|| match (System::name(), System::os_version()) {
        (Some(name), Some(version)) => Some(format!("{name} {version}")),
        (name, version) => name.or(version),
    })
}

/// Size in physical pixels of the monitor the window is on.
fn monitor_size(winit: &slint::winit_030::winit::window::Window) -> Option<(u32, u32)> {
    let size = winit.current_monitor()?.size();
    Some((size.width, size.height)).filter(|(width, height)| *width > 0 && *height > 0)
}

/// The windowing system behind the window: what tells Wayland from X11 on
/// Linux.
fn windowing_system_of(winit: &slint::winit_030::winit::window::Window) -> Option<&'static str> {
    let handle = winit.window_handle().ok()?;
    match handle.as_raw() {
        RawWindowHandle::Wayland(_) => Some("Wayland"),
        RawWindowHandle::Xlib(_) | RawWindowHandle::Xcb(_) => Some("X11"),
        RawWindowHandle::Win32(_) => Some("Windows (Win32)"),
        RawWindowHandle::AppKit(_) => Some("macOS (AppKit)"),
        _ => None,
    }
}

/// The input language and layout id Windows has active for the UI thread,
/// e.g. `it-IT (layout 04100410)`. Other platforms have no call Cordiale
/// can rely on for this.
#[cfg(windows)]
fn keyboard_layout() -> Option<String> {
    use windows::Win32::Globalization::LCIDToLocaleName;
    use windows::Win32::UI::Input::KeyboardAndMouse::GetKeyboardLayout;

    // SAFETY: thread id 0 means the calling thread, the UI thread here.
    let layout = unsafe { GetKeyboardLayout(0) };
    let layout_id = (layout.0 as usize & 0xFFFF_FFFF) as u32;
    let language_id = layout_id & 0xFFFF;
    if language_id == 0 {
        return None;
    }
    // LOCALE_NAME_MAX_LENGTH, terminator included.
    let mut name = [0u16; 85];
    // SAFETY: the buffer outlives the call and its length goes with it.
    let written = unsafe { LCIDToLocaleName(language_id, Some(&mut name[..]), 0) };
    let length = usize::try_from(written).ok().filter(|length| *length > 1)?;
    let tag = String::from_utf16_lossy(&name[..length - 1]);
    Some(format!("{tag} (layout {layout_id:08X})"))
}

#[cfg(not(windows))]
fn keyboard_layout() -> Option<String> {
    None
}
