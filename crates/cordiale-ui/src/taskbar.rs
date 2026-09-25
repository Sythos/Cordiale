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

//! The unread count as a Windows taskbar overlay badge (the small icon on
//! the app's taskbar button), like the badge Cicchetto gets from the
//! browser. Elsewhere the count stays in the window title only.

/// Side of the overlay icon, in pixels (Windows' small icon size).
#[cfg_attr(not(windows), allow(dead_code))]
const SIZE: usize = 16;

/// Shows `count` on the taskbar button, or clears the badge for 0.
/// `description` is what screen readers announce for it.
#[cfg(windows)]
pub fn set_badge(window: &slint::Window, count: i32, description: &str) {
    if let Err(err) = windows_badge::set(window, count, description) {
        cordiale_core::persistence::log_line(&format!("taskbar badge failed: {err}"));
    }
}

#[cfg(not(windows))]
pub fn set_badge(_window: &slint::Window, _count: i32, _description: &str) {}

/// 3x5 digit glyphs, one row per entry, most significant bit on the left.
#[cfg_attr(not(windows), allow(dead_code))]
const DIGITS: [[u8; 5]; 10] = [
    [0b111, 0b101, 0b101, 0b101, 0b111],
    [0b010, 0b110, 0b010, 0b010, 0b111],
    [0b111, 0b001, 0b111, 0b100, 0b111],
    [0b111, 0b001, 0b111, 0b001, 0b111],
    [0b101, 0b101, 0b111, 0b001, 0b001],
    [0b111, 0b100, 0b111, 0b001, 0b111],
    [0b111, 0b100, 0b111, 0b101, 0b111],
    [0b111, 0b001, 0b001, 0b001, 0b001],
    [0b111, 0b101, 0b111, 0b101, 0b111],
    [0b111, 0b101, 0b111, 0b001, 0b111],
];

/// The badge as `SIZE`x`SIZE` ARGB pixels, top row first: a red disc with
/// the count (capped at 99) in white, glyphs drawn at twice their size.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn badge_pixels(count: i32) -> Vec<u32> {
    const RED: u32 = 0x00D3_2F2F;
    const WHITE: u32 = 0xFFFF_FFFF;
    const SCALE: usize = 2;
    let mut pixels = vec![0u32; SIZE * SIZE];
    let radius = SIZE as f32 / 2.0;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 + 0.5 - radius;
            let dy = y as f32 + 0.5 - radius;
            let coverage = (radius - (dx * dx + dy * dy).sqrt() + 0.5).clamp(0.0, 1.0);
            let alpha = (coverage * 255.0).round() as u32;
            pixels[y * SIZE + x] = (alpha << 24) | RED;
        }
    }

    let text = count.clamp(0, 99).to_string();
    let glyph_width = 3 * SCALE;
    let gap = SCALE;
    let width = text.len() * glyph_width + (text.len() - 1) * gap;
    let left = (SIZE - width) / 2;
    let top = (SIZE - 5 * SCALE) / 2;
    for (index, digit) in text.bytes().enumerate() {
        let glyph = DIGITS[usize::from(digit - b'0')];
        let glyph_left = left + index * (glyph_width + gap);
        for (row, bits) in glyph.iter().enumerate() {
            for column in 0..3 {
                if bits & (0b100 >> column) == 0 {
                    continue;
                }
                for sy in 0..SCALE {
                    for sx in 0..SCALE {
                        let x = glyph_left + column * SCALE + sx;
                        let y = top + row * SCALE + sy;
                        pixels[y * SIZE + x] = WHITE;
                    }
                }
            }
        }
    }
    pixels
}

#[cfg(windows)]
mod windows_badge {
    use std::cell::RefCell;

    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Gdi::{
        CreateBitmap, CreateDIBSection, DeleteObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
        DIB_RGB_COLORS,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::UI::Shell::{ITaskbarList3, TaskbarList};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateIconIndirect, DestroyIcon, HICON, ICONINFO,
    };

    use super::{badge_pixels, SIZE};

    thread_local! {
        static TASKBAR: RefCell<Option<ITaskbarList3>> = const { RefCell::new(None) };
    }

    pub fn set(window: &slint::Window, count: i32, description: &str) -> Result<(), String> {
        let handle = window.window_handle();
        let raw = handle
            .window_handle()
            .map_err(|err| err.to_string())?
            .as_raw();
        let RawWindowHandle::Win32(win32) = raw else {
            return Ok(());
        };
        let hwnd = HWND(win32.hwnd.get() as *mut core::ffi::c_void);
        let taskbar = taskbar()?;
        if count <= 0 {
            // SAFETY: a null icon removes the overlay of a live window.
            return unsafe { taskbar.SetOverlayIcon(hwnd, HICON::default(), PCWSTR::null()) }
                .map_err(|err| err.to_string());
        }
        let icon = badge_icon(count)?;
        let description = HSTRING::from(description);
        // SAFETY: the taskbar copies the icon, so it is destroyed right after.
        let result = unsafe { taskbar.SetOverlayIcon(hwnd, icon, &description) };
        // SAFETY: `icon` came from CreateIconIndirect and is no longer used.
        let _ = unsafe { DestroyIcon(icon) };
        result.map_err(|err| err.to_string())
    }

    /// The taskbar COM object, created once per UI thread.
    fn taskbar() -> Result<ITaskbarList3, String> {
        TASKBAR.with(|cell| {
            if let Some(existing) = cell.borrow().as_ref() {
                return Ok(existing.clone());
            }
            // SAFETY: plain COM setup on the UI thread; an apartment the
            // windowing layer already set up is reported and kept.
            let created: ITaskbarList3 = unsafe {
                let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
                CoCreateInstance(&TaskbarList, None, CLSCTX_INPROC_SERVER)
            }
            .map_err(|err| err.to_string())?;
            // SAFETY: required once before any other ITaskbarList3 call.
            unsafe { created.HrInit() }.map_err(|err| err.to_string())?;
            *cell.borrow_mut() = Some(created.clone());
            Ok(created)
        })
    }

    fn badge_icon(count: i32) -> Result<HICON, String> {
        let pixels = badge_pixels(count);
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: SIZE as i32,
                // Negative: rows top to bottom, like `badge_pixels`.
                biHeight: -(SIZE as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: a 32-bit top-down DIB of SIZE x SIZE pixels; `bits` points
        // at exactly `pixels.len()` u32 values once it succeeds.
        unsafe {
            let color = CreateDIBSection(None, &info, DIB_RGB_COLORS, &mut bits, None, 0)
                .map_err(|err| err.to_string())?;
            std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits.cast::<u32>(), pixels.len());
            let mask = CreateBitmap(SIZE as i32, SIZE as i32, 1, 1, None);
            let icon = CreateIconIndirect(&ICONINFO {
                fIcon: true.into(),
                xHotspot: 0,
                yHotspot: 0,
                hbmMask: mask,
                hbmColor: color,
            });
            let _ = DeleteObject(color.into());
            let _ = DeleteObject(mask.into());
            icon.map_err(|err| err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badge_is_a_red_disc_with_white_digits() {
        let one = badge_pixels(1);
        assert_eq!(one.len(), SIZE * SIZE);
        // Corners stay transparent, the rim is opaque red.
        assert_eq!(one[0] >> 24, 0);
        assert_eq!(one[8 * SIZE + 1], 0xFFD3_2F2F);
        // The "1" stem (column 1 of the glyph) is white, its sides aren't.
        let top = (SIZE - 10) / 2;
        let left = (SIZE - 6) / 2;
        assert_eq!(one[(top + 4) * SIZE + left + 2], 0xFFFF_FFFF);
        assert_ne!(one[(top + 4) * SIZE + left], 0xFFFF_FFFF);
        // Two digits still fit inside the disc; the count is capped at 99.
        assert_eq!(badge_pixels(150), badge_pixels(99));
        let ninety_nine = badge_pixels(99);
        for (index, pixel) in ninety_nine.iter().enumerate() {
            if *pixel == 0xFFFF_FFFF {
                let (x, y) = (index % SIZE, index / SIZE);
                assert!(one[y * SIZE + x] >> 24 > 0, "digit pixel off the disc");
            }
        }
    }
}
