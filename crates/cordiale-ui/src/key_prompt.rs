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

//! The security key prompt of the USB backend (issue #161): with no system
//! dialog on Linux and macOS, Cordiale says when to touch the key, asks for
//! its PIN and offers a retry in an overlay of its own (`key-prompt-*` in
//! the window). The ceremony runs on a blocking thread while the worker
//! waits for it, so the overlay's answers go straight to that thread over
//! a channel, never through the worker.

use std::sync::mpsc::{channel, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use slint::ComponentHandle;

use crate::AppWindow;

/// What the user answered.
pub(crate) enum Reply {
    Pin(String),
    Retry,
    Cancel,
}

/// How long a question waits: the life of Grappa's challenge. A prompt
/// left open must not hold the worker forever.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(300);

static WINDOW: OnceLock<slint::Weak<AppWindow>> = OnceLock::new();
/// Where the overlay's buttons send their answer while a question is open.
static ANSWER: Mutex<Option<Sender<Reply>>> = Mutex::new(None);

/// Wires the overlay; called once at start-up.
pub(crate) fn install(ui: &AppWindow) {
    let _ = WINDOW.set(ui.as_weak());
    ui.on_key_prompt_submit(|pin| answer(Reply::Pin(pin.to_string())));
    ui.on_key_prompt_retry(|| answer(Reply::Retry));
    ui.on_key_prompt_cancel(|| answer(Reply::Cancel));
}

/// Tells the user to touch the key, which now waits for it.
pub(crate) fn touching() {
    show("touch", "", -1);
}

/// Shows `step` ("pin" or "error") with the `key-*` reason and waits for
/// the answer. The PIN field is emptied every time the overlay changes.
pub(crate) fn ask(step: &'static str, reason: &'static str, retries: i32) -> Reply {
    let (sender, receiver) = channel();
    set_answer(Some(sender));
    show(step, reason, retries);
    let reply = receiver
        .recv_timeout(ANSWER_TIMEOUT)
        .unwrap_or(Reply::Cancel);
    set_answer(None);
    reply
}

/// Hides the overlay when the ceremony ends, however it ends.
pub(crate) struct Overlay;

impl Drop for Overlay {
    fn drop(&mut self) {
        show("", "", -1);
    }
}

fn show(step: &'static str, reason: &'static str, retries: i32) {
    if let Some(window) = WINDOW.get() {
        let _ = window.upgrade_in_event_loop(move |ui| {
            ui.set_key_prompt_step(step.into());
            ui.set_key_prompt_error(reason.into());
            ui.set_key_prompt_retries(retries);
            ui.set_key_prompt_pin("".into());
        });
    }
}

fn set_answer(sender: Option<Sender<Reply>>) {
    if let Ok(mut slot) = ANSWER.lock() {
        *slot = sender;
    }
}

fn answer(reply: Reply) {
    if let Ok(Some(sender)) = ANSWER.lock().as_deref() {
        let _ = sender.send(reply);
    }
}
