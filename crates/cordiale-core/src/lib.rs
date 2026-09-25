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

//! Shared core of Cordiale.
//!
//! This crate hosts the domain model, the Grappa protocol, persistence and
//! network services. The GUI depends on the core, never the other way
//! around.

#![forbid(unsafe_code)]

/// Initial client version, distinct from the Grappa protocol version.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod admin;
pub mod bootstrap;
pub mod client;
pub mod credentials;
pub mod domain;
pub mod formatting;
pub mod isupport;
pub mod links;
pub mod persistence;
pub mod phoenix;
pub mod profile;
pub mod protocol;
pub mod radio;
pub mod rest;
pub mod session;
pub mod slash;
pub mod theme;
pub mod upload;
pub mod websocket;
pub mod wire_event;
