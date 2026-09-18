//! Shared core of Cordiale.
//!
//! This crate hosts the domain model, the Grappa protocol, persistence and
//! network services. The GUI depends on the core, never the other way
//! around.

#![forbid(unsafe_code)]

/// Stable application name.
pub const APP_NAME: &str = "Cordiale";

/// Initial client version, distinct from the Grappa protocol version.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod client;
pub mod credentials;
pub mod domain;
pub mod persistence;
pub mod protocol;
pub mod rest;
