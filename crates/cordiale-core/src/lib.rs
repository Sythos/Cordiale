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

pub mod credentials;
pub mod domain;
pub mod persistence;

/// Placeholder for the protocol boundary, to be implemented in Phase 1.
pub mod protocol {
    /// Compatibility contract for messages/events received from the server.
    ///
    /// The final parser must ignore unknown fields and events, and respect
    /// `protocol_version` and `min_protocol_version`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CompatibilityPolicy;
}
