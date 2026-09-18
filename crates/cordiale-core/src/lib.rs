//! Core condivisibile di Cordiale.
//!
//! Questo crate ospiterà il modello di dominio, il protocollo Grappa, la
//! persistenza e i servizi di rete. La GUI deve dipendere dal core, non il
//! contrario.

#![forbid(unsafe_code)]

/// Nome stabile dell’applicazione.
pub const APP_NAME: &str = "Cordiale";

/// Versione iniziale del client, distinta dalla versione del protocollo Grappa.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Segnaposto per il confine del protocollo, da implementare nella Fase 1.
pub mod protocol {
    /// Contratto di compatibilità per messaggi/eventi ricevuti dal server.
    ///
    /// Il parser definitivo dovrà ignorare campi ed eventi sconosciuti e
    /// rispettare `protocol_version` e `min_protocol_version`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CompatibilityPolicy;
}
