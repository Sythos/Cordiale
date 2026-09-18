//! Modello di dominio: server, profili e metodo di autenticazione.
//!
//! Un server è identificato dalla propria `base_url`; un profilo appartiene
//! a un server ed è identificato da `(server_base_url, identifier)`. Le
//! credenziali vere e proprie non vivono qui: sono responsabilità del
//! `CredentialStore` (Fase 1, punto 3), interrogato con la stessa chiave.

use serde::{Deserialize, Serialize};

/// Un server Grappa a cui l'utente può connettersi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    /// URL di base del server, usata anche come chiave identificativa.
    pub base_url: String,
    /// Etichetta mostrata all'utente in fase di selezione server.
    pub label: String,
}

/// Come un profilo si autentica su `POST /auth/login`.
///
/// Entrambe le varianti viaggiano sul campo wire `password`, ma vanno tenute
/// distinte localmente: un token per-client è scoped e un `403
/// client_token_scope` non va mai trattato come una password sbagliata da
/// far ritentare all'utente (vedi `docs/protocol-notes.md`, §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Password,
    ClientToken,
}

/// Un profilo con cui autenticarsi su un determinato server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// `base_url` del `Server` a cui appartiene.
    pub server_base_url: String,
    /// Identificatore inviato come `identifier` in `POST /auth/login`.
    pub identifier: String,
    pub auth_method: AuthMethod,
    /// Se `true`, il profilo va riproposto come selezionabile agli avvii
    /// successivi; la credenziale resta comunque nel `CredentialStore`, mai
    /// qui.
    pub remembered: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_round_trips_through_json() {
        let server = Server {
            base_url: "https://irc.sindro.me".to_string(),
            label: "Sindro".to_string(),
        };

        let json = serde_json::to_string(&server).expect("serialize");
        let decoded: Server = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(server, decoded);
    }

    #[test]
    fn profile_round_trips_through_json() {
        let profile = Profile {
            server_base_url: "https://irc.sindro.me".to_string(),
            identifier: "vjt".to_string(),
            auth_method: AuthMethod::ClientToken,
            remembered: true,
        };

        let json = serde_json::to_string(&profile).expect("serialize");
        let decoded: Profile = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(profile, decoded);
    }
}
