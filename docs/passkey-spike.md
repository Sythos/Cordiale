# Spike passkey (WebAuthn) — issue #147

Obiettivo: capire se e come Cordiale, client nativo e non browser, può
produrre ceremonie WebAuthn che Grappa accetta, e cosa si può implementare
subito senza un autenticatore fisico per provarlo.

Legenda usata in tutto il documento:

- **[verificato]** = letto nel sorgente (Grappa, Cicchetto, la libreria Wax
  0.7.0 che Grappa usa, i crate Rust citati) o nella documentazione ufficiale
  della piattaforma;
- **[dedotto]** = conclusione ragionevole ma non provata su un'istanza reale,
  su hardware o in CI.

Nessuna ceremonia è stata eseguita contro un Grappa reale: non c'era un
autenticatore a disposizione. Le verifiche sono tutte sul codice.

## Verdetti in breve

| Piattaforma | Meccanismo | Verdetto |
|---|---|---|
| Windows 10 1903+ / 11 | API client di `webauthn.dll` (`WebAuthNAuthenticatorGetAssertion` / `MakeCredential`) | **Implementata (issue #160), non provata**: strutture del crate `windows` 0.62, DLL caricata a runtime, il chiamante fornisce il `clientDataJSON` (vedi "Windows: com'è implementata") |
| macOS, passkey di piattaforma/iCloud | AuthenticationServices | **Non fattibile**: richiede app firmata con Team ID Apple, entitlement `webcredentials:` e un file `apple-app-site-association` su **ogni** server Grappa |
| macOS, chiavette USB | CTAP2 su HID diretto | **Implementata dietro la feature cargo `ctap-hid` (issue #161), non provata**: solo chiavi fisiche con PIN, niente copertura CI su macOS (vedi "Linux e macOS: chiavette USB") |
| Linux | CTAP2 su hidraw (nessuna API di sistema) | **Implementata dietro la feature cargo `ctap-hid` (issue #161), non provata**: solo chiavi fisiche USB con PIN; passkey sincronizzate e telefono (hybrid) irraggiungibili |
| Tutte | Gestione senza autenticatore (elenco, eliminazione) e contratto tipizzato | **Fatto in questo ramo** |

## a) Origine e RP ID: come li controlla Grappa

**[verificato]** `GrappaWeb.PasskeyOrigin.origin/0`
(`lib/grappa_web/passkey_origin.ex`) restituisce `GRAPPA_PASSKEY_ORIGIN` se
l'operatore l'ha impostato, altrimenti `GrappaWeb.Endpoint.url()`. Ogni
ceremonia (login secondo fattore, passwordless, registrazione, cambio modo)
passa quel valore a `Grappa.Accounts.WebAuthn`, che costruisce la challenge
Wax con:

```elixir
[origin: origin, rp_id: URI.parse(origin).host, user_verification: "required", timeout: 300]
```

**[verificato]** Alla verifica, Wax 0.7.0 (`lib/wax.ex`, `register/3` e
`authenticate/6`) fa **due** controlli distinti:

1. `valid_origin?/2` chiama la funzione di default `Wax.origins_match?/2`, che
   è `client_data_origin in List.wrap(challenge_origin)`: confronto **esatto
   della stringa intera** (schema, host, porta), non del solo RP ID. Grappa
   passa una sola stringa, niente liste né `origin_verify_fun` personalizzata.
2. `valid_rp_id?/2` confronta `rpIdHash` nei dati dell'autenticatore con
   `SHA-256(rp_id)`, dove `rp_id` è l'host dell'origine.

Quindi il `clientDataJSON` deve contenere **esattamente** l'origine di
Grappa, e l'autenticatore deve essere interrogato con RP ID = host di quella
origine.

**Valori tipici.**

- **[verificato]** In produzione `config/runtime.exs` imposta
  `url: [host: PHX_HOST, scheme: "https", port: 443]`; **[dedotto]** con la
  porta di default Phoenix non la scrive, quindi l'origine è
  `https://<PHX_HOST>` e l'RP ID è `<PHX_HOST>`.
- **[dedotto]** Per l'istanza pubblica `https://irc.sindro.me`: origine
  `https://irc.sindro.me`, RP ID `irc.sindro.me`, **a meno che** l'operatore
  non abbia impostato `GRAPPA_PASSKEY_ORIGIN` (dall'esterno non si vede).
- **[verificato]** `.env.example` mostra
  `GRAPPA_PASSKEY_ORIGIN=http://localhost:5173` per lo sviluppo con Vite:
  in quel caso l'origine differisce dall'URL a cui si collega un client.

**Conseguenza pratica.** Le opzioni che Grappa invia contengono `rp_id` ma
**non** l'origine (`authentication_options/3` e `registration_options/3`,
[verificato]), e `/api/config` non la espone. Un client nativo deve
ricostruirla. La regola implementata (`cordiale_core::passkey_origin`,
issue #163) è: schema, host in minuscolo e porta dell'URL del server a cui
Cordiale è collegato, con la porta di default (443 per https, 80 per http)
omessa, senza percorso né credenziali; l'RP ID è l'host di quell'origine.
Se l'operatore ha un'origine diversa (porta non standard, dominio dietro
proxy, sviluppo), l'errore è il generico `401 invalid_two_factor`,
indistinguibile da un autenticatore sbagliato: per questo ogni server ha un
override locale (Connessione e Impostazioni > Sicurezza), salvato in
`servers.json` e mai inviato a Grappa, che va scritto come la stringa di
`GRAPPA_PASSKEY_ORIGIN` e sostituisce la regola. Una proposta a Grappa per
esporre l'origine (per esempio in `/api/config` o nelle opzioni)
eliminerebbe l'override; va fatta nel repository di Grappa.

## b) Cosa deve contenere il `clientDataJSON` e quali formati passano

**[verificato]** `Wax.ClientData.parse_raw_json/1` legge solo:

- `type`: `"webauthn.get"` per le asserzioni, `"webauthn.create"` per la
  registrazione (qualsiasi altro valore fa fallire la verifica);
- `challenge`: base64url **senza padding** dei byte della challenge; deve
  essere identico a `public_key.challenge` delle opzioni (i byte, non la
  stringa: Grappa li genera, 32 byte casuali);
- `origin`: la stringa esatta di §a;
- `tokenBinding`: facoltativo, se presente deve avere uno `status` valido.

`crossOrigin` e ogni altro campo sono ignorati. L'hash firmato è
`SHA-256` dei **byte grezzi** del JSON, quindi la serializzazione è libera
purché il client invii al server esattamente i byte che ha fatto firmare.

**Parametri della ceremonia [verificato in `webauthn.ex`].**

- Algoritmi ammessi in registrazione: `-7` (ES256) e `-257` (RS256).
- `user_verification: "required"` sia in registrazione sia in asserzione: Wax
  rifiuta i dati senza flag UV (`user_not_verified`). Serve biometria o PIN
  sull'autenticatore; una chiavetta senza PIN impostato non basta.
- Registrazione: `attestation: "none"`, `resident_key: "preferred"`.
- La porta passwordless (`/auth/passkeys/options`) **non** invia
  `allow_credentials` (un chiamante anonimo non riceve id di credenziali),
  quindi funziona solo con una credenziale **discoverable** (resident key).
  Secondo fattore e cambio modo invece inviano l'elenco completo.
- Challenge valida 300 s; consumata una volta sola
  (`WebAuthnChallengeStore.take/2`).
- Opzioni e verifica sono legate a `{ip, client_id}` del chiamante: vanno
  fatte dalla stessa connessione logica.
- Contatore di firma: un contatore che non avanza viene rifiutato come clone
  (`consume_sign_count/2`), con lo stesso `401 invalid_two_factor` opaco.

**Attestazione: solo `none` passa [verificato].** Grappa non sovrascrive la
preferenza di attestazione di Wax, il cui default in `Wax.Challenge` è
`attestation: "none"`. Con quel valore:

- il formato `none` è accettato;
- `packed` **con** `x5c`, `tpm`, `fido-u2f` e `android-key` rispondono
  `invalid_attestation_conveyance_preference` (accettati solo con
  `attestation: "direct"`);
- restano accettati `packed` in self-attestation (senza `x5c`) e `apple`.

Un browser, con `attestation: "none"`, sostituisce da sé l'attestazione. Un
client che parla CTAP2 direttamente riceve invece quella del dispositivo
(di solito `packed` con certificato) e **deve** ricodificare l'oggetto CBOR
come `{fmt: "none", attStmt: {}, authData}` prima di inviarlo, altrimenti la
registrazione fallisce. Con `webauthn.dll` si chiede
`WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE`; **[dedotto]** Windows
restituisce allora il formato `none`, ma per sicurezza conviene ricostruire
comunque l'oggetto dai `pbAuthenticatorData` restituiti.

**Corpi da inviare [verificato in `cicchetto/src/lib/passkeys.ts` e nel
controller].** Tutti i binari in base64url senza padding:

- asserzione: `{challenge_id, raw_id, authenticator_data, client_data_json,
  signature, user_handle}` (`user_handle` è inviato da Cicchetto ma il server
  non lo legge);
- registrazione: `{challenge_id, raw_id, attestation_object,
  client_data_json, transports}`.

## c) Un'app nativa può produrre un'asserzione per un'origine web?

### Windows — fattibile ora

- **[verificato]** L'API giusta è quella **client** di `webauthn.dll`
  (`WebAuthNAuthenticatorGetAssertion`, `WebAuthNAuthenticatorMakeCredential`,
  `WebAuthNGetApiVersionNumber`). La "plugin API" di Windows 11 serve al
  contrario: permette a un gestore di passkey di terze parti di *fornire*
  credenziali a Windows, non a un'app di *usarle*; non c'entra con Cordiale.
- **[verificato]** Il chiamante passa `WEBAUTHN_CLIENT_DATA {dwVersion,
  cbClientDataJSON, pbClientDataJSON, pwszHashAlgId}`, cioè il JSON completo
  costruito da lui, e l'RP ID come stringa. È esattamente ciò che fa
  libfido2 in `src/winhello.c` (`pack_cd`), che non è un browser.
- **[verificato]** Il crate `windows` 0.62.2, già dipendenza di
  `cordiale-ui` su Windows, espone tutte queste funzioni e strutture con la
  sola feature aggiuntiva `Win32_Networking_WindowsWebServices`: nessun crate
  nuovo, nessuna libreria di sistema, compila su `windows-latest` e non tocca
  Linux (`cfg(windows)`).
- **[verificato]** Serve un `HWND` padre per la finestra di sistema:
  Cordiale lo ricava già via `raw-window-handle` per il badge della taskbar
  (`taskbar.rs`). La chiamata è sincrona e bloccante: va fatta fuori dal
  thread UI (`spawn_blocking`).
- **[verificato]** L'accesso HID diretto alle chiavi FIDO su Windows richiede
  privilegi di amministratore (lo documenta `ctap-hid-fido2`): `webauthn.dll`
  è l'unica strada praticabile.
- **[dedotto]** Windows non verifica un'associazione tra app non pacchettizzata
  e RP ID (libfido2/OpenSSH usano la stessa API con RP ID arbitrari). Da
  `webauthn.dll` passano Windows Hello, chiavi USB/NFC, telefono via hybrid
  (Windows 11 recente) e gestori di passkey registrati: la stessa copertura di
  Edge/Chrome.
- Rischio residuo: l'origine va indovinata (§a).

### macOS — AuthenticationServices non fattibile, chiavette USB con riserva

- **[verificato]** `ASAuthorizationPlatformPublicKeyCredentialProvider` e
  `ASAuthorizationSecurityKeyPublicKeyCredentialProvider` richiedono
  l'entitlement `com.apple.developer.associated-domains` con
  `webcredentials:<dominio>`, un'app firmata con un Team ID (con firma ad-hoc
  gli entitlement non vengono applicati) e un file
  `apple-app-site-association` sul dominio che elenca `TEAMID.bundle-id`.
  Cordiale è distribuita non firmata, e ogni Grappa è self-hosted: servirebbe
  che ogni operatore pubblichi quel file per un ID app di cui il progetto non
  dispone. L'entitlement per i browser
  (`com.apple.developer.web-browser.public-key-credential`) è concesso da
  Apple solo ai browser. **Non fattibile**, e con questo restano fuori le
  passkey iCloud.
- **[dedotto]** Un'app non sandboxed può aprire le chiavi FIDO via IOKit HID
  senza entitlement (così facevano Chrome e Firefox prima dell'API di
  sistema; `ctap-hid-fido2` dichiara "nothing in particular" per macOS).
  Stesse condizioni di Linux: solo chiavi fisiche, PIN obbligatorio (UV
  richiesto), attestazione da ricodificare. Il CI di verifica non gira su
  macOS (solo il packaging), quindi ogni rottura si vedrebbe tardi.
  **Fattibile con riserva.**

### Linux — fattibile con riserva, solo chiavi fisiche

- **[verificato]** Non esiste un'API di piattaforma per WebAuthn: l'unica
  strada è CTAP2 su HID (`/dev/hidraw*`) verso una chiave fisica. Passkey
  sincronizzate (Google, iCloud, gestori) e telefono via hybrid (caBLE:
  QR + BLE + server tunnel) restano fuori.
- **[dedotto]** I permessi su hidraw: systemd (dalla 244) marca i dispositivi
  FIDO con `uaccess` per l'utente della sessione, quindi sui desktop moderni
  non servono regole udev manuali; sulle distribuzioni senza, sì.
- UV richiesto ⇒ l'app deve chiedere il **PIN** della chiave e fare il
  protocollo PIN/UV (ECDH P-256, AES, HMAC) per ottenere il flag UV; le chiavi
  senza PIN o biometria non passano.

**Crate valutati (stato su crates.io al 2026-09-30).**

| Crate | Versione / licenza | Note |
|---|---|---|
| `ctap-hid-fido2` | 3.6.0 (2026-09-05), MIT | **Candidato.** Sincrono, crypto `ring` (già nel grafo via rustls). **[verificato]** calcola `clientDataHash = SHA-256(challenge)` sull'argomento `challenge`: passandogli i byte del `clientDataJSON` si ottiene l'hash corretto. Restituisce `auth_data` grezzo, firma, id credenziale; gestisce PIN e resident key. Dipende da `hidapi` con `linux-static-hidraw` (compila il C di hidapi, richiede gli header di libudev) |
| `authenticator` (Mozilla) | 0.5.0 (2025-10), MPL-2.0 | Accetta `client_data_hash` diretto, feature `crypto_rust` pura Rust; su Linux usa `libudev`, su Windows `winapi` (inutile senza admin). Scartato in #161: crypto NSS di default, API a macchina di stati con callback, e tira `serde_cbor` (non più mantenuto) più copie vecchie di `base64`, `rand`, `bitflags` e `bytes` |
| `webauthn-authenticator-rs` (kanidm) | 0.5.5 (2026-04), MPL-2.0 | Costruisce il `clientDataJSON` da sé, ma `ctap2` tira `openssl` (su Windows richiede OpenSSL installato), `usb` tira `fido-hid-rs` con `bindgen` (libclang) e `udev`, `win10` usa `windows` 0.41 (duplicato). Troppo pesante |
| `libfido2-sys` / `fido2-rs` | 0.5.1 / 0.6.0, MIT | Richiedono libfido2 di sistema (o compilarla su Windows). Sconsigliati |

**CI.** **[verificato]** `udev` 0.9.3 e `libudev-sys` sono già nel
`Cargo.lock`, trascinati dal backend `linuxkms` di Slint (via `input`), e il
job Linux del CI è verde; **[dedotto]** gli header di libudev sono quindi già
disponibili sul runner `ubuntu-26.04`, e `ctap-hid-fido2` non aggiungerebbe
librerie di sistema. Il C di hidapi va però provato in CI prima di
contarci; su `windows-latest` hidapi compila senza librerie esterne, ma su
Windows il ramo HID non servirebbe (si usa `webauthn.dll`).

## d) Come il flusso di Cicchetto si traduce in chiamate

**[verificato]** in `cicchetto/src/Login.tsx`, `PasskeySettings.tsx`,
`lib/api.ts`, `lib/passkeys.ts` e nel router di Grappa.

| Flusso | Chiamate | Serve l'autenticatore? |
|---|---|---|
| Login con passkey come secondo fattore | `POST /auth/login` → `202 {passkey_options, totp_available, challenge_token}` → `navigator.credentials.get` → `POST /auth/passkeys/second-factor` → `{token, subject}` | Sì |
| Stesso 202, fallback codice | `challenge_token` non nullo → `POST /auth/totp/verify {challenge_token, code}`; con `totp_available: false` il codice può essere solo un recovery code | No |
| Login passwordless | `POST /auth/passkeys/options {identifier}` (30 per IP ogni 15 min) → `get` → `POST /auth/passkeys/verify` | Sì |
| Recupero passwordless | `POST /auth/passkeys/recover {identifier, recovery_code}` → `{token, subject}`; `429 too_many_attempts`, codice errato `401 invalid_two_factor` | No (consuma un codice) |
| Stato | `GET /me/passkeys` → `{mode, passkeys: [{id, name, inserted_at, last_used_at}]}` | No |
| Aggiunta | `POST /me/passkeys/registration/options {password, name}` → `navigator.credentials.create` → `POST /me/passkeys/registration` → `201` + riepilogo | Sì |
| Cambio modo (`second_factor`/`disabled`) | `POST /me/passkeys/mode/options {password, mode}` → `get` → `POST /me/passkeys/mode` → `{mode}` | Sì |
| Attivazione passwordless | `POST /me/passkeys/passwordless/recovery {password}` → `{recovery_codes, recovery_token}` (codici mostrati prima) → `POST /me/passkeys/passwordless/options {recovery_token}` → `get` → `POST /me/passkeys/mode` | Sì |
| Eliminazione | `DELETE /me/passkeys/:id {password}` → `204`; `409 passkey_required` se è l'ultima e il modo è armato; `404 not_found` | No |
| Rinomina | **Nessun endpoint** in Grappa | — |

Tutte le route `/me/passkeys*` passano da `RequireFullSession`: un token
per-client riceve `403 client_token_scope`. Cordiale le raggiunge solo se è
entrato con la password (come per il TOTP). I codici dei recovery generati da
`passwordless/recovery` diventano validi solo al `POST /me/passkeys/mode`
riuscito: mostrarli senza poter completare la ceremonia darebbe all'utente
codici inutili, quindi Cordiale non chiama quella route.

**[verificato]** Un account in modo `passwordless` che prova la password
riceve `401 invalid_credentials` (`AuthController`, ramo `:passwordless`):
per Cordiale oggi è indistinguibile da una password errata.

## Cosa entra in questo ramo

Solo ciò che non dipende da un autenticatore ed è verificabile con un server
simulato:

- `cordiale-core`: il contratto tipizzato di tutte le route passkey
  (opzioni di asserzione e di registrazione, corpi di asserzione e
  credenziale, stato, modo, recovery passwordless) come metodi di
  `GrappaClient`, con test wiremock; il `202` ora conserva `passkey_options`
  tipizzate e `totp_available`.
- Settings → Security: elenco delle passkey con modo, data di creazione e
  ultimo uso, eliminazione con password; testo che spiega che aggiunta e
  cambio modo richiedono ancora Cicchetto.
- Login: con un 202 in cui la passkey è accompagnata solo dai recovery code
  (`totp_available: false`), il passo codice chiede un recovery code invece
  del codice dell'app.

## Windows: com'è implementata (issue #160)

La ricetta di §a e §b, scritta senza compilatore locale (la compilazione la
fa il CI su `windows-latest`) e **mai provata con un autenticatore reale**:

- **Separazione.** `crates/cordiale-ui/src/ceremony.rs` è la cucitura
  indipendente dalla piattaforma: tipi di richiesta e risposta già
  decodificati, `available()`, `get_assertion()` e `make_credential()` che
  passano al backend della piattaforma (altrove rispondono `Unsupported`),
  più le funzioni pure con i test che girano anche su Linux:
  `clientDataJSON`, base64url, corpi JSON di Grappa e oggetto di
  attestazione `none`. Tutto l'FFI `unsafe` sta in `webauthn_windows.rs`.
- **Caricamento.** `webauthn.dll` è caricata a runtime da System32
  (`LoadLibraryExW` + `GetProcAddress`), non collegata: con l'import diretto
  del crate `windows` un sistema senza la DLL non avvierebbe Cordiale. Serve
  `WebAuthNGetApiVersionNumber` (Windows 10 1903+); senza, i pulsanti passkey
  non compaiono.
- **Ceremonia.** `clientDataJSON` costruito da Cordiale (`type`,
  `challenge` base64url senza padding, `origin`, `crossOrigin: false`); RP ID
  = `rp_id` delle opzioni; UV `REQUIRED`; strutture di opzioni alla
  versione più vecchia che basta (versione 4 di `MakeCredential` solo per
  `bPreferResidentKey`, con API 3+); elenco `allow_credentials` vuoto sulla
  porta passwordless (credenziale discoverable); attestazione
  `NONE`, e l'oggetto inviato a Grappa è comunque ricostruito come
  `{fmt: "none", attStmt: {}, authData}` dai `pbAuthenticatorData`.
- **Origine.** Quella di §a (override per server se salvato, altrimenti
  dall'URL); se il suo host non coincide con `rp_id` si usa
  `https://<rp_id>`, perché un'origine con un altro host non può passare.
- **Thread.** L'`HWND` della finestra è letto sul thread UI; la chiamata
  bloccante gira con `spawn_blocking`. In Settings la ceremonia gira in un
  task a parte, così la sessione continua mentre il dialogo è aperto.
- **Flussi.** Secondo fattore (pulsante "Usa una passkey" nel passo del
  codice, anche quando la passkey è l'unico fattore), login passwordless
  dalla schermata di connessione, aggiunta di una passkey, cambio modo
  (`second_factor`/`disabled`) e attivazione passwordless in due passi
  (codici mostrati prima). Opzioni e verifica passano dallo stesso client.
- **Errori.** Annullata, scaduta o "nessuna passkey qui" danno lo stesso
  messaggio (Windows non li distingue in modo affidabile); il codice
  `HRESULT` va nel log. Un `401 invalid_two_factor` resta opaco (§a).

## Linux e macOS: chiavette USB (issue #161)

Scritta senza compilatore locale e **mai provata con una chiave reale**;
il CI di default non la compila (vedi sotto).

- **Crate.** `ctap-hid-fido2` 3.6.0, sorgente letto: API sincrona,
  `GetAssertionArgsBuilder` / `MakeCredentialArgsBuilder` con PIN, allow
  list e resident key; riceve i byte del `clientDataJSON` della cucitura e
  ne firma lo SHA-256; restituisce `auth_data` grezzo, firma, id della
  credenziale e `user.id`. Crea chiavi ES256 (-7), che Grappa accetta.
- **Feature spenta di default.** Dipendenza **opzionale**, solo per Linux e
  macOS, dietro la feature cargo `ctap-hid`: il build normale, il CI e i
  pacchetti di rilascio non cambiano. Nel `Cargo.lock` entrano 22 pacchetti
  nuovi senza che cambi la versione di quelli esistenti; l'advisory DB di
  RustSec non ha avvisi aperti per quelle versioni (`anyhow` 1.0.104 e
  `time` 0.3.55 sono già oltre le correzioni). Per compilarla serve il C di
  `hidapi`: su Linux gli header di libudev (`libudev-dev`, via
  `pkg-config`) e a runtime `libudev.so.1`; su macOS i framework IOKit e
  CoreFoundation. Si attiva con
  `cargo build --release --package cordiale-ui --features ctap-hid`.
- **Aggancio.** Il backend (`ceremony_ctap.rs`) si innesta in
  `ceremony.rs` come terzo ramo del `cfg`: `available()` diventa vero e i
  flussi di #160 (secondo fattore, passwordless, aggiunta, cambio modo,
  attivazione passwordless) lo usano senza modifiche. Il backend riceve
  richieste già decodificate e restituisce byte grezzi; `clientDataJSON`,
  attestazione `none` e corpi di Grappa restano della cucitura, con i suoi
  test.
- **PIN e tocco.** Non c'è un dialogo di sistema, quindi Cordiale mostra un
  riquadro suo (`key_prompt.rs`): "tocca la chiave" quando aspetta, il
  campo PIN quando la chiave ne ha uno (UV è obbligatorio), l'errore con
  "Riprova". Il primo tentativo va senza PIN: se la chiave lo chiede, si
  rifà con le stesse opzioni (Grappa le consuma solo alla verifica). Le
  risposte del riquadro vanno dritte al thread della ceremonia, non al
  worker, che intanto aspetta; ogni domanda scade dopo 5 minuti (la vita
  della challenge) come un annullamento.
- **Decisioni testate nel CI di default** (`cordiale-core/src/security_key.rs`):
  PIN o verifica integrata dalle opzioni `clientPin`/`uv`, regole del PIN
  (4-63 caratteri), protocollo PIN 1 o 2, flag UP e UV della risposta,
  credenziale omessa con allow list di un solo elemento, resident key
  richiesta o preferita, e lettura degli stati CTAP2 (PIN errato con i
  tentativi rimasti, bloccato, chiave non registrata, tempo scaduto...).
- **[dedotto] Limiti.** Una sola chiave inserita alla volta; mentre la
  chiave lampeggia la ceremonia non si può annullare (il crate rinuncia
  dopo circa un minuto); sulla porta passwordless, con più passkey dello
  stesso server sulla chiave, risponde la prima; il nome dell'RP non viene
  passato alla chiave (il crate non lo prevede).

## Cosa resta aperto

1. **Prova su Windows** della ceremonia (secondo fattore, passwordless,
   registrazione, cambio modo, attivazione passwordless; vedi "Windows: com'è
   implementata") contro un'istanza Grappa di prova con
   `GRAPPA_PASSKEY_ORIGIN` noto, con Windows Hello e con una chiavetta USB.
2. **Chiavette USB su Linux/macOS** (#161): fatte dietro la feature
   `ctap-hid` (vedi "Linux e macOS: chiavette USB"); restano la prova con
   una chiave reale con PIN contro un Grappa con origine nota, e un job CI
   che compili la feature (Linux con `libudev-dev`, macOS) prima di
   accenderla nei pacchetti.
3. **Origine**: regola di ricostruzione e override per server fatti (§a);
   resta da chiedere a Grappa di esporla, così l'override non servirebbe.
4. **Login con recovery code** per gli account passwordless (non richiede
   autenticatore; il metodo client esiste, manca l'ingresso nella schermata
   di connessione).
5. Rinomina: servirebbe un endpoint lato Grappa.
