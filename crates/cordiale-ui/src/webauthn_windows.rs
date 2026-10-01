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

//! The Windows ceremony backend: the client API of `webauthn.dll`, which
//! reaches Windows Hello, USB/NFC security keys, a phone and registered
//! passkey managers. The caller hands over its own `clientDataJSON` and
//! the RP ID, as libfido2's `winhello.c` does; nothing here checks that an
//! unpackaged app "owns" the RP ID.
//!
//! All the unsafe FFI of the passkey feature is in this module:
//!
//! - `webauthn.dll` is loaded at run time (`LoadLibraryExW` from System32,
//!   `GetProcAddress`), never linked: the `windows` crate's own wrappers
//!   would put it in the import table, and a Windows without the DLL or one
//!   of its exports would then refuse to start Cordiale at all. Only the
//!   crate's struct and constant definitions are used.
//! - Every input struct uses the oldest version that has the fields we
//!   set (the DLL reads a struct only up to its `dwVersion`), and points
//!   into locals that outlive the blocking call.
//! - What the DLL returns is copied out and freed with its own free
//!   function, exactly once.

use std::ffi::c_void;
use std::sync::OnceLock;

use windows::core::{s, w, BOOL, HRESULT, PCWSTR};
use windows::Win32::Foundation::{ERROR_CANCELLED, ERROR_TIMEOUT, HWND, NTE_USER_CANCELLED};
use windows::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_API_VERSION_1, WEBAUTHN_API_VERSION_3, WEBAUTHN_ASSERTION,
    WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
    WEBAUTHN_CREDENTIAL, WEBAUTHN_CREDENTIALS, WEBAUTHN_CREDENTIAL_ATTESTATION,
    WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3, WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CTAP_TRANSPORT_BLE,
    WEBAUTHN_CTAP_TRANSPORT_HYBRID, WEBAUTHN_CTAP_TRANSPORT_INTERNAL, WEBAUTHN_CTAP_TRANSPORT_NFC,
    WEBAUTHN_CTAP_TRANSPORT_USB, WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_RP_ENTITY_INFORMATION,
    WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_ENTITY_INFORMATION,
    WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

use crate::ceremony::{
    AssertionRequest, AssertionResponse, CeremonyError, CredentialRequest, CredentialResponse,
    ParentWindow,
};

// The exported functions, as `webauthn.h` declares them.
type RawProc = unsafe extern "system" fn() -> isize;
type GetApiVersionNumber = unsafe extern "system" fn() -> u32;
type GetAssertion = unsafe extern "system" fn(
    HWND,
    PCWSTR,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    *mut *mut WEBAUTHN_ASSERTION,
) -> HRESULT;
type MakeCredential = unsafe extern "system" fn(
    HWND,
    *const WEBAUTHN_RP_ENTITY_INFORMATION,
    *const WEBAUTHN_USER_ENTITY_INFORMATION,
    *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
) -> HRESULT;
type FreeAssertion = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);
type FreeCredentialAttestation = unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION);

/// The loaded API. The DLL stays loaded for the life of the process, so
/// the function pointers never dangle.
struct Api {
    version: u32,
    get_assertion: GetAssertion,
    make_credential: MakeCredential,
    free_assertion: FreeAssertion,
    free_attestation: FreeCredentialAttestation,
}

fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(load).as_ref()
}

/// Loads `webauthn.dll` from System32 and resolves the functions Cordiale
/// calls. `None` before Windows 10 1903 (API version 1), which is also
/// where `WebAuthNGetApiVersionNumber` first appeared.
fn load() -> Option<Api> {
    // SAFETY: loading a system DLL by name from System32 only; the module
    // handle is never freed, which keeps every pointer below valid. Each
    // transmute turns `GetProcAddress`'s generic function pointer into the
    // signature `webauthn.h` declares for that export.
    unsafe {
        let module = LoadLibraryExW(w!("webauthn.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32).ok()?;
        let version_proc = GetProcAddress(module, s!("WebAuthNGetApiVersionNumber"))?;
        let version = std::mem::transmute::<RawProc, GetApiVersionNumber>(version_proc)();
        if version < WEBAUTHN_API_VERSION_1 {
            return None;
        }
        let get_assertion = GetProcAddress(module, s!("WebAuthNAuthenticatorGetAssertion"))?;
        let make_credential = GetProcAddress(module, s!("WebAuthNAuthenticatorMakeCredential"))?;
        let free_assertion = GetProcAddress(module, s!("WebAuthNFreeAssertion"))?;
        let free_attestation = GetProcAddress(module, s!("WebAuthNFreeCredentialAttestation"))?;
        Some(Api {
            version,
            get_assertion: std::mem::transmute::<RawProc, GetAssertion>(get_assertion),
            make_credential: std::mem::transmute::<RawProc, MakeCredential>(make_credential),
            free_assertion: std::mem::transmute::<RawProc, FreeAssertion>(free_assertion),
            free_attestation: std::mem::transmute::<RawProc, FreeCredentialAttestation>(
                free_attestation,
            ),
        })
    }
}

pub fn available() -> bool {
    api().is_some()
}

pub fn get_assertion(
    request: &AssertionRequest,
    parent: Option<ParentWindow>,
) -> Result<AssertionResponse, CeremonyError> {
    let api = api().ok_or(CeremonyError::Unsupported)?;
    let rp_id = wide(&request.rp_id);
    let client_data = client_data(&request.client_data_json)?;
    // The DLL only reads the ids; the struct field just isn't `const`.
    let mut allowed = request
        .allow_credentials
        .iter()
        .map(|id| -> Result<WEBAUTHN_CREDENTIAL, CeremonyError> {
            Ok(WEBAUTHN_CREDENTIAL {
                dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                cbId: length(id)?,
                pbId: id.as_ptr().cast_mut(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1,
        dwTimeoutMilliseconds: request.timeout_ms,
        // An empty list asks for a discoverable credential.
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: length(&allowed)?,
            pCredentials: if allowed.is_empty() {
                std::ptr::null_mut()
            } else {
                allowed.as_mut_ptr()
            },
        },
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        ..Default::default()
    };
    let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
    // SAFETY: `rp_id`, `client_data` (and the JSON it points to),
    // `options` and `allowed` all outlive this blocking call; the DLL only
    // writes `assertion`.
    let result = unsafe {
        (api.get_assertion)(
            parent_hwnd(parent),
            PCWSTR(rp_id.as_ptr()),
            &client_data,
            &options,
            &mut assertion,
        )
    };
    if result.is_err() {
        return Err(ceremony_error(result));
    }
    if assertion.is_null() {
        return Err(CeremonyError::Failed("no assertion returned".into()));
    }
    // SAFETY: a successful call returns a valid assertion, read here and
    // then freed once with the DLL's own function.
    let response = unsafe {
        let answer = &*assertion;
        let user_handle = copy_bytes(answer.pbUserId, answer.cbUserId);
        let response = AssertionResponse {
            credential_id: copy_bytes(answer.Credential.pbId, answer.Credential.cbId),
            authenticator_data: copy_bytes(answer.pbAuthenticatorData, answer.cbAuthenticatorData),
            signature: copy_bytes(answer.pbSignature, answer.cbSignature),
            user_handle: (!user_handle.is_empty()).then_some(user_handle),
        };
        (api.free_assertion)(assertion);
        response
    };
    if response.credential_id.is_empty() || response.signature.is_empty() {
        return Err(CeremonyError::Failed("incomplete assertion".into()));
    }
    Ok(response)
}

pub fn make_credential(
    request: &CredentialRequest,
    parent: Option<ParentWindow>,
) -> Result<CredentialResponse, CeremonyError> {
    let api = api().ok_or(CeremonyError::Unsupported)?;
    let rp_id = wide(&request.rp_id);
    let rp_name = wide(&request.rp_name);
    let user_name = wide(&request.user_name);
    let user_display_name = wide(&request.user_display_name);
    let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        pwszId: PCWSTR(rp_id.as_ptr()),
        pwszName: PCWSTR(rp_name.as_ptr()),
        pwszIcon: PCWSTR::null(),
    };
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: length(&request.user_id)?,
        // Read only, like the credential ids above.
        pbId: request.user_id.as_ptr().cast_mut(),
        pwszName: PCWSTR(user_name.as_ptr()),
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: PCWSTR(user_display_name.as_ptr()),
    };
    let mut parameters: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> = request
        .algorithms
        .iter()
        .map(|algorithm| WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: *algorithm,
        })
        .collect();
    let cose = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: length(&parameters)?,
        pCredentialParameters: parameters.as_mut_ptr(),
    };
    let client_data = client_data(&request.client_data_json)?;
    let mut options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1,
        dwTimeoutMilliseconds: request.timeout_ms,
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        bRequireResidentKey: BOOL::from(request.require_resident_key),
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        ..Default::default()
    };
    // "Preferred" resident keys need options version 4 (API version 3,
    // Windows 10 2004); older systems decide on their own.
    if request.prefer_resident_key && api.version >= WEBAUTHN_API_VERSION_3 {
        options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4;
        options.bPreferResidentKey = BOOL::from(true);
    }
    let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
    // SAFETY: every string, id, parameter list and the client data
    // outlive this blocking call; the DLL only writes `attestation`.
    let result = unsafe {
        (api.make_credential)(
            parent_hwnd(parent),
            &rp,
            &user,
            &cose,
            &client_data,
            &options,
            &mut attestation,
        )
    };
    if result.is_err() {
        return Err(ceremony_error(result));
    }
    if attestation.is_null() {
        return Err(CeremonyError::Failed("no credential returned".into()));
    }
    // SAFETY: a successful call returns a valid attestation, read here
    // and then freed once with the DLL's own function. `dwUsedTransport`
    // only exists from version 3 of the struct.
    let response = unsafe {
        let answer = &*attestation;
        let transport = if answer.dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3 {
            transport_name(answer.dwUsedTransport)
        } else {
            None
        };
        let response = CredentialResponse {
            credential_id: copy_bytes(answer.pbCredentialId, answer.cbCredentialId),
            authenticator_data: copy_bytes(answer.pbAuthenticatorData, answer.cbAuthenticatorData),
            transports: transport.into_iter().map(str::to_string).collect(),
        };
        (api.free_attestation)(attestation);
        response
    };
    if response.credential_id.is_empty() || response.authenticator_data.is_empty() {
        return Err(CeremonyError::Failed("incomplete credential".into()));
    }
    Ok(response)
}

/// The client data struct over `json`, which must outlive its use.
fn client_data(json: &[u8]) -> Result<WEBAUTHN_CLIENT_DATA, CeremonyError> {
    Ok(WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: length(json)?,
        // Read only: the DLL hashes these bytes.
        pbClientDataJSON: json.as_ptr().cast_mut(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    })
}

/// The dialog's owner: Cordiale's window, or whatever is in front when
/// its handle couldn't be read.
fn parent_hwnd(parent: Option<ParentWindow>) -> HWND {
    match parent {
        Some(parent) => HWND(parent.0 as *mut c_void),
        // SAFETY: a plain query with no arguments.
        None => unsafe { GetForegroundWindow() },
    }
}

/// Cancelled and timed out read the same to the user; so does "no passkey
/// here", which Windows reports through its own dialog first and then as
/// a cancellation. Everything else keeps its code for the log.
fn ceremony_error(result: HRESULT) -> CeremonyError {
    if result == NTE_USER_CANCELLED
        || result == HRESULT::from_win32(ERROR_CANCELLED.0)
        || result == HRESULT::from_win32(ERROR_TIMEOUT.0)
    {
        CeremonyError::Cancelled
    } else {
        CeremonyError::Failed(format!("{:#010x} {}", result.0, result.message()))
    }
}

fn transport_name(transport: u32) -> Option<&'static str> {
    match transport {
        WEBAUTHN_CTAP_TRANSPORT_USB => Some("usb"),
        WEBAUTHN_CTAP_TRANSPORT_NFC => Some("nfc"),
        WEBAUTHN_CTAP_TRANSPORT_BLE => Some("ble"),
        WEBAUTHN_CTAP_TRANSPORT_INTERNAL => Some("internal"),
        WEBAUTHN_CTAP_TRANSPORT_HYBRID => Some("hybrid"),
        _ => None,
    }
}

/// A null-terminated UTF-16 copy of `text`.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn length<T>(items: &[T]) -> Result<u32, CeremonyError> {
    u32::try_from(items.len()).map_err(|_| CeremonyError::InvalidOptions("length"))
}

/// Copies `length` bytes the DLL returned; nothing for a null pointer.
///
/// # Safety
///
/// A non-null `pointer` must be valid for `length` bytes.
unsafe fn copy_bytes(pointer: *const u8, length: u32) -> Vec<u8> {
    if pointer.is_null() || length == 0 {
        return Vec::new();
    }
    // SAFETY: the caller guarantees `length` readable bytes at `pointer`.
    unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec()
}
