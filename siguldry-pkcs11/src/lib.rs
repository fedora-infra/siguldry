// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A PKCS#11 module that implemented the bare minimum to support signing using keys in
//! a Siguldry server.
//!
//! This module requires that users have set up a siguldry-client proxy.
//!
//! TODOs:
//!   - Complete audit of unsafe code and add missing safety documentation
//!   - Remove unwrap() (except for locking related code) throughout.
//!   - Figure out how to properly present PGP keys such that Sequoia can use
//!     them via its cryptoki backend
//!   - Add test coverage for signing RPMs, containers, UEFI applications, etc
//!     via pesign, rpmsign, cosign + openssl, etc.
//!
//! For PGP, target working with https://gitlab.com/sequoia-pgp/sequoia-keystore/-/tree/neal/cryptoki/cryptoki?ref_type=heads

#![allow(non_snake_case)]
use std::{
    collections::HashMap,
    ffi::CStr,
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex},
};

use cryptoki::context::CInitializeFlags;
use siguldry::protocol;
use tracing::{instrument, level_filters::LevelFilter};

use cryptoki_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_C_INITIALIZE_ARGS_PTR, CK_FLAGS, CK_FUNCTION_LIST,
    CK_FUNCTION_LIST_PTR, CK_INFO, CK_INFO_PTR, CK_INTERFACE, CK_INTERFACE_PTR,
    CK_INTERFACE_PTR_PTR, CK_MECHANISM_INFO, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_RV,
    CK_SESSION_HANDLE, CK_SLOT_ID, CK_SLOT_INFO_PTR, CK_TOKEN_INFO_PTR, CK_ULONG, CK_ULONG_PTR,
    CK_USER_TYPE, CK_UTF8CHAR, CK_UTF8CHAR_PTR, CK_VERSION, CK_VERSION_PTR, CKF_LOGIN_REQUIRED,
    CKF_SIGN, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT, CKF_USER_PIN_INITIALIZED, CKM_ECDSA,
    CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_512, CKM_ECDSA_SHA256, CKM_ECDSA_SHA512,
    CKM_SHA3_256_RSA_PKCS, CKM_SHA3_512_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL,
    CKR_CANT_LOCK, CKR_MECHANISM_INVALID, CKR_NEED_TO_CREATE_THREADS, CKR_OBJECT_HANDLE_INVALID,
    CKR_OK, CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INCORRECT,
    CKR_SESSION_HANDLE_INVALID, CKR_SLOT_ID_INVALID, CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN, CKR_USER_TYPE_INVALID, CKU_USER,
};

mod interfaces;
mod objects;
mod session;
mod sign;
mod unsupported;

use interfaces::{FUNCTIONS, INTERFACE_2_40, INTERFACE_3_0, INTERFACE_3_2, INTERFACES};
use objects::Attribute;
use session::Session;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt};

use siguldry::client::ProxyClient;

const DEFAULT_PROXY_SOCKET: &str = "/run/siguldry-client/proxy.socket";

// The spec indicates this should be blank character padded and _not_ null-terminated
const MANUFACTURER_ID: [u8; 32] = *b"Fedora Infrastructure           ";
// The spec indicates this should be blank character padded and _not_ null-terminated
const LIBRARY_DESCRIPTION: [u8; 32] = *b"Siguldry PKCS#11 Library        ";
const LIBRARY_VERSION: CK_VERSION = CK_VERSION { major: 1, minor: 0 };

/// Supported mechanisms for signing with RSA keys
const RSA_PKCS_MECHANISMS: [CK_MECHANISM_TYPE; 4] = [
    CKM_SHA256_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS,
    CKM_SHA3_512_RSA_PKCS,
];

/// Supported mechanisms for EC keys.
const ECDSA_MECHANISMS: [CK_MECHANISM_TYPE; 5] = [
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA512,
    CKM_ECDSA_SHA3_256,
    CKM_ECDSA_SHA3_512,
];

/// The set of sessions that have been created by the application
static SESSIONS: LazyLock<Arc<Mutex<HashMap<u64, Session>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

/// The set of available tokens.
///
/// Each key in the Siguldry server is mapped to a token. This list
/// is not updated after being initialized so there's a stable set of
/// slots.
static TOKENS: LazyLock<Arc<Vec<protocol::Key>>> = LazyLock::new(|| {
    let server_keys = CLIENT
        .lock()
        .as_mut()
        .expect("Client lock poisoned")
        .list_keys()
        .expect("Failed to list server keys");

    let tokens_available = server_keys.len();
    tracing::info!(
        tokens_available,
        "Successfully read available keys from Siguldry"
    );

    Arc::new(server_keys)
});

static LOGGING: LazyLock<()> = LazyLock::new(|| {
    let log_filter = EnvFilter::builder()
        .with_env_var("LIBSIGULDRY_PKCS11_LOG")
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()
        .expect("Set a valid log filter");
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");
});

/// The client used to communicate with the siguldry client proxy
///
/// This is gross, but because the client uses OpenSSL and users of
/// this library _also_ it via OpenSSL, it can cause some unpleasantness.
static CLIENT: LazyLock<Arc<Mutex<ProxyClient>>> = LazyLock::new(|| {
    let path = std::env::var("SIGULDRY_PKCS11_PROXY_PATH")
        .unwrap_or_else(|_| DEFAULT_PROXY_SOCKET.to_string());
    let path = PathBuf::from(path);
    let proxy_client = ProxyClient::new(path).expect("proxy unix socket could not be found");

    Arc::new(Mutex::new(proxy_client))
});

// Implemented as decribed in Section 5.4.1 of the PKCS #11 specification, version 3.2.
#[instrument(ret)]
extern "C" fn C_Initialize(pInitArgs: *mut ::std::os::raw::c_void) -> CK_RV {
    if !pInitArgs.is_null() {
        let pInitArgs = pInitArgs as CK_C_INITIALIZE_ARGS_PTR;

        // Safety:
        // If non-null, the specification states it MUST point to a CK_C_INITIALIZE_ARGS structure.
        let pReserved = unsafe { (*pInitArgs).pReserved };
        if !pReserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        // Safety:
        // If non-null, the specification states it MUST point to a CK_C_INITIALIZE_ARGS structure.
        let mutex_functions_provided = unsafe {
            (*pInitArgs).LockMutex.is_some()
                || (*pInitArgs).UnlockMutex.is_some()
                || (*pInitArgs).CreateMutex.is_some()
                || (*pInitArgs).DestroyMutex.is_some()
        };

        // SAFETY:
        // If non-null, the specification states it MUST point to a CK_C_INITIALIZE_ARGS structure.
        let flags = unsafe { (*pInitArgs).flags };

        if let Some(flags) = CInitializeFlags::from_bits(flags) {
            if !flags.contains(CInitializeFlags::OS_LOCKING_OK) && mutex_functions_provided {
                // We don't implement using the provided mutex functions, so we inform
                // the caller that we can't lock.
                return CKR_CANT_LOCK;
            }
            if flags.contains(CInitializeFlags::LIBRARY_CANT_CREATE_OS_THREADS) {
                // We spawn processes and while it may be that things that pass this flag
                // are okay with that, for now assume we don't work in such cases.
                return CKR_NEED_TO_CREATE_THREADS;
            }
        } else {
            return CKR_ARGUMENTS_BAD;
        }
    }
    tracing::info!("Initialized siguldry-pkcs11 successfully");

    CKR_OK
}

// Implemented as decribed in Section 5.4.2 of the PKCS #11 specification, version 3.2.
#[instrument(ret)]
extern "C" fn C_Finalize(pReserved: *mut ::std::os::raw::c_void) -> CK_RV {
    if pReserved.is_null() {
        SESSIONS.lock().expect("session lock was poisoned").clear();
        CKR_OK
    } else {
        CKR_ARGUMENTS_BAD
    }
}

// Implemented as decribed in Section 5.4.3 of the PKCS #11 specification, version 3.2.
#[instrument(ret)]
extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    const INFO: CK_INFO = CK_INFO {
        cryptokiVersion: CK_VERSION {
            major: 2,
            minor: 40,
        },
        manufacturerID: MANUFACTURER_ID,
        flags: 0,
        libraryDescription: LIBRARY_DESCRIPTION,
        libraryVersion: LIBRARY_VERSION,
    };

    if pInfo.is_null() {
        CKR_ARGUMENTS_BAD
    } else {
        // Safety:
        // The pointer is a valid non-null pointer to a CK_INFO structure.
        unsafe { *pInfo = INFO };
        CKR_OK
    }
}

#[instrument(ret)]
extern "C" fn C_GetInfo_3_0(pInfo: CK_INFO_PTR) -> CK_RV {
    const INFO: CK_INFO = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 3, minor: 0 },
        manufacturerID: MANUFACTURER_ID,
        flags: 0,
        libraryDescription: LIBRARY_DESCRIPTION,
        libraryVersion: LIBRARY_VERSION,
    };

    if pInfo.is_null() {
        CKR_ARGUMENTS_BAD
    } else {
        // Safety:
        // The pointer is a valid non-null pointer to a CK_INFO structure.
        unsafe { *pInfo = INFO };
        CKR_OK
    }
}

#[instrument(ret)]
extern "C" fn C_GetInfo_3_2(pInfo: CK_INFO_PTR) -> CK_RV {
    const INFO: CK_INFO = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 3, minor: 2 },
        manufacturerID: MANUFACTURER_ID,
        flags: 0,
        libraryDescription: LIBRARY_DESCRIPTION,
        libraryVersion: LIBRARY_VERSION,
    };

    if pInfo.is_null() {
        CKR_ARGUMENTS_BAD
    } else {
        // Safety:
        // The pointer is a valid non-null pointer to a CK_INFO structure.
        unsafe { *pInfo = INFO };
        CKR_OK
    }
}

// Implemented as decribed in Section 5.4.4 of the PKCS #11 specification, version 3.2.
#[instrument(ret)]
#[unsafe(no_mangle)]
pub extern "C" fn C_GetFunctionList(ppfunctionlist: *mut CK_FUNCTION_LIST_PTR) -> CK_RV {
    // Set up logging as early as possible.
    *LOGGING;
    if ppfunctionlist.is_null() {
        CKR_ARGUMENTS_BAD
    } else {
        unsafe {
            *ppfunctionlist = &FUNCTIONS as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
        }
        CKR_OK
    }
}

// Implemented as decribed in Section 5.4.5 of the PKCS #11 specification, version 3.2.
#[instrument(ret)]
#[unsafe(no_mangle)]
pub extern "C" fn C_GetInterfaceList(
    pInterfaceList: CK_INTERFACE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    // Set up logging as early as possible.
    *LOGGING;
    if pulCount.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    if pInterfaceList.is_null() {
        // Safety:
        // The pointer is non-NULL and per the specification must contain the the number of
        // elements the buffer must contain if pInterfaceList is NULL.
        unsafe { *pulCount = INTERFACES.len() as CK_ULONG };
        CKR_OK
    } else {
        let buffer_size = unsafe { *pulCount };
        // Safety:
        // The pointer is non-NULL and per the specification must contain the the number of
        // elements in the buffer or, if the buffer is too small, the size required.
        unsafe { *pulCount = INTERFACES.len() as CK_ULONG };
        if buffer_size >= INTERFACES.len() as CK_ULONG {
            for (index, interface) in INTERFACES.iter().enumerate() {
                let interface = **interface;
                unsafe { *pInterfaceList.add(index) = interface };
            }
            CKR_OK
        } else {
            CKR_BUFFER_TOO_SMALL
        }
    }
}

// Implemented as decribed in Section 5.4.6 of the PKCS #11 specification, version 3.2.
#[instrument(ret)]
#[unsafe(no_mangle)]
pub extern "C" fn C_GetInterface(
    pInterfaceName: CK_UTF8CHAR_PTR,
    pVersion: CK_VERSION_PTR,
    ppInterface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    // Set up logging as early as possible.
    *LOGGING;
    if ppInterface.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // There are no vendor-specific functions so the only name we allow is PKCS 11.
    if !pInterfaceName.is_null() {
        // Safety:
        // The pointer is non-NULL, and according to the specification must point to a
        // NULL-terminated string.
        let interface_name = unsafe { CStr::from_ptr(pInterfaceName as *const i8) };
        if interface_name != interfaces::FUNCTIONS_NAME {
            tracing::warn!("The only supported interface name is PKCS 11");
            return CKR_ARGUMENTS_BAD;
        }
    }
    if flags != 0 {
        tracing::warn!("Interface is not fork-safe, but caller indicated it must be.");
        return CKR_ARGUMENTS_BAD;
    }

    let interface = if pVersion.is_null() {
        &*INTERFACE_3_2
    } else {
        match unsafe { *pVersion } {
            CK_VERSION {
                major: 2,
                minor: 40,
            } => &INTERFACE_2_40,
            CK_VERSION { major: 3, minor: 0 } => &*INTERFACE_3_0,
            CK_VERSION { major: 3, minor: 2 } => &*INTERFACE_3_2,
            _ => {
                return CKR_ARGUMENTS_BAD;
            }
        }
    };

    unsafe { *ppInterface = interface as *const CK_INTERFACE as CK_INTERFACE_PTR };
    CKR_OK
}

/// C_GetSlotList is used to obtain a list of slots in the system.
///
/// tokenPresent indicates whether the list obtained includes only those slots
/// with a token present (CK_TRUE), or all slots (CK_FALSE); pulCount points
/// to the location that receives the number of slots.
///
/// For our implementation, each key is presented in its own token, so the number
/// of slots is equal to the number of keys in the server.
///
/// Refer to Section 5.5.1 of the PKCS #11 specification, version 3.2 for details.
#[instrument(ret)]
extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: *mut CK_SLOT_ID,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    if pulCount.is_null() {
        tracing::error!("Caller provided a NULL pointer for pulCount");
        return CKR_ARGUMENTS_BAD;
    }

    let number_of_slots = TOKENS.len() as u64;

    if pSlotList.is_null() {
        // Safety:
        // The pointer is non-null and must point to a valid location per the specification.
        tracing::debug!(number_of_slots, "Informing caller of the number of slots");
        unsafe { *pulCount = number_of_slots }
    } else {
        // Safety:
        // If pSlotList is not NULL_PTR, then *pulCount MUST contain the size (in terms of CK_SLOT_ID
        // elements) of the buffer pointed to by pSlotList
        let buffer_size = unsafe { *pulCount };
        unsafe { *pulCount = number_of_slots };
        if buffer_size < number_of_slots {
            tracing::debug!(
                buffer_size,
                number_of_slots,
                "Caller provided a buffer size that is too small"
            );
            return CKR_BUFFER_TOO_SMALL;
        }
        tracing::debug!(buffer_size, number_of_slots, "Returning slot IDs to caller");
        for slot in 0..number_of_slots {
            unsafe { *pSlotList.add(slot as usize) = slot };
        }
    }

    CKR_OK
}

#[instrument(ret)]
extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    if pInfo.is_null() {
        tracing::error!("Caller provided a NULL pointer for pInfo");
        return CKR_ARGUMENTS_BAD;
    }

    if let Some(token) = TOKENS.get(slotID as usize) {
        tracing::debug!(token.name, "Populating slot info for token");
        let mut slot_description = token.name.clone();
        if slot_description.len() > 64 {
            // Ensure we don't split on a character boundry; once MSRV is 1.91+ we can use floor_char_boundry()
            let mut index = 63;
            while !slot_description.is_char_boundary(index) {
                index -= 1;
            }
            let _ = slot_description.split_off(index);
        }
        while slot_description.len() < 64 {
            slot_description.push(' ');
        }

        unsafe {
            (*pInfo).flags = CKF_TOKEN_PRESENT;
            (*pInfo).firmwareVersion = CK_VERSION { major: 1, minor: 0 };
            (*pInfo).hardwareVersion = CK_VERSION { major: 1, minor: 0 };
            (*pInfo).manufacturerID = *b"Fedora Infrastructure           ";
            (*pInfo).slotDescription.copy_from_slice(
                slot_description
                    .as_bytes()
                    .get(..64)
                    .expect("Description MUST pad to 64 bytes"),
            );
        }
    } else {
        tracing::error!(
            slotID,
            slots_available = TOKENS.len(),
            "Caller provided invalid slot ID"
        );
        return CKR_SLOT_ID_INVALID;
    }

    CKR_OK
}

#[instrument(ret)]
extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    if let Some(token) = TOKENS.get(slotID as usize) {
        let mut label = token.name.clone();
        if label.len() > 32 {
            // Ensure we don't split on a character boundry; once MSRV is 1.91+ we can use floor_char_boundry()
            let mut index = 31;
            while !label.is_char_boundary(index) {
                index -= 1;
            }
            let _ = label.split_off(index);
        }
        while label.len() < 32 {
            label.push(' ');
        }
        unsafe {
            // Tokens are always initialized and have a PIN set up. Login unlocks the key in Siguldry.
            (*pInfo).flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
            (*pInfo).firmwareVersion = CK_VERSION { major: 1, minor: 0 };
            (*pInfo).hardwareVersion = CK_VERSION { major: 1, minor: 0 };
            (*pInfo).manufacturerID = *b"Fedora                          ";
            (*pInfo).label.copy_from_slice(
                label
                    .as_bytes()
                    .get(..32)
                    .expect("Label MUST pad to 32 bytes"),
            );
            (*pInfo).model = *b"Siguldry        ";
            (*pInfo).serialNumber = *b"0               ";
            (*pInfo).ulMaxPinLen = 128;
            (*pInfo).ulMinPinLen = 64;
        }
        CKR_OK
    } else {
        CKR_SLOT_ID_INVALID
    }
}

/// Login corresponds to unlocking the key in Siguldry.
///
/// Refer to Section 5.6.8 of the PKCS #11 specification, version 3.2 for details.
#[instrument(ret, skip(pPin, ulPinLen))]
extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: *mut CK_UTF8CHAR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };

    if session.logged_in {
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    // At this time we don't support security officer logins or operations.
    if userType != CKU_USER {
        return CKR_USER_TYPE_INVALID;
    }

    if !pPin.is_null() {
        let pin_len: usize = if let Ok(pin_len) = ulPinLen.try_into() {
            pin_len
        } else {
            return CKR_ARGUMENTS_BAD;
        };

        // Safety:
        // According to the specification, if pPin is non-null, it points to a properly initialized
        // buffer of length ulPinLen.
        let pin = unsafe { core::slice::from_raw_parts(pPin, pin_len) };
        let pin_string = if let Ok(pin_string) = String::from_utf8(pin.to_vec()) {
            pin_string
        } else {
            return CKR_ARGUMENTS_BAD;
        };
        let result = CLIENT
            .lock()
            .as_mut()
            .expect("Client lock poisoned")
            .unlock(session.key.name.clone(), pin_string);
        if result.is_err() {
            return CKR_PIN_INCORRECT;
        }
    } else {
        // Passing a null pointer for pPin indicates the protected authentication path is being used.
        // This is supported in Siguldry by configuring the client proxy to unlock the necessary keys.
        // For now, we'll just assume the user set this up correctly.
        //
        // TODO: Add an is-unlocked command to Siguldry to ensure that's the case.
        tracing::info!(
            key = session.key.name,
            "Protected authentication path specified; configure the siguldry client to unlock key"
        );
    }

    // The specification states "each of the applications sessions will enter the state" so we
    // need to walk the session list
    let slot_id = session.slot_id;
    sessions
        .iter_mut()
        .filter(|(_id, session)| session.slot_id == slot_id)
        .for_each(|(_id, session)| session.logged_in = true);
    CKR_OK
}

#[instrument(ret)]
extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };

    if !session.logged_in {
        return CKR_USER_NOT_LOGGED_IN;
    }

    // TODO: Siguldry doesn't currently support locking a key again so this is kinda a no-op
    let slot_id = session.slot_id;
    sessions
        .iter_mut()
        .filter(|(_id, session)| session.slot_id == slot_id)
        .for_each(|(_id, session)| session.logged_in = false);

    CKR_OK
}

#[instrument(ret)]
extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: *mut CK_MECHANISM_TYPE,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    if pulCount.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let key = if let Some(key) = TOKENS.get(slotID as usize) {
        key
    } else {
        return CKR_SLOT_ID_INVALID;
    };

    let supported_mechanisms = match key.key_algorithm {
        protocol::KeyAlgorithm::Rsa2K | protocol::KeyAlgorithm::Rsa4K => {
            RSA_PKCS_MECHANISMS.as_slice()
        }
        protocol::KeyAlgorithm::P256 => ECDSA_MECHANISMS.as_slice(),
        _ => {
            tracing::error!("Server key type is unsupported by this module");
            return CKR_ARGUMENTS_BAD;
        }
    };

    if !pMechanismList.is_null() {
        let count = unsafe { *pulCount };
        unsafe { *pulCount = supported_mechanisms.len() as CK_ULONG };
        if count >= supported_mechanisms.len() as u64 {
            for (index, mechanism) in supported_mechanisms.iter().enumerate() {
                // Safety:
                // The pointer is non-null and the buffer is large enough to contain the
                // list of supported mechanisms.
                unsafe { *pMechanismList.add(index) = *mechanism };
            }
        } else {
            return CKR_BUFFER_TOO_SMALL;
        }
    } else {
        // Safety:
        // The pointer is non-Null. The specification, per Section 5.2,
        // indicates value pointed to by pulCount must be set to the needed buffer size
        // by the function.
        unsafe { *pulCount = supported_mechanisms.len() as CK_ULONG };
    }

    CKR_OK
}

#[instrument(ret)]
extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let key = if let Some(key) = TOKENS.get(slotID as usize) {
        key
    } else {
        return CKR_SLOT_ID_INVALID;
    };
    let (min, max) = match key.key_algorithm {
        protocol::KeyAlgorithm::Rsa2K | protocol::KeyAlgorithm::Rsa4K => {
            if !RSA_PKCS_MECHANISMS.contains(&type_) {
                return CKR_MECHANISM_INVALID;
            }
            (2048, 4096)
        }
        protocol::KeyAlgorithm::P256 => {
            if !ECDSA_MECHANISMS.contains(&type_) {
                return CKR_MECHANISM_INVALID;
            }
            (256, 256)
        }
        _ => {
            tracing::error!("Server key type is unsupported by this module");
            return CKR_ARGUMENTS_BAD;
        }
    };

    unsafe {
        (*pInfo).ulMinKeySize = min;
        (*pInfo).ulMaxKeySize = max;
        (*pInfo).flags = CKF_SIGN;
    }

    CKR_OK
}

#[instrument(ret)]
extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    if session.found_objects.is_some() {
        return CKR_OPERATION_ACTIVE;
    }

    // Passing 0 is "match everything"
    if ulCount == 0 {
        session.found_objects = Some(session.objects.keys().copied().collect());
        return CKR_OK;
    }

    if pTemplate.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut attributes = Vec::with_capacity(ulCount as usize);
    for index in 0..ulCount {
        let template = unsafe { pTemplate.add(index as usize) };
        attributes.push(Attribute::from(template));
    }
    tracing::info!(attributes=?attributes, "Initialized search for objects with attributes");

    // Simplify state tracking by eagerly performing the search; this might not be the most efficient
    // approach but we won't be hurting for memory or anything.
    let mut found_objects = vec![];
    for (handle, object) in session.objects.iter() {
        if object.matches(&attributes) {
            found_objects.push(*handle);
        }
    }
    tracing::info!(count=found_objects.len(), objects=?found_objects, "found objects");
    session.found_objects = Some(found_objects);
    CKR_OK
}

#[instrument(ret)]
extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: *mut CK_OBJECT_HANDLE,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: *mut CK_ULONG,
) -> CK_RV {
    if pulObjectCount.is_null() || phObject.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };

    let found_objects = if let Some(found_objects) = &mut session.found_objects {
        found_objects
    } else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };

    unsafe { *pulObjectCount = 0 };
    let mut objects_found = 0;
    for _ in 0..ulMaxObjectCount {
        if let Some(object_id) = found_objects.pop() {
            unsafe { *(phObject.add(objects_found as usize)) = object_id as CK_OBJECT_HANDLE };
            objects_found += 1;
        } else {
            break;
        }
    }
    unsafe { *pulObjectCount = objects_found };
    tracing::info!(objects_found, "provided caller with objects");

    CKR_OK
}

/// Implemented as described in section 5.7.9 of PKCS #11 version 3.2.
#[instrument(ret)]
extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    if session.found_objects.is_none() {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    session.found_objects = None;
    CKR_OK
}

#[instrument(ret)]
extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut sessions = SESSIONS.lock().expect("session lock was poisoned");
    let session = if let Some(session) = sessions.get_mut(&hSession) {
        session
    } else {
        return CKR_SESSION_HANDLE_INVALID;
    };

    if let Some(object) = session.objects.get(&hObject) {
        let mut return_values = vec![];
        for index in 0..ulCount {
            let template = unsafe { pTemplate.add(index as usize) };
            return_values.push(object.set_attribute(template));
        }
        // Let the caller know about the most problematic issues first.
        if return_values.contains(&CKR_ATTRIBUTE_TYPE_INVALID) {
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
        if return_values.contains(&CKR_ATTRIBUTE_SENSITIVE) {
            return CKR_ATTRIBUTE_SENSITIVE;
        }
        // This would likely be CKR_BUFFER_TOO_SMALL
        if let Some(bad_rv) = return_values.into_iter().find(|rv| *rv != CKR_OK) {
            return bad_rv;
        }
    } else {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    CKR_OK
}
