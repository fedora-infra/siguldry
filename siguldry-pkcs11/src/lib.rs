// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A PKCS#11 module that implemented the bare minimum to support signing using keys in
//! a Siguldry server.
//!
//! This module requires that users have set up a siguldry-client proxy.
//!
//! Sequoia cryptoki support is provided by this module by presenting Siguldry PGP keys
//! in the format expected by the Sequoia key store. Keys with an Id attribute that starts
//! with "pgp" are PGP keys.

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
    CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_512, CKM_ECDSA_SHA256, CKM_ECDSA_SHA512, CKM_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS, CKM_SHA3_512_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA512_RSA_PKCS,
    CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL,
    CKR_CANT_LOCK, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_FUNCTION_FAILED, CKR_MECHANISM_INVALID, CKR_NEED_TO_CREATE_THREADS,
    CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED,
    CKR_PIN_INCORRECT, CKR_SESSION_HANDLE_INVALID, CKR_SLOT_ID_INVALID, CKR_USER_ALREADY_LOGGED_IN,
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

const DEFAULT_PROXY_SOCKET: &str = "/run/siguldry-client-proxy/siguldry-client-proxy.socket";

// The spec indicates this should be blank character padded and _not_ null-terminated
const MANUFACTURER_ID: [u8; 32] = *b"Fedora Infrastructure           ";
// The spec indicates this should be blank character padded and _not_ null-terminated
const LIBRARY_DESCRIPTION: [u8; 32] = *b"Siguldry PKCS#11 Library        ";
const LIBRARY_VERSION: CK_VERSION = CK_VERSION { major: 1, minor: 0 };

/// Supported mechanisms for signing with RSA keys
const RSA_PKCS_MECHANISMS: [CK_MECHANISM_TYPE; 5] = [
    CKM_RSA_PKCS,
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
static CLIENT: LazyLock<Arc<Mutex<Option<ProxyClient>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

/// The set of available tokens.
///
/// Each key in the Siguldry server is mapped to a token. This list
/// is not updated after being initialized so there's a stable set of
/// slots.
static TOKENS: LazyLock<Arc<Mutex<Option<Vec<protocol::Key>>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

/// The set of sessions that have been created by the application
static SESSIONS: LazyLock<Arc<Mutex<HashMap<u64, Session>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

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

    let path = std::env::var("LIBSIGULDRY_PKCS11_PROXY_PATH")
        .map_or_else(|_| PathBuf::from(DEFAULT_PROXY_SOCKET), PathBuf::from);
    tracing::debug!(socket_path=?path, "Attempting to connect to the siguldry client proxy");
    let mut proxy_client = match ProxyClient::new(path.clone()) {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(?error, socket=?path, "Failed to connect to the siguldry client proxy");
            return CKR_FUNCTION_FAILED;
        }
    };

    let keys = match proxy_client.list_keys() {
        Ok(keys) => {
            tracing::info!(
                tokens_available = keys.len(),
                "Successfully read available keys from Siguldry"
            );
            keys
        }
        Err(error) => {
            tracing::error!(
                ?error,
                "Failed to retrieve a list of keys from the server via the proxy"
            );
            return CKR_FUNCTION_FAILED;
        }
    };

    let mut client = CLIENT.lock().expect("client lock is poisoned");
    if client.is_some() {
        tracing::error!("The module was already initialized");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    } else {
        *client = Some(proxy_client);
    }
    let mut tokens = TOKENS.lock().expect("tokens lock is poisoned");
    if tokens.is_some() {
        tracing::error!("The module tokens were already initialized but the client was not!");
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    } else {
        *tokens = Some(keys);
    }

    tracing::info!("Initialized siguldry-pkcs11 successfully");
    CKR_OK
}

// Implemented as decribed in Section 5.4.2 of the PKCS #11 specification, version 3.2.
#[instrument(ret)]
extern "C" fn C_Finalize(pReserved: *mut ::std::os::raw::c_void) -> CK_RV {
    if pReserved.is_null() {
        SESSIONS.lock().expect("session lock was poisoned").clear();
        CLIENT.lock().expect("client lock is poisoned").take();
        TOKENS.lock().expect("tokens lock is poisoned").take();
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

/// Implemented as decribed in Section 5.4.4 of the PKCS #11 specification, version 3.2.
///
/// # Safety
///
/// The caller must ensure the following:
/// - ppFunctionList must be a non-NULL pointer that points to a value which will receive a pointer
///   to a CK_FUNCTION_LIST object.
#[instrument(ret)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut CK_FUNCTION_LIST_PTR) -> CK_RV {
    // Set up logging as early as possible.
    *LOGGING;
    if ppFunctionList.is_null() {
        CKR_ARGUMENTS_BAD
    } else {
        // Safety:
        // The pointer is a valid non-null pointer to a CK_FUNCTION_LIST structure,
        // per the specification.
        unsafe {
            *ppFunctionList = &FUNCTIONS as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
        }
        CKR_OK
    }
}

/// Implemented as decribed in Section 5.4.5 of the PKCS #11 specification, version 3.2.
///
/// # Safety
///
/// The caller must ensure the following:
///
/// - pInterfaceList is a NULL pointer, or it points to a list of CK_INTERFACE of length pulCount.
/// - pulCount is set to the length of pInterfaceList if pInterfaceList is non-NULL.
#[instrument(ret)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterfaceList(
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
        // Safety:
        // In the event that pInterfaceList is non-NULL, pulCount must contain the number
        // of CK_INTERFACE objects the buffer has room for.
        let buffer_size = unsafe { *pulCount };
        // Safety:
        // The pointer is non-NULL and per the specification must contain the the number of
        // elements in the buffer or, if the buffer is too small, the size required.
        unsafe { *pulCount = INTERFACES.len() as CK_ULONG };
        if buffer_size >= INTERFACES.len() as CK_ULONG {
            for (index, interface) in INTERFACES.iter().enumerate() {
                let interface = **interface;
                // Safety:
                // The specification requires that if the pointer is non-NULL, it must have allocated
                // space for least pulCount entries.
                unsafe { *pInterfaceList.add(index) = interface };
            }
            CKR_OK
        } else {
            CKR_BUFFER_TOO_SMALL
        }
    }
}

/// Implemented as decribed in Section 5.4.6 of the PKCS #11 specification, version 3.2.
///
/// # Safety
///
/// The caller must ensure the following:
///
/// - pInterfaceName must be a null pointer, or it must point to a UTF-8 encoded, NULL-terminated
///   string.
/// - pVersion must be a null pointer, or it must point to a [`CK_VERSION`] structure.
/// - ppInterface must point to a valid location to receive the pointer to a CK_INTERFACE structure.
#[instrument(ret)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterface(
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
        // Safety:
        // If non-NULL, pVersion must point to a CK_VERSION structure according to the specification.
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

    // Safety:
    // The pointer is not NULL and the specification states it must point to a location that receives
    // the interface pointer.
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

    let number_of_slots: CK_ULONG = if let Some(slots) = TOKENS
        .lock()
        .expect("tokens lock is poisoned")
        .as_ref()
        .map(|t| t.len())
        .and_then(|t| t.try_into().ok())
    {
        slots
    } else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };

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

        // Safety:
        // pulCount must always be a valid pointer to a CK_ULONG and must be set to the
        // number of slots when the function returns CKR_BUFFER_TOO_SMALL or CKR_OK.
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

    let token = match TOKENS
        .lock()
        .expect("tokens lock is poisoned")
        .as_ref()
        .map(|tokens| tokens.get(slotID as usize).cloned())
    {
        Some(Some(token)) => token,
        Some(None) => {
            tracing::error!(slotID, "Caller provided invalid slot ID");
            return CKR_SLOT_ID_INVALID;
        }
        None => {
            tracing::error!("Cryptoki not initialized");
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
    };

    tracing::debug!(token.name, "Populating slot info for token");
    let mut slot_description = token.name;
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

    // Safety:
    // pInfo is a non-NULL pointer and according to the specification must point to a CK_SLOT_INFO
    // struct.
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

    CKR_OK
}

#[instrument(ret)]
extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let token = match TOKENS
        .lock()
        .expect("tokens lock is poisoned")
        .as_ref()
        .map(|tokens| tokens.get(slotID as usize).cloned())
    {
        Some(Some(token)) => token,
        Some(None) => {
            tracing::error!(slotID, "Caller provided invalid slot ID");
            return CKR_SLOT_ID_INVALID;
        }
        None => {
            tracing::error!("Cryptoki not initialized");
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
    };

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

    // Safety:
    // pInfo is a non-NULL pointer and per the specification must point to a CK_TOKEN_INFO struct.
    unsafe {
        // Tokens are always initialized and have a PIN set up. Login unlocks the key in Siguldry.
        // The client proxy can optionally be configured to unlock one or more keys automatically,
        // which enables the protected authentication path. In that scenario, the application logs
        // in without a PIN and, if the token is unlocked via the proxy, can proceed.
        //
        // Once we have the ability to see if a key is unlocked via the proxy, add
        // CKF_PROTECTED_AUTHENTICATION_PATH to this list to support the protected authentication
        // path. A change will also be needed in C_Login.
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
        match CLIENT
            .lock()
            .expect("client lock poisoned")
            .as_mut()
            .map(|client| client.unlock(session.key.name.clone(), pin_string))
        {
            Some(Ok(_)) => tracing::debug!(key = session.key.name, "Unlocked key"),
            Some(Err(_)) => return CKR_PIN_INCORRECT,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
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
    let key = match TOKENS
        .lock()
        .expect("tokens lock is poisoned")
        .as_ref()
        .map(|tokens| tokens.get(slotID as usize).cloned())
    {
        Some(Some(token)) => token,
        Some(None) => {
            tracing::error!(slotID, "Caller provided invalid slot ID");
            return CKR_SLOT_ID_INVALID;
        }
        None => {
            tracing::error!("Cryptoki not initialized");
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
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
    let key = match TOKENS
        .lock()
        .expect("tokens lock is poisoned")
        .as_ref()
        .map(|tokens| tokens.get(slotID as usize).cloned())
    {
        Some(Some(token)) => token,
        Some(None) => {
            tracing::error!(slotID, "Caller provided invalid slot ID");
            return CKR_SLOT_ID_INVALID;
        }
        None => {
            tracing::error!("Cryptoki not initialized");
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
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

/// Implemented as described in section 5.7.7 of the PKCS #11 specification, version 3.2.
///
/// # Safety
///
/// The caller must ensure either:
///  
/// pTemplate must be a non-NULL pointer to a list of CK_ATTRIBUTE objects of length ulCount
///
/// OR
///
/// ulCount is 0 in which case all objects are returned and the value of pTemplate can be anything.
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
        if let Ok(attribute) = Attribute::try_from(template) {
            attributes.push(attribute);
        } else {
            return CKR_ARGUMENTS_BAD;
        }
    }
    tracing::debug!(attributes=?attributes, "Initialized search for objects with attributes");

    // Simplify state tracking by eagerly performing the search; this might not be the most efficient
    // approach but we won't be hurting for memory or anything.
    let mut found_objects = vec![];
    for (handle, object) in session.objects.iter() {
        if object.matches(&attributes) {
            found_objects.push(*handle);
        }
    }
    tracing::debug!(count = found_objects.len(), "found objects");
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
    tracing::debug!(objects_found, "provided caller with objects");

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

// Implemented as described in section 5.7.5 of the PKCS #11 specification, version 3.2.
//
// Safety:
// - pTemplate is non-NULL and points to a list of valid CK_ATTRIBUTE objects of length ulCount.
// - The pValue field of the CK_ATTRIBUTE object must either be a NULL pointer, or be a buffer
//   of length of the pValueLen field of the object.
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
