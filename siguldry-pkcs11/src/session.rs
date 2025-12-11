// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Session management functions and objects.

use std::collections::HashMap;

use siguldry::protocol;
use tracing::instrument;

use crate::objects::Object;
use crate::{SESSIONS, TOKENS};
use cryptoki_sys::{
    CK_FLAGS, CK_NOTIFY, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE_PTR,
    CK_SESSION_INFO_PTR, CK_SLOT_ID, CKF_ASYNC_SESSION, CKF_SERIAL_SESSION, CKR_ARGUMENTS_BAD,
    CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_OK, CKR_SESSION_ASYNC_NOT_SUPPORTED,
    CKR_SESSION_COUNT, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    CKR_SLOT_ID_INVALID, CKS_RO_PUBLIC_SESSION, CKS_RO_USER_FUNCTIONS,
};

#[derive(Debug)]
pub struct Session {
    pub slot_id: CK_SLOT_ID,
    pub objects: HashMap<CK_OBJECT_HANDLE, Object>,
    pub found_objects: Option<Vec<u64>>,
    /// The Siguldry key associated with this slot.
    pub key: protocol::Key,
    /// Whether the user has unlocked the key by calling C_Login
    /// Used to provide the correct session state since users check
    /// the session state to decide whether to login.
    pub logged_in: bool,
    // Some if there's been a call to SignInit
    pub signing_state: Option<SigningState>,
    pub signature: Option<Vec<u8>>,
}

impl Session {
    pub fn reset_signing_state(&mut self) {
        self.signature = None;
        self.signing_state = None;
    }
}

pub struct SigningState {
    /// This flag is set to true if the caller has used C_SignUpdate
    pub multipart: bool,
    pub mechanism: u64,
    pub hasher: Option<openssl::hash::Hasher>,
}

impl std::fmt::Debug for SigningState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningState")
            .field("multipart", &self.multipart)
            .field("mechanism", &self.mechanism)
            .finish()
    }
}

#[instrument(ret)]
pub(crate) extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: *mut ::std::os::raw::c_void,
    notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if phSession.is_null() {
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

    // For legacy reasons, the CKF_SERIAL_SESSION bit MUST always be set
    if flags & CKF_SERIAL_SESSION == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    // We should look into supporting async sessions, but currently don't.
    if flags & CKF_ASYNC_SESSION != 0 {
        return CKR_SESSION_ASYNC_NOT_SUPPORTED;
    }

    let objects = match Object::from_key(key.clone()) {
        Ok(objects) => objects,
        Err(error) => {
            tracing::error!(
                ?error,
                key = key.name,
                "Unable to create PKCS #11 objects from key"
            );
            return CKR_FUNCTION_FAILED;
        }
    };
    let mut sessions = SESSIONS.lock().expect("Session lock is poisoned");
    if let Some(session_handle) = sessions.keys().max().copied().unwrap_or(41).checked_add(1)
        && sessions
            .insert(
                session_handle,
                Session {
                    slot_id: slotID,
                    objects,
                    found_objects: None,
                    key: key.clone(),
                    // TODO: need to track if a token is unlocked to set this correctly.
                    logged_in: false,
                    signing_state: None,
                    signature: None,
                },
            )
            .is_none()
    {
        tracing::debug!(session_handle, "new session opened");
        // Safety:
        // The session handle is non-NULL and according to Section 5.6.1 of the specification version 3.2,
        // must point to the location that receives the new session handle.
        unsafe { *phSession = session_handle };
        CKR_OK
    } else {
        CKR_SESSION_COUNT
    }
}

#[instrument(ret)]
pub(crate) extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    let mut sessions = SESSIONS.lock().expect("Session lock is poisoned");
    if let Some(session) = sessions.remove(&hSession) {
        tracing::debug!(session_handle = hSession, session.slot_id, "closed session");
        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}

#[instrument(ret)]
pub(crate) extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
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
    tracing::info!(key.name, "Closing all sessions for token");

    let sessions_handle = SESSIONS.clone();
    let mut sessions = sessions_handle.lock().expect("Session lock is poisoned");
    let slot_sessions = sessions
        .iter()
        .filter(|(_, session)| session.slot_id == slotID)
        .map(|(handle, _)| *handle)
        .collect::<Vec<_>>();
    for session in slot_sessions {
        let _ = sessions.remove(&session);
    }
    CKR_OK
}

#[instrument(ret)]
pub(crate) extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: CK_SESSION_INFO_PTR,
) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    if let Some(session) = SESSIONS
        .as_ref()
        .lock()
        .expect("session lock is poisoned")
        .get(&hSession)
    {
        let state = if session.logged_in {
            CKS_RO_USER_FUNCTIONS
        } else {
            CKS_RO_PUBLIC_SESSION
        };
        unsafe {
            (*pInfo).slotID = session.slot_id;
            (*pInfo).state = state;
            (*pInfo).flags = CKF_SERIAL_SESSION;
            (*pInfo).ulDeviceError = 0;
        }

        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}
