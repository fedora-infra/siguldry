// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A long set of stub functions with acceptable signatures for unsupported functions.

#![allow(unused_variables)]
#![allow(non_snake_case)]
use tracing::instrument;

use cryptoki_sys::{
    CK_ASYNC_DATA, CK_ATTRIBUTE, CK_BYTE, CK_BYTE_PTR, CK_FLAGS, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SESSION_VALIDATION_FLAGS_TYPE, CK_SLOT_ID,
    CK_ULONG, CK_USER_TYPE, CK_UTF8CHAR, CKR_FUNCTION_NOT_PARALLEL, CKR_FUNCTION_NOT_SUPPORTED,
};

#[instrument(ret)]
pub(crate) extern "C" fn C_CancelFunction(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

#[instrument(ret)]
pub(crate) extern "C" fn C_CopyObject(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
    phNewObject: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_CreateObject(
    hSession: CK_SESSION_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
    phObject: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DecryptDigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DecryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastPart: CK_BYTE_PTR,
    pulLastPartLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DecryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DecryptVerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DeriveKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulAttributeCount: CK_ULONG,
    phKey: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DestroyObject(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_Digest(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DigestEncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DigestFinal(
    hSession: CK_SESSION_HANDLE,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DigestInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_EncryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_EncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_GenerateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
    phKey: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: *mut CK_ATTRIBUTE,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: *mut CK_ATTRIBUTE,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: *mut CK_OBJECT_HANDLE,
    phPrivateKey: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_GenerateRandom(
    hSession: CK_SESSION_HANDLE,
    RandomData: CK_BYTE_PTR,
    ulRandomLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_GetFunctionStatus(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_PARALLEL
}

#[instrument(ret)]
pub(crate) extern "C" fn C_GetObjectSize(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_GetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    pulOperationStateLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_InitPIN(
    hSession: CK_SESSION_HANDLE,
    pPin: *mut CK_UTF8CHAR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_InitToken(
    slotID: CK_SLOT_ID,
    pPin: *mut CK_UTF8CHAR,
    ulPinLen: CK_ULONG,
    pLabel: *mut CK_UTF8CHAR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SeedRandom(
    hSession: CK_SESSION_HANDLE,
    pSeed: CK_BYTE_PTR,
    ulSeedLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SetPIN(
    hSession: CK_SESSION_HANDLE,
    pOldPin: *mut CK_UTF8CHAR,
    ulOldLen: CK_ULONG,
    pNewPin: *mut CK_UTF8CHAR,
    ulNewLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SignEncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SignRecover(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SignRecoverInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_UnwrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: *mut CK_ATTRIBUTE,
    ulAttributeCount: CK_ULONG,
    phKey: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_Verify(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifyFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifyInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifyRecover(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifyRecoverInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_WaitForSlotEvent(
    flags: CK_FLAGS,
    pSlot: *mut CK_SLOT_ID,
    pReserved: *mut ::std::os::raw::c_void,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_WrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_LoginUser(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: *mut CK_UTF8CHAR,
    ulPinLen: CK_ULONG,
    pUsername: *mut CK_UTF8CHAR,
    ulUsernameLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SessionCancel(hSession: CK_SESSION_HANDLE, flags: CK_FLAGS) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_MessageEncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_EncryptMessage(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
    pPlaintext: CK_BYTE_PTR,
    ulPlaintextLen: CK_ULONG,
    pCiphertext: CK_BYTE_PTR,
    pulCiphertextLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_EncryptMessageBegin(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_EncryptMessageNext(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pPlaintextPart: CK_BYTE_PTR,
    ulPlaintextPartLen: CK_ULONG,
    pCiphertextPart: CK_BYTE_PTR,
    pulCiphertextPartLen: *mut CK_ULONG,
    flags: CK_FLAGS,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_MessageEncryptFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_MessageDecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DecryptMessage(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
    pCiphertext: CK_BYTE_PTR,
    ulCiphertextLen: CK_ULONG,
    pPlaintext: CK_BYTE_PTR,
    pulPlaintextLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DecryptMessageBegin(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DecryptMessageNext(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pCiphertextPart: *mut CK_BYTE,
    ulCiphertextPartLen: CK_ULONG,
    pPlaintextPart: *mut CK_BYTE,
    pulPlaintextPartLen: *mut CK_ULONG,
    flags: CK_FLAGS,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_MessageDecryptFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_MessageSignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SignMessage(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SignMessageBegin(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_SignMessageNext(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_MessageSignFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_MessageVerifyInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifyMessage(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifyMessageBegin(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifyMessageNext(
    hSession: CK_SESSION_HANDLE,
    pParameter: *mut ::std::os::raw::c_void,
    ulParameterLen: CK_ULONG,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
    pSignature: *mut CK_BYTE,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_MessageVerifyFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_EncapsulateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hPublicKey: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulAttributeCount: CK_ULONG,
    pCiphertext: *mut CK_BYTE,
    pulCiphertextLen: *mut CK_ULONG,
    phKey: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_DecapsulateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hPrivateKey: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulAttributeCount: CK_ULONG,
    pCiphertext: *mut CK_BYTE,
    ulCiphertextLen: CK_ULONG,
    phKey: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifySignatureInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
    pSignature: *mut CK_BYTE,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifySignature(
    hSession: CK_SESSION_HANDLE,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifySignatureUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: *mut CK_BYTE,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_VerifySignatureFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_GetSessionValidationFlags(
    hSession: CK_SESSION_HANDLE,
    ulSessionValidationFlagsType: CK_SESSION_VALIDATION_FLAGS_TYPE,
    pFlags: *mut CK_FLAGS,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_AsyncComplete(
    hSession: CK_SESSION_HANDLE,
    pOperationID: *mut CK_UTF8CHAR,
    pAsyncData: *mut CK_ASYNC_DATA,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_AsyncGetID(
    hSession: CK_SESSION_HANDLE,
    pOperationID: *mut CK_UTF8CHAR,
    pulOperationIDLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_AsyncJoin(
    hSession: CK_SESSION_HANDLE,
    pOperationID: *mut CK_UTF8CHAR,
    ulOperationIDLen: CK_ULONG,
    pAsyncContext: *mut CK_BYTE,
    ulAsyncContextLen: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_WrapKeyAuthenticated(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: *mut CK_BYTE,
    ulWrappedKeyLen: CK_ULONG,
    pTag: *mut CK_BYTE,
    pulTagLen: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

#[instrument(ret)]
pub(crate) extern "C" fn C_UnwrapKeyAuthenticated(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: *mut CK_BYTE,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: *mut CK_ATTRIBUTE,
    ulAttributeCount: CK_ULONG,
    pTag: *mut CK_BYTE,
    ulTagLen: CK_ULONG,
    phKey: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
