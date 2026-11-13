// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Contains types necessary for communicating with pesign.
//!
//! While we could generate these from pesign's headers with bindgen,
//! we don't expect new development to occur in the pesign-client, and
//! we only require a few structures and constants.
//!
//! Refer to pesign's [daemon.h][1] definitions for the C versions.
//!
//! [1]: https://github.com/rhboot/pesign/blob/116/src/daemon.h

// zerocopy 0.8.63's FromBytes derive triggers this with Rust 1.100
#![allow(clippy::empty_enums)]

use std::ffi::CStr;

use anyhow::anyhow;
use bytes::{BufMut, Bytes, BytesMut};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::config::Key;

// The version of the pesign daemon interface we support.
//
// The pesign-client will reject a version mis-match so if
// pesign adjusts the version we will stop working with it.
// However, as we'll likely add our own interface later this
// shouldn't be an issue. Probably.
const PESIGND_VERSION: u32 = 0x2a9edaf0;

// Known pesign commands; we only support [`CMD_SIGN_ATTACHED_WITH_FILE_TYPE`]
const CMD_KILL_DAEMON: u32 = 0;
const CMD_UNLOCK_TOKEN: u32 = 1;
const CMD_SIGN_ATTACHED: u32 = 2;
const CMD_SIGN_DETACHED: u32 = 3;
const CMD_RESPONSE: u32 = 4;
const CMD_IS_TOKEN_UNLOCKED: u32 = 5;
const CMD_GET_CMD_VERSION: u32 = 6;
const CMD_SIGN_ATTACHED_WITH_FILE_TYPE: u32 = 7;
const CMD_SIGN_DETACHED_WITH_FILE_TYPE: u32 = 8;

/// The size required for a Pesign request header.
///
/// You can attempt to create a [`Header`] from byte slices of this size
/// using its [`TryFrom`] implementation.
pub const PESIGN_HEADER_SIZE: usize = std::mem::size_of::<PesignHeader>();

/// The maximum request payload size.
///
/// This is arbitrary, but should be plenty for any request and aligns with the
/// setting in pesign's daemon.
const PESIGN_MAX_PAYLOAD: usize = 1024;

/// The full set of pesign client commands.
///
/// It is not required that the server support all commands, but at a minimum
/// it must support the [`Command::GetCmdVersion`] command as the client will
/// query for command support using that command.
#[derive(Debug, Copy, Clone)]
pub enum Command {
    Kill,
    UnlockToken,
    SignAttached,
    SignDetached,
    Response,
    IsTokenUnlocked,
    GetCmdVersion,
    SignAttachedWithFileType,
    SignDetachedWithFileType,
}

impl TryFrom<u32> for Command {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            CMD_KILL_DAEMON => Ok(Self::Kill),
            CMD_UNLOCK_TOKEN => Ok(Self::UnlockToken),
            CMD_SIGN_ATTACHED => Ok(Self::SignAttached),
            CMD_SIGN_DETACHED => Ok(Self::SignDetached),
            CMD_RESPONSE => Ok(Self::Response),
            CMD_IS_TOKEN_UNLOCKED => Ok(Self::IsTokenUnlocked),
            CMD_GET_CMD_VERSION => Ok(Self::GetCmdVersion),
            CMD_SIGN_ATTACHED_WITH_FILE_TYPE => Ok(Self::SignAttachedWithFileType),
            CMD_SIGN_DETACHED_WITH_FILE_TYPE => Ok(Self::SignDetachedWithFileType),
            _ => Err(anyhow!("Unknown Command '{}'", value)),
        }
    }
}

impl From<Command> for u32 {
    fn from(value: Command) -> Self {
        match value {
            Command::Kill => CMD_KILL_DAEMON,
            Command::UnlockToken => CMD_UNLOCK_TOKEN,
            Command::SignAttached => CMD_SIGN_ATTACHED,
            Command::SignDetached => CMD_SIGN_DETACHED,
            Command::Response => CMD_RESPONSE,
            Command::IsTokenUnlocked => CMD_IS_TOKEN_UNLOCKED,
            Command::GetCmdVersion => CMD_GET_CMD_VERSION,
            Command::SignAttachedWithFileType => CMD_SIGN_ATTACHED_WITH_FILE_TYPE,
            Command::SignDetachedWithFileType => CMD_SIGN_DETACHED_WITH_FILE_TYPE,
        }
    }
}

/// The pesign message header.
///
/// Each message sent from the client to the server and from the server to the client
/// begins with this header.
///
/// As we have no plans to support new versions of pesign-client, it hardly seems
/// worth setting up bindgen. This is the pesignd_msghdr structure in pesign's daemon.h.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct PesignHeader {
    version: u32,
    command: u32,
    size: u32,
}

impl PesignHeader {
    fn new(command: u32, size: u32) -> Self {
        Self {
            version: PESIGND_VERSION,
            command,
            size,
        }
    }
}

// The raw pesign response.
//
// This is the pesignd_cmd_response structure in pesign's daemon.h.
// At the moment we don't bother supporting error messages, which is a
// flexible array member of chars.
#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct PesignResponse {
    // The command result
    return_code: i32,
    // Maybe in the future we can bother supporting error messages
    error_message: [u8; 4],
}

impl PesignResponse {
    fn new(return_code: i32) -> Self {
        Self {
            return_code,
            error_message: [0; 4],
        }
    }
}

/// A pesign response.
///
/// This can be converted into a [`Bytes`] object to send to the client.
#[derive(Debug, Clone, Copy)]
pub enum Response {
    Success,
    Failure,
}

impl<T, E> From<&Result<T, E>> for Response {
    fn from(value: &Result<T, E>) -> Self {
        match value {
            Ok(_) => Self::Success,
            Err(_) => Self::Failure,
        }
    }
}

impl From<Response> for Bytes {
    fn from(value: Response) -> Self {
        let mut buf = bytes::BytesMut::new();
        buf.put_slice(
            PesignHeader::new(
                Command::Response.into(),
                std::mem::size_of::<PesignResponse>() as u32,
            )
            .as_bytes(),
        );
        let return_code = match value {
            Response::Success => 0,
            Response::Failure => -1,
        };
        buf.put_slice(PesignResponse::new(return_code).as_bytes());
        buf.freeze()
    }
}

/// Describes the pesign request/response.
///
/// When receiving a request from pesign-client, read [`PESIGN_HEADER_SIZE`] bytes and then
/// attempt to convert the byte slice to [`Header`] with its [`TryInto`] implementation. In
/// the event that the bytes represent an invalid header, an error is returned.
#[derive(Debug, Copy, Clone)]
pub struct Header {
    pub command: Command,
    pub payload_length: usize,
}

impl TryFrom<Header> for Bytes {
    type Error = anyhow::Error;

    fn try_from(value: Header) -> Result<Self, Self::Error> {
        let payload_length: u32 = value.payload_length.try_into()?;
        let mut buf = BytesMut::new();
        let header = PesignHeader::new(value.command.into(), payload_length);
        buf.put_slice(header.as_bytes());

        Ok(buf.freeze())
    }
}

impl TryFrom<&PesignHeader> for Header {
    type Error = anyhow::Error;

    fn try_from(value: &PesignHeader) -> Result<Self, Self::Error> {
        let payload_length: usize = value.size.try_into()?;
        if payload_length > PESIGN_MAX_PAYLOAD {
            return Err(anyhow!(
                "Payload size is too large (declared {}, maximum is {})",
                payload_length,
                PESIGN_MAX_PAYLOAD
            ));
        }

        Ok(Self {
            command: value.command.try_into()?,
            payload_length,
        })
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let header: Header = PesignHeader::ref_from_bytes(value)
            .map_err(|e| anyhow!("pesign header invalid: {:?}", e))?
            .try_into()?;

        Ok(header)
    }
}

/// Represents a client request to sign a file.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SignAttachedRequest {
    pub token_name: String,
    pub certificate_name: String,
}

impl SignAttachedRequest {
    pub fn key<'a>(&self, available_keys: &'a [Key]) -> Result<&'a Key, anyhow::Error> {
        available_keys
            .iter()
            .find(|key| {
                key.pesign_token_name == self.token_name
                    && key.pesign_certificate_name == self.certificate_name
            })
            .ok_or_else(|| {
                tracing::error!(
                    request=?self,
                    "Configuration does not have the requested key/cert pair"
                );
                anyhow!("Client requested a token and certificate name we don't know about!")
            })
    }
}

impl TryFrom<&[u8]> for SignAttachedRequest {
    type Error = anyhow::Error;

    /// Attempt to parse the request from the payload bytes.
    ///
    /// A valid request is composed of:
    ///
    /// 1. FILE_TYPE (u32) - The file type.
    /// 2. TOKEN_LEN (u32) - The length of the token name string.
    /// 3. TOKEN_NAME ([u8; TOKEN_LEN]) - A null-terminated string identifying the token
    ///    to use when signing.
    /// 4. CERT_LEN (u32) - The length of the certificate name string.
    /// 5. CERT_NAME ([u8; CERT_LEN]) - A null-terminated string identifying the certificate
    ///    to use when signing.
    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        if payload.len() < std::mem::size_of::<u32>() * 3 {
            return Err(anyhow!("Request payload is too small"));
        }

        // pesign also defines a type for kernel modules, but at the moment we don't do anything for those.
        let (file_type, remaining_payload) = payload.split_at(std::mem::size_of::<u32>());
        let file_type = file_type.try_into().map(u32::from_ne_bytes)?;
        if file_type != 0 {
            return Err(anyhow!("Unsupported file type; only PE type supported"));
        }

        let (token_length, remaining_payload) =
            remaining_payload.split_at(std::mem::size_of::<u32>());
        let token_length: usize = token_length
            .try_into()
            .map(u32::from_ne_bytes)?
            .try_into()?;
        if token_length > remaining_payload.len() {
            return Err(anyhow!(
                "Malformed request; token length longer than payload"
            ));
        }
        let (token_name, remaining_payload) = remaining_payload.split_at(token_length);
        let token = CStr::from_bytes_until_nul(token_name)?
            .to_str()?
            .to_string();

        let (cert_length, remaining_payload) =
            remaining_payload.split_at(std::mem::size_of::<u32>());
        let cert_length: usize = cert_length.try_into().map(u32::from_ne_bytes)?.try_into()?;
        if cert_length != remaining_payload.len() {
            return Err(anyhow!(
                "Malformed request; certificate name length doesn't match payload size"
            ));
        }
        let certificate = CStr::from_bytes_until_nul(remaining_payload)?
            .to_str()?
            .to_string();

        Ok(Self {
            token_name: token,
            certificate_name: certificate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Regardless of header correctness, it should never crash.
        #[test]
        fn header_never_panics(payload in prop::array::uniform12(u8::MIN..u8::MAX)) {
            let _ = Header::try_from(payload.as_slice());
        }

        #[test]
        fn header_valid_commands(mut payload in vec![0..8u32, 0..1024u32]) {
            payload.insert(0, PESIGND_VERSION);
            let payload = payload.into_iter().flat_map(|b| b.to_ne_bytes()).collect::<Vec<_>>();
            Header::try_from(payload.as_slice()).unwrap();
        }

        #[test]
        fn header_invalid_commands(mut payload in vec![8..u32::MAX, 0..1024u32]) {
            payload.insert(0, PESIGND_VERSION);
            let payload = payload.into_iter().flat_map(|b| b.to_ne_bytes()).collect::<Vec<_>>();
            if Header::try_from(payload.as_slice()).is_ok() {
                panic!("Header shouldn't contain a command over 8");
            }
        }

        #[test]
        fn header_payload_size(payload_size in 0..1024u32) {
            let payload = vec![PESIGND_VERSION, 8, payload_size];
            let payload = payload.into_iter().flat_map(|b| b.to_ne_bytes()).collect::<Vec<_>>();
            let result = Header::try_from(payload.as_slice());
            if payload_size > PESIGN_MAX_PAYLOAD as u32 {
                if result.is_ok() {
                    panic!("Payload was too large");
                }
            } else {
                result.unwrap();
            }
        }

        // Regardless of payload correctness, it should never crash.
        #[test]
        fn sign_attached_request_never_panics(payload in prop::collection::vec(u8::MIN..u8::MAX, 0..PESIGN_MAX_PAYLOAD)) {
            let _ = SignAttachedRequest::try_from(payload.as_slice());
        }

        // Generate some acceptable requests using random token and certificate names
        #[test]
        fn sign_attached_request(name in "\\PC+") {
            let mut payload = Vec::from(0_u32.to_ne_bytes());
            let name_bytes = name.as_bytes();
            for _ in 0..2 {
                payload.extend_from_slice((name_bytes.len() as u32 + 1).to_ne_bytes().as_slice());
                payload.extend_from_slice(name_bytes);
                payload.push(0);
            }

            SignAttachedRequest::try_from(payload.as_slice()).unwrap();
        }

    }
}
