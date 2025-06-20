// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Error types for the Siguldry server, bridge, and client.

use zerocopy::TryCastError;

pub use crate::protocol::{Error as ProtocolError, ServerError};

/// Errors that occur during the connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectionError {
    /// An I/O occurred.
    ///
    /// This is very likely due to temporary networking issues and the operation
    /// should be retried.
    ///
    /// Be aware, however, that it could be because the specified hostname or
    /// port is incorrect, in which case retrying will never succeed.
    #[error("an I/O error occurred: {0}")]
    Io(std::io::Error),

    /// An OpenSSL error occurred.
    ///
    /// This is possibly a bug in this client or the OpenSSL bindings, or because
    /// the system-provided OpenSSL library does not support an operation this client
    /// needs. Retrying is not recommended.
    #[error("one or more openssl errors occurred: {0}")]
    SslErrors(#[from] openssl::error::ErrorStack),

    /// The TLS connection to the Sigul bridge or the Sigul server failed.
    ///
    /// This could be due to a protocol level failure, like a handshake failure
    /// due to no common supported versions/ciphers/etc, or because the TLS
    /// certificate is incorrect, or due to a network-level failure.
    ///
    /// It may be worth retrying, although in the event of a handshake failure
    /// or TLS certificate issue, it will not succeed.
    #[error("an SSL error occurred: {0}")]
    Ssl(#[from] openssl::ssl::Error),

    /// A Sigul protocol violation occurred.
    ///
    /// This occurs if the handshake is malformed, the framing is invalid, etc.
    /// This is almost certainly a bug.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

impl From<std::io::Error> for ConnectionError {
    fn from(error: std::io::Error) -> Self {
        // I/O errors may occur due to a TLS error, like if the server rejects the client certificate
        // but then the client reads from the socket. Map those type of errors to our more specific
        // error variants.
        if let Some(ssl_error) = std::error::Error::source(&error)
            .and_then(|error| error.downcast_ref::<openssl::error::ErrorStack>())
        {
            ConnectionError::Ssl(ssl_error.to_owned().into())
        } else {
            ConnectionError::Io(error)
        }
    }
}

impl<S, D> From<TryCastError<S, D>> for ConnectionError
where
    D: zerocopy::TryFromBytes,
{
    fn from(value: TryCastError<S, D>) -> Self {
        ProtocolError::Framing(format!("{value:?}")).into()
    }
}

/// Errors the [`crate::client::Client`] may return.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Returned in the event that an error occurred while communicating with the Sigul bridge or
    /// Sigul server. This may be a result of a transient networking problem, or because of a more
    /// permanent issue such as invalid configuration, or event a client bug.
    ///
    /// Retrying the operation that led to this error is safe, although whether subsequent
    /// attempts fail or succeed depend on the specific error.  Refer to [`ConnectionError`] for
    /// details on the possible errors and if retrying is advisable.
    #[error("connection error with Sigul bridge or server: {0}")]
    Connection(#[from] ConnectionError),

    /// A general I/O error occurred, unrelated to the underlying network connection. It is likely
    /// due to a file not existing, or being unreadable by this process.
    ///
    /// For example, TLS certificates and private keys are read from the filesystem.  Some client
    /// operations may involve sending or receiving files, as well.
    #[error("an I/O error occurred: {0}")]
    Io(#[from] std::io::Error),

    /// Returned in the event that the OpenSSL configuration derived from
    /// [`crate::client::TlsConfig`] is invalid or otherwise disagreeable to OpenSSL.
    ///
    /// This error is not returned for an OpenSSL-related error during the connection, so retrying
    /// is not appropriate.
    #[error("openssl could not be configured: {0}")]
    Ssl(#[from] openssl::error::ErrorStack),

    /// Errors the server returned for a particular request.
    ///
    /// Retrying may be appropriate for some server errors, while others may never succeed.
    #[error("The server responded with an error: {0}")]
    Server(#[from] ServerError),

    #[error("Failed to serialize a request or response to JSON: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Generic error that indicates a fatal error, likely due to a bug in the client.
    ///
    /// Retrying the operation will not help, and this should be reported as bug.
    #[error(transparent)]
    Fatal(#[from] anyhow::Error),
}
