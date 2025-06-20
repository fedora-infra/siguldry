// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A variety of errors that might occur when using the Sigul client.

/// Errors the [`crate::client::Client`] may return.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Returned in the event that the Sigul server responds with a non-zero status code.
    #[error("the sigul server replied with an error: {0}")]
    Sigul(#[from] Sigul),

    /// Returned in the event that a request could not be serialized, or
    /// if a Sigul response could not be deserialized.
    ///
    /// Repeating the operation that led to this error will not succeed.
    #[error("failed to serialize to or deserialize from sigul: {0}")]
    Serde(#[from] crate::serdes::Error),

    /// The HMAC on the Sigul server's header or payload was incorrect,
    /// and its responses may have been tampered with (or corrupted) by
    /// the Sigul bridge.
    ///
    /// It's possible retrying the request will result in success in the
    /// unlikely event that a bit flipped somewhere along the way, but is
    /// also likely to fail with this error again if something more
    /// nefarious is occurring.
    #[error("the Sigul server signature on its response was invalid")]
    InvalidSignature,

    /// Returned in the event that an error occurred while communicating with the Sigul bridge or
    /// Sigul server. This may be a result of a transient networking problem, or because of a more
    /// permanent issue such and invalid configuration, or event a client bug.
    ///
    /// Retrying the operation that led to this error should be safe, although whether subsequent
    /// attempts fail or succeed depend on the specific error.  Refer to [`ConnectionError`] for
    /// details on the possible errors and if retrying is advisable.
    #[error("connection error with Sigul bridge or server: {0}")]
    Connection(#[from] ConnectionError),

    /// A general I/O error occurred, unrelated to the underlying network connection. It is likely
    /// due to a file not existing, or being unreadable by this process.
    ///
    /// For example, TLS certificates and private keys are read from the filesystem.  Some client
    /// operations involve sending or receiving files, as well.
    #[error("an I/O error occurred: {0}")]
    Io(#[from] std::io::Error),

    /// Returned in the event that the OpenSSL configuration derived from
    /// [`crate::client::TlsConfig`] is invalid or otherwise disagreeable to OpenSSL.
    ///
    /// This error is not returned for an OpenSSL-related error during the connection, so retrying
    /// is not appropriate.
    #[error("openssl could not be configured: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),

    /// Generic error that indicates a fatal error, likely due to a bug in the client.
    ///
    /// Retrying the operation will not help, and this should be reported as bug.
    #[error(transparent)]
    Fatal(#[from] anyhow::Error),
}

/// Status codes returned by the Sigul Server.
#[derive(Debug, thiserror::Error)]
// Clippy: Sigul 1.2 is the final version using this error protocol and the enumeration will not be
// expanded.
#[allow(clippy::exhaustive_enums)]
pub enum Sigul {
    /// The protocol version is not known to the server.
    #[error("unknown protocol version")]
    UnknownVersion,

    /// The requested operation is unknown.
    #[error("unknown operation")]
    UnknownOp,

    /// Authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// The object (command-specific) already exists.
    #[error("the specified object already exists")]
    AlreadyExists,

    /// The specified user was not found.
    #[error("the specified user was not found")]
    UserNotFound,

    /// Returned when attempting to delete a user that has access to keys.
    #[error("the specified user can access one or more keys")]
    UserHasKeyAccess,

    /// Returned when the user specified can't access the referenced key.
    #[error("the specified user cannot access this key")]
    KeyUserNotFound,

    /// The specified key was not found.
    #[error("the specified key was not found")]
    KeyNotFound,

    /// The server returns this when an unexpected exception occurred.
    #[error("An unknown error occurred")]
    UnknownError,

    /// Returned when revoking a user's key access and they're the only user with access.
    #[error("this is the only user with access to this key")]
    OnlyOneKeyUser,

    /// Returned if the RPM file is corrupt.
    #[error("the RPM file is corrupt")]
    CorruptRpm,

    /// The RPM provided can't be authenticated.
    #[error("missing RPM file authentication by client")]
    UnauthenticatedRpm,

    /// Returned when importing keys or certificates and the provided file is invalid.
    #[error("invalid import file")]
    InvalidImport,

    /// Returned when importing keys and the passphrase cannot decrypt the file.
    #[error("import passphrase does not match")]
    ImportPassphraseError,

    /// Returned from the decrypt operation if decryption fails.
    #[error("decryption failed")]
    DecryptFailed,

    /// The specified key type is not valid for the operation.
    #[error("unsupported key type for operation")]
    UnsupportedKeyType,

    /// An error the server didn't define was returned.
    #[error("An unexpected error occurred: error code {0}")]
    Unexpected(u32),
}

impl From<u32> for Sigul {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::UnknownVersion,
            2 => Self::UnknownOp,
            3 => Self::AuthenticationFailed,
            4 => Self::AlreadyExists,
            5 => Self::UserNotFound,
            6 => Self::UserHasKeyAccess,
            7 => Self::KeyUserNotFound,
            8 => Self::KeyNotFound,
            9 => Self::UnknownError,
            10 => Self::OnlyOneKeyUser,
            11 => Self::CorruptRpm,
            12 => Self::UnauthenticatedRpm,
            13 => Self::InvalidImport,
            14 => Self::ImportPassphraseError,
            15 => Self::DecryptFailed,
            16 => Self::UnsupportedKeyType,
            other => Self::Unexpected(other),
        }
    }
}

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
    Io(#[from] std::io::Error),

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
    /// The primary case for this is if a chunk for the outer TLS session arrives
    /// while the inner TLS session is active.
    ///
    /// Retrying might succeed, but this is a bug and should be reported.
    #[error("a Sigul protocol violation occurred: {0}")]
    ProtocolViolation(String),
}
