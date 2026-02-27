// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{num::NonZeroU16, path::PathBuf};

use sequoia_openpgp::crypto::Password;
use serde::{Deserialize, Serialize};

use crate::config::Credentials;

/// Configuration for the siguldry server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The location where the server should store its state.
    ///
    /// This includes an SQLite database as well as encrypted private keys,
    /// certificates, and any other state required to operate. To back up
    /// the service, back up this directory.
    ///
    /// Defaults to "/var/lib/siguldry" if not set.
    #[serde(default = "default_state_directory")]
    pub state_directory: PathBuf,

    /// The path to the socket-activated signer socket.
    ///
    /// This socket should be managed by a systemd socket unit (siguldry-signer.socket)
    /// with Accept=yes. When a connection is made to this socket, systemd will spawn
    /// a new siguldry-signer instance.
    ///
    /// Defaults to "/run/siguldry-signer/signer.socket", which matches the default systemd
    /// socket unit shipped with Siguldry; ordinarily you should not need to set this.
    #[serde(default = "default_socket_path")]
    pub signer_socket_path: PathBuf,

    /// The hostname of the Sigul bridge; this is used to verify the bridge's
    /// TLS certificate.
    pub bridge_hostname: String,

    /// The port to connect to the Sigul bridge; the default port is 44333 for
    /// the server.
    pub bridge_port: u16,

    /// The number of ready connections to maintain with the bridge. This decreases the latency of
    /// responses when multiple client connections are established, at the expense of some idle
    /// connections. Be aware that the bridge has its own limits on the allowable number of idle
    /// server connections. If you use multiple servers with a single bridge, be sure that the
    /// bridge allows enough idle connections to cover each server's pool size. The default is 32.
    pub connection_pool_size: usize,

    /// The minimum length for user's access password, in *bytes*. For example, the multi-byte
    /// UTF-8 character "🪿" counts as 4 bytes.
    pub user_password_length: NonZeroU16,

    /// The credentials to use when connecting to the bridge and when accepting client connections
    /// tunneled through the bridge. Note that the certificate must have both `clientAuth` and
    /// `serverAuth` in its extended key usage extension.
    pub credentials: Credentials,

    /// Certificates created by Siguldry allow the user to specify the subject's common name.
    ///
    /// The rest of the certificate's subject is specified here.
    pub certificate_subject: X509SubjectName,

    /// The set of certificates to encrypt passwords with.
    ///
    /// At least one entry should include a PKCS#11 URI for a private key. Passwords are encrypted
    /// using each certificate, so providing more than one binding means *any* of the private keys
    /// associated with the certificates will allow you to access the password, assuming you have
    /// the user-set password for the key as well.
    ///
    /// If no bindings are configured, the key's password is protected using only the user-provided
    /// password.
    #[serde(default)]
    pub pkcs11_bindings: Vec<Pkcs11Binding>,
}

/// The values to use when creating x509 certificates in subject names.
///
/// The user provides the common name to use, all other values are defined here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509SubjectName {
    pub country: String,
    pub state_or_province: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
}

impl Default for X509SubjectName {
    fn default() -> Self {
        Self {
            country: "US".to_string(),
            state_or_province: "Massachusetts".to_string(),
            locality: "Cambridge".to_string(),
            organization: "The Uncoöperative Organization".to_string(),
            organizational_unit: "Department of the Unmanageable".to_string(),
        }
    }
}

/// Bind decrypting key access passphrases (e.g. HSM PINs, key passphrases) to a server-side secret.
///
/// The server encrypts the secret needed to use a signing key with a user-provided password. It
/// then encrypts _that_ with one or more secrets accessible only to the server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Pkcs11Binding {
    /// The PEM-encoded X509 certificate to use to encrypt secrets.
    pub certificate: PathBuf,
    /// The PKCS#11 URI of the private key.
    ///
    /// This is optional, and if it is not set, the server will not attempt to decrypt secrets with
    /// this entry. It will, however, encrypt any key passphrases created with the certificate. This
    /// is useful when there are multiple servers where each server has its own secret, and the
    /// database is migrated from one to the other.
    ///
    /// In production it's strongly recommended that the key is in a hardware token (Yubikey, TPM, etc).
    /// For testing and development, a software token like Kryoptic can be used.
    pub private_key: Option<String>,
    /// The PIN to access the private key.
    ///
    /// This field is _not_ read from configuration. Instead, it must be input at service startup using
    /// the `siguldry-server` CLI.
    #[doc(hidden)]
    #[serde(skip)]
    pub pin: Option<Password>,
}

impl Pkcs11Binding {
    /// Returns true if this binding has both a private key URI and an associated PIN.
    pub(crate) fn can_unbind(&self) -> bool {
        self.private_key.is_some() && self.pin.is_some()
    }
}

impl Config {
    pub fn database(&self) -> PathBuf {
        self.state_directory.join("siguldry.sqlite")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_directory: default_state_directory(),
            signer_socket_path: default_socket_path(),
            bridge_hostname: "bridge.example.com".to_string(),
            bridge_port: 44333,
            connection_pool_size: 32,
            user_password_length: NonZeroU16::new(32).unwrap(),
            credentials: Credentials {
                private_key: PathBuf::from("siguldry.server.private_key.pem"),
                certificate: PathBuf::from("siguldry.server.certificate.pem"),
                ca_certificate: PathBuf::from("siguldry.ca_certificate.pem"),
            },
            pkcs11_bindings: vec![],
            certificate_subject: Default::default(),
        }
    }
}

impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            toml::ser::to_string_pretty(&self).unwrap_or_default()
        )
    }
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/siguldry-signer/signer.socket")
}

fn default_state_directory() -> PathBuf {
    PathBuf::from("/var/lib/siguldry/")
}
