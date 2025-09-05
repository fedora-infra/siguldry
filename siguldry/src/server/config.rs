// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{
    fs::DirBuilder, io::ErrorKind, num::NonZeroU16, os::unix::fs::DirBuilderExt, path::PathBuf,
};

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
    pub state_directory: PathBuf,

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

/// Bind decrypting key access passphrases (e.g. HSM PINs, key passphrases) to a server-side secret.
///
/// The server encrypts the secret needed to use a signing key with a user-provided password. It
/// then encrypts _that_ with one or more secrets accessible only to the server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Pkcs11Binding {
    /// The PEM-encoded public key to use to encrypt secrets.
    pub public_key: PathBuf,
    /// The PKCS#11 URI of the private key.
    ///
    /// This is optional, and if it is not set, the server will not attempt to decrypt secrets with
    /// this entry. It will, however, encrypt any key passphrases created with the public key. This
    /// is useful when there are multiple servers where each server has its own secret, and the
    /// database is migrated from one to the other.
    ///
    /// In production it's strongly recommended that the key is in a hardware token (Yubikey, TPM, etc).
    /// For testing and development, SoftHSMv2 can be used.
    pub private_key: Option<String>,
    /// The PIN to access the private key.
    ///
    /// This field is _not_ read from configuration. Instead, it must be input at service startup using
    /// the `siguldry-server` CLI.
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
    /// The directory where GPG keys are stored relative to `state_directory`.
    const GPG_DIRECTORY: &str = "gpg-keys";

    /// The directory keys used for signatures supported by OpenSSL.
    ///
    /// Within the directory, there is a directory for private keys ("private"), public keys ("public"),
    /// and X509 certificates ("certs"). They are all PEM-encoded and private keys are encrypted.
    const KEYPAIRS_DIRECTORY: &str = "keys";

    pub fn database(&self) -> PathBuf {
        self.state_directory.join("siguldry.sqlite")
    }

    fn maybe_create_private_dir(&self, path: &str) -> anyhow::Result<PathBuf> {
        let dir = self.state_directory.join(path);
        if !dir.is_dir() {
            if let Err(err) = DirBuilder::new().mode(0o700).create(&dir) {
                if err.kind() != ErrorKind::AlreadyExists {
                    return Err(err.into());
                }
            }
        }
        Ok(dir)
    }

    /// Get the absolute path to the directory for a given key handle.
    ///
    /// The directory contains a `private_key.pem` file, `public_key.pem` file, and zero or more
    /// X509 certificate files which are also PEM-encoded.
    pub fn keypair_dir(&self, handle: &str) -> anyhow::Result<PathBuf> {
        self.maybe_create_private_dir(&format!("{}/{handle}", Self::KEYPAIRS_DIRECTORY))
    }

    /// Get the absolute path to the GPG directory.
    pub fn gpg_keystore(&self) -> anyhow::Result<PathBuf> {
        self.maybe_create_private_dir(Self::GPG_DIRECTORY)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_directory: PathBuf::from("/var/lib/siguldry/"),
            bridge_hostname: "bridge.example.com".to_string(),
            bridge_port: 44333,
            connection_pool_size: 32,
            user_password_length: NonZeroU16::new(32).unwrap(),
            credentials: Credentials {
                private_key: PathBuf::from("sigul.server.private_key.pem"),
                certificate: PathBuf::from("sigul.server.certificate.pem"),
                ca_certificate: PathBuf::from("sigul.ca.certificate.pem"),
            },
            pkcs11_bindings: vec![Pkcs11Binding {
                public_key: PathBuf::from("/etc/siguldry/public_key.pem"),
                private_key: Some("pkcs11:serial=abc123;id=%01;type=private".to_string()),
                pin: None,
            }],
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
