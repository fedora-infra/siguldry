// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! A Sigul client.

use std::io::Cursor;
use std::path::Path;
use std::{collections::HashMap, io::Read};

use anyhow::Context;
use bytes::{Buf, Bytes};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncWrite};
use tracing::{Instrument, instrument};

use crate::v1::connection::Connection;
use crate::v1::error::ClientError as Error;

/// String newtype with custom Display and Debug impls to avoid logging passphrases.
pub struct Password(String);

impl Password {
    /// Convert this password to bytes to send.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password").field(&"*****").finish()
    }
}

impl std::fmt::Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Password").field(&"*****").finish()
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl TryFrom<&Path> for Password {
    type Error = Error;

    /// Read a passphrase from the file.
    ///
    /// If the first line does not contain a string, an error is returned.
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        let passphrase = std::fs::read_to_string(value)?
            .lines()
            .next()
            .and_then(|pass| {
                let pass = pass.trim();
                if !pass.is_empty() { Some(pass) } else { None }
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Passphrase file {} does not contain a password on the first line",
                    value.display()
                )
            })?
            .to_string();

        Ok(Self(passphrase))
    }
}

/// The key types supported by Sigul.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KeyType {
    /// The GnuPG key type.
    ///
    /// Server configuration determines the key size and algorithm used when creating a new key.
    GnuPG {
        /// The real name field to use on the GPG key, if any.
        real_name: Option<String>,
        /// The comment field to use on the GPG key, if any.
        comment: Option<String>,
        /// The email address for the GPG key, if any.
        email: Option<String>,
        /// The expiration date for the GPG key. If [`Option::None`], the key does not expire.
        expire_date: Option<String>,
    },
    /// The Elliptic Curve Cryptography key type.
    ///
    /// Server configuration determines the curve used when creating a new key.
    Ecc,
    /// The RSA key type.
    ///
    /// Server configuration determines the key size used when creating a new key.
    Rsa,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::GnuPG { .. } => write!(f, "gnupg"),
            KeyType::Ecc => write!(f, "ECC"),
            KeyType::Rsa => write!(f, "RSA"),
        }
    }
}

/// The certificate types supported by Sigul
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum CertificateType {
    /// A Certificate Authority.
    ///
    /// Certificates used to sign other certificates.
    Ca,
    /// A certificate for code signing.
    ///
    /// For example, a certificate used when signing PE applications should be this type.
    CodeSigning,
    /// A certificate for a TLS server.
    ///
    /// In practice, this is not used by anything in Fedora (that I am aware of).
    SslServer,
}

impl std::fmt::Display for CertificateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateType::Ca => write!(f, "ca"),
            CertificateType::CodeSigning => write!(f, "codesigning"),
            CertificateType::SslServer => write!(f, "sslserver"),
        }
    }
}

/// Sigul commands supported by this client.
#[derive(Serialize, Debug, Clone)]
pub(crate) enum Command {
    ListUsers {
        /// The user to authenticate as.
        user: String,
    },
    UserInfo {
        /// The user to authenticate as.
        user: String,
        /// The user to retrieve info for.
        name: String,
    },
    NewUser {
        /// The user to authenticate as.
        user: String,
        /// The name of the new user.
        name: String,
        /// Whether the new user is an administrator.
        admin: bool,
    },
    DeleteUser {
        /// The user to authenticate as.
        user: String,
        /// The user to delete.
        name: String,
    },
    ModifyUser {
        /// The user to authenticate as.
        user: String,

        /// The user to modify.
        name: String,

        /// Whether or not the user should be an admin. Providing `None` means no change.
        #[serde(skip_serializing_if = "Option::is_none")]
        admin: Option<bool>,

        /// The new user name, if a change is desired. Providing `None` means no change.
        #[serde(skip_serializing_if = "Option::is_none")]
        new_name: Option<String>,
    },
    /// Show information about the user's key access.
    KeyUserInfo {
        /// The user to authenticate as.
        user: String,
        /// The user to list key information for.
        name: String,
        /// The key name to list information for.
        key: String,
    },
    ModifyKeyUser {
        /// The user to authenticate as.
        user: String,
        /// The user to update key access for.
        name: String,
        /// The key name to update key access for.
        key: String,
        /// Whether or not the user is the key admin.
        #[serde(skip_serializing_if = "Option::is_none")]
        key_admin: Option<bool>,
    },
    ListKeys {
        /// The user to authenticate as.
        user: String,
    },
    NewKey {
        /// The user to authenticate as.
        user: String,
        /// The key name.
        key: String,
        /// The key type.
        keytype: String,
        /// The key admin, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        initial_key_admin: Option<String>,
        /// The "Real name" of the key subject, if the key type is "gnupg".
        #[serde(skip_serializing_if = "Option::is_none")]
        name_real: Option<String>,
        /// A comment about the key, if the key type is "gnupg".
        #[serde(skip_serializing_if = "Option::is_none")]
        name_comment: Option<String>,
        /// The email associated with the key, if the key type is "gnupg".
        #[serde(skip_serializing_if = "Option::is_none")]
        name_email: Option<String>,
        /// The key expiration date in YYYY-MM-DD format, if the key type is "gnupg".
        #[serde(skip_serializing_if = "Option::is_none")]
        expire_date: Option<String>,
    },
    ImportKey {
        /// The user to authenticate as.
        user: String,
        /// What the imported key should be named.
        key: String,
        /// The key type. Must be one of [`KeyType`].
        keytype: String,
        /// The key's initial admin. If omitted, the user importing the key is set as the admin.
        #[serde(skip_serializing_if = "Option::is_none")]
        initial_key_admin: Option<String>,
    },
    DeleteKey {
        /// The user to authenticate as.
        user: String,
        /// The key name to delete.
        key: String,
    },
    ModifyKey {
        /// The user to authenticate as.
        user: String,
        /// The key name to modify.
        key: String,
        /// The new key name, if a change is desired. Providing `None` means no change.
        #[serde(skip_serializing_if = "Option::is_none")]
        new_name: Option<String>,
    },
    ListKeyUsers {
        /// The user to authenticate as.
        user: String,
        /// The key name to list users for.
        key: String,
    },
    GrantKeyAccess {
        /// The user to authenticate as.
        user: String,
        /// The key to grant `name` access to.
        key: String,
        /// The user to grant access to the key.
        name: String,
    },
    ChangeKeyExpiration {
        /// The user to authenticate as.
        user: String,
        /// The key to change the expiration date for; note this is only valid for GnuPG keys.
        key: String,
        /// The new expiration date in YYYY-MM-DD format.
        /// If `None`, the key's expiration date is set to "non-expiring".
        #[serde(skip_serializing_if = "Option::is_none")]
        expire_date: Option<String>,
        /// The subkey to change the expiration date for, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        subkey: Option<String>,
    },
    RevokeKeyAccess {
        /// The user to authenticate as.
        user: String,
        /// The key to revoke `name` access from.
        key: String,
        /// The user to revoke access from the key.
        name: String,
    },
    GetPublicKey {
        /// The user to authenticate as.
        user: String,
        /// The key name to retrieve the public key for.
        key: String,
    },
    ChangePassphrase {
        /// The user to authenticate as.
        user: String,
        /// The key name to change the passphrase for.
        key: String,
    },
    // The following commands are not yet implemented in the client:
    //
    // SignText {},
    // SignData {},
    // Decrypt {},
    // SignGitTag {},
    // SignContainer {},
    // SignOstree {},
    // SignRpm {},
    // SignRpms {},
    SignCertificate {
        /// The user to authenticate as.
        user: String,
        issuer_key: String,
        subject_key: String,
        /// A RFC 4514 compliant string
        subject: String,
        /// Validity for the signature in the format <int:n>y for n years
        validity: String,
        subject_certificate_name: String,
        /// The type of certificate to create
        certificate_type: String,
        /// The issuer's certificate name; `None` if self-signed (issuer_key == subject_key)
        #[serde(skip_serializing_if = "Option::is_none")]
        issuer_certificate_name: Option<String>,
    },
    SignPe {
        /// The user to authenticate as.
        user: String,
        key: String,
        cert_name: String,
    },
    ListBindingMethods {
        /// The user to authenticate as.
        user: String,
    },
}

/// Response types used by the client.
pub mod responses {
    /// A Sigul user.
    #[derive(Debug, Clone)]
    pub struct User {
        /// The username.
        pub(crate) name: String,
        /// True if the user is a sigul administrator
        pub(crate) admin: bool,
    }

    impl User {
        /// The user's name.
        pub fn name(&self) -> &str {
            &self.name
        }

        /// Returns true if the user is a Sigul administrator.
        pub fn admin(&self) -> bool {
            self.admin
        }
    }

    /// User's access information for a key.
    #[derive(Debug, Clone)]
    pub struct KeyUserInfo {
        /// The username this key info relates to.
        pub(crate) user: String,
        /// The key name this key info relates to.
        pub(crate) key: String,
        /// True if the user is the key administrator.
        pub(crate) admin: bool,
    }

    impl KeyUserInfo {
        /// The user's name.
        pub fn user(&self) -> &str {
            &self.user
        }

        /// The key's name
        pub fn key(&self) -> &str {
            &self.key
        }

        /// Returns true if the user is a Sigul administrator.
        pub fn admin(&self) -> bool {
            self.admin
        }
    }

    /// A public key as returned by the Sigul server.
    ///
    /// GnuPG keys are expected to be ASCII-armored, and RSA or ECC keys should be PEM-encoded.
    #[derive(Debug, Clone)]
    pub struct PublicKey {
        /// The key name this public key relates to.
        pub(crate) key_name: String,
        /// The public key data.
        pub(crate) data: Vec<u8>,
    }

    impl PublicKey {
        /// The key's name.
        pub fn key_name(&self) -> &str {
            &self.key_name
        }

        /// The public key data.
        pub fn data(&self) -> &[u8] {
            &self.data
        }

        /// Convert the public key data to a string.
        ///
        /// As the data is expected to be UTF-8 encoded PEM or ASCII-armored data, this will
        /// only return an error if the server is misbehaving.
        pub fn as_string(&self) -> Result<String, std::string::FromUtf8Error> {
            String::from_utf8(self.data.clone())
        }
    }
}

/// Connect to a sigul server.
#[derive(Debug, Clone)]
pub struct Client {
    /// The TLS configuration to use for connections to the bridge and server.
    tls_config: TlsConfig,
    /// The bridge's hostname used to connect to it as well as validate its TLS certificate.
    bridge_hostname: String,
    /// The port to use when connecting to the bridge.
    bridge_port: u16,
    /// The server's hostname, used to validate its TLS certificate.
    server_hostname: String,
    /// The username to authenticate as.
    user_name: String,
}

/// The TLS configuration used by the Sigul client.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    connector: SslConnector,
}

impl TlsConfig {
    /// Create a new TLS configuration for a Sigul client.
    pub fn new<P: AsRef<std::path::Path>>(
        certificate: P,
        private_key: P,
        private_key_passphrase: Option<P>,
        certificate_authority: P,
    ) -> Result<Self, Error> {
        let mut connector = SslConnector::builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        // The Python version makes this configurable, and fails if the min version is less than 1.2
        connector.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        connector.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        connector.set_ca_file(&certificate_authority)?;

        let mut private_key_buf = vec![];
        std::fs::File::open(private_key)?.read_to_end(&mut private_key_buf)?;
        let private_key = match &private_key_passphrase {
            Some(passphrase_path) => {
                let mut passphrase = vec![];
                std::fs::File::open(passphrase_path)?.read_to_end(&mut passphrase)?;
                openssl::pkey::PKey::private_key_from_pem_passphrase(&private_key_buf, &passphrase)?
            }
            None => openssl::pkey::PKey::private_key_from_pem(&private_key_buf)?,
        };
        connector.set_private_key(&private_key)?;
        connector.set_certificate_file(&certificate, SslFiletype::PEM)?;
        connector.check_private_key()?;

        Ok(Self {
            connector: connector.build(),
        })
    }

    /// Retrieve an SSL configuration acceptable to use when connecting to the provided hostname.
    pub fn ssl(&self, hostname: &str) -> Result<openssl::ssl::Ssl, Error> {
        let ssl = self.connector.configure()?.into_ssl(hostname)?;
        tracing::debug!(verify_mode=?ssl.ssl_context().verify_mode(), hostname=hostname, "Created SSL connection config");
        Ok(ssl)
    }
}

/// Utility for commands that don't expect large (or any) payload response.
fn get_payload_pipe() -> (
    tokio::task::JoinHandle<Result<Vec<u8>, std::io::Error>>,
    tokio::io::WriteHalf<tokio::io::SimplexStream>,
) {
    let (mut payload_reader, payload_writer) = tokio::io::simplex(4096);
    let payload = tokio::spawn(
        async move {
            let mut payload = vec![];
            payload_reader.read_to_end(&mut payload).await?;
            tracing::debug!(payload_length = payload.len(), "Response payload received",);
            Ok::<_, std::io::Error>(payload)
        }
        .in_current_span(),
    );

    (payload, payload_writer)
}

impl Client {
    /// Create a new Sigul client.
    ///
    /// This can fail if the OpenSSL library available doesn't support the required TLS configuration.
    pub fn new(
        tls_config: TlsConfig,
        bridge_hostname: String,
        bridge_port: u16,
        server_hostname: String,
        user_name: String,
    ) -> Self {
        Self {
            tls_config,
            bridge_hostname,
            bridge_port,
            server_hostname,
            user_name,
        }
    }

    /// Connect to the Sigul bridge.
    async fn connect(&self) -> Result<Connection, Error> {
        let ssl = self.tls_config.ssl(&self.bridge_hostname)?;
        Ok(Connection::connect((self.bridge_hostname.as_str(), self.bridge_port), ssl).await?)
    }

    /// List the users on the Sigul server
    ///
    /// The user you are authenticated as must be an administrator.
    #[instrument(skip_all)]
    pub async fn users(&self, admin_passphrase: Password) -> Result<Vec<String>, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ListUsers {
                    user: self.user_name.clone(),
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;

        let mut num_users = response
            .fields
            .get("num-users")
            .map(|b| Bytes::from(b.clone()))
            .ok_or(anyhow::anyhow!("missing expected field 'num-users'"))?;

        if num_users.len() != 4 {
            // The expected value of this field is a u32.
            return Err(anyhow::anyhow!(
                "the 'num-users' field was {} bytes; expected 4",
                num_users.len()
            )
            .into());
        }
        let num_users: usize = num_users
            .get_u32()
            .try_into()
            .context("the number of users couldn't be converted to usize")?;
        let users = payload
            .split(|byte| *byte == 0)
            .filter_map(|name| {
                if !name.is_empty() {
                    String::from_utf8(name.into()).ok()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if users.len() != num_users {
            return Err(anyhow::anyhow!(
                "Server response indicated {} users, but {} names were sent!",
                num_users,
                users.len()
            )
            .into());
        }

        Ok(users)
    }

    /// Get information about the given user
    #[instrument(skip_all)]
    pub async fn get_user(
        &self,
        admin_passphrase: Password,
        name: String,
    ) -> Result<responses::User, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::UserInfo {
                    user: self.user_name.clone(),
                    name: name.clone(),
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        let admin = response
            .fields
            .get("admin")
            .and_then(|b| b.first())
            .map(|b| *b == 1)
            .ok_or(anyhow::anyhow!("missing expected field 'admin'"))?;

        Ok(responses::User { name, admin })
    }

    /// Add a new user to the Sigul server.
    ///
    /// If the `admin` parameter is `true`, the new user is created as a server administrator.
    /// Optionally, the new user's password can be set. If it is not set when the user is created,
    /// it can be set using [`Client::modify_user`].
    #[instrument(skip_all)]
    pub async fn create_user(
        &self,
        admin_passphrase: Password,
        name: String,
        admin: bool,
        user_passphrase: Option<Password>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        user_passphrase
            .as_ref()
            .map(|p| inner_request.insert("new-password", p.as_bytes()));
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::NewUser {
                    user: self.user_name.clone(),
                    name,
                    admin,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Modify an existing user on the Sigul server.
    ///
    /// Users can have new names, their password changed, and be set as admins or not.
    /// Providing `None` for any optional parameters will leave that setting unchanged.
    #[instrument(skip_all)]
    pub async fn modify_user(
        &self,
        admin_passphrase: Password,
        name: String,
        new_name: Option<String>,
        admin: Option<bool>,
        user_passphrase: Option<Password>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        user_passphrase
            .as_ref()
            .map(|p| inner_request.insert("new-password", p.as_bytes()));
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ModifyUser {
                    user: self.user_name.clone(),
                    name,
                    new_name,
                    admin,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Remove a user from the Sigul server.
    ///
    /// Users can only be deleted if they do not have access to any keys, and this call will
    /// fail with [`crate::error::Sigul::UserHasKeyAccess`] if an attempt is made to delete a
    /// user with key access.
    #[instrument(skip_all)]
    pub async fn delete_user(&self, admin_passphrase: Password, name: String) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::DeleteUser {
                    user: self.user_name.clone(),
                    name,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Show information about a user's key access.
    ///
    /// If the user can access the key, the response will include whether or not the user is the key's admin.
    ///
    /// This call will return [`crate::error::Sigul::KeyUserNotFound`] if the
    /// given user cannot access the key.
    #[instrument(skip_all)]
    pub async fn key_user_info(
        &self,
        admin_passphrase: Password,
        name: String,
        key: String,
    ) -> Result<responses::KeyUserInfo, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::KeyUserInfo {
                    user: self.user_name.clone(),
                    name: name.clone(),
                    key: key.clone(),
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        let admin = response
            .fields
            .get("key-admin")
            .and_then(|b| b.first())
            .map(|b| *b == 1)
            .ok_or(anyhow::anyhow!("missing expected field 'admin'"))?;

        Ok(responses::KeyUserInfo {
            user: name,
            key,
            admin,
        })
    }

    /// Modify a key's user by making the user an admin or removing them as an admin.
    #[instrument(skip_all)]
    pub async fn modify_key_user(
        &self,
        admin_passphrase: Password,
        name: String,
        key: String,
        key_admin: Option<bool>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ModifyKeyUser {
                    user: self.user_name.clone(),
                    name: name.clone(),
                    key: key.clone(),
                    key_admin,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// List the keys available in the Sigul server.
    #[instrument(skip_all)]
    pub async fn keys(&self, admin_passphrase: Password) -> Result<Vec<String>, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ListKeys {
                    user: self.user_name.clone(),
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;

        let mut num_keys = response
            .fields
            .get("num-keys")
            .map(|b| Bytes::from(b.clone()))
            .ok_or(anyhow::anyhow!("missing expected field 'num-keys'"))?;

        if num_keys.len() != 4 {
            // The expected value of this field is a u32.
            return Err(anyhow::anyhow!(
                "the 'num-keys' field was {} bytes; expected 4",
                num_keys.len()
            )
            .into());
        }
        let num_keys: usize = num_keys
            .get_u32()
            .try_into()
            .context("the number of keys couldn't be converted to usize")?;
        let keys = payload
            .split(|byte| *byte == 0)
            .filter_map(|name| {
                if !name.is_empty() {
                    String::from_utf8(name.into()).ok()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if keys.len() != num_keys {
            return Err(anyhow::anyhow!(
                "Server response indicated {} users, but {} names were sent!",
                num_keys,
                keys.len()
            )
            .into());
        }

        Ok(keys)
    }

    /// Create a new key on the Sigul server.
    ///
    /// If the `initial_key_admin` parameter is not provided, the current user is set as the key's admin.
    ///
    /// The `name_real`, `name_comment`, and `name_email` parameters are only used if the key type is [`KeyType::GnuPG`].
    #[instrument(skip_all)]
    pub async fn new_key(
        &self,
        admin_passphrase: Password,
        key_passphrase: Password,
        key_name: String,
        key_type: KeyType,
        initial_key_admin: Option<String>,
    ) -> Result<responses::PublicKey, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        inner_request.insert("passphrase", key_passphrase.as_bytes());
        let keytype = key_type.to_string();
        let (name_real, name_comment, name_email, expire_date) = match key_type {
            KeyType::GnuPG {
                real_name,
                comment,
                email,
                expire_date,
            } => (real_name, comment, email, expire_date),
            KeyType::Ecc | KeyType::Rsa => (None, None, None, None),
        };
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::NewKey {
                    user: self.user_name.clone(),
                    key: key_name.clone(),
                    keytype,
                    initial_key_admin,
                    name_real,
                    name_comment,
                    name_email,
                    expire_date,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;

        Ok(responses::PublicKey {
            key_name,
            data: payload,
        })
    }

    /// Import a key into the Sigul server.
    ///
    /// `key_passphrase` is the passphrase that can be used to decrypt the key file, and
    /// `new_key_passphrase` is the passphrase that will unlock the key after it has been imported.
    /// `key_pem` is the key file in PEM format and must be encrypted with `key_passphrase`, and
    /// `key_type` is the type of key being imported.
    ///
    /// If `initial_key_admin` is not provided, the user importing the key is set as the key's admin.
    #[instrument(skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub async fn import_key(
        &self,
        admin_passphrase: Password,
        key_passphrase: Password,
        new_key_passphrase: Password,
        key_name: String,
        key_pem: &[u8],
        key_type: KeyType,
        initial_key_admin: Option<String>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();
        let request_payload = Cursor::new(key_pem);

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        inner_request.insert("passphrase", key_passphrase.as_bytes());
        inner_request.insert("new-passphrase", new_key_passphrase.as_bytes());
        let response = connection
            .outer_request(
                Command::ImportKey {
                    user: self.user_name.clone(),
                    key: key_name,
                    keytype: key_type.to_string(),
                    initial_key_admin,
                },
                Some(request_payload),
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Delete a key from the Sigul server.
    #[instrument(skip_all)]
    pub async fn delete_key(
        &self,
        admin_passphrase: Password,
        key_name: String,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::DeleteKey {
                    user: self.user_name.clone(),
                    key: key_name,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Modify a key on the Sigul server.
    #[instrument(skip_all)]
    pub async fn modify_key(
        &self,
        admin_passphrase: Password,
        key_name: String,
        new_key_name: Option<String>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ModifyKey {
                    user: self.user_name.clone(),
                    key: key_name,
                    new_name: new_key_name,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// List the users that have access to a key.
    #[instrument(skip_all)]
    pub async fn key_users(
        &self,
        admin_passphrase: Password,
        key_name: String,
    ) -> Result<Vec<String>, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ListKeyUsers {
                    user: self.user_name.clone(),
                    key: key_name.clone(),
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;

        let mut num_users = response
            .fields
            .get("num-users")
            .map(|b| Bytes::from(b.clone()))
            .ok_or(anyhow::anyhow!("missing expected field 'num-users'"))?;

        if num_users.len() != 4 {
            // The expected value of this field is a u32.
            return Err(anyhow::anyhow!(
                "the 'num-users' field was {} bytes; expected 4",
                num_users.len()
            )
            .into());
        }
        let num_users: usize = num_users
            .get_u32()
            .try_into()
            .context("the number of users couldn't be converted to usize")?;
        let users = payload
            .split(|byte| *byte == 0)
            .filter_map(|name| {
                if !name.is_empty() {
                    String::from_utf8(name.into()).ok()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if users.len() != num_users {
            return Err(anyhow::anyhow!(
                "Server response indicated {} users, but {} names were sent!",
                num_users,
                users.len()
            )
            .into());
        }

        Ok(users)
    }

    /// Grant a user access to a key.
    ///
    /// The current user must be a key administrator to grant access to the key. `key_passphrase`
    /// is the passphrase to use the key as the current authenticated user, and `user_passphrase`
    /// is the passphrase that will be used to unlock the key for the user being granted access.
    ///
    /// `client_bindings` and `server_bindings` are optional bindings that can be used to
    /// restrict the key's use to a specific client or server. If `None`, no bindings are set.
    /// If `server_bindings` or `client_bindings` is provided, it must be a JSON-serialized string
    /// containing the bindings.
    #[instrument(skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub async fn grant_key_access(
        &self,
        admin_passphrase: Password,
        key_name: String,
        key_passphrase: Password,
        user_name: String,
        user_passphrase: Password,
        client_binding: Option<String>,
        server_binding: Option<String>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        inner_request.insert("passphrase", key_passphrase.as_bytes());
        inner_request.insert("new-passphrase", user_passphrase.as_bytes());
        // A silly little hack to avoid lifetime issues since everything is borrowed.
        let client_binding_bytes = client_binding.unwrap_or_default();
        if !client_binding_bytes.is_empty() {
            inner_request.insert("client-binding", client_binding_bytes.as_bytes());
        }
        let server_binding_bytes = server_binding.unwrap_or_default();
        if !server_binding_bytes.is_empty() {
            inner_request.insert("server-binding", server_binding_bytes.as_bytes());
        }
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::GrantKeyAccess {
                    user: self.user_name.clone(),
                    key: key_name,
                    name: user_name,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Change a key's expiration date.
    #[instrument(skip_all)]
    pub async fn change_key_expiration(
        &self,
        admin_passphrase: Password,
        key_name: String,
        key_passphrase: Password,
        subkey_id: Option<String>,
        expire_date: Option<String>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        inner_request.insert("passphrase", key_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ChangeKeyExpiration {
                    user: self.user_name.clone(),
                    key: key_name,
                    expire_date,
                    subkey: subkey_id,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Revoke a user's key access.
    #[instrument(skip_all)]
    pub async fn revoke_key_access(
        &self,
        admin_passphrase: Password,
        key_name: String,
        user_name: String,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::RevokeKeyAccess {
                    user: self.user_name.clone(),
                    key: key_name,
                    name: user_name,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Retrieve the public key for a given key name.
    #[instrument(skip_all)]
    pub async fn get_public_key(
        &self,
        admin_passphrase: Password,
        key_name: String,
    ) -> Result<responses::PublicKey, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::GetPublicKey {
                    user: self.user_name.clone(),
                    key: key_name.clone(),
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;

        Ok(responses::PublicKey {
            key_name,
            data: payload,
        })
    }

    /// Change the passphrase for a key.
    ///
    /// This changes the passphrase for the current user.
    #[instrument(skip_all)]
    pub async fn change_passphrase(
        &self,
        key_name: String,
        current_key_passphrase: Password,
        new_key_passphrase: Password,
        client_binding: Option<String>,
        server_binding: Option<String>,
    ) -> Result<(), Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("passphrase", current_key_passphrase.as_bytes());
        inner_request.insert("new-passphrase", new_key_passphrase.as_bytes());
        let client_binding_bytes = client_binding.unwrap_or_default();
        if !client_binding_bytes.is_empty() {
            inner_request.insert("client-binding", client_binding_bytes.as_bytes());
        }
        let server_binding_bytes = server_binding.unwrap_or_default();
        if !server_binding_bytes.is_empty() {
            inner_request.insert("server-binding", server_binding_bytes.as_bytes());
        }
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ChangePassphrase {
                    user: self.user_name.clone(),
                    key: key_name,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;
        assert!(payload.is_empty());

        Ok(())
    }

    /// Sign a platform executable (PE) file for Secure Boot.
    #[instrument(skip_all)]
    pub async fn sign_pe<I, O>(
        &self,
        input: I,
        output: O,
        key_passphrase: Password,
        key_name: String,
        cert_name: String,
    ) -> Result<(), Error>
    where
        I: AsyncRead + AsyncSeek + Unpin,
        O: AsyncWrite + Unpin,
    {
        let connection = self.connect().await?;

        let op = Command::SignPe {
            user: self.user_name.clone(),
            key: key_name,
            cert_name,
        };

        let mut inner_request = HashMap::new();
        inner_request.insert("passphrase", key_passphrase.as_bytes());

        let response = connection
            .outer_request(op, Some(input))
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(output)
            .await?;

        tracing::info!(?response.fields, response.status_code, "Got response fields");
        Ok(())
    }

    /// Create and sign a certificate for a key Sigul manages.
    #[instrument(skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_certificate(
        &self,
        issuer_key_name: String,
        issuer_key_passphrase: Password,
        issuer_certificate_name: Option<String>,
        subject_key_name: String,
        subject_certificate_name: String,
        subject_certificate_type: CertificateType,
        subject_common_name: String,
        validity: u32,
    ) -> Result<X509, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("passphrase", issuer_key_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::SignCertificate {
                    user: self.user_name.clone(),
                    issuer_key: issuer_key_name,
                    subject_key: subject_key_name,
                    subject: format!("CN={subject_common_name}"),
                    validity: format!("{validity}y"),
                    subject_certificate_name,
                    certificate_type: subject_certificate_type.to_string(),
                    issuer_certificate_name,
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;

        let certificate = X509::from_pem(&payload)?;

        Ok(certificate)
    }

    /// List the server binding methods available on the Sigul server.
    #[instrument(skip_all)]
    pub async fn server_binding_methods(
        &self,
        admin_passphrase: Password,
    ) -> Result<Vec<String>, Error> {
        let connection = self.connect().await?;
        let (payload_reader, payload_writer) = get_payload_pipe();

        let mut inner_request = HashMap::new();
        inner_request.insert("password", admin_passphrase.as_bytes());
        let response = connection
            .outer_request::<tokio::io::Empty>(
                Command::ListBindingMethods {
                    user: self.user_name.clone(),
                },
                None,
            )
            .await?
            .inner_request(self.tls_config.ssl(&self.server_hostname)?, inner_request)
            .await?
            .response(payload_writer)
            .await?;
        tracing::info!(response.status_code, "Sigul response received");
        let payload = payload_reader
            .await
            .context("response payload could not be read")??;

        let mut num_methods = response
            .fields
            .get("num-methods")
            .map(|b| Bytes::from(b.clone()))
            .ok_or(anyhow::anyhow!("missing expected field 'num-methods'"))?;

        if num_methods.len() != 4 {
            // The expected value of this field is a u32.
            return Err(anyhow::anyhow!(
                "the 'num-methods' field was {} bytes; expected 4",
                num_methods.len()
            )
            .into());
        }
        let num_methods: usize = num_methods
            .get_u32()
            .try_into()
            .context("the number of keys couldn't be converted to usize")?;
        let binding_methods = payload
            .split(|byte| *byte == 0)
            .filter_map(|method| {
                if !method.is_empty() {
                    String::from_utf8(method.into()).ok()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if binding_methods.len() != num_methods {
            return Err(anyhow::anyhow!(
                "Server response indicated {} binding methods, but {} methods were sent!",
                num_methods,
                binding_methods.len()
            )
            .into());
        }

        Ok(binding_methods)
    }
}
