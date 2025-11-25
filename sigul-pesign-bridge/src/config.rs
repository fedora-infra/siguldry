// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The configuration format for `sigul-pesign-bridge`.
//!
//! Configuration is provided via a command-line argument or environment
//! variable (`SIGUL_PESIGN_BRIDGE_CONFIG`). The configuration should be in TOML format.
//!
//! The [`Config`] has several top-level settings, as well as a list of one or
//! more signing [`Key`] settings.
//!
//! There is no configuration merging: a configuration file must contain
//! settings for _all_ required fields.
//!
//! To validate your configuration, refer to the `sigul-pesign-bridge config` command.

use std::{num::NonZeroU64, path::PathBuf};

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};

/// The configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The total length of time (in seconds) to wait for a signing request to complete.
    ///
    /// The service will retry requests to the Sigul server until it succeeds or
    /// this timeout is reached, at which point it will signal to the pesign-client
    /// that the request failed.
    pub total_request_timeout_secs: NonZeroU64,

    /// The timeout (in seconds) to wait for a response from the Sigul server.
    ///
    /// Requests that time out are retried until `total_request_timeout_secs` is reached.
    /// As such, this value should be several times smaller than `total_request_timeout_secs`.
    pub sigul_request_timeout_secs: NonZeroU64,

    /// Configuration to connect to the Sigul server.
    pub sigul: Siguldry,

    /// A list of signing keys available for use.
    ///
    /// Each key must be accessible to the Sigul client user in the Sigul
    /// server. The pesign-client specifies the key it wants to sign its
    /// request. If the requested key is not in this list, the request is
    /// rejected.
    pub keys: Vec<Key>,
}

/// Configuration to connect to the Sigul server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Siguldry {
    /// The hostname of the Sigul bridge; this is used to verify the bridge's
    /// TLS certificate.
    pub bridge_hostname: String,
    /// The port to connect to the Sigul bridge; the typical port is 44334.
    pub bridge_port: u16,
    /// The hostname of the Sigul server; this is used to verify the server's
    /// TLS certificate.
    pub server_hostname: String,
    /// The username to use when authenticating with the Sigul bridge.
    pub sigul_user_name: String,
    /// The systemd credentials ID of the PEM-encoded private key file.
    ///
    /// This private key is the key that matches the `client_certificate` and is used to authenticate
    /// with the Sigul bridge. It is expected to be provided by systemd's "ImportCredential" or
    /// "LoadCredentialEncrypted" option.
    ///
    /// # Example
    ///
    /// To prepare the encrypted configuration:
    ///
    /// ```bash
    /// systemd-creds encrypt /secure/ramfs/private-key.pem /etc/credstore.encrypted/sigul.client.private_key
    /// ```
    ///
    /// This will produce an encrypted blob which will be decrypted by systemd at runtime.
    pub private_key: PathBuf,
    /// The path to client certificate that matches the `private_key`.
    pub client_certificate: PathBuf,
    /// The path to the certificate authority to use when verifying the Sigul bridge and Sigul
    /// server certificates.
    pub ca_certificate: PathBuf,
}

impl Default for Siguldry {
    fn default() -> Self {
        Self {
            bridge_hostname: "localhost".into(),
            bridge_port: 44334,
            server_hostname: "localhost".into(),
            sigul_user_name: "sigul-client".into(),
            private_key: "sigul.client.private_key.pem".into(),
            client_certificate: "sigul.client.certificate.pem".into(),
            ca_certificate: "sigul.ca_certificate.pem".into(),
        }
    }
}

/// A signing key and certificate pair.
///
/// When the sigul client requests that a PE be signed, it must specify a
/// signing key and a certificate to use. Additionally, it must provide a
/// passphrase to use the requested signing key.
///
/// If the pesign-client requests a signature from a [`Key`] that is not in the
/// [`Config`], its request is rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    /// The token name that pesign-client provides; it will be mapped to the
    /// `key_name` field when passed to sigul. For example, if pesign-client
    /// asks for "OpenSC Card" and the key name in Sigul is "fedora-signer",
    /// set `pesign_token_name` to "OpenSC Card" and `key_name` to "fedora-signer".
    pub pesign_token_name: String,
    /// The certificate name that pesign-client provides; it will be mapped to
    /// the `certificate_name` field just like `pesign_token_name` is mapped.
    pub pesign_certificate_name: String,
    /// The name of the key in the Sigul server.
    pub key_name: String,
    /// The name of the certificate in the Sigul server.
    pub certificate_name: String,
    /// The systemd credential ID containing the passphrase.
    ///
    /// The passphrase inside the file must be entirely on the first line of
    /// the file and the file should be terminated with a newline. The default
    /// settings for `systemd-ask-password` will produce an acceptable file:
    ///
    /// ```bash
    /// systemd-ask-password | systemd-creds encrypt - /etc/credstore.encrypted/sigul.key.phrase
    /// ```
    pub passphrase_path: PathBuf,
    /// If set, the service will validate the PE has been signed with the given
    /// certificate before returning the signed file to the client.
    ///
    /// This validation is done with the `sbverify` application, which must be
    /// installed to use this option. This is optional, and if unset, no signature
    /// validation is performed before passing the result back to the pesign-client.
    pub certificate_file: Option<PathBuf>,
}

impl Default for Key {
    fn default() -> Self {
        Self {
            pesign_token_name: "OpenSC Card".to_string(),
            pesign_certificate_name: "some-signing-certificate".to_string(),
            key_name: "signing-key".to_string(),
            certificate_name: "codesigning".to_string(),
            passphrase_path: PathBuf::from("sigul.signing-key-passphrase"),
            certificate_file: None,
        }
    }
}

impl Key {
    /// The Sigul passphrase protecting this key.
    #[doc(hidden)]
    pub fn passphrase(&self) -> Result<String, anyhow::Error> {
        let passphrase = std::fs::read_to_string(&self.passphrase_path)?
            .lines()
            .next()
            .and_then(|pass| {
                let pass = pass.trim();
                if !pass.is_empty() { Some(pass) } else { None }
            })
            .ok_or_else(|| {
                anyhow!(
                    "Passphrase file {} does not contain a password on the first line",
                    self.passphrase_path.display()
                )
            })?
            .to_string();

        Ok(passphrase)
    }
}

impl Config {
    /// Fix up any relative paths in the configuration file to use the provided credentials directory.
    ///
    /// # Errors
    ///
    /// If the referenced files don't exist, an error is returned.
    #[doc(hidden)]
    pub fn fix_credentials(&mut self, credentials_dir: &std::path::Path) -> anyhow::Result<()> {
        self
            .keys
            .iter_mut()
            .map(|key| {
                if key.passphrase_path.is_absolute() {
                    tracing::warn!(
                        passphrase_path = key.passphrase_path.display().to_string(),
                        key_name = key.key_name,
                        "Path to passphrase file is absolute; consider using systemd credentials"
                    );
                } else {
                    let passphrase_path = credentials_dir.join(&key.passphrase_path);
                    if !passphrase_path.exists() {
                        return Err(anyhow::anyhow!(
                            "No file named '{}' found in credentials directory",
                            key.passphrase_path.display(),
                        ));
                    }
                    key.passphrase_path = passphrase_path;
                }

                if let Some(ca_cert) = &key.certificate_file  && !ca_cert.is_absolute() {
                        let absolute_ca_cert = credentials_dir.join(ca_cert);
                        if !absolute_ca_cert.exists() {
                            tracing::error!(key.key_name, ?key.certificate_file, "CA file is not an absolute path and isn't in the credentials directory");
                            return Err(anyhow::anyhow!("CA file '{}' is missing", ca_cert.display()));
                        }
                        key.certificate_file = Some(absolute_ca_cert);

                }

                Ok(())
            }).collect::<Result<Vec<_>, _>>()?;

        if self.sigul.private_key.is_absolute() {
            tracing::warn!(
                private_key = self.sigul.private_key.display().to_string(),
                "Path to private key file is absolute; consider using systemd credentials"
            );
        } else {
            self.sigul.private_key = credentials_dir.join(&self.sigul.private_key);
            if !self.sigul.private_key.exists() {
                return Err(anyhow::anyhow!(
                    "No private key file named '{}' found in credentials directory",
                    self.sigul.private_key.display()
                ));
            }
        }
        if !self.sigul.client_certificate.is_absolute() {
            self.sigul.client_certificate = credentials_dir.join(&self.sigul.client_certificate);
            if !self.sigul.client_certificate.exists() {
                return Err(anyhow::anyhow!(
                    "No client certificate file named '{}' found in credentials directory",
                    self.sigul.client_certificate.display()
                ));
            }
        }
        if !self.sigul.ca_certificate.is_absolute() {
            self.sigul.ca_certificate = credentials_dir.join(&self.sigul.ca_certificate);
            if !self.sigul.ca_certificate.exists() {
                return Err(anyhow::anyhow!(
                    "No CA certificate file named '{}' found in credentials directory",
                    self.sigul.ca_certificate.display()
                ));
            }
        }

        Ok(())
    }

    /// Check the configuration file for validity.
    ///
    /// An error is returned if the files referenced do not exist, or if any of them contain invalid
    /// values.
    #[doc(hidden)]
    pub fn validate(&self) -> anyhow::Result<()> {
        self.keys
            .iter()
            .map(|key| {
                key.passphrase()
                    .inspect_err(|e| tracing::error!(path=?key.passphrase_path, error=%e))
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.keys
            .iter()
            .filter_map(|key| key.certificate_file.as_ref())
            .map(|ca_cert| {
                if !ca_cert.exists() {
                    Err(anyhow::anyhow!(
                        "The CA file '{}' does not exist",
                        ca_cert.display()
                    ))
                } else {
                    Ok(())
                }
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        if self.keys.iter().any(|key| key.certificate_file.is_some()) {
            let mut command = std::process::Command::new("sbverify");
            command.arg("--help");
            let output = command.output()?;
            if !output.status.success() {
                return Err(anyhow!(
                    "sbverify needs to be installed and functional: {:?}",
                    output
                ));
            }
        }

        Ok(())
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

impl Default for Config {
    fn default() -> Self {
        Self {
            total_request_timeout_secs: NonZeroU64::new(60 * 10)
                .expect("Don't set the default to 0"),
            sigul_request_timeout_secs: NonZeroU64::new(60).expect("Don't set the default to 0"),
            keys: vec![Key::default()],
            sigul: Siguldry::default(),
        }
    }
}

pub(crate) fn load(path: &str) -> anyhow::Result<Config> {
    let config = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read from path {path:?}"))?;
    tracing::info!(%path, "Read from configuration file");
    toml::from_str(&config)
        .inspect_err(|error| {
            eprintln!("Failed to parse configuration loaded from {path:?}:\n{error}");
            eprintln!("Example config file:\n\n{}", Config::default());
        })
        .context("configuration file is invalid")
}
