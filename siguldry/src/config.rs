// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{env, path::PathBuf};

use anyhow::Context;
use openssl::{
    error::ErrorStack,
    ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion},
};
use serde::{Deserialize, Serialize};

/// Credentials required to authenticate connections.
///
/// It is highly recommended that you use systemd credentials to ensure the private key is
/// only accessible to the service using it. If the paths provided are relative, it is assumed
/// to be relative to the `$CREDENTIALS_DIRECTORY` environment variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// The systemd credentials ID of the PEM-encoded private key file.
    ///
    /// This private key is the key that matches the `certificate` and is used to authenticate
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
    /// The path to the certificate that matches the `private_key`.
    pub certificate: PathBuf,
    /// The path to the certificate authority to use when verifying certificates.
    pub ca_certificate: PathBuf,
}

impl Credentials {
    pub(crate) fn ssl_connector(&self) -> Result<SslConnector, ErrorStack> {
        let mut connector = SslConnector::builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        connector.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        connector.set_ca_file(&self.ca_certificate)?;
        connector.set_private_key_file(&self.private_key, SslFiletype::PEM)?;
        connector.set_certificate_file(&self.certificate, SslFiletype::PEM)?;
        connector.check_private_key()?;

        Ok(connector.build())
    }

    pub(crate) fn ssl_acceptor(&self) -> anyhow::Result<SslAcceptor> {
        // TODO bump to mozilla_modern_v5 if RHEL10 supports that
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let client_ca_cert = openssl::x509::X509::from_pem(
            std::fs::read_to_string(&self.ca_certificate)?.as_bytes(),
        )?;
        acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.add_client_ca(&client_ca_cert)?;
        acceptor.set_ca_file(&self.ca_certificate)?;
        acceptor.set_private_key_file(&self.private_key, SslFiletype::PEM)?;
        acceptor.set_certificate_file(&self.certificate, SslFiletype::PEM)?;
        acceptor.check_private_key()?;

        Ok(acceptor.build())
    }

    /// Fix up any relative paths in the configuration file to use the provided credentials directory.
    ///
    /// # Errors
    ///
    /// If the referenced files don't exist, an error is returned.
    pub fn with_credentials_dir(
        &mut self,
        credentials_dir: &std::path::Path,
    ) -> anyhow::Result<()> {
        if self.private_key.is_absolute() {
            tracing::warn!(
                private_key = self.private_key.display().to_string(),
                "Path to private key file is absolute; consider using systemd credentials"
            );
        } else {
            self.private_key = credentials_dir.join(&self.private_key);
            if !self.private_key.exists() {
                return Err(anyhow::anyhow!(
                    "No private key file named '{}' found in credentials directory",
                    self.private_key.display()
                ));
            }
        }
        if !self.certificate.is_absolute() {
            self.certificate = credentials_dir.join(&self.certificate);
            if !self.certificate.exists() {
                return Err(anyhow::anyhow!(
                    "No certificate file named '{}' found in credentials directory",
                    self.certificate.display()
                ));
            }
        }
        if !self.ca_certificate.is_absolute() {
            self.ca_certificate = credentials_dir.join(&self.ca_certificate);
            if !self.ca_certificate.exists() {
                return Err(anyhow::anyhow!(
                    "No CA certificate file named '{}' found in credentials directory",
                    self.ca_certificate.display()
                ));
            }
        }

        Ok(())
    }
}

#[cfg(feature = "cli")]
fn private_load_config<T>(path: &std::path::Path) -> anyhow::Result<T>
where
    T: Default + std::fmt::Display + serde::de::DeserializeOwned,
{
    let config = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read from path {path:?}"))?;
    tracing::info!(path=%path.display(), "Read from configuration file");
    toml::from_str(&config)
        .inspect_err(|error| {
            eprintln!("Failed to parse configuration loaded from {path:?}:\n{error}");
            eprintln!("Example config file:\n\n{}", T::default());
        })
        .context("configuration file is invalid")
}

/// Load the configuration with fallback options.
///
/// If `path` is [`None`], the `default` path, which should be relative to CONFIGURATION_DIRECTORY, is
/// checked.  If the default config doesn't exist, the [`Default`] implementation is returned. It's
/// expected that CONFIGURATION_DIRECTORY is set via systemd.
///
/// # Errors
///
/// In the event that one of the config files exists, but is invalid, an error is returned.
#[cfg(feature = "cli")]
pub fn load_config<T>(path: Option<PathBuf>, default: &std::path::Path) -> anyhow::Result<T>
where
    T: Default + std::fmt::Display + serde::de::DeserializeOwned,
{
    path.or_else(|| {
        env::var("CONFIGURATION_DIRECTORY")
            .inspect_err(|error| {
                tracing::warn!(
                    ?error,
                    "CONFIGURATION_DIRECTORY environment variable isn't readable"
                );
            })
            .map(PathBuf::from)
            .ok()
            .map(|base_path| base_path.join(default))
            .filter(|path| path.is_file())
    })
    .map_or_else(
        || {
            tracing::warn!("No configuration file found; using defaults");
            Ok(T::default())
        },
        |path| {
            tracing::info!(?path, "Attempting to  load configuration");
            private_load_config::<T>(&path)
        },
    )
}
