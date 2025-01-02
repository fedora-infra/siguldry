//! Available configuration for `sigul-pesign-bridge`.
//!
//!

use std::{num::NonZeroU64, path::PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The directory where the service stores temporary files.
    ///
    /// These temporary files are the PE applications (both signed and unsigned) that are passed to
    /// the Sigul client. As such, this directory should be as secure as the directory that contains
    /// the service socket as an attacker could substitute the input or output file with a malicious
    /// file that could either be signed by the service, or injected into an RPM.
    ///
    /// However, as anyone with access to the socket can get a PE application signed, the use of temporary
    /// files should be as safe as the socket. This directory should be read/writeable only to the service
    /// owner/group. Furthermore, this is used as the base for temporary directories that are read/writable
    /// solely to the owner.
    pub work_directory: PathBuf,

    /// The path to use for the service Unix socket.
    ///
    /// This directory should be read/writable only to the service owner and the group which should be allowed
    /// to sign files. There is no authentication on requests, so anyone with access to the socket can sign
    /// files.
    pub socket_path: PathBuf,

    /// The systemd credentials ID of the Sigul client configuration.
    ///
    /// This configuration file includes the password to access the NSS database that contains the
    /// client certificate used to authenticate with the Sigul server. As such, it is expected to
    /// be provided by systemd's "LoadCredentialsEncrypted" option.
    ///
    /// To prepare the encrypted configuration::
    ///
    ///   # systemd-creds encrypt /secure/ramfs/sigul-client.conf /etc/sigul-pesign-bridge/sigul-client.conf
    ///
    /// This will produce an encrypted blob which will be decrypted by systemd at runtime.
    ///  
    /// # Example
    ///
    /// Suppose the systemd unit file contains the following::
    ///  
    ///     [Service]
    ///     LoadCredentialsEncrypted=sigul-client-config:/etc/sigul-pesign-bridge/sigul-client.conf
    ///
    /// The credentials ID is "sigul-client-config". The decrypted file is provided to the service
    /// by systemd using the path "$CREDENTIALS_PATH/sigul-client-config".
    pub sigul_client_config: PathBuf,

    /// The total length of time (in seconds) to wait for a signing request to complete.
    ///
    /// The service will retry requests to the Sigul server until it succeeds or
    /// this timeout is reached, at which point it will signal to the pesign-client
    /// that the request failed.
    pub request_timeout_secs: NonZeroU64,

    /// A list of signing keys available for use.
    pub keys: Vec<Key>,
}

/// A signing key and certificate pair.
///
/// Each sigul request must specify a signing key to use and a certificate.
/// Additionally, it must provide a passphrase to use the requested signing key.
///
/// The service must be configured with a set of [`Key`] it has access to for signing.
/// If a client specifies a key that is not in the configuration, its request is rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    /// The name of the key in Sigul.
    pub key_name: String,
    /// The name of the certificate in Sigul.
    pub certificate_name: String,
    /// The ID used in the systemd encrypted credential.
    pub passphrase_path: PathBuf,
    /// If set, the service will validate the PE has been signed with the given certificate
    /// before returning the signed file to the client.
    pub certificate_file: Option<PathBuf>,
}

impl Default for Key {
    fn default() -> Self {
        Self {
            key_name: "signing-key".to_string(),
            certificate_name: "codesigning".to_string(),
            passphrase_path: PathBuf::from("sigul-signing-key-passphrase"),
            certificate_file: None,
        }
    }
}

impl Key {
    /// The Sigul passphrase protecting this key.
    pub fn passphrase(&self) -> Result<String, anyhow::Error> {
        let mut credentials_path = std::env::var("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .context("You (or systemd) must set the CREDENTIALS_DIRECTORY environment variable")?;
        credentials_path.push(&self.passphrase_path);
        let mut passphrase = std::fs::read_to_string(credentials_path)?;
        // TODO: decide on how to handle a passphrase file with newlines (split and take the first line, reject?)
        passphrase.push('\0');
        Ok(passphrase)
    }
}

impl Config {
    /// Get the absolute path to the Sigul client configuration file.
    ///
    /// The configuration file is expected to be stored relative to the CREDENTIALS_DIRECTORY.
    pub fn sigul_client_config(&self) -> Result<PathBuf, anyhow::Error> {
        let mut config_path = std::env::var("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .context("You (or systemd) must set the CREDENTIALS_DIRECTORY environment variable")?;
        config_path.push(&self.sigul_client_config);
        Ok(config_path)
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
            work_directory: PathBuf::from("/run/pesign/"),
            socket_path: PathBuf::from("/run/pesign/socket"),
            request_timeout_secs: NonZeroU64::new(60 * 15).expect("Don't set the default to 0"),
            keys: vec![Key::default()],
            sigul_client_config: PathBuf::from("sigul-client-config"),
        }
    }
}

pub(crate) fn load(path: &str) -> anyhow::Result<Config> {
    let config = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read from path {path:?}"))?;
    toml::from_str(&config)
        .inspect_err(|error| {
            println!("Failed to parse configuration loaded from {path:?}:\n{error}");
            println!("Example config file:\n\n{}", Config::default());
        })
        .context("configuration file is invalid")
}
