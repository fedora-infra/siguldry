// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! The Siguldry client configuration.

use std::{path::PathBuf, time::Duration};

use sequoia_openpgp::crypto::Password;
use serde::{Deserialize, Serialize};

use crate::config::Credentials;

/// Configuration for the siguldry client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The Siguldry server hostname. This is used to validate the server's TLS certificate.
    pub server_hostname: String,
    /// The Siguldry bridge hostname. This is used to validate the bridge's TLS certificate.
    pub bridge_hostname: String,
    /// The port on the Siguldry bridge to connect to; the default is 44334.
    pub bridge_port: u16,
    /// The amount of time to wait before giving up on a request and retrying.
    ///
    /// This covers both sending requests and receiving responses. In other words, the client
    /// will retry the request on a new connection if it cannot write the request to the socket
    /// within `request_timeout`, *and* it will retry if it fails to read a response to that
    /// request from the socket within `request_timeout`.
    pub request_timeout: Duration,
    /// The credentials to use when authenticating to the Siguldry bridge and server. Note that
    /// the certificate must have the `clientAuth` extended key usage extension.
    pub credentials: Credentials,

    /// A list of keys to unlock for the client.
    ///
    /// This can be set for users of the client who can't (or don't want to) call unlock or safely
    /// store a password. One example would be the PKCS#11 module used inside a build environment.
    pub keys: Vec<Key>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_hostname: "server.example.com".to_string(),
            bridge_hostname: "bridge.example.com".to_string(),
            bridge_port: 44334,
            request_timeout: Duration::from_secs(30),
            credentials: Credentials {
                private_key: PathBuf::from("siguldry.client.private_key.pem"),
                certificate: PathBuf::from("siguldry.client.certificate.pem"),
                ca_certificate: PathBuf::from("siguldry.ca_certificate.pem"),
            },
            keys: vec![],
        }
    }
}

#[cfg(feature = "cli")]
impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            toml::ser::to_string_pretty(&self).unwrap_or_default()
        )
    }
}

/// A key to unlock for the client
#[derive(Debug, Clone, Serialize)]
pub struct Key {
    /// The name of the key in the Siguldry server.
    pub key_name: String,
    /// The systemd credential ID containing the passphrase.
    ///
    /// The passphrase inside the file must be entirely on the first line of
    /// the file and the file should be terminated with a newline. The default
    /// settings for `systemd-ask-password` will produce an acceptable file:
    ///
    /// ```bash
    /// systemd-ask-password | systemd-creds encrypt - /etc/credstore.encrypted/siguldry.my_key_password
    /// ```
    pub passphrase_path: PathBuf,
    #[serde(skip)]
    pub(crate) passphrase: Password,
}

impl Key {
    // Useful for tests that serialize entries out.
    #[doc(hidden)]
    pub fn private_new(key_name: String, passphrase_path: PathBuf) -> Self {
        Self {
            key_name,
            passphrase_path,
            passphrase: "".into(),
        }
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct KeyHelper {
            key_name: String,
            passphrase_path: PathBuf,
        }

        let helper = KeyHelper::deserialize(deserializer)?;

        let passphrase = std::fs::read_to_string(&helper.passphrase_path)
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "Failed to read passphrase file {}: {}",
                    helper.passphrase_path.display(),
                    e
                ))
            })?
            .lines()
            .next()
            .and_then(|pass| {
                let pass = pass.trim();
                if !pass.is_empty() { Some(pass) } else { None }
            })
            .ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "Passphrase file {} does not contain a password on the first line",
                    helper.passphrase_path.display()
                ))
            })?
            .to_string()
            .into();

        Ok(Key {
            key_name: helper.key_name,
            passphrase_path: helper.passphrase_path,
            passphrase,
        })
    }
}

impl Key {
    pub fn password(&self) -> String {
        self.passphrase
            .map(|p| String::from_utf8(p.to_vec()).expect("The password deserialized to a string"))
    }
}
