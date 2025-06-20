// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

#![doc = include_str!("../README.md")]

#[doc(hidden)]
pub mod cli;
pub mod config;
pub(crate) mod pesign;
mod service;

use std::path::PathBuf;

use anyhow::Context as AnyhowContext;
#[doc(hidden)]
pub use service::listen;

/// Unifying structure for the CLI options and configuration file.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Context {
    pub(crate) runtime_directory: PathBuf,
    pub(crate) config: config::Config,
    pub(crate) sigul_client: siguldry::v1::client::Client,
}

impl Context {
    pub fn new(config: config::Config, runtime_directory: PathBuf) -> anyhow::Result<Self> {
        // if multiple runtime directories were provided, we don't know which to use so panic for now.
        if runtime_directory
            .to_str()
            .ok_or(anyhow::anyhow!(
                "runtime_directory must be valid unicode characters"
            ))?
            .contains(':')
        {
            return Err(anyhow::anyhow!(
                "Multiple RuntimeDirectories are not supported"
            ));
        }

        let tls_config = siguldry::v1::client::TlsConfig::new(
            &config.sigul.client_certificate,
            &config.sigul.private_key,
            None, // The expectation is the key is encrypted via systemd
            &config.sigul.ca_certificate,
        )
        .context("Failed to create OpenSSL TLS configuration")?;
        let sigul_client = siguldry::v1::client::Client::new(
            tls_config,
            config.sigul.bridge_hostname.clone(),
            config.sigul.bridge_port,
            config.sigul.server_hostname.clone(),
            config.sigul.sigul_user_name.clone(),
        );

        Ok(Self {
            runtime_directory,
            config,
            sigul_client,
        })
    }
}
