// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Signs OSTree commits.
//!
//! This assumes the message references an ostree and commit that is available on the local
//! filesystem. Fedora runs the auto-signing service on a host that has write access to an
//! NFS share with all the ostrees.

use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use siguldry::protocol::Key;
use tokio::sync::Semaphore;
use tracing::{Level, instrument};

use crate::{PgpConfig, config::Config};

/// Message sent after a Pungi OSTree compose.
///
/// This message, sadly, doesn't include a schema. It is sent on
/// "org.fedoraproject.*.pungi.compose.ostree". The message does include
/// additional fields, but we will only reference the ones we need.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OstreeCompose {
    /// The OSTree reference name.
    #[serde(rename = "ref")]
    reference: String,
    /// The commit ID in that reference to sign.
    commitid: String,
}

#[derive(Clone)]
pub(crate) struct OstreeSigner {
    config: Arc<Config>,
    concurrency: Arc<Semaphore>,
    pgp_home: Arc<PgpConfig>,
    signing_keys: Arc<HashMap<String, Key>>,
}

impl OstreeSigner {
    pub fn new(
        config: Arc<Config>,
        concurrency: Arc<Semaphore>,
        pgp_home: Arc<PgpConfig>,
        signing_keys: Arc<HashMap<String, Key>>,
    ) -> Self {
        Self {
            config,
            concurrency,
            pgp_home,
            signing_keys,
        }
    }

    // Sign an OSTree reference.
    //
    // For OSTree signing, we expect the tree to be a local directory which
    // is updated by something else and which we have write access to. In Fedora
    // this is an NFS share with Koji.
    #[instrument(skip_all,  err(level = Level::WARN), fields(ostree.reference = ostree.reference, ostree.commitid = ostree.commitid.chars().take(12).collect::<String>()))]
    pub async fn sign(&self, ostree: OstreeCompose) -> anyhow::Result<()> {
        let ref_config = if let Some(ref_config) = self
            .config
            .ostree
            .iter()
            .find(|config| config.reference == ostree.reference)
        {
            tracing::info!(
                key = ref_config.siguldry_key,
                cert = ref_config.siguldry_openpgp_cert,
                "OSTree ref configured for signing"
            );
            ref_config
        } else {
            tracing::info!("OSTree ref is not configured for auto-signing");
            crate::metrics_utils::ostree_skipped().increment(1);
            return Ok(());
        };

        let signing_cert = self
            .signing_keys
            .get(&ref_config.siguldry_key)
            .and_then(|key| {
                key.certificates
                    .iter()
                    .find(|cert| cert.name == ref_config.siguldry_openpgp_cert)
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to find the OpenPGP certificate {} for signing key {}",
                    ref_config.siguldry_openpgp_cert,
                    ref_config.siguldry_key
                )
            })?;
        let gpg_homedir = self
            .pgp_home
            .gpg_homedirs
            .get(&signing_cert.fingerprint)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "OpenPGP fingerprint {} missing from gpg homedirs!",
                    signing_cert.fingerprint
                )
            })?;

        if !ostree.commitid.chars().all(|c| c.is_ascii_hexdigit()) {
            tracing::error!("Commit ID is not a valid hex string");
            crate::metrics_utils::ostree_skipped().increment(1);
            return Ok(());
        }
        // It's probably always going to be SHA-256, but let's be reasonable here.
        if ostree.commitid.len() > 128 {
            tracing::error!("Commit ID is unreasonably long");
            crate::metrics_utils::ostree_skipped().increment(1);
            return Ok(());
        }

        // We first sign the commit ID, then update the reference to point to that commit ID.
        let mut sign_command = tokio::process::Command::new("ostree");
        sign_command
            .kill_on_drop(true)
            .env_clear()
            .arg("gpg-sign")
            .arg(format!("--repo={}", ref_config.directory.display()))
            .arg(format!("--gpg-homedir={}", gpg_homedir.display()))
            .arg(&ostree.commitid)
            .arg(&signing_cert.fingerprint);
        let signing_permit = self
            .concurrency
            .acquire()
            .await
            .context("Concurrency semaphore is closed")?;
        let sign_start_time = std::time::Instant::now();
        let output = sign_command
            .output()
            .await
            .context("Failed to spawn ostree; is it installed?")?;
        crate::metrics_utils::ostree_sign_time().record(sign_start_time.elapsed().as_secs() as f64);
        drop(signing_permit);

        if !output.status.success() {
            tracing::error!(
                exit_code = ?output.status.code(),
                stdout = %String::from_utf8_lossy(&output.stdout),
                stderr = %String::from_utf8_lossy(&output.stderr),
                "Signing command failed: '{sign_command:?}'",
            );

            crate::metrics_utils::ostree_failed().increment(1);
            return Err(anyhow::anyhow!("Failed to run ostree gpg-sign"));
        } else {
            tracing::debug!(?sign_command, "Successfully ran signing command");
            tracing::info!(
                siguldry_key = ref_config.siguldry_key,
                "Successfully signed OSTree commit"
            );
        }

        let mut ref_command = tokio::process::Command::new("ostree");
        ref_command
            .kill_on_drop(true)
            .env_clear()
            .arg("refs")
            .arg(format!("--repo={}", ref_config.directory.display()))
            .arg("--force")
            .arg(format!("--create={}", ref_config.reference))
            .arg(&ostree.commitid);

        let output = ref_command
            .output()
            .await
            .context("Failed to spawn ostree; is it installed?")?;
        if !output.status.success() {
            tracing::error!(
                exit_code = ?output.status.code(),
                stdout = %String::from_utf8_lossy(&output.stdout),
                stderr = %String::from_utf8_lossy(&output.stderr),
                "Signing command failed: '{ref_command:?}'",
            );

            crate::metrics_utils::ostree_failed().increment(1);
            return Err(anyhow::anyhow!("Failed to run ostree gpg-sign"));
        }
        tracing::debug!(?ref_command, "Successfully ran reference update command");
        tracing::info!("Successfully updated OSTree reference to the signed commit");
        crate::metrics_utils::ostree_signed(ostree.reference).increment(1);

        Ok(())
    }
}
