// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Handler for CoreOS artifacts.
//!
//! This matches robosignatory, but is not ideal. It fetches artifacts from an S3 bucket, produces
//! an OpenPGP signature, and then pushes that signature to the S3 bucket.

use std::{
    collections::HashMap,
    ffi::CStr,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use pyo3::{
    Py, PyAny, Python,
    types::{PyAnyMethods, PyModule},
};
use serde::{Deserialize, Serialize};
use siguldry::protocol::Key;
use tokio::{io::AsyncWriteExt, sync::Semaphore};
use tracing::{Level, instrument};

use crate::{PgpConfig, config::Config};

const COREOS: &CStr = pyo3::ffi::c_str!(include_str!("coreos.py"));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ArtifactSign {
    /// The CoreOS stream this artifact belongs to, like "testing-devel"
    stream: String,
    /// Some CoreOS-generated UUID.
    request_id: String,
    /// The build version, like "44.20260521.20.1".
    build_id: String,
    /// The architecture of the artifact
    basearch: String,
    /// List of artifacts to sign.
    artifacts: Vec<Artifact>,
    /// This field is set by us in the response
    pub status: Option<String>,
    /// This field is set by us in the response
    #[serde(rename = "failure-message")]
    pub failure_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Artifact {
    // The digest algorithm and hex-encoded digest, separated by ":"
    //
    // For example, "sha256:e9c1786057d1efaf233fbffc2e464ce0803590efbb85023ef5a9d1124a7ae6e9".
    checksum: String,
    // The S3 URL for the artifact
    //
    // For example, "s3://fcos-builds/prod/signatures/oci/staging/testing-devel/4250693625056566298".
    file: String,
}

#[derive(Clone)]
pub(crate) struct CoreOsSigner {
    config: Arc<Config>,
    concurrency: Arc<Semaphore>,
    http_client: reqwest::Client,
    pgp_home: Arc<PgpConfig>,
    signing_keys: Arc<HashMap<String, Key>>,
    s3_client: Arc<Py<PyAny>>,
}

// Maps to the pre-existing AMQP response additions the robosignatory CoreOS handler has
pub(crate) enum Status {
    Failure(String),
    Success,
}

impl CoreOsSigner {
    pub fn new(
        config: Arc<Config>,
        concurrency: Arc<Semaphore>,
        http_client: reqwest::Client,
        pgp_home: Arc<PgpConfig>,
        signing_keys: Arc<HashMap<String, Key>>,
    ) -> anyhow::Result<Self> {
        // yes this is gross, but it's short term (I hope); we have no business writing
        // to an S3 bucket
        let s3_client = Python::attach(|py| {
            let module = PyModule::from_code(py, COREOS, c"coreos.py", c"")
                .context("Failed to initialize Python helper; is boto3 installed?")?;
            let client = module
                .getattr("S3Client")?
                .call(
                    (
                        &config.coreos.aws_region,
                        &config.coreos.aws_bucket,
                        &config.coreos.aws_access_key,
                        &config.coreos.aws_access_secret,
                    ),
                    None,
                )
                .context("Failed to initialize S3Client")
                .map(|obj| Arc::new(obj.unbind()))?;
            Ok::<_, anyhow::Error>(client)
        })?;

        Ok(Self {
            config,
            concurrency,
            http_client,
            pgp_home,
            signing_keys,
            s3_client,
        })
    }

    #[instrument(skip_all, err(level = Level::WARN), fields(build.id = request.build_id, build.stream = request.stream, build.arch = request.basearch))]
    pub async fn sign(&self, request: ArtifactSign) -> anyhow::Result<Status> {
        // Find the proper signing key
        let build_major = match request
            .build_id
            .split('.')
            .next()
            .map(|v| v.parse::<usize>())
        {
            Some(Ok(version)) => version,
            Some(Err(error)) => {
                tracing::error!(
                    ?error,
                    "Request included a build ID that doesn't start with a valid integer"
                );
                return Ok(Status::Failure(
                    "Request included a build ID that doesn't start with a valid integer"
                        .to_string(),
                ));
            }
            None => {
                tracing::error!("Request included a build ID that is not in the expected format");
                return Ok(Status::Failure(
                    "Request included a build ID that is not in the expected format".to_string(),
                ));
            }
        };
        let key = if let Some(key) = self
            .config
            .coreos
            .keys
            .iter()
            .find(|key| key.build_version == build_major)
        {
            key
        } else {
            tracing::error!(
                version = build_major,
                "The request was for a build version that isn't configured to be signed"
            );
            return Err(anyhow::anyhow!(
                "Missing signing key configuration for CoreOS {build_major} builds"
            ));
        };
        let siguldry_key = if let Some(k) = self.signing_keys.get(&key.siguldry_key) {
            k
        } else {
            tracing::error!(
                ?key,
                "The configured signing key doesn't exist in siguldry, or isn't accessible to the user"
            );
            return Err(anyhow::anyhow!(
                "User cannot access signing key for CoreOS {build_major} builds"
            ));
        };
        let siguldry_cert = if let Some(cert) = siguldry_key
            .certificates
            .iter()
            .find(|cert| cert.name == key.siguldry_openpgp_cert)
        {
            cert
        } else {
            let available_certs = siguldry_key
                .certificates
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>();
            tracing::error!(
                requested_cert = key.siguldry_openpgp_cert,
                ?available_certs,
                "The configured signing certificate doesn't exist in Siguldry"
            );
            return Err(anyhow::anyhow!(
                "Missing certificate for CoreOS {build_major} builds"
            ));
        };
        let gpg_home = self
            .pgp_home
            .gpg_homedirs
            .get(&siguldry_cert.fingerprint)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "OpenPGP fingerprint {} missing from gpg homedirs!",
                    siguldry_cert.fingerprint
                )
            })?
            .to_owned();

        let expected_prefix = format!("s3://{}/", self.config.coreos.aws_bucket);
        let base_url =
            reqwest::Url::parse("https://s3.amazonaws.com/").expect("Set a valid base URL");
        for artifact in request.artifacts {
            // Check message validity
            let (digest_algorithm, digest) = if let Some(split) = artifact.checksum.split_once(':')
            {
                split
            } else {
                tracing::error!(
                    artifact.checksum,
                    "Checksum should be in the format algo:hex; skipping request!"
                );
                return Ok(Status::Failure(
                    "Checksum should be in the format algo:hex; skipping request!".to_string(),
                ));
            };
            let algorithm = if let Some(algorithm) =
                openssl::hash::MessageDigest::from_name(digest_algorithm)
            {
                algorithm
            } else {
                tracing::error!(digest_algorithm, "Unsupported digest algorithm");
                return Ok(Status::Failure(format!(
                    "Unsupported digest algorithm '{digest_algorithm}'"
                )));
            };
            let mut hasher =
                openssl::hash::Hasher::new(algorithm).context("Failed to create openssl hasher")?;
            let expected_digest = match hex::decode(digest) {
                Ok(digest) => digest,
                Err(error) => {
                    tracing::error!(
                        ?error,
                        "Message digest was not a hex string; skipping request"
                    );
                    return Ok(Status::Failure(
                        "Message digest was not a hex string; skipping request".to_string(),
                    ));
                }
            };
            let path = if let Some(path) = artifact.file.strip_prefix(&expected_prefix) {
                path
            } else {
                tracing::error!(
                    expected_prefix,
                    artifact.file,
                    "Requested file was not in the expected AWS bucket"
                );
                return Ok(Status::Failure(
                    "Requested file was not in the expected AWS bucket".to_string(),
                ));
            };

            // Download the thingy
            let mut url = base_url.clone();
            url.set_path(format!("{}/{path}", self.config.coreos.aws_bucket).as_str());
            let signing_permit = self
                .concurrency
                .acquire()
                .await
                .context("Concurrency semaphore is closed")?;
            let sign_start_time = Instant::now();
            tracing::debug!(?url, "Attempting to download artifact");
            let mut response = self
                .http_client
                .get(url.clone())
                .send()
                .await?
                .error_for_status()?;

            // Spawn the signing command, streaming the downloaded bytes to its stdin.
            let mut command = match self.config.coreos.signing_tool {
                crate::config::SigningTool::Sq => {
                    let mut command = tokio::process::Command::new("sq");
                    command
                        .kill_on_drop(true)
                        .env_clear()
                        .env("SEQUOIA_HOME", &self.pgp_home.sq_homedir)
                        .arg("--batch")
                        .arg("sign")
                        .arg("--binary")
                        .arg("--signature-file")
                        .arg("-")
                        .arg(format!("--signer={}", siguldry_cert.fingerprint));
                    command
                }
                crate::config::SigningTool::Gpg => {
                    let mut command = tokio::process::Command::new("gpg");
                    command
                        .kill_on_drop(true)
                        .env_clear()
                        .env("GNUPGHOME", &gpg_home)
                        .env("SEQUOIA_HOME", &self.pgp_home.sq_homedir)
                        .arg("--batch")
                        .arg("--pinentry-mode cancel")
                        .arg("--detach-sign")
                        .arg("--output")
                        .arg("-");
                    command
                }
            };
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command
                .spawn()
                .context("Failed to spawn signing command; make sure gpg/sq is installed")?;
            let mut stdin = child
                .stdin
                .take()
                .expect("stdin must be configured as piped");

            let stream_result = tokio::spawn(async move {
                // More than enough for streaming to stdin; the HTTP client has a global read
                // timeout and doesn't need to be wrapped in a timeout here.
                let write_timeout = Duration::from_secs(10);
                while let Some(chunk) = response.chunk().await? {
                    let chunk_size = chunk.len();
                    tracing::trace!(chunk_size, "Streaming chunk to signing command");
                    tokio::time::timeout(write_timeout, stdin.write_all(&chunk))
                        .await
                        .context("Timed out writing to signing tool stdin")?
                        .context("IO error writing to signing tool stdin")?;
                    hasher.update(&chunk)?;
                }
                tokio::time::timeout(write_timeout, stdin.shutdown())
                    .await
                    .context("Timed out flushing stdin")??;
                let digest = hasher
                    .finish()
                    .context("Failed to complete message digest")?;
                Ok::<_, anyhow::Error>(digest)
            });

            let (download_task, output_task) =
                tokio::join!(stream_result, child.wait_with_output());
            let output = output_task.context("Failed to wait for the child process output")?;
            if !output.status.success() {
                tracing::error!(
                    exit_code = ?output.status.code(),
                    stdout = %String::from_utf8_lossy(&output.stdout),
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "Signing command failed: '{command:?}'",
                );
                return Err(anyhow::anyhow!("Failed to run signing command"));
            }
            tracing::debug!(
                signing_command = ?command,
                "Successfully ran signing command"
            );
            drop(signing_permit);

            // Since we're streaming into the signing tool and not buffering anything,
            // this is where we confirm the file matches the advertised checksum.
            // If the digest doesn't match, we discard the signature and try again later.
            let actual_digest = download_task
                .context("Failed to join the task writing to stdin")?
                .context("Failed to download and digest file")?;
            if expected_digest.as_slice() != actual_digest.as_ref() {
                tracing::error!(
                    artifact.checksum,
                    actual_digest = hex::encode(actual_digest),
                    "Artifact checksum mismatch"
                );
                return Err(anyhow::anyhow!("Artifact checksum mismatch"));
            } else {
                tracing::info!(
                    artifact.checksum,
                    artifact.file,
                    "Successfully signed artifact"
                );
                let signature = output.stdout;
                let s3_client = Arc::clone(&self.s3_client);

                // If uploading fails, it should return an error and we'll retry later.
                tokio::task::spawn_blocking(move || {
                    Python::attach(|py| {
                        let client = s3_client.bind(py);
                        client
                            .call_method1("upload", ("key", signature))
                            .context("Failed to upload signature to S3 bucket")?;

                        Ok::<_, anyhow::Error>(())
                    })
                })
                .await
                .context("Thread calling Python S3Client panicked")??;
                crate::metrics_utils::coreos_sign_time()
                    .record(sign_start_time.elapsed().as_secs_f64());
                crate::metrics_utils::coreos_artifacts_signed().increment(1);
            }
        }

        Ok(Status::Success)
    }
}
