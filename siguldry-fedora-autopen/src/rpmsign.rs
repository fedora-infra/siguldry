// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Handler for RPM signing.

use std::{
    collections::HashMap, fs::Permissions, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc,
};

use anyhow::Context;
use openssl::hash::{Hasher, MessageDigest};
use serde::{Deserialize, Serialize};
use siguldry::protocol::{Certificate, Key};
use tokio::{
    io::{AsyncWriteExt, BufWriter},
    process::Command,
    sync::Semaphore,
};
use tracing::{Instrument, Level, instrument};
use uuid::Uuid;

use crate::{
    PgpConfig,
    config::{Config, SigningTool},
    koji::{KojiHandle, KojiOps, Rpm},
};

const MB: usize = 1024 * 1024;

/// Derive the Koji "sigkey" from the signing certificate
///
/// Koji identifies signing keys by the last 4 bytes of the OpenPGP Key ID, hex-encoded,
/// which is just the last 8 characters of the fingerprint.
fn koji_sigkey(cert: &Certificate) -> String {
    cert.fingerprint
        .chars()
        .skip(cert.fingerprint.chars().count() - 8)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// This is the koji_fedoramessaging.tag.TagV1 schema sent by Koji.
///
/// This message is emitted when Koji tags a build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BuildsysTag {
    /// The build ID
    build_id: i64,
    /// The package name
    name: String,
    /// The tag ID
    tag_id: i64,
    /// Distinguish between messages from primary and secondary koji
    instance: String,
    /// Name of the tag, if it has one.
    ///
    /// The schema indicates this can be null, but since we require a tag
    /// name to operate, this isn't an optional field.
    tag: String,
    /// The name of the user that triggered the build.
    user: String,
    /// The version of the build.
    version: String,
    /// The name of the package owner.
    owner: String,
    /// The release number of the package.
    release: String,
}

#[derive(Clone)]
pub struct KojiSigner<K: KojiOps = KojiHandle> {
    config: Arc<Config>,
    pgp_home: Arc<PgpConfig>,
    signing_keys: Arc<HashMap<String, Key>>,
    http_client: reqwest::Client,
    koji: K,
    concurrency: Arc<Semaphore>,
    storage_limit: Option<Arc<Semaphore>>,
}

impl<K: KojiOps> KojiSigner<K> {
    pub fn new(
        config: Arc<Config>,
        concurrency: Arc<Semaphore>,
        pgp_home: Arc<PgpConfig>,
        signing_keys: Arc<HashMap<String, Key>>,
        http_client: reqwest::Client,
        koji: K,
    ) -> Self {
        let storage_limit = config
            .rpm
            .storage_limit_mb
            .map(Semaphore::new)
            .map(Arc::new);
        Self {
            config,
            pgp_home,
            signing_keys,
            http_client,
            koji,
            concurrency,
            storage_limit,
        }
    }

    #[instrument(skip(self, build), err(level = Level::WARN), fields(build.id = build.build_id, tag.id = build.tag_id))]
    pub async fn sign(&self, build: BuildsysTag) -> anyhow::Result<()> {
        // Skip any Koji messages from instances other than the configured one, and if the
        // message references a tag we aren't configured for.
        if self.config.koji.instance != build.instance {
            tracing::info!(
                "Skipping message from Koji instance {}; we only sign {}",
                &build.instance,
                &self.config.koji.instance
            );
            return Ok(());
        }
        if self.config.koji.match_tag(&build.tag).is_none() {
            tracing::info!(build.tag, "Build tag is not configured for auto-signing");
            return Ok(());
        }

        let koji_build = self.koji.build_info(build.build_id).await?;
        let latest_event = if let Some(event) = koji_build.active_tag() {
            event
        } else {
            tracing::error!("The tag_listing for the build contained no events");
            // TODO: is this normal, do we retry or skip?
            return Err(anyhow::anyhow!("Failed to find tag history for the build"));
        };

        // Look up the tag rule for this event. If none matches, this isn't a
        // build we autosign. We've checked above against the tag in the message, but
        // we double check here after querying Koji on the current state of the build.
        let (tag, tag_to) =
            if let Some(matched) = self.config.koji.match_tag(&latest_event.tag_name) {
                matched
            } else {
                tracing::error!(
                    build.tag,
                    latest_event.tag_name,
                    "The build's latest event tag is not configured for auto-signing"
                );
                return Ok(());
            };
        let tag_from = latest_event.tag_name.clone();
        if !tag
            .trusted_taggers
            .iter()
            .any(|trusted| trusted == &latest_event.creator_name)
        {
            tracing::warn!(
                trusted_taggers=?tag.trusted_taggers,
                tagger=latest_event.creator_name,
                "Build tag is configure for auto-signing, but build was tagged by an untrusted user: skipping"
            );
            return Ok(());
        }

        tracing::info!(
            build.name,
            build.version,
            build.release,
            rpms_in_build = koji_build.rpms.len(),
            tag_event_creator = latest_event.creator_name,
            "Signing build {} tagged into tag {} on koji instance {}",
            koji_build.id,
            build.tag,
            build.instance
        );

        // All permissions checks are done; set up the signing environment
        let temp_dir_root = std::env::temp_dir();
        let temp_dir = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .prefix(&format!("rpm-build-{}-", build.build_id))
            .rand_bytes(16)
            .tempdir_in(&temp_dir_root)
            .inspect_err(|error| {
                tracing::error!(
                    ?error,
                    "Failed to make temporary directory inside {temp_dir_root:?}"
                );
            })?;

        let cert = self
            .signing_keys
            .get(&tag.siguldry_key)
            .and_then(|key| {
                key.certificates
                    .iter()
                    .find(|cert| cert.name == tag.siguldry_openpgp_cert)
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to find the OpenPGP certificate {} for signing key {}",
                    tag.siguldry_openpgp_cert,
                    tag.siguldry_key
                )
            })?;

        let sigkey = koji_sigkey(cert);
        let rpm_ids = koji_build.rpms.iter().map(|r| r.id).collect::<Vec<_>>();
        let mut signing_tasks = tokio::task::JoinSet::new();
        for rpm in koji_build.rpms.into_iter().filter(|rpm| {
            if rpm.existing_sigkeys.contains(&sigkey) {
                // In the event this build has been partially signed, only process ones without
                // a signature from the configured key ID.
                tracing::debug!(
                    sigkey,
                    rpm.id,
                    rpm.draft,
                    rpm.name,
                    rpm.epoch,
                    rpm.version,
                    rpm.release,
                    "Skipping RPM since it's already been signed by this key"
                );
                false
            } else {
                true
            }
        }) {
            let task_signer = self.clone();
            let fingerprint = cert.fingerprint.clone();
            let target_dir = temp_dir.path().to_path_buf();
            let expected_sigkey = sigkey.clone();
            let file_signing_key = tag.file_signing_key.clone();
            let siguldry_key = tag.siguldry_key.clone();
            let gpg_home = self
                .pgp_home
                .gpg_homedirs
                .get(&fingerprint)
                .ok_or_else(|| {
                    anyhow::anyhow!("OpenPGP fingerprint {fingerprint} missing from gpg homedirs!")
                })?
                .to_owned();
            let ima_certificate = file_signing_key
                .as_ref()
                .map(|ima| {
                    self.signing_keys.get(&ima.siguldry_key).and_then(|k| {
                        k.certificates
                            .iter()
                            .find(|c| c.name == ima.siguldry_x509_cert)
                    })
                })
                .ok_or_else(|| anyhow::anyhow!("The referenced IMA key couldn't be found!"))?
                .cloned();

            if file_signing_key.is_some() && ima_certificate.is_none() {
                return Err(anyhow::anyhow!(
                    "The referenced IMA certificate couldn't be found!"
                ));
            }

            let rpm_size_in_mb = rpm.size >> 20;
            if let Some(storage_limit) = self.config.rpm.storage_limit_mb
                && rpm.size > (storage_limit * MB).try_into()?
            {
                return Err(anyhow::anyhow!(
                    "RPM is larger ({} MiB) than the configured storage limit ({} MiB) and cannot be signed",
                    rpm.size >> 20,
                    storage_limit
                ));
            }

            let rpm_span = tracing::info_span!("rpm", rpm.id);
            signing_tasks.spawn(
                async move {
                    // Hold the necessary permits until we've finished signing.
                    //
                    // We do this inside the spawned task so that each build gets its RPMs in line for permits
                    // around the same time. We may want to consider a different strategy in the future if we
                    // would prefer huge builds to be interleaved with other signing tasks.
                    //
                    // If storage limits are enforced, builds first acquire a concurrency permit and _then_ the
                    // required storage space. Because permits are given out in the order requested, small RPMs
                    // will stack up behind a huge RPM when storage is limited.
                    let signing_permit = task_signer.concurrency.acquire().await?;
                    let storage_permit = if let Some(storage_limit) = task_signer.storage_limit {
                        let permit_count = rpm_size_in_mb
                            .max(1)
                            .try_into()
                            .expect("RPMs larger than 4 PiB aren't supported");
                        let permit = storage_limit.acquire_many_owned(permit_count).await?;
                        Some(permit)
                    } else {
                        None
                    };
                    let _active_guard =
                        Gauge::increment(crate::metrics_utils::rpms_active(), 1_f64);
                    let path = download(&task_signer.http_client, target_dir, &rpm).await?;
                    let _storage_guard =
                        Gauge::from_gauge(crate::metrics_utils::rpms_storage(), rpm.size as f64);

                    let mut command = Command::new("rpmsign");
                    command
                        .kill_on_drop(true)
                        .env_clear()
                        .env("OPENSSL_CONF", &task_signer.pgp_home.openssl_config)
                        .env("GNUPGHOME", &gpg_home)
                        .env("SEQUOIA_HOME", &task_signer.pgp_home.sq_homedir)
                        .arg("--resign")
                        .arg(format!("--key-id={fingerprint}"));
                    match task_signer.config.rpm.signing_tool {
                        SigningTool::Sq => command.arg("--define").arg("_openpgp_sign sq"),
                        SigningTool::Gpg => command
                            .arg("--define")
                            .arg("_openpgp_sign gpg")
                            .arg("--define")
                            .arg("_gpg_sign_cmd_extra_args --batch --pinentry-mode cancel"),
                    };
                    if task_signer.config.rpm.with_rpmv4 {
                        command.arg("--rpmv4");
                    }
                    if let (Some(file_signing_key), Some(cert)) =
                        (&file_signing_key, &ima_certificate)
                    {
                        let cert = openssl::x509::X509::from_pem(cert.certificate.as_bytes())?;
                        let keyid = cert
                            .subject_key_id()
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "IMA certificate is missing a Subject Key Identifier extension"
                                )
                            })?
                            .as_slice()
                            .last_chunk::<4>()
                            .map(|b| u32::from_be_bytes(*b))
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "IMA certificate's Subject Key Identifier is too short"
                                )
                            })?;
                        command
                            .arg("--signfiles")
                            .arg("--fskpath")
                            .arg(format!(
                                "pkcs11:model=Siguldry;token={};type=private",
                                file_signing_key.siguldry_key
                            ))
                            .arg("--define")
                            .arg(format!("_file_signing_key_id {keyid}"));
                        tracing::debug!(
                            siguldry_key = file_signing_key.siguldry_key,
                            siguldry_cert = file_signing_key.siguldry_x509_cert,
                            ima_keyid = keyid,
                            "Signing RPM for IMA"
                        );
                    }
                    let sign_start_time = std::time::Instant::now();
                    let output = command
                        .arg(&path)
                        .output()
                        .await
                        .context("Failed to spawn rpmsign; is it installed?")?;
                    let sign_time = sign_start_time.elapsed();
                    crate::metrics_utils::rpms_sign_time().record(sign_time.as_secs() as f64);
                    drop(signing_permit);

                    if !output.status.success() {
                        tracing::error!(
                            exit_code = ?output.status.code(),
                            stdout = %String::from_utf8_lossy(&output.stdout),
                            stderr = %String::from_utf8_lossy(&output.stderr),
                            "Signing command failed: '{command:?}'",
                        );

                        return Err(anyhow::anyhow!("Failed to run rpmsign"));
                    } else {
                        tracing::debug!(
                            signing_command = ?command,
                            "Successfully ran signing command"
                        );
                        let siguldry_key_ima = file_signing_key
                            .as_ref()
                            .map(|ima| ima.siguldry_key.as_str());
                        tracing::info!(
                            rpm.id,
                            rpm.name,
                            rpm.version,
                            rpm.release,
                            siguldry_key,
                            siguldry_key_ima,
                            "Successfully signed RPM"
                        );
                    }

                    task_signer
                        .koji
                        .add_signature(rpm.id, expected_sigkey, path.clone())
                        .await?;

                    // We want to remove the file ASAP, rather than relying on the tempdir cleanup
                    // because we may be tracking storage.
                    let _ = tokio::fs::remove_file(path).await.inspect_err(|error| {
                        tracing::error!(?error, "Failed to remove RPM after signing");
                    });
                    drop(storage_permit);

                    Ok::<_, anyhow::Error>(())
                }
                .instrument(rpm_span),
            );
        }

        // Wait for all the signatures to complete and, if all succeed, move the build over.
        // In the event that some fail we return the error and retry later, we'll skip over
        // any RPM that has been signed by the requested key ID, so we'll keep making forward
        // progress.
        //
        // We use join_next() for more accurate metrics reporting over join_all()
        let mut rpm_failed = 0_u32;
        while let Some(task) = signing_tasks.join_next().await {
            match task {
                Ok(Ok(())) => {
                    tracing::trace!("RPM signing task joined successfully");
                    crate::metrics_utils::rpms_signed().increment(1);
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "RPM signing task failed");
                    crate::metrics_utils::rpms_failed().increment(1);
                    rpm_failed += 1;
                }
                Err(error) => {
                    tracing::error!(?error, "RPM signing task panicked!");
                    crate::metrics_utils::rpms_failed().increment(1);
                    rpm_failed += 1;
                }
            }
        }
        if rpm_failed > 0 {
            return Err(anyhow::anyhow!(
                "{} RPM signing tasks failed and will be retried later",
                rpm_failed
            ));
        }

        // Now that all signatures are uploaded, request Koji write out an RPM copy with the signature
        // We want to do this separately from the signing task so that if it fails, we don't resign
        // and attempt to upload another signature for the RPM.
        for id in rpm_ids {
            self.koji.write_signed_rpm(id, sigkey.clone()).await?;
        }

        tracing::info!(
            sigkey,
            tag_from,
            tag_to,
            "All RPMs successfully signed; sending build move request to Koji"
        );
        self.koji
            .move_build(build.build_id, sigkey, tag_from, tag_to)
            .await?;

        // This won't catch cleanup failures where the drop happens in prior error paths
        let path = temp_dir.path().display().to_string();
        if let Err(error) = temp_dir.close() {
            tracing::error!(
                ?error,
                path,
                "Temporary directory used for RPMs failed to clean up"
            );
        }

        Ok(())
    }
}

#[instrument(skip_all, err)]
async fn download(
    http_client: &reqwest::Client,
    dest_dir: PathBuf,
    rpm: &Rpm,
) -> anyhow::Result<PathBuf> {
    let url = reqwest::Url::parse(&rpm.url)?;
    // We don't have the RPM arch, and this seems like the easiest way to make a unique name
    let destination = dest_dir.join(Uuid::new_v4().to_string());

    tracing::debug!(path = url.path(), "Attempting to download RPM from Koji");

    // TODO: be more precise
    let mut response = http_client.get(url).send().await?.error_for_status()?;
    let content_length = response.content_length();
    tracing::debug!(content_length, rpm.size, "Response received");

    let file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&destination)
        .await?;
    let mut file = BufWriter::new(file);
    let mut bytes_written = 0;
    let artifact_size_gauge = crate::metrics_utils::rpms_storage();
    let mut digest = Hasher::new(MessageDigest::sha256())?;
    while let Some(chunk) = response.chunk().await? {
        let chunk_size = chunk.len();
        tracing::trace!(?destination, chunk_size, "Writing chunk to file");
        file.write_all(&chunk).await?;
        bytes_written += chunk_size;
        artifact_size_gauge.increment(chunk_size as f64);
        digest.update(&chunk)?;
    }
    file.shutdown().await?;
    drop(file);

    let expected_digest = hex::decode(&rpm.sha256sum)?;
    let actual_digest = digest.finish()?;
    let hex_checksum = hex::encode(actual_digest);
    if expected_digest.as_slice() != actual_digest.as_ref() {
        tracing::error!(
            expected_bytes = rpm.size,
            expected_checksum = rpm.sha256sum,
            actual_bytes = bytes_written,
            actual_checksum = hex_checksum,
            "RPM checksum mismatch"
        );
        return Err(anyhow::anyhow!(
            "Downloaded RPM checksum did not match advertised checksum"
        ));
    }
    tracing::info!(
        bytes_written,
        sha256sum = hex_checksum,
        rpm.name,
        rpm.epoch,
        rpm.version,
        rpm.release,
        "Completed RPM download"
    );

    Ok(destination)
}

// Wrapper that decrements on drop.
struct Gauge {
    inner: metrics::Gauge,
    amount: f64,
}

impl Gauge {
    /// Increment the gauge by the given amount, then decrement by that amount on drop.
    fn increment(inner: metrics::Gauge, amount: f64) -> Self {
        inner.increment(amount);
        Self { inner, amount }
    }

    /// Decrement the given amount from the gauge on drop.
    fn from_gauge(inner: metrics::Gauge, amount: f64) -> Self {
        Self { inner, amount }
    }
}

impl Drop for Gauge {
    fn drop(&mut self) {
        self.inner.decrement(self.amount);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use tokio::sync::{
        Mutex,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    };

    use siguldry::protocol::{Certificate, CertificateType, KeyAlgorithm};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use crate::{
        config::Tag,
        koji::{Build, TagEvent},
    };

    use super::*;

    /// Build a `signing_keys` map containing the `demo` key referenced by [`sample_tag`].
    fn demo_signing_keys() -> HashMap<String, Key> {
        let mut keys = HashMap::new();
        keys.insert(
            "demo".to_string(),
            Key {
                name: "demo".to_string(),
                key_algorithm: KeyAlgorithm::default(),
                handle: "demo-handle".to_string(),
                public_key: String::new(),
                certificates: vec![Certificate {
                    certificate: String::new(),
                    certificate_type: CertificateType::Pgp,
                    fingerprint: "DEADBEEF".to_string(),
                    name: "demo-openpgp".to_string(),
                }],
            },
        );
        keys
    }

    fn signer_with_keys(
        config: Config,
        koji: StubKoji,
        signing_keys: HashMap<String, Key>,
    ) -> KojiSigner<StubKoji> {
        let http_client = reqwest::Client::builder().build().unwrap();
        let pgp_home = PgpConfig {
            openssl_config: PathBuf::new(),
            sq_homedir: PathBuf::new(),
            gpg_homedirs: HashMap::new(),
        };
        KojiSigner::new(
            Arc::new(config),
            Arc::new(Semaphore::new(4)),
            Arc::new(pgp_home),
            Arc::new(signing_keys),
            http_client,
            koji,
        )
    }

    fn sample_tag(from: &str, to: &str) -> Tag {
        Tag {
            from: from.to_string(),
            to: to.to_string(),
            siguldry_key: "demo".to_string(),
            siguldry_openpgp_cert: "demo-openpgp".to_string(),
            file_signing_key: None,
            trusted_taggers: vec!["bodhi".to_string()],
            sidetags: None,
        }
    }

    #[test]
    fn active_tag_returns_none_for_empty_history() {
        let build = Build::default();
        assert!(build.tag_history.is_empty());
        assert!(build.active_tag().is_none());
    }

    #[test]
    fn active_tag_returns_event_with_largest_create_event() {
        let build = Build {
            tag_history: vec![
                TagEvent {
                    create_event: 1,
                    creator_name: "nobody".into(),
                    tag_name: "old".into(),
                },
                TagEvent {
                    create_event: 5,
                    creator_name: "somebody".into(),
                    tag_name: "newest".into(),
                },
                TagEvent {
                    create_event: 3,
                    creator_name: "everybody".into(),
                    tag_name: "middle".into(),
                },
            ],
            ..Default::default()
        };

        let active = build.active_tag().unwrap();
        assert_eq!(active.create_event, 5);
        assert_eq!(active.tag_name, "newest");
        assert_eq!(active.creator_name, "somebody");
    }

    fn sample_build_msg(instance: &str) -> BuildsysTag {
        BuildsysTag {
            build_id: 0,
            name: "pkg".into(),
            tag_id: 1,
            instance: instance.into(),
            tag: "f45-signing-pending".into(),
            user: "bodhi".into(),
            version: "1".into(),
            owner: "owner".into(),
            release: "1.fc45".into(),
        }
    }

    /// A mock [`KojiOps`] implementation that returns a fake build and records requests.
    #[derive(Clone)]
    struct StubKoji {
        build: Build,
        signatures: Arc<UnboundedReceiver<(i64, String, PathBuf)>>,
        signature_sender: UnboundedSender<(i64, String, PathBuf)>,
        #[allow(clippy::type_complexity)]
        move_build: Arc<Mutex<UnboundedReceiver<(i64, String, String, String)>>>,
        move_build_sender: UnboundedSender<(i64, String, String, String)>,
    }

    impl StubKoji {
        pub fn new(build: Build) -> Self {
            let (signature_sender, signatures) = mpsc::unbounded_channel();
            let (move_build_sender, move_build) = mpsc::unbounded_channel();
            Self {
                build,
                signatures: Arc::new(signatures),
                signature_sender,
                move_build: Arc::new(Mutex::new(move_build)),
                move_build_sender,
            }
        }
    }

    impl KojiOps for StubKoji {
        async fn build_info(&self, build_id: i64) -> anyhow::Result<Build> {
            assert_eq!(self.build.id, build_id);
            Ok(self.build.clone())
        }

        async fn add_signature(
            &self,
            rpm_id: i64,
            expected_sigkey: String,
            signed_package: PathBuf,
        ) -> anyhow::Result<()> {
            self.signature_sender
                .send((rpm_id, expected_sigkey, signed_package))?;
            Ok(())
        }

        async fn write_signed_rpm(&self, rpm_id: i64, _sigkey: String) -> anyhow::Result<()> {
            assert!(
                self.build
                    .rpms
                    .iter()
                    .find(|rpm| rpm.id == rpm_id)
                    .is_some()
            );
            Ok(())
        }

        async fn move_build(
            &self,
            build_id: i64,
            expected_sigkey: String,
            tag_from: String,
            tag_to: String,
        ) -> anyhow::Result<i64> {
            assert_eq!(self.build.id, build_id);
            self.move_build_sender
                .send((build_id, expected_sigkey, tag_from, tag_to))?;
            Ok(1)
        }
    }

    fn keyless_signer(config: Config, koji: StubKoji) -> KojiSigner<StubKoji> {
        let http_client = reqwest::Client::builder().build().unwrap();
        let pgp_home = PgpConfig {
            openssl_config: PathBuf::new(),
            sq_homedir: PathBuf::new(),
            gpg_homedirs: HashMap::new(),
        };
        KojiSigner::new(
            Arc::new(config),
            Arc::new(Semaphore::new(4)),
            Arc::new(pgp_home),
            Arc::new(HashMap::new()),
            http_client,
            koji,
        )
    }

    #[tokio::test]
    async fn sign_returns_ok_when_no_tag_rule_matches() {
        let mut config = Config::default();
        config.koji.instance = "primary".into();
        config.koji.tags = vec![sample_tag("some-other-tag", "some-other-dest")];
        let stub = StubKoji::new(Build {
            tag_history: vec![TagEvent {
                create_event: 1,
                creator_name: "bodhi".into(),
                tag_name: "f45-signing-pending".into(),
            }],
            ..Default::default()
        });
        let signer = keyless_signer(config, stub);
        signer.sign(sample_build_msg("primary")).await.unwrap();
        assert!(signer.koji.signatures.is_empty());
    }

    /// A missing signing key in the lookup table results in a useful error message
    #[tokio::test]
    async fn sign_is_missing_key() {
        let mut config = Config::default();
        config.koji.instance = "primary".into();
        config.koji.tags = vec![sample_tag("f45-signing-pending", "f45-testing-pending")];
        let stub = StubKoji::new(Build {
            tag_history: vec![TagEvent {
                create_event: 1,
                creator_name: "bodhi".into(),
                tag_name: "f45-signing-pending".into(),
            }],
            ..Default::default()
        });
        let signer = keyless_signer(config, stub);
        let result = signer.sign(sample_build_msg("primary")).await.unwrap_err();
        assert_eq!(
            format!("{result}"),
            "Failed to find the OpenPGP certificate demo-openpgp for signing key demo"
        );
    }

    /// A bit of a weird case, but a build with no RPMs shouldn't crash
    #[tokio::test]
    async fn sign_no_rpms() {
        let mut config = Config::default();
        config.koji.instance = "primary".into();
        config.koji.tags = vec![sample_tag("f45-signing-pending", "f45-testing-pending")];
        let stub = StubKoji::new(Build {
            tag_history: vec![TagEvent {
                create_event: 1,
                creator_name: "bodhi".into(),
                tag_name: "f45-signing-pending".into(),
            }],
            ..Default::default()
        });
        let signer = signer_with_keys(config, stub, demo_signing_keys());
        signer.sign(sample_build_msg("primary")).await.unwrap();
        assert!(signer.koji.signatures.is_empty());
        let (_build_id, _sigkey, from, to) =
            signer.koji.move_build.lock().await.recv().await.unwrap();

        assert_eq!(from, "f45-signing-pending");
        assert_eq!(to, "f45-testing-pending");
    }

    fn rpm_for(url: String, body: &[u8]) -> Rpm {
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(body).unwrap();
        let sha256sum = hex::encode(hasher.finish().unwrap());

        Rpm {
            id: 1,
            draft: false,
            epoch: None,
            name: "hello".into(),
            version: "1".into(),
            release: "1.fc45".into(),
            size: body.len() as u64,
            url,
            sha256sum,
            existing_sigkeys: vec![],
        }
    }

    #[tokio::test]
    async fn download_succeeds() -> anyhow::Result<()> {
        let body = b"hello, world".to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/hello.rpm"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let temp_dir = tempfile::tempdir()?;
        let client = reqwest::Client::builder().build()?;
        let rpm = rpm_for(format!("{}/hello.rpm", server.uri()), &body);

        let path = download(&client, temp_dir.path().to_path_buf(), &rpm).await?;

        assert!(path.exists());
        assert!(path.starts_with(temp_dir.path()));
        let metadata = tokio::fs::metadata(&path).await?;
        assert_eq!(metadata.mode() & 0o777, 0o600);
        let written = tokio::fs::read(&path).await?;
        assert_eq!(written, body);

        Ok(())
    }

    #[tokio::test]
    async fn download_checksum_mismatch_errors() -> anyhow::Result<()> {
        let body = b"hello, world".to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/hello.rpm"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let temp_dir = tempfile::tempdir()?;
        let client = reqwest::Client::builder().build()?;
        let mut rpm = rpm_for(format!("{}/hello.rpm", server.uri()), &body);
        rpm.sha256sum = "42".repeat(32);

        let error = download(&client, temp_dir.path().to_path_buf(), &rpm)
            .await
            .unwrap_err();
        assert!(
            format!("{error}")
                .contains("Downloaded RPM checksum did not match advertised checksum"),
            "unexpected error: {error}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn download_http_5xx_errors() {
        let body = b"hello, world".to_vec();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/hello.rpm"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let client = reqwest::Client::builder().build().unwrap();
        let rpm = rpm_for(format!("{}/hello.rpm", server.uri()), &body);

        let _error = download(&client, temp_dir.path().to_path_buf(), &rpm)
            .await
            .unwrap_err();
    }
}
