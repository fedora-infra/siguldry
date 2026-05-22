// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{
    collections::HashMap,
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::exit,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use siguldry::protocol::{CertificateType, Key};
use tokio::{
    io::AsyncWriteExt,
    signal::unix::{SignalKind, signal},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt};

mod amqp;
mod cli;
mod config;
mod coreos;
mod koji;
mod metrics_utils;
mod ostree;
mod rpmsign;

// The path, relative to $CONFIGURATION_DIRECTORY, of the default config file location.
const DEFAULT_CONFIG: &str = "fedora-autopen.toml";
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = cli::Cli::parse();

    let log_filter = EnvFilter::builder().parse(&opts.log_filter).context(
        "SIGULDRY_FEDORA_AUTOPEN_LOG contains an invalid log directive; refer to \
            https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/\
            filter/struct.EnvFilter.html#directives for format details.",
    )?;
    let stderr_layer = tracing_subscriber::fmt::layer()
        .without_time()
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");

    let config: config::Config = config::load_config(opts.config, &PathBuf::from(DEFAULT_CONFIG))?;

    // Spawns the HTTP server onto the current Tokio runtime.
    if let Some(metrics) = &config.metrics {
        crate::metrics_utils::init(metrics)?;
    }

    let halt_token = CancellationToken::new();
    tokio::spawn(signal_handler(halt_token.clone()));

    let temp_dir_root = std::env::temp_dir();
    let pgp_dir = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .prefix("pgp-keys-")
        .tempdir_in(&temp_dir_root)
        .inspect_err(|error| {
            tracing::error!(
                ?error,
                "Failed to make temporary directory inside {temp_dir_root:?}"
            );
        })?;

    let signing_keys = Arc::new(
        signing_keys(&config)
            .await
            .context("Failed to load available signing keys from Siguldry")?,
    );
    let key_list = signing_keys.values().collect::<Vec<_>>();
    let pgp_home = setup_pgp(&config, pgp_dir.path(), key_list.as_slice())
        .await
        .context("Failed to load OpenPGP certificates")?;
    drop(key_list);
    let pgp_home = Arc::new(pgp_home);
    let config = Arc::new(config);

    match opts.command {
        cli::Command::Consume => run_consumer(config, pgp_home, signing_keys, halt_token).await,
        cli::Command::Process { file } => {
            process_message(config, pgp_home, signing_keys, file).await
        }
    }
}

async fn run_consumer(
    config: Arc<config::Config>,
    pgp_home: Arc<PgpConfig>,
    signing_keys: Arc<HashMap<String, Key>>,
    halt_token: CancellationToken,
) -> anyhow::Result<()> {
    let koji_actor = koji::KojiActor::new(config.koji.clone())?;

    let koji_url = reqwest::Url::parse(&config.koji.url)?;
    let koji_host = koji_url.host_str().unwrap().to_string();
    let retry_policy = reqwest::retry::for_host(koji_host).classify_fn(|request| {
        if request.error().is_some() {
            request.retryable()
        } else {
            match request.status() {
                Some(status)
                    if status.is_server_error() && request.method() == reqwest::Method::GET =>
                {
                    request.retryable()
                }
                _ => request.success(),
            }
        }
    });
    let http_client = reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(30 * 60))
        .pool_idle_timeout(Duration::from_secs(120))
        .pool_max_idle_per_host(128)
        .user_agent(USER_AGENT)
        .retry(retry_policy)
        .build()?;

    loop {
        if let Err(error) = amqp::connect_and_consume(
            config.clone(),
            http_client.clone(),
            pgp_home.clone(),
            signing_keys.clone(),
            koji_actor.handle(),
            halt_token.clone(),
        )
        .await
        {
            tracing::warn!(?error, "Restarting AMQP broker connection in 15 seconds...");
            tokio::time::sleep(Duration::from_secs(15)).await;
        } else {
            tracing::info!("Consumer completed");
            break;
        }

        crate::metrics_utils::amqp_reconnects().increment(1);
    }

    koji_actor.shutdown()?;

    Ok(())
}

// Process a JSON-formatted AMQP-like message
async fn process_message(
    config: Arc<config::Config>,
    pgp_home: Arc<PgpConfig>,
    signing_keys: Arc<HashMap<String, Key>>,
    file: PathBuf,
) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;

    let bytes = if file.as_os_str() == "-" {
        let mut buf = Vec::new();
        tokio::io::stdin()
            .read_to_end(&mut buf)
            .await
            .context("Failed to read message JSON from stdin")?;
        buf
    } else {
        tokio::fs::read(&file)
            .await
            .with_context(|| format!("Failed to read message JSON from {}", file.display()))?
    };

    #[derive(serde::Deserialize)]
    struct Message {
        topic: String,
        body: serde_json::Value,
    }

    let message: Message =
        serde_json::from_slice(&bytes).context("Message JSON did not match the expected format")?;
    let topic = message.topic.as_str();
    tracing::info!(topic, "Processing single message from file");

    if topic.ends_with(".pungi.compose.ostree") {
        let event: ostree::OstreeCompose = serde_json::from_value(message.body)
            .context("Message body is not a valid OSTree compose payload")?;
        let signer =
            ostree::OstreeSigner::new(config, Arc::new(Semaphore::new(16)), pgp_home, signing_keys);
        signer
            .sign(event)
            .await
            .with_context(|| format!("Failed to sign OSTree compose for topic {topic}"))?;
        Ok(())
    } else {
        Err(anyhow::anyhow!("Unsupported topic {topic}"))
    }
}

/// Check that all keys in the configuration are present on the signing
/// server and accessible to the user.
///
/// Return the associated public keys, X.509 certificates, and OpenPGP certificates
/// as they are needed for various signing operations.
#[instrument(skip_all)]
async fn signing_keys(config: &config::Config) -> anyhow::Result<HashMap<String, Key>> {
    let socket = config.siguldry.client_proxy_socket.clone();
    let keys = tokio::task::spawn_blocking(move || {
        let mut client = siguldry::client::ProxyClient::new(socket)
            .context("Failed to create a connection to the Siguldry client proxy")?;
        let keys = client
            .list_keys()
            .context("Failed to list available keys in Siguldry via the client proxy")?;

        for key in keys.iter() {
            let is_unlocked = client
                .is_unlocked(key.name.clone())
                .with_context(|| format!("Failed to check if the {} key is unlocked", &key.name))?;
            if is_unlocked {
                tracing::info!(
                    key.name,
                    "Signing key is unlocked by the siguldry-client-proxy"
                );
            } else {
                tracing::debug!(
                    key.name,
                    "Siguldry client has access to a signing key, but it is not unlocked"
                );
            }
        }
        client.shutdown()?;
        Ok::<_, anyhow::Error>(keys)
    })
    .await??;

    // Key names are unique and it's more convenient to work from a map
    let keys = keys
        .into_iter()
        .map(|k| (k.name.clone(), k))
        .collect::<HashMap<_, _>>();

    // Collect all known missing keys and certs before reporting the error
    let mut missing_keys = vec![];
    let mut missing_certs = vec![];

    // Check RPM signing keys
    for tag in config.koji.tags.iter() {
        if let Some(key) = keys.get(&tag.siguldry_key) {
            if let Some(cert) = key
                .certificates
                .iter()
                .find(|c| c.name == tag.siguldry_openpgp_cert)
            {
                if !matches!(cert.certificate_type, CertificateType::Pgp) {
                    tracing::error!(key.name, cert.name, ?cert.certificate_type, "The certificate referenced by 'siguldry_openpgp_cert' must be an OpenPGP certificate");
                    missing_certs.push(tag.siguldry_openpgp_cert.clone());
                }
            } else {
                tracing::error!(
                    tag.from,
                    tag.to,
                    key.name,
                    tag.siguldry_openpgp_cert,
                    "The key does not have a certificate with that name"
                );
                missing_certs.push(tag.siguldry_openpgp_cert.clone());
            }
        } else {
            tracing::error!(
                tag.from,
                tag.to,
                tag.siguldry_key,
                "The key referenced cannot be found in Siguldry (does this user have access?)"
            );
            missing_keys.push(tag.siguldry_key.clone());
        }

        // Check IMA keys
        if let Some(file_signing_key) = &tag.file_signing_key {
            tracing::debug!(?file_signing_key, "Checking validity of IMA key");
            if let Some(key) = keys.get(&file_signing_key.siguldry_key) {
                if let Some(cert) = key
                    .certificates
                    .iter()
                    .find(|c| c.name == file_signing_key.siguldry_x509_cert)
                {
                    if !matches!(cert.certificate_type, CertificateType::X509) {
                        tracing::error!(key.name, cert.name, ?cert.certificate_type, "The certificate referenced by 'siguldry_x509_cert' must be an X.509 certificate");
                        missing_certs.push(file_signing_key.siguldry_x509_cert.clone());
                    }
                } else {
                    let available_certs = key
                        .certificates
                        .iter()
                        .map(|c| c.name.as_str())
                        .collect::<Vec<_>>();
                    tracing::error!(
                        tag.from,
                        tag.to,
                        ?available_certs,
                        file_signing_key.siguldry_key,
                        file_signing_key.siguldry_x509_cert,
                        "The key does not have a certificate with that name"
                    );
                    missing_certs.push(file_signing_key.siguldry_x509_cert.clone());
                }
            } else {
                tracing::error!(
                    tag.from,
                    tag.to,
                    tag.siguldry_key,
                    "The key referenced cannot be found in Siguldry (does this user have access?)"
                );
                missing_keys.push(tag.siguldry_key.clone());
            }
        }
    }

    Ok(keys)
}

#[derive(Clone)]
struct PgpConfig {
    openssl_config: PathBuf,
    sq_homedir: PathBuf,
    // Maps certificate fingerprints to their homedirs
    gpg_homedirs: HashMap<String, PathBuf>,
}

async fn setup_pgp(
    config: &config::Config,
    homedir: &Path,
    keys: &[&Key],
) -> anyhow::Result<PgpConfig> {
    // For IMA we need to configure OpenSSL to load the PKCS #11 provider
    let openssl_config = homedir.join("openssl.cnf");
    let mut openssl_cnf = tokio::fs::OpenOptions::new()
        .mode(0o600)
        .create_new(true)
        .write(true)
        .open(&openssl_config)
        .await?;

    openssl_cnf
        .write_all(
            "
openssl_conf = openssl_init

[openssl_init]
providers = providers

[providers]
default = default_provider
pkcs11 = pkcs11_provider

[default_provider]
activate = 1

[pkcs11_provider]
module = /usr/lib64/ossl-modules/pkcs11.so
activate = 1\n"
                .as_bytes(),
        )
        .await?;

    let pgp_certificates = homedir.join("openpgp_certificates");
    tokio::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&pgp_certificates)
        .await?;

    let sq_homedir = homedir.join("sq_config");
    let sq_cryptoki = sq_homedir.join("config/keystore/cryptoki");
    tokio::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&sq_cryptoki)
        .await?;
    let mut config_file = tokio::fs::OpenOptions::new()
        .mode(0o600)
        .create_new(true)
        .write(true)
        .open(sq_cryptoki.join("config.toml"))
        .await?;
    config_file
        .write_all("[[modules]]\npath = \"/usr/lib64/pkcs11/libsiguldry_pkcs11.so\"\n".as_bytes())
        .await?;
    config_file.shutdown().await?;
    drop(config_file);

    let pgp_cert_names = config
        .koji
        .tags
        .iter()
        .map(|tag| tag.siguldry_openpgp_cert.as_str())
        .chain(
            config
                .ostree
                .iter()
                .map(|o| o.siguldry_openpgp_cert.as_str()),
        )
        .chain(
            config
                .coreos
                .keys
                .iter()
                .map(|k| k.siguldry_openpgp_cert.as_str()),
        )
        .collect::<Vec<_>>();
    let mut gpg_homedirs = HashMap::new();
    for key in keys {
        for cert in key
            .certificates
            .iter()
            .filter(|c| matches!(c.certificate_type, CertificateType::Pgp))
        {
            // If we're not using the cert, don't bother importing it.
            if !pgp_cert_names.contains(&cert.name.as_str()) {
                continue;
            }

            tracing::info!(
                key.name,
                cert.name,
                cert.fingerprint,
                "Importing OpenPGP certificate"
            );
            let cert_path = pgp_certificates.join(format!("{}.pgp", cert.fingerprint));
            let mut cert_file = tokio::fs::OpenOptions::new()
                .mode(0o644)
                .create_new(true)
                .write(true)
                .open(&cert_path)
                .await?;
            cert_file.write_all(cert.certificate.as_bytes()).await?;
            cert_file.shutdown().await?;

            let mut command = tokio::process::Command::new("sq");
            let output = command
                .kill_on_drop(true)
                .env_clear()
                .env(
                    "LIBSIGULDRY_PKCS11_PROXY_PATH",
                    &config.siguldry.client_proxy_socket,
                )
                .env("SEQUOIA_HOME", &sq_homedir)
                .arg("--batch")
                .arg("cert")
                .arg("import")
                .arg(&cert_path)
                .output()
                .await?;
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to import OpenPGP certificate"));
            }

            // GPG can't handle more than 1 token without weird things happening
            // The simplest (weird) solution is to create a homedir per key.
            let gpg_homedir = homedir.join(format!("gpg_configs/{}", cert.fingerprint));
            gpg_homedirs.insert(cert.fingerprint.clone(), gpg_homedir.clone());
            tokio::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&gpg_homedir)
                .await?;
            let mut gpg_agent_file = tokio::fs::OpenOptions::new()
                .mode(0o600)
                .create_new(true)
                .write(true)
                .open(gpg_homedir.join("gpg-agent.conf"))
                .await?;
            gpg_agent_file
                .write_all("scdaemon-program /usr/bin/gnupg-pkcs11-scd\n".as_bytes())
                .await?;
            gpg_agent_file.shutdown().await?;
            drop(gpg_agent_file);
            let mut gpg_pkcs11_scd_file = tokio::fs::OpenOptions::new()
                .mode(0o600)
                .create_new(true)
                .write(true)
                .open(gpg_homedir.join("gnupg-pkcs11-scd.conf"))
                .await?;
            gpg_pkcs11_scd_file.write_all("providers siguldry\nprovider-siguldry-library /usr/lib64/pkcs11/libsiguldry_pkcs11.so\nprovider-siguldry-allow-protected-auth\n".as_bytes()).await?;
            gpg_pkcs11_scd_file.shutdown().await?;
            drop(gpg_pkcs11_scd_file);

            let mut command = tokio::process::Command::new("gpg");
            let output = command
                .kill_on_drop(true)
                .env_clear()
                .env("GNUPGHOME", &gpg_homedir)
                .env("LIBSIGULDRY_PKCS11_KEYS", &key.name)
                .env(
                    "LIBSIGULDRY_PKCS11_PROXY_PATH",
                    &config.siguldry.client_proxy_socket,
                )
                .arg("--batch")
                .arg("--import")
                .arg(&cert_path)
                .output()
                .await?;
            if !output.status.success() {
                tracing::error!(
                    ?command,
                    exit_code = ?output.status.code(),
                    stdout = %String::from_utf8_lossy(&output.stdout),
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "Failed to import OpenPGP certificate"
                );
                return Err(anyhow::anyhow!("Failed to import OpenPGP certificate"));
            } else {
                tracing::debug!(
                    key.name,
                    cert.name,
                    cert.fingerprint,
                    "Successfully imported OpenPGP certificate"
                );
            }

            // Required to have gpg find the private keys backed by PKCS#11.
            //
            // We also have to apply a filter to the keys exposed by PKCS#11 because, due
            // to gpg limitations, gnupg-pkcs11-scd can only expose a single token. Its
            // work-arounds for that problem leads to prompts, so we have to be careful to
            // ensure each instance only sees one token.
            let mut command = tokio::process::Command::new("gpg");
            let output = command
                .kill_on_drop(true)
                .env_clear()
                .env("GNUPGHOME", &gpg_homedir)
                .env("LIBSIGULDRY_PKCS11_KEYS", &key.name)
                .env(
                    "LIBSIGULDRY_PKCS11_PROXY_PATH",
                    &config.siguldry.client_proxy_socket,
                )
                .arg("--card-status")
                .output()
                .await?;
            if !output.status.success() {
                tracing::error!(
                    ?command,
                    exit_code = ?output.status.code(),
                    stdout = %String::from_utf8_lossy(&output.stdout),
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "Failed to discover secret key from PKCS#11 token"
                );
                return Err(anyhow::anyhow!(
                    "Failed to discover PKCS#11 keys with 'gpg --card-status' "
                ));
            }
            tracing::debug!(
                ?command,
                stdout = %String::from_utf8_lossy(&output.stdout),
                "'gpg --card-status' succeeded"
            );
        }
    }

    Ok(PgpConfig {
        openssl_config,
        sq_homedir,
        gpg_homedirs,
    })
}

// Repeated requests to terminate should exit immediately.
#[allow(clippy::exit)]
async fn signal_handler(halt_token: CancellationToken) -> Result<(), anyhow::Error> {
    let mut sigterm_stream = signal(SignalKind::terminate()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGTERM signal handler");
    })?;
    let mut sigint_stream = signal(SignalKind::interrupt()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGINT signal handler");
    })?;

    let mut signaled = false;
    loop {
        tokio::select! {
            _ = sigterm_stream.recv() => {
                halt_token.cancel();
            }
            _ = sigint_stream.recv() => {
                halt_token.cancel();
            }
        }
        if !signaled {
            tracing::info!("Shutdown signal received; beginning service shutdown");
            signaled = true;
        } else {
            tracing::error!("Giving up waiting for graceful shutdown; exiting now!");
            exit(1);
        }
    }
}
