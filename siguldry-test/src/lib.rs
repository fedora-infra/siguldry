// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Utilities for testing Siguldry components, useful across end-to-end tests, benchmarks, and the
//! PKCS #11 module.

use std::{
    io::Write,
    net::SocketAddr,
    num::NonZeroU16,
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
};

use anyhow::{Context, bail};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::Attribute,
    session::UserType,
    slot::Slot,
    types::AuthPin,
};
use sequoia_openpgp::crypto::Password;
use siguldry::{
    bridge, client,
    config::Credentials,
    server::{self, Pkcs11Binding},
};
use tokio::{net::UnixListener, process::Command, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

#[derive(Clone)]
pub struct Creds {
    pub server: Credentials,
    pub bridge: Credentials,
    pub client: Credentials,
}

// Generate a set of credentials in the given directory.
pub async fn create_credentials(
    dir: &Path,
    bridge_hostname: &str,
    server_hostname: &str,
    client_name: &str,
) -> anyhow::Result<Creds> {
    let mut command = Command::new("bash");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../devel/siguldry_auth_keys.sh");
    let output = command
        .current_dir(dir)
        .arg(script.as_path())
        .args([server_hostname, bridge_hostname, client_name])
        .output()
        .await?;
    if !output.status.success() {
        bail!("Failed to generate auth keys");
    }

    let creds_directory = dir.join("creds/");
    Ok(Creds {
        server: Credentials {
            private_key: creds_directory.join("siguldry.server.private_key.pem"),
            certificate: creds_directory.join("siguldry.server.certificate.pem"),
            ca_certificate: creds_directory.join("siguldry.ca_certificate.pem"),
        },
        bridge: Credentials {
            private_key: creds_directory.join("siguldry.bridge.private_key.pem"),
            certificate: creds_directory.join("siguldry.bridge.certificate.pem"),
            ca_certificate: creds_directory.join("siguldry.ca_certificate.pem"),
        },
        client: Credentials {
            private_key: creds_directory.join("siguldry.client.private_key.pem"),
            certificate: creds_directory.join("siguldry.client.certificate.pem"),
            ca_certificate: creds_directory.join("siguldry.ca_certificate.pem"),
        },
    })
}

// Dropping TempDir cleans up the directory, but it needs to live to the end of the test.
#[allow(dead_code)]
pub struct Instance {
    pub server: server::service::Listener,
    pub bridge: bridge::Listener,
    pub client: client::Client,
    pub creds: Creds,
    pub state_dir: tempfile::TempDir,
    pub signer_helper: (CancellationToken, JoinHandle<anyhow::Result<()>>),
    client_proxy: Option<(CancellationToken, JoinHandle<anyhow::Result<()>>)>,
}

impl Instance {
    pub async fn halt(self) -> anyhow::Result<()> {
        drop(self.client);
        if let Some((halt_token, client_proxy)) = self.client_proxy {
            halt_token.cancel();
            client_proxy.await??;
        }

        let (halt_token, signer_helper) = self.signer_helper;
        halt_token.cancel();
        signer_helper.await??;

        self.server.halt().await?;
        self.bridge.halt().await?;
        Ok(())
    }

    pub fn client_proxy_socket(&self) -> PathBuf {
        self.state_dir.path().join("client-proxy.socket")
    }
}

pub mod keys {
    pub const GPG_KEY_NAME: &str = "test-gpg-key";
    pub const GPG_KEY_PASSWORD: &str = "🪿🪿🪿";
    pub const GPG_KEY_EMAIL: &str = "admin@example.com";

    pub const GPG_EC_KEY_NAME: &str = "test-gpg-ec-key";
    pub const GPG_EC_KEY_PASSWORD: &str = "🐉🐉🐉🐉🐉";
    pub const GPG_EC_KEY_EMAIL: &str = "admin@example.com";

    pub const CA_KEY_NAME: &str = "test-ca-key";
    pub const CA_KEY_PASSWORD: &str = "🦀🦀🦀🦀";

    pub const CODESIGNING_KEY_NAME: &str = "test-codesigning-key";
    pub const CODESIGNING_KEY_PASSWORD: &str = "🪶🪶🪶🪶";

    pub const EC_KEY_NAME: &str = "test-ec-key";
    pub const EC_KEY_PASSWORD: &str = "🌙🌙🌙🌙";

    pub const HSM_PIN: &str = "very-secret-pin";
    pub const HSM_ACCESS_PASSWORD: &str = "🦆🦆🦆🦆🪿";

    pub const HSM_EC_KEY_NAME: &str = "test-hsm-ec-key";
    pub const HSM_RSA_KEY_NAME: &str = "test-hsm-rsa-key";

    /// ID used for the PKCS#11 binding key
    pub const HSM_BINDING_KEY_ID: u8 = 99;

    /// GPG key imported from sigul
    pub const SIGUL_GPG_KEY_NAME: &str = "test-sigul-gpg-key";
    pub const SIGUL_GPG_KEY_PASSWORD: &str = "siguldry-gpg-key-passphrase";

    /// CA key imported from sigul
    pub const SIGUL_CA_KEY_NAME: &str = "test-sigul-ca-key";
    pub const SIGUL_CA_CERT_NAME: &str = "root";

    /// RSA key imported from sigul
    pub const SIGUL_RSA_KEY_NAME: &str = "test-sigul-rsa-key";
    pub const SIGUL_RSA_CERT_NAME: &str = "codesigning";

    /// SoftHSM token PIN for the binding key used with sigul keys.
    pub const SIGUL_SOFTHSM_PIN: &str = "abc123def";
}

/// Builder for creating test instances with specific key configurations.
#[derive(Default)]
pub struct InstanceBuilder {
    creds: Option<Creds>,
    // If enabled, the gpg keys will use v6 keys.
    with_gpg_rfc9580_keys: bool,
    with_gpg_key: bool,
    with_gpg_ec_key: bool,
    with_ca_key: bool,
    with_codesigning_key: bool,
    with_ec_key: bool,
    with_hsm_ec_key: bool,
    with_hsm_rsa_key: bool,
    with_hsm: bool,
    with_pkcs11_binding: bool,
    with_client_proxy: bool,
    with_sigul_import: Option<String>,
}

impl InstanceBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Use pre-generated credentials instead of creating new ones.
    pub fn with_creds(mut self, creds: Creds) -> Self {
        self.creds = Some(creds);
        self
    }

    pub fn use_rfc9580_for_gpg(mut self) -> Self {
        self.with_gpg_rfc9580_keys = true;
        self
    }

    pub fn with_gpg_key(mut self) -> Self {
        self.with_gpg_key = true;
        self
    }

    pub fn with_gpg_ec_key(mut self) -> Self {
        self.with_gpg_ec_key = true;
        self
    }

    pub fn with_codesigning_key(mut self) -> Self {
        self.with_ca_key = true;
        self.with_codesigning_key = true;
        self
    }

    pub fn with_ec_key(mut self) -> Self {
        self.with_ca_key = true;
        self.with_ec_key = true;
        self
    }

    pub fn with_hsm_ec_key(mut self) -> Self {
        self.with_hsm = true;
        self.with_ca_key = true;
        self.with_hsm_ec_key = true;
        self
    }

    pub fn with_hsm_rsa_key(mut self) -> Self {
        self.with_hsm = true;
        self.with_ca_key = true;
        self.with_hsm_rsa_key = true;
        self
    }

    /// Configure the server to use a PKCS#11 binding key for key password encryption.
    pub fn with_pkcs11_binding(mut self) -> Self {
        self.with_hsm = true;
        self.with_pkcs11_binding = true;
        self
    }

    /// Create a Unix socket to proxy client requests (useful for PKCS #11 testing).
    pub fn with_client_proxy(mut self) -> Self {
        self.with_client_proxy = true;
        self
    }

    /// Import keys from a pre-existing sigul database instead of creating new ones.
    ///
    /// Tests that use this rely on `cargo xtask generate-sigul-data` to be run.
    ///
    /// If None is provided for answers, the complete database will be imported.
    /// Otherwise, provide a string that selectively imports things based on what
    /// generate-sigul-data outputs (yes this is horrible, I know, I'm sorry).
    pub fn with_sigul_import(mut self, answers: Option<String>) -> Self {
        self.with_sigul_import = if answers.is_some() {
            answers
        } else {
            let sigul_data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("devel/sigul-data");
            let import_answers_path = sigul_data_dir.join("import-dialog-answers");
            let answers = std::fs::read_to_string(&import_answers_path)
                .expect("Run 'cargo xtask generate-sigul-data' to populate sigul test data");
            Some(answers)
        };
        self
    }

    pub fn with_all_keys(mut self) -> Self {
        self.with_gpg_key = true;
        self.with_ca_key = true;
        self.with_codesigning_key = true;
        self.with_ec_key = true;
        self.with_hsm_rsa_key = true;
        self.with_hsm_ec_key = true;
        self
    }

    pub async fn setup_hsm(tempdir: &Path) -> anyhow::Result<(Pkcs11, Slot, AuthPin)> {
        let hsm_config_path = tempdir.join("kryoptic.toml");
        let hsm_db_path = tempdir.join("kryoptic.sql");
        std::fs::write(
            &hsm_config_path,
            format!(
                "[[slots]]\nslot = 1\ndbtype = \"sqlite\"\ndbargs = \"{}\"",
                hsm_db_path.display()
            ),
        )?;
        // SAFETY:
        // These tests are required to run with nextest, which starts a new process for each test.
        // Using set_var is only safe if no other code is interacting with the environment variables,
        // which should be true under nextest. Refer to
        // https://nexte.st/docs/configuration/env-vars/#altering-the-environment-within-tests to ensure
        // this remains the case with current versions of Rust.
        unsafe {
            std::env::set_var("KRYOPTIC_CONF", &hsm_config_path);
        };

        let pkcs11 = Pkcs11::new("/usr/lib64/pkcs11/libkryoptic_pkcs11.so")
            .context("Install the kryoptic PKCS#11 module")?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .context("Failed to initialized kryoptic PKCS#11 module")?;
        let slot = pkcs11
            .get_slots_with_token()?
            .pop()
            .expect("no slot available");
        let so_pin = AuthPin::new("12345678".into());
        let user_pin = AuthPin::new(keys::HSM_PIN.into());
        pkcs11
            .init_token(slot, &so_pin, "siguldry-test-token")
            .context("Failed to initialize token")?;
        pkcs11
            .open_rw_session(slot)
            .and_then(|session| {
                session.login(UserType::So, Some(&so_pin))?;
                session.init_pin(&user_pin)?;
                Ok(())
            })
            .context("Failed to initialize user pin")?;

        Ok((pkcs11, slot, user_pin))
    }

    pub async fn build(self) -> anyhow::Result<Instance> {
        // TODO come up with a better way to handle this; perhaps don't use the binaries at all?
        let server_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/debug/siguldry-server");
        // Unlike the server, which involves no DNS resolution from the client, the
        // bridge hostname needs to resolve and match the certificate it presents.
        let bridge_hostname = "localhost";
        let server_hostname = "siguldry-server";
        let client_name = "siguldry-client";
        let tempdir = tempfile::TempDir::new()?;
        let pkcs11 = if self.with_hsm {
            Some(Self::setup_hsm(tempdir.path()).await?)
        } else {
            None
        };
        let pkcs11_bindings = if self.with_pkcs11_binding {
            let (pkcs11, slot, user_pin) = pkcs11
                .as_ref()
                .expect("HSM must be set up for PKCS#11 binding");
            let binding = Self::create_binding_key(pkcs11, *slot, user_pin, tempdir.path()).await?;
            vec![binding]
        } else {
            vec![]
        };

        let creds = if let Some(creds) = self.creds {
            creds
        } else {
            create_credentials(
                tempdir.path(),
                bridge_hostname,
                server_hostname,
                client_name,
            )
            .await?
        };

        let bridge_config = bridge::Config {
            server_listening_address: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            client_listening_address: SocketAddr::from_str("127.0.0.1:0").unwrap(),
            credentials: creds.bridge.clone(),
        };
        let bridge_config_file = tempdir.path().join("bridge.toml");
        std::fs::write(&bridge_config_file, toml::to_string_pretty(&bridge_config)?)?;
        let bridge = bridge::listen(bridge_config)
            .instrument(tracing::info_span!("bridge"))
            .await?;

        let server_config = server::Config {
            state_directory: tempdir.path().into(),
            bridge_hostname: bridge_hostname.to_string(),
            bridge_port: bridge.server_port(),
            credentials: creds.server.clone(),
            signer_socket_path: tempdir.path().join("signer-helper.socket"),
            user_password_length: NonZeroU16::new(keys::GPG_KEY_PASSWORD.len() as u16)
                .expect("it's three geese"),
            pkcs11_bindings,
            connection_pool_size: 1,
            ..Default::default()
        };
        let server_config_file = tempdir.path().join("server.toml");
        std::fs::write(&server_config_file, toml::to_string_pretty(&server_config)?)?;

        Self::run_server_command(
            &server_bin,
            &server_config_file,
            &["manage", "migrate"],
            None,
        )?;

        if let Some(answers) = &self.with_sigul_import {
            Self::import_sigul_data(&server_bin, tempdir.path(), &server_config_file, answers)?;
        } else {
            Self::run_server_command(
                &server_bin,
                &server_config_file,
                &["manage", "users", "create", "siguldry-client"],
                None,
            )?;

            let profile = if self.with_gpg_rfc9580_keys {
                "rfc9580"
            } else {
                "rfc4880"
            };

            if self.with_gpg_key {
                Self::run_server_command(
                    &server_bin,
                    &server_config_file,
                    &[
                        "manage",
                        "gpg",
                        "create",
                        "--profile",
                        profile,
                        "siguldry-client",
                        keys::GPG_KEY_NAME,
                        keys::GPG_KEY_EMAIL,
                    ],
                    Some(&format!("{}\n", keys::GPG_KEY_PASSWORD)),
                )?;
            }

            if self.with_gpg_ec_key {
                Self::run_server_command(
                    &server_bin,
                    &server_config_file,
                    &[
                        "manage",
                        "gpg",
                        "create",
                        "--profile",
                        profile,
                        "--algorithm",
                        "p256",
                        "siguldry-client",
                        keys::GPG_EC_KEY_NAME,
                        keys::GPG_EC_KEY_EMAIL,
                    ],
                    Some(&format!("{}\n", keys::GPG_EC_KEY_PASSWORD)),
                )?;
            }

            if self.with_ca_key {
                Self::create_ca_key(&server_bin, self.with_pkcs11_binding, &server_config_file)?;
            }

            if let Some((pkcs11, slot, user_pin)) = pkcs11 {
                if self.with_hsm_rsa_key {
                    Self::create_hsm_rsa_key(&pkcs11, slot, &user_pin)?;
                }
                if self.with_hsm_ec_key {
                    Self::create_hsm_ec_key(&pkcs11, slot, &user_pin)?;
                }

                Self::run_server_command(
                    &server_bin,
                    &server_config_file,
                    &[
                        "manage",
                        "pkcs11",
                        "register",
                        "--module",
                        "/usr/lib64/pkcs11/libkryoptic_pkcs11.so",
                        "siguldry-client",
                    ],
                    Some(&format!(
                        "{}\n{}\n",
                        keys::HSM_PIN,
                        keys::HSM_ACCESS_PASSWORD
                    )),
                )?;
                pkcs11.finalize()?;
            }

            if self.with_codesigning_key {
                Self::create_codesigning_key(&server_bin, &server_config_file)?;
            }

            if self.with_ec_key {
                Self::create_ec_key(&server_bin, &server_config_file)?;
            }
        }

        let signer_helper = {
            let halt_token = CancellationToken::new();
            let listener = UnixListener::bind(&server_config.signer_socket_path)?;

            let signer_halt = halt_token.clone();

            let signer = tokio::spawn(async move {
                let stream = tokio::select! {
                    _ = signer_halt.cancelled() => {
                        return Ok(());
                    }
                    result = listener.accept() => {
                        let (unix_stream, _) = result?;
                        unix_stream
                    }
                };
                tracing::info!("signing helper accepted connection");
                let (reader, writer) = tokio::io::split(stream);
                siguldry::server::ipc::serve(signer_halt, reader, writer).await?;
                Ok::<_, anyhow::Error>(())
            });
            (halt_token, signer)
        };

        let server = server::service::Server::new(server_config).await?;
        let server = server.run();

        let client_config = client::Config {
            server_hostname: server_hostname.to_string(),
            bridge_hostname: bridge_hostname.to_string(),
            bridge_port: bridge.client_port(),
            credentials: creds.client.clone(),
            ..Default::default()
        };
        let client_config_file = tempdir.path().join("client.toml");
        std::fs::write(&client_config_file, toml::to_string_pretty(&client_config)?)?;
        let client = client::Client::new(client_config)?;

        let client_proxy = if self.with_client_proxy {
            let halt_token = CancellationToken::new();
            let client_proxy =
                Self::create_client_proxy(tempdir.path(), client.clone(), halt_token.clone())?;
            Some((halt_token, client_proxy))
        } else {
            None
        };

        Ok(Instance {
            server,
            bridge,
            client,
            creds,
            state_dir: tempdir,
            signer_helper,
            client_proxy,
        })
    }

    fn create_client_proxy(
        state_dir: &Path,
        client: client::Client,
        halt_token: CancellationToken,
    ) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
        let socket_path = state_dir.join("client-proxy.socket");
        // Safety:
        // This is only safe when the set runner is nextest _or_ cargo-test is using a single
        // thread. Expect random test failures in other scenarios.
        unsafe {
            std::env::set_var("SIGULDRY_PKCS11_PROXY_PATH", &socket_path);
        }

        let proxy_halt = halt_token.clone();
        let listener = UnixListener::bind(&socket_path)?;

        let proxy = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let (reader, writer) = tokio::io::split(stream);
            siguldry::client::proxy(client, proxy_halt, reader, writer).await?;
            Ok::<_, anyhow::Error>(())
        });

        Ok(proxy)
    }

    /// Run a siguldry-server command with optional stdin input.
    fn run_server_command(
        server_bin: &Path,
        config_file: &Path,
        args: &[&str],
        stdin_input: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut command = std::process::Command::new(server_bin);
        command
            .env("SIGULDRY_SERVER_CONFIG", config_file)
            .args(args);

        if let Some(input) = stdin_input {
            command.stdin(Stdio::piped());
            let mut child = command.spawn()?;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(input.as_bytes())?;
            drop(stdin);
            let result = child.wait_with_output()?;
            if !result.status.success() {
                bail!("Command failed: {:?}", args);
            }
        } else {
            let result = command.output()?;
            if !result.status.success() {
                bail!("Command failed: {:?}", args);
            }
        }
        Ok(())
    }

    fn create_hsm_rsa_key(pkcs11: &Pkcs11, slot: Slot, user_pin: &AuthPin) -> anyhow::Result<()> {
        let id = Attribute::Id(vec![1]);
        let label = Attribute::Label(keys::HSM_RSA_KEY_NAME.as_bytes().to_vec());
        let _ = pkcs11.open_rw_session(slot).and_then(|session| {
            session.login(UserType::User, Some(user_pin))?;
            session.generate_key_pair(
                &Mechanism::RsaPkcsKeyPairGen,
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Verify(true),
                    Attribute::Encrypt(true),
                    Attribute::ModulusBits(4096.into()),
                ],
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Sign(true),
                    Attribute::Decrypt(true),
                ],
            )
        })?;

        Ok(())
    }

    /// Create an RSA key in the HSM for PKCS#11 binding
    async fn create_binding_key(
        pkcs11: &Pkcs11,
        slot: Slot,
        user_pin: &AuthPin,
        tempdir: &Path,
    ) -> anyhow::Result<Pkcs11Binding> {
        let id = Attribute::Id(vec![keys::HSM_BINDING_KEY_ID]);
        let label = Attribute::Label(b"siguldry-binding-key".to_vec());
        pkcs11.open_rw_session(slot).and_then(|session| {
            session.login(UserType::User, Some(user_pin))?;
            session.generate_key_pair(
                &Mechanism::RsaPkcsKeyPairGen,
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Verify(true),
                    Attribute::Encrypt(true),
                    Attribute::ModulusBits(2048.into()),
                ],
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Sign(true),
                    Attribute::Decrypt(true),
                ],
            )
        })?;

        let key_uri = format!(
            "pkcs11:token=siguldry-test-token;id=%{:02x};type=private",
            keys::HSM_BINDING_KEY_ID
        );
        let module_path = "/usr/lib64/pkcs11/libkryoptic_pkcs11.so";
        let cert_file = tempdir.join("binding-cert.pem");
        let hsm_config_path = tempdir.join("kryoptic.toml");
        let mut command = Command::new("openssl");
        let output = command
            .env("KRYOPTIC_CONF", &hsm_config_path)
            .env("PKCS11_PROVIDER_MODULE", module_path)
            .args([
                "req",
                "-x509",
                "-provider",
                "pkcs11",
                "-subj",
                "/CN=siguldry-binding-key",
            ])
            .arg("-passin")
            .arg(format!("pass:{}", keys::HSM_PIN))
            .arg("-key")
            .arg(&key_uri)
            .arg("-out")
            .arg(&cert_file)
            .output()
            .await?;
        if !output.status.success() {
            panic!(
                "Failed to create x509 certificate:  {:?}",
                String::from_utf8_lossy(&output.stderr)
            )
        }
        let mut command = Command::new("pkcs11-tool");
        let output = command
            .env("KRYOPTIC_CONF", &hsm_config_path)
            .arg(format!("--module={}", module_path))
            .args([
                "--login",
                "--type=cert",
                "--label=self-signed-cert",
                "--id=1",
            ])
            .arg(format!("--pin={}", keys::HSM_PIN))
            .arg(format!("--write-object={}", cert_file.display()))
            .output()
            .await?;
        if !output.status.success() {
            panic!(
                "Failed to add cert to PKCS 11 token: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(Pkcs11Binding {
            certificate: cert_file,
            private_key: Some(key_uri),
            pin: Some(Password::from(keys::HSM_PIN)),
        })
    }

    fn create_hsm_ec_key(pkcs11: &Pkcs11, slot: Slot, user_pin: &AuthPin) -> anyhow::Result<()> {
        let id = Attribute::Id(vec![42]);
        let label = Attribute::Label(keys::HSM_EC_KEY_NAME.as_bytes().to_vec());
        let _ = pkcs11.open_rw_session(slot).and_then(|session| {
            session.login(UserType::User, Some(user_pin))?;

            // Annoyingly it doesn't seem possible to convert a named curve Nid to ASN.1 in
            // OpenSSL, so we manually create it from the OID for NIST P-256.
            let p256_oid = asn1::oid!(1, 2, 840, 10045, 3, 1, 7);
            let p256_oid_bytes = asn1::write_single(&p256_oid).unwrap();
            session.generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::EcParams(p256_oid_bytes),
                    Attribute::Verify(true),
                    Attribute::Encrypt(true),
                ],
                &[
                    id.clone(),
                    label.clone(),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Sign(true),
                    Attribute::Decrypt(true),
                ],
            )
        })?;

        Ok(())
    }

    fn create_ca_key(
        server_bin: &Path,
        with_pkcs11_binding: bool,
        server_config_file: &Path,
    ) -> anyhow::Result<()> {
        Self::run_server_command(
            server_bin,
            server_config_file,
            &[
                "manage",
                "key",
                "create",
                "siguldry-client",
                keys::CA_KEY_NAME,
            ],
            Some(&format!("{}\n", keys::CA_KEY_PASSWORD)),
        )?;

        let input = if with_pkcs11_binding {
            format!("{}\n{}\n", keys::HSM_PIN, keys::CA_KEY_PASSWORD)
        } else {
            format!("{}\n", keys::CA_KEY_PASSWORD)
        };
        Self::run_server_command(
            server_bin,
            server_config_file,
            &[
                "manage",
                "key",
                "x509",
                "--user-name",
                "siguldry-client",
                "--key-name",
                keys::CA_KEY_NAME,
                "--common-name",
                keys::CA_KEY_NAME,
                "--validity-days",
                "30",
                "certificate-authority",
            ],
            Some(&input),
        )
    }

    fn create_codesigning_key(server_bin: &Path, server_config_file: &Path) -> anyhow::Result<()> {
        Self::run_server_command(
            server_bin,
            server_config_file,
            &[
                "manage",
                "key",
                "create",
                "siguldry-client",
                keys::CODESIGNING_KEY_NAME,
            ],
            Some(&format!("{}\n", keys::CODESIGNING_KEY_PASSWORD)),
        )?;

        Self::run_server_command(
            server_bin,
            server_config_file,
            &[
                "manage",
                "key",
                "x509",
                "--user-name",
                "siguldry-client",
                "--key-name",
                keys::CODESIGNING_KEY_NAME,
                "--common-name",
                keys::CODESIGNING_KEY_NAME,
                "--validity-days",
                "30",
                "--certificate-authority",
                keys::CA_KEY_NAME,
                "code-signing",
            ],
            Some(&format!("{}\n", keys::CA_KEY_PASSWORD)),
        )
    }

    fn create_ec_key(server_bin: &Path, server_config_file: &Path) -> anyhow::Result<()> {
        Self::run_server_command(
            server_bin,
            server_config_file,
            &[
                "manage",
                "key",
                "create",
                "--algorithm=p256",
                "siguldry-client",
                keys::EC_KEY_NAME,
            ],
            Some(&format!("{}\n", keys::EC_KEY_PASSWORD)),
        )?;

        Self::run_server_command(
            server_bin,
            server_config_file,
            &[
                "manage",
                "key",
                "x509",
                "--user-name",
                "siguldry-client",
                "--key-name",
                keys::EC_KEY_NAME,
                "--common-name",
                keys::EC_KEY_NAME,
                "--validity-days",
                "30",
                "--certificate-authority",
                keys::CA_KEY_NAME,
                "code-signing",
            ],
            Some(&format!("{}\n", keys::CA_KEY_PASSWORD)),
        )
    }

    fn import_sigul_data(
        server_bin: &Path,
        state_dir: &Path,
        server_config_file: &Path,
        answers: &str,
    ) -> anyhow::Result<PathBuf> {
        let sigul_data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("devel/sigul-data");
        let sigul_dir = sigul_data_dir.join("sigul");
        let softhsm_dir = sigul_data_dir.join("softhsm");
        for path in [&sigul_dir, &softhsm_dir] {
            if !path.exists() {
                panic!("Run 'cargo xtask generate-sigul-data' to populate sigul test data");
            }
        }

        let softhsm_conf = state_dir.join("softhsm2.conf");
        std::fs::write(
            &softhsm_conf,
            format!(
                "directories.tokendir = {}",
                softhsm_dir.join("tokens").display()
            ),
        )?;
        let binding_uri = "pkcs11:token=Sigul%20Token%200;object=binding-key;type=private";

        let stdin_input = format!("{}\n{}", keys::SIGUL_SOFTHSM_PIN, answers);
        let mut child = std::process::Command::new(server_bin)
            .env("SIGULDRY_SERVER_LOG", "TRACE")
            .env("SIGULDRY_SERVER_CONFIG", server_config_file)
            .env("SOFTHSM2_CONF", &softhsm_conf)
            .arg("manage")
            .arg("import-sigul")
            .arg("--binding-uri")
            .arg(binding_uri)
            .arg(sigul_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn siguldry-server import-sigul")?;

        {
            let mut stdin = child.stdin.take().expect("stdin was piped");
            stdin
                .write_all(stdin_input.as_bytes())
                .context("Failed to write to stdin")?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to wait for import-sigul")?;

        if !output.status.success() {
            bail!(
                "import-sigul command failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(softhsm_conf)
    }
}
